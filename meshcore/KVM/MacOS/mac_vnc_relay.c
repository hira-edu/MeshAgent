/*
 * RFB 3.8 client used to relay Apple Screen Sharing over loopback.
 *
 * Only Raw, CopyRect and DesktopSize are negotiated, so every server message
 * has a length the client can validate. Anything else ends the connection.
 */
#define __STDC_WANT_LIB_EXT1__ 1
#include "mac_vnc_relay.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <CommonCrypto/CommonCryptor.h>

#define VNC_MAX_DIMENSION	16384
#define VNC_MAX_PIXELS		(64 * 1024 * 1024)
#define VNC_MAX_TEXT		(16 * 1024 * 1024)
#define VNC_MAX_REASON		4096
#define VNC_MAX_NAME		65535
#define VNC_BPP				4
#define VNC_WHEEL_DELTA		120
#define VNC_MAX_WHEEL_STEPS	10
#define VNC_MAX_HELD_KEYS	32

#define RFB_SEC_NONE		1
#define RFB_SEC_VNC			2
#define RFB_ENC_RAW			0
#define RFB_ENC_COPYRECT	1
#define RFB_ENC_DESKTOPSIZE	-223

struct vnc_relay
{
	int fd;
	int io_timeout_ms;
	int failed;					// First fatal error; read and written atomically
	pthread_mutex_t write_lock;	// Serializes client-to-server messages and guards buttons
	pthread_mutex_t fb_lock;	// Guards fb, width and height
	uint8_t *fb;				// width * height pixels, B G R X byte order
	int width;
	int height;
	uint8_t *row;				// Pump-thread scratch for one Raw row
	size_t row_size;
	uint8_t buttons;			// Guarded by write_lock, like the fields below
	int pointer_x, pointer_y;
	int wheel_rest;				// Wheel delta not yet sent as a whole step
	uint32_t held[VNC_MAX_HELD_KEYS];
	int held_count;
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static int relay_failed(vnc_relay *r) { return __atomic_load_n(&r->failed, __ATOMIC_ACQUIRE); }

// Records the first fatal error and unblocks both directions of the socket.
static int relay_fail(vnc_relay *r, int error)
{
	int expected = 0;
	__atomic_compare_exchange_n(&r->failed, &expected, error, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
	if (r->fd >= 0) { shutdown(r->fd, SHUT_RDWR); }
	return relay_failed(r);
}

static int wait_fd(int fd, short events, int timeout_ms)
{
	struct pollfd p = { fd, events, 0 };
	int n;
	do { n = poll(&p, 1, timeout_ms); } while (n < 0 && errno == EINTR);
	return n;
}

static int recv_exact(vnc_relay *r, void *buffer, size_t length)
{
	size_t got = 0;
	while (got < length)
	{
		if (relay_failed(r) != 0) { return relay_failed(r); }
		int n = wait_fd(r->fd, POLLIN, r->io_timeout_ms);
		if (n == 0) { return VNC_RELAY_E_TIMEOUT; }
		if (n < 0) { return VNC_RELAY_E_CLOSED; }
		ssize_t count = recv(r->fd, (uint8_t*)buffer + got, length - got, 0);
		if (count == 0) { return VNC_RELAY_E_CLOSED; }
		if (count < 0)
		{
			if (errno == EINTR || errno == EAGAIN) { continue; }
			return VNC_RELAY_E_CLOSED;
		}
		got += (size_t)count;
	}
	return VNC_RELAY_OK;
}

static int discard(vnc_relay *r, size_t length)
{
	uint8_t sink[4096];
	while (length > 0)
	{
		size_t chunk = length < sizeof(sink) ? length : sizeof(sink);
		int e = recv_exact(r, sink, chunk);
		if (e != VNC_RELAY_OK) { return e; }
		length -= chunk;
	}
	return VNC_RELAY_OK;
}

// Caller holds write_lock, except during the handshake when no other thread can use the relay.
static int send_all(vnc_relay *r, const void *buffer, size_t length)
{
	size_t sent = 0;
	while (sent < length)
	{
		if (relay_failed(r) != 0) { return relay_failed(r); }
		int n = wait_fd(r->fd, POLLOUT, r->io_timeout_ms);
		if (n == 0) { return relay_fail(r, VNC_RELAY_E_TIMEOUT); }
		if (n < 0) { return relay_fail(r, VNC_RELAY_E_CLOSED); }
		ssize_t count = send(r->fd, (const uint8_t*)buffer + sent, length - sent, 0);
		if (count < 0)
		{
			if (errno == EINTR || errno == EAGAIN) { continue; }
			return relay_fail(r, VNC_RELAY_E_CLOSED);
		}
		sent += (size_t)count;
	}
	return VNC_RELAY_OK;
}

static int send_locked(vnc_relay *r, const void *buffer, size_t length)
{
	pthread_mutex_lock(&r->write_lock);
	int e = send_all(r, buffer, length);
	pthread_mutex_unlock(&r->write_lock);
	return e;
}

static int connect_loopback(uint16_t port, int timeout_ms)
{
	struct sockaddr_in address;
	int one = 1, error = 0, flags;
	socklen_t length = sizeof(error);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { return -1; }
	// Without SO_NOSIGPIPE a send to a closed peer would kill the process.
	if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) { close(fd); return -1; }
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }
	if (connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, timeout_ms) <= 0 ||
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 || error != 0)
		{
			close(fd);
			return -1;
		}
	}
	if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
	return fd;
}

static uint8_t reverse_bits(uint8_t b)
{
	b = (uint8_t)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
	b = (uint8_t)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
	return (uint8_t)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
}

// VNC authentication: DES-encrypt the challenge with the bit-reversed password as key.
static int vnc_auth_response(const char *password, const uint8_t challenge[16], uint8_t response[16])
{
	uint8_t key[8] = { 0 };
	size_t moved = 0, i;
	for (i = 0; i < sizeof(key) && password[i] != 0; ++i) { key[i] = reverse_bits((uint8_t)password[i]); }
	CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionECBMode, key, kCCKeySizeDES, NULL,
		challenge, 16, response, 16, &moved);
	memset_s(key, sizeof(key), 0, sizeof(key));
	return (status == kCCSuccess && moved == 16) ? VNC_RELAY_OK : VNC_RELAY_E_AUTH;
}

static int read_reason(vnc_relay *r)
{
	uint8_t length[4];
	int e = recv_exact(r, length, sizeof(length));
	if (e != VNC_RELAY_OK) { return e; }
	if (rd32(length) > VNC_MAX_REASON) { return VNC_RELAY_E_PROTOCOL; }
	return discard(r, rd32(length));
}

static int valid_size(int width, int height)
{
	return width > 0 && height > 0 && width <= VNC_MAX_DIMENSION && height <= VNC_MAX_DIMENSION &&
		(long long)width * height <= VNC_MAX_PIXELS;
}

static int request_update(vnc_relay *r, int incremental, int width, int height)
{
	uint8_t message[10] = { 3, (uint8_t)(incremental ? 1 : 0) };
	wr16(message + 6, (uint16_t)width);
	wr16(message + 8, (uint16_t)height);
	return send_locked(r, message, sizeof(message));
}

static int handshake(vnc_relay *r, const char *password, vnc_relay_peer_check peer_check, void *context)
{
	uint8_t buffer[24];
	uint8_t types[255];
	uint8_t count;
	int e, i, chosen = 0;

	// Apple advertises "RFB 003.889"; any 3.x at or above 3.8 speaks the 3.8 handshake.
	if ((e = recv_exact(r, buffer, 12)) != VNC_RELAY_OK) { return e; }
	if (memcmp(buffer, "RFB ", 4) != 0 || buffer[7] != '.' || buffer[11] != '\n') { return VNC_RELAY_E_PROTOCOL; }
	for (i = 4; i < 11; ++i) { if (i != 7 && (buffer[i] < '0' || buffer[i] > '9')) { return VNC_RELAY_E_PROTOCOL; } }
	int major = (buffer[4] - '0') * 100 + (buffer[5] - '0') * 10 + (buffer[6] - '0');
	int minor = (buffer[8] - '0') * 100 + (buffer[9] - '0') * 10 + (buffer[10] - '0');
	if (major != 3 || minor < 8) { return VNC_RELAY_E_UNSUPPORTED; }
	// The server has accepted the connection, so its process now holds the peer socket.
	if (peer_check != NULL && peer_check(r->fd, context) != 0) { return VNC_RELAY_E_PEER; }
	if ((e = send_all(r, "RFB 003.008\n", 12)) != VNC_RELAY_OK) { return e; }

	if ((e = recv_exact(r, &count, 1)) != VNC_RELAY_OK) { return e; }
	if (count == 0)
	{
		e = read_reason(r);
		return e == VNC_RELAY_OK ? VNC_RELAY_E_UNSUPPORTED : e;
	}
	if ((e = recv_exact(r, types, count)) != VNC_RELAY_OK) { return e; }
	// Screen Sharing never offers None. With a credential, accept only VNC authentication, so a
	// server offering no authentication cannot be mistaken for it.
	int wanted = (password != NULL && password[0] != 0) ? RFB_SEC_VNC : RFB_SEC_NONE;
	for (i = 0; i < count; ++i) { if (types[i] == wanted) { chosen = wanted; } }
	if (chosen == 0) { return VNC_RELAY_E_UNSUPPORTED; }
	buffer[0] = (uint8_t)chosen;
	if ((e = send_all(r, buffer, 1)) != VNC_RELAY_OK) { return e; }

	if (chosen == RFB_SEC_VNC)
	{
		uint8_t challenge[16], response[16];
		if ((e = recv_exact(r, challenge, sizeof(challenge))) != VNC_RELAY_OK) { return e; }
		e = vnc_auth_response(password, challenge, response);
		if (e == VNC_RELAY_OK) { e = send_all(r, response, sizeof(response)); }
		memset_s(response, sizeof(response), 0, sizeof(response));
		if (e != VNC_RELAY_OK) { return e; }
	}

	if ((e = recv_exact(r, buffer, 4)) != VNC_RELAY_OK) { return e; }
	if (rd32(buffer) != 0)
	{
		read_reason(r);			// The credential was refused whatever the reason says or how it ends
		return VNC_RELAY_E_AUTH;
	}

	buffer[0] = 1;	// Shared: do not disconnect other Screen Sharing viewers
	if ((e = send_all(r, buffer, 1)) != VNC_RELAY_OK) { return e; }

	if ((e = recv_exact(r, buffer, 24)) != VNC_RELAY_OK) { return e; }
	r->width = rd16(buffer);
	r->height = rd16(buffer + 2);
	if (!valid_size(r->width, r->height) || rd32(buffer + 20) > VNC_MAX_NAME) { return VNC_RELAY_E_PROTOCOL; }
	if ((e = discard(r, rd32(buffer + 20))) != VNC_RELAY_OK) { return e; }

	r->fb = (uint8_t*)calloc((size_t)r->width * r->height, VNC_BPP);
	if (r->fb == NULL) { return VNC_RELAY_E_NOMEM; }

	// 32 bpp little-endian true colour, red at bit 16: bytes arrive as B G R X.
	uint8_t format[20] = { 0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0 };
	if ((e = send_all(r, format, sizeof(format))) != VNC_RELAY_OK) { return e; }

	uint8_t encodings[16] = { 2, 0 };
	wr16(encodings + 2, 3);
	wr32(encodings + 4, (uint32_t)RFB_ENC_RAW);
	wr32(encodings + 8, (uint32_t)RFB_ENC_COPYRECT);
	wr32(encodings + 12, (uint32_t)(int32_t)RFB_ENC_DESKTOPSIZE);
	if ((e = send_all(r, encodings, sizeof(encodings))) != VNC_RELAY_OK) { return e; }

	return request_update(r, 0, r->width, r->height);
}

vnc_relay* vnc_relay_open(uint16_t port, const char *password, int io_timeout_ms, vnc_relay_peer_check peer_check, void *context, int *error)
{
	int e = VNC_RELAY_OK;
	vnc_relay *r = NULL;
	if (io_timeout_ms <= 0) { e = VNC_RELAY_E_ARG; goto done; }
	if ((r = (vnc_relay*)calloc(1, sizeof(*r))) == NULL) { e = VNC_RELAY_E_NOMEM; goto done; }
	r->io_timeout_ms = io_timeout_ms;
	r->fd = -1;
	if (pthread_mutex_init(&r->write_lock, NULL) != 0) { free(r); r = NULL; e = VNC_RELAY_E_NOMEM; goto done; }
	if (pthread_mutex_init(&r->fb_lock, NULL) != 0) { pthread_mutex_destroy(&r->write_lock); free(r); r = NULL; e = VNC_RELAY_E_NOMEM; goto done; }
	if ((r->fd = connect_loopback(port, io_timeout_ms)) < 0) { e = VNC_RELAY_E_CONNECT; goto done; }
	e = handshake(r, password, peer_check, context);

done:
	if (error != NULL) { *error = e; }
	if (e != VNC_RELAY_OK && r != NULL) { vnc_relay_close(r); r = NULL; }
	return r;
}

void vnc_relay_shutdown(vnc_relay *r)
{
	if (r != NULL) { relay_fail(r, VNC_RELAY_E_CLOSED); }
}

void vnc_relay_close(vnc_relay *r)
{
	if (r == NULL) { return; }
	if (r->fd >= 0) { close(r->fd); }
	pthread_mutex_destroy(&r->write_lock);
	pthread_mutex_destroy(&r->fb_lock);
	free(r->fb);
	free(r->row);
	free(r);
}

const char* vnc_relay_strerror(int error)
{
	switch (error)
	{
		case VNC_RELAY_OK: return "ok";
		case VNC_RELAY_E_CONNECT: return "Screen Sharing is not listening on loopback";
		case VNC_RELAY_E_PROTOCOL: return "Screen Sharing sent an invalid or unsupported message";
		case VNC_RELAY_E_AUTH: return "Screen Sharing rejected the agent credential";
		case VNC_RELAY_E_UNSUPPORTED: return "Screen Sharing offered no supported version or security type";
		case VNC_RELAY_E_CLOSED: return "Screen Sharing connection closed";
		case VNC_RELAY_E_TIMEOUT: return "Screen Sharing stopped responding";
		case VNC_RELAY_E_NOMEM: return "out of memory";
		case VNC_RELAY_E_ARG: return "invalid argument";
		case VNC_RELAY_E_PEER: return "the Screen Sharing connection is not served by a root process";
		default: return "unknown error";
	}
}

static int apply_raw(vnc_relay *r, int x, int y, int w, int h)
{
	size_t row_bytes = (size_t)w * VNC_BPP;
	int e, row;
	if (row_bytes > r->row_size)
	{
		uint8_t *grown = (uint8_t*)realloc(r->row, row_bytes);
		if (grown == NULL) { return VNC_RELAY_E_NOMEM; }
		r->row = grown;
		r->row_size = row_bytes;
	}
	// Read each row before taking fb_lock so a slow server never stalls framebuffer copies.
	for (row = 0; row < h; ++row)
	{
		if ((e = recv_exact(r, r->row, row_bytes)) != VNC_RELAY_OK) { return e; }
		pthread_mutex_lock(&r->fb_lock);
		memcpy(r->fb + (((size_t)(y + row) * r->width) + x) * VNC_BPP, r->row, row_bytes);
		pthread_mutex_unlock(&r->fb_lock);
	}
	return VNC_RELAY_OK;
}

static int apply_copyrect(vnc_relay *r, int x, int y, int w, int h)
{
	uint8_t source[4];
	int e = recv_exact(r, source, sizeof(source));
	if (e != VNC_RELAY_OK) { return e; }
	int sx = rd16(source), sy = rd16(source + 2);
	if (sx + w > r->width || sy + h > r->height) { return VNC_RELAY_E_PROTOCOL; }

	size_t row_bytes = (size_t)w * VNC_BPP;
	int up = sy < y;	// Copy bottom-up when moving down so overlapping rows are read before being overwritten
	pthread_mutex_lock(&r->fb_lock);
	for (int i = 0; i < h; ++i)
	{
		int row = up ? h - 1 - i : i;
		memmove(r->fb + (((size_t)(y + row) * r->width) + x) * VNC_BPP,
			r->fb + (((size_t)(sy + row) * r->width) + sx) * VNC_BPP, row_bytes);
	}
	pthread_mutex_unlock(&r->fb_lock);
	return VNC_RELAY_OK;
}

static int apply_resize(vnc_relay *r, int w, int h)
{
	if (!valid_size(w, h)) { return VNC_RELAY_E_PROTOCOL; }
	uint8_t *fb = (uint8_t*)calloc((size_t)w * h, VNC_BPP);
	if (fb == NULL) { return VNC_RELAY_E_NOMEM; }
	pthread_mutex_lock(&r->fb_lock);
	uint8_t *old = r->fb;
	r->fb = fb;
	r->width = w;
	r->height = h;
	pthread_mutex_unlock(&r->fb_lock);
	free(old);
	return VNC_RELAY_OK;
}

static int read_update(vnc_relay *r)
{
	uint8_t header[12];
	int e, flags = 0;
	if ((e = recv_exact(r, header, 3)) != VNC_RELAY_OK) { return e; }
	int rects = rd16(header + 1);

	for (int i = 0; i < rects; ++i)
	{
		if ((e = recv_exact(r, header, sizeof(header))) != VNC_RELAY_OK) { return e; }
		int x = rd16(header), y = rd16(header + 2), w = rd16(header + 4), h = rd16(header + 6);
		int32_t encoding = (int32_t)rd32(header + 8);

		if (encoding == RFB_ENC_DESKTOPSIZE)
		{
			if ((e = apply_resize(r, w, h)) != VNC_RELAY_OK) { return e; }
			flags |= VNC_RELAY_RESIZED;	// The new framebuffer is blank until its pixels arrive
			continue;
		}
		// Only the pump thread changes the dimensions, so reading them here without fb_lock is safe.
		if (x + w > r->width || y + h > r->height) { return VNC_RELAY_E_PROTOCOL; }
		if (w == 0 || h == 0)
		{
			// Nothing to draw; a CopyRect still carries its source position.
			if (encoding == RFB_ENC_RAW) { continue; }
			if (encoding == RFB_ENC_COPYRECT) { if ((e = discard(r, 4)) != VNC_RELAY_OK) { return e; } continue; }
			return VNC_RELAY_E_PROTOCOL;
		}
		if (encoding == RFB_ENC_RAW) { e = apply_raw(r, x, y, w, h); }
		else if (encoding == RFB_ENC_COPYRECT) { e = apply_copyrect(r, x, y, w, h); }
		else { return VNC_RELAY_E_PROTOCOL; }
		if (e != VNC_RELAY_OK) { return e; }
		flags |= VNC_RELAY_UPDATED;
	}

	// Keep exactly one update request outstanding; after a resize ask for the whole new framebuffer.
	if ((e = request_update(r, (flags & VNC_RELAY_RESIZED) == 0, r->width, r->height)) != VNC_RELAY_OK) { return e; }
	return flags;
}

int vnc_relay_pump(vnc_relay *r, int wait_ms)
{
	uint8_t type, header[7];
	int e;
	if (r == NULL) { return VNC_RELAY_E_ARG; }
	if ((e = relay_failed(r)) != 0) { return e; }

	int n = wait_fd(r->fd, POLLIN, wait_ms);
	if (n == 0) { return 0; }
	if (n < 0) { return relay_fail(r, VNC_RELAY_E_CLOSED); }

	if ((e = recv_exact(r, &type, 1)) != VNC_RELAY_OK) { return relay_fail(r, e); }
	switch (type)
	{
		case 0:		// FramebufferUpdate
			e = read_update(r);
			break;
		case 2:		// Bell
			e = 0;
			break;
		case 3:		// ServerCutText
			if ((e = recv_exact(r, header, sizeof(header))) != VNC_RELAY_OK) { break; }
			e = rd32(header + 3) > VNC_MAX_TEXT ? VNC_RELAY_E_PROTOCOL : discard(r, rd32(header + 3));
			break;
		default:	// SetColourMapEntries is invalid for the negotiated true-colour format
			e = VNC_RELAY_E_PROTOCOL;
			break;
	}
	return e < 0 ? relay_fail(r, e) : e;
}

int vnc_relay_size(vnc_relay *r, int *width, int *height)
{
	if (r == NULL) { return VNC_RELAY_E_ARG; }
	pthread_mutex_lock(&r->fb_lock);
	if (width != NULL) { *width = r->width; }
	if (height != NULL) { *height = r->height; }
	pthread_mutex_unlock(&r->fb_lock);
	return relay_failed(r);
}

int vnc_relay_copy_rgb24(vnc_relay *r, uint8_t *dst, size_t dst_size, size_t dst_stride, int *width, int *height)
{
	int e = VNC_RELAY_OK;
	if (r == NULL || dst == NULL) { return VNC_RELAY_E_ARG; }
	if ((e = relay_failed(r)) != 0) { return e; }
	pthread_mutex_lock(&r->fb_lock);
	size_t row_bytes = (size_t)r->width * 3;
	if (dst_stride < row_bytes || dst_size < dst_stride * (size_t)(r->height - 1) + row_bytes) { e = VNC_RELAY_E_ARG; }
	else
	{
		for (int y = 0; y < r->height; ++y)
		{
			const uint8_t *s = r->fb + (size_t)y * r->width * VNC_BPP;
			uint8_t *d = dst + (size_t)y * dst_stride;
			for (int x = 0; x < r->width; ++x, s += VNC_BPP, d += 3)
			{
				d[0] = s[2];
				d[1] = s[1];
				d[2] = s[0];
			}
		}
	}
	if (width != NULL) { *width = r->width; }
	if (height != NULL) { *height = r->height; }
	pthread_mutex_unlock(&r->fb_lock);
	return e;
}

int vnc_relay_key(vnc_relay *r, uint32_t keysym, int down)
{
	int i, e;
	if (r == NULL || keysym == 0) { return VNC_RELAY_E_ARG; }
	uint8_t message[8] = { 4, (uint8_t)(down ? 1 : 0) };
	wr32(message + 4, keysym);
	pthread_mutex_lock(&r->write_lock);
	e = send_all(r, message, sizeof(message));
	// Remember pressed keys so vnc_relay_release_all can lift them when the session ends.
	for (i = 0; i < r->held_count && r->held[i] != keysym; ++i) { }
	if (e == VNC_RELAY_OK && down && i == r->held_count && r->held_count < VNC_MAX_HELD_KEYS) { r->held[r->held_count++] = keysym; }
	else if (!down && i < r->held_count) { r->held[i] = r->held[--r->held_count]; }
	pthread_mutex_unlock(&r->write_lock);
	return e;
}

int vnc_relay_release_all(vnc_relay *r)
{
	uint8_t message[8] = { 4, 0 };
	int e = VNC_RELAY_OK;
	if (r == NULL) { return VNC_RELAY_E_ARG; }
	pthread_mutex_lock(&r->write_lock);
	while (r->held_count > 0 && e == VNC_RELAY_OK)
	{
		wr32(message + 4, r->held[--r->held_count]);
		e = send_all(r, message, sizeof(message));
	}
	if (e == VNC_RELAY_OK && r->buttons != 0)
	{
		uint8_t pointer[6];
		r->buttons = 0;
		pointer[0] = 5; pointer[1] = 0;
		wr16(pointer + 2, (uint16_t)r->pointer_x);
		wr16(pointer + 4, (uint16_t)r->pointer_y);
		e = send_all(r, pointer, sizeof(pointer));
	}
	r->held_count = 0;
	pthread_mutex_unlock(&r->write_lock);
	return e;
}

static size_t put_pointer(uint8_t *p, uint8_t mask, int x, int y)
{
	p[0] = 5;
	p[1] = mask;
	wr16(p + 2, (uint16_t)x);
	wr16(p + 4, (uint16_t)y);
	return 6;
}

int vnc_relay_mouse(vnc_relay *r, int x, int y, int button, short wheel)
{
	uint8_t messages[6 * (1 + 2 * VNC_MAX_WHEEL_STEPS)];
	size_t length = 0;
	int w, h, e;
	if (r == NULL) { return VNC_RELAY_E_ARG; }
	if (button == 0x88) { return relay_failed(r); }	// Double-click marker; both clicks were already sent

	pthread_mutex_lock(&r->fb_lock);
	w = r->width;
	h = r->height;
	pthread_mutex_unlock(&r->fb_lock);
	if (x < 0 || w <= 0) { x = 0; } else if (x >= w) { x = w - 1; }
	if (y < 0 || h <= 0) { y = 0; } else if (y >= h) { y = h - 1; }

	pthread_mutex_lock(&r->write_lock);
	switch (button)
	{
		case 0x02: r->buttons |= 0x01; break;					// Left down
		case 0x04: r->buttons &= (uint8_t)~0x01; break;			// Left up
		case 0x08: r->buttons |= 0x04; break;					// Right down
		case 0x10: r->buttons &= (uint8_t)~0x04; break;			// Right up
		case 0x20: r->buttons |= 0x02; break;					// Middle down
		case 0x40: r->buttons &= (uint8_t)~0x02; break;			// Middle up
		default: break;											// Move only
	}
	r->pointer_x = x;
	r->pointer_y = y;
	length += put_pointer(messages + length, r->buttons, x, y);

	if (wheel != 0)
	{
		// RFB buttons 4 and 5 are one wheel step up and down.
		int total = r->wheel_rest + (int)wheel;
		int steps = total / VNC_WHEEL_DELTA;
		r->wheel_rest = total % VNC_WHEEL_DELTA;
		if (steps > VNC_MAX_WHEEL_STEPS || steps < -VNC_MAX_WHEEL_STEPS)
		{
			steps = steps > 0 ? VNC_MAX_WHEEL_STEPS : -VNC_MAX_WHEEL_STEPS;
			r->wheel_rest = 0;
		}
		uint8_t notch = steps > 0 ? 0x08 : 0x10;
		for (int i = 0; i < abs(steps); ++i)
		{
			length += put_pointer(messages + length, r->buttons | notch, x, y);
			length += put_pointer(messages + length, r->buttons, x, y);
		}
	}
	e = send_all(r, messages, length);
	pthread_mutex_unlock(&r->write_lock);
	return e;
}

uint32_t vnc_relay_vk_to_keysym(unsigned char vk)
{
	if (vk >= 0x30 && vk <= 0x39) { return vk; }							// VK_0..VK_9 -> '0'..'9'
	if (vk >= 0x41 && vk <= 0x5A) { return (uint32_t)vk + 0x20; }			// VK_A..VK_Z -> 'a'..'z'
	if (vk >= 0x60 && vk <= 0x69) { return 0xFFB0 + (uint32_t)(vk - 0x60); }	// VK_NUMPAD0..9 -> KP_0..9
	if (vk >= 0x70 && vk <= 0x87) { return 0xFFBE + (uint32_t)(vk - 0x70); }	// VK_F1..VK_F24 -> F1..F24
	switch (vk)
	{
		case 0x08: return 0xFF08;	// VK_BACK -> BackSpace
		case 0x09: return 0xFF09;	// VK_TAB -> Tab
		case 0x0C: return 0xFF0B;	// VK_CLEAR -> Clear
		case 0x0D: return 0xFF0D;	// VK_RETURN -> Return
		case 0x10: return 0xFFE1;	// VK_SHIFT -> Shift_L
		case 0x11: return 0xFFE3;	// VK_CONTROL -> Control_L
		case 0x12: return 0xFFE9;	// VK_MENU -> Alt_L (Option)
		case 0x13: return 0xFF13;	// VK_PAUSE -> Pause
		case 0x14: return 0xFFE5;	// VK_CAPITAL -> Caps_Lock
		case 0x1B: return 0xFF1B;	// VK_ESCAPE -> Escape
		case 0x20: return 0x0020;	// VK_SPACE -> space
		case 0x21: return 0xFF55;	// VK_PRIOR -> Page_Up
		case 0x22: return 0xFF56;	// VK_NEXT -> Page_Down
		case 0x23: return 0xFF57;	// VK_END -> End
		case 0x24: return 0xFF50;	// VK_HOME -> Home
		case 0x25: return 0xFF51;	// VK_LEFT -> Left
		case 0x26: return 0xFF52;	// VK_UP -> Up
		case 0x27: return 0xFF53;	// VK_RIGHT -> Right
		case 0x28: return 0xFF54;	// VK_DOWN -> Down
		case 0x29: return 0xFF60;	// VK_SELECT -> Select
		case 0x2A: return 0xFF61;	// VK_PRINT -> Print
		case 0x2B: return 0xFF62;	// VK_EXECUTE -> Execute
		case 0x2C: return 0xFF61;	// VK_SNAPSHOT -> Print
		case 0x2D: return 0xFF63;	// VK_INSERT -> Insert
		case 0x2E: return 0xFFFF;	// VK_DELETE -> Delete
		case 0x2F: return 0xFF6A;	// VK_HELP -> Help
		case 0x5B: return 0xFFEB;	// VK_LWIN -> Super_L (Command)
		case 0x5C: return 0xFFEC;	// VK_RWIN -> Super_R (Command)
		case 0x5D: return 0xFF67;	// VK_APPS -> Menu
		case 0x6A: return 0xFFAA;	// VK_MULTIPLY -> KP_Multiply
		case 0x6B: return 0xFFAB;	// VK_ADD -> KP_Add
		case 0x6C: return 0xFFAC;	// VK_SEPARATOR -> KP_Separator
		case 0x6D: return 0xFFAD;	// VK_SUBTRACT -> KP_Subtract
		case 0x6E: return 0xFFAE;	// VK_DECIMAL -> KP_Decimal
		case 0x6F: return 0xFFAF;	// VK_DIVIDE -> KP_Divide
		case 0x90: return 0xFF7F;	// VK_NUMLOCK -> Num_Lock
		case 0x91: return 0xFF14;	// VK_SCROLL -> Scroll_Lock
		case 0xA0: return 0xFFE1;	// VK_LSHIFT -> Shift_L
		case 0xA1: return 0xFFE2;	// VK_RSHIFT -> Shift_R
		case 0xA2: return 0xFFE3;	// VK_LCONTROL -> Control_L
		case 0xA3: return 0xFFE4;	// VK_RCONTROL -> Control_R
		case 0xA4: return 0xFFE9;	// VK_LMENU -> Alt_L
		case 0xA5: return 0xFFEA;	// VK_RMENU -> Alt_R
		case 0xBA: return 0x003B;	// VK_OEM_1 -> semicolon
		case 0xBB: return 0x003D;	// VK_OEM_PLUS -> equal
		case 0xBC: return 0x002C;	// VK_OEM_COMMA -> comma
		case 0xBD: return 0x002D;	// VK_OEM_MINUS -> minus
		case 0xBE: return 0x002E;	// VK_OEM_PERIOD -> period
		case 0xBF: return 0x002F;	// VK_OEM_2 -> slash
		case 0xC0: return 0x0060;	// VK_OEM_3 -> grave
		case 0xDB: return 0x005B;	// VK_OEM_4 -> bracketleft
		case 0xDC: return 0x005C;	// VK_OEM_5 -> backslash
		case 0xDD: return 0x005D;	// VK_OEM_6 -> bracketright
		case 0xDE: return 0x0027;	// VK_OEM_7 -> apostrophe
		case 0xE2: return 0x003C;	// VK_OEM_102 -> less (ISO key)
		default: return 0;
	}
}

uint32_t vnc_relay_unicode_to_keysym(uint16_t unicode)
{
	switch (unicode)
	{
		case 0x08: return 0xFF08;	// BackSpace
		case 0x09: return 0xFF09;	// Tab
		case 0x0A:
		case 0x0D: return 0xFF0D;	// Return
		case 0x1B: return 0xFF1B;	// Escape
		case 0x7F: return 0xFFFF;	// Delete
		default: break;
	}
	if (unicode < 0x20 || (unicode >= 0x80 && unicode < 0xA0)) { return 0; }	// Other control characters
	if (unicode >= 0xD800 && unicode <= 0xDFFF) { return 0; }					// Lone surrogates
	if (unicode <= 0xFF) { return unicode; }									// Latin-1 keysyms equal the code point
	return 0x01000000 | unicode;												// Unicode keysym
}
