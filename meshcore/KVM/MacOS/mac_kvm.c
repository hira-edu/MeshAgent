/*
Copyright 2010 - 2018 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * macOS remote desktop relays Apple Screen Sharing (screensharingd) on loopback.
 *
 * The agent starts one root-owned helper (-kvm0) per session. The helper reads
 * the VNC credential that installation stored beside the executable, checks that
 * only root holds the Screen Sharing port, and translates between the RFB
 * session and the MeshCentral tile protocol on stdin/stdout. screensharingd owns
 * capture, input, the login window and user switching, so there is no other
 * capture or input path: any failure ends the session with a visible reason.
 */

#include "mac_kvm.h"
#include "mac_vnc_relay.h"
#include "../../meshdefines.h"
#include "../../meshinfo.h"
#include "../../../microstack/ILibParsers.h"
#include "../../../microstack/ILibProcessPipe.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/stat.h>

#define MAC_KVM_RELAY_SECRET		"vncrelay.secret"
#define MAC_KVM_RELAY_SECRET_MAX	8		// VNC authentication uses at most eight password bytes
#define MAC_KVM_RELAY_TIMEOUT_MS	5000
#define MAC_KVM_FRAME_MS			100
#define MAC_KVM_MAX_DRAIN			32		// Server messages applied before the next tile pass

#define MAC_KVM_SECRET_OK			0
#define MAC_KVM_SECRET_MISSING		-1
#define MAC_KVM_SECRET_UNSAFE		-2
#define MAC_KVM_SECRET_INVALID		-3

#define MAC_KVM_LISTENER_ROOT		1
#define MAC_KVM_LISTENER_NONE		0
#define MAC_KVM_LISTENER_FOREIGN	-1
#define MAC_KVM_LISTENER_ERROR		-2

int KVM_SEND(char *buffer, int bufferLen)
{
    int sent = 0;
    if (bufferLen < 0) { errno = EINVAL; return -1; }
    while (sent < bufferLen)
    {
        ssize_t count = write(STDOUT_FILENO, buffer + sent, (size_t)(bufferLen - sent));
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { if (count == 0) { errno = EIO; } return -1; }
        sent += (int)count;
    }
    return sent;
}


int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
struct tileInfo_t **g_tileInfo = NULL;
static atomic_int g_remotepause = 0;
static atomic_int g_shutdown = 0;
static atomic_int g_refresh = 0;
static vnc_relay *g_relay = NULL;
static uint8_t *g_desktop = NULL;
static size_t g_desktopSize = 0;
extern void* tilebuffer;
ILibProcessPipe_Process gChildProcess;
ILibQueue g_messageQ;

void kvm_send_resolution()
{
	char *buffer = ILibMemory_SmartAllocate(8);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);	// Y position

	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}

static void MacKvm_FlushMessages(void)
{
	char *buf;
	ILibQueue_Lock(g_messageQ);
	while (ILibQueue_IsEmpty(g_messageQ) == 0)
	{
		if ((buf = (char*)ILibQueue_DeQueue(g_messageQ)) != NULL)
		{
			KVM_SEND(buf, (int)ILibMemory_Size(buf));
			ILibMemory_Free(buf);
		}
	}
	ILibQueue_UnLock(g_messageQ);
}

// Shows the reason in the viewer's desktop message bar.
static void MacKvm_SendMessage(const char *message)
{
	unsigned char packet[512];
	size_t length = strlen(message);
	if (length > sizeof(packet) - 4) { length = sizeof(packet) - 4; }
	packet[0] = 0;
	packet[1] = MNG_KVM_MESSAGE;
	packet[2] = (unsigned char)((length + 4) >> 8);
	packet[3] = (unsigned char)(length + 4);
	memcpy(packet + 4, message, length);
	KVM_SEND((char*)packet, (int)length + 4);
}

static int MacKvm_ExecutableDirectory(char *path, size_t capacity)
{
	char image[PATH_MAX], resolved[PATH_MAX];
	uint32_t size = sizeof(image);
	char *slash;
	if (_NSGetExecutablePath(image, &size) != 0 || realpath(image, resolved) == NULL) { return -1; }
	if ((slash = strrchr(resolved, '/')) == NULL) { return -1; }
	if (slash == resolved) { slash[1] = 0; } else { *slash = 0; }
	return strlcpy(path, resolved, capacity) < capacity ? 0 : -1;
}

// Installation stores the Screen Sharing VNC password beside the executable. The
// directory and file must be root-owned and closed to other accounts, and the file
// must be a regular, singly linked file, so no other account can substitute it.
int MacKvm_ReadRelaySecret(const char *directory, char *password, size_t capacity)
{
	char buffer[MAC_KVM_RELAY_SECRET_MAX + 3];
	struct stat info;
	ssize_t count;
	size_t length, i;
	int dir = -1, fd = -1, result = MAC_KVM_SECRET_INVALID;

	if (password == NULL || capacity < MAC_KVM_RELAY_SECRET_MAX + 1) { return MAC_KVM_SECRET_INVALID; }
	password[0] = 0;
	if ((dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) { result = MAC_KVM_SECRET_UNSAFE; goto done; }
	if (fstat(dir, &info) != 0 || info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) { result = MAC_KVM_SECRET_UNSAFE; goto done; }
	if ((fd = openat(dir, MAC_KVM_RELAY_SECRET, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)) < 0)
	{
		result = errno == ENOENT ? MAC_KVM_SECRET_MISSING : MAC_KVM_SECRET_UNSAFE;
		goto done;
	}
	if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0 || info.st_nlink != 1)
	{
		result = MAC_KVM_SECRET_UNSAFE;
		goto done;
	}
	do { count = read(fd, buffer, sizeof(buffer)); } while (count < 0 && errno == EINTR);
	if (count <= 0) { goto done; }
	length = (size_t)count;
	if (buffer[length - 1] == '\n') { --length; }
	if (length == 0 || length > MAC_KVM_RELAY_SECRET_MAX) { goto done; }
	for (i = 0; i < length; ++i) { if ((unsigned char)buffer[i] < 0x20 || (unsigned char)buffer[i] > 0x7E) { goto done; } }
	memcpy(password, buffer, length);
	password[length] = 0;
	result = MAC_KVM_SECRET_OK;

done:
	memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
	if (fd >= 0) { close(fd); }
	if (dir >= 0) { close(dir); }
	return result;
}

// screensharingd is socket-activated by launchd, so while Screen Sharing is on only
// root processes hold the port. When it is off, any account could listen there and
// collect the VNC authentication exchange, so every process holding a listener on the
// port must run entirely as root. Socket info reports no owner, so the holding
// process's credentials are checked. Other accounts' descriptors are only visible to root.
int MacKvm_RelayListener(uint16_t port)
{
	pid_t *pids = NULL;
	struct proc_fdinfo *fds = NULL;
	int fdCapacity = 0, found = 0, foreign = 0;
	int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	if (bytes <= 0) { return MAC_KVM_LISTENER_ERROR; }
	bytes += 64 * (int)sizeof(pid_t);
	if ((pids = (pid_t*)malloc((size_t)bytes)) == NULL) { return MAC_KVM_LISTENER_ERROR; }
	if ((bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes)) <= 0) { free(pids); return MAC_KVM_LISTENER_ERROR; }

	for (int p = 0; p < bytes / (int)sizeof(pid_t); ++p)
	{
		if (pids[p] <= 0) { continue; }
		int size = proc_pidinfo(pids[p], PROC_PIDLISTFDS, 0, NULL, 0);
		if (size <= 0) { continue; }	// Exited, or holds no descriptors
		size += 32 * (int)PROC_PIDLISTFD_SIZE;	// Room for descriptors opened before the second call
		if (size > fdCapacity)
		{
			struct proc_fdinfo *grown = (struct proc_fdinfo*)realloc(fds, (size_t)size);
			if (grown == NULL) { foreign = 1; break; }
			fds = grown;
			fdCapacity = size;
		}
		if ((size = proc_pidinfo(pids[p], PROC_PIDLISTFDS, 0, fds, fdCapacity)) <= 0) { continue; }
		int listening = 0;
		for (int i = 0; i < size / (int)PROC_PIDLISTFD_SIZE && !listening; ++i)
		{
			struct socket_fdinfo socket;
			if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) { continue; }
			if (proc_pidfdinfo(pids[p], fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != (int)sizeof(socket)) { continue; }
			if (socket.psi.soi_kind != SOCKINFO_TCP || socket.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) { continue; }
			listening = ntohs((uint16_t)socket.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport) == port;
		}
		if (!listening) { continue; }
		struct proc_bsdinfo owner;
		// A holder whose credentials cannot be read is treated as foreign.
		if (proc_pidinfo(pids[p], PROC_PIDTBSDINFO, 0, &owner, sizeof(owner)) == (int)sizeof(owner) &&
			owner.pbi_uid == 0 && owner.pbi_ruid == 0 && owner.pbi_svuid == 0) { found = 1; }
		else { foreign = 1; }
	}
	free(fds);
	free(pids);
	return foreign ? MAC_KVM_LISTENER_FOREIGN : (found ? MAC_KVM_LISTENER_ROOT : MAC_KVM_LISTENER_NONE);
}

static vnc_relay* MacKvm_OpenRelay(char *reason, size_t capacity)
{
	char directory[PATH_MAX], password[MAC_KVM_RELAY_SECRET_MAX + 1];
	vnc_relay *relay = NULL;
	int error = VNC_RELAY_OK;

	if (geteuid() != 0) { strlcpy(reason, "Remote desktop requires the agent to run as the root service.", capacity); return NULL; }
	if (MacKvm_ExecutableDirectory(directory, sizeof(directory)) != 0) { strlcpy(reason, "Remote desktop could not locate the agent installation.", capacity); return NULL; }
	switch (MacKvm_ReadRelaySecret(directory, password, sizeof(password)))
	{
		case MAC_KVM_SECRET_OK:
			break;
		case MAC_KVM_SECRET_MISSING:
			strlcpy(reason, "Remote desktop is not set up on this Mac: the Screen Sharing credential is missing. Reinstall the agent to enable it.", capacity);
			return NULL;
		case MAC_KVM_SECRET_UNSAFE:
			strlcpy(reason, "Remote desktop is disabled: the Screen Sharing credential has unsafe ownership or permissions.", capacity);
			return NULL;
		default:
			strlcpy(reason, "Remote desktop is disabled: the Screen Sharing credential is invalid.", capacity);
			return NULL;
	}

	switch (MacKvm_RelayListener(VNC_RELAY_DEFAULT_PORT))
	{
		case MAC_KVM_LISTENER_ROOT:
			relay = vnc_relay_open(VNC_RELAY_DEFAULT_PORT, password, MAC_KVM_RELAY_TIMEOUT_MS, &error);
			if (relay == NULL) { snprintf(reason, capacity, "Remote desktop is unavailable: %s.", vnc_relay_strerror(error)); }
			break;
		case MAC_KVM_LISTENER_NONE:
			strlcpy(reason, "Remote desktop is unavailable: Screen Sharing is turned off on this Mac.", capacity);
			break;
		case MAC_KVM_LISTENER_FOREIGN:
			strlcpy(reason, "Remote desktop is disabled: a process not owned by root is listening on the Screen Sharing port.", capacity);
			break;
		default:
			strlcpy(reason, "Remote desktop is unavailable: the Screen Sharing listener could not be verified.", capacity);
			break;
	}
	memset_s(password, sizeof(password), 0, sizeof(password));
	return relay;
}

// Adopts the relay's framebuffer size; the viewer's coordinates are framebuffer pixels.
static int kvm_init(void)
{
	int old_height_count = TILE_HEIGHT_COUNT, width, height;
	if (vnc_relay_size(g_relay, &width, &height) != VNC_RELAY_OK) { return -1; }

	SCREEN_WIDTH = width;
	SCREEN_HEIGHT = height;
	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	COMPRESSION_RATIO = 50;
	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH) { TILE_WIDTH_COUNT++; }
	if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }

	// Tiles read whole 32-pixel blocks, so the buffer is padded to tile multiples and kept zeroed there.
	free(g_desktop);
	g_desktopSize = (size_t)adjust_screen_size(SCREEN_WIDTH) * (size_t)adjust_screen_size(SCREEN_HEIGHT) * 3;
	if ((g_desktop = (uint8_t*)calloc(1, g_desktopSize)) == NULL) { g_desktopSize = 0; return -1; }

	reset_tile_info(old_height_count);
	kvm_send_resolution();
	return 0;
}

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ((unsigned short)(unsigned char)block[0] << 8) | (unsigned char)block[1];
	size = ((unsigned short)(unsigned char)block[2] << 8) | (unsigned char)block[3];

	if (size > blocklen) return 0;
	if (size < 4) return -1; // Stop this stream; its packet boundary is no longer trustworthy.

	switch (type)
	{
		case MNG_KVM_KEY_UNICODE: // Unicode Key
		{
			if (size != 7) break;
			// Actions 0 and 4 are key down. The character is typed as a press and release on
			// key down, so a lost key-up message cannot leave it held.
			if (block[4] != 0 && block[4] != 4) break;
			uint32_t keysym = vnc_relay_unicode_to_keysym((uint16_t)((((unsigned char)block[5]) << 8) | (unsigned char)block[6]));
			if (keysym == 0) break;
			if (vnc_relay_key(g_relay, keysym, 1) == VNC_RELAY_OK) { vnc_relay_key(g_relay, keysym, 0); }
			break;
		}
		case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			uint32_t keysym = vnc_relay_vk_to_keysym((unsigned char)block[5]);
			if (keysym != 0) { vnc_relay_key(g_relay, keysym, block[4] == 0 || block[4] == 4); }
			break;
		}
		case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (size == 10 || size == 12)
			{
				x = ((int)(unsigned char)block[6] << 8) | (unsigned char)block[7];
				y = ((int)(unsigned char)block[8] << 8) | (unsigned char)block[9];
				if (size == 12) w = (short)(((unsigned int)(unsigned char)block[10] << 8) | (unsigned char)block[11]);
				vnc_relay_mouse(g_relay, x, y, (int)(unsigned char)(block[5]), w);
			}
			break;
		}
		case MNG_KVM_COMPRESSION: // Compression
		{
			if (size != 6) break;
			set_tile_compression((int)block[4], (int)block[5]);
			COMPRESSION_RATIO = 100;
			break;
		}
		case MNG_KVM_REFRESH: // Refresh
		{
			// The main loop owns the tile state; it resends the resolution and every tile.
			if (size == 4) { g_refresh = 1; }
			break;
		}
		case MNG_KVM_PAUSE: // Pause
		{
			if (size != 5) break;
			g_remotepause = block[4];
			break;
		}
	}

	return size;
}


int kvm_relay_feeddata(char* buf, int len)
{
	if (gChildProcess == NULL) { return 0; }
	ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
	return(len);
}

// Viewer flow control is applied to the helper's output pipe by the agent.
void kvm_pause(int pause)
{
	UNREFERENCED_PARAMETER(pause);
}


void* kvm_mainloopinput(void* param)
{
    unsigned char buffer[65535];
    size_t length = 0;
    UNREFERENCED_PARAMETER(param);
    while (!g_shutdown)
    {
        struct pollfd pending = { STDIN_FILENO, POLLIN, 0 };
        int ready = poll(&pending, 1, 100);
        if (ready < 0 && errno == EINTR) { continue; }
        if (ready < 0 || (pending.revents & (POLLERR | POLLNVAL))) { break; }
        if (ready == 0) { continue; }
        ssize_t count = read(STDIN_FILENO, buffer + length, sizeof(buffer) - length);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) { continue; }
        if (count <= 0) { break; }
        length += (size_t)count;
        size_t consumed = 0;
        while (consumed < length)
        {
            int size = kvm_server_inputdata((char*)buffer + consumed, (int)(length - consumed));
            if (size < 0 || (size_t)size > length - consumed) { goto disconnected; }
            if (size == 0) { break; }
            consumed += (size_t)size;
        }
        if (consumed)
        {
            length -= consumed;
            memmove(buffer, buffer + consumed, length);
        }
        if (length == sizeof(buffer)) { break; }
    }
disconnected:
    g_shutdown = 1;
    return NULL;
}

// Encodes and sends every changed tile of the current framebuffer copy.
static int MacKvm_SendTiles(void)
{
	void *buf = NULL;
	long long tilesize = 0;
	int x, y, r, c;

	for (r = 0; r < TILE_HEIGHT_COUNT; r++)
	{
		for (c = 0; c < TILE_WIDTH_COUNT; c++) { g_tileInfo[r][c].flag = TILE_TODO; }
	}
	for (y = 0; y < TILE_HEIGHT_COUNT && !g_shutdown; y++)
	{
		for (x = 0; x < TILE_WIDTH_COUNT && !g_shutdown; x++)
		{
			if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND) { continue; }
			getTileAt(TILE_WIDTH * x, TILE_HEIGHT * y, &buf, &tilesize, g_desktop, (long long)g_desktopSize, y, x);
			if (buf != NULL)
			{
				int written = KVM_SEND(buf, (int)tilesize);
				free(buf);
				buf = NULL;
				if (written == -1) { return -1; }
			}
		}
	}
	return 0;
}

void* kvm_server_mainloop(void* param)
{
	char reason[256];
	pthread_t input;
	int inputStarted = 0, ready = 0, dirty = 0, failed = 1, r, c;
	UNREFERENCED_PARAMETER(param);

	ILibCriticalLogFilename = "KVMSlave.log";
	signal(SIGPIPE, SIG_IGN);
	g_shutdown = 0;
	g_messageQ = ILibQueue_Create();

	if ((g_relay = MacKvm_OpenRelay(reason, sizeof(reason))) == NULL) { MacKvm_SendMessage(reason); goto done; }
	if (kvm_init() != 0) { MacKvm_SendMessage("Remote desktop could not allocate the screen buffer."); goto done; }
	if (pthread_create(&input, NULL, kvm_mainloopinput, NULL) != 0) { MacKvm_SendMessage("Remote desktop could not start its input thread."); goto done; }
	inputStarted = 1;

	while (!g_shutdown)
	{
		MacKvm_FlushMessages();

		int flags = vnc_relay_pump(g_relay, MAC_KVM_FRAME_MS);
		for (int i = 0; flags > 0 && i < MAC_KVM_MAX_DRAIN; ++i)
		{
			int more = vnc_relay_pump(g_relay, 0);
			if (more == 0) { break; }
			flags = more < 0 ? more : (flags | more);
		}
		if (flags < 0)
		{
			if (!g_shutdown)
			{
				snprintf(reason, sizeof(reason), "Remote desktop ended: %s.", vnc_relay_strerror(flags));
				MacKvm_FlushMessages();
				MacKvm_SendMessage(reason);
			}
			break;
		}

		if ((flags & VNC_RELAY_RESIZED) && kvm_init() != 0)
		{
			MacKvm_SendMessage("Remote desktop could not allocate the screen buffer.");
			break;
		}
		if (flags & VNC_RELAY_UPDATED) { ready = dirty = 1; }
		if (g_refresh)
		{
			g_refresh = 0;
			kvm_send_resolution();
			for (r = 0; r < TILE_HEIGHT_COUNT; r++)
			{
				for (c = 0; c < TILE_WIDTH_COUNT; c++) { g_tileInfo[r][c].crc = 0xFF; g_tileInfo[r][c].flag = TILE_TODO; }
			}
			dirty = 1;
		}
		// Hold tiles until Screen Sharing delivers its first full frame, and while the viewer is paused.
		if (!ready || !dirty || g_remotepause) { continue; }

		int width, height;
		if (vnc_relay_copy_rgb24(g_relay, g_desktop, g_desktopSize, (size_t)adjust_screen_size(SCREEN_WIDTH) * 3, &width, &height) != VNC_RELAY_OK) { continue; }
		if (width != SCREEN_WIDTH || height != SCREEN_HEIGHT) { continue; }
		dirty = 0;
		MacKvm_FlushMessages();
		if (MacKvm_SendTiles() != 0) { break; }
	}
	failed = 0;

done:
	g_shutdown = 1;
	if (g_relay != NULL) { vnc_relay_shutdown(g_relay); }
	if (inputStarted) { pthread_join(input, NULL); }
	vnc_relay_close(g_relay);
	g_relay = NULL;

	if (g_tileInfo != NULL)
	{
		for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); }
		free(g_tileInfo);
		g_tileInfo = NULL;
	}
	free(g_desktop);
	g_desktop = NULL;
	g_desktopSize = 0;
	if (tilebuffer != NULL)
	{
		free(tilebuffer);
		tilebuffer = NULL;
	}
	ILibQueue_Destroy(g_messageQ);
	return (void*)(intptr_t)failed;
}

void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	UNREFERENCED_PARAMETER(exitCode);
	if (user == NULL) { return; }
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
	void *reserved = ((void**)user)[1];
	int active = gChildProcess == sender;
	if (active) { gChildProcess = NULL; }
	// Pipe teardown can still deliver callbacks before deferred process destruction.
	ILibProcessPipe_Process_UpdateUserObject(sender, NULL);
	ILibMemory_Free(user);
	if (active && writeHandler != NULL) { writeHandler(NULL, 0, reserved); }
}
void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
    if (user == NULL) { *bytesConsumed = bufferLen; return; }
    size_t length = 0;
    int frame = MacKvm_FrameLength((const unsigned char*)buffer, bufferLen, &length);
    ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)user)[0];
    void *reserved = ((void**)user)[1];
    *bytesConsumed = 0;
    if (frame > 0)
    {
        *bytesConsumed = length;
        writeHandler(buffer, (int)length, reserved);
    }
    else if (frame < 0)
    {
        *bytesConsumed = bufferLen;
        ILibProcessPipe_Process_SoftKill(sender);
    }
}
void kvm_relay_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(user);
	*bytesConsumed = bufferLen;
}

// Starts the relay helper with the agent's own credentials. It must stay root to read
// the Screen Sharing credential, and it serves the login window and every user alike.
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved)
{
    if (exePath == NULL || exePath[0] != '/' || processPipeMgr == NULL || writeHandler == NULL) { return NULL; }
    char *args[] = { exePath, "-kvm0", NULL };
    void **user = (void**)ILibMemory_Allocate(2 * sizeof(void*), 0, NULL, NULL);
    user[0] = writeHandler;
    user[1] = reserved;

    gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx3(processPipeMgr, exePath, args, ILibProcessPipe_SpawnTypes_DEFAULT, NULL, 0);
    if (gChildProcess == NULL) { ILibMemory_Free(user); return NULL; }
    char metadata[64];
    snprintf(metadata, sizeof(metadata), "Screen Sharing relay (pid: %d)", ILibProcessPipe_Process_GetPID(gChildProcess));
    ILibProcessPipe_Process_ResetMetadata(gChildProcess, metadata);
    ILibProcessPipe_Process_AddHandlers(gChildProcess, 65535, &kvm_relay_ExitHandler, &kvm_relay_StdOutHandler, &kvm_relay_StdErrHandler, NULL, user);
    return ILibProcessPipe_Process_GetStdOut(gChildProcess);
}

// Force a KVM reset & refresh
void kvm_relay_reset()
{
	char buffer[4];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size
	kvm_relay_feeddata(buffer, 4);
}

// Clean up the KVM session.
void kvm_cleanup()
{
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
}
