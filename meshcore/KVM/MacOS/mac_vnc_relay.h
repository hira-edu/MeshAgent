/*
 * RFB client for relaying Apple Screen Sharing (screensharingd) on loopback.
 *
 * Threading: one thread calls vnc_relay_pump(); any thread may send input or
 * copy the framebuffer. To stop, call vnc_relay_shutdown() to unblock the pump
 * thread, join it, then vnc_relay_close().
 */
#ifndef MAC_VNC_RELAY_H_
#define MAC_VNC_RELAY_H_

#include <stddef.h>
#include <stdint.h>

#define VNC_RELAY_DEFAULT_PORT	5900

#define VNC_RELAY_OK			0
#define VNC_RELAY_E_CONNECT		-1	// Nothing listening, or connect failed
#define VNC_RELAY_E_PROTOCOL	-2	// Server sent something malformed or unexpected
#define VNC_RELAY_E_AUTH		-3	// Server rejected the credentials
#define VNC_RELAY_E_UNSUPPORTED	-4	// No common RFB version or security type
#define VNC_RELAY_E_CLOSED		-5	// Connection closed or shut down
#define VNC_RELAY_E_TIMEOUT		-6	// Server stalled inside a message or handshake
#define VNC_RELAY_E_NOMEM		-7
#define VNC_RELAY_E_ARG			-8
#define VNC_RELAY_E_PEER		-9	// The peer check refused the server process

// vnc_relay_pump() result flags
#define VNC_RELAY_UPDATED		1	// Framebuffer contents changed
#define VNC_RELAY_RESIZED		2	// Framebuffer dimensions changed

typedef struct vnc_relay vnc_relay;

// Called with the connected socket once the server's greeting arrives, before the client sends
// anything. Returns nonzero to refuse the connection.
typedef int (*vnc_relay_peer_check)(int fd, void *context);

// Connects to 127.0.0.1:port. With a password only VNC authentication is accepted; without one
// only None is. The password is not retained. peer_check may be NULL.
vnc_relay* vnc_relay_open(uint16_t port, const char *password, int io_timeout_ms, vnc_relay_peer_check peer_check, void *context, int *error);
// Releases every key and button this relay holds down. Call before shutdown so none stay held.
int vnc_relay_release_all(vnc_relay *relay);
void vnc_relay_shutdown(vnc_relay *relay);
void vnc_relay_close(vnc_relay *relay);
const char* vnc_relay_strerror(int error);

// Waits up to wait_ms for a server message and applies it. Returns VNC_RELAY_* flags, 0, or a negative error.
int vnc_relay_pump(vnc_relay *relay, int wait_ms);
int vnc_relay_size(vnc_relay *relay, int *width, int *height);
// Copies the framebuffer as packed RGB rows into dst; rows beyond the framebuffer are left untouched.
int vnc_relay_copy_rgb24(vnc_relay *relay, uint8_t *dst, size_t dst_size, size_t dst_stride, int *width, int *height);

int vnc_relay_key(vnc_relay *relay, uint32_t keysym, int down);
// x/y are framebuffer pixels; button uses the MeshCentral MOUSEEVENTF_* values. The viewer
// sends both clicks of a double click, so its 0x88 marker is ignored. Wheel deltas of 120 per
// step accumulate across calls, so small trackpad deltas are not rounded up to whole steps.
int vnc_relay_mouse(vnc_relay *relay, int x, int y, int button, short wheel);

uint32_t vnc_relay_vk_to_keysym(unsigned char vk);
uint32_t vnc_relay_unicode_to_keysym(uint16_t unicode);

#endif
