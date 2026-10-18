// Tracks the mouse buttons one KVM session has handed to its input injector and not released, so
// that ending the session can release exactly those. It is fed the MOUSE packets the session
// actually delivered; it never reads the physical button state, so a button the local user holds is
// never released. Platform-free: the callers own locking and delivery.
//
// MOUSE packet: [0-1] type 2, [2-3] size 10 (or 12 with a wheel delta), [4] unused, [5] button
// byte, [6-7] x, [8-9] y, all big-endian. Button bytes: down 0x02/0x08/0x20, up 0x04/0x10/0x40;
// 0x88 marks a double click, which the agents ignore.

#ifndef MESHCORE_KVM_POINTER_RELEASE_H
#define MESHCORE_KVM_POINTER_RELEASE_H

#include <stddef.h>

#define KVM_POINTER_RELEASE_PACKET_SIZE 10
#define KVM_POINTER_RELEASE_MAX_PACKETS 3

typedef struct KvmPointerTrack
{
	unsigned char held;		// down bytes (0x02, 0x08, 0x20) currently pressed
	unsigned short x;		// last position delivered
	unsigned short y;
} KvmPointerTrack;

static const unsigned char kvm_pointer_buttons[KVM_POINTER_RELEASE_MAX_PACKETS][2] = { { 0x02, 0x04 }, { 0x08, 0x10 }, { 0x20, 0x40 } };

static void kvm_pointer_track_reset(KvmPointerTrack* track)
{
	if (track == NULL) { return; }
	track->held = 0;
	track->x = 0;
	track->y = 0;
}

// Record one delivered packet. Returns 1 when it was a MOUSE packet the agents act on, else 0.
static int kvm_pointer_track_packet(KvmPointerTrack* track, const char* buffer, int bufferLen)
{
	const unsigned char* p = (const unsigned char*)buffer;
	unsigned short type, size;
	unsigned char button;
	int i;

	if (track == NULL || buffer == NULL || bufferLen < KVM_POINTER_RELEASE_PACKET_SIZE) { return 0; }
	type = (unsigned short)((p[0] << 8) | p[1]);
	size = (unsigned short)((p[2] << 8) | p[3]);
	if (type != 2 || (size != 10 && size != 12) || bufferLen < (int)size) { return 0; }
	button = p[5];
	if (button == 0x88) { return 1; }
	track->x = (unsigned short)((p[6] << 8) | p[7]);
	track->y = (unsigned short)((p[8] << 8) | p[9]);
	for (i = 0; i < KVM_POINTER_RELEASE_MAX_PACKETS; ++i)
	{
		if (button & kvm_pointer_buttons[i][0]) { track->held = (unsigned char)(track->held | kvm_pointer_buttons[i][0]); }
		if (button & kvm_pointer_buttons[i][1]) { track->held = (unsigned char)(track->held & ~kvm_pointer_buttons[i][0]); }
	}
	return 1;
}

// Build one up packet per held button that is not in alsoHeldElsewhere (down bytes another live
// session still holds), at the last delivered position. Returns the number of packets written.
static int kvm_pointer_track_release_packets(const KvmPointerTrack* track, unsigned char alsoHeldElsewhere, char packets[KVM_POINTER_RELEASE_MAX_PACKETS][KVM_POINTER_RELEASE_PACKET_SIZE])
{
	int i, count = 0;

	if (track == NULL || packets == NULL) { return 0; }
	for (i = 0; i < KVM_POINTER_RELEASE_MAX_PACKETS; ++i)
	{
		unsigned char down = kvm_pointer_buttons[i][0];
		unsigned char* out = (unsigned char*)packets[count];
		if ((track->held & down) == 0 || (alsoHeldElsewhere & down) != 0) { continue; }
		out[0] = 0x00; out[1] = 0x02; out[2] = 0x00; out[3] = KVM_POINTER_RELEASE_PACKET_SIZE;
		out[4] = 0x00; out[5] = kvm_pointer_buttons[i][1];
		out[6] = (unsigned char)(track->x >> 8); out[7] = (unsigned char)(track->x & 0xFF);
		out[8] = (unsigned char)(track->y >> 8); out[9] = (unsigned char)(track->y & 0xFF);
		++count;
	}
	return count;
}

#endif
