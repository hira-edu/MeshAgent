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

#include "mac_kvm.h"
#include "mac_hid.h"
#include "../../meshdefines.h"
#include "../../meshinfo.h"
#include "../../../microstack/ILibParsers.h"
#include "../../../microstack/ILibAsyncSocket.h"
#include "../../../microstack/ILibAsyncServerSocket.h"
#include "../../../microstack/ILibProcessPipe.h"
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDLib.h>
#include <IOKit/hidsystem/IOHIDParameter.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreServices/CoreServices.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <stdatomic.h>

int KVM_Listener_FD = -1;
#define KVM_Listener_Path "/usr/local/mesh_services/meshagent/kvm"
#if defined(_TLSLOG)
#define TLSLOG1 printf
#else
#define TLSLOG1(...) ;
#endif


int KVM_AGENT_FD = -1;
int KVM_SEND(char *buffer, int bufferLen)
{
    int fd = KVM_AGENT_FD == -1 ? STDOUT_FILENO : KVM_AGENT_FD;
    int sent = 0;
    if (bufferLen < 0) { errno = EINVAL; return -1; }
    while (sent < bufferLen)
    {
        ssize_t count = write(fd, buffer + sent, (size_t)(bufferLen - sent));
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { if (count == 0) { errno = EIO; } return -1; }
        sent += (int)count;
    }
    return sent;
}



CGDirectDisplayID SCREEN_NUM = 0;
int SH_HANDLE = 0;
int SCREEN_WIDTH = 0;
int SCREEN_HEIGHT = 0;
int SCREEN_SCALE = 1;
int SCREEN_SCALE_SET = 0;
int SCREEN_DEPTH = 0;
int TILE_WIDTH = 0;
int TILE_HEIGHT = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
int FRAME_RATE_TIMER = 0;
struct tileInfo_t **g_tileInfo = NULL;
int g_remotepause = 0;
int g_pause = 0;
static atomic_int g_shutdown = 0;
static atomic_int g_resetipc = 0;
int kvm_clientProcessId = 0;
int g_restartcount = 0;
int g_totalRestartCount = 0;
int restartKvm = 0;
extern void* tilebuffer;
pid_t g_slavekvm = 0;
pthread_t kvmthread = (pthread_t)NULL;
ILibProcessPipe_Process gChildProcess;
ILibQueue g_messageQ;

//int logenabled = 1;
//FILE *logfile = NULL;
//#define MASTERLOGFILE "/dev/null"
//#define SLAVELOGFILE "/dev/null"
//#define LOGFILE "/dev/null"


#define KvmDebugLog(...)
//#define KvmDebugLog(...) printf(__VA_ARGS__); if (logfile != NULL) fprintf(logfile, __VA_ARGS__);
//#define KvmDebugLog(x) if (logenabled) printf(x);
//#define KvmDebugLog(x) if (logenabled) fprintf(logfile, "Writing from slave in kvm_send_resolution\n");

void senddebug(int val)
{
	char *buffer = (char*)ILibMemory_SmartAllocate(8);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_DEBUG);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);			// Write the size
	((int*)buffer)[1] = val;

	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}



void kvm_send_resolution() 
{
	char *buffer = ILibMemory_SmartAllocate(8);
	
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCREEN_WIDTH);		// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCREEN_HEIGHT);	// Y position


	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
}

#define BUFSIZE 65535

int set_kbd_state(int input_state)
{
	int ret = 0;
	kern_return_t kr;
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// Set CAPSLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDCapsLockState, (input_state & 4) == 4);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// Set NUMLOCK
		kr = IOHIDSetModifierLockState(ioc, kIOHIDNumLockState, (input_state & 1) == 1);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}
int get_kbd_state()
{
	int ret = 0;
	kern_return_t kr;
	io_service_t ios;
	io_connect_t ioc;
	CFMutableDictionaryRef mdict;

	while (1)
	{
		mdict = IOServiceMatching(kIOHIDSystemClass);
		ios = IOServiceGetMatchingService(kIOMasterPortDefault, (CFDictionaryRef)mdict);
		if (!ios)
		{
			if (mdict)
			{
				CFRelease(mdict);
			}
			ILIBLOGMESSAGEX("IOServiceGetMatchingService() failed\n");
			break;
		}

		kr = IOServiceOpen(ios, mach_task_self(), kIOHIDParamConnectType, &ioc);
		IOObjectRelease(ios);
		if (kr != KERN_SUCCESS)
		{
			ILIBLOGMESSAGEX("IOServiceOpen() failed: %x\n", kr);
			break;
		}

		// CAPSLOCK_QUERY
		bool state;
		kr = IOHIDGetModifierLockState(ioc, kIOHIDCapsLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= (state << 2);

		// NUMLOCK_QUERY
		kr = IOHIDGetModifierLockState(ioc, kIOHIDNumLockState, &state);
		if (kr != KERN_SUCCESS)
		{
			IOServiceClose(ioc);
			ILIBLOGMESSAGEX("IOHIDGetModifierLockState() failed: %x\n", kr);
			break;
		}
		ret |= state;

		IOServiceClose(ioc);
		break;
	}
	return(ret);
}


int kvm_init()
{
	ILibCriticalLogFilename = "KVMSlave.log";
	int old_height_count = TILE_HEIGHT_COUNT;
	
	SCREEN_NUM = CGMainDisplayID();
	
	if (SCREEN_WIDTH > 0)
	{
		CGDisplayModeRef mode = CGDisplayCopyDisplayMode(SCREEN_NUM);
		SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
		if (SCREEN_SCALE < 1) SCREEN_SCALE = 1; // Guard against a 0 scale (would zero the screen dims and divide-by-zero in mouse scaling).
		CGDisplayModeRelease(mode);
	}

	SCREEN_HEIGHT = CGDisplayPixelsHigh(SCREEN_NUM) * SCREEN_SCALE;
	SCREEN_WIDTH = CGDisplayPixelsWide(SCREEN_NUM) * SCREEN_SCALE;
	// Some magic numbers.
	TILE_WIDTH = 32;
	TILE_HEIGHT = 32;
	COMPRESSION_RATIO = 50;
	FRAME_RATE_TIMER = 100;
	
	TILE_HEIGHT_COUNT = SCREEN_HEIGHT / TILE_HEIGHT;
	TILE_WIDTH_COUNT = SCREEN_WIDTH / TILE_WIDTH;
	if (SCREEN_WIDTH % TILE_WIDTH) { TILE_WIDTH_COUNT++; }
	if (SCREEN_HEIGHT % TILE_HEIGHT) { TILE_HEIGHT_COUNT++; }
	
	kvm_send_resolution();
	reset_tile_info(old_height_count);
	
	unsigned char *buffer = ILibMemory_SmartAllocate(5);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEYSTATE);		// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
	buffer[4] = (unsigned char)get_kbd_state();

	// Write the reply to the pipe.
	ILibQueue_Lock(g_messageQ);
	ILibQueue_EnQueue(g_messageQ, buffer);
	ILibQueue_UnLock(g_messageQ);
	return 0;
}

// void CheckDesktopSwitch(int checkres) { return; }

// Query existing authorization only. Service/helper startup must never prompt.
static int MacKvm_CanCaptureScreen(void)
{
    if (__builtin_available(macOS 10.15, *)) { return CGPreflightScreenCaptureAccess(); }
    return 1;
}

static int MacKvm_CanPostInput(void)
{
    // A virtual device is an input transport, not a desktop authorization grant.
    if (__builtin_available(macOS 10.9, *)) { return AXIsProcessTrustedWithOptions(NULL); }
    return 1;
}

// Use the existing desktop message packet so denied access is visible remotely.
static void MacKvm_SendPermissionStatus(int canCapture, int canInput)
{
    const char *message = !canCapture
        ? "macOS Screen Recording permission is required. Enable MeshAgent in System Settings > Privacy & Security."
        : (!canInput
            ? "macOS Accessibility permission is required for keyboard and mouse control. Enable MeshAgent in System Settings > Privacy & Security."
            : "");
    unsigned char packet[256];
    size_t length = strlen(message) + 4;
    packet[0] = 0;
    packet[1] = MNG_KVM_MESSAGE;
    packet[2] = (unsigned char)(length >> 8);
    packet[3] = (unsigned char)length;
    memcpy(packet + 4, message, length - 4);
    KVM_SEND((char*)packet, (int)length);
}

int kvm_server_inputdata(char* block, int blocklen)
{
	unsigned short type, size;
	//CheckDesktopSwitch(0);
	
	//senddebug(100+blocklen);

	// Decode the block header
	if (blocklen < 4) return 0;
	type = ((unsigned short)(unsigned char)block[0] << 8) | (unsigned char)block[1];
	size = ((unsigned short)(unsigned char)block[2] << 8) | (unsigned char)block[3];

	if (size > blocklen) return 0;
	if (size < 4) return -1; // Stop this stream; its packet boundary is no longer trustworthy.

	switch (type)
	{
		case MNG_KVM_KEY_UNICODE: // Unicode Key
			if (size != 7 || !MacKvm_CanPostInput()) break;
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			break;
		case MNG_KVM_KEY: // Key
		{
			if (size != 6 || KVM_AGENT_FD != -1 || !MacKvm_CanPostInput()) { break; }
			KeyAction(block[5], block[4]);
			break;
		}
		case MNG_KVM_MOUSE: // Mouse
		{
			int x, y;
			short w = 0;
			if (KVM_AGENT_FD != -1 || !MacKvm_CanPostInput()) { break; }
			if (size == 10 || size == 12)
			{
				if (SCREEN_SCALE < 1) { break; }
				x = (((int)(unsigned char)block[6] << 8) | (unsigned char)block[7]) / SCREEN_SCALE;
				y = (((int)(unsigned char)block[8] << 8) | (unsigned char)block[9]) / SCREEN_SCALE;
				
				if (size == 12) w = (short)(((unsigned int)(unsigned char)block[10] << 8) | (unsigned char)block[11]);
				
				//printf("x:%d, y:%d, b:%d, w:%d\n", x, y, block[5], w);
				MouseAction(x, y, (int)(unsigned char)(block[5]), w);
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
			kvm_send_resolution();

			int row, col;
			if (size != 4) break;
			if (g_tileInfo == NULL) {
				if ((g_tileInfo = (struct tileInfo_t **) malloc(TILE_HEIGHT_COUNT * sizeof(struct tileInfo_t *))) == NULL) ILIBCRITICALEXIT(254);
				for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
					if ((g_tileInfo[row] = (struct tileInfo_t *) malloc(TILE_WIDTH_COUNT * sizeof(struct tileInfo_t))) == NULL) ILIBCRITICALEXIT(254);
				}
			}
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
				for (col = 0; col < TILE_WIDTH_COUNT; col++) {
					g_tileInfo[row][col].crc = 0xFF;
					g_tileInfo[row][col].flag = 0;
				}
			}
			break;
		}
		case MNG_KVM_PAUSE: // Pause
		{
			if (size != 5) break;
			g_remotepause = block[4];
			break;
		}
		case MNG_KVM_FRAME_RATE_TIMER:
		{
			//int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			//if (fr > 20 && fr < 2000) FRAME_RATE_TIMER = fr;
			break;
		}
	}

	return size;
}


int kvm_relay_feeddata(char* buf, int len)
{
	ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
	return(len);
}

// Set the KVM pause state
void kvm_pause(int pause)
{
	g_pause = pause;
}


void* kvm_mainloopinput(void* param)
{
    unsigned char buffer[65535];
    size_t length = 0;
    int fd = KVM_AGENT_FD == -1 ? STDIN_FILENO : KVM_AGENT_FD;
    UNREFERENCED_PARAMETER(param);
    while (!g_shutdown && !g_resetipc)
    {
        struct pollfd pending = { fd, POLLIN, 0 };
        int ready = poll(&pending, 1, 100);
        if (ready < 0 && errno == EINTR) { continue; }
        if (ready < 0 || (pending.revents & (POLLERR | POLLNVAL))) { break; }
        if (ready == 0) { continue; }
        ssize_t count = read(fd, buffer + length, sizeof(buffer) - length);
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
    if (KVM_AGENT_FD == -1) { g_shutdown = 1; }
    else { g_resetipc = 1; }
    return NULL;
}

void ExitSink(int s)
{
	UNREFERENCED_PARAMETER(s);

	signal(SIGTERM, SIG_IGN);	
	
	if (KVM_Listener_FD > 0) 
	{
		write(STDOUT_FILENO, "EXITING\n", 8);
		fsync(STDOUT_FILENO);
		close(KVM_Listener_FD); 
	}
	g_shutdown = 1;
}
void* kvm_server_mainloop(void* param)
{
	int x, y, height, width, r, c = 0;
	long long desktopsize = 0;
	long long tilesize = 0;
	void *desktop = NULL;
	void *buf = NULL;
	int screen_height, screen_width, screen_num;
	int permissionState = -1;
	int written = 0;
	struct sockaddr_un serveraddr;

	signal(SIGPIPE, SIG_IGN);
	if (param == NULL)
	{
		// This is doing I/O via StdIn/StdOut

		int flags;
		flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
		if (fcntl(STDOUT_FILENO, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) {}
	}
	else
	{
		// this is doing I/O via a Unix Domain Socket
		if ((KVM_Listener_FD = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "ERROR CREATING DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			written = write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		int flags;
		flags = fcntl(KVM_Listener_FD, F_GETFL, 0);
		if (fcntl(KVM_Listener_FD, F_SETFL, (O_NONBLOCK | flags) ^ O_NONBLOCK) == -1) { }

		written = write(STDOUT_FILENO, "Set FCNTL2\n", 11);
		fsync(STDOUT_FILENO);

		memset(&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sun_family = AF_UNIX;
		strcpy(serveraddr.sun_path, KVM_Listener_Path);
		remove(KVM_Listener_Path);
		if (bind(KVM_Listener_FD, (struct sockaddr *)&serveraddr, SUN_LEN(&serveraddr)) < 0)
		{
			char tmp[255];
			int tmplen = sprintf_s(tmp, sizeof(tmp), "BIND ERROR on DOMAIN SOCKET: %d\n", errno);
			// Error creating domain socket
			written = write(STDOUT_FILENO, tmp, tmplen);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		if (listen(KVM_Listener_FD, 1) < 0)
		{
			written = write(STDOUT_FILENO, "LISTEN ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}

		written = write(STDOUT_FILENO, "LISTENING ON DOMAIN SOCKET\n", 27);
		fsync(STDOUT_FILENO);

		signal(SIGTERM, ExitSink);

		if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
		{
			written = write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
			fsync(STDOUT_FILENO);
			return(NULL);
		}
		else
		{
			char tmp[255];
			int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
			written = write(STDOUT_FILENO, tmp, tmpLen);
			fsync(STDOUT_FILENO);

		}
	}
	// Init the kvm
	g_messageQ = ILibQueue_Create();
	if (kvm_init() != 0) { return (void*)-1; }

	if (vhid_init()) {
		KvmDebugLog("Virtual HID active\n");
	}

	g_shutdown = 0;
	if (pthread_create(&kvmthread, NULL, kvm_mainloopinput, param) != 0) { kvmthread = (pthread_t)NULL; g_shutdown = 1; }


	if (KVM_AGENT_FD != -1)
	{
		written = write(STDOUT_FILENO, "Starting Loop []\n", 14);
		fsync(STDOUT_FILENO);

		char stmp[255];
		int stmpLen = sprintf_s(stmp, sizeof(stmp), "TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);
		written = write(STDOUT_FILENO, stmp, stmpLen);
		fsync(STDOUT_FILENO);
	}

	while (!g_shutdown) 
	{
		if (g_resetipc != 0)
		{
			if (kvmthread != (pthread_t)NULL) { pthread_join(kvmthread, NULL); kvmthread = (pthread_t)NULL; }
			g_resetipc = 0;
			permissionState = -1;
			close(KVM_AGENT_FD);

			SCREEN_HEIGHT = SCREEN_WIDTH = 0;

			char stmp[255];
			int stmpLen = sprintf_s(stmp, sizeof(stmp), "Waiting for NEXT DomainSocket, TILE_HEIGHT_COUNT=%d, TILE_WIDTH_COUNT=%d\n", TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT);
			written = write(STDOUT_FILENO, stmp, stmpLen);
			fsync(STDOUT_FILENO);

			if ((KVM_AGENT_FD = accept(KVM_Listener_FD, NULL, NULL)) < 0)
			{
				g_shutdown = 1;
				written = write(STDOUT_FILENO, "ACCEPT ERROR ON DOMAIN SOCKET", 29);
				fsync(STDOUT_FILENO);
				break;
			}
			else
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "ACCEPTed new connection %d on Domain Socket\n", KVM_AGENT_FD);
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
				if (pthread_create(&kvmthread, NULL, kvm_mainloopinput, param) != 0) { kvmthread = (pthread_t)NULL; g_shutdown = 1; break; }
			}
		}
		
		// Check if there are pending messages to be sent
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

        // Recheck so grants/revocations take effect without opening a consent dialog.
        int canCapture = MacKvm_CanCaptureScreen();
        int canInput = MacKvm_CanPostInput();
        int currentPermissions = canCapture | (canInput << 1);
        if (currentPermissions != permissionState)
        {
            MacKvm_SendPermissionStatus(canCapture, canInput);
            permissionState = currentPermissions;
        }
        if (!canCapture) { usleep(250000); continue; }

		for (r = 0; r < TILE_HEIGHT_COUNT; r++) 
		{
			for (c = 0; c < TILE_WIDTH_COUNT; c++) 
			{
				g_tileInfo[r][c].flag = TILE_TODO;
#ifdef KVM_ALL_TILES
				g_tileInfo[r][c].crc = 0xFF;
#endif
			}
		}

		screen_num = CGMainDisplayID();

		if (screen_num == 0) { g_shutdown = 1; senddebug(-2); break; }
		
		if (SCREEN_SCALE_SET == 0)
		{
			CGDisplayModeRef mode = CGDisplayCopyDisplayMode(screen_num);
			if (SCREEN_WIDTH > 0 && SCREEN_SCALE < (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH)
			{
				SCREEN_SCALE = (int) CGDisplayModeGetPixelWidth(mode) / SCREEN_WIDTH;
				SCREEN_SCALE_SET = 1;
			}			 
			CGDisplayModeRelease(mode);
		}
		
		screen_height = CGDisplayPixelsHigh(screen_num) * SCREEN_SCALE;
		screen_width = CGDisplayPixelsWide(screen_num) * SCREEN_SCALE;
		
		if ((SCREEN_HEIGHT != screen_height || (SCREEN_WIDTH != screen_width) || SCREEN_NUM != screen_num)) 
		{
			kvm_init();
			continue;
		}

		//senddebug(screen_num);
		CGImageRef image = CGDisplayCreateImage(screen_num);
		//senddebug(99);
		if (image == NULL) 
		{
			g_shutdown = 1;
			senddebug(0);
		}
		else {
			//senddebug(100);
			getScreenBuffer((unsigned char **)&desktop, &desktopsize, image);

			if (KVM_AGENT_FD != -1)
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "...Enter for loop\n");
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
			}

			for (y = 0; y < TILE_HEIGHT_COUNT; y++) 
			{
				for (x = 0; x < TILE_WIDTH_COUNT; x++) {
					height = TILE_HEIGHT * y;
					width = TILE_WIDTH * x;
					if (!g_shutdown && (g_pause)) { usleep(100000); g_pause = 0; } //HACK: Change this
					
					if (g_shutdown) { x = TILE_WIDTH_COUNT; y = TILE_HEIGHT_COUNT; break; }
					
					if (g_tileInfo[y][x].flag == TILE_SENT || g_tileInfo[y][x].flag == TILE_DONT_SEND) {
						continue;
					}
					
					getTileAt(width, height, &buf, &tilesize, desktop, desktopsize, y, x);
					
					if (buf && !g_shutdown)
					{	
						// Write the reply to the pipe.
						//KvmDebugLog("Writing to master in kvm_server_mainloop\n");

						written = KVM_SEND(buf, tilesize);

						//KvmDebugLog("Wrote %d bytes to master in kvm_server_mainloop\n", written);
						if (written == -1) 
						{ 
							/*ILIBMESSAGE("KVMBREAK-K2\r\n");*/ 
							if(KVM_AGENT_FD == -1)
							{
								// This is a User Session, so if the connection fails, we exit out... We can be spawned again later
								g_shutdown = 1; height = SCREEN_HEIGHT; width = SCREEN_WIDTH; break;
							}
						}
						//else
						//{
						//	char tmp[255];
						//	int tmpLen = sprintf_s(tmp, sizeof(tmp), "KVM_SEND => tilesize: %d\n", tilesize);
						//	written = write(STDOUT_FILENO, tmp, tmpLen);
						//	fsync(STDOUT_FILENO);
						//}
						free(buf);

					}
				}
			}

			if (KVM_AGENT_FD != -1)
			{
				char tmp[255];
				int tmpLen = sprintf_s(tmp, sizeof(tmp), "...exit for loop\n");
				written = write(STDOUT_FILENO, tmp, tmpLen);
				fsync(STDOUT_FILENO);
			}

		}
		CGImageRelease(image);
	}
	
	g_shutdown = 1;
	if (kvmthread != (pthread_t)NULL) { pthread_join(kvmthread, NULL); }
	kvmthread = (pthread_t)NULL;

	if (g_tileInfo != NULL) { for (r = 0; r < TILE_HEIGHT_COUNT; r++) { free(g_tileInfo[r]); } }
	g_tileInfo = NULL;
	if(tilebuffer != NULL) {
		free(tilebuffer);
		tilebuffer = NULL;
	}

	vhid_cleanup();

	if (KVM_AGENT_FD != -1)
	{
		written = write(STDOUT_FILENO, "Exiting...\n", 11);
		fsync(STDOUT_FILENO);
	}
	ILibQueue_Destroy(g_messageQ);
	return (void*)0;
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
	//KVMDebugLog *log = (KVMDebugLog*)buffer;

	//UNREFERENCED_PARAMETER(sender);
	//UNREFERENCED_PARAMETER(user);

	//if (bufferLen < sizeof(KVMDebugLog) || bufferLen < log->length) { *bytesConsumed = 0;  return; }
	//*bytesConsumed = log->length;
	////ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), (ILibRemoteLogging_Modules)log->logType, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	//ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	*bytesConsumed = bufferLen;
}


// launchctl asuser changes the GUI bootstrap/audit context, not credentials.
// Run this in the new helper before opening any desktop or input API.
int MacKvm_InitializeSessionUser(const char *value)
{
    uid_t uid = geteuid();
    if (value != NULL)
    {
        unsigned long number = 0;
        if (*value == 0) { errno = EINVAL; return -1; }
        for (const unsigned char *p = (const unsigned char*)value; *p; ++p)
        {
            if (*p < '0' || *p > '9' || number > ((unsigned long)INT_MAX - (*p - '0')) / 10)
            { errno = EINVAL; return -1; }
            number = number * 10 + (*p - '0');
        }
        uid = (uid_t)number;
    }
    if (uid == 0 || uid > INT_MAX || (geteuid() != 0 && geteuid() != uid)) { errno = EPERM; return -1; }
    struct stat console;
    if (stat("/dev/console", &console) != 0) { return -1; }
    if (console.st_uid != uid) { errno = ESTALE; return -1; }
    struct passwd account, *found = NULL;
    char scratch[16384];
    int error = getpwuid_r(uid, &account, scratch, sizeof(scratch), &found);
    if (error != 0 || found == NULL) { errno = error != 0 ? error : ENOENT; return -1; }
    if (account.pw_uid != uid || account.pw_gid == (gid_t)-1 || account.pw_name == NULL || !*account.pw_name || account.pw_dir == NULL || account.pw_dir[0] != '/')
    { errno = EINVAL; return -1; }
    if (geteuid() == 0)
    {
        if (initgroups(account.pw_name, account.pw_gid) != 0 || setgid(account.pw_gid) != 0 || setuid(uid) != 0) { return -1; }
    }
    if (getuid() != uid || geteuid() != uid || getgid() != account.pw_gid || getegid() != account.pw_gid)
    { errno = EPERM; return -1; }
    if (setenv("HOME", account.pw_dir, 1) != 0 || setenv("USER", account.pw_name, 1) != 0 || setenv("LOGNAME", account.pw_name, 1) != 0 ||
        setenv("SHELL", account.pw_shell != NULL && *account.pw_shell ? account.pw_shell : "/bin/sh", 1) != 0 || unsetenv("TMPDIR") != 0 || chdir("/") != 0)
    { return -1; }
    return 0;
}

// Return the output pipe, or the LoginWindow socket path when no user is logged in.
void* kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid)
{
    if (uid == 0) { return (void*)KVM_Listener_Path; }
    if (uid < 0 || exePath == NULL || exePath[0] != '/' || (geteuid() != 0 && geteuid() != (uid_t)uid)) { return NULL; }
    char userId[16];
    snprintf(userId, sizeof(userId), "%u", (unsigned int)uid);
    char *gui[] = { "launchctl", "asuser", userId, exePath, "-kvm0", "--session-uid", userId, NULL };
    void **user = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, NULL, NULL);
    user[0] = writeHandler;
    user[1] = reserved;
    user[2] = processPipeMgr;
    user[3] = exePath;

    // Keep root until the helper can establish all supplementary groups and its
    // primary GID as well as UID. The generic pipe spawn only calls setuid().
    gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx3(processPipeMgr, "/bin/launchctl",
        gui, ILibProcessPipe_SpawnTypes_DEFAULT, NULL, 0);
    if (gChildProcess == NULL) { ILibMemory_Free(user); return NULL; }
    g_slavekvm = ILibProcessPipe_Process_GetPID(gChildProcess);
    char metadata[64];
    snprintf(metadata, sizeof(metadata), "Child KVM (pid: %d)", g_slavekvm);
    ILibProcessPipe_Process_ResetMetadata(gChildProcess, metadata);
    ILibProcessPipe_Process_AddHandlers(gChildProcess, 65535, &kvm_relay_ExitHandler, &kvm_relay_StdOutHandler, &kvm_relay_StdErrHandler, NULL, user);
    g_shutdown = 0;
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
	KvmDebugLog("kvm_cleanup\n");
	g_shutdown = 1;
	if (gChildProcess != NULL)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		gChildProcess = NULL;
	}
}
