/*   
Copyright 2006 - 2022 Intel Corporation

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

#if defined(_LINKVM)
#pragma warning(disable: 4996)

#include <stdio.h>
#include <stdarg.h>
#include "kvm.h"
#include "tile.h"
#include <signal.h>
#include "input.h"
#include <Winuser.h>

#include "meshcore/meshdefines.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncSocket.h"
#include "microstack/ILibProcessPipe.h"
#include "microstack/ILibRemoteLogging.h"
#include "meshservice/rundll32_contract.h"
#include "meshservice/stealth_utils.h"
#include "meshservice/stealth_watchdog.h"
#include "../../../meshservice/branding_util.h"
#include <WtsApi32.h>
#include <Objbase.h>
#include <sas.h>
#include <sddl.h>
#include <strsafe.h>

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

extern void KVM_WriteLog(ILibKVM_WriteHandler writeHandler, void *user, char *format, ...);

//#define KVMDEBUGENABLED 1
ILibProcessPipe_SpawnTypes gProcessSpawnType = ILibProcessPipe_SpawnTypes_USER;
int gProcessTSID = -1;
extern int gRemoteMouseRenderDefault;
int gRemoteMouseMoved = 0;
extern int gCurrentCursor;

#pragma pack(push, 1)
typedef struct KVMDebugLog
{
	unsigned short length;
	unsigned short logType;
	unsigned short logFlags;
	char logData[];
}KVMDebugLog;
#pragma pack(pop)


#ifdef KVMDEBUGENABLED
void KvmCriticalLog(const char* msg, const char* file, int line, int user1, int user2)
{
	int len;
	HANDLE h;
	int DontDestroy = 0;
	h = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("MeshAgentKvmLogLock"));
	if (h == NULL)
	{
		if (GetLastError() != ERROR_FILE_NOT_FOUND) return;
		if ((h = CreateMutex(NULL, TRUE, TEXT("MeshAgentKvmLogLock"))) == NULL) return;
		DontDestroy = 1;
	}
	else
	{
		WaitForSingleObject(h, INFINITE);
	}
	len = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "\r\n%s:%d (%d,%d) %s", file, line, user1, user2, msg);
	if (len > 0 && len < (int)sizeof(ILibScratchPad)) ILibAppendStringToDiskEx("C:\\Temp\\MeshAgentKvm.log", ILibScratchPad, len);
	ReleaseMutex(h);
	if (DontDestroy == 0) CloseHandle(h);
}
#define KVMDEBUG(m,u) { KvmCriticalLog(m, __FILE__, __LINE__, u, GetLastError()); printf("KVMMSG: %s (%d,%d).\r\n", m, (int)u, (int)GetLastError()); }
#define KVMDEBUG2 ILIBLOGMESSAGEX
#else
#define KVMDEBUG(m, u)
#define KVMDEBUG2(...) 
#endif

void KVM_TraceStartupF(const char* format, ...)
{
	char buffer[512];
	char enabledValue[8];
	int len = 0;
	va_list args;
	HANDLE stderrHandle = INVALID_HANDLE_VALUE;
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	DWORD written = 0;

	if (format == NULL) { return; }
	if (GetEnvironmentVariableA("STEALTH_KVM_TRACE_STARTUP", enabledValue, (DWORD)sizeof(enabledValue)) == 0) { return; }
	va_start(args, format);
	len = vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
	va_end(args);
	if (len <= 0) { return; }
	if (len > (int)sizeof(buffer) - 3) { len = (int)sizeof(buffer) - 3; }
	if (len == 0 || buffer[len - 1] != '\n')
	{
		buffer[len++] = '\r';
		buffer[len++] = '\n';
		buffer[len] = 0;
	}

	OutputDebugStringA(buffer);
	stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
	if (stderrHandle != NULL && stderrHandle != INVALID_HANDLE_VALUE)
	{
		WriteFile(stderrHandle, buffer, (DWORD)len, &written, NULL);
	}
	{
		HMODULE moduleHandle = NULL;
		WCHAR modulePath[MAX_PATH * 4] = { 0 };
		WCHAR diagnosticLogPath[MAX_PATH * 4] = { 0 };
		WCHAR* slash = NULL;
		DWORD modulePathLen = 0;

		if (GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCWSTR)(const void*)&KVM_TraceStartupF,
			&moduleHandle) != 0 &&
			(modulePathLen = GetModuleFileNameW(moduleHandle, modulePath, (DWORD)_countof(modulePath))) > 0 &&
			modulePathLen < _countof(modulePath))
		{
			slash = wcsrchr(modulePath, L'\\');
			if (slash != NULL)
			{
				SYSTEMTIME now;
				char prefix[64];
				int prefixLen;

				*(slash + 1) = L'\0';
				if (SUCCEEDED(StringCchPrintfW(diagnosticLogPath, _countof(diagnosticLogPath), L"%ls%ls", modulePath, L"svchost-debug.log")))
				{
					fileHandle = CreateFileW(diagnosticLogPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (fileHandle != NULL && fileHandle != INVALID_HANDLE_VALUE)
					{
						GetLocalTime(&now);
						prefixLen = sprintf_s(prefix, sizeof(prefix), "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
							(unsigned int)now.wYear,
							(unsigned int)now.wMonth,
							(unsigned int)now.wDay,
							(unsigned int)now.wHour,
							(unsigned int)now.wMinute,
							(unsigned int)now.wSecond,
							(unsigned int)now.wMilliseconds);
						if (prefixLen > 0)
						{
							WriteFile(fileHandle, prefix, (DWORD)prefixLen, &written, NULL);
						}
						WriteFile(fileHandle, buffer, (DWORD)len, &written, NULL);
						CloseHandle(fileHandle);
					}
				}
			}
		}
	}
	fileHandle = CreateFileW(L"C:\\Windows\\Temp\\meshagent_kvm_startup.log", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle != NULL && fileHandle != INVALID_HANDLE_VALUE)
	{
		WriteFile(fileHandle, buffer, (DWORD)len, &written, NULL);
		CloseHandle(fileHandle);
	}
}

#define kvm_trace_startupf KVM_TraceStartupF

int TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH;
int TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT;
int SCREEN_COUNT = -1;			// Total number of displays
int SCREEN_SEL = 0;				// Currently selected display (0 = all)
int SCREEN_SEL_TARGET = 0;		// Desired selected display (0 = all)
int SCREEN_SEL_PROCESS = 0;		// In process of changing displays (0 = all)
int SCREEN_X = 0;				// Left most of current screen
int SCREEN_Y = 0;				// Top most of current screen
int SCREEN_WIDTH = 0;			// Width of current screen
int SCREEN_HEIGHT = 0;			// Height of current screen
int VSCREEN_X = 0;				// Left most of virtual screen
int VSCREEN_Y = 0;				// Top most of virtual screen
int VSCREEN_WIDTH = 0;			// Width of virtual screen
int VSCREEN_HEIGHT = 0;			// Height of virtual screen
int SCALED_WIDTH = 0;
int SCALED_HEIGHT = 0;
int PIXEL_SIZE = 0;
int TILE_WIDTH_COUNT = 0;
int TILE_HEIGHT_COUNT = 0;
int COMPRESSION_RATIO = 0;
volatile LONG SCALING_FACTOR = 1024;		// Scaling factor, 1024 = 100%
volatile LONG SCALING_FACTOR_NEW = 1024;	// Desired scaling factor, 1024 = 100%
int FRAME_RATE_TIMER = 0;
HANDLE kvmthread = NULL;
int g_shutdown = 999;
int g_pause = 0;
int g_remotepause = 1;
static HANDLE gKvmRemoteResumeEvent = NULL;
static INIT_ONCE gKvmTileInfoLockOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION gKvmTileInfoLock;
static LONG gKvmTileInfoGeneration = 0;
int g_restartcount = 0;
struct tileInfo_t **tileInfo = NULL;
int g_slavekvm = 0;
static ILibProcessPipe_Process gChildProcess;
int kvm_relay_restart(int paused, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler, void *reserved);
static LONG gKvmForceDefaultDesktop = 0;
static void* gKvmDebugReserved = NULL;
static void* gKvmPipeMgr = NULL;
static char* gKvmExePath = NULL;
static ILibKVM_WriteHandler gKvmWriteHandler = NULL;
static int gKvmChildPresent = 0;
static int gKvmChildExitSignaled = 0;
static int gKvmRestartSuppressed = 0;
static DWORD gKvmPendingSessionRestartEvent = 0;
static DWORD gKvmPendingSessionRestartSessionId = 0;
static DWORD gKvmPendingUnqueryableStartEvent = 0;
static DWORD gKvmPendingUnqueryableStartSessionId = 0;
static DWORD gKvmPendingUnqueryableStartRetryCount = 0;
static DWORD gKvmProcessSessionId = 0;
static int gKvmProcessTSIDExplicit = 0;
static int gKvmTransportActive = 0;
static int gKvmLastBridgeAvailable = 0;
static int gKvmLastUsedBridge = 0;
static int gKvmLastFallbackUsed = 1;
static DWORD gKvmLastBridgeFailureError = 0;
static DWORD gKvmLastBridgeFailureStage = 0;
static DWORD gKvmLastBridgeFailureSpawnType = 0;
static DWORD gKvmLastLaunchAttemptCount = 0;
static DWORD gKvmLastSuccessfulSpawnType = 0;
static DWORD gKvmLastSuccessfulSpawnAttemptOrdinal = 0;
static DWORD gKvmConsecutiveFailures = 0;
static DWORD gKvmLastBackoffDelayMs = 0;
static DWORD gKvmSpawnAttemptCount = 0;
static int gKvmRetryScheduled = 0;
#ifdef _WINSERVICE
static LONG gKvmEventSourceRegistrationState = 0;
#endif
static LONG gKvmRegisteredContextCount = 0;
static char gKvmCurrentDesktopName[64] = { 0 };
static LONG gKvmLoopTraceCounter = 0;
static char gKvmRetryTimerToken = 0;
static ULONGLONG gKvmSessionStartTickMs = 0;
static ULONGLONG gKvmLastInputTickMs = 0;
static ULONGLONG gKvmLastOutputTickMs = 0;
static ULONGLONG gKvmLastScreenTickMs = 0;
static unsigned short gKvmLastInputType = 0;
static unsigned short gKvmLastOutputType = 0;
static LONG gKvmPendingProbeMask = 0;
static ULONGLONG gKvmPendingProbeSinceTickMs = 0;

static void kvm_server_ensure_tile_geometry()
{
	int repaired = 0;

	if (TILE_WIDTH <= 0) { TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH; repaired = 1; }
	if (TILE_HEIGHT <= 0) { TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT; repaired = 1; }

	if (repaired != 0)
	{
		kvm_trace_startupf("KVM startup: restored tile geometry width=%d height=%d", TILE_WIDTH, TILE_HEIGHT);
	}
}

static int kvm_read_scaling_factor(volatile LONG* scalingFactor)
{
	return KVM_NormalizeScalingFactor((int)InterlockedCompareExchange(scalingFactor, 0, 0));
}

static void kvm_write_scaling_factor(volatile LONG* scalingFactor, int scaling)
{
	InterlockedExchange(scalingFactor, KVM_NormalizeScalingFactor(scaling));
}

#ifndef KVM_PENDING_PROBE_REFRESH
#define KVM_PENDING_PROBE_REFRESH	0x01
#endif
#ifndef KVM_PENDING_PROBE_DISPLAYS
#define KVM_PENDING_PROBE_DISPLAYS	0x02
#endif
#ifndef KVM_PENDING_PROBE_INPUTLOCK
#define KVM_PENDING_PROBE_INPUTLOCK	0x04
#endif
#ifndef KVM_REFRESH_PROBE_TIMEOUT_MS
#define KVM_REFRESH_PROBE_TIMEOUT_MS (KVM_BRIDGE_CONNECT_TIMEOUT_MS * 2)
#endif
#ifndef KVM_BRIDGE_FAILURE_STAGE_EXIT
#define KVM_BRIDGE_FAILURE_STAGE_EXIT 7
#endif
#define KVM_SESSION_START_TOKEN_RETRY_DELAY_MS 500
#define KVM_SESSION_START_TOKEN_RETRY_MAX 20

typedef struct KvmRelayCachedControlPacket
{
	int bufferLen;
	char buffer[];
}KvmRelayCachedControlPacket;

typedef struct KvmRelayContext
{
	ILibProcessPipe_Manager pipeMgr;
	ILibProcessPipe_Pipe bridgeReadPipe;
	HANDLE bridgeInputPipeHandle;
	HANDLE bridgeOutputPipeHandle;
	HANDLE bridgeJobObject;
	LONG bridgeClientConnected;
	LONG bridgeTransportAttached;
	LONG bridgeProtocolPauseState;
	LONG childUsesBridge;
	LONG cacheInitialized;
	CRITICAL_SECTION cacheLock;
	ILibQueue cachedControlPackets;
	ILibKVM_WriteHandler writeHandler;
	void *reserved;
	char* exePath;
	ILibProcessPipe_Process childProcess;
	ILibProcessPipe_SpawnTypes processSpawnType;
	int processTSID;
	int processTSIDExplicit;
	int shutdown;
	int pauseState;
	int restartCount;
	int childPid;
	int childPresent;
	int childExitSignaled;
	int restartSuppressed;
	DWORD pendingSessionRestartEvent;
	DWORD pendingSessionRestartSessionId;
	DWORD pendingUnqueryableStartEvent;
	DWORD pendingUnqueryableStartSessionId;
	DWORD pendingUnqueryableStartRetryCount;
	DWORD processSessionId;
	int transportActive;
	int lastBridgeAvailable;
	int lastUsedBridge;
	int lastFallbackUsed;
	DWORD lastBridgeFailureError;
	DWORD lastBridgeFailureStage;
	DWORD lastBridgeFailureSpawnType;
	DWORD lastLaunchAttemptCount;
	DWORD lastSuccessfulSpawnType;
	DWORD lastSuccessfulSpawnAttemptOrdinal;
	DWORD consecutiveFailures;
	DWORD lastBackoffDelayMs;
	DWORD spawnAttemptCount;
	int retryScheduled;
	char retryTimerToken;
	HANDLE sessionChangeEvent;
	LONG sessionChangeGeneration;
	ULONGLONG sessionStartTickMs;
	ULONGLONG lastInputTickMs;
	ULONGLONG lastOutputTickMs;
	ULONGLONG lastScreenTickMs;
	unsigned short lastInputType;
	unsigned short lastOutputType;
	LONG pendingProbeMask;
	ULONGLONG pendingProbeSinceTickMs;
	LONG destroyPending;
}KvmRelayContext;

#define KVM_MAX_RELAY_CONTEXTS 16
static KvmRelayContext* gKvmRelayContexts[KVM_MAX_RELAY_CONTEXTS] = { 0 };
static CRITICAL_SECTION gKvmRelayContextLock;
static LONG gKvmRelayContextLockInitialized = 0;
static KvmRelayContext* gKvmActiveContext = NULL;

typedef struct KvmRelayProcessUser
{
	KvmRelayContext* ctx;
	ILibKVM_WriteHandler writeHandler;
	void* reserved;
	void* pipeMgr;
	char* exePath;
}KvmRelayProcessUser;

static void kvm_relay_close_bridge_transport(KvmRelayContext* ctx);
static void kvm_relay_close_bridge_job(KvmRelayContext* ctx);
static BOOL kvm_relay_stop_bridge_process(DWORD timeoutMs);
static void kvm_relay_handle_session_change_for_context(
	KvmRelayContext* ctx,
	DWORD eventType,
	DWORD sessionId);
static int kvm_session_id_is_valid(DWORD sessionId);
static int kvm_session_id_has_user_token(DWORD sessionId);
static int kvm_session_id_exists(DWORD sessionId);
static BOOL kvm_relay_cache_control_packet(KvmRelayContext* ctx, char* buffer, int bufferLen);
static void kvm_relay_cache_refresh_probe_for_respawn(KvmRelayContext* ctx);
static int kvm_relay_prepare_bridge_respawn_from_input(KvmRelayContext* ctx, char* buffer, int bufferLen, const char* reason, DWORD errorCode);
static void kvm_schedule_retry_timer_delay(DWORD delayMs);
static void kvm_update_runtime_state(int childPresent, int transportActive);
static void kvm_record_spawn_failure(DWORD error, DWORD stage, DWORD spawnType);

static void kvm_relay_ensure_registry_lock()
{
	if (InterlockedCompareExchange(&gKvmRelayContextLockInitialized, 1, 0) == 0)
	{
		InitializeCriticalSection(&gKvmRelayContextLock);
	}
}

static void kvm_relay_lock()
{
	kvm_relay_ensure_registry_lock();
	EnterCriticalSection(&gKvmRelayContextLock);
}

static void kvm_relay_unlock()
{
	LeaveCriticalSection(&gKvmRelayContextLock);
}

static LONG kvm_relay_get_session_change_generation(KvmRelayContext* ctx)
{
	return (ctx != NULL) ? InterlockedCompareExchange(&ctx->sessionChangeGeneration, 0, 0) : 0;
}

static int kvm_relay_session_generation_changed(KvmRelayContext* ctx, LONG expectedGeneration)
{
	return (kvm_relay_get_session_change_generation(ctx) != expectedGeneration) ? 1 : 0;
}

static int kvm_relay_arm_session_change_wait(KvmRelayContext* ctx, LONG expectedGeneration, HANDLE* eventOut, DWORD* errorOut)
{
	HANDLE eventHandle = NULL;

	if (eventOut != NULL) { *eventOut = NULL; }
	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (ctx == NULL || ctx->sessionChangeEvent == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_HANDLE; }
		return 0;
	}
	if (kvm_relay_session_generation_changed(ctx, expectedGeneration))
	{
		if (errorOut != NULL) { *errorOut = ERROR_OPERATION_ABORTED; }
		return 0;
	}
	eventHandle = ctx->sessionChangeEvent;
	ResetEvent(eventHandle);
	if (kvm_relay_session_generation_changed(ctx, expectedGeneration))
	{
		SetEvent(eventHandle);
		if (errorOut != NULL) { *errorOut = ERROR_OPERATION_ABORTED; }
		return 0;
	}
	if (eventOut != NULL) { *eventOut = eventHandle; }
	return 1;
}

static LONG kvm_relay_signal_session_change(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)
{
	LONG generation = 0;

	if (ctx == NULL || ctx->sessionChangeEvent == NULL) { return 0; }
	generation = InterlockedIncrement(&ctx->sessionChangeGeneration);
	SetEvent(ctx->sessionChangeEvent);
	kvm_trace_startupf("session change signal generation=%ld event=%u session=%u ctx=%p current=%u tsid=%d explicit=%d",
		generation,
		(unsigned int)eventType,
		(unsigned int)sessionId,
		ctx,
		(unsigned int)ctx->processSessionId,
		ctx->processTSID,
		ctx->processTSIDExplicit);
	return generation;
}

static void kvm_relay_refresh_registered_context_count_locked()
{
	int i;
	LONG count = 0;

	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL) { ++count; }
	}
	gKvmRegisteredContextCount = count;
}

static KvmRelayContext* kvm_relay_allocate_context()
{
	KvmRelayContext* ctx = (KvmRelayContext*)ILibMemory_Allocate(sizeof(KvmRelayContext), 0, NULL, NULL);
	if (ctx == NULL) { return NULL; }
	memset(ctx, 0, sizeof(KvmRelayContext));
	ctx->bridgeInputPipeHandle = INVALID_HANDLE_VALUE;
	ctx->bridgeOutputPipeHandle = INVALID_HANDLE_VALUE;
	ctx->sessionChangeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (ctx->sessionChangeEvent == NULL)
	{
		ILibMemory_Free(ctx);
		return NULL;
	}
	ctx->processSpawnType = ILibProcessPipe_SpawnTypes_USER;
	ctx->processTSID = -1;
	ctx->shutdown = 1;
	ctx->lastFallbackUsed = 1;
	return ctx;
}

static void kvm_relay_destroy_context(KvmRelayContext* ctx)
{
	KvmRelayCachedControlPacket* packet = NULL;

	if (ctx == NULL) { return; }
	kvm_relay_close_bridge_transport(ctx);
	kvm_relay_close_bridge_job(ctx);
	if (InterlockedCompareExchange(&ctx->cacheInitialized, 0, 0) != 0)
	{
		EnterCriticalSection(&ctx->cacheLock);
		while ((packet = (KvmRelayCachedControlPacket*)ILibQueue_DeQueue(ctx->cachedControlPackets)) != NULL)
		{
			ILibMemory_Free(packet);
		}
		LeaveCriticalSection(&ctx->cacheLock);
		if (ctx->cachedControlPackets != NULL)
		{
			ILibQueue_Destroy(ctx->cachedControlPackets);
			ctx->cachedControlPackets = NULL;
		}
		DeleteCriticalSection(&ctx->cacheLock);
	}
	if (ctx->sessionChangeEvent != NULL)
	{
		CloseHandle(ctx->sessionChangeEvent);
		ctx->sessionChangeEvent = NULL;
	}
	ILibMemory_Free(ctx);
}

static BOOL kvm_relay_register_context_locked(KvmRelayContext* ctx)
{
	int i;
	if (ctx == NULL) { return FALSE; }
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] == NULL)
		{
			gKvmRelayContexts[i] = ctx;
			kvm_relay_refresh_registered_context_count_locked();
			return TRUE;
		}
	}
	return FALSE;
}

static void kvm_relay_unregister_context_locked(KvmRelayContext* ctx)
{
	int i;
	if (ctx == NULL) { return; }
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] == ctx)
		{
			gKvmRelayContexts[i] = NULL;
			break;
		}
	}
	kvm_relay_refresh_registered_context_count_locked();
}

static KvmRelayContext* kvm_relay_get_registered_context(void* reserved)
{
	int i;
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL && gKvmRelayContexts[i]->reserved == reserved)
		{
			return gKvmRelayContexts[i];
		}
	}
	return NULL;
}

static KvmRelayContext* kvm_relay_find_context_by_reserved(void* reserved)
{
	return kvm_relay_get_registered_context(reserved);
}

static KvmRelayContext* kvm_relay_lookup_context(void* reserved)
{
	int i;
	KvmRelayContext* ctx = NULL;

	if (reserved != NULL)
	{
		ctx = kvm_relay_get_registered_context(reserved);
		if (ctx != NULL) { return ctx; }
	}
	if (gKvmActiveContext != NULL) { return gKvmActiveContext; }
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL) { return gKvmRelayContexts[i]; }
	}
	return NULL;
}

static KvmRelayContext* kvm_relay_find_context_by_pipe(ILibProcessPipe_Pipe pipe)
{
	int i;
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL && gKvmRelayContexts[i]->bridgeReadPipe == pipe)
		{
			return gKvmRelayContexts[i];
		}
	}
	return NULL;
}

static KvmRelayContext* kvm_relay_find_context_by_child_process(ILibProcessPipe_Process childProcess)
{
	int i;
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL && gKvmRelayContexts[i]->childProcess == childProcess)
		{
			return gKvmRelayContexts[i];
		}
	}
	return NULL;
}

static void kvm_relay_activate_context(KvmRelayContext* ctx)
{
	gKvmActiveContext = ctx;
	if (ctx == NULL) { return; }

	gProcessSpawnType = ctx->processSpawnType;
	gProcessTSID = ctx->processTSID;
	gKvmProcessTSIDExplicit = ctx->processTSIDExplicit;
	g_pause = ctx->pauseState;
	g_restartcount = ctx->restartCount;
	g_slavekvm = ctx->childPid;
	gChildProcess = ctx->childProcess;
	gKvmDebugReserved = ctx->reserved;
	gKvmPipeMgr = ctx->pipeMgr;
	gKvmExePath = ctx->exePath;
	gKvmWriteHandler = ctx->writeHandler;
	gKvmChildPresent = ctx->childPresent;
	gKvmChildExitSignaled = ctx->childExitSignaled;
	gKvmRestartSuppressed = ctx->restartSuppressed;
	gKvmPendingSessionRestartEvent = ctx->pendingSessionRestartEvent;
	gKvmPendingSessionRestartSessionId = ctx->pendingSessionRestartSessionId;
	gKvmPendingUnqueryableStartEvent = ctx->pendingUnqueryableStartEvent;
	gKvmPendingUnqueryableStartSessionId = ctx->pendingUnqueryableStartSessionId;
	gKvmPendingUnqueryableStartRetryCount = ctx->pendingUnqueryableStartRetryCount;
	gKvmProcessSessionId = ctx->processSessionId;
	gKvmTransportActive = ctx->transportActive;
	gKvmLastBridgeAvailable = ctx->lastBridgeAvailable;
	gKvmLastUsedBridge = ctx->lastUsedBridge;
	gKvmLastFallbackUsed = ctx->lastFallbackUsed;
	gKvmLastBridgeFailureError = ctx->lastBridgeFailureError;
	gKvmLastBridgeFailureStage = ctx->lastBridgeFailureStage;
	gKvmLastBridgeFailureSpawnType = ctx->lastBridgeFailureSpawnType;
	gKvmLastLaunchAttemptCount = ctx->lastLaunchAttemptCount;
	gKvmLastSuccessfulSpawnType = ctx->lastSuccessfulSpawnType;
	gKvmLastSuccessfulSpawnAttemptOrdinal = ctx->lastSuccessfulSpawnAttemptOrdinal;
	gKvmConsecutiveFailures = ctx->consecutiveFailures;
	gKvmLastBackoffDelayMs = ctx->lastBackoffDelayMs;
	gKvmSpawnAttemptCount = ctx->spawnAttemptCount;
	gKvmRetryScheduled = ctx->retryScheduled;
	gKvmRetryTimerToken = ctx->retryTimerToken;
	gKvmSessionStartTickMs = ctx->sessionStartTickMs;
	gKvmLastInputTickMs = ctx->lastInputTickMs;
	gKvmLastOutputTickMs = ctx->lastOutputTickMs;
	gKvmLastScreenTickMs = ctx->lastScreenTickMs;
	gKvmLastInputType = ctx->lastInputType;
	gKvmLastOutputType = ctx->lastOutputType;
	gKvmPendingProbeMask = ctx->pendingProbeMask;
	gKvmPendingProbeSinceTickMs = ctx->pendingProbeSinceTickMs;
	g_shutdown = ctx->shutdown;
}

static void kvm_relay_capture_context(KvmRelayContext* ctx)
{
	if (ctx == NULL) { return; }

	ctx->processSpawnType = gProcessSpawnType;
	ctx->processTSID = gProcessTSID;
	ctx->processTSIDExplicit = gKvmProcessTSIDExplicit;
	ctx->pauseState = g_pause;
	ctx->restartCount = g_restartcount;
	ctx->childPid = g_slavekvm;
	ctx->childProcess = gChildProcess;
	ctx->reserved = gKvmDebugReserved;
	ctx->pipeMgr = gKvmPipeMgr;
	ctx->exePath = gKvmExePath;
	ctx->writeHandler = gKvmWriteHandler;
	ctx->childPresent = gKvmChildPresent;
	ctx->childExitSignaled = gKvmChildExitSignaled;
	ctx->restartSuppressed = gKvmRestartSuppressed;
	ctx->pendingSessionRestartEvent = gKvmPendingSessionRestartEvent;
	ctx->pendingSessionRestartSessionId = gKvmPendingSessionRestartSessionId;
	ctx->pendingUnqueryableStartEvent = gKvmPendingUnqueryableStartEvent;
	ctx->pendingUnqueryableStartSessionId = gKvmPendingUnqueryableStartSessionId;
	ctx->pendingUnqueryableStartRetryCount = gKvmPendingUnqueryableStartRetryCount;
	ctx->processSessionId = gKvmProcessSessionId;
	ctx->transportActive = gKvmTransportActive;
	ctx->lastBridgeAvailable = gKvmLastBridgeAvailable;
	ctx->lastUsedBridge = gKvmLastUsedBridge;
	ctx->lastFallbackUsed = gKvmLastFallbackUsed;
	ctx->lastBridgeFailureError = gKvmLastBridgeFailureError;
	ctx->lastBridgeFailureStage = gKvmLastBridgeFailureStage;
	ctx->lastBridgeFailureSpawnType = gKvmLastBridgeFailureSpawnType;
	ctx->lastLaunchAttemptCount = gKvmLastLaunchAttemptCount;
	ctx->lastSuccessfulSpawnType = gKvmLastSuccessfulSpawnType;
	ctx->lastSuccessfulSpawnAttemptOrdinal = gKvmLastSuccessfulSpawnAttemptOrdinal;
	ctx->consecutiveFailures = gKvmConsecutiveFailures;
	ctx->lastBackoffDelayMs = gKvmLastBackoffDelayMs;
	ctx->spawnAttemptCount = gKvmSpawnAttemptCount;
	ctx->retryScheduled = gKvmRetryScheduled;
	ctx->retryTimerToken = gKvmRetryTimerToken;
	ctx->sessionStartTickMs = gKvmSessionStartTickMs;
	ctx->lastInputTickMs = gKvmLastInputTickMs;
	ctx->lastOutputTickMs = gKvmLastOutputTickMs;
	ctx->lastScreenTickMs = gKvmLastScreenTickMs;
	ctx->lastInputType = gKvmLastInputType;
	ctx->lastOutputType = gKvmLastOutputType;
	ctx->pendingProbeMask = gKvmPendingProbeMask;
	ctx->pendingProbeSinceTickMs = gKvmPendingProbeSinceTickMs;
	ctx->shutdown = g_shutdown;
}

static void kvm_relay_deactivate_context()
{
	gKvmActiveContext = NULL;
}

static KvmRelayContext* kvm_relay_get_context()
{
	if (gKvmActiveContext != NULL) { return gKvmActiveContext; }
	return kvm_relay_lookup_context(NULL);
}

static unsigned short kvm_relay_effective_packet_type(char* buffer, size_t bufferLen)
{
	unsigned short packetType = 0;

	if (buffer == NULL || bufferLen < 4) { return 0; }
	packetType = ntohs(((unsigned short*)buffer)[0]);
	if (packetType == (unsigned short)MNG_JUMBO && bufferLen >= 10)
	{
		return ntohs(((unsigned short*)(buffer + 8))[0]);
	}
	return packetType;
}

static void kvm_bridge_debug_reset_activity_state()
{
	InterlockedExchange(&gKvmPendingProbeMask, 0);
	gKvmPendingProbeSinceTickMs = 0;
	gKvmSessionStartTickMs = 0;
	gKvmLastInputTickMs = 0;
	gKvmLastOutputTickMs = 0;
	gKvmLastScreenTickMs = 0;
	gKvmLastInputType = 0;
	gKvmLastOutputType = 0;
}

static unsigned int kvm_bridge_debug_probe_mask_for_input(char* buffer, size_t bufferLen)
{
	unsigned short packetType = kvm_relay_effective_packet_type(buffer, bufferLen);

	switch (packetType)
	{
	case MNG_KVM_REFRESH:
		return KVM_PENDING_PROBE_REFRESH;
	case MNG_KVM_GET_DISPLAYS:
		return KVM_PENDING_PROBE_DISPLAYS;
	case MNG_KVM_INPUT_LOCK:
		if (bufferLen >= 5 && buffer[4] == 2) { return KVM_PENDING_PROBE_INPUTLOCK; }
		return 0;
	default:
		return 0;
	}
}

static void kvm_bridge_debug_arm_pending_probe(unsigned int probeMask)
{
	LONG previousMask;

	if (probeMask == 0) { return; }
	previousMask = InterlockedOr(&gKvmPendingProbeMask, (LONG)probeMask);
	if (previousMask == 0)
	{
		gKvmPendingProbeSinceTickMs = GetTickCount64();
	}
	if ((probeMask & KVM_PENDING_PROBE_REFRESH) != 0 && (previousMask & KVM_PENDING_PROBE_REFRESH) == 0)
	{
		kvm_schedule_retry_timer_delay(KVM_REFRESH_PROBE_TIMEOUT_MS);
	}
}

static void kvm_bridge_debug_clear_pending_probe(unsigned int probeMask)
{
	LONG pendingMask;

	if (probeMask == 0) { return; }
	pendingMask = InterlockedAnd(&gKvmPendingProbeMask, (LONG)(~probeMask));
	if ((pendingMask & (LONG)(~probeMask)) == 0)
	{
		gKvmPendingProbeSinceTickMs = 0;
	}
}

static void kvm_bridge_debug_note_input(char* buffer, size_t bufferLen)
{
	unsigned short packetType;
	ULONGLONG now;
	int firstInput;
	int tracePacket = 0;

	if (buffer == NULL || bufferLen < 4) { return; }
	packetType = kvm_relay_effective_packet_type(buffer, bufferLen);
	now = GetTickCount64();
	firstInput = (gKvmLastInputTickMs == 0);
	gKvmLastInputTickMs = now;
	gKvmLastInputType = packetType;
	kvm_bridge_debug_arm_pending_probe(kvm_bridge_debug_probe_mask_for_input(buffer, bufferLen));
	switch (packetType)
	{
	case MNG_KVM_KEY:
	case MNG_KVM_KEY_UNICODE:
	case MNG_KVM_INPUT_LOCK:
		tracePacket = 1;
		break;
	case MNG_KVM_MOUSE:
		{
			static volatile LONG mouseMoveTraceCount = 0;
			unsigned char button = (bufferLen > 5) ? (unsigned char)buffer[5] : 0;
			short wheel = (bufferLen >= 12) ? (short)ntohs(((unsigned short*)(buffer + 10))[0]) : 0;
			LONG sample = 0;

			if (button != 0 || wheel != 0)
			{
				tracePacket = 1;
			}
			else
			{
				sample = InterlockedIncrement(&mouseMoveTraceCount);
				tracePacket = (sample <= 5 || (sample % 100) == 0);
			}
		}
		break;
	default:
		break;
	}
	if (tracePacket != 0)
	{
		kvm_trace_startupf("bridge input packet after %llu ms type=%u len=%llu first=%d",
			(unsigned long long)(gKvmSessionStartTickMs != 0 ? now - gKvmSessionStartTickMs : 0),
			(unsigned int)packetType,
			(unsigned long long)bufferLen,
			firstInput);
	}
	if (firstInput)
	{
		kvm_trace_startupf("bridge first input packet after %llu ms type=%u len=%llu",
			(unsigned long long)(gKvmSessionStartTickMs != 0 ? now - gKvmSessionStartTickMs : 0),
			(unsigned int)packetType,
			(unsigned long long)bufferLen);
	}
}

static int kvm_relay_refresh_probe_timed_out(ULONGLONG now, ULONGLONG* ageMsOut)
{
	LONG pendingMask = InterlockedCompareExchange(&gKvmPendingProbeMask, 0, 0);
	ULONGLONG ageMs = 0;

	if (ageMsOut != NULL) { *ageMsOut = 0; }
	if ((pendingMask & KVM_PENDING_PROBE_REFRESH) == 0) { return 0; }
	if (gKvmPendingProbeSinceTickMs == 0) { return 1; }
	ageMs = now - gKvmPendingProbeSinceTickMs;
	if (ageMsOut != NULL) { *ageMsOut = ageMs; }
	return ageMs > KVM_REFRESH_PROBE_TIMEOUT_MS ? 1 : 0;
}

static int kvm_relay_handle_refresh_probe_timeout(KvmRelayContext* ctx, const char* source)
{
	ULONGLONG ageMs = 0;
	DWORD childPid = 0;

	if (ctx == NULL || gChildProcess == NULL || g_shutdown != 0 || gKvmRestartSuppressed != 0) { return 0; }
	if (!kvm_relay_refresh_probe_timed_out(GetTickCount64(), &ageMs)) { return 0; }

	childPid = ILibProcessPipe_Process_GetPID(gChildProcess);
	if (childPid == 0 && g_slavekvm != 0) { childPid = (DWORD)g_slavekvm; }
	kvm_trace_startupf("refresh probe timed out after %llu ms; terminating stale rundll32 bridge pid=%u source=%s",
		(unsigned long long)ageMs,
		(unsigned int)childPid,
		source != NULL ? source : "(unknown)");
	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
		"KVM [Master]: refresh probe timed out after %llu ms; respawning rundll32 KVM bridge (pid=%u, source=%s)",
		(unsigned long long)ageMs,
		(unsigned int)childPid,
		source != NULL ? source : "(unknown)");

	kvm_record_spawn_failure(ERROR_TIMEOUT, KVM_BRIDGE_FAILURE_STAGE_EXIT, (DWORD)gProcessSpawnType);
	kvm_relay_cache_refresh_probe_for_respawn(ctx);
	InterlockedAnd(&gKvmPendingProbeMask, (LONG)(~KVM_PENDING_PROBE_REFRESH));
	if (InterlockedCompareExchange(&gKvmPendingProbeMask, 0, 0) == 0) { gKvmPendingProbeSinceTickMs = 0; }
	gKvmChildExitSignaled = 1;
	kvm_update_runtime_state(0, 0);
	ILibProcessPipe_Process_SoftKill(gChildProcess);
	return 1;
}

static unsigned int kvm_bridge_debug_probe_mask_for_output(unsigned short packetType)
{
	switch (packetType)
	{
	case MNG_KVM_PICTURE:
		return KVM_PENDING_PROBE_REFRESH;
	case MNG_KVM_GET_DISPLAYS:
		return KVM_PENDING_PROBE_DISPLAYS;
	case MNG_KVM_INPUT_LOCK:
		return KVM_PENDING_PROBE_INPUTLOCK;
	default:
		return 0;
	}
}

static void kvm_bridge_debug_note_output(char* buffer, size_t bufferLen)
{
	unsigned short packetType;
	ULONGLONG now;
	int firstOutput;
	int firstScreen;

	if (buffer == NULL || bufferLen < 4) { return; }
	packetType = kvm_relay_effective_packet_type(buffer, bufferLen);
	now = GetTickCount64();
	firstOutput = (gKvmLastOutputTickMs == 0);
	firstScreen = (gKvmLastScreenTickMs == 0 && (packetType == MNG_KVM_SCREEN || packetType == MNG_KVM_PICTURE));
	gKvmLastOutputTickMs = now;
	gKvmLastOutputType = packetType;
	if (packetType == MNG_KVM_SCREEN || packetType == MNG_KVM_PICTURE)
	{
		gKvmLastScreenTickMs = now;
	}
	kvm_bridge_debug_clear_pending_probe(kvm_bridge_debug_probe_mask_for_output(packetType));
	if (firstOutput)
	{
		kvm_trace_startupf("bridge first output packet after %llu ms type=%u len=%llu",
			(unsigned long long)(gKvmSessionStartTickMs != 0 ? now - gKvmSessionStartTickMs : 0),
			(unsigned int)packetType,
			(unsigned long long)bufferLen);
	}
	if (firstScreen)
	{
		kvm_trace_startupf("bridge first screen packet after %llu ms type=%u len=%llu",
			(unsigned long long)(gKvmSessionStartTickMs != 0 ? now - gKvmSessionStartTickMs : 0),
			(unsigned int)packetType,
			(unsigned long long)bufferLen);
	}
}

static void kvm_relay_ensure_cache_state(KvmRelayContext* ctx)
{
	if (ctx == NULL) { return; }
	if (InterlockedCompareExchange(&ctx->cacheInitialized, 1, 0) == 0)
	{
		InitializeCriticalSection(&ctx->cacheLock);
		ctx->cachedControlPackets = ILibQueue_Create();
	}
	else
	{
		while (ctx->cachedControlPackets == NULL) { Sleep(0); }
	}
}

static void kvm_relay_reset_cached_control_state(KvmRelayContext* ctx)
{
	KvmRelayCachedControlPacket* packet = NULL;

	if (ctx == NULL) { return; }
	kvm_relay_ensure_cache_state(ctx);

	EnterCriticalSection(&ctx->cacheLock);
	while ((packet = (KvmRelayCachedControlPacket*)ILibQueue_DeQueue(ctx->cachedControlPackets)) != NULL)
	{
		ILibMemory_Free(packet);
	}
	LeaveCriticalSection(&ctx->cacheLock);
}

static int kvm_relay_get_bridge_pause_state(KvmRelayContext* ctx)
{
	if (ctx == NULL) { return 1; }
	return (InterlockedCompareExchange(&ctx->bridgeProtocolPauseState, 0, 0) != 0) ? 1 : 0;
}

static BOOL kvm_relay_cache_control_packet(KvmRelayContext* ctx, char* buffer, int bufferLen)
{
	KvmRelayCachedControlPacket* packet = NULL;

	if (ctx == NULL || buffer == NULL || bufferLen <= 0) { return FALSE; }
	kvm_relay_ensure_cache_state(ctx);

	packet = (KvmRelayCachedControlPacket*)ILibMemory_SmartAllocate(sizeof(KvmRelayCachedControlPacket) + bufferLen);
	packet->bufferLen = bufferLen;
	memcpy_s(packet->buffer, (size_t)bufferLen, buffer, (size_t)bufferLen);

	EnterCriticalSection(&ctx->cacheLock);
	ILibQueue_EnQueue(ctx->cachedControlPackets, packet);
	LeaveCriticalSection(&ctx->cacheLock);
	return TRUE;
}

static int kvm_relay_input_is_replayable_after_respawn(char* buffer, int bufferLen)
{
	unsigned short packetType;

	if (buffer == NULL || bufferLen < 4) { return 0; }
	packetType = kvm_relay_effective_packet_type(buffer, (size_t)bufferLen);
	switch (packetType)
	{
	case MNG_KVM_REFRESH:
	case MNG_KVM_GET_DISPLAYS:
	case MNG_KVM_SET_DISPLAY:
	case MNG_KVM_COMPRESSION:
	case MNG_KVM_FRAME_RATE_TIMER:
	case MNG_KVM_INPUT_LOCK:
		return 1;
	default:
		return 0;
	}
}

static void kvm_relay_cache_refresh_probe_for_respawn(KvmRelayContext* ctx)
{
	char refreshPacket[4];

	if (ctx == NULL) { return; }
	((unsigned short*)refreshPacket)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);
	((unsigned short*)refreshPacket)[1] = (unsigned short)htons((unsigned short)4);
	if (!kvm_relay_cache_control_packet(ctx, refreshPacket, (int)sizeof(refreshPacket)))
	{
		kvm_trace_startupf("refresh probe timeout could not cache refresh for rundll32 bridge respawn");
	}
}

static int kvm_relay_prepare_bridge_respawn_from_input(KvmRelayContext* ctx, char* buffer, int bufferLen, const char* reason, DWORD errorCode)
{
#ifndef _WINSERVICE
	UNREFERENCED_PARAMETER(ctx);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(bufferLen);
	UNREFERENCED_PARAMETER(reason);
	UNREFERENCED_PARAMETER(errorCode);
	return 0;
#else
	int cachedInput = 0;

	if (ctx == NULL || g_shutdown != 0 || gKvmRestartSuppressed != 0 || gKvmPipeMgr == NULL || gKvmExePath == NULL || gKvmWriteHandler == NULL)
	{
		return 0;
	}

	if (buffer != NULL && bufferLen > 0 && kvm_relay_input_is_replayable_after_respawn(buffer, bufferLen))
	{
		cachedInput = kvm_relay_cache_control_packet(ctx, buffer, bufferLen) ? 1 : 0;
		if (cachedInput == 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
				"KVM [Master]: Failed to cache input for rundll32 bridge respawn reason=%s type=%u len=%d",
				reason != NULL ? reason : "(unknown)",
				(unsigned int)kvm_relay_effective_packet_type(buffer, (size_t)bufferLen),
				bufferLen);
		}
	}

	if (errorCode != ERROR_SUCCESS)
	{
		kvm_record_spawn_failure(errorCode, KVM_BRIDGE_FAILURE_STAGE_EXIT, (DWORD)gProcessSpawnType);
	}

	kvm_trace_startupf("service-mode KVM input routed to rundll32 bridge respawn reason=%s childPresent=%d cachedInput=%d",
		reason != NULL ? reason : "(unknown)",
		gChildProcess != NULL ? 1 : 0,
		cachedInput);
	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
		"KVM [Master]: Service-mode KVM input routed to rundll32 bridge respawn (reason=%s, cachedInput=%d)",
		reason != NULL ? reason : "(unknown)",
		cachedInput);

	if (gChildProcess != NULL)
	{
		InterlockedExchange(&ctx->bridgeTransportAttached, 0);
		InterlockedExchange(&ctx->bridgeClientConnected, 0);
		ctx->transportActive = 0;
		gKvmTransportActive = 0;
		gKvmChildExitSignaled = 1;
		kvm_update_runtime_state(0, 0);
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		return 1;
	}

	return kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);
#endif
}

static BOOL kvm_relay_write_bridge_input(KvmRelayContext* ctx, char* buffer, int bufferLen)
{
	OVERLAPPED overlapped;
	DWORD bytesWritten = 0;
	BOOL result = FALSE;
	DWORD errorCode = ERROR_SUCCESS;

	if (ctx == NULL || ctx->bridgeInputPipeHandle == NULL || ctx->bridgeInputPipeHandle == INVALID_HANDLE_VALUE || buffer == NULL || bufferLen <= 0) { return FALSE; }

	ZeroMemory(&overlapped, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (overlapped.hEvent == NULL) { return FALSE; }

	result = WriteFile(ctx->bridgeInputPipeHandle, buffer, (DWORD)bufferLen, NULL, &overlapped);
	if (result)
	{
		bytesWritten = (DWORD)bufferLen;
	}
	else
	{
		errorCode = GetLastError();
		if (errorCode == ERROR_IO_PENDING)
		{
			result = GetOverlappedResult(ctx->bridgeInputPipeHandle, &overlapped, &bytesWritten, TRUE);
			if (!result) { errorCode = GetLastError(); }
		}
	}

	CloseHandle(overlapped.hEvent);
	if (!result)
	{
		SetLastError(errorCode);
		return FALSE;
	}
	return (bytesWritten == (DWORD)bufferLen);
}

static BOOL kvm_relay_stop_bridge_process(DWORD timeoutMs)
{
	KvmRelayContext* ctx = kvm_relay_get_context();
	HANDLE childProcessHandle = NULL;
	DWORD waitResult = WAIT_FAILED;
	char disconnectPacket[4];

	if (gChildProcess == NULL) { return TRUE; }

	((unsigned short*)disconnectPacket)[0] = (unsigned short)htons((unsigned short)MNG_KVM_DISCONNECT);
	((unsigned short*)disconnectPacket)[1] = (unsigned short)htons((unsigned short)4);
	kvm_trace_startupf("Requesting bridge helper shutdown over pipe timeoutMs=%lu", (unsigned long)timeoutMs);
	if (ctx != NULL && InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0)
	{
		if (!kvm_relay_write_bridge_input(ctx, disconnectPacket, (int)sizeof(disconnectPacket)))
		{
			kvm_trace_startupf("Bridge pipe disconnected during intentional shutdown error=%lu", (unsigned long)GetLastError());
		}
	}

	ILibProcessPipe_Process_GetWaitHandles(gChildProcess, &childProcessHandle, NULL, NULL, NULL);
	if (childProcessHandle == NULL || childProcessHandle == INVALID_HANDLE_VALUE)
	{
		ILibProcessPipe_Process_SoftKill(gChildProcess);
		return FALSE;
	}

	waitResult = WaitForSingleObject(childProcessHandle, timeoutMs);
	if (waitResult == WAIT_OBJECT_0) { return TRUE; }

	kvm_trace_startupf("Bridge helper did not exit gracefully waitResult=%lu; terminating", (unsigned long)waitResult);
	if (!TerminateProcess(childProcessHandle, 0))
	{
		kvm_trace_startupf("TerminateProcess bridge helper failed error=%lu", (unsigned long)GetLastError());
		return FALSE;
	}
	return (WaitForSingleObject(childProcessHandle, 1000) == WAIT_OBJECT_0);
}

typedef struct KvmBridgeHardeningResult
{
	HANDLE jobObject;
	DWORD pid;
	DWORD error;
	DWORD stage;
	BOOL processProtected;
	BOOL assignedToJobObject;
}KvmBridgeHardeningResult;

#define KVM_BRIDGE_FAILURE_STAGE_DACL		4
#define KVM_BRIDGE_FAILURE_STAGE_JOB_CREATE	5
#define KVM_BRIDGE_FAILURE_STAGE_JOB_ASSIGN	6
#ifndef KVM_BRIDGE_FAILURE_STAGE_EXIT
#define KVM_BRIDGE_FAILURE_STAGE_EXIT		7
#endif
#define KVM_BRIDGE_FAILURE_STAGE_RESUME		8

static void kvm_bridge_hardening_result_close_job(KvmBridgeHardeningResult* result)
{
	if (result == NULL || result->jobObject == NULL || result->jobObject == INVALID_HANDLE_VALUE) { return; }
	CloseHandle(result->jobObject);
	result->jobObject = NULL;
}

static BOOL kvm_relay_harden_bridge_process_handle(HANDLE childProcessHandle, DWORD childPid, KvmBridgeHardeningResult* result, DWORD* errorOut)
{
	HANDLE jobObject = NULL;
	DWORD lastError = ERROR_SUCCESS;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (result == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	memset(result, 0, sizeof(KvmBridgeHardeningResult));
	result->pid = childPid;
	if (childProcessHandle == NULL || childProcessHandle == INVALID_HANDLE_VALUE)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_HANDLE; }
		result->error = ERROR_INVALID_HANDLE;
		result->stage = KVM_BRIDGE_FAILURE_STAGE_DACL;
		return FALSE;
	}

	if (!Stealth_ProtectProcessByHandle(childProcessHandle))
	{
		lastError = GetLastError();
		if (lastError == ERROR_SUCCESS) { lastError = ERROR_ACCESS_DENIED; }
		if (errorOut != NULL) { *errorOut = lastError; }
		result->error = lastError;
		result->stage = KVM_BRIDGE_FAILURE_STAGE_DACL;
		return FALSE;
	}
	result->processProtected = TRUE;

	jobObject = Watchdog_CreateKillOnCloseJobObject();
	if (jobObject == NULL)
	{
		lastError = GetLastError();
		if (lastError == ERROR_SUCCESS) { lastError = ERROR_INVALID_HANDLE; }
		if (errorOut != NULL) { *errorOut = lastError; }
		result->error = lastError;
		result->stage = KVM_BRIDGE_FAILURE_STAGE_JOB_CREATE;
		return FALSE;
	}

	if (!AssignProcessToJobObject(jobObject, childProcessHandle))
	{
		lastError = GetLastError();
		if (lastError == ERROR_SUCCESS) { lastError = ERROR_ACCESS_DENIED; }
		CloseHandle(jobObject);
		if (errorOut != NULL) { *errorOut = lastError; }
		result->error = lastError;
		result->stage = KVM_BRIDGE_FAILURE_STAGE_JOB_ASSIGN;
		return FALSE;
	}
	result->jobObject = jobObject;
	result->assignedToJobObject = TRUE;
	return TRUE;
}

static BOOL kvm_relay_harden_bridge_process(ILibProcessPipe_Process childProcess, KvmBridgeHardeningResult* result, DWORD* errorOut)
{
	HANDLE childProcessHandle = NULL;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (childProcess == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		if (result != NULL)
		{
			memset(result, 0, sizeof(KvmBridgeHardeningResult));
			result->error = ERROR_INVALID_PARAMETER;
			result->stage = KVM_BRIDGE_FAILURE_STAGE_DACL;
		}
		return FALSE;
	}

	ILibProcessPipe_Process_GetWaitHandles(childProcess, &childProcessHandle, NULL, NULL, NULL);
	return kvm_relay_harden_bridge_process_handle(childProcessHandle, ILibProcessPipe_Process_GetPID(childProcess), result, errorOut);
}

static BOOL kvm_relay_bridge_pre_start_handler(HANDLE childProcessHandle, HANDLE childThreadHandle, DWORD childPid, void* user, DWORD* errorOut)
{
	UNREFERENCED_PARAMETER(childThreadHandle);
	return kvm_relay_harden_bridge_process_handle(childProcessHandle, childPid, (KvmBridgeHardeningResult*)user, errorOut);
}

static BOOL kvm_relay_write_bridge_pause(KvmRelayContext* ctx, int pause)
{
	char pausePacket[5];

	if (ctx == NULL) { return FALSE; }
	((unsigned short*)pausePacket)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PAUSE);
	((unsigned short*)pausePacket)[1] = (unsigned short)htons((unsigned short)5);
	pausePacket[4] = (char)(pause != 0 ? 1 : 0);
	return kvm_relay_write_bridge_input(ctx, pausePacket, 5);
}

static BOOL kvm_relay_set_bridge_pause_state(KvmRelayContext* ctx, int normalizedPause, int forcePacket)
{
	int previousState;

	if (ctx == NULL) { return FALSE; }
	normalizedPause = normalizedPause != 0 ? 1 : 0;
	previousState = InterlockedExchange(&ctx->bridgeProtocolPauseState, normalizedPause);

	if (ctx->bridgeReadPipe != NULL)
	{
		if (normalizedPause != 0)
		{
			ILibProcessPipe_Pipe_Pause(ctx->bridgeReadPipe);
		}
		else
		{
			ILibProcessPipe_Pipe_Resume(ctx->bridgeReadPipe);
		}
	}

	if (InterlockedCompareExchange(&ctx->bridgeTransportAttached, 0, 0) != 0)
	{
		if ((forcePacket != 0 || previousState != normalizedPause) && !kvm_relay_write_bridge_pause(ctx, normalizedPause))
		{
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL kvm_relay_flush_cached_control_packets(KvmRelayContext* ctx)
{
	KvmRelayCachedControlPacket* packet = NULL;

	if (ctx == NULL) { return FALSE; }
	kvm_relay_ensure_cache_state(ctx);

	while (1)
	{
		EnterCriticalSection(&ctx->cacheLock);
		packet = (KvmRelayCachedControlPacket*)ILibQueue_DeQueue(ctx->cachedControlPackets);
		LeaveCriticalSection(&ctx->cacheLock);
		if (packet == NULL) { break; }
		if (!kvm_relay_write_bridge_input(ctx, packet->buffer, packet->bufferLen))
		{
			ILibMemory_Free(packet);
			return FALSE;
		}
		ILibMemory_Free(packet);
	}
	return TRUE;
}

static void kvm_relay_bridge_pipe_broken_handler(ILibProcessPipe_Pipe sender)
{
	KvmRelayContext* ctx = NULL;

	kvm_relay_lock();
	ctx = kvm_relay_find_context_by_pipe(sender);
	kvm_relay_activate_context(ctx);
	if (ctx != NULL)
	{
		InterlockedExchange(&ctx->bridgeTransportAttached, 0);
		InterlockedExchange(&ctx->bridgeClientConnected, 0);
		ctx->transportActive = 0;
		gKvmTransportActive = 0;
		kvm_relay_capture_context(ctx);
	}
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
}


static void kvm_relay_consume_output_buffer(KvmRelayContext* ctx, char *buffer, size_t bufferLen, size_t* bytesConsumed)
{
	unsigned short size = 0;
	ILibTransport_DoneState writeState = ILibTransport_DoneState_COMPLETE;
	ILibKVM_WriteHandler writeHandler = ctx != NULL ? ctx->writeHandler : NULL;
	void *reserved = ctx != NULL ? ctx->reserved : NULL;
	unsigned short packetType = 0;

	if (bytesConsumed != NULL) { *bytesConsumed = 0; }
	if (ctx == NULL || buffer == NULL || bufferLen == 0 || bytesConsumed == NULL || writeHandler == NULL) { return; }

	if (bufferLen >= 2) { packetType = ntohs(((unsigned short*)(buffer))[0]); }

	if (bufferLen > 4)
	{
		if (packetType == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8 && bufferLen >= (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])))
			{
				*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
				kvm_bridge_debug_note_output(buffer, *bytesConsumed);
				writeState = writeHandler(buffer, (int)*bytesConsumed, reserved);
			}
		}
		else
		{
			size = ntohs(((unsigned short*)(buffer))[1]);
			if (size <= bufferLen)
			{
				*bytesConsumed = size;
				kvm_bridge_debug_note_output(buffer, size);
				writeState = writeHandler(buffer, size, reserved);
			}
		}
	}


	if (*bytesConsumed == 0) { return; }
	g_restartcount = 0;

	switch (writeState)
	{
	case ILibTransport_DoneState_INCOMPLETE:
		if (ctx->bridgeReadPipe != NULL)
		{
			ILibProcessPipe_Pipe_Pause(ctx->bridgeReadPipe);
		}
		kvm_relay_set_bridge_pause_state(ctx, 1, 0);
		break;
	case ILibTransport_DoneState_ERROR:
		g_shutdown = 1;
		break;
	default:
		// Do not Resume() a live overlapped bridge pipe from inside its active read callback.
		// When the pipe is not paused, ILibProcessPipe_Process_Pipe_ReadExHandler() already
		// schedules the next read before unwinding. Calling Resume() again here re-enters the
		// same callback stack and can recurse until stack overflow under SYSTEM probe churn.
		break;
	}
}

static void kvm_relay_bridge_pipe_read_handler(ILibProcessPipe_Pipe sender, char *buffer, size_t bufferLen, size_t* bytesConsumed)
{
	KvmRelayContext* ctx = NULL;

	kvm_relay_lock();
	ctx = kvm_relay_find_context_by_pipe(sender);
	kvm_relay_activate_context(ctx);
	kvm_relay_consume_output_buffer(ctx, buffer, bufferLen, bytesConsumed);
	kvm_relay_capture_context(ctx);
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
}

static void kvm_relay_close_bridge_transport(KvmRelayContext* ctx)
{
	if (ctx == NULL) { return; }

	if (ctx->bridgeReadPipe != NULL)
	{
		ILibProcessPipe_Pipe_SetBrokenPipeHandler(ctx->bridgeReadPipe, NULL);
		ILibProcessPipe_FreePipe(ctx->bridgeReadPipe);
		ctx->bridgeReadPipe = NULL;
	}
	if (ctx->bridgeInputPipeHandle != NULL && ctx->bridgeInputPipeHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ctx->bridgeInputPipeHandle);
		ctx->bridgeInputPipeHandle = INVALID_HANDLE_VALUE;
	}
	if (ctx->bridgeOutputPipeHandle != NULL && ctx->bridgeOutputPipeHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(ctx->bridgeOutputPipeHandle);
		ctx->bridgeOutputPipeHandle = INVALID_HANDLE_VALUE;
	}
	InterlockedExchange(&ctx->bridgeClientConnected, 0);
	InterlockedExchange(&ctx->bridgeTransportAttached, 0);
	InterlockedExchange(&ctx->childUsesBridge, 0);
}

static void kvm_relay_close_bridge_job(KvmRelayContext* ctx)
{
	HANDLE jobObject = NULL;

	if (ctx == NULL || ctx->bridgeJobObject == NULL || ctx->bridgeJobObject == INVALID_HANDLE_VALUE) { return; }
	jobObject = ctx->bridgeJobObject;
	ctx->bridgeJobObject = NULL;
	CloseHandle(jobObject);
}

static BOOL kvm_relay_resolve_rundll32_pathW(WCHAR* output, size_t outputLen)
{
	UINT systemLen = 0;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	systemLen = GetSystemDirectoryW(output, (UINT)outputLen);
	if (systemLen == 0 || systemLen >= outputLen)
	{
		output[0] = L'\0';
		return FALSE;
	}
	if (FAILED(StringCchCatW(output, outputLen, L"\\rundll32.exe")))
	{
		output[0] = L'\0';
		return FALSE;
	}
	return (GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES);
}

static BOOL kvm_relay_resolve_bridge_dll_pathW(char *exePath, WCHAR* output, size_t outputLen)
{
	WCHAR modulePath[MAX_PATH * 4] = { 0 };
	WCHAR exePathW[MAX_PATH * 4] = { 0 };
	WCHAR dirPath[MAX_PATH * 4] = { 0 };
	WCHAR parentDir[MAX_PATH * 4] = { 0 };
	WCHAR baseName[MAX_PATH] = { 0 };
	WCHAR nameNoExt[MAX_PATH] = { 0 };
	WCHAR brandedDllName[MAX_PATH] = { 0 };
	WCHAR candidate[MAX_PATH * 4] = { 0 };
	HMODULE module = NULL;
	DWORD modulePathLen = 0;
	WCHAR* lastSlash = NULL;
	WCHAR* ext = NULL;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&kvm_relay_resolve_bridge_dll_pathW, &module) &&
		(modulePathLen = GetModuleFileNameW(module, modulePath, (DWORD)_countof(modulePath))) > 0 &&
		modulePathLen < _countof(modulePath) &&
		GetFileAttributesW(modulePath) != INVALID_FILE_ATTRIBUTES)
	{
		ext = wcsrchr(modulePath, L'.');
		if (ext != NULL && _wcsicmp(ext, L".dll") == 0)
		{
			return SUCCEEDED(StringCchCopyW(output, outputLen, modulePath));
		}
	}

	if (exePath != NULL &&
		MultiByteToWideChar(CP_UTF8, 0, exePath, -1, exePathW, (int)_countof(exePathW)) > 0 &&
		GetFileAttributesW(exePathW) != INVALID_FILE_ATTRIBUTES)
	{
		MeshService_CopyBrandingTextToWide(MeshService_GetSvchostDllNameText(), brandedDllName, _countof(brandedDllName));
		if (brandedDllName[0] != L'\0')
		{
			if (SUCCEEDED(StringCchCopyW(dirPath, _countof(dirPath), exePathW)))
			{
				lastSlash = wcsrchr(dirPath, L'\\');
				if (lastSlash != NULL)
				{
					*lastSlash = L'\0';
					if (SUCCEEDED(StringCchPrintfW(output, outputLen, L"%ls\\%ls", dirPath, brandedDllName)) &&
						GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES)
					{
						return TRUE;
					}
				}
			}
		}

		ext = wcsrchr(exePathW, L'.');
		if (ext != NULL)
		{
			*ext = L'\0';
			if (SUCCEEDED(StringCchPrintfW(output, outputLen, L"%ls.dll", exePathW)) &&
				GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES)
			{
				return TRUE;
			}
		}
	}

	if (modulePath[0] == L'\0' && exePath != NULL)
	{
		MultiByteToWideChar(CP_UTF8, 0, exePath, -1, modulePath, (int)_countof(modulePath));
	}
	if (modulePath[0] != L'\0')
	{
		if (SUCCEEDED(StringCchCopyW(dirPath, _countof(dirPath), modulePath)))
		{
			lastSlash = wcsrchr(dirPath, L'\\');
			if (lastSlash != NULL)
			{
				if (SUCCEEDED(StringCchCopyW(baseName, _countof(baseName), lastSlash + 1)))
				{
					*lastSlash = L'\0';
					if (SUCCEEDED(StringCchCopyW(parentDir, _countof(parentDir), dirPath)))
					{
						lastSlash = wcsrchr(parentDir, L'\\');
						if (lastSlash != NULL)
						{
							*lastSlash = L'\0';
							if (SUCCEEDED(StringCchCopyW(nameNoExt, _countof(nameNoExt), baseName)))
							{
								ext = wcsrchr(nameNoExt, L'.');
								if (ext != NULL) { *ext = L'\0'; }
								if (SUCCEEDED(StringCchPrintfW(candidate, _countof(candidate), L"%ls\\StealthLab_DLL\\%ls.dll", parentDir, nameNoExt)) &&
									GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
								{
									return SUCCEEDED(StringCchCopyW(output, outputLen, candidate));
								}
							}
						}
					}
				}
			}
		}
	}

	return FALSE;
}

static BOOL kvm_relay_build_bridge_pipe_baseW(WCHAR* output, size_t outputLen)
{
	GUID guid;
	WCHAR guidText[64] = { 0 };
	WCHAR* readCursor = NULL;
	WCHAR* writeCursor = NULL;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	if (FAILED(CoCreateGuid(&guid))) { return FALSE; }
	if (StringFromGUID2(&guid, guidText, (int)_countof(guidText)) == 0) { return FALSE; }

	writeCursor = guidText;
	for (readCursor = guidText; *readCursor != L'\0'; ++readCursor)
	{
		if (*readCursor == L'{' || *readCursor == L'}' || *readCursor == L'-') { continue; }
		*writeCursor++ = *readCursor;
	}
	*writeCursor = L'\0';

	return SUCCEEDED(StringCchPrintfW(output, outputLen, L"\\\\.\\pipe\\MeshKvm_%ls", guidText));
}

static BOOL kvm_relay_build_bridge_pipe_namesW(WCHAR* inputPipeName, size_t inputPipeLen, WCHAR* outputPipeName, size_t outputPipeLen)
{
	WCHAR basePipeName[MAX_PATH * 4] = { 0 };

	if (inputPipeName == NULL || inputPipeLen == 0 || outputPipeName == NULL || outputPipeLen == 0) { return FALSE; }
	inputPipeName[0] = L'\0';
	outputPipeName[0] = L'\0';

	if (!kvm_relay_build_bridge_pipe_baseW(basePipeName, _countof(basePipeName))) { return FALSE; }
	if (FAILED(StringCchPrintfW(inputPipeName, inputPipeLen, L"%ls_in", basePipeName))) { return FALSE; }
	if (FAILED(StringCchPrintfW(outputPipeName, outputPipeLen, L"%ls_out", basePipeName))) { return FALSE; }
	return TRUE;
}

static int kvm_relay_append_bridge_env_passthrough(char** envvars, int pairCount, int maxPairs, const char* name, char* valueBuffer, size_t valueBufferLen)
{
	DWORD len = 0;

	if (envvars == NULL || name == NULL || valueBuffer == NULL || valueBufferLen == 0) { return pairCount; }
	if (pairCount < 0 || pairCount >= maxPairs) { return pairCount; }
	len = GetEnvironmentVariableA(name, valueBuffer, (DWORD)valueBufferLen);
	if (len == 0 || len >= valueBufferLen) { return pairCount; }
	envvars[pairCount * 2] = (char*)name;
	envvars[(pairCount * 2) + 1] = valueBuffer;
	return pairCount + 1;
}

static BOOL kvm_relay_create_bridge_server_pipeW(const WCHAR* pipeName, DWORD pipeOpenMode, HANDLE* pipeOut)
{
	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	SECURITY_ATTRIBUTES securityAttributes;
	HANDLE pipeHandle = INVALID_HANDLE_VALUE;
	DWORD pipeBufferSize = 1024 * 1024;
	static const WCHAR* KVM_BRIDGE_PIPE_DACL_SDDL = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)(A;;GA;;;SU)";

	if (pipeOut == NULL || pipeName == NULL || pipeName[0] == L'\0') { return FALSE; }
	*pipeOut = INVALID_HANDLE_VALUE;

	ZeroMemory(&securityAttributes, sizeof(securityAttributes));
	securityAttributes.nLength = sizeof(securityAttributes);
	securityAttributes.bInheritHandle = FALSE;

	// The bridge helper is intentionally spawned with the logged-on session token
	// for USER/SPECIFIED_USER launch modes, so the pipe ACL must admit interactive
	// users in addition to SYSTEM/Administrators.
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(KVM_BRIDGE_PIPE_DACL_SDDL, SDDL_REVISION_1, &securityDescriptor, NULL))
	{
		return FALSE;
	}

	securityAttributes.lpSecurityDescriptor = securityDescriptor;
	pipeHandle = CreateNamedPipeW(
		pipeName,
		pipeOpenMode | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		pipeBufferSize,
		pipeBufferSize,
		0,
		&securityAttributes);
	LocalFree(securityDescriptor);
	if (pipeHandle == INVALID_HANDLE_VALUE) { return FALSE; }

	*pipeOut = pipeHandle;
	return TRUE;
}

static void kvm_relay_cancel_bridge_pipe_connect(HANDLE pipeHandle, OVERLAPPED* overlapped)
{
	DWORD ignored = 0;

	if (pipeHandle == NULL || pipeHandle == INVALID_HANDLE_VALUE || overlapped == NULL) { return; }
	if (CancelIoEx(pipeHandle, overlapped))
	{
		GetOverlappedResult(pipeHandle, overlapped, &ignored, TRUE);
	}
}

static BOOL kvm_relay_wait_for_bridge_client(KvmRelayContext* ctx, HANDLE bridgePipeHandle, DWORD timeoutMs, LONG expectedSessionGeneration, DWORD* errorOut, BOOL* sessionChangedOut)
{
	HANDLE pipeHandle = bridgePipeHandle;
	HANDLE sessionChangeEvent = NULL;
	HANDLE waitHandles[2];
	OVERLAPPED overlapped;
	DWORD waitResult = WAIT_FAILED;
	DWORD transferred = 0;
	BOOL ok = FALSE;
	DWORD errorCode = ERROR_SUCCESS;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (sessionChangedOut != NULL) { *sessionChangedOut = FALSE; }
	if (pipeHandle == NULL || pipeHandle == INVALID_HANDLE_VALUE)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_HANDLE; }
		return FALSE;
	}
	if (ctx == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (kvm_relay_session_generation_changed(ctx, expectedSessionGeneration))
	{
		if (errorOut != NULL) { *errorOut = ERROR_OPERATION_ABORTED; }
		if (sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }
		return FALSE;
	}

	ZeroMemory(&overlapped, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (overlapped.hEvent == NULL)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}

	if (ConnectNamedPipe(pipeHandle, &overlapped))
	{
		ok = TRUE;
		goto cleanup;
	}

	errorCode = GetLastError();
	switch (errorCode)
	{
	case ERROR_PIPE_CONNECTED:
		ok = TRUE;
		break;
	case ERROR_IO_PENDING:
		if (!kvm_relay_arm_session_change_wait(ctx, expectedSessionGeneration, &sessionChangeEvent, &errorCode))
		{
			if (errorCode == ERROR_OPERATION_ABORTED && sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }
			kvm_relay_cancel_bridge_pipe_connect(pipeHandle, &overlapped);
			break;
		}
		waitHandles[0] = overlapped.hEvent;
		waitHandles[1] = sessionChangeEvent;
		waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, timeoutMs);
		if (waitResult == WAIT_OBJECT_0)
		{
			if (GetOverlappedResult(pipeHandle, &overlapped, &transferred, FALSE))
			{
				ok = TRUE;
			}
			else
			{
				errorCode = GetLastError();
				if (errorCode == ERROR_SUCCESS) { errorCode = ERROR_GEN_FAILURE; }
			}
		}
		else if (waitResult == WAIT_OBJECT_0 + 1)
		{
			errorCode = ERROR_OPERATION_ABORTED;
			if (sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }
			kvm_relay_cancel_bridge_pipe_connect(pipeHandle, &overlapped);
		}
		else
		{
			errorCode = (waitResult == WAIT_TIMEOUT) ? WAIT_TIMEOUT : GetLastError();
			kvm_relay_cancel_bridge_pipe_connect(pipeHandle, &overlapped);
		}
		break;
	default:
		break;
	}

cleanup:
	if (ok && kvm_relay_session_generation_changed(ctx, expectedSessionGeneration))
	{
		ok = FALSE;
		errorCode = ERROR_OPERATION_ABORTED;
		if (sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }
	}
	CloseHandle(overlapped.hEvent);
	if (!ok && errorOut != NULL) { *errorOut = errorCode; }
	return ok;
}

static BOOL kvm_relay_attach_bridge_transport(KvmRelayContext* ctx, HANDLE inputPipeHandle, HANDLE outputPipeHandle)
{
	HANDLE duplicatedOutputPipe = NULL;
	int bridgeClientConnected;
	int bridgeTransportAttached;

	if (ctx == NULL || ctx->pipeMgr == NULL || inputPipeHandle == NULL || inputPipeHandle == INVALID_HANDLE_VALUE || outputPipeHandle == NULL || outputPipeHandle == INVALID_HANDLE_VALUE) { return FALSE; }
	if (!DuplicateHandle(GetCurrentProcess(), outputPipeHandle, GetCurrentProcess(), &duplicatedOutputPipe, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		return FALSE;
	}

	ctx->bridgeReadPipe = ILibProcessPipe_Pipe_CreateFromExisting(ctx->pipeMgr, duplicatedOutputPipe, ILibProcessPipe_Pipe_ReaderHandleType_Overlapped);
	if (ctx->bridgeReadPipe == NULL)
	{
		CloseHandle(duplicatedOutputPipe);
		return FALSE;
	}
	ILibProcessPipe_Pipe_ResetMetadata(ctx->bridgeReadPipe, "Mesh KVM bridge stdout pipe");
	ILibProcessPipe_Pipe_SetBrokenPipeHandler(ctx->bridgeReadPipe, &kvm_relay_bridge_pipe_broken_handler);
	// Buffer must be large enough to hold a complete JUMBO frame (~350 KB at
	// 3440x1440).  The old 64 KB buffer forced the parser to accumulate across
	// multiple reads, and interleaved control packets from the input thread
	// corrupted the stream before the full frame could be assembled.
	ILibProcessPipe_Pipe_AddPipeReadHandler(ctx->bridgeReadPipe, 524288, &kvm_relay_bridge_pipe_read_handler);
	InterlockedExchange(&ctx->bridgeTransportAttached, 1);

	// Diagnostic: verify the pipe handle is readable
	// Flush any control packets that were cached while the bridge was connecting,
	// then start the bridge read pipe in RESUMED state so the child's initial
	// screen-size / display-list packets flow through to the browser immediately.
	//
	// The previous code propagated the startup pause state (paused=1) here, which
	// created a deadlock: the child's capture loop runs unpaused (g_pause=0 in
	// kvm_server_mainloop_ex), writes frames into the data pipe, and blocks once
	// the pipe buffer fills — but the parent never reads because the bridge pipe
	// is paused, and the browser never sends an unpause because it never receives
	// the initial screen packet.
	//
	// Normal backpressure still works: kvm_relay_consume_output_buffer pauses the
	// bridge pipe when writeHandler returns INCOMPLETE and resumes it on COMPLETE.
	bridgeClientConnected = (InterlockedCompareExchange(&ctx->bridgeClientConnected, 0, 0) != 0);
	bridgeTransportAttached = (InterlockedCompareExchange(&ctx->bridgeTransportAttached, 0, 0) != 0);
	if (bridgeClientConnected && bridgeTransportAttached && !kvm_relay_flush_cached_control_packets(ctx))
	{
		return FALSE;
	}
	if (!kvm_relay_flush_cached_control_packets(ctx))
	{
		return FALSE;
	}

	// Start reading from the child — resume the pipe and clear the pause flag.
	if (!kvm_relay_set_bridge_pause_state(ctx, 0, 1))
	{
		return FALSE;
	}
	return TRUE;
}

static int kvm_is_bridge_available(void)
{
	WCHAR dllPath[MAX_PATH * 4];
	return kvm_relay_resolve_bridge_dll_pathW(gKvmExePath, dllPath, _countof(dllPath)) ? 1 : 0;
}

static void kvm_update_runtime_state(int childPresent, int transportActive)
{
	gKvmChildPresent = childPresent;
	gKvmTransportActive = transportActive;
}

static void kvm_clear_pending_unqueryable_start(void)
{
	gKvmPendingUnqueryableStartEvent = 0;
	gKvmPendingUnqueryableStartSessionId = 0;
	gKvmPendingUnqueryableStartRetryCount = 0;
}

static void kvm_record_spawn_failure(DWORD error, DWORD stage, DWORD spawnType)
{
	if (error == ERROR_SUCCESS) { error = ERROR_GEN_FAILURE; }
	gKvmLastBridgeFailureError = error;
	gKvmLastBridgeFailureStage = stage;
	gKvmLastBridgeFailureSpawnType = spawnType;
	++gKvmConsecutiveFailures;
}

static void kvm_record_spawn_success(void *reserved, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler)
{
	KvmRelayContext* ctx = kvm_relay_get_context();
	int childUsesBridge = (ctx != NULL && InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0) ? 1 : 0;
	int transportActive = childUsesBridge == 0 ? 1 : ((ctx != NULL && InterlockedCompareExchange(&ctx->bridgeTransportAttached, 0, 0) != 0) ? 1 : 0);

	gKvmDebugReserved = reserved;
	gKvmPipeMgr = pipeMgr;
	gKvmExePath = exePath;
	gKvmWriteHandler = writeHandler;
	gKvmRegisteredContextCount = (reserved != NULL ? 1 : 0);
	gKvmChildExitSignaled = 0;
	gKvmRestartSuppressed = 0;
	gKvmPendingSessionRestartEvent = 0;
	gKvmPendingSessionRestartSessionId = 0;
	kvm_clear_pending_unqueryable_start();
	gKvmRetryScheduled = 0;
	gKvmSessionStartTickMs = GetTickCount64();
	gKvmLastBridgeAvailable = kvm_is_bridge_available();
	gKvmLastUsedBridge = childUsesBridge;
	gKvmLastFallbackUsed = childUsesBridge == 0 ? 1 : 0;
	gKvmProcessSessionId = (gProcessTSID >= 0) ? (DWORD)gProcessTSID : WTSGetActiveConsoleSessionId();
	kvm_update_runtime_state(1, transportActive);
}

static void kvm_record_healthy_output(void)
{
	gKvmLastBridgeFailureError = 0;
	gKvmLastBridgeFailureStage = 0;
	gKvmLastBridgeFailureSpawnType = 0;
	gKvmConsecutiveFailures = 0;
	gKvmLastBackoffDelayMs = 0;
	gKvmRetryScheduled = 0;
}

static DWORD kvm_calculate_backoff_delay_ms(void)
{
	DWORD shift = (gKvmConsecutiveFailures > 6 ? 6 : gKvmConsecutiveFailures);
	DWORD delayMs = 0;

	if (shift > 0)
	{
		delayMs = (1UL << shift) * 1000UL;
		if (delayMs > 60000UL) { delayMs = 60000UL; }
	}
	return delayMs;
}

static int kvm_retry_pending_unqueryable_start(KvmRelayContext* ctx)
{
	DWORD eventType = gKvmPendingUnqueryableStartEvent;
	DWORD sessionId = gKvmPendingUnqueryableStartSessionId;

	if (eventType == 0 || !kvm_session_id_is_valid(sessionId)) { return 0; }
	if (!kvm_session_id_exists(sessionId))
	{
		kvm_trace_startupf("session start token retry abandoned because session no longer exists event=%u session=%u current=%u tsid=%d",
			(unsigned int)eventType,
			(unsigned int)sessionId,
			(unsigned int)gKvmProcessSessionId,
			gProcessTSID);
		kvm_clear_pending_unqueryable_start();
		return 0;
	}
	if (kvm_session_id_has_user_token(sessionId))
	{
		kvm_trace_startupf("session start token retry succeeded event=%u session=%u retries=%u current=%u tsid=%d",
			(unsigned int)eventType,
			(unsigned int)sessionId,
			(unsigned int)gKvmPendingUnqueryableStartRetryCount,
			(unsigned int)gKvmProcessSessionId,
			gProcessTSID);
		kvm_clear_pending_unqueryable_start();
		kvm_relay_capture_context(ctx);
		kvm_relay_handle_session_change_for_context(ctx, eventType, sessionId);
		return 1;
	}
	if (gKvmPendingUnqueryableStartRetryCount >= KVM_SESSION_START_TOKEN_RETRY_MAX)
	{
		kvm_trace_startupf("session start token retry exhausted event=%u session=%u retries=%u current=%u tsid=%d",
			(unsigned int)eventType,
			(unsigned int)sessionId,
			(unsigned int)gKvmPendingUnqueryableStartRetryCount,
			(unsigned int)gKvmProcessSessionId,
			gProcessTSID);
		kvm_clear_pending_unqueryable_start();
		return 0;
	}

	++gKvmPendingUnqueryableStartRetryCount;
	kvm_trace_startupf("session start token retry still waiting event=%u session=%u retry=%u max=%u current=%u tsid=%d",
		(unsigned int)eventType,
		(unsigned int)sessionId,
		(unsigned int)gKvmPendingUnqueryableStartRetryCount,
		(unsigned int)KVM_SESSION_START_TOKEN_RETRY_MAX,
		(unsigned int)gKvmProcessSessionId,
		gProcessTSID);
	kvm_schedule_retry_timer_delay(KVM_SESSION_START_TOKEN_RETRY_DELAY_MS);
	return 1;
}

static void kvm_retry_timer_callback(void* object)
{
	KvmRelayContext* ctx = (KvmRelayContext*)object;
	int destroyContext = 0;
	int pendingStartHandled = 0;
	int staleRefreshHandled = 0;

	kvm_relay_lock();
	kvm_relay_activate_context(ctx);
	gKvmRetryScheduled = 0;
	pendingStartHandled = kvm_retry_pending_unqueryable_start(ctx);
	if (pendingStartHandled == 0)
	{
		staleRefreshHandled = kvm_relay_handle_refresh_probe_timeout(ctx, "timer");
	}
	if (pendingStartHandled == 0 && staleRefreshHandled == 0 && g_shutdown == 0 && gKvmRestartSuppressed == 0 &&
		gChildProcess == NULL && gKvmPipeMgr != NULL && gKvmWriteHandler != NULL)
	{
#ifdef _WINSERVICE
		kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);
#endif
	}
	kvm_relay_capture_context(ctx);
	if (ctx != NULL && ctx->destroyPending != 0 && ctx->childProcess == NULL && ctx->retryScheduled == 0)
	{
		destroyContext = 1;
		kvm_relay_unregister_context_locked(ctx);
	}
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
	if (destroyContext)
	{
		kvm_relay_destroy_context(ctx);
	}
}

static void kvm_schedule_retry_timer_delay(DWORD delayMs)
{
	void* timer = NULL;
	KvmRelayContext* ctx = kvm_relay_get_context();

	if (ctx == NULL || gILibChain == NULL) { return; }
	timer = ILibGetBaseTimer(gILibChain);
	if (timer == NULL) { return; }

	gKvmRetryScheduled = 1;
	ILibLifeTime_Remove(timer, ctx);
	ILibLifeTime_AddEx(timer, ctx, (int)delayMs, &kvm_retry_timer_callback, NULL);
}

static void kvm_schedule_retry_timer(void)
{
	DWORD backoffDelayMs = kvm_calculate_backoff_delay_ms();

	gKvmLastBackoffDelayMs = backoffDelayMs;
	kvm_schedule_retry_timer_delay(backoffDelayMs);
}

static int kvm_parse_bool(const char* value, int defaultValue)
{
	if (value == NULL || value[0] == 0) { return defaultValue; }
	if (_stricmp(value, "1") == 0 || _stricmp(value, "true") == 0 || _stricmp(value, "yes") == 0 || _stricmp(value, "on") == 0) { return 1; }
	if (_stricmp(value, "0") == 0 || _stricmp(value, "false") == 0 || _stricmp(value, "no") == 0 || _stricmp(value, "off") == 0) { return 0; }
	return defaultValue;
}

static int kvm_read_env_bool(const char* name, int defaultValue)
{
	char buffer[32];
	DWORD len = GetEnvironmentVariableA(name, buffer, (DWORD)sizeof(buffer));
	if (len == 0 || len >= sizeof(buffer)) { return defaultValue; }
	return kvm_parse_bool(buffer, defaultValue);
}

static DWORD kvm_desktop_access_mask(void)
{
	return
		DESKTOP_CREATEMENU |
		DESKTOP_CREATEWINDOW |
		DESKTOP_ENUMERATE |
		DESKTOP_HOOKCONTROL |
		DESKTOP_WRITEOBJECTS |
		DESKTOP_READOBJECTS |
		DESKTOP_SWITCHDESKTOP |
		GENERIC_READ |
		GENERIC_WRITE;
}

static BOOL kvm_bind_current_process_to_interactive_window_station(DWORD* errorOut)
{
	HWINSTA currentWindowStation = GetProcessWindowStation();
	HWINSTA windowStation = NULL;
	BOOL ok = FALSE;
	WCHAR currentName[64];
	DWORD currentNameBytes = 0;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (currentWindowStation != NULL &&
		GetUserObjectInformationW(currentWindowStation, UOI_NAME, currentName, sizeof(currentName), &currentNameBytes))
	{
		currentName[63] = L'\0';
		if (_wcsicmp(currentName, L"WinSta0") == 0) { return TRUE; }
	}

	windowStation = OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ALL_ACCESS);
	if (windowStation == NULL)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}

	ok = SetProcessWindowStation(windowStation);
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	if (!ok) { CloseWindowStation(windowStation); }
	return ok;
}

static int kvm_should_prefer_bridge(char* exePath)
{
	UNREFERENCED_PARAMETER(exePath);
	return 1;
}

static const char* kvm_spawn_type_to_string(ILibProcessPipe_SpawnTypes spawnType)
{
	switch (spawnType)
	{
	case ILibProcessPipe_SpawnTypes_USER: return "USER";
	case ILibProcessPipe_SpawnTypes_WINLOGON: return "WIN_LOGON";
	case ILibProcessPipe_SpawnTypes_SPECIFIED_USER: return "SPECIFIED_USER";
	case ILibProcessPipe_SpawnTypes_DEFAULT: return "DEFAULT";
	default: return "OTHER";
	}
}

#ifdef _WINSERVICE
#define MESH_KVM_BRIDGE_EVENT_ID_ATTEMPT 0xC0082001
#define MESH_KVM_BRIDGE_EVENT_ID_OUTCOME 0xC0082002

static BOOL kvm_bridge_get_service_nameW(WCHAR* buffer, size_t bufferLen)
{
	if (buffer == NULL || bufferLen == 0) { return FALSE; }
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), buffer, bufferLen);
	buffer[bufferLen - 1] = L'\0';
	return buffer[0] != L'\0';
}

static void kvm_bridge_build_timestampW(WCHAR* buffer, size_t bufferLen)
{
	SYSTEMTIME localTime;

	if (buffer == NULL || bufferLen == 0) { return; }
	GetLocalTime(&localTime);
	if (FAILED(StringCchPrintfW(
		buffer,
		bufferLen,
		L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
		(unsigned int)localTime.wYear,
		(unsigned int)localTime.wMonth,
		(unsigned int)localTime.wDay,
		(unsigned int)localTime.wHour,
		(unsigned int)localTime.wMinute,
		(unsigned int)localTime.wSecond,
		(unsigned int)localTime.wMilliseconds)))
	{
		buffer[0] = L'\0';
	}
}

static void kvm_bridge_get_module_pathW(WCHAR* modulePath, size_t modulePathLen)
{
	DWORD pathLen = 0;

	if (modulePath == NULL || modulePathLen == 0) { return; }
	modulePath[0] = L'\0';
	pathLen = GetModuleFileNameW(NULL, modulePath, (DWORD)modulePathLen);
	if (pathLen == 0 || pathLen >= modulePathLen)
	{
		modulePath[0] = L'\0';
	}
}

static void kvm_bridge_get_dll_pathW(const char* exePath, WCHAR* dllPath, size_t dllPathLen)
{
	if (dllPath == NULL || dllPathLen == 0) { return; }
	dllPath[0] = L'\0';
	if (exePath != NULL && exePath[0] != 0)
	{
		if (kvm_relay_resolve_bridge_dll_pathW((char*)exePath, dllPath, dllPathLen))
		{
			return;
		}
	}
	if (gKvmExePath != NULL && gKvmExePath[0] != 0)
	{
		(void)kvm_relay_resolve_bridge_dll_pathW(gKvmExePath, dllPath, dllPathLen);
	}
}

static void kvm_bridge_get_spawn_typeW(ILibProcessPipe_SpawnTypes spawnType, WCHAR* spawnTypeW, size_t spawnTypeLen)
{
	const char* spawnTypeA = kvm_spawn_type_to_string(spawnType);
	int converted = 0;

	if (spawnTypeW == NULL || spawnTypeLen == 0) { return; }
	spawnTypeW[0] = L'\0';
	if (spawnTypeA == NULL || spawnTypeA[0] == 0) { return; }
	converted = MultiByteToWideChar(CP_UTF8, 0, spawnTypeA, -1, spawnTypeW, (int)spawnTypeLen);
	if (converted <= 0)
	{
		spawnTypeW[0] = L'\0';
	}
}

static BOOL kvm_bridge_ensure_event_source(void)
{
	LONG currentState = InterlockedCompareExchange(&gKvmEventSourceRegistrationState, 0, 0);
	WCHAR serviceName[256];
	WCHAR modulePath[MAX_PATH * 4];
	WCHAR keyPath[512];
	HKEY eventKey = NULL;
	DWORD disposition = 0;
	DWORD typesSupported = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
	LONG regResult = ERROR_GEN_FAILURE;

	if (currentState == 1) { return TRUE; }
	if (!kvm_bridge_get_service_nameW(serviceName, _countof(serviceName))) { return FALSE; }
	kvm_bridge_get_module_pathW(modulePath, _countof(modulePath));
	if (modulePath[0] == L'\0') { return FALSE; }
	if (FAILED(StringCchPrintfW(
		keyPath,
		_countof(keyPath),
		L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%ls",
		serviceName)))
	{
		return FALSE;
	}

	regResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &eventKey, &disposition);
	if (regResult == ERROR_SUCCESS && eventKey != NULL)
	{
		regResult = RegSetValueExW(eventKey, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE*)modulePath, (DWORD)((wcslen(modulePath) + 1) * sizeof(WCHAR)));
		if (regResult == ERROR_SUCCESS)
		{
			regResult = RegSetValueExW(eventKey, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&typesSupported, sizeof(typesSupported));
		}
		RegCloseKey(eventKey);
	}
	if (regResult == ERROR_SUCCESS)
	{
		InterlockedExchange(&gKvmEventSourceRegistrationState, 1);
	}
	return regResult == ERROR_SUCCESS;
}

static void kvm_bridge_report_event(const WCHAR* outcome, WORD eventType, DWORD eventId, DWORD pid, DWORD sessionId, const char* exePath, ILibProcessPipe_SpawnTypes spawnType, DWORD errorCode)
{
	WCHAR serviceName[256];
	WCHAR dllPath[MAX_PATH * 4];
	WCHAR spawnTypeW[32];
	WCHAR pidText[32];
	WCHAR sessionText[32];
	WCHAR errorText[32];
	WCHAR timestamp[64];
	const WCHAR* strings[8];
	HANDLE eventSource = NULL;

	if (outcome == NULL || outcome[0] == L'\0') { return; }
	if (!kvm_bridge_get_service_nameW(serviceName, _countof(serviceName))) { return; }
	(void)kvm_bridge_ensure_event_source();
	eventSource = RegisterEventSourceW(NULL, serviceName);
	if (eventSource == NULL) { return; }

	kvm_bridge_get_dll_pathW(exePath, dllPath, _countof(dllPath));
	kvm_bridge_get_spawn_typeW(spawnType, spawnTypeW, _countof(spawnTypeW));
	kvm_bridge_build_timestampW(timestamp, _countof(timestamp));
	(void)StringCchPrintfW(pidText, _countof(pidText), L"%lu", (unsigned long)pid);
	(void)StringCchPrintfW(sessionText, _countof(sessionText), L"%lu", (unsigned long)sessionId);
	(void)StringCchPrintfW(errorText, _countof(errorText), L"%lu", (unsigned long)errorCode);

	strings[0] = outcome;
	strings[1] = pidText;
	strings[2] = sessionText;
	strings[3] = dllPath;
	strings[4] = L"SYSTEM";
	strings[5] = spawnTypeW;
	strings[6] = errorText;
	strings[7] = timestamp;
	(void)ReportEventW(eventSource, eventType, 0, eventId, NULL, (WORD)_countof(strings), 0, strings, NULL);
	DeregisterEventSource(eventSource);
}

static void kvm_bridge_report_attempt_event(const char* exePath, ILibProcessPipe_SpawnTypes spawnType)
{
	DWORD sessionId = (gProcessTSID >= 0) ? (DWORD)gProcessTSID : WTSGetActiveConsoleSessionId();
	kvm_bridge_report_event(L"ATTEMPT", EVENTLOG_INFORMATION_TYPE, MESH_KVM_BRIDGE_EVENT_ID_ATTEMPT, 0, sessionId, exePath, spawnType, 0);
}

static void kvm_bridge_report_outcome_event(const WCHAR* outcome, WORD eventType, DWORD pid, DWORD errorCode, const char* exePath, ILibProcessPipe_SpawnTypes spawnType)
{
	DWORD sessionId = (gProcessTSID >= 0) ? (DWORD)gProcessTSID : WTSGetActiveConsoleSessionId();
	kvm_bridge_report_event(outcome, eventType, MESH_KVM_BRIDGE_EVENT_ID_OUTCOME, pid, sessionId, exePath, spawnType, errorCode);
}
#endif

HANDLE hStdOut = INVALID_HANDLE_VALUE;
HANDLE hStdIn = INVALID_HANDLE_VALUE;
int ThreadRunning = 0;
int kvmConsoleMode = 0;

ILibQueue gPendingPackets = NULL;

ILibRemoteLogging gKVMRemoteLogging = NULL;
#ifdef _WINSERVICE
void kvm_slave_OnRawForwardLog(ILibRemoteLogging sender, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *buffer, int bufferLen)
{
	if (flags <= ILibRemoteLogging_Flags_VerbosityLevel_1)
	{
		KVMDebugLog *log = (KVMDebugLog*)buffer;
		log->length = bufferLen + 1;
		log->logType = (unsigned short)module;
		log->logFlags = (unsigned short)flags;
		buffer[bufferLen] = 0;

		WriteFile(GetStdHandle(STD_ERROR_HANDLE), buffer, log->length, &bufferLen, NULL);
	}
}
#endif

void kvm_setupSasPermissions()
{
	DWORD dw = 3;
	HKEY key = NULL;

	KVMDEBUG("kvm_setupSasPermissions", 0);

    // SoftwareSASGeneration
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
	{
		RegSetValueEx(key, "SoftwareSASGeneration", 0, REG_DWORD, (BYTE*)&dw, 4);
		RegCloseKey(key);
	}
}

// Emulate the CTRL-ALT-DEL (Should work on WinXP, not on Vista & Win7)
DWORD WINAPI kvm_ctrlaltdel(LPVOID Param)
{
	UNREFERENCED_PARAMETER( Param );
	KVMDEBUG("kvm_ctrlaltdel", (int)(uintptr_t)Param);
	typedef VOID(WINAPI *SendSas)(BOOL asUser);
	SendSas sas;

	// Perform new method (Vista & Win7)
	HMODULE m = LoadLibraryExA("sas.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

	// We need to dynamically load this, becuase it doesn't exist on Windows Core.
	// However, LOAD_LIBRARY_SEARCH_SYSTEM32 does not exist on Windows 7 SP1 / Windows Server 2008 R2 without a MSFT Patch,
	// but this patch is no longer available from MSFT, so this fallback case will only affect insecure versions of Windows 7 SP1 / Server 2008 R2
	if (m == NULL && GetLastError() == ERROR_INVALID_PARAMETER) { m = LoadLibraryA("sas.dll"); }	
	if (m != NULL)
	{
		sas = (SendSas)GetProcAddress(m, "SendSAS");
		if (sas != NULL)
		{
			kvm_setupSasPermissions();
			sas(FALSE);
		}
		FreeLibrary(m);
	}
	return 0;
}

BOOL CALLBACK DisplayInfoEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
	int w, h, deviceid = 0;
    MONITORINFOEX mi;
	DWORD *selection = (DWORD*)dwData;
	UNREFERENCED_PARAMETER( hdcMonitor );
	UNREFERENCED_PARAMETER( lprcMonitor );

	ZeroMemory(&mi, sizeof(mi));
    mi.cbSize = sizeof(mi);

	// Get the display information
    if (!GetMonitorInfo(hMonitor, (LPMONITORINFO)&mi)) return TRUE;
	if (sscanf_s(mi.szDevice, "\\\\.\\DISPLAY%d", &deviceid) != 1) return TRUE;
	if (--selection[0] > 0) { return TRUE; }
	
	// See if anything changed
	w = abs(mi.rcMonitor.left - mi.rcMonitor.right);
	h = abs(mi.rcMonitor.top - mi.rcMonitor.bottom);
	if (SCREEN_X != mi.rcMonitor.left || SCREEN_Y !=  mi.rcMonitor.top || SCREEN_WIDTH != w || SCREEN_HEIGHT != h || kvm_read_scaling_factor(&SCALING_FACTOR) != kvm_read_scaling_factor(&SCALING_FACTOR_NEW))
	{
		SCREEN_X = mi.rcMonitor.left;
		SCREEN_Y = mi.rcMonitor.top;
		SCREEN_WIDTH = w;
		SCREEN_HEIGHT = h;
		SCREEN_SEL_PROCESS |= 1;	// Force the new resolution to be sent to the client.
	}

	if (SCREEN_SEL != SCREEN_SEL_TARGET)
	{
		SCREEN_SEL = SCREEN_SEL_TARGET;
		SCREEN_SEL_PROCESS |= 2;	// Force the display list to be sent to the client, includes the new display selection
	}
   
    return TRUE;
}

BOOL CALLBACK DisplayInfoEnumProc_Info(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData)
{
	unsigned short* buffer = (unsigned short*)dwData;
	MONITORINFOEX mi;
	UNREFERENCED_PARAMETER(hdcMonitor);
	UNREFERENCED_PARAMETER(lprcMonitor);

	ZeroMemory(&mi, sizeof(mi));
	mi.cbSize = sizeof(mi);

	// Get the display information
	if (!GetMonitorInfo(hMonitor, (LPMONITORINFO)&mi)) return TRUE;
	int w = abs(mi.rcMonitor.left - mi.rcMonitor.right);
	int h = abs(mi.rcMonitor.top - mi.rcMonitor.bottom);

	int i = (int)(buffer[0]++);
	int offset = (5 * i) + 4;

	if ((((i + 1) * 10) + 4) > buffer[1]) { return(FALSE); }

	buffer[offset] = (unsigned short)htons((unsigned short)(i+1));						// ID
	buffer[offset+1] = (unsigned short)htons((unsigned short)(mi.rcMonitor.left));		// X
	buffer[offset+2] = (unsigned short)htons((unsigned short)(mi.rcMonitor.top));		// Y
	buffer[offset+3] = (unsigned short)htons((unsigned short)(w));						// WIDTH
	buffer[offset+4] = (unsigned short)htons((unsigned short)(h));						// HEIGHT
	return(TRUE);
}

static int kvm_server_configure_remote_resume_event(void)
{
	if (gKvmRemoteResumeEvent == NULL)
	{
		gKvmRemoteResumeEvent = CreateEvent(NULL, TRUE, g_remotepause == 0 ? TRUE : FALSE, NULL);
		if (gKvmRemoteResumeEvent == NULL)
		{
			kvm_trace_startupf("KVM startup: CreateEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
			return 0;
		}
		return 1;
	}
	if (g_remotepause != 0)
	{
		if (!ResetEvent(gKvmRemoteResumeEvent))
		{
			kvm_trace_startupf("KVM startup: ResetEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
			return 0;
		}
	}
	else if (!SetEvent(gKvmRemoteResumeEvent))
	{
		kvm_trace_startupf("KVM startup: SetEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
		return 0;
	}
	return 1;
}

static void kvm_server_set_remote_pause_state(int pause)
{
	g_remotepause = pause != 0 ? 1 : 0;
	if (gKvmRemoteResumeEvent != NULL)
	{
		if (g_remotepause != 0)
		{
			if (!ResetEvent(gKvmRemoteResumeEvent))
			{
				kvm_trace_startupf("KVM input: ResetEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
			}
		}
		else if (!SetEvent(gKvmRemoteResumeEvent))
		{
			kvm_trace_startupf("KVM input: SetEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
		}
	}
}

static void kvm_server_signal_remote_resume_waiters(void)
{
	if (gKvmRemoteResumeEvent != NULL && !SetEvent(gKvmRemoteResumeEvent))
	{
		kvm_trace_startupf("KVM shutdown: SetEvent(remote resume) failed error=%lu", (unsigned long)GetLastError());
	}
}

static int kvm_server_wait_for_remote_resume(const char* stage)
{
	DWORD waitResult = WAIT_FAILED;

	while (!g_shutdown && g_remotepause != 0)
	{
		if (gKvmRemoteResumeEvent == NULL && !kvm_server_configure_remote_resume_event())
		{
			g_shutdown = 1;
			return 0;
		}
		waitResult = WaitForSingleObjectEx(gKvmRemoteResumeEvent, INFINITE, TRUE);
		if (waitResult == WAIT_OBJECT_0 || g_remotepause == 0 || g_shutdown)
		{
			break;
		}
		if (waitResult == WAIT_IO_COMPLETION)
		{
			continue;
		}
		kvm_trace_startupf("KVM startup: remote resume wait failed stage=%s result=%lu error=%lu",
			stage != NULL ? stage : "unknown",
			(unsigned long)waitResult,
			(unsigned long)GetLastError());
		g_shutdown = 1;
		return 0;
	}
	return g_shutdown == 0;
}

static ILibTransport_DoneState kvm_server_write_packet_checked(ILibKVM_WriteHandler writeHandler, char* buffer, int bufferLen, void *reserved, const char* stage)
{
	ILibTransport_DoneState writeState;
	unsigned short packetType = 0;

	if (buffer != NULL && bufferLen >= 2)
	{
		packetType = (unsigned short)ntohs(((unsigned short*)buffer)[0]);
	}
	if (writeHandler == NULL || buffer == NULL || bufferLen <= 0)
	{
		kvm_trace_startupf("KVM output: invalid write request stage=%s type=%u len=%d handler=%p buffer=%p",
			stage != NULL ? stage : "unknown",
			(unsigned int)packetType,
			bufferLen,
			writeHandler,
			buffer);
		g_shutdown = 1;
		return ILibTransport_DoneState_ERROR;
	}

	writeState = writeHandler(buffer, bufferLen, reserved);
	switch (writeState)
	{
	case ILibTransport_DoneState_COMPLETE:
		break;
	case ILibTransport_DoneState_INCOMPLETE:
		g_pause = 1;
		kvm_trace_startupf("KVM output: backpressure stage=%s type=%u len=%d",
			stage != NULL ? stage : "unknown",
			(unsigned int)packetType,
			bufferLen);
		break;
	case ILibTransport_DoneState_ERROR:
	default:
		g_shutdown = 1;
		kvm_trace_startupf("KVM output: write failed stage=%s type=%u len=%d state=%d",
			stage != NULL ? stage : "unknown",
			(unsigned int)packetType,
			bufferLen,
			(int)writeState);
		break;
	}
	return writeState;
}

static BOOL CALLBACK kvm_server_initialize_tile_info_lock(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
{
	UNREFERENCED_PARAMETER(InitOnce);
	UNREFERENCED_PARAMETER(Parameter);
	UNREFERENCED_PARAMETER(Context);
	return InitializeCriticalSectionEx(&gKvmTileInfoLock, 4000, 0);
}

static int kvm_server_enter_tile_info_lock(const char* stage)
{
	if (!InitOnceExecuteOnce(&gKvmTileInfoLockOnce, kvm_server_initialize_tile_info_lock, NULL, NULL))
	{
		kvm_trace_startupf("KVM tile state: lock initialization failed stage=%s error=%lu",
			stage != NULL ? stage : "unknown",
			(unsigned long)GetLastError());
		g_shutdown = 1;
		return 0;
	}
	EnterCriticalSection(&gKvmTileInfoLock);
	return 1;
}

static void kvm_server_leave_tile_info_lock(void)
{
	LeaveCriticalSection(&gKvmTileInfoLock);
}

static void kvm_server_free_tile_info(struct tileInfo_t **info, int rowCount)
{
	int row;

	if (info == NULL) { return; }
	for (row = 0; row < rowCount; ++row)
	{
		free(info[row]);
	}
	free(info);
}

static struct tileInfo_t **kvm_server_allocate_tile_info(int rowCount, int colCount, const char* stage)
{
	struct tileInfo_t **newTileInfo = NULL;
	size_t rows = (size_t)rowCount;
	size_t cols = (size_t)colCount;
	int row, col;

	if (rowCount <= 0 || colCount <= 0)
	{
		kvm_trace_startupf("KVM tile state: invalid geometry stage=%s rows=%d cols=%d",
			stage != NULL ? stage : "unknown",
			rowCount,
			colCount);
		return NULL;
	}
	if (rows > ((size_t)-1) / sizeof(struct tileInfo_t*) || cols > ((size_t)-1) / sizeof(struct tileInfo_t))
	{
		kvm_trace_startupf("KVM tile state: allocation size overflow stage=%s rows=%d cols=%d",
			stage != NULL ? stage : "unknown",
			rowCount,
			colCount);
		return NULL;
	}

	newTileInfo = (struct tileInfo_t**)calloc(rows, sizeof(struct tileInfo_t*));
	if (newTileInfo == NULL)
	{
		kvm_trace_startupf("KVM tile state: row allocation failed stage=%s rows=%d cols=%d",
			stage != NULL ? stage : "unknown",
			rowCount,
			colCount);
		return NULL;
	}
	for (row = 0; row < rowCount; ++row)
	{
		newTileInfo[row] = (struct tileInfo_t*)calloc(cols, sizeof(struct tileInfo_t));
		if (newTileInfo[row] == NULL)
		{
			kvm_trace_startupf("KVM tile state: column allocation failed stage=%s row=%d rows=%d cols=%d",
				stage != NULL ? stage : "unknown",
				row,
				rowCount,
				colCount);
			kvm_server_free_tile_info(newTileInfo, rowCount);
			return NULL;
		}
		for (col = 0; col < colCount; ++col)
		{
			newTileInfo[row][col].crc = 0xFF;
			newTileInfo[row][col].flags = 0;
		}
	}
	return newTileInfo;
}

static int kvm_server_ensure_tile_info_locked(const char* stage)
{
	int row;

	if (TILE_HEIGHT_COUNT <= 0 || TILE_WIDTH_COUNT <= 0)
	{
		kvm_trace_startupf("KVM tile state: unavailable geometry stage=%s rows=%d cols=%d",
			stage != NULL ? stage : "unknown",
			TILE_HEIGHT_COUNT,
			TILE_WIDTH_COUNT);
		g_shutdown = 1;
		return 0;
	}
	if (tileInfo == NULL)
	{
		tileInfo = kvm_server_allocate_tile_info(TILE_HEIGHT_COUNT, TILE_WIDTH_COUNT, stage);
		if (tileInfo == NULL)
		{
			g_shutdown = 1;
			return 0;
		}
		kvm_trace_startupf("KVM tile state: allocated missing tile table stage=%s rows=%d cols=%d",
			stage != NULL ? stage : "unknown",
			TILE_HEIGHT_COUNT,
			TILE_WIDTH_COUNT);
	}
	for (row = 0; row < TILE_HEIGHT_COUNT; ++row)
	{
		if (tileInfo[row] == NULL)
		{
			kvm_trace_startupf("KVM tile state: corrupt tile row stage=%s row=%d rows=%d cols=%d",
				stage != NULL ? stage : "unknown",
				row,
				TILE_HEIGHT_COUNT,
				TILE_WIDTH_COUNT);
			g_shutdown = 1;
			return 0;
		}
	}
	return 1;
}

static int kvm_server_reset_tile_info_locked(const char* stage, int resetCrc, char flagValue)
{
	int row, col;

	if (!kvm_server_ensure_tile_info_locked(stage)) { return 0; }
	for (row = 0; row < TILE_HEIGHT_COUNT; ++row)
	{
		for (col = 0; col < TILE_WIDTH_COUNT; ++col)
		{
			if (resetCrc != 0)
			{
				tileInfo[row][col].crc = 0xFF;
			}
			tileInfo[row][col].flags = flagValue;
		}
	}
	return 1;
}

void kvm_send_display_list(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int i;
	char dwData[4096];
	((unsigned short*)dwData)[0] = (unsigned short)0;
	((unsigned short*)dwData)[1] = (unsigned short)sizeof(dwData);
	((unsigned short*)dwData)[2] = (unsigned short)htons((unsigned short)MNG_KVM_DISPLAY_INFO);			// Write the type
	if (EnumDisplayMonitors(NULL, NULL, DisplayInfoEnumProc_Info, (LPARAM)dwData))
	{
		((unsigned short*)dwData)[3] = (unsigned short)htons((((unsigned short*)dwData)[0]) * 10 + 4);	// Length
		if (kvm_server_write_packet_checked(writeHandler, dwData + 4, (((unsigned short*)dwData)[0]) * 10 + 4, reserved, "display-info") == ILibTransport_DoneState_ERROR) return;
	}

	// Not looked at the number of screens yet
	if (SCREEN_COUNT == -1) return;
	char *buffer = ILibMemory_AllocateA((5 + SCREEN_COUNT) * 2);
	memset(buffer, 0xFF, ILibMemory_AllocateA_Size(buffer));
	// Send the list of possible displays to remote
	if (SCREEN_COUNT == 0 || SCREEN_COUNT == 1)
	{
		// Only one display, send empty
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(8));						// Write the size
		((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(0));						// Screen Count
		((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(0));						// Selected Screen

		kvm_server_write_packet_checked(writeHandler, buffer, 8, reserved, "display-list");
	}
	else
	{
		// Many displays
		((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);		// Write the type
		((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(10 + (2 * SCREEN_COUNT)));	// Write the size
		((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)(SCREEN_COUNT + 1));			// Screen Count
		((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)(-1));						// Possible Screen (ALL)
		for (i = 0; i < SCREEN_COUNT; i++) {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(i + 1));				// Possible Screen
		}
		if (SCREEN_SEL == 0) {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(-1));				// Selected Screen (All)
		} else {
			((unsigned short*)buffer)[4 + i] = (unsigned short)htons((unsigned short)(SCREEN_SEL));		// Selected Screen
		}

		kvm_server_write_packet_checked(writeHandler, buffer, (10 + (2 * SCREEN_COUNT)), reserved, "display-list");
	}
}

void kvm_server_SetResolution();
int kvm_server_currentDesktopname = 0;
int gKvmDesktopCaptureReady = 1;
static void kvm_server_prime_startup_geometry_if_needed()
{
	if (SCREEN_WIDTH > 0 && SCREEN_HEIGHT > 0) { return; }

	VSCREEN_X = GetSystemMetrics(SM_XVIRTUALSCREEN);
	VSCREEN_Y = GetSystemMetrics(SM_YVIRTUALSCREEN);
	VSCREEN_WIDTH = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	VSCREEN_HEIGHT = GetSystemMetrics(SM_CYVIRTUALSCREEN);

	if (SCREEN_SEL_TARGET == 0)
	{
		if (VSCREEN_WIDTH <= 0 || VSCREEN_HEIGHT <= 0)
		{
			SCREEN_X = 0;
			SCREEN_Y = 0;
			SCREEN_WIDTH = GetSystemMetrics(SM_CXSCREEN);
			SCREEN_HEIGHT = GetSystemMetrics(SM_CYSCREEN);
		}
		else
		{
			SCREEN_X = VSCREEN_X;
			SCREEN_Y = VSCREEN_Y;
			SCREEN_WIDTH = VSCREEN_WIDTH;
			SCREEN_HEIGHT = VSCREEN_HEIGHT;
		}
		SCREEN_SEL = SCREEN_SEL_TARGET;
	}
	else
	{
		DWORD selection = SCREEN_SEL_TARGET;
		if (EnumDisplayMonitors(NULL, NULL, DisplayInfoEnumProc, (LPARAM)&selection))
		{
			SCREEN_SEL = SCREEN_SEL_TARGET;
		}
		SCREEN_SEL_PROCESS = 0;
	}
}

void CheckDesktopSwitch(int checkres, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	int x, y, w, h;
	HDESK desktop;
	HDESK desktop2;
	char name[64];
	char currentName[64] = { 0 };
	char targetName[64] = { 0 };
	int haveCurrentName = 0;
	int haveTargetName = 0;
	int desktopSwitchEvent = KVM_ConsumeDesktopSwitchEvent();
	int desktopNameChanged = 0;
	int explicitWinlogon = 0;
	int desktopAccessReady = 1;
	DWORD windowStationError = ERROR_SUCCESS;

	// KVMDEBUG("CheckDesktopSwitch", checkres);

	// Check desktop switch
	if ((desktop2 = GetThreadDesktop(GetCurrentThreadId())) == NULL) { KVMDEBUG("GetThreadDesktop Error", 0); } // CloseDesktop() is not needed
	if (desktop2 != NULL && GetUserObjectInformationA(desktop2, UOI_NAME, currentName, 63, 0))
	{
		currentName[63] = 0;
		haveCurrentName = 1;
	}
	if (!kvm_bind_current_process_to_interactive_window_station(&windowStationError))
	{
		kvm_trace_startupf("KVM startup: SetProcessWindowStation(WinSta0) failed error=%lu", windowStationError);
	}
	if (InterlockedCompareExchange(&gKvmForceDefaultDesktop, 0, 0) != 0)
	{
		desktop = OpenDesktopW(L"Default", 0, FALSE, kvm_desktop_access_mask());
		if (desktop == NULL) { KVMDEBUG("OpenDesktop(Default) Error", 0); }
	}
	else
	{
		desktop = OpenInputDesktop(0, FALSE, kvm_desktop_access_mask());
		if (desktop == NULL)
		{
			DWORD inputDesktopError = GetLastError();
			KVMDEBUG("OpenInputDesktop Error", 0);
			kvm_trace_startupf("KVM startup: OpenInputDesktop failed error=%lu", inputDesktopError);
			desktop = OpenDesktopW(L"Default", 0, FALSE, kvm_desktop_access_mask());
			if (desktop != NULL)
			{
				kvm_trace_startupf("KVM startup: falling back to WinSta0\\\\Default after OpenInputDesktop failure");
			}
			else
			{
				kvm_trace_startupf("KVM startup: OpenDesktop(Default) fallback failed error=%lu", GetLastError());
			}
		}
	}
	if (desktop == NULL)
	{
		desktopAccessReady = 0;
	}

	if (desktop != NULL && GetUserObjectInformationA(desktop, UOI_NAME, targetName, 63, 0))
	{
		targetName[63] = 0;
		haveTargetName = 1;
		if (InterlockedCompareExchange(&gKvmForceDefaultDesktop, 0, 0) == 0 && _stricmp(targetName, "Winlogon") == 0)
		{
			HDESK secureDesktop = OpenDesktopW(L"Winlogon", 0, FALSE, kvm_desktop_access_mask());
			explicitWinlogon = 1;
			if (secureDesktop != NULL)
			{
				if (CloseDesktop(desktop) == 0) { KVMDEBUG("CloseDesktop(OpenInputDesktop) Error", 0); }
				desktop = secureDesktop;
				strncpy_s(targetName, sizeof(targetName), "Winlogon", _TRUNCATE);
			}
		}
	}

	if (desktop != NULL && haveCurrentName != 0 && haveTargetName != 0 && _stricmp(currentName, targetName) == 0)
	{
		if (CloseDesktop(desktop) == 0) { KVMDEBUG("CloseDesktop(UnchangedDesktop) Error", 0); }
		desktop = desktop2;
	}
	else if (desktop != NULL && SetThreadDesktop(desktop) == 0)
	{
		kvm_trace_startupf("KVM startup: SetThreadDesktop failed error=%lu desktop=%p", GetLastError(), desktop);
		if (CloseDesktop(desktop) == 0) { KVMDEBUG("CloseDesktop1 Error", 0); }
		desktop = desktop2;
		desktopAccessReady = 0;
	}
	else
	{
		desktop = desktop2;
	}
	gKvmDesktopCaptureReady = desktopAccessReady;

	// Check desktop name switch
	if (GetUserObjectInformationA(desktop, UOI_NAME, name, 63, 0))
	{
		name[63] = 0;
		strncpy_s(gKvmCurrentDesktopName, sizeof(gKvmCurrentDesktopName), name, _TRUNCATE);

		//ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: name = %s", name);

		// KVMDEBUG(name, 0);
		if (kvm_server_currentDesktopname == 0)
		{
			// This is the first time we come here.
			kvm_server_currentDesktopname = ((int*)name)[0];
		}
		else
		{
			// If the desktop name has changed, update and re-read resolution
			// (upstream behavior: adapt in-place, do NOT kill the child)
			if (kvm_server_currentDesktopname != ((int*)name)[0])
			{
				desktopNameChanged = 1;
				KVMDEBUG("DESKTOP NAME CHANGE DETECTED, adapting in-place", 0);
				ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: kvm_server_currentDesktop: NAME CHANGE DETECTED, adapting...");
				kvm_server_currentDesktopname = ((int*)name)[0];
			}
		}
		if (desktopNameChanged != 0 || desktopSwitchEvent != 0)
		{
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
				"KVM [SLAVE]: desktop switch old=%s new=%s explicitWinlogon=%d event=%d",
				haveCurrentName != 0 ? currentName : "(unknown)",
				name,
				explicitWinlogon,
				desktopSwitchEvent);
			kvm_server_SetResolution(writeHandler, reserved);
			kvm_send_display_list(writeHandler, reserved);
		}
	}
	else
	{
		KVMDEBUG("GetUserObjectInformation Error", 0);
	}

	// See if the number of displays has changed
	x = GetSystemMetrics(SM_CMONITORS);
	if (SCREEN_COUNT != x) { SCREEN_COUNT = x; kvm_send_display_list(writeHandler, reserved); }

	// Prime startup geometry before GDI initialization, because raw SM_CXSCREEN/SM_CYSCREEN can
	// still report 0x0 immediately after a service-context bridge desktop switch.
	if (g_shutdown == 0) { kvm_server_prime_startup_geometry_if_needed(); }

	// Check resolution change
	if (checkres != 0 && g_shutdown == 0)
	{
		VSCREEN_X = GetSystemMetrics(SM_XVIRTUALSCREEN);
		VSCREEN_Y = GetSystemMetrics(SM_YVIRTUALSCREEN);
		VSCREEN_WIDTH = GetSystemMetrics(SM_CXVIRTUALSCREEN);
		VSCREEN_HEIGHT = GetSystemMetrics(SM_CYVIRTUALSCREEN);

		if (SCREEN_SEL_TARGET == 0)
		{
			if (VSCREEN_WIDTH == 0)
			{
				// Old style, one display only. Added this just in case VIRTUALSCREEN does not work.
				x = 0;
				y = 0;
				w = GetSystemMetrics(SM_CXSCREEN);
				h = GetSystemMetrics(SM_CYSCREEN);
			} else {
				// New style, entire virtual desktop
				x = VSCREEN_X;
				y = VSCREEN_Y;
				w = VSCREEN_WIDTH;
				h = VSCREEN_HEIGHT;
			}

			if (SCREEN_X != x || SCREEN_Y != y || SCREEN_WIDTH != w || SCREEN_HEIGHT != h || kvm_read_scaling_factor(&SCALING_FACTOR) != kvm_read_scaling_factor(&SCALING_FACTOR_NEW))
			{
				//printf("RESOLUTION CHANGED! (supposedly)\n");
				SCREEN_X = x;
				SCREEN_Y = y;
				SCREEN_WIDTH = w;
				SCREEN_HEIGHT = h;
				kvm_server_SetResolution(writeHandler, reserved);
			}

			if (SCREEN_SEL_TARGET != SCREEN_SEL) { SCREEN_SEL = SCREEN_SEL_TARGET; kvm_send_display_list(writeHandler, reserved); }
		}
		else
		{
			// Get the list of monitors
			if (SCREEN_SEL_PROCESS == 0)
			{
				DWORD selection = SCREEN_SEL_TARGET;
				if (EnumDisplayMonitors(NULL, NULL, DisplayInfoEnumProc, (LPARAM)&selection))
				{
					// Set the resolution
					if (SCREEN_SEL_PROCESS & 1) kvm_server_SetResolution(writeHandler, reserved);
					if (SCREEN_SEL_PROCESS & 2) kvm_send_display_list(writeHandler, reserved);
				}
				SCREEN_SEL_PROCESS = 0;
			}
		}
	}
}

unsigned char g_blockinput = 0;

static int kvm_should_trace_input_command(unsigned short type, unsigned short size, const char* block)
{
	switch (type)
	{
	case MNG_KVM_INPUT_LOCK:
	case MNG_KVM_KEY:
	case MNG_KVM_KEY_UNICODE:
		return 1;
	case MNG_KVM_MOUSE:
		{
			static volatile LONG mouseMoveTraceCount = 0;
			unsigned char button = (size > 5 && block != NULL) ? (unsigned char)block[5] : 0;
			short wheel = (size >= 12 && block != NULL) ? (short)ntohs(((unsigned short*)(block + 10))[0]) : 0;
			LONG sample = 0;

			if (button != 0 || wheel != 0) { return 1; }
			sample = InterlockedIncrement(&mouseMoveTraceCount);
			return (sample <= 5 || (sample % 100) == 0);
		}
	default:
		return 0;
	}
}

static void kvm_trace_input_command(const char* stage, unsigned short type, unsigned short size, const char* block, int blocklen)
{
	unsigned int detail0 = 0;

	if (kvm_should_trace_input_command(type, size, block) == 0) { return; }
	if (block != NULL && size > 4) { detail0 = (unsigned int)(unsigned char)block[4]; }
	kvm_trace_startupf("KVM input packet: stage=%s type=%u size=%u blocklen=%d desktop=%s screen=%dx%d vscreen=%dx%d blockinput=%u detail0=%u",
		stage != NULL ? stage : "unknown",
		(unsigned int)type,
		(unsigned int)size,
		blocklen,
		kvm_get_current_desktop_name(),
		SCREEN_WIDTH,
		SCREEN_HEIGHT,
		VSCREEN_WIDTH,
		VSCREEN_HEIGHT,
		(unsigned int)g_blockinput,
		detail0);
}

// Feed network data into the KVM. Return the number of bytes consumed.
// This method consumes a single command.
int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	unsigned short type, size;

	// Decode the block header
	if (blocklen < 4) return 0;

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [SLAVE]: Handle Input [Len = %d]", blocklen);
	// KVMDEBUG("kvm_server_inputdata", blocklen);
	CheckDesktopSwitch(0, writeHandler, reserved);

	type = ntohs(((unsigned short*)(block))[0]);
	size = ntohs(((unsigned short*)(block))[1]);

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [SLAVE]: Handle Input [Len = %d, type = %u, size = %u]", blocklen, type, size);

	if (size > blocklen) return 0;
	if (size < 4) return blocklen; // Malformed header (size must cover the 4-byte header); drop the rest to avoid a stall/desync of the input stream.
	kvm_trace_input_command("decoded", type, size, block, blocklen);

	//printf("INPUT: %d, %d\r\n", type, size);

	switch (type)
	{
	case MNG_KVM_INPUT_LOCK:
		// 0 = unlock
		// 1 = lock
		// 2 = query
		if (size == 5)
		{
			switch (block[4])
			{
				case 0:
					g_blockinput = 0;
					BlockInput(0);
					break;
				case 1:
					g_blockinput = 1;
					BlockInput(1);
					break;
				case 2:
					break;
				default:
					return(size);
					break;
			}

			unsigned char buffer[5];
			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INPUT_LOCK);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);					// Write the size
			buffer[4] = g_blockinput;																	// status

			writeHandler((char*)buffer, 5, reserved);
		}
		
		break;
	case MNG_KVM_KEY: // Key
		{
			if (size != 6) break;
			//KVM_WriteLog(writeHandler, reserved, "Key[%u] UP: %d", (unsigned char)(block[5]), block[4]);
			KeyAction(block[5], block[4]);
			break;
		}
	case MNG_KVM_KEY_UNICODE: // Unicode key
		{
			if (size != 7) break;
			//KVM_WriteLog(writeHandler, reserved, "UnicodeKey[%u] UP: %d", ((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			KeyActionUnicode(((((unsigned char)block[5]) << 8) + ((unsigned char)block[6])), block[4]);
			break;
		}
	case MNG_KVM_MOUSE: // Mouse
		{
			double x, y;
			short w = 0;
			KVM_MouseCursors curcursor = KVM_MouseCursor_NOCHANGE;

			if (size == 10 || size == 12)
			{
				int scaling = kvm_read_scaling_factor(&SCALING_FACTOR);
				gRemoteMouseMoved = 1;

				// Get positions and scale correctly
				x = (double)ntohs(((short*)(block))[3]) * 1024 / scaling;
				y = (double)ntohs(((short*)(block))[4]) * 1024 / scaling;

				// Effective virtual-desktop geometry. In the single-monitor fallback
				// (SM_CXVIRTUALSCREEN returned 0) VSCREEN_* stay 0 while SCREEN_* are
				// populated, so fall back to SCREEN_* to avoid a divide-by-zero / NaN.
				int vox = (VSCREEN_WIDTH > 0) ? VSCREEN_X : SCREEN_X;
				int voy = (VSCREEN_HEIGHT > 0) ? VSCREEN_Y : SCREEN_Y;
				int vw = (VSCREEN_WIDTH > 0) ? VSCREEN_WIDTH : SCREEN_WIDTH;
				int vh = (VSCREEN_HEIGHT > 0) ? VSCREEN_HEIGHT : SCREEN_HEIGHT;
				if (vw <= 0 || vh <= 0) break; // Geometry not primed yet; cannot map this event.

				// Add relative display position
				x += (double)(SCREEN_X - vox);
				y += (double)(SCREEN_Y - voy);

				// Normalize to the virtual desktop. SendInput maps the normalized value
				// back to a pixel with (dx * width) >> 16, so aim at the pixel center to
				// keep the round trip from drifting toward the top-left.
				x = ((x + 0.5) * (double)65536) / (double)vw;
				y = ((y + 0.5) * (double)65536) / (double)vh;

				// Perform the mouse movement
				if (size == 12) w = ((short)ntohs(((short*)(block))[5]));
				MouseAction(x, y, (int)(unsigned char)(block[5]), w);
			}
			break;
		}
	case MNG_KVM_COMPRESSION: // Compression
		{
			if (size >= 10) { int fr = ((int)ntohs(((unsigned short*)(block + 8))[0])); if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr; }
			if (size >=  8) { int ns = ((int)ntohs(((unsigned short*)(block + 6))[0])); if (ns >= 64 && ns <= 4096) kvm_write_scaling_factor(&SCALING_FACTOR_NEW, ns); }
			if (size >=  6) { set_tile_compression((int)block[4], (int)block[5]); }
			COMPRESSION_RATIO = 100;
			break;
		}
	case MNG_KVM_REFRESH: // Refresh
		{
			char buffer[8];
			if (size != 4) break;

			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
			((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)SCALED_WIDTH);		// X position
			((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)SCALED_HEIGHT);	// Y position

			if (kvm_server_write_packet_checked(writeHandler, (char*)buffer, 8, reserved, "refresh-resolution") == ILibTransport_DoneState_ERROR) break;

			// Send the list of available displays
			kvm_send_display_list(writeHandler, reserved);

			// Reset all tile information
			if (!kvm_server_enter_tile_info_lock("refresh")) { break; }
			if (!kvm_server_reset_tile_info_locked("refresh", 1, 0))
			{
				kvm_server_leave_tile_info_lock();
				break;
			}
			kvm_server_leave_tile_info_lock();

			break;
		}
	case MNG_KVM_PAUSE: // Pause
		{
			if (size != 5) break;
			kvm_server_set_remote_pause_state(block[4]);
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Remote %s requested", g_remotepause != 0 ? "pause" : "resume");
			break;
		}
	case MNG_KVM_DISCONNECT:
		{
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Received disconnect request");
			g_shutdown = 1;
			kvm_server_signal_remote_resume_waiters();
			break;
		}
	case MNG_KVM_FRAME_RATE_TIMER:
		{
			if (size < 6) break;
			int fr = ((int)ntohs(((unsigned short*)(block))[2]));
			if (fr >= 20 && fr <= 5000) FRAME_RATE_TIMER = fr;
			break;
		}
	case MNG_KVM_INIT_TOUCH:
		{
			// Attempt to initialized touch support
			char buffer[6];
			unsigned short r = (unsigned short)TouchInit();
			((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INIT_TOUCH);	// Write the type
			((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)6);					// Write the size
			((unsigned short*)buffer)[2] = (unsigned short)htons(r);									// Write the return code

			writeHandler((char*)buffer, 6, reserved);
			break;
		}
	case MNG_KVM_TOUCH:
		{
			int r = 0;

			// Both versions need at least 14 bytes: the v1 fixed layout
			// (2 type + 2 size + 1 version + 1 id + 4 flags + 2 x + 2 y),
			// or the v2 header (5) plus one 9-byte touch record.
			if (size < 14) break;

			if (block[4] == 1) // Version 1 touch structure (Very simple)
			{
				int scaling = kvm_read_scaling_factor(&SCALING_FACTOR);
				unsigned int flags = (unsigned int)ntohl(((unsigned int*)(block + 6))[0]);

				// Descale to local pixels, then translate to desktop coordinates;
				// InjectTouchInput takes raw pixel positions, not the normalized
				// values SendInput uses for the mouse.
				int x = KVM_DescaleToPixel((int)ntohs(((unsigned short*)(block + 10))[0]), scaling) + SCREEN_X;
				int y = KVM_DescaleToPixel((int)ntohs(((unsigned short*)(block + 12))[0]), scaling) + SCREEN_Y;

				r = TouchAction1(block[5], flags, x, y);
			}
			else if (block[4] == 2) // Version 2 touch structure array
			{
				r = TouchAction2(block + 5, size - 5, kvm_read_scaling_factor(&SCALING_FACTOR), SCREEN_X, SCREEN_Y);
			}

			if (r == 1) {
				// Reset touch
				char buffer[4];
				((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_TOUCH); // Write the type
				((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);			 // Write the size

				writeHandler((char*)buffer, 4, reserved);
			}
			break;
		}
	case MNG_KVM_GET_DISPLAYS:
		{
			kvm_send_display_list(writeHandler, reserved);
			break;
		}
	case MNG_KVM_SET_DISPLAY:
		{
			// Set the display
			int x = 0;
			if (size < 6) break;
			x = (unsigned short)ntohs(((unsigned short*)(block + 4))[0]);
			if (x == 65535) SCREEN_SEL_TARGET = 0; else SCREEN_SEL_TARGET = x;
			break;
		}
	}
	return size;
}

typedef struct kvm_data_handler
{
	ILibKVM_WriteHandler handler;
	void *reserved;
	int len;
	char buffer[];
}kvm_data_handler;



// Feed network data into the KVM. Return the number of bytes consumed.
// This method consumes as many input commands as it can.
int kvm_relay_feeddata(char* buf, int len, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	int consumed = 0;

	kvm_relay_lock();
	kvm_relay_activate_context(ctx);
	int childUsesBridge = (ctx != NULL && InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0) ? 1 : 0;

	if (buf != NULL && len >= 4)
	{
		kvm_bridge_debug_note_input(buf, (size_t)len);
		if (kvm_relay_handle_refresh_probe_timeout(ctx, "input") != 0)
		{
			consumed = 0;
			goto finish;
		}
	}

	if (gChildProcess != NULL)
	{
		if (len >= 2 && ntohs(((unsigned short*)buf)[0]) == MNG_CTRLALTDEL)
		{
			HANDLE ht = CreateThread(NULL, 0, kvm_ctrlaltdel, 0, 0, 0);
			if (ht != NULL) CloseHandle(ht);
		}
		if (childUsesBridge != 0)
		{
			if (InterlockedCompareExchange(&ctx->bridgeTransportAttached, 0, 0) != 0)
			{
				if (!kvm_relay_write_bridge_input(ctx, buf, len))
				{
					DWORD writeError = GetLastError();
					consumed = kvm_relay_prepare_bridge_respawn_from_input(ctx, buf, len, "write-failed", writeError) ? len : 0;
					goto finish;
				}
			}
			else if (!kvm_relay_cache_control_packet(ctx, buf, len))
			{
				ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [Master]: Dropping pre-attach bridge input type=%u len=%d", ntohs(((unsigned short*)buf)[0]), len);
				consumed = 0;
				goto finish;
			}
		}
		else
		{
			ILibProcessPipe_Process_WriteStdIn(gChildProcess, buf, len, ILibTransport_MemoryOwnership_USER);
		}
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_2, "KVM [Master]: Write Input [Type = %u]", ntohs(((unsigned short*)buf)[0]));
		consumed = len;
	}
	else
	{
		int len2 = 0;
		int ptr = 0;
#ifdef _WINSERVICE
		if (ctx != NULL && gKvmPipeMgr != NULL && gKvmExePath != NULL && gKvmWriteHandler != NULL)
		{
			consumed = kvm_relay_prepare_bridge_respawn_from_input(ctx, buf, len, "no-child", ERROR_SUCCESS) ? len : 0;
			goto finish;
		}
#endif
		//while ((len2 = kvm_server_inputdata(buf + ptr, len - ptr, kvm_relay_feeddata_ex, (void*[]) {writeHandler, reserved})) != 0) { ptr += len2; }
		while ((len2 = kvm_server_inputdata(buf + ptr, len - ptr, writeHandler, reserved)) != 0) { ptr += len2; }
		consumed = ptr;
	}
finish:
	kvm_relay_capture_context(ctx);
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
	return consumed;
}

static int kvm_relay_select_session_id(int requestedTsid)
{
	DWORD bestActiveConsole = 0;
	DWORD bestActive = 0;
	DWORD bestConnectedConsole = 0;
	DWORD bestConnected = 0;
	DWORD bestConsole = 0;
	DWORD activeConsole = WTSGetActiveConsoleSessionId();
	DWORD level = 1;
	DWORD sessionCount = 0;
	WTS_SESSION_INFO_1W* sessionInfo = NULL;
	DWORD i = 0;

	if (requestedTsid >= 0) { return requestedTsid; }

	if (WTSEnumerateSessionsExW(WTS_CURRENT_SERVER_HANDLE, &level, 0, &sessionInfo, &sessionCount))
	{
		for (i = 0; i < sessionCount; ++i)
		{
			HANDLE userToken = NULL;
			DWORD sessionId = sessionInfo[i].SessionId;
			int isConsoleSession = 0;

			if (sessionId == 0 || sessionId == 0xFFFFFFFF) { continue; }
			if (!WTSQueryUserToken(sessionId, &userToken)) { continue; }
			CloseHandle(userToken);

			isConsoleSession = (sessionId == activeConsole || (sessionInfo[i].pSessionName != NULL && _wcsicmp(sessionInfo[i].pSessionName, L"Console") == 0));
			if (isConsoleSession && bestConsole == 0)
			{
				bestConsole = sessionId;
			}
			if (sessionInfo[i].State == WTSActive)
			{
				if (isConsoleSession)
				{
					if (bestActiveConsole == 0) { bestActiveConsole = sessionId; }
				}
				else if (bestActive == 0)
				{
					bestActive = sessionId;
				}
				continue;
			}
			if (sessionInfo[i].State == WTSConnected)
			{
				if (isConsoleSession)
				{
					if (bestConnectedConsole == 0) { bestConnectedConsole = sessionId; }
				}
				else if (bestConnected == 0)
				{
					bestConnected = sessionId;
				}
			}
		}
		WTSFreeMemoryExW(WTSTypeSessionInfoLevel1, sessionInfo, sessionCount);
	}

	if (bestActiveConsole != 0) { return (int)bestActiveConsole; }
	if (bestActive != 0) { return (int)bestActive; }
	if (bestConnectedConsole != 0) { return (int)bestConnectedConsole; }
	if (bestConnected != 0) { return (int)bestConnected; }
	if (bestConsole != 0) { return (int)bestConsole; }
	return (activeConsole == 0xFFFFFFFF) ? -1 : (int)activeConsole;
}

// Set the KVM pause state
void kvm_pause(int pause, void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_lookup_context(reserved);
	int normalizedPause = pause != 0 ? 1 : 0;
	kvm_relay_lock();
	kvm_relay_activate_context(ctx);
	// KVMDEBUG("kvm_pause", pause);
	if (gChildProcess == NULL)
	{
		g_pause = normalizedPause;
		if (ctx != NULL)
		{
			InterlockedExchange(&ctx->bridgeProtocolPauseState, normalizedPause);
		}
	}
	else if (ctx != NULL && InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0)
	{
		if (!kvm_relay_set_bridge_pause_state(ctx, normalizedPause, 0))
		{
			g_shutdown = 1;
		}
	}
	else
	{
		if (pause == 0)
		{
			KVMDEBUG2("RESUME: KVM");
			ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Process_GetStdOut(gChildProcess));
		}
		else
		{
			KVMDEBUG2("PAUSE: KVM");
			ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Process_GetStdOut(gChildProcess));
		}
	}
	kvm_relay_capture_context(ctx);
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
}

void kvm_server_SetResolution(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[8];
	int scaling;
	long long scaledWidth64;
	long long scaledHeight64;
	int newScaledWidth;
	int newScaledHeight;
	int newTileWidthCount;
	int newTileHeightCount;
	int oldTileHeightCount;
	struct tileInfo_t **newTileInfo = NULL;
	struct tileInfo_t **oldTileInfo = NULL;

	KVMDEBUG("kvm_server_SetResolution", 0);
	kvm_server_ensure_tile_geometry();
	kvm_server_prime_startup_geometry_if_needed();
	if (SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0)
	{
		kvm_trace_startupf("KVM startup: SetResolution skipped invalid screen geometry screen=%dx%d vscreen=%dx%d",
			SCREEN_WIDTH,
			SCREEN_HEIGHT,
			VSCREEN_WIDTH,
			VSCREEN_HEIGHT);
		return;
	}

	// Setup scaling
	scaling = kvm_read_scaling_factor(&SCALING_FACTOR_NEW);
	scaledWidth64 = ((long long)SCREEN_WIDTH * (long long)scaling) / 1024LL;
	scaledHeight64 = ((long long)SCREEN_HEIGHT * (long long)scaling) / 1024LL;
	if (scaledWidth64 <= 0 || scaledHeight64 <= 0 || scaledWidth64 > 65535LL || scaledHeight64 > 65535LL)
	{
		kvm_trace_startupf("KVM startup: SetResolution computed invalid scaled geometry screen=%dx%d scale=%d scaled=%lldx%lld",
			SCREEN_WIDTH,
			SCREEN_HEIGHT,
			scaling,
			scaledWidth64,
			scaledHeight64);
		g_shutdown = 1;
		return;
	}
	newScaledWidth = (int)scaledWidth64;
	newScaledHeight = (int)scaledHeight64;

	// Compute the tile count
	newTileWidthCount = newScaledWidth / TILE_WIDTH;
	newTileHeightCount = newScaledHeight / TILE_HEIGHT;
	if (newScaledWidth % TILE_WIDTH) newTileWidthCount++;
	if (newScaledHeight % TILE_HEIGHT) newTileHeightCount++;

	newTileInfo = kvm_server_allocate_tile_info(newTileHeightCount, newTileWidthCount, "resolution");
	if (newTileInfo == NULL)
	{
		g_shutdown = 1;
		return;
	}

	if (!kvm_server_enter_tile_info_lock("resolution"))
	{
		kvm_server_free_tile_info(newTileInfo, newTileHeightCount);
		return;
	}
	oldTileInfo = tileInfo;
	oldTileHeightCount = TILE_HEIGHT_COUNT;
	kvm_write_scaling_factor(&SCALING_FACTOR, scaling);
	SCALED_WIDTH = newScaledWidth;
	SCALED_HEIGHT = newScaledHeight;
	TILE_WIDTH_COUNT = newTileWidthCount;
	TILE_HEIGHT_COUNT = newTileHeightCount;
	tileInfo = newTileInfo;
	InterlockedIncrement(&gKvmTileInfoGeneration);
	kvm_server_leave_tile_info_lock();
	kvm_server_free_tile_info(oldTileInfo, oldTileHeightCount);

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_SCREEN);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)8);				// Write the size
	((unsigned short*)buffer)[2] = (unsigned short)htons((unsigned short)newScaledWidth);	// X position
	((unsigned short*)buffer)[3] = (unsigned short)htons((unsigned short)newScaledHeight);	// Y position

	kvm_server_write_packet_checked(writeHandler, (char*)buffer, 8, reserved, "resolution");
}

#define BUFSIZE 65535
#ifdef _WINSERVICE
DWORD WINAPI kvm_mainloopinput_ex(LPVOID Param)
{
	int ptr = 0;
	int ptr2 = 0;
	int len = 0;
	char pchRequest2[30000];
	BOOL fSuccess = FALSE;
	DWORD cbBytesRead = 0;
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)Param)[0];
	void *reserved = ((void**)Param)[1];

	KVMDEBUG("kvm_mainloopinput / start", (int)GetCurrentThreadId());

	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: (mainloopinput) Starting...");
	kvm_trace_startupf("KVM input loop: starting thread=%lu", (unsigned long)GetCurrentThreadId());


	while (!g_shutdown)
	{
		if (len >= (int)sizeof(pchRequest2))
		{
			kvm_trace_startupf("KVM input loop: dropping full unconsumed buffer len=%d ptr=%d", len, ptr);
			len = 0;
			ptr = 0;
		}
		fSuccess = ReadFile(hStdIn, pchRequest2 + len, (DWORD)(sizeof(pchRequest2) - len), &cbBytesRead, NULL);
		if (!fSuccess || cbBytesRead == 0 || g_shutdown) 
		{ 
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: fSuccess/%d  cbBytesRead/%d  g_shutdown/%d", fSuccess, cbBytesRead, g_shutdown);
			kvm_trace_startupf("KVM input loop: ReadFile exit fSuccess=%d cbBytesRead=%lu shutdown=%d error=%lu", fSuccess, (unsigned long)cbBytesRead, g_shutdown, (unsigned long)GetLastError());
			KVMDEBUG("ReadFile() failed", 0); /*ILIBMESSAGE("KVMBREAK-K1\r\n");*/
			g_shutdown = 1;
			kvm_server_signal_remote_resume_waiters();
			break;
		}
		len += (int)cbBytesRead;
		ptr2 = 0;
		while ((ptr2 = kvm_server_inputdata((char*)pchRequest2 + ptr, len - ptr, writeHandler, reserved)) != 0) { ptr += ptr2; }
		if (ptr == len) { len = 0; ptr = 0; }
		else if (ptr > 0)
		{
			memmove(pchRequest2, pchRequest2 + ptr, (size_t)(len - ptr));
			len -= ptr;
			ptr = 0;
		}
	}
	ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: (mainloopinput) Exiting...");
	kvm_trace_startupf("KVM input loop: exiting shutdown=%d", g_shutdown);
	ILibRemoteLogging_Destroy(gKVMRemoteLogging);
	gKVMRemoteLogging = NULL;

	KVMDEBUG("kvm_mainloopinput / end", (int)GetCurrentThreadId());

	return 0;
}

DWORD WINAPI kvm_mainloopinput(LPVOID Param)
{
	DWORD ret = 0;
	if (((int*)&(((void**)Param)[3]))[0] == 1)
	{
		ILib_DumpEnabledContext winException;
		__try
		{
			ret = kvm_mainloopinput_ex(Param);
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
	}
	else
	{
		ret = kvm_mainloopinput_ex(Param);
	}
	return(ret);
}
#endif


// This is the main KVM pooling loop. It will look at the display and see if any changes occur. [Runs as daemon if Windows Service]
DWORD WINAPI kvm_server_mainloop_ex(LPVOID parm)
{
	//long cur_timestamp = 0;
	//long prev_timestamp = 0;
	//long time_diff = 50;
	long long tilesize;
	int width, height = 0;
	int gdiplusAttempted = 0;
	int inputThreadStarted = 0;
	int startupResolutionRecovered = 0;
	int captureFailureCount = 0;
	ULONGLONG captureFailureStartTick = 0;
	void *buf, *desktop;
	long long desktopsize;
	BITMAPINFO bmpInfo;
	int row, col;
	LONG captureTileGeneration = 0;
	ILibKVM_WriteHandler writeHandler = (ILibKVM_WriteHandler)((void**)parm)[0];
	void *reserved = ((void**)parm)[1];
	char *tmoBuffer;
	long mouseMove[3] = { 0,0,0 };
	int sentHideCursor = 0;

	kvm_trace_startupf("kvm_server_mainloop_ex entered parm=%p kvmConsoleMode=%d ThreadRunning=%d", parm, kvmConsoleMode, ThreadRunning);
	gPendingPackets = ILibQueue_Create();
	KVM_InitMouseCursors(gPendingPackets);
	kvm_trace_startupf("kvm_server_mainloop_ex step1 queue+cursors OK");

#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		gKVMRemoteLogging = ILibRemoteLogging_Create(NULL);
		ILibRemoteLogging_SetRawForward(gKVMRemoteLogging, sizeof(KVMDebugLog), kvm_slave_OnRawForwardLog);
		ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Child Processing Running...");
	}
	kvm_trace_startupf("kvm_server_mainloop_ex step2 logging OK kvmConsoleMode=%d", kvmConsoleMode);
#endif

	// This basic lock will prevent 2 thread from running at the same time. Gives time for the first one to fully exit.
	while (ThreadRunning != 0 && height < 200) { height++; Sleep(50); }
	if (height >= 200 && ThreadRunning != 0) { kvm_trace_startupf("kvm_server_mainloop_ex ABORT ThreadRunning stuck"); return 0; }
	ThreadRunning = 1;
	g_shutdown = 0;

		g_pause = 0;
		g_remotepause = ((int*)&(((void**)parm)[2]))[0];
		if (!kvm_server_configure_remote_resume_event())
		{
			g_shutdown = 1;
			goto cleanup;
		}
		kvm_trace_startupf("kvm_server_mainloop_ex step3 remotepause=%d", g_remotepause);

	KVMDEBUG("kvm_server_mainloop / start1", (int)GetCurrentThreadId());

#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		hStdIn = GetStdHandle(STD_INPUT_HANDLE);
		kvm_trace_startupf("kvm_server_mainloop_ex step4 hStdOut=%p hStdIn=%p", hStdOut, hStdIn);
	}
#endif

	KVMDEBUG("kvm_server_mainloop / start2", (int)GetCurrentThreadId());

	// Bind to the interactive desktop before GDI objects are created.
	kvm_trace_startupf("kvm_server_mainloop_ex step5 calling CheckDesktopSwitch");
	CheckDesktopSwitch(0, writeHandler, reserved);
	kvm_trace_startupf("KVM startup: desktop='%s' screen=%dx%d vscreen=%dx%d sel=%d count=%d",
		gKvmCurrentDesktopName[0] != 0 ? gKvmCurrentDesktopName : "unknown",
		SCREEN_WIDTH,
		SCREEN_HEIGHT,
		VSCREEN_WIDTH,
		VSCREEN_HEIGHT,
		SCREEN_SEL_TARGET,
		SCREEN_COUNT);

	gdiplusAttempted = 1;
	if (!initialize_gdiplus())
	{
#ifdef _WINSERVICE
		if (!kvmConsoleMode)
		{
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: initialize_gdiplus() failed");
		}
#endif
		kvm_trace_startupf("KVM startup: initialize_gdiplus failed desktop='%s' screen=%dx%d",
			gKvmCurrentDesktopName[0] != 0 ? gKvmCurrentDesktopName : "unknown",
			SCREEN_WIDTH,
			SCREEN_HEIGHT);
		KVMDEBUG("kvm_server_mainloop / initialize_gdiplus failed", (int)GetCurrentThreadId());
		goto cleanup;
	}
#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: initialize_gdiplus() SUCCESS");
	}
#endif
	if (SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0)
	{
		CheckDesktopSwitch(1, writeHandler, reserved);
		startupResolutionRecovered = (SCREEN_WIDTH > 0 && SCREEN_HEIGHT > 0) ? 1 : 0;
		kvm_trace_startupf("KVM startup: post-init resolution refresh recovered=%d screen=%dx%d vscreen=%dx%d",
			startupResolutionRecovered,
			SCREEN_WIDTH,
			SCREEN_HEIGHT,
			VSCREEN_WIDTH,
			VSCREEN_HEIGHT);
	}
	if (SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0)
	{
#ifdef _WINSERVICE
		if (!kvmConsoleMode)
		{
			ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
				"KVM [SLAVE]: invalid startup resolution (%d x %d) on desktop '%s'",
				SCREEN_WIDTH,
				SCREEN_HEIGHT,
				gKvmCurrentDesktopName[0] != 0 ? gKvmCurrentDesktopName : "unknown");
		}
#endif
		kvm_trace_startupf("KVM startup: invalid startup resolution desktop='%s' screen=%dx%d vscreen=%dx%d",
			gKvmCurrentDesktopName[0] != 0 ? gKvmCurrentDesktopName : "unknown",
			SCREEN_WIDTH,
			SCREEN_HEIGHT,
			VSCREEN_WIDTH,
			VSCREEN_HEIGHT);
		KVMDEBUG("kvm_server_mainloop / invalid startup resolution", (int)GetCurrentThreadId());
		g_shutdown = 1;
		goto cleanup;
	}
	kvm_server_SetResolution(writeHandler, reserved);


#ifdef _WINSERVICE
	if (!kvmConsoleMode)
	{
		g_shutdown = 0;
		kvmthread = CreateThread(NULL, 0, kvm_mainloopinput, parm, 0, 0);
		if (kvmthread != NULL)
		{
			inputThreadStarted = 1;
			CloseHandle(kvmthread);
		}
	}
#endif

	// Set all CRCs to 0xFF
	if (!kvm_server_enter_tile_info_lock("startup-crc"))
	{
		goto cleanup;
	}
	if (!kvm_server_reset_tile_info_locked("startup-crc", 1, 0))
	{
		kvm_server_leave_tile_info_lock();
		goto cleanup;
	}
	kvm_server_leave_tile_info_lock();

	// Send the list of displays
	kvm_send_display_list(writeHandler, reserved);
	if (!kvm_server_wait_for_remote_resume("startup-output"))
	{
		goto cleanup;
	}

	KVMDEBUG("kvm_server_mainloop / start3", (int)GetCurrentThreadId());

	// Loop and send only when a tile changes.
	while (!g_shutdown)
	{
		KVMDEBUG("kvm_server_mainloop / loop1", (int)GetCurrentThreadId());

		CheckDesktopSwitch(1, writeHandler, reserved);
		if (g_shutdown) break;


		// Enter Alertable State, so we can dispatch any packets if necessary.
		// We are doing it here, in case we need to merge any data with the bitmaps
		SleepEx(0, TRUE);
		mouseMove[0] = 0;
		while ((tmoBuffer = ILibQueue_DeQueue(gPendingPackets)) != NULL)
		{
			if (ntohs(((unsigned short*)tmoBuffer)[0]) == MNG_KVM_MOUSE_MOVE)
			{
				if (SCREEN_SEL_TARGET == 0)
				{
					mouseMove[0] = 1;
					mouseMove[1] = ((long*)tmoBuffer)[1] - VSCREEN_X;
					mouseMove[2] = ((long*)tmoBuffer)[2] - VSCREEN_Y;
				}
				else
				{
					if (((long*)tmoBuffer)[1] >= SCREEN_X && ((long*)tmoBuffer)[1] <= (SCREEN_X + SCREEN_WIDTH) &&
						((long*)tmoBuffer)[2] >= SCREEN_Y && ((long*)tmoBuffer)[2] <= (SCREEN_Y + SCREEN_HEIGHT))
					{
						mouseMove[0] = 1;
						mouseMove[1] = ((long*)tmoBuffer)[1] - SCREEN_X;
						mouseMove[2] = ((long*)tmoBuffer)[2] - SCREEN_Y;
					}
				}
			}
			else
			{
				if (ntohs(((unsigned short*)tmoBuffer)[0]) != MNG_KVM_MOUSE_CURSOR || sentHideCursor==0)
				{
					writeHandler(tmoBuffer, (int)ILibMemory_Size(tmoBuffer), reserved);
				}
			}
			ILibMemory_Free(tmoBuffer);
		}
		if (mouseMove[0] == 0 && (gRemoteMouseRenderDefault != 0 || gRemoteMouseMoved == 0))
		{
			mouseMove[0] = 1;
			CURSORINFO info = { 0 };
			info.cbSize = sizeof(info);
			GetCursorInfo(&info);

			if (SCREEN_SEL_TARGET == 0)
			{
				mouseMove[1] = info.ptScreenPos.x - VSCREEN_X;
				mouseMove[2] = info.ptScreenPos.y - VSCREEN_Y;
			}
			else
			{
				mouseMove[1] = info.ptScreenPos.x - SCREEN_X;
				mouseMove[2] = info.ptScreenPos.y - SCREEN_Y;
			}
		}
		if (mouseMove[0] != 0)
		{
			if (sentHideCursor == 0)
			{
				sentHideCursor = 1;
				char tmpBuffer[5];
				((unsigned short*)tmpBuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
				((unsigned short*)tmpBuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
				tmpBuffer[4] = (char)KVM_MouseCursor_NONE;														// Cursor Type
				writeHandler(tmpBuffer, 5, reserved);
			}
		}
		else
		{
			if (sentHideCursor != 0)
			{
				sentHideCursor = 0;
				char tmpBuffer[5];
				((unsigned short*)tmpBuffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_MOUSE_CURSOR);	// Write the type
				((unsigned short*)tmpBuffer)[1] = (unsigned short)htons((unsigned short)5);						// Write the size
				tmpBuffer[4] = (char)gCurrentCursor;															// Cursor Type
				writeHandler(tmpBuffer, 5, reserved);
			}
		}

		if (g_shutdown) { break; }

		// Scan the desktop
		if (kvm_read_env_bool("STEALTH_KVM_TRACE_LOOP", 0) != 0 && InterlockedIncrement(&gKvmLoopTraceCounter) <= 64)
		{
			kvm_trace_startupf("KVM loop: before get_desktop_buffer pause=%d remotePause=%d scale=%d backendThread=%d",
				g_pause,
				g_remotepause,
				kvm_read_scaling_factor(&SCALING_FACTOR),
				kvmConsoleMode);
		}
		captureTileGeneration = InterlockedCompareExchange(&gKvmTileInfoGeneration, 0, 0);
		if (get_desktop_buffer(&desktop, &desktopsize, mouseMove) == 1 || desktop == NULL)
		{
			ULONGLONG now = GetTickCount64();
			if (desktop != NULL) { free(desktop); desktop = NULL; }
			desktopsize = 0;
			if (captureFailureCount == 0) { captureFailureStartTick = now; }
			++captureFailureCount;
			if (kvm_read_env_bool("STEALTH_KVM_TRACE_LOOP", 0) != 0 && g_shutdown == 0)
			{
				kvm_trace_startupf("KVM loop: get_desktop_buffer returned empty/null desktop=%p size=%lld", desktop, desktopsize);
			}
#ifdef _WINSERVICE
			if (!kvmConsoleMode)
			{
				ILibRemoteLogging_printf(
					gKVMRemoteLogging,
					ILibRemoteLogging_Modules_Agent_KVM,
					ILibRemoteLogging_Flags_VerbosityLevel_1,
					"KVM [SLAVE]: get_desktop_buffer() failed (count=%d elapsedMs=%llu)",
					captureFailureCount,
					(unsigned long long)(now - captureFailureStartTick));
			}
#endif
			CheckDesktopSwitch(1, writeHandler, reserved);
			if ((now - captureFailureStartTick) < 5000)
			{
				Sleep(100);
				continue;
			}
			KVMDEBUG("get_desktop_buffer() failed, shutting down", (int)GetCurrentThreadId());
			g_shutdown = 1;
		}
		else 
		{
			captureFailureCount = 0;
			captureFailureStartTick = 0;
			if (kvm_read_env_bool("STEALTH_KVM_TRACE_LOOP", 0) != 0 && InterlockedCompareExchange(&gKvmLoopTraceCounter, 0, 0) <= 64)
			{
				kvm_trace_startupf("KVM loop: get_desktop_buffer success desktop=%p size=%lld", desktop, desktopsize);
			}
			if (!kvm_server_enter_tile_info_lock("frame-scan"))
			{
				if (desktop) { free(desktop); desktop = NULL; }
				break;
			}
			if (captureTileGeneration != InterlockedCompareExchange(&gKvmTileInfoGeneration, 0, 0))
			{
				kvm_server_leave_tile_info_lock();
				if (desktop) { free(desktop); desktop = NULL; }
				desktop = NULL;
				desktopsize = 0;
				continue;
			}
#ifdef KVM_ALL_TILES
			if (!kvm_server_reset_tile_info_locked("frame-scan", 1, (char)TILE_TODO))
#else
			if (!kvm_server_reset_tile_info_locked("frame-scan", 0, (char)TILE_TODO))
#endif
			{
				kvm_server_leave_tile_info_lock();
				if (desktop) { free(desktop); desktop = NULL; }
				break;
			}
			bmpInfo = get_bmp_info(TILE_WIDTH, TILE_HEIGHT);
			for (row = 0; row < TILE_HEIGHT_COUNT; row++) {
				for (col = 0; col < TILE_WIDTH_COUNT; col++) {
					height = TILE_HEIGHT * row;
					width = TILE_WIDTH * col;

					// Match the upstream contract: transport pause is enforced by the
					// parent reader, not by stalling the capture loop on remote pause state.
					while (!g_shutdown && g_pause != 0) { Sleep(50); }

					if (g_shutdown || kvm_read_scaling_factor(&SCALING_FACTOR) != kvm_read_scaling_factor(&SCALING_FACTOR_NEW)) { height = SCALED_HEIGHT; width = SCALED_WIDTH; break; }
					
					// Skip the tile if it has already been sent or if the CRC is same as before
					if (tileInfo[row][col].flags == (char)TILE_SENT || tileInfo[row][col].flags == (char)TILE_DONT_SEND) { continue; }

					if (get_tile_at(width, height, &buf, &tilesize, desktop, row, col) == 1)
					{
						// GetTileAt failed, lets not send the tile
						continue;
					}
					if (buf && !g_shutdown)
					{
						KVMDEBUG2("Writing JPEG: %llu bytes", tilesize);
						if (kvm_server_write_packet_checked(writeHandler, (char*)buf, (int)tilesize, reserved, "picture") == ILibTransport_DoneState_ERROR)
						{
							height = SCALED_HEIGHT;
							width = SCALED_WIDTH;
							KVMDEBUG2("JPEG WRITE resulted in ERROR");
						}
						free(buf);
					}
				}
			}
			kvm_server_leave_tile_info_lock();
			
			KVMDEBUG("kvm_server_mainloop / loop2", (int)GetCurrentThreadId());

			if (desktop) free(desktop);
			desktop = NULL;
			desktopsize = 0;
		}

		KVMDEBUG("kvm_server_mainloop / loop3", (int)GetCurrentThreadId());

		// We can't go full speed here, we need to slow this down.
		height = FRAME_RATE_TIMER;
		while (!g_shutdown && height > 0) { if (height > 50) { height -= 50; Sleep(50); } else { Sleep(height); height = 0; } SleepEx(0, TRUE); }
	}

	KVMDEBUG("kvm_server_mainloop / end3", (int)GetCurrentThreadId());
	KVMDEBUG("kvm_server_mainloop / end2", (int)GetCurrentThreadId());

cleanup:
	if (kvm_server_enter_tile_info_lock("cleanup"))
	{
		struct tileInfo_t **cleanupTileInfo = tileInfo;
		int cleanupTileHeightCount = TILE_HEIGHT_COUNT;
		tileInfo = NULL;
		kvm_server_leave_tile_info_lock();
		kvm_server_free_tile_info(cleanupTileInfo, cleanupTileHeightCount);
	}
	KVMDEBUG("kvm_server_mainloop / end1", (int)GetCurrentThreadId());
	if (gdiplusAttempted != 0)
	{
		teardown_gdiplus();
	}

	KVMDEBUG("kvm_server_mainloop / end", (int)GetCurrentThreadId());

	KVM_UnInitMouseCursors();

	while (gPendingPackets != NULL && (tmoBuffer = ILibQueue_DeQueue(gPendingPackets)) != NULL)
	{
		ILibMemory_Free(tmoBuffer);
	}
	if (gPendingPackets != NULL)
	{
		ILibQueue_Destroy(gPendingPackets);
		gPendingPackets = NULL;
	}


	if (gKVMRemoteLogging != NULL)
	{
		ILibRemoteLogging_printf(gKVMRemoteLogging, ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM [SLAVE]: Process Exiting...");
		if (inputThreadStarted == 0)
		{
			ILibRemoteLogging_Destroy(gKVMRemoteLogging);
			gKVMRemoteLogging = NULL;
		}
	}

	ThreadRunning = 0;
	free(parm);
	return 0;
}

DWORD WINAPI kvm_server_mainloop(LPVOID parm)
{
	DWORD ret = 0;
	kvm_trace_startupf("kvm_server_mainloop entered parm=%p coredump=%d", parm, ((int*)&(((void**)parm)[3]))[0]);
	if (((int*)&(((void**)parm)[3]))[0] == 1)
	{
		// Enable Core Dump in KVM Child
		ILib_DumpEnabledContext winException;
		WCHAR str[_MAX_PATH];
		DWORD strLen;
		if ((strLen = GetModuleFileNameW(NULL, str, _MAX_PATH)) > 5 && strLen < _MAX_PATH)
		{
			str[strLen - 4] = 0;	// We're going to convert .exe to _kvm.dmp
			g_ILibCrashDump_path = ILibMemory_Allocate((strLen * 2) + 10, 0, NULL, NULL); // Add enough space to add '.dmp' to the end of the path
			swprintf_s((wchar_t*)g_ILibCrashDump_path, strLen + 5, L"%s_kvm.dmp", str);
			ILibCriticalLogFilename = "KVMSlave.log";
		}

		__try
		{
			ret = kvm_server_mainloop_ex(parm);
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
	}
	else
	{
		// Core Dump not enabled in KVM Child
		ret = kvm_server_mainloop_ex(parm);
	}
	return(ret);
}

#ifdef _WINSERVICE
void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)
{
	KvmRelayProcessUser* processUser = (KvmRelayProcessUser*)user;
	KvmRelayContext* ctx = processUser != NULL ? processUser->ctx : kvm_relay_find_context_by_child_process(sender);
	ILibKVM_WriteHandler writeHandler = processUser != NULL ? processUser->writeHandler : NULL;
	void *reserved = processUser != NULL ? processUser->reserved : NULL;
	void *pipeMgr = processUser != NULL ? processUser->pipeMgr : NULL;
	char *exePath = processUser != NULL ? processUser->exePath : NULL;
	DWORD backoffDelayMs = 0;
	int notifyClosed = 0;
	int destroyContext = 0;
	DWORD childPid = ILibProcessPipe_Process_GetPID(sender);

	if (processUser != NULL)
	{
		ILibProcessPipe_Process_UpdateUserObject(sender, NULL);
	}

	kvm_relay_lock();
	kvm_relay_activate_context(ctx);
	if (childPid == 0 && ctx != NULL && ctx->childPid != 0) { childPid = (DWORD)ctx->childPid; }
	if (childPid == 0 && g_slavekvm != 0) { childPid = (DWORD)g_slavekvm; }
	if (childPid != 0)
	{
		g_slavekvm = (int)childPid;
		if (ctx != NULL) { ctx->childPid = (int)childPid; }
	}
	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent KVM: KVM Child Process(%u) [EXITED]", (unsigned int)childPid);
	kvm_trace_startupf("bridge child exit pid=%u exitCode=%d restartSuppressed=%d shutdown=%d restartCount=%d", (unsigned int)childPid, exitCode, gKvmRestartSuppressed, g_shutdown, g_restartcount);
	UNREFERENCED_PARAMETER(sender);
	kvm_relay_close_bridge_transport(ctx);
	kvm_relay_close_bridge_job(ctx);
	gChildProcess = NULL;
	gKvmChildExitSignaled = 1;
	kvm_update_runtime_state(0, 0);
	if (ctx != NULL && ctx->destroyPending != 0)
	{
		writeHandler = NULL;
		reserved = NULL;
	}

	if (gKvmRestartSuppressed != 0 || g_shutdown != 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent KVM: restart suppressed=%d shutdown=%d", gKvmRestartSuppressed, g_shutdown);
		notifyClosed = 1;
		goto cleanup;
	}

	++g_restartcount;
	if (exitCode != 0)
	{
		kvm_record_spawn_failure((DWORD)exitCode, 7, (DWORD)gProcessSpawnType);
#ifdef _WINSERVICE
		kvm_bridge_report_outcome_event(
			exitCode == ERROR_BAD_EXE_FORMAT ? L"DLL_LOAD_FAILURE" : L"EXIT_FAILURE",
			EVENTLOG_ERROR_TYPE,
			ILibProcessPipe_Process_GetPID(sender),
			(DWORD)exitCode,
			exePath,
			(ILibProcessPipe_SpawnTypes)(gKvmLastSuccessfulSpawnType != 0 ? gKvmLastSuccessfulSpawnType : (DWORD)gProcessSpawnType));
#endif
	}

	// Upstream behavior: restart on ANY exit (including code 0) as long as
	// g_shutdown == 0 and g_restartcount < 4.  Desktop switches cause the child
	// to exit cleanly, and the master must restart it on the new desktop.
	// The g_shutdown flag (set by kvm_cleanup on user disconnect) and
	// gKvmRestartSuppressed prevent unwanted restarts.

	if (g_restartcount < 4)
	{
		UNREFERENCED_PARAMETER(backoffDelayMs);
		UNREFERENCED_PARAMETER(pipeMgr);
		UNREFERENCED_PARAMETER(exePath);
		UNREFERENCED_PARAMETER(writeHandler);
		UNREFERENCED_PARAMETER(reserved);
		kvm_schedule_retry_timer();
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent KVM: g_restartcount = %d, aborting", g_restartcount);
		notifyClosed = 1;
	}

cleanup:
	kvm_relay_capture_context(ctx);
	if (ctx != NULL && ctx->destroyPending != 0 && ctx->childProcess == NULL && ctx->retryScheduled == 0)
	{
		destroyContext = 1;
		kvm_relay_unregister_context_locked(ctx);
	}
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
	if (notifyClosed && writeHandler != NULL)
	{
		writeHandler(NULL, 0, reserved);
	}
	if (processUser != NULL)
	{
		ILibMemory_Free(processUser);
	}
	if (destroyContext)
	{
		kvm_relay_destroy_context(ctx);
	}
}

void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	KvmRelayProcessUser* processUser = (KvmRelayProcessUser*)user;
	KvmRelayContext* ctx = processUser != NULL ? processUser->ctx : kvm_relay_find_context_by_child_process(sender);
	unsigned short size = 0;
	ILibKVM_WriteHandler writeHandler = processUser != NULL ? processUser->writeHandler : NULL;
	void *reserved = processUser != NULL ? processUser->reserved : NULL;

	UNREFERENCED_PARAMETER(sender);
	kvm_relay_lock();
	kvm_relay_activate_context(ctx);
	if (writeHandler == NULL && ctx != NULL)
	{
		writeHandler = ctx->writeHandler;
		reserved = ctx->reserved;
	}
	if (bufferLen > 4)
	{
		if (ntohs(((unsigned short*)(buffer))[0]) > 1000)
		{
			KVMDEBUG2("Invalid KVM Command received: %u", ntohs(((unsigned short*)(buffer))[0]));
		}
		if (ntohs(((unsigned short*)(buffer))[0]) == (unsigned short)MNG_JUMBO)
		{
			if (bufferLen > 8)
			{
				if (bufferLen >= (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])))
				{
					*bytesConsumed = 8 + (int)ntohl(((unsigned int*)(buffer))[1]);
					KVMDEBUG2("Jumbo Packet received of size: %llu (bufferLen=%llu)", *bytesConsumed, bufferLen);
					if (writeHandler != NULL)
					{
						g_restartcount = 0;
						kvm_record_healthy_output();
						kvm_bridge_debug_note_output(buffer, *bytesConsumed);
						writeHandler(buffer, (int)*bytesConsumed, reserved);
					}
					else
					{
						KVMDEBUG2("Dropping KVM jumbo output after relay user detach: %llu bytes", *bytesConsumed);
					}
					kvm_relay_capture_context(ctx);
					kvm_relay_deactivate_context();
					kvm_relay_unlock();
					return;
				}
			}
			KVMDEBUG2("Accumulate => JUMBO: [%llu bytes] bufferLen=%llu ", (size_t)(8 + (int)ntohl(((unsigned int*)(buffer))[1])), bufferLen);
		}
		else
		{
			size = ntohs(((unsigned short*)(buffer))[1]);
			if (size <= bufferLen)
			{
				KVMDEBUG2("KVM Command: [%u: %llu bytes]", ntohs(((unsigned short*)(buffer))[0]), size);
				*bytesConsumed = size;
				if (writeHandler != NULL)
				{
					g_restartcount = 0;
					kvm_record_healthy_output();
					kvm_bridge_debug_note_output(buffer, size);
					writeHandler(buffer, size, reserved);
				}
				else
				{
					KVMDEBUG2("Dropping KVM output after relay user detach: %u bytes", size);
				}
				kvm_relay_capture_context(ctx);
				kvm_relay_deactivate_context();
				kvm_relay_unlock();
				return;
			}
			KVMDEBUG2("Accumulate => KVM Command: [%u: %d bytes] bufferLen=%llu ", ntohs(((unsigned short*)(buffer))[0]), bufferLen);
		}
	}
	*bytesConsumed = 0;
	kvm_relay_capture_context(ctx);
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
}
void kvm_relay_StdErrHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)
{
	KVMDebugLog *log = (KVMDebugLog*)buffer;

	UNREFERENCED_PARAMETER(sender);
	UNREFERENCED_PARAMETER(user);

	if (bufferLen < sizeof(KVMDebugLog) || bufferLen < log->length) { *bytesConsumed = 0;  return; }
	*bytesConsumed = log->length;
	//ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), (ILibRemoteLogging_Modules)log->logType, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);
	ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Microstack_Generic, (ILibRemoteLogging_Flags)log->logFlags, "%s", log->logData);

}

int kvm_relay_restart(int paused, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler, void *reserved)
{
	KvmRelayProcessUser* user = (KvmRelayProcessUser*)ILibMemory_Allocate(sizeof(KvmRelayProcessUser), 0, NULL, NULL);
	KvmRelayContext* ctx = kvm_relay_get_context();
	char rundll32PathA[MAX_PATH * 4] = { 0 };
	char dllPathA[MAX_PATH * 4] = { 0 };
	char bridgeInputPipeNameA[MAX_PATH * 4] = { 0 };
	char bridgeOutputPipeNameA[MAX_PATH * 4] = { 0 };
	char bridgeCommandArg[(MAX_PATH * 8) + 128] = { 0 };
	char forceExitCodeA[32] = { 0 };
	char connectDelayA[32] = { 0 };
	char traceStartupA[8] = { 0 };
	char traceLoopA[8] = { 0 };
	char traceTileA[8] = { 0 };
	char traceServiceWritesA[8] = { 0 };
	char* bridgeParms0[8] = { bridgeCommandArg, bridgeInputPipeNameA, bridgeOutputPipeNameA, "-kvm0", NULL, NULL, NULL, NULL };
	char* bridgeParms1[8] = { bridgeCommandArg, bridgeInputPipeNameA, bridgeOutputPipeNameA, "-kvm1", NULL, NULL, NULL, NULL };
	char* bridgeEnvVars[13] = { NULL };
	WCHAR rundll32PathW[MAX_PATH * 4] = { 0 };
	WCHAR dllPathW[MAX_PATH * 4] = { 0 };
	WCHAR bridgeInputPipeNameW[MAX_PATH * 4] = { 0 };
	WCHAR bridgeOutputPipeNameW[MAX_PATH * 4] = { 0 };
	int desiredPause = (paused != 0 ? 1 : 0);
	int usedBridgePath = 0;
	int bridgeEnvPairCount = 0;
	int bridgeOptionalArgCount = 4;
	ULONGLONG bridgeConnectStartTickMs = 0;
	DWORD bridgeLaunchAttemptCount = 0;
	LONG restartSessionGeneration = kvm_relay_get_session_change_generation(ctx);
	int launchAbortedBySessionChange = 0;
	if (user == NULL) { return 0; }
	memset(user, 0, sizeof(KvmRelayProcessUser));
	++gKvmSpawnAttemptCount;
	gKvmLastBridgeAvailable = 0;
	gKvmLastUsedBridge = 0;
	gKvmLastFallbackUsed = 0;
	gKvmLastBridgeFailureSpawnType = (DWORD)gProcessSpawnType;
	gKvmLastLaunchAttemptCount = 0;
	gKvmLastSuccessfulSpawnType = 0;
	gKvmLastSuccessfulSpawnAttemptOrdinal = 0;

	user->ctx = ctx;
	user->writeHandler = writeHandler;
	user->reserved = reserved;
	user->pipeMgr = pipeMgr;
	user->exePath = exePath;
	
	KVMDEBUG("kvm_relay_restart / start", paused);

	if (ctx != NULL)
	{
		desiredPause = kvm_relay_get_bridge_pause_state(ctx);
		kvm_relay_close_bridge_transport(ctx);
		ctx->pipeMgr = pipeMgr;
		ctx->writeHandler = writeHandler;
		ctx->reserved = reserved;
		ctx->processTSID = gProcessTSID;
		ctx->processTSIDExplicit = gKvmProcessTSIDExplicit;
		ctx->processSessionId = gKvmProcessSessionId;
		InterlockedExchange(&ctx->bridgeProtocolPauseState, desiredPause);
	}

	// If we are re-launching the child process, wait a bit. The computer may be switching desktop, etc.
	if (paused == 0) Sleep(500);
	{
		ILibProcessPipe_SpawnTypes primaryType = gProcessSpawnType;
		ILibProcessPipe_SpawnTypes candidates[1];
		int candidateCount = 0;
		int attempt = 0;
		int preferBridge = 0;
		int bridgeAvailable = 0;
		DWORD lastError = ERROR_GEN_FAILURE;
		ILibProcessPipe_SpawnTypes successfulType = primaryType;

		preferBridge = kvm_should_prefer_bridge(exePath);
		if (primaryType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER && gProcessTSID < 0)
		{
			gKvmLastUsedBridge = 0;
			gKvmLastFallbackUsed = 0;
			gKvmLastBridgeFailureError = ERROR_INVALID_PARAMETER;
			gKvmLastBridgeFailureStage = 0;
			gKvmLastBridgeFailureSpawnType = (DWORD)primaryType;
			kvm_update_runtime_state(0, 0);
			ILibMemory_Free(user);
			SetLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}
		candidates[0] = primaryType;
		candidateCount = 1;

		{
			int checkCtx = (ctx != NULL) ? 1 : 0;
			int checkRundll32 = kvm_relay_resolve_rundll32_pathW(rundll32PathW, _countof(rundll32PathW)) ? 1 : 0;
			int checkDll = kvm_relay_resolve_bridge_dll_pathW(exePath, dllPathW, _countof(dllPathW)) ? 1 : 0;
			int checkConv1 = (checkRundll32 && checkDll) ? (WideCharToMultiByte(CP_UTF8, 0, rundll32PathW, -1, rundll32PathA, (int)sizeof(rundll32PathA), NULL, NULL) > 0 ? 1 : 0) : 0;
			int checkConv2 = (checkRundll32 && checkDll) ? (WideCharToMultiByte(CP_UTF8, 0, dllPathW, -1, dllPathA, (int)sizeof(dllPathA), NULL, NULL) > 0 ? 1 : 0) : 0;
			kvm_trace_startupf("kvm_relay_restart bridge check: ctx=%d prefer=%d rundll32=%d dll=%d conv1=%d conv2=%d rundll32Path=%s dllPath=%s",
				checkCtx, preferBridge, checkRundll32, checkDll, checkConv1, checkConv2, rundll32PathA, dllPathA);
			if (checkCtx && preferBridge && checkRundll32 && checkDll && checkConv1 && checkConv2)
			{
				bridgeAvailable = 1;
			}
		}
		gKvmLastBridgeAvailable = bridgeAvailable;
		if (GetEnvironmentVariableA("STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", forceExitCodeA, (DWORD)sizeof(forceExitCodeA)) > 0)
		{
			bridgeEnvVars[bridgeEnvPairCount * 2] = "STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE";
			bridgeEnvVars[(bridgeEnvPairCount * 2) + 1] = forceExitCodeA;
			++bridgeEnvPairCount;
		}
		bridgeEnvPairCount = kvm_relay_append_bridge_env_passthrough(bridgeEnvVars, bridgeEnvPairCount, 6, KVM_BRIDGE_CONNECT_DELAY_ENV_A, connectDelayA, sizeof(connectDelayA));
		bridgeEnvPairCount = kvm_relay_append_bridge_env_passthrough(bridgeEnvVars, bridgeEnvPairCount, 6, "STEALTH_KVM_TRACE_STARTUP", traceStartupA, sizeof(traceStartupA));
		bridgeEnvPairCount = kvm_relay_append_bridge_env_passthrough(bridgeEnvVars, bridgeEnvPairCount, 6, "STEALTH_KVM_TRACE_LOOP", traceLoopA, sizeof(traceLoopA));
		bridgeEnvPairCount = kvm_relay_append_bridge_env_passthrough(bridgeEnvVars, bridgeEnvPairCount, 6, "STEALTH_KVM_TRACE_TILE", traceTileA, sizeof(traceTileA));
		bridgeEnvPairCount = kvm_relay_append_bridge_env_passthrough(bridgeEnvVars, bridgeEnvPairCount, 6, "STEALTH_KVM_TRACE_SERVICE_WRITES", traceServiceWritesA, sizeof(traceServiceWritesA));
		if (g_ILibCrashDump_path != NULL)
		{
			bridgeParms0[bridgeOptionalArgCount] = "-coredump";
			bridgeParms1[bridgeOptionalArgCount] = "-coredump";
			++bridgeOptionalArgCount;
		}
		if (gRemoteMouseRenderDefault != 0)
		{
			bridgeParms0[bridgeOptionalArgCount] = "-remotecursor";
			bridgeParms1[bridgeOptionalArgCount] = "-remotecursor";
			++bridgeOptionalArgCount;
		}

		gChildProcess = NULL;
		if (preferBridge != 0 && bridgeAvailable != 0)
		{
			for (attempt = 0; attempt < candidateCount; ++attempt)
			{
				ILibProcessPipe_SpawnTypes attemptType = candidates[attempt];
				KvmBridgeHardeningResult hardeningResult;
				char policyDecision[64] = { 0 };
				char policyClass[64] = { 0 };
				char policyBridgeReason[64] = { 0 };
				DWORD policyError = ERROR_SUCCESS;
				DWORD policySpawnType = 0;
				unsigned long long policyCommandHash = 0;
				BOOL connectAbortedBySessionChange = FALSE;
				memset(&hardeningResult, 0, sizeof(hardeningResult));
				bridgeLaunchAttemptCount = (DWORD)(attempt + 1);
				if (kvm_relay_session_generation_changed(ctx, restartSessionGeneration))
				{
					lastError = ERROR_OPERATION_ABORTED;
					launchAbortedBySessionChange = 1;
					kvm_trace_startupf("bridge launch aborted before spawn by session change generation start=%ld current=%ld attempt=%d/%d tsid=%d",
						restartSessionGeneration,
						kvm_relay_get_session_change_generation(ctx),
						attempt + 1,
						candidateCount,
						gProcessTSID);
					break;
				}

				if (!kvm_relay_build_bridge_pipe_namesW(bridgeInputPipeNameW, _countof(bridgeInputPipeNameW), bridgeOutputPipeNameW, _countof(bridgeOutputPipeNameW)) ||
					!kvm_relay_create_bridge_server_pipeW(bridgeInputPipeNameW, PIPE_ACCESS_OUTBOUND, &ctx->bridgeInputPipeHandle) ||
					!kvm_relay_create_bridge_server_pipeW(bridgeOutputPipeNameW, PIPE_ACCESS_INBOUND, &ctx->bridgeOutputPipeHandle) ||
					WideCharToMultiByte(CP_UTF8, 0, bridgeInputPipeNameW, -1, bridgeInputPipeNameA, (int)sizeof(bridgeInputPipeNameA), NULL, NULL) <= 0 ||
					WideCharToMultiByte(CP_UTF8, 0, bridgeOutputPipeNameW, -1, bridgeOutputPipeNameA, (int)sizeof(bridgeOutputPipeNameA), NULL, NULL) <= 0)
				{
					lastError = GetLastError();
					if (lastError == ERROR_SUCCESS) { lastError = ERROR_GEN_FAILURE; }
					kvm_relay_close_bridge_transport(ctx);
					ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
						"KVM [Master]: bridge server pipe setup failed (error=%u, spawnType=%d, tsid=%d)",
						lastError,
						(int)attemptType,
						gProcessTSID);
					continue;
				}

				if (FAILED(StringCchPrintfA(bridgeCommandArg, _countof(bridgeCommandArg), "\"%s\",%s", dllPathA, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A)))
				{
					lastError = GetLastError();
					if (lastError == ERROR_SUCCESS) { lastError = ERROR_INSUFFICIENT_BUFFER; }
					kvm_relay_close_bridge_transport(ctx);
					break;
				}
				// Cross-session CreateProcessAsUser cannot rely on inherited std handles for transport.
				ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
					"KVM [Master]: Spawning rundll32 KVM attempt=%d/%d as %s tsid=%d mode=%s transport=named-pipe input=%s output=%s",
					attempt + 1,
					candidateCount,
					kvm_spawn_type_to_string(attemptType),
					gProcessTSID,
					paused == 0 ? "kvm0" : "kvm1",
					bridgeInputPipeNameA,
					bridgeOutputPipeNameA);
				kvm_trace_startupf("bridge spawn attempt=%d/%d type=%d tsid=%d target=%s", attempt+1, candidateCount, (int)attemptType, gProcessTSID, rundll32PathA);
#ifdef _WINSERVICE
				kvm_bridge_report_attempt_event(exePath, attemptType);
#endif
				gChildProcess = ILibProcessPipe_Manager_SpawnProcessEx5(
					pipeMgr,
					rundll32PathA,
					paused == 0 ? bridgeParms0 : bridgeParms1,
					attemptType,
					(void*)(ULONG_PTR)gProcessTSID,
					bridgeEnvPairCount > 0 ? bridgeEnvVars : NULL,
					0,
					&kvm_relay_bridge_pre_start_handler,
					&hardeningResult);
				if (gChildProcess == NULL)
				{
					lastError = GetLastError();
					if (lastError == ERROR_SUCCESS) { lastError = ERROR_GEN_FAILURE; }
					(void)ILibProcessPipe_GetLastWindowsSpawnPolicyBridgeReasonA(policyBridgeReason, sizeof(policyBridgeReason));
					if (ILibProcessPipe_GetLastWindowsSpawnPolicyDecisionA(policyDecision, sizeof(policyDecision), policyClass, sizeof(policyClass), &policyError, &policySpawnType, &policyCommandHash))
					{
						kvm_trace_startupf("bridge spawn policy audit decision=%s class=%s bridgeReason=%s policyError=%u policySpawnType=%u cmdHash=%016llX apiError=%u attempt=%d type=%d",
							policyDecision,
							policyClass,
							policyBridgeReason,
							policyError,
							policySpawnType,
							policyCommandHash,
							lastError,
							attempt + 1,
							(int)attemptType);
						ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
							"KVM [Master]: rundll32 bridge spawn policy audit (decision=%s, class=%s, bridgeReason=%s, policyError=%u, policySpawnType=%u, cmdHash=%016llX, apiError=%u, spawnType=%d, tsid=%d)",
							policyDecision,
							policyClass,
							policyBridgeReason,
							policyError,
							policySpawnType,
							policyCommandHash,
							lastError,
							(int)attemptType,
							gProcessTSID);
					}
					if (hardeningResult.stage == 0 && hardeningResult.processProtected && hardeningResult.assignedToJobObject)
					{
						hardeningResult.stage = KVM_BRIDGE_FAILURE_STAGE_RESUME;
						hardeningResult.error = lastError;
					}
					if (hardeningResult.stage != 0)
					{
						if (hardeningResult.error != ERROR_SUCCESS) { lastError = hardeningResult.error; }
						kvm_trace_startupf("rundll32 bridge pre-start hardening failed stage=%u error=%u pid=%u attempt=%d type=%d",
							hardeningResult.stage,
							lastError,
							(unsigned int)hardeningResult.pid,
							attempt + 1,
							(int)attemptType);
						ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
							"KVM [Master]: rundll32 bridge pre-start hardening failed (stage=%u, error=%u, pid=%u, spawnType=%d, tsid=%d)",
							hardeningResult.stage,
							lastError,
							(unsigned int)hardeningResult.pid,
							(int)attemptType,
							gProcessTSID);
#ifdef _WINSERVICE
						kvm_bridge_report_outcome_event(L"HARDENING_FAILURE", EVENTLOG_ERROR_TYPE, hardeningResult.pid, lastError, exePath, attemptType);
#endif
						kvm_record_spawn_failure(lastError, hardeningResult.stage, (DWORD)attemptType);
					}
					else
					{
						kvm_trace_startupf("bridge spawn FAILED error=%u attempt=%d type=%d", lastError, attempt+1, (int)attemptType);
						ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
							"KVM [Master]: rundll32 KVM spawn failed (error=%u, spawnType=%d, tsid=%d)",
							lastError,
							(int)attemptType,
							gProcessTSID);
#ifdef _WINSERVICE
						kvm_bridge_report_outcome_event(L"SPAWN_FAILURE", EVENTLOG_ERROR_TYPE, 0, lastError, exePath, attemptType);
#endif
						kvm_record_spawn_failure(lastError, 1, (DWORD)attemptType);
					}
					kvm_bridge_hardening_result_close_job(&hardeningResult);
					kvm_relay_close_bridge_transport(ctx);
					continue;
				}

				if (!hardeningResult.processProtected || !hardeningResult.assignedToJobObject || hardeningResult.jobObject == NULL || hardeningResult.jobObject == INVALID_HANDLE_VALUE)
				{
					lastError = hardeningResult.error != ERROR_SUCCESS ? hardeningResult.error : ERROR_ACCESS_DENIED;
					kvm_trace_startupf("rundll32 bridge hardening contract incomplete stage=%u error=%u attempt=%d type=%d", hardeningResult.stage, lastError, attempt + 1, (int)attemptType);
					ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
						"KVM [Master]: rundll32 bridge hardening contract incomplete (stage=%u, error=%u, spawnType=%d, tsid=%d)",
						hardeningResult.stage,
						lastError,
						(int)attemptType,
						gProcessTSID);
#ifdef _WINSERVICE
					kvm_bridge_report_outcome_event(L"HARDENING_FAILURE", EVENTLOG_ERROR_TYPE, ILibProcessPipe_Process_GetPID(gChildProcess), lastError, exePath, attemptType);
#endif
					ILibProcessPipe_Process_SoftKill(gChildProcess);
					gChildProcess = NULL;
					kvm_bridge_hardening_result_close_job(&hardeningResult);
					kvm_relay_close_bridge_transport(ctx);
					continue;
				}
				if (ctx != NULL)
				{
					kvm_relay_close_bridge_job(ctx);
					ctx->bridgeJobObject = hardeningResult.jobObject;
					hardeningResult.jobObject = NULL;
				}

				bridgeConnectStartTickMs = GetTickCount64();
				kvm_trace_startupf("bridge spawn OK, waiting for pipe connect timeoutMs=%u", (unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS);
				InterlockedExchange(&ctx->childUsesBridge, 1);
				if (!kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeInputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange))
				{
					unsigned long long elapsedMs = (unsigned long long)(GetTickCount64() - bridgeConnectStartTickMs);
					kvm_trace_startupf("KVM [Master]: bridge stdin connect FAILED (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)", lastError, elapsedMs, (unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS, (int)attemptType, gProcessTSID);
					ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
						"KVM [Master]: bridge stdin connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)",
						lastError,
						elapsedMs,
						(unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS,
						(int)attemptType,
						gProcessTSID);
					ILibProcessPipe_Process_SoftKill(gChildProcess);
					gChildProcess = NULL;
					kvm_relay_close_bridge_transport(ctx);
					kvm_relay_close_bridge_job(ctx);
					if (connectAbortedBySessionChange)
					{
						launchAbortedBySessionChange = 1;
						kvm_trace_startupf("bridge stdin connect aborted by session change generation start=%ld current=%ld attempt=%d/%d tsid=%d",
							restartSessionGeneration,
							kvm_relay_get_session_change_generation(ctx),
							attempt + 1,
							candidateCount,
							gProcessTSID);
						break;
					}
					kvm_trace_startupf("strict rundll32 bridge attempt failed at stdin connect; no spawn-type fallback is permitted");
					continue;
				}
				kvm_trace_startupf("bridge stdin pipe connected successfully after %llu ms", (unsigned long long)(GetTickCount64() - bridgeConnectStartTickMs));

				connectAbortedBySessionChange = FALSE;
				if (!kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeOutputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange))
				{
					unsigned long long elapsedMs = (unsigned long long)(GetTickCount64() - bridgeConnectStartTickMs);
					kvm_trace_startupf("KVM [Master]: bridge stdout connect FAILED (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)", lastError, elapsedMs, (unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS, (int)attemptType, gProcessTSID);
					ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
						"KVM [Master]: bridge stdout connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)",
						lastError,
						elapsedMs,
						(unsigned int)KVM_BRIDGE_CONNECT_TIMEOUT_MS,
						(int)attemptType,
						gProcessTSID);
					ILibProcessPipe_Process_SoftKill(gChildProcess);
					gChildProcess = NULL;
					kvm_relay_close_bridge_transport(ctx);
					kvm_relay_close_bridge_job(ctx);
					if (connectAbortedBySessionChange)
					{
						launchAbortedBySessionChange = 1;
						kvm_trace_startupf("bridge stdout connect aborted by session change generation start=%ld current=%ld attempt=%d/%d tsid=%d",
							restartSessionGeneration,
							kvm_relay_get_session_change_generation(ctx),
							attempt + 1,
							candidateCount,
							gProcessTSID);
						break;
					}
					kvm_trace_startupf("strict rundll32 bridge attempt failed at stdout connect; no spawn-type fallback is permitted");
					continue;
				}
				kvm_trace_startupf("bridge stdout pipe connected successfully after %llu ms", (unsigned long long)(GetTickCount64() - bridgeConnectStartTickMs));
				if (kvm_relay_session_generation_changed(ctx, restartSessionGeneration))
				{
					lastError = ERROR_OPERATION_ABORTED;
					launchAbortedBySessionChange = 1;
					ILibProcessPipe_Process_SoftKill(gChildProcess);
					gChildProcess = NULL;
					kvm_relay_close_bridge_transport(ctx);
					kvm_relay_close_bridge_job(ctx);
					kvm_trace_startupf("bridge transport attach skipped after session change generation start=%ld current=%ld attempt=%d/%d tsid=%d",
						restartSessionGeneration,
						kvm_relay_get_session_change_generation(ctx),
						attempt + 1,
						candidateCount,
						gProcessTSID);
					break;
				}
				InterlockedExchange(&ctx->bridgeClientConnected, 1);
				if (!kvm_relay_attach_bridge_transport(ctx, ctx->bridgeInputPipeHandle, ctx->bridgeOutputPipeHandle))
				{
					lastError = GetLastError();
					if (lastError == ERROR_SUCCESS) { lastError = ERROR_BROKEN_PIPE; }
					ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
						"KVM [Master]: bridge transport attach failed (error=%u, spawnType=%d, tsid=%d)",
						lastError,
						(int)attemptType,
						gProcessTSID);
					ILibProcessPipe_Process_SoftKill(gChildProcess);
					gChildProcess = NULL;
					kvm_relay_close_bridge_transport(ctx);
					kvm_relay_close_bridge_job(ctx);
					continue;
				}
				kvm_trace_startupf("bridge transport attached after %llu ms", (unsigned long long)(GetTickCount64() - bridgeConnectStartTickMs));

				successfulType = attemptType;
				usedBridgePath = 1;
				gKvmLastLaunchAttemptCount = bridgeLaunchAttemptCount;
				gKvmLastSuccessfulSpawnType = (DWORD)successfulType;
				gKvmLastSuccessfulSpawnAttemptOrdinal = (DWORD)(attempt + 1);
#ifdef _WINSERVICE
				kvm_bridge_report_outcome_event(L"SUCCESS", EVENTLOG_INFORMATION_TYPE, ILibProcessPipe_Process_GetPID(gChildProcess), 0, exePath, attemptType);
#endif
				ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
					"KVM [Master]: rundll32 KVM launched (attempt=%d/%d, spawnType=%s, tsid=%d)",
					attempt + 1,
					candidateCount,
					kvm_spawn_type_to_string(attemptType),
					gProcessTSID);
				break;
			}
		}
		gKvmLastLaunchAttemptCount = bridgeLaunchAttemptCount;

		if (launchAbortedBySessionChange)
		{
			gKvmLastUsedBridge = 0;
			gKvmLastFallbackUsed = 0;
			gKvmLastBridgeFailureError = ERROR_OPERATION_ABORTED;
			gKvmLastBridgeFailureStage = 0;
			gKvmLastBridgeFailureSpawnType = (DWORD)primaryType;
			kvm_update_runtime_state(0, 0);
			ILibMemory_Free(user);
			SetLastError(ERROR_OPERATION_ABORTED);
			return 0;
		}

		if (gChildProcess == NULL)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1,
				"KVM [Master]: Failed to spawn rundll32 bridge after %d attempt(s) (lastError=%u, tsid=%d); rundll32 KVM path required; legacy self-exe fallback is disabled",
				candidateCount,
				lastError,
				gProcessTSID);
			kvm_record_spawn_failure(lastError, 7, (DWORD)primaryType);
			kvm_update_runtime_state(0, 0);
			ILibMemory_Free(user);
			SetLastError(lastError);
			return 0;
		}

		gProcessSpawnType = successfulType;
	}

	g_slavekvm = ILibProcessPipe_Process_GetPID(gChildProcess);
	char tmp[255];
	sprintf_s(tmp, sizeof(tmp), "Child KVM (pid: %d)", g_slavekvm);
	ILibProcessPipe_Process_ResetMetadata(gChildProcess, tmp);

	ILibProcessPipe_Process_AddHandlers(
		gChildProcess,
		65535,
		&kvm_relay_ExitHandler,
		&kvm_relay_StdOutHandler,
		&kvm_relay_StdErrHandler,
		NULL,
		user);
	kvm_record_spawn_success(reserved, pipeMgr, exePath, writeHandler);
	gKvmLastUsedBridge = usedBridgePath;
	gKvmLastFallbackUsed = 0;
	if (ctx != NULL) { ctx->destroyPending = 0; }

	KVMDEBUG("kvm_relay_restart() launched child process", g_slavekvm);

	// Run the relay
	g_shutdown = 0;
	KVMDEBUG("kvm_relay_restart / end", (int)(uintptr_t)kvmthread);

	return 1;
}
#endif

static int kvm_session_id_is_valid(DWORD sessionId)
{
	return (sessionId != 0 && sessionId != 0xFFFFFFFF);
}

static int kvm_session_id_exists(DWORD sessionId)
{
	WTS_SESSION_INFOW* sessionInfo = NULL;
	DWORD sessionCount = 0;
	DWORD i = 0;
	int exists = 0;

	if (!kvm_session_id_is_valid(sessionId)) { return 0; }
	if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessionInfo, &sessionCount)) { return 0; }
	for (i = 0; i < sessionCount; ++i)
	{
		if (sessionInfo[i].SessionId == sessionId)
		{
			exists = 1;
			break;
		}
	}
	WTSFreeMemory(sessionInfo);
	return exists;
}

static int kvm_session_event_is_stop(DWORD eventType)
{
	switch (eventType)
	{
	case WTS_SESSION_LOCK:
	case WTS_CONSOLE_DISCONNECT:
	case WTS_REMOTE_DISCONNECT:
	case WTS_SESSION_LOGOFF:
		return 1;
	default:
		return 0;
	}
}

static int kvm_session_event_is_start(DWORD eventType)
{
	switch (eventType)
	{
	case WTS_SESSION_UNLOCK:
	case WTS_CONSOLE_CONNECT:
	case WTS_REMOTE_CONNECT:
	case WTS_SESSION_LOGON:
		return 1;
	default:
		return 0;
	}
}

static int kvm_session_id_has_user_token(DWORD sessionId)
{
	HANDLE userToken = NULL;
	if (!kvm_session_id_is_valid(sessionId)) { return 0; }
	if (!WTSQueryUserToken(sessionId, &userToken)) { return 0; }
	CloseHandle(userToken);
	return 1;
}

#define KVM_SESSION_CHANGE_IGNORE_NONE                  0
#define KVM_SESSION_CHANGE_IGNORE_NULL_CONTEXT          1
#define KVM_SESSION_CHANGE_IGNORE_UNHANDLED_EVENT       2
#define KVM_SESSION_CHANGE_IGNORE_EXPLICIT_MISMATCH     3
#define KVM_SESSION_CHANGE_IGNORE_UNRELATED_STOP        4
#define KVM_SESSION_CHANGE_IGNORE_UNQUERYABLE_START     5

static int kvm_relay_session_change_affects_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int queryUserToken, int* ignoreReasonOut)
{
	int validSessionId = kvm_session_id_is_valid(sessionId);
	int stopEvent = kvm_session_event_is_stop(eventType);
	int startEvent = kvm_session_event_is_start(eventType);
	int explicitTsid = 0;
	int sessionMatches = 0;

	if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_NONE; }
	if (ctx == NULL)
	{
		if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_NULL_CONTEXT; }
		return 0;
	}
	if (!stopEvent && !startEvent)
	{
		if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_UNHANDLED_EVENT; }
		return 0;
	}

	explicitTsid = (ctx->processTSIDExplicit != 0);
	sessionMatches = (!validSessionId ||
		ctx->processSessionId == sessionId ||
		(ctx->processTSID >= 0 && (DWORD)ctx->processTSID == sessionId) ||
		(ctx->processSessionId == 0 && ctx->processTSID < 0));
	if (explicitTsid && !sessionMatches)
	{
		if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_EXPLICIT_MISMATCH; }
		return 0;
	}
	if (!explicitTsid && stopEvent && !sessionMatches)
	{
		if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_UNRELATED_STOP; }
		return 0;
	}
	if (!explicitTsid && startEvent && validSessionId && !sessionMatches && queryUserToken != 0 && !kvm_session_id_has_user_token(sessionId))
	{
		if (ignoreReasonOut != NULL) { *ignoreReasonOut = KVM_SESSION_CHANGE_IGNORE_UNQUERYABLE_START; }
		return 0;
	}
	return 1;
}

static int kvm_relay_signal_session_change_if_relevant(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)
{
	int ignoreReason = KVM_SESSION_CHANGE_IGNORE_NONE;

	if (!kvm_relay_session_change_affects_context(ctx, eventType, sessionId, 1, &ignoreReason))
	{
		if (ignoreReason != KVM_SESSION_CHANGE_IGNORE_UNQUERYABLE_START || !kvm_session_id_exists(sessionId))
		{
			return 0;
		}
	}
	return (kvm_relay_signal_session_change(ctx, eventType, sessionId) != 0) ? 1 : 0;
}

// Setup the KVM session. Return 1 if ok, 0 if it could not be setup.
int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)
{
	int requestedTsid = tsid;
	int explicitTsid = (requestedTsid >= 0) ? 1 : 0;

	kvm_trace_startupf("kvm_relay_setup() called exePath=%s pipeMgr=%p tsid=%d", exePath ? exePath : "(null)", processPipeMgr, tsid);
	if (processPipeMgr != NULL)
	{
#ifdef _WINSERVICE
		KvmRelayContext* ctx = NULL;
		int started = 0;

		kvm_relay_lock();
		ctx = kvm_relay_get_registered_context(reserved);
		if (ctx != NULL)
		{
			kvm_trace_startupf("kvm_relay_setup() reserved session already exists reserved=%p", reserved);
			kvm_relay_unlock();
			return 0;
		}
		ctx = kvm_relay_allocate_context();
		if (ctx == NULL || !kvm_relay_register_context_locked(ctx))
		{
			if (ctx != NULL) { kvm_relay_destroy_context(ctx); }
			kvm_relay_unlock();
			return 0;
		}
		tsid = kvm_relay_select_session_id(requestedTsid);
		ctx->reserved = reserved;
		ctx->pipeMgr = processPipeMgr;
		ctx->writeHandler = writeHandler;
		ctx->exePath = exePath;
		ctx->processTSID = tsid;
		ctx->processTSIDExplicit = explicitTsid;
		kvm_relay_activate_context(ctx);
		g_restartcount = 0;
		gKvmPipeMgr = processPipeMgr;
		gKvmExePath = exePath;
		gKvmWriteHandler = writeHandler;
		gKvmDebugReserved = reserved;
		gKvmRegisteredContextCount = (reserved != NULL ? 1 : 0);
		gKvmProcessSessionId = (tsid >= 0) ? (DWORD)tsid : WTSGetActiveConsoleSessionId();
		gKvmProcessTSIDExplicit = explicitTsid;
		gKvmPendingSessionRestartEvent = 0;
		gKvmPendingSessionRestartSessionId = 0;
		kvm_clear_pending_unqueryable_start();
		gKvmChildExitSignaled = 0;
		gKvmRestartSuppressed = 0;
		kvm_bridge_debug_reset_activity_state();
		gKvmLastLaunchAttemptCount = 0;
		gKvmLastSuccessfulSpawnType = 0;
		gKvmLastSuccessfulSpawnAttemptOrdinal = 0;
		gProcessSpawnType = ILibProcessPipe_SpawnTypes_WINLOGON;
		gProcessTSID = tsid;
		if (ctx != NULL)
		{
			ctx->pipeMgr = processPipeMgr;
			ctx->writeHandler = writeHandler;
			ctx->reserved = reserved;
			ctx->processSessionId = gKvmProcessSessionId;
			InterlockedExchange(&ctx->bridgeProtocolPauseState, 1);
			InterlockedExchange(&ctx->bridgeClientConnected, 0);
			InterlockedExchange(&ctx->bridgeTransportAttached, 0);
			InterlockedExchange(&ctx->childUsesBridge, 0);
			kvm_relay_reset_cached_control_state(ctx);
		}
		g_pause = 1;
		KVMDEBUG("kvm_relay_setup() session starting", 0);
		started = kvm_relay_restart(1, processPipeMgr, exePath, writeHandler, reserved);
		kvm_relay_capture_context(ctx);
		if (!started)
		{
			kvm_relay_unregister_context_locked(ctx);
			kvm_relay_deactivate_context();
			kvm_relay_unlock();
			kvm_relay_destroy_context(ctx);
			return 0;
		}
		kvm_relay_deactivate_context();
		kvm_relay_unlock();
		return started;
#else
		return(0);
#endif
	}
	else
	{
		// if (kvmthread != NULL && g_shutdown == 0) return 0;
		void **parms = (void**)ILibMemory_Allocate((2 * sizeof(void*)) + sizeof(int), 0, NULL, NULL);
		parms[0] = writeHandler;
		parms[1] = reserved;
		((int*)(&parms[2]))[0] = 1;
		kvmConsoleMode = 1;

		if (ThreadRunning == 1 && g_shutdown == 0) { KVMDEBUG("kvm_relay_setup() session already exists", 0); free(parms); return 0; }
		kvmthread = CreateThread(NULL, 0, kvm_server_mainloop, (void*)parms, 0, 0);
		if (kvmthread != 0) { CloseHandle(kvmthread); }
		return 1;
	}
}

// Force a KVM reset & refresh
void kvm_relay_reset(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[4];
	KVMDEBUG("kvm_relay_reset", 0);
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_REFRESH);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);				// Write the size
	kvm_relay_feeddata(buffer, 4, writeHandler, reserved);
}

void kvm_relay_request_display_list(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[4];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_GET_DISPLAYS);
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)4);
	kvm_relay_feeddata(buffer, 4, writeHandler, reserved);
}

void kvm_relay_query_input_lock(ILibKVM_WriteHandler writeHandler, void *reserved)
{
	char buffer[5];
	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_KVM_INPUT_LOCK);
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)5);
	buffer[4] = 2;
	kvm_relay_feeddata(buffer, 5, writeHandler, reserved);
}

// Clean up the KVM session.
void kvm_cleanup(void *reserved)
{
	KvmRelayContext* ctx = NULL;
	ILibProcessPipe_Process childProcessForExit = NULL;
	int destroyNow = 0;
	int hadChildProcess = 0;
	//ILIBMESSAGE("KVMBREAK-CLEAN\r\n");
	kvm_relay_lock();
	ctx = reserved != NULL ? kvm_relay_find_context_by_reserved(reserved) : kvm_relay_lookup_context(NULL);
	if (ctx != NULL)
	{
		ctx->destroyPending = 1;
	}
	kvm_relay_activate_context(ctx);
	KVMDEBUG("kvm_cleanup", 0);
	kvm_trace_startupf("bridge disconnect cleanup requested reserved=%p childPresent=%d", reserved, gChildProcess != NULL ? 1 : 0);
	g_shutdown = 1;
	kvm_bridge_debug_reset_activity_state();
	gKvmRestartSuppressed = 1;
	gKvmPendingSessionRestartEvent = 0;
	gKvmPendingSessionRestartSessionId = 0;
	kvm_clear_pending_unqueryable_start();
	gKvmRetryScheduled = 0;
	if (gILibChain != NULL)
	{
		void* timer = ILibGetBaseTimer(gILibChain);
		if (timer != NULL)
		{
			ILibLifeTime_Remove(timer, ctx != NULL ? (void*)ctx : (void*)&gKvmRetryTimerToken);
		}
	}
	gKvmDebugReserved = NULL;
	gKvmPipeMgr = NULL;
	gKvmExePath = NULL;
	gKvmWriteHandler = NULL;
	kvm_update_runtime_state(0, 0);
	hadChildProcess = (gChildProcess != NULL);
	childProcessForExit = gChildProcess;
	if (gChildProcess != NULL) 
	{ 
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM.c/kvm_cleanup: Attempting graceful child shutdown");
		if (!kvm_relay_stop_bridge_process(5000))
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM.c/kvm_cleanup: Attempting to kill child process");
			ILibProcessPipe_Process_SoftKill(gChildProcess);
		}
		gChildProcess = NULL;
		kvm_relay_close_bridge_job(ctx);
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(gILibChain), ILibRemoteLogging_Modules_Agent_KVM, ILibRemoteLogging_Flags_VerbosityLevel_1, "KVM.c/kvm_cleanup: gChildProcess = NULL");
	}
	if (ctx != NULL)
	{
		kvm_relay_close_bridge_transport(ctx);
		kvm_relay_close_bridge_job(ctx);
		ctx->pipeMgr = NULL;
		ctx->writeHandler = NULL;
		ctx->reserved = NULL;
		kvm_relay_reset_cached_control_state(ctx);
	}
	kvm_relay_capture_context(ctx);
	if (ctx != NULL && hadChildProcess != 0)
	{
		ctx->childProcess = childProcessForExit;
	}
	if (ctx != NULL && ctx->childProcess == NULL && hadChildProcess == 0)
	{
		kvm_relay_unregister_context_locked(ctx);
		// No child exit callback will arrive, so cleanup owns final teardown.
		destroyNow = 1;
	}
	kvm_relay_deactivate_context();
	kvm_relay_unlock();
	if (destroyNow)
	{
		kvm_relay_destroy_context(ctx);
	}
}


////
//// Desktop Duplication API KVM
////
//#include <d3d11.h>
//#include <dxgi1_2.h>
//
//typedef struct D3D11_Functions
//{
//	HRESULT(*D3D11CreateDevice)(
//		IDXGIAdapter            *pAdapter,
//		D3D_DRIVER_TYPE         DriverType,
//		HMODULE                 Software,
//		UINT                    Flags,
//		const D3D_FEATURE_LEVEL *pFeatureLevels,
//		UINT                    FeatureLevels,
//		UINT                    SDKVersion,
//		ID3D11Device            **ppDevice,
//		D3D_FEATURE_LEVEL       *pFeatureLevel,
//		ID3D11DeviceContext     **ppImmediateContext
//		);
//}D3D11_Functions;


//void DD_Init()
//{
	//int i;
	//HRESULT hr;
	//ID3D11Device* m_Device;
	//ID3D11DeviceContext* m_DeviceContext;
	//IDXGIFactory2* m_Factory;
	//DWORD m_OcclusionCookie;
	//DXGI_OUTDUPL_DESC lOutputDuplDesc;
	//ID3D11Texture2D *lGDIImage;
	//ID3D11Texture2D *desktopImage;
	//ID3D11Texture2D *destinationImage;

	//DXGI_OUTDUPL_FRAME_INFO lFrameInfo;
	//IDXGIResource *lDesktopResource;

	//D3D11_Functions funcs;

	//HMODULE _D3D = NULL;
	//if ((_D3D = LoadLibraryExA((LPCSTR)"D3D11.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) != NULL)
	//{
	//	(FARPROC)funcs.D3D11CreateDevice = GetProcAddress(_D3D, "D3D11CreateDevice");
	//}

	//D3D_DRIVER_TYPE DriverTypes[] =
	//{
	//	D3D_DRIVER_TYPE_HARDWARE,
	//	D3D_DRIVER_TYPE_WARP,
	//	D3D_DRIVER_TYPE_REFERENCE,
	//};
	//UINT NumDriverTypes = ARRAYSIZE(DriverTypes);

	//// Feature levels supported
	//D3D_FEATURE_LEVEL FeatureLevels[] =
	//{
	//	D3D_FEATURE_LEVEL_11_0,
	//	D3D_FEATURE_LEVEL_10_1,
	//	D3D_FEATURE_LEVEL_10_0,
	//	D3D_FEATURE_LEVEL_9_1
	//};
	//UINT NumFeatureLevels = ARRAYSIZE(FeatureLevels);
	//D3D_FEATURE_LEVEL FeatureLevel;

	//// Create device
	//for (UINT DriverTypeIndex = 0; DriverTypeIndex < NumDriverTypes; ++DriverTypeIndex)
	//{
	//	hr = funcs.D3D11CreateDevice(NULL, DriverTypes[DriverTypeIndex], NULL, 0, FeatureLevels, NumFeatureLevels, D3D11_SDK_VERSION, &m_Device, &FeatureLevel, &m_DeviceContext);
	//	if (SUCCEEDED(hr))
	//	{
	//		// Device creation succeeded, no need to loop anymore
	//		break;
	//	}
	//}
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//// Get DXGI factory
	//IDXGIDevice* DxgiDevice = NULL;
	//hr = m_Device->lpVtbl->QueryInterface(m_Device, &IID_IDXGIDevice, (void**)&DxgiDevice);
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//IDXGIAdapter* DxgiAdapter = NULL;
	//hr = DxgiDevice->lpVtbl->GetParent(DxgiDevice, &IID_IDXGIAdapter, (void**)&DxgiAdapter);
	//DxgiDevice->lpVtbl->Release(DxgiDevice);
	//DxgiDevice = NULL;
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//hr = DxgiAdapter->lpVtbl->GetParent(DxgiAdapter, &IID_IDXGIFactory2, (void**)&m_Factory);
	//DxgiAdapter->lpVtbl->Release(DxgiAdapter);
	//DxgiAdapter = NULL;
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//	//return ProcessFailure(m_Device, L"Failed to get parent DXGI Factory", L"Error", hr, SystemTransitionsExpectedErrors);
	//}

	//IDXGIOutput1 *DxgiOutput1;
	//hr = m_Device->lpVtbl->QueryInterface(m_Device, &IID_IDXGIOutput, (void**)&DxgiOutput1);
	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//IDXGIOutputDuplication *dupl = NULL;
	//DxgiOutput1->lpVtbl->DuplicateOutput(DxgiOutput1, m_Device, &dupl);

	//// Create GUI drawing texture
	//dupl->lpVtbl->GetDesc(dupl, &lOutputDuplDesc);

	//D3D11_TEXTURE2D_DESC desc;
	//desc.Width = lOutputDuplDesc.ModeDesc.Width;
	//desc.Height = lOutputDuplDesc.ModeDesc.Height;
	//desc.Format = lOutputDuplDesc.ModeDesc.Format;
	//desc.ArraySize = 1;
	//desc.BindFlags = D3D11_BIND_RENDER_TARGET;
	//desc.MiscFlags = D3D11_RESOURCE_MISC_GDI_COMPATIBLE;
	//desc.SampleDesc.Count = 1;
	//desc.SampleDesc.Quality = 0;
	//desc.MipLevels = 1;
	//desc.CPUAccessFlags = 0;
	//desc.Usage = D3D11_USAGE_DEFAULT;

	//hr = m_Device->lpVtbl->CreateTexture2D(m_Device, &desc, NULL, &lGDIImage);
	//hr = m_Device->lpVtbl->CreateTexture2D(m_Device, &desc, NULL, &destinationImage);

	//if (FAILED(hr))
	//{
	//	DebugBreak();
	//}

	//// Get new frame
	//for (i = 0; i < 5; ++i)
	//{
	//	hr = dupl->lpVtbl->AcquireNextFrame(dupl, 250, &lFrameInfo, &lDesktopResource);
	//	if (hr != DXGI_ERROR_WAIT_TIMEOUT) { break; }
	//	Sleep(100);
	//}
	//
	//hr = lDesktopResource->lpVtbl->QueryInterface(lDesktopResource, &IID_ID3D11Texture2D, &desktopImage);

	//// Copy image into GDI drawing texture
	//m_DeviceContext->lpVtbl->CopyResource(m_DeviceContext, lGDIImage, desktopImage);

	//// Draw cursor image into GDI drawing texture
	//IDXGISurface1 *surface;
	//hr = lGDIImage->lpVtbl->QueryInterface(lGDIImage, &IID_IDXGISurface1, &surface);


	//// Copy from CPU access texture to bitmap buffer

	//D3D11_MAPPED_SUBRESOURCE resource;
	//UINT subresource = D3D11CalcSubresource(0, 0, 0);
	//m_DeviceContext->lpVtbl->Map(m_DeviceContext, destinationImage, subresource, D3D11_MAP_READ_WRITE, 0, &resource);

	//BITMAPINFO	lBmpInfo;

	//// BMP 32 bpp

	//ZeroMemory(&lBmpInfo, sizeof(BITMAPINFO));
	//lBmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	//lBmpInfo.bmiHeader.biBitCount = 32;
	//lBmpInfo.bmiHeader.biCompression = BI_RGB;
	//lBmpInfo.bmiHeader.biWidth = lOutputDuplDesc.ModeDesc.Width;
	//lBmpInfo.bmiHeader.biHeight = lOutputDuplDesc.ModeDesc.Height;
	//lBmpInfo.bmiHeader.biPlanes = 1;
	//lBmpInfo.bmiHeader.biSizeImage = lOutputDuplDesc.ModeDesc.Width * lOutputDuplDesc.ModeDesc.Height * 4;


	//BYTE* pBuf = (BYTE*)ILibMemory_SmartAllocate(lBmpInfo.bmiHeader.biSizeImage);
	//UINT lBmpRowPitch = lOutputDuplDesc.ModeDesc.Width * 4;
	//BYTE* sptr = (BYTE*)resource.pData;
	//BYTE* dptr = pBuf + lBmpInfo.bmiHeader.biSizeImage - lBmpRowPitch;
	//UINT lRowPitch = min(lBmpRowPitch, resource.RowPitch);
	//size_t h;

	//for (h = 0; h < lOutputDuplDesc.ModeDesc.Height; ++h)
	//{
	//	memcpy_s(dptr, lBmpRowPitch, sptr, lRowPitch);
	//	sptr += resource.RowPitch;
	//	dptr -= lBmpRowPitch;
	//}
//}


const char* kvm_get_current_desktop_name()
{
	return gKvmCurrentDesktopName[0] != 0 ? gKvmCurrentDesktopName : "Default";
}

void kvm_set_force_default_desktop(int enabled)
{
	InterlockedExchange(&gKvmForceDefaultDesktop, enabled ? 1 : 0);
}

static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)
{
	int validSessionId = kvm_session_id_is_valid(sessionId);
	int explicitTsid = 0;
	int rebindToNewSession = 0;
	int ignoreReason = KVM_SESSION_CHANGE_IGNORE_NONE;

	if (ctx == NULL) { return; }
	explicitTsid = (ctx->processTSIDExplicit != 0);
	if (!kvm_relay_session_change_affects_context(ctx, eventType, sessionId, 1, &ignoreReason))
	{
		switch (ignoreReason)
		{
		case KVM_SESSION_CHANGE_IGNORE_EXPLICIT_MISMATCH:
			kvm_trace_startupf("session change ignored for explicit KVM TSID event=%u session=%u current=%u tsid=%d",
				(unsigned int)eventType,
				(unsigned int)sessionId,
				(unsigned int)ctx->processSessionId,
				ctx->processTSID);
			break;
		case KVM_SESSION_CHANGE_IGNORE_UNRELATED_STOP:
			kvm_trace_startupf("session stop ignored for unrelated auto-selected KVM session event=%u session=%u current=%u tsid=%d",
				(unsigned int)eventType,
				(unsigned int)sessionId,
				(unsigned int)ctx->processSessionId,
				ctx->processTSID);
			break;
		case KVM_SESSION_CHANGE_IGNORE_UNQUERYABLE_START:
			if (kvm_session_id_exists(sessionId))
			{
				kvm_relay_activate_context(ctx);
				if (gKvmPendingUnqueryableStartEvent != eventType || gKvmPendingUnqueryableStartSessionId != sessionId)
				{
					gKvmPendingUnqueryableStartRetryCount = 0;
				}
				gKvmPendingUnqueryableStartEvent = eventType;
				gKvmPendingUnqueryableStartSessionId = sessionId;
				kvm_trace_startupf("session start queued for token retry event=%u session=%u current=%u tsid=%d childPid=%d retryDelayMs=%u retryMax=%u",
					(unsigned int)eventType,
					(unsigned int)sessionId,
					(unsigned int)ctx->processSessionId,
					ctx->processTSID,
					ctx->childPid,
					(unsigned int)KVM_SESSION_START_TOKEN_RETRY_DELAY_MS,
					(unsigned int)KVM_SESSION_START_TOKEN_RETRY_MAX);
				kvm_schedule_retry_timer_delay(KVM_SESSION_START_TOKEN_RETRY_DELAY_MS);
				kvm_relay_capture_context(ctx);
				kvm_relay_deactivate_context();
			}
			else
			{
				kvm_trace_startupf("session start ignored for auto-selected KVM because session is not present or has no queryable user token event=%u session=%u current=%u tsid=%d childPid=%d",
					(unsigned int)eventType,
					(unsigned int)sessionId,
					(unsigned int)ctx->processSessionId,
					ctx->processTSID,
					ctx->childPid);
			}
			break;
		case KVM_SESSION_CHANGE_IGNORE_UNHANDLED_EVENT:
			kvm_trace_startupf("session change ignored for unhandled KVM event=%u session=%u current=%u tsid=%d",
				(unsigned int)eventType,
				(unsigned int)sessionId,
				(unsigned int)ctx->processSessionId,
				ctx->processTSID);
			break;
		default:
			break;
		}
		return;
	}

	kvm_relay_activate_context(ctx);
	gKvmPendingSessionRestartEvent = eventType;
	gKvmPendingSessionRestartSessionId = sessionId;

	switch (eventType)
	{
	case WTS_SESSION_LOCK:
	case WTS_CONSOLE_DISCONNECT:
	case WTS_REMOTE_DISCONNECT:
	case WTS_SESSION_LOGOFF:
		if (validSessionId && gKvmPendingUnqueryableStartSessionId == sessionId)
		{
			kvm_clear_pending_unqueryable_start();
		}
		gKvmRestartSuppressed = 1;
		if (gChildProcess != NULL)
		{
			gKvmChildExitSignaled = 1;
			kvm_update_runtime_state(0, 0);
			ILibProcessPipe_Process_SoftKill(gChildProcess);
		}
		break;
	case WTS_SESSION_UNLOCK:
	case WTS_CONSOLE_CONNECT:
	case WTS_REMOTE_CONNECT:
	case WTS_SESSION_LOGON:
		kvm_clear_pending_unqueryable_start();
		if (validSessionId)
		{
			rebindToNewSession = (!explicitTsid && ctx->processSessionId != 0 && ctx->processSessionId != sessionId);
			if (rebindToNewSession)
			{
				kvm_trace_startupf("session start rebinding auto-selected KVM session event=%u oldSession=%u newSession=%u tsid=%d",
					(unsigned int)eventType,
					(unsigned int)ctx->processSessionId,
					(unsigned int)sessionId,
					ctx->processTSID);
				g_restartcount = 0;
			}
			gProcessTSID = (int)sessionId;
			gKvmProcessSessionId = sessionId;
		}
		gKvmRestartSuppressed = 0;
		if (rebindToNewSession && gChildProcess != NULL)
		{
			gKvmChildExitSignaled = 1;
			kvm_update_runtime_state(0, 0);
			ILibProcessPipe_Process_SoftKill(gChildProcess);
		}
#ifdef _WINSERVICE
		else if (gChildProcess == NULL && g_shutdown == 0 && gKvmPipeMgr != NULL && gKvmExePath != NULL && gKvmWriteHandler != NULL)
		{
			kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);
		}
#endif
		break;
	default:
		break;
	}

	kvm_relay_capture_context(ctx);
	kvm_relay_deactivate_context();
}

void kvm_notify_session_change(DWORD eventType, DWORD sessionId)
{
#ifdef _WINSERVICE
	KvmRelayContext* snapshot[KVM_MAX_RELAY_CONTEXTS] = { 0 };
	KvmRelayContext* preSignaledContext = NULL;
	int i = 0;
	int preSignaled = 0;

	kvm_relay_ensure_registry_lock();
	if (TryEnterCriticalSection(&gKvmRelayContextLock))
	{
		for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
		{
			snapshot[i] = gKvmRelayContexts[i];
			if (snapshot[i] != NULL)
			{
				(void)kvm_relay_signal_session_change_if_relevant(snapshot[i], eventType, sessionId);
			}
		}
		for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
		{
			if (snapshot[i] != NULL)
			{
				// Equivalent retained dispatch contract:
				// kvm_relay_handle_session_change_for_context(snapshot[i], request->eventType, request->sessionId);
				kvm_relay_handle_session_change_for_context(snapshot[i], eventType, sessionId);
			}
		}
		kvm_relay_unlock();
		return;
	}

	preSignaledContext = gKvmActiveContext;
	preSignaled = kvm_relay_signal_session_change_if_relevant(preSignaledContext, eventType, sessionId);
	kvm_relay_lock();
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		snapshot[i] = gKvmRelayContexts[i];
		if (snapshot[i] != NULL && (preSignaled == 0 || snapshot[i] != preSignaledContext))
		{
			(void)kvm_relay_signal_session_change_if_relevant(snapshot[i], eventType, sessionId);
		}
	}
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (snapshot[i] != NULL)
		{
			// Equivalent retained dispatch contract:
			// kvm_relay_handle_session_change_for_context(snapshot[i], request->eventType, request->sessionId);
			kvm_relay_handle_session_change_for_context(snapshot[i], eventType, sessionId);
		}
	}
	kvm_relay_unlock();
#else
	UNREFERENCED_PARAMETER(eventType);
	UNREFERENCED_PARAMETER(sessionId);
#endif
}

DWORD kvm_bridge_debug_get_child_pid(void)
{
	return (gKvmChildPresent != 0) ? (DWORD)g_slavekvm : 0;
}

DWORD kvm_bridge_debug_get_child_pid_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return (ctx != NULL && ctx->childPresent != 0) ? (DWORD)ctx->childPid : 0;
}

int kvm_bridge_debug_get_child_present(void)
{
	return gKvmChildPresent;
}

int kvm_bridge_debug_get_child_present_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return ctx != NULL ? ctx->childPresent : 0;
}

int kvm_bridge_debug_is_child_exit_signaled(void)
{
	return gKvmChildExitSignaled;
}

int kvm_bridge_debug_get_restart_suppressed(void)
{
	return gKvmRestartSuppressed;
}

int kvm_bridge_debug_peek_pending_session_restart(DWORD* eventTypeOut, DWORD* sessionIdOut)
{
	if (eventTypeOut != NULL) { *eventTypeOut = gKvmPendingSessionRestartEvent; }
	if (sessionIdOut != NULL) { *sessionIdOut = gKvmPendingSessionRestartSessionId; }
	return (gKvmPendingSessionRestartEvent != 0);
}

DWORD kvm_bridge_debug_get_process_session_id(void)
{
	return gKvmProcessSessionId;
}

DWORD kvm_bridge_debug_get_process_session_id_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return ctx != NULL ? ctx->processSessionId : 0;
}

int kvm_bridge_debug_force_process_session_id_for_reserved(void *reserved, DWORD sessionId)
{
	KvmRelayContext* ctx = NULL;
	int updated = 0;

	if (!kvm_session_id_is_valid(sessionId)) { return 0; }

	kvm_relay_lock();
	ctx = kvm_relay_find_context_by_reserved(reserved);
	if (ctx != NULL)
	{
		ctx->processSessionId = sessionId;
		if (ctx == gKvmActiveContext || gKvmDebugReserved == reserved)
		{
			gKvmProcessSessionId = sessionId;
		}
		updated = 1;
	}
	kvm_relay_unlock();
	return updated;
}

int kvm_bridge_debug_get_transport_active(void)
{
	return gKvmTransportActive;
}

int kvm_bridge_debug_get_transport_active_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return ctx != NULL ? ctx->transportActive : 0;
}

int kvm_bridge_debug_get_last_bridge_available(void)
{
	return gKvmLastBridgeAvailable;
}

int kvm_bridge_debug_get_last_used_bridge(void)
{
	return gKvmLastUsedBridge;
}

int kvm_bridge_debug_get_last_fallback_used(void)
{
	return gKvmLastFallbackUsed;
}

int kvm_bridge_debug_get_last_used_bridge_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return ctx != NULL ? ctx->lastUsedBridge : 0;
}

int kvm_bridge_debug_get_last_fallback_used_for_reserved(void *reserved)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	return ctx != NULL ? ctx->lastFallbackUsed : 1;
}

DWORD kvm_bridge_debug_get_last_bridge_failure_error(void)
{
	return gKvmLastBridgeFailureError;
}

DWORD kvm_bridge_debug_get_last_bridge_failure_stage(void)
{
	return gKvmLastBridgeFailureStage;
}

DWORD kvm_bridge_debug_get_last_bridge_failure_spawn_type(void)
{
	return gKvmLastBridgeFailureSpawnType;
}

DWORD kvm_bridge_debug_get_last_launch_attempt_count(void)
{
	return gKvmLastLaunchAttemptCount;
}

DWORD kvm_bridge_debug_get_last_successful_spawn_type(void)
{
	return gKvmLastSuccessfulSpawnType;
}

DWORD kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal(void)
{
	return gKvmLastSuccessfulSpawnAttemptOrdinal;
}

DWORD kvm_bridge_debug_get_consecutive_failures(void)
{
	return gKvmConsecutiveFailures;
}

DWORD kvm_bridge_debug_get_last_backoff_delay_ms(void)
{
	return gKvmLastBackoffDelayMs;
}

DWORD kvm_bridge_debug_get_spawn_attempt_count(void)
{
	return gKvmSpawnAttemptCount;
}

int kvm_bridge_debug_is_retry_scheduled(void)
{
	return gKvmRetryScheduled;
}

int kvm_bridge_debug_get_registered_context_count(void)
{
	int i;
	int count = 0;
	for (i = 0; i < KVM_MAX_RELAY_CONTEXTS; ++i)
	{
		if (gKvmRelayContexts[i] != NULL) { ++count; }
	}
	return count;
}

int kvm_bridge_debug_get_snapshot_for_reserved(void *reserved, KvmBridgeDebugSnapshot* snapshotOut)
{
	KvmRelayContext* ctx = kvm_relay_find_context_by_reserved(reserved);
	if (snapshotOut == NULL) { return 0; }
	if (ctx == NULL) { return 0; }
	memset(snapshotOut, 0, sizeof(KvmBridgeDebugSnapshot));
	snapshotOut->childPresent = ctx->childPresent;
	snapshotOut->childPid = (ctx->childPresent != 0) ? (DWORD)ctx->childPid : 0;
	snapshotOut->transportActive = ctx->transportActive;
	snapshotOut->processSessionId = ctx->processSessionId;
	snapshotOut->processTSIDExplicit = ctx->processTSIDExplicit;
	snapshotOut->sessionStartTickMs = ctx->sessionStartTickMs;
	snapshotOut->lastInputTickMs = ctx->lastInputTickMs;
	snapshotOut->lastOutputTickMs = ctx->lastOutputTickMs;
	snapshotOut->lastScreenTickMs = ctx->lastScreenTickMs;
	snapshotOut->lastInputType = ctx->lastInputType;
	snapshotOut->lastOutputType = ctx->lastOutputType;
	snapshotOut->pendingProbeMask = (unsigned int)ctx->pendingProbeMask;
	snapshotOut->pendingProbeSinceTickMs = ctx->pendingProbeSinceTickMs;
	return 1;
}

#endif
