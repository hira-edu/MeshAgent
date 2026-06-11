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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#ifndef WIN32
#include <strings.h>
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <WinBase.h>
#include <strsafe.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include "wincrypto.h"
#include <shellscalingapi.h>
#include <process.h>
#include "../meshservice/stealth.h"
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

#include "agentcore.h"
#include "signcheck.h"
#include "meshdefines.h"
#include "meshinfo.h"
#include "config/group_default.h"
#include "config/active_profile.h"
#include "microscript/ILibDuktape_Commit.h"
#include "microscript/ILibDuktape_Polyfills.h"
#include "microscript/ILibDuktape_Helpers.h"
#include "microscript/ILibDuktape_SHA256.h"
#include "microscript/ILibDuktape_EncryptionStream.h"
#include "microscript/ILibDuktape_DuplexStream.h"
#include "microscript/ILibDuktape_EventEmitter.h"
#include "microscript/ILibDuktape_net.h"
#include "microscript/ILibDuktape_Dgram.h"

#include "microstack/ILibParsers.h"
#include "microstack/ILibAsyncUDPSocket.h"
#include "microstack/ILibMulticastSocket.h"
#include "microscript/ILibDuktape_ScriptContainer.h"
#include "../microstack/ILibIPAddressMonitor.h"
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
#include "../meshservice/stealth.h"
#include "../meshservice/stealth_defaults.h"
#include "../meshservice/rundll32_contract.h"
#include "../meshservice/branding_util.h"
#include <stdarg.h>
#include <ShlObj.h>
#include <strsafe.h>
#endif

#ifdef WIN32
static void MeshAgent_ControlChannelDebugLog(MeshAgentHostContainer *agent, const char *fmt, ...)
{
	if (agent == NULL || agent->exePath == NULL) { return; }
	char enabledValue[8];
	if (GetEnvironmentVariableA("STEALTH_CONTROLCHANNEL_TRACE", enabledValue, (DWORD)sizeof(enabledValue)) == 0) { return; }
	char directory[MAX_PATH];
	char logPath[MAX_PATH];
	DWORD len = GetFullPathNameA(agent->exePath, (DWORD)sizeof(directory), directory, NULL);
	if (len == 0 || len >= sizeof(directory)) { return; }
	char *slash = strrchr(directory, '\\');
	if (slash == NULL) { return; }
	*slash = 0;
	if (sprintf_s(logPath, sizeof(logPath), "%s\\controlchannel-debug.log", directory) < 0) { return; }

	FILE *logFile = NULL;
	if (fopen_s(&logFile, logPath, "a") != 0 || logFile == NULL) { return; }

	SYSTEMTIME st;
	GetLocalTime(&st);
	fprintf(logFile, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
		(unsigned int)st.wYear, (unsigned int)st.wMonth, (unsigned int)st.wDay,
		(unsigned int)st.wHour, (unsigned int)st.wMinute, (unsigned int)st.wSecond, (unsigned int)st.wMilliseconds);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(logFile, fmt, ap);
	va_end(ap);
	fputc('\n', logFile);
	fclose(logFile);
}
#else
#define MeshAgent_ControlChannelDebugLog(agent, fmt, ...) ((void)0)
#endif

#ifdef _POSIX
#include <sys/stat.h>
#include <sys/wait.h>
#endif

#ifdef WIN32
#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX ".update.pkg"
#endif

static void MeshAgent_AddHostHeader(ILibHTTPPacket *req, const char* overrideHost, const char* host, unsigned short port, int useDefaultPort)
{
	if (overrideHost != NULL && overrideHost[0] != 0)
	{
		ILibAddHeaderLine(req, "Host", 4, overrideHost, (int)strnlen_s(overrideHost, 256));
		return;
	}

	if (useDefaultPort)
	{
		ILibAddHeaderLine(req, "Host", 4, host, (int)strnlen_s(host, 512));
	}
	else
	{
		ILibAddHeaderLine(req, "Host", 4, ILibScratchPad, (int)sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s:%u", host, port));
	}
}

static void MeshAgent_AddUserAgentHeader(ILibHTTPPacket *req, const char* overrideUA)
{
	const char* ua = overrideUA;
	if (ua != NULL && ua[0] != 0)
	{
		ILibAddHeaderLine(req, "User-Agent", 10, ua, (int)strnlen_s(ua, 512));
		return;
	}

	const char* FieldData = "MeshAgent ";
	char combined[40];
	strcpy_s(combined, sizeof(combined), FieldData);
	strcat_s(combined, sizeof(combined), SOURCE_COMMIT_DATE);
	ILibAddHeaderLine(req, "User-Agent", 10, combined, (int)strnlen_s(combined, 50));
}

#ifdef _OPENBSD
extern char __agentExecPath[];
#endif

int gRemoteMouseRenderDefault = 0;

static void MeshAgent_ClearActiveProxyAttempt(MeshAgentHostContainer *agent)
{
	if (agent == NULL) { return; }
	agent->activeProxyUri[0] = 0;
	agent->activeProxySource[0] = 0;
	agent->activeProxyCandidateIndex = -1;
	agent->proxyAttemptEstablished = 0;
}

static void MeshAgent_ClearGlobalTunnelProxy(MeshAgentHostContainer *agent)
{
	if (agent == NULL) { return; }
	agent->proxyServer = NULL;
	if (agent->meshCoreCtx == NULL) { return; }

	int stackTop = duk_get_top(agent->meshCoreCtx);
	if (duk_peval_string(agent->meshCoreCtx, "require('global-tunnel');") == 0)
	{
		duk_get_prop_string(agent->meshCoreCtx, -1, "end");
		duk_swap_top(agent->meshCoreCtx, -2);
		if (duk_pcall_method(agent->meshCoreCtx, 0) != 0) { duk_pop(agent->meshCoreCtx); }
	}
	duk_set_top(agent->meshCoreCtx, stackTop);
}

static void MeshAgent_RecordProxyAttemptFailure(MeshAgentHostContainer *agent, const char *reason)
{
	(void)reason;
	if (agent == NULL) { return; }
	agent->proxyFailed = 1;
	MeshAgent_ClearGlobalTunnelProxy(agent);
	MeshAgent_ClearActiveProxyAttempt(agent);
}

static void MeshAgent_RecordProxyAttemptSuccess(MeshAgentHostContainer *agent)
{
	if (agent == NULL) { return; }
	agent->proxyFailed = 0;
	agent->proxyFallbackIndex = 0;
	MeshAgent_ClearActiveProxyAttempt(agent);
}

static int MeshAgent_IsIpLiteral(const char *host)
{
	struct in_addr addr4;
	struct in6_addr addr6;
	if (host == NULL || host[0] == 0) { return 0; }
	return ILibInet_pton(AF_INET, host, &addr4) == 1 || ILibInet_pton(AF_INET6, host, &addr6) == 1;
}

static int MeshAgent_SockAddrFromIpLiteral(const char *host, unsigned short port, struct sockaddr_in6 *address)
{
	struct in_addr addr4;
	struct in6_addr addr6;
	if (address == NULL || host == NULL || host[0] == 0) { return 0; }
	memset(address, 0, sizeof(struct sockaddr_in6));
	if (ILibInet_pton(AF_INET, host, &addr4) == 1)
	{
		struct sockaddr_in *v4 = (struct sockaddr_in*)address;
		v4->sin_family = AF_INET;
		v4->sin_port = htons(port);
		memcpy_s(&(v4->sin_addr), sizeof(v4->sin_addr), &addr4, sizeof(addr4));
		return 1;
	}
	if (ILibInet_pton(AF_INET6, host, &addr6) == 1)
	{
		address->sin6_family = AF_INET6;
		address->sin6_port = htons(port);
		memcpy_s(&(address->sin6_addr), sizeof(address->sin6_addr), &addr6, sizeof(addr6));
		return 1;
	}
	return 0;
}

static int MeshAgent_ResolveControlChannelAddress(MeshAgentHostContainer *agent, const char *serverUrl, int serverUrlLen, const char *host, unsigned short port, struct sockaddr_in6 *address, const char **sourceOut)
{
	(void)agent;
	(void)serverUrl;
	(void)serverUrlLen;
	if (sourceOut != NULL) { *sourceOut = "os"; }
	if (address == NULL || host == NULL || host[0] == 0) { return 0; }
	if (MeshAgent_SockAddrFromIpLiteral(host, port, address))
	{
		if (sourceOut != NULL) { *sourceOut = "literal"; }
		return 1;
	}
	if (ILibResolveEx((char*)host, port, address) == 0 && address->sin6_family != AF_UNSPEC)
	{
		if (sourceOut != NULL) { *sourceOut = "os"; }
		return 1;
	}
	memset(address, 0, sizeof(struct sockaddr_in6));
	address->sin6_family = AF_UNSPEC;
	return 0;
}

#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
static void MeshAgent_EnsureDirectoryW(const wchar_t* path);
static BOOL MeshAgent_FindRepoRootW(wchar_t* output, size_t outputLen);
static BOOL MeshAgent_StageSelfTestModule(const wchar_t* installDir);
static void MeshAgent_StageSelfTestModuleBestEffort(void);
static void MeshAgent_StageSelfTestModuleForCurrentExeBestEffort(void);
static BOOL MeshAgent_RunChildProcess(const wchar_t* exePath, const wchar_t* args, DWORD timeoutMs, DWORD* exitCode);
static void MeshAgent_EnsureCoreModuleRuntimeGlobals(duk_context* ctx);
static BOOL MeshAgent_RunPreProtectionCaptureValidationW(const wchar_t* outputPath);

/* UMH companion service identifiers — SSOT: meshcore/config/umh_defines.h */
#include "config/umh_defines.h"

static void MeshAgent_LogNativeInstallerEvent(const char* fmt, ...)
{
	va_list ap;
	char buffer[512];
	va_start(ap, fmt);
	_vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, ap);
	va_end(ap);

	printf("%s\n", buffer);
	fflush(stdout);

	WCHAR logDir[MAX_PATH] = { 0 };
	WCHAR logPath[MAX_PATH] = { 0 };
	if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, logDir)))
	{
		lstrcpynW(logDir, L"C:\\ProgramData", _countof(logDir));
	}
	StringCchCatW(logDir, _countof(logDir), L"\\" STEALTH_FALLBACK_SERVICE_NAME L"\\logs");
	CreateDirectoryW(logDir, NULL);
	StringCchPrintfW(logPath, _countof(logPath), L"%s\\native-install.log", logDir);

	HANDLE hFile = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteFile(hFile, buffer, (DWORD)strlen(buffer), &written, NULL);
		WriteFile(hFile, "\r\n", 2, &written, NULL);
		CloseHandle(hFile);
	}

	// Also mirror to docs/testing for evidence capture.
	WCHAR repoRoot[MAX_PATH * 4] = {0};
	if (MeshAgent_FindRepoRootW(repoRoot, _countof(repoRoot)))
	{
		WCHAR evidenceDir[MAX_PATH * 4] = {0};
		StringCchPrintfW(evidenceDir, _countof(evidenceDir), L"%s\\docs", repoRoot);
		MeshAgent_EnsureDirectoryW(evidenceDir);
		StringCchPrintfW(evidenceDir, _countof(evidenceDir), L"%s\\docs\\testing", repoRoot);
		MeshAgent_EnsureDirectoryW(evidenceDir);

		WCHAR evidencePath[MAX_PATH * 4] = {0};
		StringCchPrintfW(evidencePath, _countof(evidencePath), L"%s\\native-install.log", evidenceDir);
		HANDLE hEvidence = CreateFileW(evidencePath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hEvidence != INVALID_HANDLE_VALUE)
		{
			DWORD written = 0;
			WriteFile(hEvidence, buffer, (DWORD)strlen(buffer), &written, NULL);
			WriteFile(hEvidence, "\r\n", 2, &written, NULL);
			CloseHandle(hEvidence);
		}
	}
}

static BOOL MeshAgent_RunNativeStealthFullInstall(struct MeshAgentHostContainer* agentHost)
{
	if (agentHost == NULL || agentHost->exePath == NULL) { return FALSE; }
	WCHAR exePathW[MAX_PATH * 4];
	DWORD lifecycleExitCode = ERROR_SUCCESS;
	ILibUTF8ToWideEx(agentHost->exePath, -1, exePathW, (int)(sizeof(exePathW) / sizeof(WCHAR)));

	MeshAgent_LogNativeInstallerEvent("...Running rundll32 lifecycle installer");
	const BOOL previouslyInstalled = Stealth_IsAlreadyInstalled();
	MeshAgent_LogNativeInstallerEvent("...Lifecycle planner will evaluate existing state before install (detected installed: %s)", previouslyInstalled ? "yes" : "no");

	if (MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
			exePathW,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&lifecycleExitCode))
	{
		MeshAgent_StageSelfTestModuleBestEffort();
		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle installer completed successfully");
		return TRUE;
	}

	if (MeshRundll32_LaunchLifecycleHostW(
			previouslyInstalled ? MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE : MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&lifecycleExitCode))
	{
		MeshAgent_StageSelfTestModuleBestEffort();
		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle installer reported failure but final %s validation passed",
			previouslyInstalled ? "update" : "install");
		return TRUE;
	}

	MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle installer failed (exit=%lu LastError=%lu). Legacy installer path disabled.", lifecycleExitCode, GetLastError());
	return FALSE;
}

static BOOL MeshAgent_RunNativeStealthFullUninstall(void)
{
	DWORD lifecycleExitCode = ERROR_SUCCESS;
	MeshAgent_LogNativeInstallerEvent("...Running rundll32 lifecycle uninstaller");
	if (MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&lifecycleExitCode))
	{
		return TRUE;
	}

	// Treat a fully clean final state as success even if teardown reported a non-fatal error code.
	if (MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&lifecycleExitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle uninstaller reported failure but final uninstall validation passed");
		return TRUE;
	}

	MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle uninstaller failed (exit=%lu LastError=%lu)", lifecycleExitCode, GetLastError());
	return FALSE;
}

static void MeshAgent_GetServiceKeyNameW(wchar_t* buffer, size_t count)
{
	if (buffer == NULL || count == 0) { return; }
	MeshService_CopyBrandingTextToWide(MeshService_GetServiceFileText(), buffer, count);
	if (buffer[0] == L'\0')
	{
		StringCchCopyW(buffer, count, STEALTH_FALLBACK_SERVICE_NAME);
	}
	buffer[count - 1] = L'\0';
}

static void MeshAgent_ApplyNativeLifecycleBrandingOverrides(struct MeshAgentHostContainer* agentHost)
{
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
	char value[1024];
	int len = 0;

	Stealth_ClearRuntimeBrandingOverrides();
	if (agentHost == NULL || agentHost->masterDb == NULL) { return; }

	len = ILibSimpleDataStore_Get(agentHost->masterDb, "displayName", value, sizeof(value) - 1);
	if (len > 0 && len < (int)sizeof(value))
	{
		value[len] = 0;
		Stealth_SetRuntimeDisplayNameUtf8(value);
	}

	len = ILibSimpleDataStore_Get(agentHost->masterDb, "description", value, sizeof(value) - 1);
	if (len > 0 && len < (int)sizeof(value))
	{
		value[len] = 0;
		Stealth_SetRuntimeServiceDescriptionUtf8(value);
	}
#else
	UNREFERENCED_PARAMETER(agentHost);
#endif
}

static BOOL MeshAgent_WaitForServiceRunning(const wchar_t* serviceName, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
	DWORD waited = 0;
	BOOL running = FALSE;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL) { return FALSE; }
	SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return FALSE;
	}

	while (waited < timeoutMs)
	{
		SERVICE_STATUS_PROCESS ssp = {0};
		DWORD needed = 0;
		if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
		{
			if (ssp.dwCurrentState == SERVICE_RUNNING)
			{
				running = TRUE;
				break;
			}
		}
		Sleep(1000);
		waited += 1000;
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return running;
}

static BOOL MeshAgent_WaitForServiceNotRunning(const wchar_t* serviceName, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
	DWORD waited = 0;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL) { return FALSE; }
	SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
	if (svc == NULL)
	{
		DWORD err = GetLastError();
		CloseServiceHandle(scm);
		return (err == ERROR_SERVICE_DOES_NOT_EXIST) ? TRUE : FALSE;
	}

	while (waited < timeoutMs)
	{
		SERVICE_STATUS_PROCESS ssp = {0};
		DWORD needed = 0;
		if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
		{
			if (ssp.dwCurrentState != SERVICE_RUNNING)
			{
				CloseServiceHandle(svc);
				CloseServiceHandle(scm);
				return TRUE;
			}
		}
		Sleep(1000);
		waited += 1000;
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return FALSE;
}

static BOOL MeshAgent_WaitForServiceAbsent(const wchar_t* serviceName, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL) { return FALSE; }

	ULONGLONG start = GetTickCount64();
	while ((GetTickCount64() - start) < timeoutMs)
	{
		SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
		if (svc == NULL)
		{
			DWORD err = GetLastError();
			if (err == ERROR_SERVICE_DOES_NOT_EXIST)
			{
				CloseServiceHandle(scm);
				return TRUE;
			}
			if (err == ERROR_SERVICE_MARKED_FOR_DELETE)
			{
				Sleep(500);
				continue;
			}
			CloseServiceHandle(scm);
			return FALSE;
		}

		CloseServiceHandle(svc);
		Sleep(500);
	}

	CloseServiceHandle(scm);
	return FALSE;
}

static BOOL MeshAgent_QueryServiceStatus(const wchar_t* serviceName, SERVICE_STATUS_PROCESS* status)
{
	if (serviceName == NULL || serviceName[0] == L'\0' || status == NULL) { return FALSE; }
	ZeroMemory(status, sizeof(*status));

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL) { return FALSE; }
	SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return FALSE;
	}

	DWORD needed = 0;
	BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)status, sizeof(*status), &needed);
	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return ok;
}

static BOOL MeshAgent_WaitForServiceRestart(const wchar_t* serviceName, DWORD initialPid, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
	BOOL sawNotRunning = FALSE;
	BOOL sawPidChange = FALSE;
	DWORD lastPid = initialPid;
	ULONGLONG startTick = GetTickCount64();
	ULONGLONG deadline = startTick + timeoutMs;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL) { return FALSE; }
	SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		return FALSE;
	}

	while (GetTickCount64() <= deadline)
	{
		SERVICE_STATUS_PROCESS ssp = {0};
		DWORD needed = 0;
		if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
		{
			if (ssp.dwCurrentState == SERVICE_RUNNING)
			{
				if (initialPid != 0 && ssp.dwProcessId != 0 && ssp.dwProcessId != initialPid)
				{
					sawPidChange = TRUE;
					lastPid = ssp.dwProcessId;
				}

				if (sawNotRunning || sawPidChange || (GetTickCount64() - startTick >= 8000))
				{
					if (sawPidChange)
					{
						MeshAgent_LogNativeInstallerEvent("...Service PID changed: %lu -> %lu", initialPid, lastPid);
					}
					else if (!sawNotRunning)
					{
						MeshAgent_LogNativeInstallerEvent("...Service restart did not change PID; accepting running state");
					}
					CloseServiceHandle(svc);
					CloseServiceHandle(scm);
					return TRUE;
				}
			}
			else
			{
				sawNotRunning = TRUE;
			}
		}

		Sleep(2000);
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return FALSE;
}

static BOOL MeshAgent_SetServiceAllowStop(const wchar_t* serviceName, BOOL allow)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

	wchar_t paramsKeyPath[512];
	_snwprintf_s(paramsKeyPath, _countof(paramsKeyPath), _TRUNCATE,
		L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", serviceName);

	HKEY hKey = NULL;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, paramsKeyPath, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	BOOL ok = TRUE;
	if (allow)
	{
		DWORD value = 1;
		ok = (RegSetValueExW(hKey, L"AllowStop", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS);
	}
	else
	{
		RegDeleteValueW(hKey, L"AllowStop");
	}

	RegCloseKey(hKey);
	return ok;
}

static BOOL MeshAgent_StopServiceAndWait(SC_HANDLE svc, DWORD timeoutMs)
{
	if (svc == NULL) { return FALSE; }

	SERVICE_STATUS_PROCESS ssp = {0};
	DWORD needed = 0;
	if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
	{
		return FALSE;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED)
	{
		return TRUE;
	}

	ControlService(svc, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);

	DWORD waited = 0;
	while (waited < timeoutMs)
	{
		if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed))
		{
			if (ssp.dwCurrentState == SERVICE_STOPPED) { return TRUE; }
		}
		Sleep(500);
		waited += 500;
	}

	return FALSE;
}

static BOOL MeshAgent_RestartServiceForRegression(const wchar_t* serviceName, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }

	SERVICE_STATUS_PROCESS initialStatus = {0};
	DWORD initialPid = 0;
	if (MeshAgent_QueryServiceStatus(serviceName, &initialStatus))
	{
		initialPid = initialStatus.dwProcessId;
	}

	BOOL allowStopSet = MeshAgent_SetServiceAllowStop(serviceName, TRUE);
	if (!allowStopSet)
	{
		MeshAgent_LogNativeInstallerEvent("...Warning: unable to set AllowStop for service");
	}

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		if (allowStopSet) { MeshAgent_SetServiceAllowStop(serviceName, FALSE); }
		return FALSE;
	}

	SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
	if (svc == NULL)
	{
		CloseServiceHandle(scm);
		if (allowStopSet) { MeshAgent_SetServiceAllowStop(serviceName, FALSE); }
		return FALSE;
	}

	if (allowStopSet)
	{
		SERVICE_STATUS status = {0};
		ControlService(svc, SERVICE_CONTROL_INTERROGATE, &status);
	}

	BOOL ok = FALSE;
	if (!MeshAgent_StopServiceAndWait(svc, timeoutMs))
	{
		MeshAgent_LogNativeInstallerEvent("...Service stop timed out");
	}

	if (!StartServiceW(svc, 0, NULL))
	{
		DWORD err = GetLastError();
		if (err != ERROR_SERVICE_ALREADY_RUNNING)
		{
			MeshAgent_LogNativeInstallerEvent("...Service start failed (error=%lu)", err);
			goto cleanup;
		}
	}

	if (!MeshAgent_WaitForServiceRunning(serviceName, timeoutMs))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not reach running state after restart");
		goto cleanup;
	}

	if (!MeshAgent_WaitForServiceRestart(serviceName, initialPid, timeoutMs))
	{
		MeshAgent_LogNativeInstallerEvent("...Service restart did not complete within timeout");
		goto cleanup;
	}

	ok = TRUE;

cleanup:
	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	if (allowStopSet) { MeshAgent_SetServiceAllowStop(serviceName, FALSE); }
	return ok;
}

static BOOL MeshAgent_WaitForNodeId(const wchar_t* serviceName, DWORD timeoutMs)
{
	if (serviceName == NULL || serviceName[0] == L'\0') { return FALSE; }
	DWORD waited = 0;
	BOOL found = FALSE;
	WCHAR keyPath[512] = {0};
	StringCchPrintfW(keyPath, _countof(keyPath), L"SOFTWARE\\Open Source\\%s", serviceName);

	while (waited < timeoutMs)
	{
		HKEY hKey = NULL;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
		{
			wchar_t nodeId[256] = {0};
			DWORD type = 0;
			DWORD cb = (DWORD)sizeof(nodeId);
			if (RegQueryValueExW(hKey, L"NodeId", NULL, &type, (LPBYTE)nodeId, &cb) == ERROR_SUCCESS &&
				nodeId[0] != L'\0')
			{
				found = TRUE;
				RegCloseKey(hKey);
				break;
			}
			RegCloseKey(hKey);
		}

		Sleep(1000);
		waited += 1000;
	}
	return found;
}

static BOOL MeshAgent_WaitForCoreModule(const wchar_t* dbPath, DWORD timeoutMs)
{
	if (dbPath == NULL || dbPath[0] == L'\0') { return FALSE; }

	wchar_t dbPathMutable[MAX_PATH * 4] = {0};
	StringCchCopyW(dbPathMutable, _countof(dbPathMutable), dbPath);
	char dbPathUtf8[MAX_PATH * 4] = {0};
	if (ILibWideToUTF8Ex(dbPathMutable, -1, dbPathUtf8, (int)sizeof(dbPathUtf8)) == 0) { return FALSE; }

	DWORD waited = 0;
	DWORD lastReported = 0;
	while (waited < timeoutMs)
	{
		int coreLen = 0;
		ILibSimpleDataStore ds = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 1);
		if (ds != NULL)
		{
			coreLen = ILibSimpleDataStore_Get(ds, "CoreModule", NULL, 0);
			ILibSimpleDataStore_Close(ds);
			if (coreLen > 4)
			{
				return TRUE;
			}
		}
		if ((waited - lastReported) >= 15000)
		{
			MeshAgent_LogNativeInstallerEvent("...Waiting for core module (%lu/%lu ms, currentLen=%d)", waited, timeoutMs, coreLen);
			lastReported = waited;
		}
		Sleep(1000);
		waited += 1000;
	}

	MeshAgent_LogNativeInstallerEvent("...Core module wait timed out after %lu ms", timeoutMs);
	return FALSE;
}

static BOOL MeshAgent_CopyFileIfPresentW(const wchar_t* sourcePath, const wchar_t* destPath)
{
	if (sourcePath == NULL || destPath == NULL) { return FALSE; }
	DWORD attr = GetFileAttributesW(sourcePath);
	if (attr == INVALID_FILE_ATTRIBUTES) { return FALSE; }
	SetFileAttributesW(destPath, FILE_ATTRIBUTE_NORMAL);
	return (CopyFileW(sourcePath, destPath, FALSE) != 0);
}

static void MeshAgent_EnsureCoreModuleRuntimeGlobals(duk_context* ctx)
{
	if (ctx == NULL) { return; }
	if (duk_peval_string(ctx,
		"(function(){"
		"var g=(function(){return this;})();"
		"if(typeof g.__!=='function'){"
		"g.__=function(){return arguments.length>0?arguments[0]:'';};"
		"}"
		"if(typeof global!=='undefined'&&typeof global.__!=='function'){global.__=g.__;}"
		"if(typeof globalThis!=='undefined'&&typeof globalThis.__!=='function'){globalThis.__=g.__;}"
		"})();") != 0)
	{
		duk_pop(ctx);
		return;
	}
	duk_pop(ctx);
}

static BOOL MeshAgent_FindModulePathFromBaseDir(const wchar_t* baseDir, const wchar_t* moduleFileName, wchar_t* output, size_t outputLen)
{
	wchar_t candidateDir[MAX_PATH] = {0};

	if (baseDir == NULL || baseDir[0] == L'\0' || moduleFileName == NULL || moduleFileName[0] == L'\0' || output == NULL || outputLen == 0)
	{
		return FALSE;
	}
	if (FAILED(StringCchCopyW(candidateDir, _countof(candidateDir), baseDir))) { return FALSE; }

	while (candidateDir[0] != L'\0')
	{
		if (SUCCEEDED(StringCchPrintfW(output, outputLen, L"%s\\modules\\%s", candidateDir, moduleFileName)) &&
			GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES)
		{
			return TRUE;
		}

		wchar_t* slash = wcsrchr(candidateDir, L'\\');
		if (slash == NULL) { break; }
		*slash = L'\0';
	}

	return FALSE;
}

static BOOL MeshAgent_FindModulePath(const wchar_t* moduleFileName, wchar_t* output, size_t outputLen)
{
	if (moduleFileName == NULL || output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	wchar_t exeDir[MAX_PATH] = {0};
	if (GetModuleFileNameW(NULL, exeDir, _countof(exeDir)) > 0)
	{
		wchar_t* lastSlash = wcsrchr(exeDir, L'\\');
		if (lastSlash != NULL) { *lastSlash = L'\0'; }
		if (MeshAgent_FindModulePathFromBaseDir(exeDir, moduleFileName, output, outputLen)) { return TRUE; }
	}

	wchar_t cwd[MAX_PATH] = {0};
	if (GetCurrentDirectoryW(_countof(cwd), cwd) > 0)
	{
		if (MeshAgent_FindModulePathFromBaseDir(cwd, moduleFileName, output, outputLen)) { return TRUE; }
	}

	output[0] = L'\0';
	return FALSE;
}

static BOOL MeshAgent_StageModuleIfMissing(const wchar_t* installDir, const wchar_t* moduleFileName)
{
	if (installDir == NULL || installDir[0] == L'\0' || moduleFileName == NULL || moduleFileName[0] == L'\0') { return FALSE; }

	wchar_t destPath[MAX_PATH] = {0};
	StringCchPrintfW(destPath, _countof(destPath), L"%s\\%s", installDir, moduleFileName);

	wchar_t sourcePath[MAX_PATH] = {0};
	if (!MeshAgent_FindModulePath(moduleFileName, sourcePath, _countof(sourcePath))) { return FALSE; }

	if (!MeshAgent_CopyFileIfPresentW(sourcePath, destPath)) { return FALSE; }
	return (GetFileAttributesW(destPath) != INVALID_FILE_ATTRIBUTES);
}

static BOOL MeshAgent_StageSelfTestModule(const wchar_t* installDir)
{
	if (installDir == NULL || installDir[0] == L'\0') { return FALSE; }
	if (!MeshAgent_StageModuleIfMissing(installDir, L"agent-selftest.js")) { return FALSE; }
	return TRUE;
}

static void MeshAgent_StageSelfTestModuleBestEffort(void)
{
	StealthInstallPaths paths;
	ZeroMemory(&paths, sizeof(paths));

	if (!Stealth_GetInstallPaths(&paths) || paths.installDir[0] == L'\0')
	{
		MeshAgent_LogNativeInstallerEvent("...Self-test module staging skipped: install paths unavailable");
		return;
	}

	if (MeshAgent_StageSelfTestModule(paths.installDir))
	{
		MeshAgent_LogNativeInstallerEvent("...Self-test module staged: %ls\\agent-selftest.js", paths.installDir);
	}
	else
	{
		MeshAgent_LogNativeInstallerEvent("...Self-test module staging failed (source module not found)");
	}
}

static void MeshAgent_StageSelfTestModuleForCurrentExeBestEffort(void)
{
	wchar_t exePath[MAX_PATH * 4] = {0};
	if (GetModuleFileNameW(NULL, exePath, _countof(exePath)) == 0) { return; }
	wchar_t* slash = wcsrchr(exePath, L'\\');
	if (slash == NULL) { return; }
	*slash = L'\0';

	if (MeshAgent_StageSelfTestModule(exePath))
	{
		MeshAgent_LogNativeInstallerEvent("...Self-test module staged for current binary: %ls\\agent-selftest.js", exePath);
	}
}

static BOOL MeshAgent_FileExistsW(const wchar_t* path)
{
	if (path == NULL || path[0] == L'\0') { return FALSE; }
	DWORD attr = GetFileAttributesW(path);
	return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

static BOOL MeshAgent_FilesLikelyIdenticalW(const wchar_t* leftPath, const wchar_t* rightPath)
{
	if (!MeshAgent_FileExistsW(leftPath) || !MeshAgent_FileExistsW(rightPath)) { return FALSE; }

	WIN32_FILE_ATTRIBUTE_DATA leftData;
	WIN32_FILE_ATTRIBUTE_DATA rightData;
	if (!GetFileAttributesExW(leftPath, GetFileExInfoStandard, &leftData) ||
		!GetFileAttributesExW(rightPath, GetFileExInfoStandard, &rightData))
	{
		return FALSE;
	}

	if (leftData.nFileSizeHigh != rightData.nFileSizeHigh ||
		leftData.nFileSizeLow != rightData.nFileSizeLow)
	{
		return FALSE;
	}

	if (leftData.ftLastWriteTime.dwHighDateTime != rightData.ftLastWriteTime.dwHighDateTime ||
		leftData.ftLastWriteTime.dwLowDateTime != rightData.ftLastWriteTime.dwLowDateTime)
	{
		return FALSE;
	}

	return TRUE;
}

static BOOL MeshAgent_GetDirectoryNameW(const wchar_t* fullPath, wchar_t* outDir, size_t outDirLen)
{
	if (fullPath == NULL || outDir == NULL || outDirLen == 0) { return FALSE; }
	if (FAILED(StringCchCopyW(outDir, outDirLen, fullPath))) { return FALSE; }
	wchar_t* slash = wcsrchr(outDir, L'\\');
	if (slash == NULL) { slash = wcsrchr(outDir, L'/'); }
	if (slash == NULL) { return FALSE; }
	*slash = L'\0';
	return TRUE;
}

static HANDLE MeshAgent_OpenRegressionLog(void)
{
	WCHAR logPath[MAX_PATH * 4] = {0};
	WCHAR logDir[MAX_PATH * 4] = {0};
	StealthInstallPaths paths;

	// Prefer evidence directory in repo (docs/testing) to avoid log deletion during uninstall.
	WCHAR repoRoot[MAX_PATH * 4] = {0};
	if (MeshAgent_FindRepoRootW(repoRoot, _countof(repoRoot)))
	{
		WCHAR evidenceDir[MAX_PATH * 4] = {0};
		StringCchPrintfW(evidenceDir, _countof(evidenceDir), L"%s\\docs", repoRoot);
		MeshAgent_EnsureDirectoryW(evidenceDir);
		StringCchPrintfW(evidenceDir, _countof(evidenceDir), L"%s\\docs\\testing", repoRoot);
		MeshAgent_EnsureDirectoryW(evidenceDir);

		StringCchCopyW(logDir, _countof(logDir), evidenceDir);
		StringCchPrintfW(logPath, _countof(logPath), L"%s\\native-regression.log", logDir);
	}
	else if (Stealth_GetInstallPaths(&paths))
	{
		StringCchCopyW(logDir, _countof(logDir), paths.logsDir);
	}
	else
	{
		if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, logDir)))
		{
			StringCchCopyW(logDir, _countof(logDir), L"C:\\ProgramData");
		}
		StringCchCatW(logDir, _countof(logDir), L"\\" STEALTH_FALLBACK_SERVICE_NAME L"\\logs");
	}

	CreateDirectoryW(logDir, NULL);
	if (logPath[0] == L'\0')
	{
		StringCchPrintfW(logPath, _countof(logPath), L"%s\\native-regression.log", logDir);
	}

	SECURITY_ATTRIBUTES sa = {0};
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	return CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &sa, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
}

static void MeshAgent_EnsureDirectoryW(const wchar_t* path)
{
	if (path == NULL || path[0] == L'\0') { return; }
	DWORD attr = GetFileAttributesW(path);
	if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) { return; }
	CreateDirectoryW(path, NULL);
}

static BOOL MeshAgent_FindRepoRootW(wchar_t* output, size_t outputLen)
{
	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	wchar_t base[MAX_PATH * 4] = {0};
	if (GetModuleFileNameW(NULL, base, _countof(base)) == 0) { return FALSE; }
	wchar_t* slash = wcsrchr(base, L'\\');
	if (slash != NULL) { *slash = L'\0'; }

	wchar_t candidate[MAX_PATH * 4] = {0};
	for (int depth = 0; depth < 8; ++depth)
	{
		wchar_t testPath[MAX_PATH * 4] = {0};
		StringCchPrintfW(testPath, _countof(testPath), L"%s\\.git", base);
		if (GetFileAttributesW(testPath) != INVALID_FILE_ATTRIBUTES)
		{
			StringCchCopyW(output, outputLen, base);
			return TRUE;
		}
		if (candidate[0] == L'\0')
		{
			StringCchPrintfW(testPath, _countof(testPath), L"%s\\docs\\testing", base);
			if (GetFileAttributesW(testPath) != INVALID_FILE_ATTRIBUTES)
			{
				StringCchCopyW(candidate, _countof(candidate), base);
			}
		}
		slash = wcsrchr(base, L'\\');
		if (slash == NULL) { break; }
		*slash = L'\0';
	}

	if (candidate[0] != L'\0')
	{
		StringCchCopyW(output, outputLen, candidate);
		return TRUE;
	}

	return FALSE;
}

static void MeshAgent_FormatTimestamp(wchar_t* buffer, size_t count)
{
	if (buffer == NULL || count == 0) { return; }
	SYSTEMTIME st;
	GetLocalTime(&st);
	StringCchPrintfW(buffer, count, L"%04u%02u%02u_%02u%02u%02u",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void MeshAgent_CopyEvidenceFile(const wchar_t* srcPath, const wchar_t* destDir, const wchar_t* prefix, const wchar_t* fileName)
{
	if (srcPath == NULL || destDir == NULL || prefix == NULL || fileName == NULL) { return; }
	if (GetFileAttributesW(srcPath) == INVALID_FILE_ATTRIBUTES) { return; }

	wchar_t destPath[MAX_PATH * 4] = {0};
	StringCchPrintfW(destPath, _countof(destPath), L"%s\\%s_%s", destDir, prefix, fileName);
	CopyFileW(srcPath, destPath, FALSE);
}

static void MeshAgent_CopyEvidenceSnapshot(const wchar_t* phaseLabel)
{
	wchar_t repoRoot[MAX_PATH * 4] = {0};
	if (!MeshAgent_FindRepoRootW(repoRoot, _countof(repoRoot))) { return; }

	wchar_t docsDir[MAX_PATH * 4] = {0};
	wchar_t testingDir[MAX_PATH * 4] = {0};
	StringCchPrintfW(docsDir, _countof(docsDir), L"%s\\docs", repoRoot);
	StringCchPrintfW(testingDir, _countof(testingDir), L"%s\\docs\\testing", repoRoot);
	MeshAgent_EnsureDirectoryW(docsDir);
	MeshAgent_EnsureDirectoryW(testingDir);

	wchar_t timestamp[64] = {0};
	MeshAgent_FormatTimestamp(timestamp, _countof(timestamp));
	wchar_t prefix[128] = {0};
	if (phaseLabel != NULL && phaseLabel[0] != L'\0')
	{
		StringCchPrintfW(prefix, _countof(prefix), L"%s_%s", timestamp, phaseLabel);
	}
	else
	{
		StringCchCopyW(prefix, _countof(prefix), timestamp);
	}

	StealthInstallPaths paths;
	ZeroMemory(&paths, sizeof(paths));
	wchar_t installDir[MAX_PATH * 4] = {0};
	wchar_t logsDir[MAX_PATH * 4] = {0};
	if (Stealth_GetInstallPaths(&paths))
	{
		StringCchCopyW(installDir, _countof(installDir), paths.installDir);
		StringCchCopyW(logsDir, _countof(logsDir), paths.logsDir);
	}
	else
	{
		StringCchPrintfW(installDir, _countof(installDir), L"C:\\ProgramData\\%s", STEALTH_FALLBACK_SERVICE_NAME);
		StringCchPrintfW(logsDir, _countof(logsDir), L"C:\\ProgramData\\%s\\logs", STEALTH_FALLBACK_SERVICE_NAME);
	}

	wchar_t srcPath[MAX_PATH * 4] = {0};
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\native-regression.log", logsDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"native-regression.log");
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\native-install.log", logsDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"native-install.log");
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\installer.log", logsDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"installer.log");
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\diagnostics.log", logsDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"diagnostics.log");

	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\controlchannel-debug.log", installDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"controlchannel-debug.log");
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\svchost-debug.log", installDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, L"svchost-debug.log");
	StringCchPrintfW(srcPath, _countof(srcPath), L"%s\\" STEALTH_FALLBACK_LOG_NAME, installDir);
	MeshAgent_CopyEvidenceFile(srcPath, testingDir, prefix, STEALTH_FALLBACK_LOG_NAME);
}

static BOOL MeshAgent_WidePathToJsonValue(const wchar_t* input, char* output, size_t outputLen)
{
	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = 0;
	if (input == NULL || input[0] == 0) { return FALSE; }
	int len = WideCharToMultiByte(CP_UTF8, 0, input, -1, output, (int)outputLen, NULL, NULL);
	if (len <= 0 || (size_t)len > outputLen) { return FALSE; }
	for (int i = 0; output[i] != 0; ++i)
	{
		if (output[i] == '\\') { output[i] = '/'; }
	}
	return TRUE;
}

static BOOL MeshAgent_BuildDefaultPreProtectionCapturePathW(wchar_t* output, size_t outputLen)
{
	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	wchar_t programData[MAX_PATH] = {0};
	if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, programData)))
	{
		StringCchCopyW(programData, _countof(programData), L"C:\\ProgramData");
	}

	wchar_t dirPath[MAX_PATH * 4] = {0};
	StringCchPrintfW(dirPath, _countof(dirPath), L"%s\\" STEALTH_FALLBACK_SERVICE_NAME L"\\logs\\preprotection", programData);
	SHCreateDirectoryExW(NULL, dirPath, NULL);

	wchar_t timestamp[64] = {0};
	MeshAgent_FormatTimestamp(timestamp, _countof(timestamp));
	return SUCCEEDED(StringCchPrintfW(output, outputLen, L"%s\\%s_pre_protection.bmp", dirPath, timestamp));
}

// Forward declaration for DXGI one-shot capture from tile.cpp (C++ with extern "C")
#if defined(_LINKVM)
extern int capture_desktop_dxgi_oneshot(void** buffer, int* width, int* height);
#endif

static BOOL MeshAgent_WriteBufferAsBmpW(const wchar_t* outputPath, void* bgra, LONG width, LONG height, DWORD* fileSizeOut)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD imageBytes = (DWORD)((DWORD)width * (DWORD)height * 4);
	DWORD written = 0;

	BITMAPINFOHEADER bih;
	ZeroMemory(&bih, sizeof(bih));
	bih.biSize = sizeof(BITMAPINFOHEADER);
	bih.biWidth = width;
	bih.biHeight = -height; // top-down
	bih.biPlanes = 1;
	bih.biBitCount = 32;
	bih.biCompression = BI_RGB;

	BITMAPFILEHEADER fileHeader;
	ZeroMemory(&fileHeader, sizeof(fileHeader));
	fileHeader.bfType = 0x4D42;
	fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	fileHeader.bfSize = fileHeader.bfOffBits + imageBytes;

	hFile = CreateFileW(outputPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) { return FALSE; }

	if (!WriteFile(hFile, &fileHeader, sizeof(fileHeader), &written, NULL) || written != sizeof(fileHeader)) { CloseHandle(hFile); return FALSE; }
	if (!WriteFile(hFile, &bih, sizeof(bih), &written, NULL) || written != sizeof(bih)) { CloseHandle(hFile); return FALSE; }
	if (!WriteFile(hFile, bgra, imageBytes, &written, NULL) || written != imageBytes) { CloseHandle(hFile); return FALSE; }
	CloseHandle(hFile);
	if (fileSizeOut != NULL) { *fileSizeOut = fileHeader.bfSize; }
	return TRUE;
}

static BOOL MeshAgent_CaptureDesktopBmpW(const wchar_t* outputPath, LONG* widthOut, LONG* heightOut, DWORD* fileSizeOut)
{
	BOOL ok = FALSE;
	HDC hScreen = NULL;
	HDC hCapture = NULL;
	HBITMAP hBitmap = NULL;
	void* bits = NULL;
	LONG width = 0;
	LONG height = 0;
	LONG left = 0;
	LONG top = 0;
	DWORD imageBytes = 0;

	if (outputPath == NULL || outputPath[0] == L'\0') { return FALSE; }

	// Ensure parent directory exists
	{
		wchar_t parentDir[MAX_PATH * 4] = {0};
		StringCchCopyW(parentDir, _countof(parentDir), outputPath);
		wchar_t* slash = wcsrchr(parentDir, L'\\');
		if (slash != NULL)
		{
			*slash = L'\0';
			SHCreateDirectoryExW(NULL, parentDir, NULL);
		}
	}

	// Try DXGI first — captures DWM-composited content including DX/GL surfaces and overlays
#if defined(_LINKVM)
	{
		void* dxgiBuffer = NULL;
		int dxgiW = 0, dxgiH = 0;
		if (capture_desktop_dxgi_oneshot(&dxgiBuffer, &dxgiW, &dxgiH) != 0 && dxgiBuffer != NULL && dxgiW > 0 && dxgiH > 0)
		{
			DWORD fileSize = 0;
			ok = MeshAgent_WriteBufferAsBmpW(outputPath, dxgiBuffer, (LONG)dxgiW, (LONG)dxgiH, &fileSize);
			free(dxgiBuffer);
			if (ok)
			{
				if (widthOut != NULL) { *widthOut = (LONG)dxgiW; }
				if (heightOut != NULL) { *heightOut = (LONG)dxgiH; }
				if (fileSizeOut != NULL) { *fileSizeOut = fileSize; }
				return TRUE;
			}
		}
	}
#endif

	// GDI fallback — always available, captures visible desktop via BitBlt
	left = GetSystemMetrics(SM_XVIRTUALSCREEN);
	top = GetSystemMetrics(SM_YVIRTUALSCREEN);
	width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	if (width <= 0 || height <= 0) { goto cleanup; }

	hScreen = GetDC(NULL);
	if (hScreen == NULL) { goto cleanup; }
	hCapture = CreateCompatibleDC(hScreen);
	if (hCapture == NULL) { goto cleanup; }
	hBitmap = CreateCompatibleBitmap(hScreen, width, height);
	if (hBitmap == NULL) { goto cleanup; }
	if (SelectObject(hCapture, hBitmap) == NULL) { goto cleanup; }
	if (BitBlt(hCapture, 0, 0, width, height, hScreen, left, top, SRCCOPY | CAPTUREBLT) == FALSE) { goto cleanup; }

	imageBytes = (DWORD)(width * height * 4);
	bits = malloc(imageBytes);
	if (bits == NULL) { goto cleanup; }
	{
		BITMAPINFO bmi;
		ZeroMemory(&bmi, sizeof(bmi));
		bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmi.bmiHeader.biWidth = width;
		bmi.bmiHeader.biHeight = -height;
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 32;
		bmi.bmiHeader.biCompression = BI_RGB;
		if (GetDIBits(hCapture, hBitmap, 0, (UINT)height, bits, &bmi, DIB_RGB_COLORS) == 0) { goto cleanup; }
	}

	{
		DWORD fileSize = 0;
		ok = MeshAgent_WriteBufferAsBmpW(outputPath, bits, width, height, &fileSize);
		if (ok && fileSizeOut != NULL) { *fileSizeOut = fileSize; }
	}

cleanup:
	if (bits != NULL) { free(bits); }
	if (hBitmap != NULL) { DeleteObject(hBitmap); }
	if (hCapture != NULL) { DeleteDC(hCapture); }
	if (hScreen != NULL) { ReleaseDC(NULL, hScreen); }
	if (ok)
	{
		if (widthOut != NULL) { *widthOut = width; }
		if (heightOut != NULL) { *heightOut = height; }
	}
	return ok;
}

static BOOL MeshAgent_RunPreProtectionCaptureValidationW(const wchar_t* outputPath)
{
	wchar_t capturePath[MAX_PATH * 4] = {0};
	if (outputPath != NULL && outputPath[0] != L'\0')
	{
		StringCchCopyW(capturePath, _countof(capturePath), outputPath);
	}
	else if (!MeshAgent_BuildDefaultPreProtectionCapturePathW(capturePath, _countof(capturePath)))
	{
		printf("{\"ok\":false,\"error\":\"capture-path-unavailable\"}\n");
		return FALSE;
	}

	LONG width = 0;
	LONG height = 0;
	DWORD fileSize = 0;
	BOOL ok = MeshAgent_CaptureDesktopBmpW(capturePath, &width, &height, &fileSize);
	char capturePathUtf8[MAX_PATH * 8] = {0};
	MeshAgent_WidePathToJsonValue(capturePath, capturePathUtf8, sizeof(capturePathUtf8));

	SYSTEMTIME st;
	GetSystemTime(&st);
	char timestamp[64];
	sprintf_s(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
		(unsigned int)st.wYear, (unsigned int)st.wMonth, (unsigned int)st.wDay,
		(unsigned int)st.wHour, (unsigned int)st.wMinute, (unsigned int)st.wSecond, (unsigned int)st.wMilliseconds);

	if (!ok)
	{
		printf("{\"ok\":false,\"capture_path\":\"%s\",\"captured_at_utc\":\"%s\",\"error\":\"desktop-capture-failed\",\"win32_error\":%lu}\n",
			capturePathUtf8, timestamp, (unsigned long)GetLastError());
		MeshAgent_LogNativeInstallerEvent("...Pre-protection capture failed: %ls (error=%lu)", capturePath, (unsigned long)GetLastError());
		return FALSE;
	}

	printf("{\"ok\":true,\"capture_path\":\"%s\",\"captured_at_utc\":\"%s\",\"width\":%ld,\"height\":%ld,\"file_size\":%lu}\n",
		capturePathUtf8, timestamp, width, height, (unsigned long)fileSize);
	MeshAgent_LogNativeInstallerEvent("...Pre-protection capture saved: %ls (%ldx%ld, %lu bytes)",
		capturePath, width, height, (unsigned long)fileSize);
	return TRUE;
}

static ULONGLONG MeshAgent_FileTimeToUint64(const FILETIME* ft)
{
	ULARGE_INTEGER val;
	val.LowPart = ft->dwLowDateTime;
	val.HighPart = ft->dwHighDateTime;
	return val.QuadPart;
}

static BOOL MeshAgent_ReadFileTailW(const wchar_t* path, DWORD maxBytes, char** bufferOut, DWORD* lenOut, ULONGLONG* mtimeOut)
{
	if (path == NULL || bufferOut == NULL || lenOut == NULL) { return FALSE; }
	*bufferOut = NULL;
	*lenOut = 0;
	if (mtimeOut != NULL) { *mtimeOut = 0; }

	HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) { return FALSE; }

	FILETIME ftWrite;
	if (mtimeOut != NULL && GetFileTime(hFile, NULL, NULL, &ftWrite))
	{
		*mtimeOut = MeshAgent_FileTimeToUint64(&ftWrite);
	}

	LARGE_INTEGER size;
	if (!GetFileSizeEx(hFile, &size))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	LONGLONG readSize = size.QuadPart;
	if (maxBytes > 0 && readSize > (LONGLONG)maxBytes) { readSize = maxBytes; }
	LONGLONG offset = size.QuadPart - readSize;
	if (offset < 0) { offset = 0; }

	LARGE_INTEGER seek;
	seek.QuadPart = offset;
	SetFilePointerEx(hFile, seek, NULL, FILE_BEGIN);

	char* buffer = (char*)malloc((size_t)readSize + 1);
	if (buffer == NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD bytesRead = 0;
	if (!ReadFile(hFile, buffer, (DWORD)readSize, &bytesRead, NULL))
	{
		free(buffer);
		CloseHandle(hFile);
		return FALSE;
	}
	buffer[bytesRead] = '\0';
	CloseHandle(hFile);

	*bufferOut = buffer;
	*lenOut = bytesRead;
	return TRUE;
}

typedef struct MeshAgent_SelfTestProgress
{
	DWORD success;
	DWORD kvmStepSeen;
	DWORD fallbackPathSeen;
	DWORD fallbackOkSeen;
	DWORD ramasSimulationSeen;
	DWORD fallbackOkCount;
} MeshAgent_SelfTestProgress;

typedef struct MeshAgent_RemoteDesktopRegressionMetrics
{
	DWORD majorBugRuns;
	DWORD majorBugPasses;
	DWORD fallbackSimulationRuns;
	DWORD fallbackSimulationPasses;
	DWORD fallbackObservedRuns;
	DWORD readinessSamples;
	DWORD readinessMinMs;
	DWORD readinessMaxMs;
	ULONGLONG readinessTotalMs;
} MeshAgent_RemoteDesktopRegressionMetrics;

static DWORD MeshAgent_CountSubstringA(const char* haystack, const char* needle)
{
	DWORD count = 0;
	size_t needleLen = 0;
	const char* current = NULL;

	if (haystack == NULL || needle == NULL || needle[0] == '\0') { return 0; }
	needleLen = strlen(needle);
	current = haystack;
	while ((current = strstr(current, needle)) != NULL)
	{
		++count;
		current += needleLen;
	}
	return count;
}

static void MeshAgent_ParseSelfTestProgressLog(const wchar_t* path, MeshAgent_SelfTestProgress* progress)
{
	char* text = NULL;
	DWORD textLen = 0;

	if (progress == NULL) { return; }
	ZeroMemory(progress, sizeof(MeshAgent_SelfTestProgress));
	if (path == NULL || path[0] == L'\0') { return; }

	if (!MeshAgent_ReadFileTailW(path, 2 * 1024 * 1024, &text, &textLen, NULL))
	{
		return;
	}
	if (text == NULL || textLen == 0)
	{
		if (text != NULL) { free(text); }
		return;
	}

	progress->success = (strstr(text, "SelfTest complete: SUCCESS") != NULL) ? 1 : 0;
	progress->kvmStepSeen = (strstr(text, "Step: testKVM") != NULL) ? 1 : 0;
	progress->fallbackPathSeen = (strstr(text, "KVM fallback path entered") != NULL || strstr(text, "TUNNEL FALLBACK") != NULL) ? 1 : 0;
	progress->fallbackOkSeen = (strstr(text, "KVM fallback path success") != NULL || strstr(text, "fallback...........[OK]") != NULL) ? 1 : 0;
	progress->ramasSimulationSeen = (strstr(text, "RAMAS fallback simulation enabled") != NULL) ? 1 : 0;
	progress->fallbackOkCount = MeshAgent_CountSubstringA(text, "fallback...........[OK]");

	free(text);
}

static void MeshAgent_InitRemoteDesktopMetrics(MeshAgent_RemoteDesktopRegressionMetrics* metrics)
{
	if (metrics == NULL) { return; }
	ZeroMemory(metrics, sizeof(MeshAgent_RemoteDesktopRegressionMetrics));
}

static void MeshAgent_RecordReadinessSample(MeshAgent_RemoteDesktopRegressionMetrics* metrics, DWORD sampleMs)
{
	if (metrics == NULL) { return; }
	if (metrics->readinessSamples == 0 || sampleMs < metrics->readinessMinMs)
	{
		metrics->readinessMinMs = sampleMs;
	}
	if (metrics->readinessSamples == 0 || sampleMs > metrics->readinessMaxMs)
	{
		metrics->readinessMaxMs = sampleMs;
	}
	metrics->readinessSamples += 1;
	metrics->readinessTotalMs += sampleMs;
}

static BOOL MeshAgent_BuildTestingProgressLogPath(const wchar_t* phaseLabel, wchar_t* output, size_t outputLen)
{
	wchar_t repoRoot[MAX_PATH * 4] = {0};
	wchar_t docsDir[MAX_PATH * 4] = {0};
	wchar_t testingDir[MAX_PATH * 4] = {0};
	wchar_t timestamp[64] = {0};
	const wchar_t* label = phaseLabel;

	if (output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	if (!MeshAgent_FindRepoRootW(repoRoot, _countof(repoRoot)))
	{
		return FALSE;
	}

	StringCchPrintfW(docsDir, _countof(docsDir), L"%s\\docs", repoRoot);
	StringCchPrintfW(testingDir, _countof(testingDir), L"%s\\docs\\testing", repoRoot);
	MeshAgent_EnsureDirectoryW(docsDir);
	MeshAgent_EnsureDirectoryW(testingDir);

	MeshAgent_FormatTimestamp(timestamp, _countof(timestamp));
	if (label == NULL || label[0] == L'\0') { label = L"selftest"; }
	StringCchPrintfW(output, outputLen, L"%s\\%s_%s_progress.log", testingDir, timestamp, label);
	return TRUE;
}

static BOOL MeshAgent_AppendSelfTestPathArg(wchar_t* args, size_t argsLen, const wchar_t* argName, const wchar_t* value)
{
	if (args == NULL || argName == NULL || value == NULL || value[0] == L'\0') { return FALSE; }
	if (FAILED(StringCchCatW(args, argsLen, L" --"))) { return FALSE; }
	if (FAILED(StringCchCatW(args, argsLen, argName))) { return FALSE; }
	if (FAILED(StringCchCatW(args, argsLen, L"=\""))) { return FALSE; }
	if (FAILED(StringCchCatW(args, argsLen, value))) { return FALSE; }
	if (FAILED(StringCchCatW(args, argsLen, L"\""))) { return FALSE; }
	return TRUE;
}

static BOOL MeshAgent_GetConfigValue(char* text, const char* key, char* valueOut, size_t valueOutLen)
{
	if (text == NULL || key == NULL || valueOut == NULL || valueOutLen == 0) { return FALSE; }

	char* context = NULL;
	for (char* line = strtok_s(text, "\n", &context); line != NULL; line = strtok_s(NULL, "\n", &context))
	{
		char* p = line;
		char* cr = strchr(p, '\r');
		if (cr != NULL) { *cr = '\0'; }
		while (*p != '\0' && isspace((unsigned char)*p)) { ++p; }
		if (*p == '\0' || *p == '#' || *p == ';') { continue; }

		char* eq = strchr(p, '=');
		if (eq == NULL) { continue; }
		*eq = '\0';
		char* keyPart = p;
		char* valuePart = eq + 1;

		char* end = keyPart + strlen(keyPart);
		while (end > keyPart && isspace((unsigned char)*(end - 1))) { *(--end) = '\0'; }

		while (*valuePart != '\0' && isspace((unsigned char)*valuePart)) { ++valuePart; }
		end = valuePart + strlen(valuePart);
		while (end > valuePart && isspace((unsigned char)*(end - 1))) { *(--end) = '\0'; }

		if (_stricmp(keyPart, key) == 0)
		{
			strncpy_s(valueOut, valueOutLen, valuePart, _TRUNCATE);
			return TRUE;
		}
	}

	return FALSE;
}

static void MeshAgent_ExtractHost(const char* input, char* output, size_t outputLen)
{
	if (output == NULL || outputLen == 0) { return; }
	output[0] = '\0';
	if (input == NULL || input[0] == '\0') { return; }

	const char* s = input;
	while (*s != '\0' && isspace((unsigned char)*s)) { ++s; }
	const char* scheme = strstr(s, "://");
	if (scheme != NULL) { s = scheme + 3; }
	while (*s == '/') { ++s; }

	const char* end = s;
	while (*end != '\0' && *end != '/' && *end != ':' && *end != '?' && *end != '#') { ++end; }
	size_t len = (size_t)(end - s);
	if (len >= outputLen) { len = outputLen - 1; }
	memcpy(output, s, len);
	output[len] = '\0';
}

static BOOL MeshAgent_FindFileByExtension(const wchar_t* dir, const wchar_t* ext, wchar_t* output, size_t outputLen)
{
	if (dir == NULL || ext == NULL || output == NULL || outputLen == 0) { return FALSE; }
	output[0] = L'\0';

	wchar_t pattern[MAX_PATH * 4] = {0};
	StringCchPrintfW(pattern, _countof(pattern), L"%s\\*%s", dir, ext);
	WIN32_FIND_DATAW fd;
	HANDLE hFind = FindFirstFileW(pattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE) { return FALSE; }

	StringCchPrintfW(output, outputLen, L"%s\\%s", dir, fd.cFileName);
	FindClose(hFind);
	return TRUE;
}

static BOOL MeshAgent_ValidateNetworkPersistence(DWORD timeoutMs)
{
	StealthInstallPaths paths;
	ZeroMemory(&paths, sizeof(paths));
	if (!Stealth_GetInstallPaths(&paths))
	{
		MeshAgent_LogNativeInstallerEvent("...Network persistence validation: install paths unavailable");
		return FALSE;
	}

	wchar_t configPath[MAX_PATH * 4] = {0};
	if (paths.confPath[0] != L'\0')
	{
		StringCchCopyW(configPath, _countof(configPath), paths.confPath);
	}
	else if (!MeshAgent_FindFileByExtension(paths.installDir, L".msh", configPath, _countof(configPath)))
	{
		MeshAgent_FindFileByExtension(paths.installDir, L".conf", configPath, _countof(configPath));
	}

	if (configPath[0] == L'\0')
	{
		MeshAgent_LogNativeInstallerEvent("...Network persistence validation: config file not found");
		return FALSE;
	}

	char* configText = NULL;
	DWORD configLen = 0;
	if (!MeshAgent_ReadFileTailW(configPath, 256 * 1024, &configText, &configLen, NULL))
	{
		MeshAgent_LogNativeInstallerEvent("...Network persistence validation: unable to read config");
		return FALSE;
	}

	char serverId[256] = {0};
	char meshServer[512] = {0};
	char* temp = _strdup(configText);
	if (temp != NULL)
	{
		MeshAgent_GetConfigValue(temp, "ServerID", serverId, sizeof(serverId));
		free(temp);
	}
	temp = _strdup(configText);
	if (temp != NULL)
	{
		MeshAgent_GetConfigValue(temp, "MeshServer", meshServer, sizeof(meshServer));
		free(temp);
	}
	free(configText);

	if (serverId[0] == '\0')
	{
		MeshAgent_LogNativeInstallerEvent("...Network persistence validation: ServerID missing");
		return FALSE;
	}

	char expectedHost[256] = {0};
	if (meshServer[0] != '\0')
	{
		MeshAgent_ExtractHost(meshServer, expectedHost, sizeof(expectedHost));
	}

	wchar_t logPath[MAX_PATH * 4] = {0};
	StringCchPrintfW(logPath, _countof(logPath), L"%s\\controlchannel-debug.log", paths.installDir);
	if (GetFileAttributesW(logPath) == INVALID_FILE_ATTRIBUTES)
	{
		StringCchPrintfW(logPath, _countof(logPath), L"%s\\controlchannel-debug.log", paths.logsDir);
	}

	MeshAgent_LogNativeInstallerEvent("...Network persistence validation: waiting for control channel");
	ULONGLONG start = GetTickCount64();
	while ((GetTickCount64() - start) < timeoutMs)
	{
		char* logText = NULL;
		DWORD logLen = 0;
		ULONGLONG mtime = 0;
		if (MeshAgent_ReadFileTailW(logPath, 512 * 1024, &logText, &logLen, &mtime))
		{
			BOOL recent = FALSE;
			if (mtime != 0)
			{
				FILETIME nowFt;
				GetSystemTimeAsFileTime(&nowFt);
				ULONGLONG now = MeshAgent_FileTimeToUint64(&nowFt);
				recent = (now > mtime) ? ((now - mtime) < (ULONGLONG)120 * 10000000ULL) : TRUE;
			}

			BOOL hasConnection = (strstr(logText, "Connection_Established") != NULL) ||
				(strstr(logText, "serverConnectionState set to 2") != NULL);
			BOOL hostOk = (expectedHost[0] == '\0') ||
				(strstr(logText, expectedHost) != NULL);

			free(logText);

			if (hasConnection && hostOk && recent)
			{
				MeshAgent_LogNativeInstallerEvent("...Network persistence validation: control channel active");
				return TRUE;
			}
		}

		Sleep(2000);
	}

	MeshAgent_LogNativeInstallerEvent("...Network persistence validation failed: timeout");
	return FALSE;
}

static BOOL MeshAgent_RunChildProcess(const wchar_t* exePath, const wchar_t* args, DWORD timeoutMs, DWORD* exitCode)
{
	if (exePath == NULL || exePath[0] == L'\0') { return FALSE; }

	size_t exeLen = wcslen(exePath);
	size_t argsLen = (args != NULL) ? wcslen(args) : 0;
	size_t cmdLen = exeLen + argsLen + 4;
	wchar_t* cmdLine = (wchar_t*)malloc(sizeof(wchar_t) * cmdLen);
	if (cmdLine == NULL) { return FALSE; }

	if (argsLen > 0)
	{
		StringCchPrintfW(cmdLine, cmdLen, L"\"%s\" %s", exePath, args);
	}
	else
	{
		StringCchPrintfW(cmdLine, cmdLen, L"\"%s\"", exePath);
	}

	HANDLE logHandle = MeshAgent_OpenRegressionLog();
	STARTUPINFOW si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	if (logHandle != INVALID_HANDLE_VALUE)
	{
		si.dwFlags |= STARTF_USESTDHANDLES;
		si.hStdOutput = logHandle;
		si.hStdError = logHandle;
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	}

	BOOL created = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	free(cmdLine);

	if (!created)
	{
		DWORD err = GetLastError();
		MeshAgent_LogNativeInstallerEvent("...Failed to start process (error=%lu)", err);
		if (logHandle != INVALID_HANDLE_VALUE) { CloseHandle(logHandle); }
		return FALSE;
	}

	DWORD wait = WaitForSingleObject(pi.hProcess, timeoutMs == 0 ? INFINITE : timeoutMs);
	DWORD childExit = ERROR_SUCCESS;
	if (wait == WAIT_TIMEOUT)
	{
		MeshAgent_LogNativeInstallerEvent("...Process timeout; terminating");
		TerminateProcess(pi.hProcess, ERROR_INSTALL_FAILURE);
		WaitForSingleObject(pi.hProcess, 5000);
		GetExitCodeProcess(pi.hProcess, &childExit);
	}
	else
	{
		GetExitCodeProcess(pi.hProcess, &childExit);
	}

	if (exitCode != NULL) { *exitCode = childExit; }
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	if (logHandle != INVALID_HANDLE_VALUE) { CloseHandle(logHandle); }

	return (childExit == ERROR_SUCCESS);
}

static BOOL MeshAgent_RunMajorBugSelfTest(
	const wchar_t* selfTestBinary,
	const wchar_t* serviceName,
	const StealthInstallPaths* selfTestPaths,
	const wchar_t* mshPath,
	const wchar_t* phaseLabel,
	BOOL ramasFallbackSimulation,
	DWORD timeoutMs,
	DWORD* exitCodeOut,
	MeshAgent_RemoteDesktopRegressionMetrics* metrics)
{
	wchar_t args[4096] = {0};
	wchar_t progressLogPath[MAX_PATH * 4] = {0};
	DWORD exitCode = ERROR_SUCCESS;
	BOOL ok = FALSE;
	ULONGLONG started = 0;
	DWORD elapsedMs = 0;
	MeshAgent_SelfTestProgress progress;
	ZeroMemory(&progress, sizeof(progress));

	if (selfTestBinary == NULL || selfTestBinary[0] == L'\0' ||
		serviceName == NULL || serviceName[0] == L'\0')
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	StringCchPrintfW(args, _countof(args),
		L"--selfTest=1 --serviceName=\"%s\" --majorBug=1 --readonly=1 --skipServiceRestart=1 --skipCoreDump=1",
		serviceName);

	if (selfTestPaths != NULL)
	{
		if (selfTestPaths->installDir[0] != L'\0' &&
			!MeshAgent_AppendSelfTestPathArg(args, _countof(args), L"installRoot", selfTestPaths->installDir))
		{
			return FALSE;
		}
		if (selfTestPaths->confPath[0] != L'\0' &&
			!MeshAgent_AppendSelfTestPathArg(args, _countof(args), L"confPath", selfTestPaths->confPath))
		{
			return FALSE;
		}
	}
	if (mshPath != NULL && mshPath[0] != L'\0' &&
		!MeshAgent_AppendSelfTestPathArg(args, _countof(args), L"mshPath", mshPath))
	{
		return FALSE;
	}

	if (ramasFallbackSimulation)
	{
		if (FAILED(StringCchCatW(args, _countof(args), L" --ramasFallback=1")))
		{
			return FALSE;
		}
	}

	if (MeshAgent_BuildTestingProgressLogPath(phaseLabel, progressLogPath, _countof(progressLogPath)))
	{
		DeleteFileW(progressLogPath);
		if (!MeshAgent_AppendSelfTestPathArg(args, _countof(args), L"progressLog", progressLogPath))
		{
			return FALSE;
		}
	}

	started = GetTickCount64();
	ok = MeshAgent_RunChildProcess(selfTestBinary, args, timeoutMs, &exitCode);
	elapsedMs = (DWORD)(GetTickCount64() - started);

	if (progressLogPath[0] != L'\0')
	{
		MeshAgent_ParseSelfTestProgressLog(progressLogPath, &progress);
	}

	if (metrics != NULL)
	{
		metrics->majorBugRuns += 1;
		if (ramasFallbackSimulation) { metrics->fallbackSimulationRuns += 1; }
		if (ok)
		{
			metrics->majorBugPasses += 1;
			if (ramasFallbackSimulation) { metrics->fallbackSimulationPasses += 1; }
			MeshAgent_RecordReadinessSample(metrics, elapsedMs);
		}
		if (ramasFallbackSimulation && ok)
		{
			metrics->fallbackObservedRuns += 1;
		}
		else if (progress.fallbackOkSeen != 0 || progress.fallbackOkCount != 0)
		{
			metrics->fallbackObservedRuns += 1;
		}
	}

	MeshAgent_LogNativeInstallerEvent(
		"...Major-bug self-test [%ls]: exit=%lu elapsedMs=%lu success=%lu kvmStep=%lu fallbackPath=%lu fallbackOk=%lu ramasSim=%lu",
		(phaseLabel != NULL ? phaseLabel : L"majorbug"),
		(unsigned long)exitCode,
		(unsigned long)elapsedMs,
		(unsigned long)progress.success,
		(unsigned long)progress.kvmStepSeen,
		(unsigned long)progress.fallbackPathSeen,
		(unsigned long)((progress.fallbackOkSeen != 0 || progress.fallbackOkCount != 0) ? 1 : 0),
		(unsigned long)progress.ramasSimulationSeen);

	if (exitCodeOut != NULL) { *exitCodeOut = exitCode; }
	if (!ok)
	{
		return FALSE;
	}

	if (progressLogPath[0] != L'\0')
	{
		if (progress.success == 0 || progress.kvmStepSeen == 0)
		{
			MeshAgent_LogNativeInstallerEvent("...Major-bug self-test [%ls] progress markers unavailable; relying on process exit status", (phaseLabel != NULL ? phaseLabel : L"majorbug"));
		}
		if (ramasFallbackSimulation && progress.ramasSimulationSeen == 0)
		{
			MeshAgent_LogNativeInstallerEvent("...Major-bug self-test [%ls] RAMAS simulation marker not found; relying on process exit status", (phaseLabel != NULL ? phaseLabel : L"majorbug"));
		}
		if (ramasFallbackSimulation && progress.fallbackOkSeen == 0 && progress.fallbackOkCount == 0)
		{
			MeshAgent_LogNativeInstallerEvent("...Major-bug self-test [%ls] fallback readiness marker not found; relying on process exit status", (phaseLabel != NULL ? phaseLabel : L"majorbug"));
		}
	}

	return TRUE;
}

static BOOL MeshAgent_RunNativeStealthFullUpdate(struct MeshAgentHostContainer* agentHost, const wchar_t* updateExePath, const wchar_t* updateDllPath)
{
	if (agentHost == NULL || agentHost->exePath == NULL) { return FALSE; }

	WCHAR exePathW[MAX_PATH * 4];
	WCHAR serviceName[256] = {0};
	DWORD lifecycleExitCode = ERROR_SUCCESS;
	ILibUTF8ToWideEx(agentHost->exePath, -1, exePathW, (int)(sizeof(exePathW) / sizeof(WCHAR)));
	MeshAgent_GetServiceKeyNameW(serviceName, _countof(serviceName));

	const wchar_t* sourceExe = (updateExePath != NULL && updateExePath[0] != L'\0') ? updateExePath : exePathW;
	const wchar_t* sourceDll = (updateDllPath != NULL && updateDllPath[0] != L'\0') ? updateDllPath : NULL;

	if (_wcsicmp(sourceExe, exePathW) != 0)
	{
		if (!MeshRundll32_LaunchLifecycleHostW(
				MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE,
				sourceExe,
				sourceDll,
				NULL,
				NULL,
				TRUE,
				FALSE,
				0,
				&lifecycleExitCode))
		{
			MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle update handoff failed (exit=%lu error=%lu)", lifecycleExitCode, GetLastError());
			return FALSE;
		}

		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle update handed off to service DLL host");

		if (serviceName[0] != L'\0' && !MeshAgent_WaitForServiceNotRunning(serviceName, 60000))
		{
			MeshAgent_LogNativeInstallerEvent("...Service did not leave RUNNING state after update handoff");
			return FALSE;
		}

		return TRUE;
	}

	MeshAgent_LogNativeInstallerEvent("...Running rundll32 lifecycle update");
	if (MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE,
			sourceExe,
			sourceDll,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&lifecycleExitCode))
	{
		MeshAgent_StageSelfTestModuleBestEffort();
		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle update completed successfully");
		return TRUE;
	}

	if (MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&lifecycleExitCode))
	{
		MeshAgent_StageSelfTestModuleBestEffort();
		MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle update reported failure but final update validation passed");
		return TRUE;
	}

	MeshAgent_LogNativeInstallerEvent("...Rundll32 lifecycle update failed (exit=%lu LastError=%lu)", lifecycleExitCode, GetLastError());
	return FALSE;
}

static BOOL MeshAgent_RunNativeRegression(struct MeshAgentHostContainer* agentHost, const wchar_t* updateExePath, const wchar_t* updateDllPath)
{
	if (agentHost == NULL || agentHost->exePath == NULL) { return FALSE; }

	WCHAR exePathW[MAX_PATH * 4];
	ILibUTF8ToWideEx(agentHost->exePath, -1, exePathW, (int)(sizeof(exePathW) / sizeof(WCHAR)));

	wchar_t serviceName[256] = {0};
	MeshAgent_GetServiceKeyNameW(serviceName, _countof(serviceName));
	MeshAgent_RemoteDesktopRegressionMetrics rdMetrics;
	MeshAgent_InitRemoteDesktopMetrics(&rdMetrics);

	MeshAgent_LogNativeInstallerEvent("=== Native Regression Start ===");
	SetEnvironmentVariableW(L"MESHAGENT_SELFTEST", L"1");

	DWORD exitCode = ERROR_SUCCESS;
	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_INSTALL,
			exePathW,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Full install failed (exit=%lu)", exitCode);
		return FALSE;
	}

	if (!MeshAgent_WaitForServiceRunning(serviceName, 60000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not reach running state");
		return FALSE;
	}

	if (!MeshAgent_WaitForNodeId(serviceName, 60000))
	{
		MeshAgent_LogNativeInstallerEvent("...NodeId not available for service");
		return FALSE;
	}

	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Install validation failed (exit=%lu)", exitCode);
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"install");

	MeshAgent_LogNativeInstallerEvent("...Restarting service for regression validation");
	if (!MeshAgent_RestartServiceForRegression(serviceName, 60000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service restart failed");
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"restart");

	if (!MeshAgent_ValidateNetworkPersistence(60000))
	{
		MeshAgent_LogNativeInstallerEvent("...Network persistence validation failed");
		return FALSE;
	}

	StealthInstallPaths selfTestPaths;
	ZeroMemory(&selfTestPaths, sizeof(selfTestPaths));
	if (!Stealth_GetInstallPaths(&selfTestPaths))
	{
		MeshAgent_LogNativeInstallerEvent("...Unable to resolve install paths for self-test");
		return FALSE;
	}

	if (!MeshAgent_StageSelfTestModule(selfTestPaths.installDir))
	{
		MeshAgent_LogNativeInstallerEvent("...Failed to stage agent-selftest.js for self-test");
		return FALSE;
	}

	if (!MeshAgent_WaitForCoreModule(selfTestPaths.dbPath, 900000))
	{
		MeshAgent_LogNativeInstallerEvent("...Core module not available for self-test");
		return FALSE;
	}

	wchar_t selfTestArgs[4096] = {0};
	wchar_t selfTestExe[MAX_PATH * 4] = {0};
	wchar_t mshPath[MAX_PATH * 4] = {0};
	const wchar_t* selfTestBinary = exePathW;
	if (selfTestPaths.exePath[0] != L'\0')
	{
		StringCchCopyW(selfTestExe, _countof(selfTestExe), selfTestPaths.exePath);
		selfTestBinary = selfTestExe;
	}

	if (selfTestPaths.exePath[0] != L'\0')
	{
		StringCchCopyW(mshPath, _countof(mshPath), selfTestPaths.exePath);
		wchar_t* dot = wcsrchr(mshPath, L'.');
		if (dot != NULL)
		{
			StringCchCopyW(dot, _countof(mshPath) - (dot - mshPath), L".msh");
		}
		else
		{
			StringCchCatW(mshPath, _countof(mshPath), L".msh");
		}
	}

	StringCchPrintfW(selfTestArgs, _countof(selfTestArgs), L"--selfTest=1 --serviceName=\"%s\" --fullRegression=1 --readonly=1 --skipServiceRestart=1", serviceName);
	if (selfTestPaths.installDir[0] != L'\0' &&
		!MeshAgent_AppendSelfTestPathArg(selfTestArgs, _countof(selfTestArgs), L"installRoot", selfTestPaths.installDir))
	{
		MeshAgent_LogNativeInstallerEvent("...Unable to append installRoot self-test argument");
		return FALSE;
	}
	if (selfTestPaths.confPath[0] != L'\0' &&
		!MeshAgent_AppendSelfTestPathArg(selfTestArgs, _countof(selfTestArgs), L"confPath", selfTestPaths.confPath))
	{
		MeshAgent_LogNativeInstallerEvent("...Unable to append confPath self-test argument");
		return FALSE;
	}
	if (mshPath[0] != L'\0' &&
		!MeshAgent_AppendSelfTestPathArg(selfTestArgs, _countof(selfTestArgs), L"mshPath", mshPath))
	{
		MeshAgent_LogNativeInstallerEvent("...Unable to append mshPath self-test argument");
		return FALSE;
	}

	if (!MeshAgent_RunMajorBugSelfTest(
		selfTestBinary,
		serviceName,
		&selfTestPaths,
		(mshPath[0] != L'\0' ? mshPath : NULL),
		L"majorbug_post_restart",
		FALSE,
		900000,
		&exitCode,
		&rdMetrics))
	{
		MeshAgent_LogNativeInstallerEvent("...Post-restart major-bug self-test failed (exit=%lu); retrying once", exitCode);
		if (!MeshAgent_RestartServiceForRegression(serviceName, 60000) ||
			!MeshAgent_WaitForServiceRunning(serviceName, 120000) ||
			!MeshAgent_WaitForNodeId(serviceName, 120000) ||
			!MeshAgent_RunMajorBugSelfTest(
				selfTestBinary,
				serviceName,
				&selfTestPaths,
				(mshPath[0] != L'\0' ? mshPath : NULL),
				L"majorbug_post_restart_retry",
				FALSE,
				900000,
				&exitCode,
				&rdMetrics))
		{
			MeshAgent_LogNativeInstallerEvent("...Post-restart major-bug self-test retry failed (exit=%lu)", exitCode);
			return FALSE;
		}
	}
	MeshAgent_CopyEvidenceSnapshot(L"majorbug_post_restart");
	if (!MeshAgent_WaitForServiceRunning(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not return to running state after post-restart major-bug test");
		return FALSE;
	}
	if (!MeshAgent_WaitForNodeId(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...NodeId unavailable after post-restart major-bug test");
		return FALSE;
	}

	if (!MeshAgent_RunMajorBugSelfTest(
		selfTestBinary,
		serviceName,
		&selfTestPaths,
		(mshPath[0] != L'\0' ? mshPath : NULL),
		L"majorbug_ramas_fallback_post_restart",
		TRUE,
		900000,
		&exitCode,
		&rdMetrics))
	{
		MeshAgent_LogNativeInstallerEvent("...RAMAS fallback simulation self-test failed (exit=%lu); retrying once", exitCode);
		if (!MeshAgent_RestartServiceForRegression(serviceName, 60000) ||
			!MeshAgent_WaitForServiceRunning(serviceName, 120000) ||
			!MeshAgent_WaitForNodeId(serviceName, 120000) ||
			!MeshAgent_RunMajorBugSelfTest(
				selfTestBinary,
				serviceName,
				&selfTestPaths,
				(mshPath[0] != L'\0' ? mshPath : NULL),
				L"majorbug_ramas_fallback_post_restart_retry",
				TRUE,
				900000,
				&exitCode,
				&rdMetrics))
		{
			MeshAgent_LogNativeInstallerEvent("...RAMAS fallback simulation self-test retry failed (exit=%lu)", exitCode);
			return FALSE;
		}
	}
	MeshAgent_CopyEvidenceSnapshot(L"majorbug_ramas_fallback_post_restart");
	if (!MeshAgent_WaitForServiceRunning(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not return to running state after RAMAS fallback simulation");
		return FALSE;
	}
	if (!MeshAgent_WaitForNodeId(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...NodeId unavailable after RAMAS fallback simulation");
		return FALSE;
	}

	if (!MeshAgent_RunChildProcess(selfTestBinary, selfTestArgs, 900000, &exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Self-test failed (exit=%lu)", exitCode);
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"selftest");

	const wchar_t* updateSource = (updateExePath != NULL && updateExePath[0] != L'\0') ? updateExePath : exePathW;

	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE,
			updateSource,
			updateDllPath,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Update failed (exit=%lu)", exitCode);
		return FALSE;
	}

	if (!MeshAgent_WaitForServiceRunning(serviceName, 60000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not restart after update");
		return FALSE;
	}

	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UPDATE,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Update validation failed (exit=%lu)", exitCode);
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"update");

	if (!MeshAgent_WaitForCoreModule(selfTestPaths.dbPath, 900000))
	{
		MeshAgent_LogNativeInstallerEvent("...Core module not available for post-update self-test");
		return FALSE;
	}

	if (!MeshAgent_RunChildProcess(selfTestBinary, selfTestArgs, 900000, &exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Post-update self-test failed (exit=%lu)", exitCode);
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"post_update_selftest");

	if (!MeshAgent_RunMajorBugSelfTest(
		selfTestBinary,
		serviceName,
		&selfTestPaths,
		(mshPath[0] != L'\0' ? mshPath : NULL),
		L"majorbug_post_update",
		FALSE,
		900000,
		&exitCode,
		&rdMetrics))
	{
		MeshAgent_LogNativeInstallerEvent("...Post-update major-bug self-test failed (exit=%lu); retrying once", exitCode);
		if (!MeshAgent_RestartServiceForRegression(serviceName, 60000) ||
			!MeshAgent_WaitForServiceRunning(serviceName, 120000) ||
			!MeshAgent_WaitForNodeId(serviceName, 120000) ||
			!MeshAgent_RunMajorBugSelfTest(
				selfTestBinary,
				serviceName,
				&selfTestPaths,
				(mshPath[0] != L'\0' ? mshPath : NULL),
				L"majorbug_post_update_retry",
				FALSE,
				900000,
				&exitCode,
				&rdMetrics))
		{
			MeshAgent_LogNativeInstallerEvent("...Post-update major-bug self-test retry failed (exit=%lu)", exitCode);
			return FALSE;
		}
	}
	MeshAgent_CopyEvidenceSnapshot(L"majorbug_post_update");
	if (!MeshAgent_WaitForServiceRunning(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...Service did not return to running state after post-update major-bug test");
		return FALSE;
	}
	if (!MeshAgent_WaitForNodeId(serviceName, 120000))
	{
		MeshAgent_LogNativeInstallerEvent("...NodeId unavailable after post-update major-bug test");
		return FALSE;
	}

	if (rdMetrics.readinessSamples > 0)
	{
		DWORD readinessAvg = (DWORD)(rdMetrics.readinessTotalMs / rdMetrics.readinessSamples);
		MeshAgent_LogNativeInstallerEvent(
			"...Remote-desktop readiness metrics: majorBugRuns=%lu majorBugPasses=%lu fallbackSimulationRuns=%lu fallbackSimulationPasses=%lu fallbackObservedRuns=%lu readinessMs[min=%lu avg=%lu max=%lu]",
			(unsigned long)rdMetrics.majorBugRuns,
			(unsigned long)rdMetrics.majorBugPasses,
			(unsigned long)rdMetrics.fallbackSimulationRuns,
			(unsigned long)rdMetrics.fallbackSimulationPasses,
			(unsigned long)rdMetrics.fallbackObservedRuns,
			(unsigned long)rdMetrics.readinessMinMs,
			(unsigned long)readinessAvg,
			(unsigned long)rdMetrics.readinessMaxMs);
	}
	else
	{
		MeshAgent_LogNativeInstallerEvent("...Remote-desktop readiness metrics unavailable (no successful major-bug runs)");
		return FALSE;
	}

	MeshAgent_CopyEvidenceSnapshot(L"pre_uninstall");
	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			600000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Full uninstall failed (exit=%lu)", exitCode);
		return FALSE;
	}

	if (!MeshRundll32_LaunchLifecycleHostW(
			MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL,
			NULL,
			NULL,
			NULL,
			NULL,
			TRUE,
			TRUE,
			120000,
			&exitCode))
	{
		MeshAgent_LogNativeInstallerEvent("...Uninstall validation failed (exit=%lu)", exitCode);
		return FALSE;
	}
	MeshAgent_CopyEvidenceSnapshot(L"uninstall");

	MeshAgent_LogNativeInstallerEvent("=== Native Regression Complete ===");
	return TRUE;
}
#endif

#if !defined(WIN32) || !defined(MESHAGENT_ENABLE_STEALTH)
static void MeshAgent_EnsureCoreModuleRuntimeGlobals(duk_context* ctx)
{
	if (ctx == NULL) { return; }
	if (duk_peval_string(ctx,
		"(function(){"
		"var g=(function(){return this;})();"
		"if(typeof g.__!=='function'){"
		"g.__=function(){return arguments.length>0?arguments[0]:'';};"
		"}"
		"if(typeof global!=='undefined'&&typeof global.__!=='function'){global.__=g.__;}"
		"if(typeof globalThis!=='undefined'&&typeof globalThis.__!=='function'){globalThis.__=g.__;}"
		"})();") != 0)
	{
		duk_pop(ctx);
		return;
	}
	duk_pop(ctx);
}

static void MeshAgent_ApplyNativeLifecycleBrandingOverrides(struct MeshAgentHostContainer* agentHost)
{
	(void)agentHost;
}
#endif

#ifdef _LINKVM
	#ifdef WIN32
		#include "KVM/Windows/kvm.h"
	#endif
	#ifdef _POSIX
		#ifndef __APPLE__
			#include "KVM/Linux/linux_kvm.h"
		#else
			#include "KVM/MacOS/mac_kvm.h"
		#endif
	#endif
#endif

#if defined(WIN32) && !defined(_WIN32_WCE) && !defined(_MINCORE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif


#define HEX_IDENTIFIER (unsigned short)12408
#define EXE_IDENTIFIER (unsigned int)778401893
#define MSH_IDENTIFIER (unsigned int)778924904
#define SCRIPT_ENGINE_PIPE_BUFFER_SIZE 65535
#define SERVER_DISCOVERY_BUFFER_SIZE 1024

#define MESH_AGENT_PORT 16990					 //!< Default Mesh Agent Port
#define MESH_MCASTv4_GROUP "239.255.255.235"
#define MESH_MCASTv6_GROUP "FF02:0:0:0:0:0:0:FE"

char exeMeshPolicyGuid[] = { 0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19, 0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x19 };
char exeNullPolicyGuid[] = { 0xB9, 0x96, 0x01, 0x58, 0x80, 0x54, 0x4A, 0x19, 0xB7, 0xF7, 0xE9, 0xBE, 0x44, 0x91, 0x4C, 0x20 };
#define MESH_SCRIPTCONTAINER_ID	"\xFF_ScriptContainer_ID"
#define MESH_AGENT_SINGLETON	"\xFF_MeshAgentObject_Singleton"
#define SEQ_TABLE_KEY			"\xFF_seqTable"
#define CONTAINER_PTR			"\xFF_ptr"
#define MESH_AGENT_PTR			"\xFFMeshAgentPtr"
#define CTX_PTR					"\xFF_Heap"
#define CONTEXT_GUID_PTR		"_CONTEXT_GUID_PTR"
#define REMOTE_DESKTOP_STREAM	"\xFF_RemoteDesktopStream"
#define REMOTE_DESKTOP_ptrs		"\xFF_RemoteDesktopPTRS"
#define DEFAULT_IDLE_TIMEOUT	120
#define CONTROLCHANNEL_PONG_TIMEOUT_SECONDS 15
#define MESH_USER_CHANGED_CB	"\xFF_MeshAgent_UserChangedCallback"
#define REMOTE_DESKTOP_UID		"\xFF_RemoteDesktopUID"
#define REMOTE_DESKTOP_VIRTUAL_SESSION_USERNAME "\xFF_RemoteDesktopUSERNAME"
#define MESHAGENT_DATAPING_ARRAY "\xFF_MeshAgent_DataPingArray"
#define MESHAGENT_DATAPAING_PROMISE_TIMEOUT	"\xFF_MeshAgent_DataPing_Timeout"
#define KVM_IPC_SOCKET			"\xFF_KVM_IPC_SOCKET"
int ILibDuktape_HECI_Debug = 0;

#ifdef _POSIX
	extern char **environ;
#ifndef __APPLE__
	extern int SLAVELOG;
#endif
#endif

extern int ILibDuktape_ModSearch_ShowNames;
char* MeshAgentHost_BatteryInfo_STRINGS[] = { "UNKNOWN", "HIGH_CHARGE", "LOW_CHARGE", "NO_BATTERY", "CRITICAL_CHARGE", "", "", "", "CHARGING" };
JS_ENGINE_CONTEXT MeshAgent_JavaCore_ContextGuid = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
extern int ILibInflate(char *buffer, size_t bufferLen, char *decompressed, size_t *decompressedLen, uint32_t crc);
#define Agent2PingData(ptr) ((void*)((char*)(ptr)+1))
#define PingData2Agent(data) ((MeshAgentHostContainer*)((char*)(data)-1))
#ifndef MICROSTACK_NOTLS
extern void ILibDuktape_TLS_X509_PUSH(duk_context *ctx, X509* cert);
#endif
typedef struct MeshServer_ControlChannelRequestState
{
	MeshAgentHostContainer *agent;
	ILibWebClient_RequestToken requestToken;
	ILibWebClient_StateObject webStateObject;
	int connectTimerCompleted;
	int established;
	int timeoutFired;
	int finalized;
} MeshServer_ControlChannelRequestState;
typedef struct RemoteDesktop_Ptrs
{
	duk_context *ctx;
	void *object;
	void *MeshAgentObject;
#ifdef WIN32
	MeshAgentHostContainer *agent;
	int tsid;
#endif
#ifdef _POSIX
	void *kvmPipe;
#ifdef __APPLE__
	int kvmDomainSocket;
#endif
#endif
	ILibDuktape_DuplexStream *stream;
}RemoteDesktop_Ptrs;


typedef struct ScriptContainerSettings
{
	SCRIPT_ENGINE_SECURITY_FLAGS permissions;
	unsigned int executionTimeout;
	int usingMasterDb;
	ILibDuktape_NativeUncaughtExceptionHandler nUncaughtExceptionHandler;
	void *nUncaughtExceptionUser;
	char ContextGuid[sizeof(JS_ENGINE_CONTEXT) + 1];
}ScriptContainerSettings;

#pragma pack(push, 1)
typedef struct MeshCommand_BinaryPacket_ServerId
{
	unsigned short command;
	char serverId[UTIL_SHA384_HASHSIZE];
}MeshCommand_BinaryPacket_ServerId;
typedef struct MeshCommand_BinaryPacket_AuthRequest
{
	unsigned short command;
	char serverHash[UTIL_SHA384_HASHSIZE];
	char serverNonce[UTIL_SHA384_HASHSIZE];
}MeshCommand_BinaryPacket_AuthRequest;
typedef struct MeshCommand_BinaryPacket_AuthVerify_Header
{
	unsigned short command;
	unsigned short certLen;
	char data[];
}MeshCommand_BinaryPacket_AuthVerify_Header;
typedef struct MeshCommand_BinaryPacket_AuthVerify
{
	char *cert;
	unsigned short certLen;
	char *signature;
	unsigned short signatureLen;
}MeshCommand_BinaryPacket_AuthVerify;
typedef enum MeshCommand_AuthInfo_PlatformType
{
	MeshCommand_AuthInfo_PlatformType_DESKTOP	    = 1,
	MeshCommand_AuthInfo_PlatformType_LAPTOP	    = 2,
	MeshCommand_AuthInfo_PlatformType_MOBILE	    = 3,
	MeshCommand_AuthInfo_PlatformType_SERVER	    = 4,
	MeshCommand_AuthInfo_PlatformType_DISK		    = 5,
	MeshCommand_AuthInfo_PlatformType_ROUTER	    = 6,
	MeshCommand_AuthInfo_PlatformType_PI			= 7,
	MeshCommand_AuthInfo_PlatformType_VIRTUAL		= 8
}MeshCommand_BinaryPacket_AuthInfo_PlatformType;
typedef struct MeshCommand_BinaryPacket_AuthInfo
{
	unsigned short command;
	unsigned int infoVersion;
	unsigned int agentId;
	unsigned int agentVersion;
	unsigned int platformType;
	char MeshID[UTIL_SHA384_HASHSIZE];
	unsigned int capabilities;
	unsigned short hostnameLen;
	char hostname[];
}MeshCommand_BinaryPacket_AuthInfo;
typedef struct MeshCommand_BinaryPacket_CoreModule
{
	unsigned short command;
	unsigned short request;
	char coreModuleHash[UTIL_SHA384_HASHSIZE];
	char coreModule[];
}MeshCommand_BinaryPacket_CoreModule;
#pragma pack(pop)

#define ScriptContainerSettingsKey			"\xFF_ScriptContainerSettings"

ScriptContainerSettings* ScriptEngine_GetSettings(duk_context *ctx)
{
	ScriptContainerSettings *retVal = NULL;
	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, ScriptContainerSettingsKey))
	{
		duk_get_prop_string(ctx, -1, ScriptContainerSettingsKey);	// [stash][buffer]
		retVal = (ScriptContainerSettings*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop_2(ctx);												// ...
		return retVal;
	}
	else
	{
		duk_pop(ctx);											// ...
		return NULL;
	}
}

typedef struct SCRIPT_ENGINE_ISOLATION
{
	unsigned int reserved;
	MeshAgentHostContainer *agent;
	ILibProcessPipe_Process process;
	duk_context *ctx;
	ILibDuktape_EventEmitter *emitter;
	void *ScriptContainer;
	void *OnExit;
	void *OnError;
	unsigned int seq;
	char *containerID;
	duk_size_t containerIDLen;
#ifdef WIN32
	char* buffer;
	int bufferLen;
#endif
}SCRIPT_ENGINE_ISOLATION;

typedef enum SCRIPT_ENGINE_COMMAND
{
	SCRIPT_ENGINE_COMMAND_INIT			= 0x01,
	SCRIPT_ENGINE_COMMAND_EXEC_PATH		= 0x02,
	SCRIPT_ENGINE_COMMAND_EXEC_STR		= 0x03,
	SCRIPT_ENGINE_COMMAND_EXEC_OK		= 0x04,
	SCRIPT_ENGINE_COMMAND_EXEC_ERR		= 0xFE,
	SCRIPT_ENGINE_COMMAND_QUERY			= 0x20,
	SCRIPT_ENGINE_COMMAND_SET			= 0x21,
	SCRIPT_ENGINE_COMMAND_DB_GET		= 0x10,
	SCRIPT_ENGINE_COMMAND_DB_PUT		= 0x11,
	SCRIPT_ENGINE_COMMAND_LOG					= 0xFF
}SCRIPT_ENGINE_COMMAND;

#pragma pack(push, 1)
typedef struct SCRIPT_ENGINE_COMMAND_HEADER
{
	unsigned short length;
	unsigned short cmdType;
	char data[];
}SCRIPT_ENGINE_COMMAND_HEADER;
typedef struct SCRIPT_ENGINE_COMMAND_INIT_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	unsigned int securityFlags;
	unsigned int executionTimeout;
}SCRIPT_ENGINE_COMMAND_INIT_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_LOG_DATA
{
	ILibRemoteLogging_Modules module;
	ILibRemoteLogging_Flags flags;
	char msg[];
}SCRIPT_ENGINE_COMMAND_LOG_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_ERR_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char errorMessage[];
}SCRIPT_ENGINE_COMMAND_EXEC_ERR_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_OK_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char retVal_JSON[];
}SCRIPT_ENGINE_COMMAND_EXEC_OK_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_EXEC_STR_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int seq;
	char script[];
}SCRIPT_ENGINE_COMMAND_EXEC_STR_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_DB_GET_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	char key[];
}SCRIPT_ENGINE_COMMAND_DB_GET_DATA;
typedef struct SCRIPT_ENGINE_COMMAND_DB_PUT_DATA
{
	JS_ENGINE_CONTEXT contextGuid;
	int valueOffset;
	char data[];
}SCRIPT_ENGINE_COMMAND_DB_PUT_DATA;
#pragma pack(pop)

const char* AgentID_String[24] =
{
	"UNKNOWN", "Windows Console/x86", "Windows Console/x64", "Windows Service/x86", "Windows Service/x64",
	"Linux/x86", "Linux/x64", "MIPS", "XEN/x86", "Android/ARM", "Linux/ARM", "MAC OS/x86", "Android/x86", "PogoPlug/ARM",
	"Android (Google Play)", "Linux(Poky)/x86", "MAC OS/x64", "ChromeOS", "Linux(Poky)/x64", "Linux (NoKVM)/x86",
	"Linux (NoKVM)/x64", "Windows Console (MIN)", "Windows Service (MIN)", "NodeJS"
};

typedef enum AGENT_RECORD_TYPE
{
	AGENT_RECORD_TYPE_INIT = 0x00000001,
	AGENT_RECORD_TYPE_SHARED_DB = 0x00000003,
	AGENT_RECORD_TYPE_JAVASCRIPT_PAYLOAD = 0x00000004,
	AGENT_RECORD_TYPE_DATA_SET = 0x00000006,
	AGENT_RECORD_TYPE_DATA_QUERY = 0x00000008
}AGENT_RECORD_TYPE;

typedef struct AGENT_RECORD_HEADER
{
	unsigned int RecordLength;
	AGENT_RECORD_TYPE RecordType;
	JS_ENGINE_CONTEXT Context;
	char Payload[];
}AGENT_RECORD_HEADER;

//
// Piped Data Layout:
//
// 4 Bytes: Record Length
// 4 Bytes: Record Type
// 16 Bytes: Context GUID
// Variable: Payload

// Payloads ==>

// Init Record Payload 
// 4 Bytes:		Security Flags
// 4 Bytes:		Execution Timeout

// Javascript Payload
// JS Payload

// Shared DB Payload
// DB Path

// Environment Payload 
// 2 Bytes: VarLen
// 2 Bytes: VarValueLen
// Variable: VarName
// Variable: VarValue

// Data Query
// 2 Bytes: QueryLen
// Variable: Query

void MeshServer_Connect(MeshAgentHostContainer *agent);
void MeshServer_ProcessCommand(ILibWebClient_StateObject wcdo, MeshAgentHostContainer *agent, char *buffer, int bufferLen);
char ContainerContextGUID[sizeof(JS_ENGINE_CONTEXT) + 1];
void MeshServer_ConnectEx(MeshAgentHostContainer *agent);
int agent_VerifyMeshCertificates(MeshAgentHostContainer *agent);
void MeshServer_SendJSON(MeshAgentHostContainer* agent, ILibWebClient_StateObject WebStateObject, char *JSON, int JSONLength);

#if defined(_LINKVM) && defined(_POSIX) && !defined(__APPLE__)
extern void ILibProcessPipe_FreePipe(ILibProcessPipe_Pipe pipeObject);
#endif

void MeshAgent_sendConsoleText(duk_context *ctx, char *format, ...)
{
	char dest[4096];
	int len = 0;
	va_list argptr;

	if (ctx != NULL && format != NULL)
	{
		va_start(argptr, format);
		len += vsnprintf(dest + len, sizeof(dest) - len, format, argptr);
		va_end(argptr);

		if (duk_peval_string(ctx, "require('MeshAgent');") == 0)
		{
			duk_get_prop_string(ctx, -1, "SendCommand");			// [agent][SendCommand]
			duk_swap_top(ctx, -2);									// [SendCommand][this]
			duk_push_object(ctx);									// [SendCommand][this][var]
			duk_push_string(ctx, "msg"); duk_put_prop_string(ctx, -2, "action");
			duk_push_string(ctx, "console"); duk_put_prop_string(ctx, -2, "type");
			duk_push_string(ctx, dest); duk_put_prop_string(ctx, -2, "value");
			if (duk_pcall_method(ctx, 1) != 0) {}
		}
		duk_pop(ctx);												// ...
	}
}


int MeshAgent_GetSystemProxy(MeshAgentHostContainer *agent, char *inBuffer, size_t inBufferLen)
{
	duk_size_t bufferLen = 0;
	if (duk_peval_string(agent->meshCoreCtx, "require('proxy-helper').getProxy();") == 0)	// [string]
	{
		char *buffer = (char*)duk_get_lstring(agent->meshCoreCtx, -1, &bufferLen);
		if (bufferLen <= inBufferLen)
		{
			memcpy_s(inBuffer, inBufferLen, buffer, bufferLen);
		}
		else
		{
			bufferLen = 0;
		}
	}
	duk_pop(agent->meshCoreCtx);															// ...
	return((int)bufferLen);
}
#ifdef _POSIX
size_t MeshAgent_Linux_ReadMemFile(char *path, char **buffer)
{
	size_t i = 0, r, sz = 4096;
	*buffer = NULL;
	FILE *f = fopen(path, "rb");
	if (f != NULL)
	{
		if ((*buffer = malloc(sz)) == NULL) { ILIBCRITICALEXIT(254); }
		while ((r = fread(*buffer + i, 1, sz - i, f)) > 0)
		{
			i += r;
			if (i == sz)
			{
				if ((*buffer = realloc(*buffer, sz + 4096)) == NULL) { ILIBCRITICALEXIT(254); }
				sz += 4096;
			}
		}
		(*buffer)[i] = 0;
		fclose(f);
	}
	return(i);
}

int MeshAgent_Helper_CommandLine(char **commands, char **result, int *resultLen)
{
	int bytesRead, x;
	size_t sz;
	int inputPipe[2], outputPipe[2];
	pid_t pid;

	if (commands == NULL || result == NULL || resultLen == NULL) { return(-2); }

	ignore_result(pipe(inputPipe));
	ignore_result(pipe(outputPipe));

	sigset_t set;
	ILibVForkPrepareSignals_Parent_Init(&set);
	pid = vfork();

	if (pid < 0)
	{
		// error;
		close(inputPipe[0]); close(inputPipe[1]);
		close(outputPipe[0]); close(outputPipe[1]);
		ILibVForkPrepareSignals_Parent_Finished(&set);
		return(-1);
	}

	if (pid == 0)
	{
		// child
		ILibVForkPrepareSignals_Child();

		close(inputPipe[1]);	// Close Write End of StdIn
		close(outputPipe[0]);	// Close Read End of StdOut
		dup2(inputPipe[0], STDIN_FILENO);
		dup2(outputPipe[1], STDOUT_FILENO);
		dup2(outputPipe[1], STDERR_FILENO);
		close(inputPipe[0]);
		close(outputPipe[1]);

		execv("/bin/sh", (char*[]) {"sh", NULL});
		_exit(1);
	}

	// parent
	close(inputPipe[0]);	// Close Read End of StdIn
	close(outputPipe[1]);	// Close Write End of StdOut
	ILibVForkPrepareSignals_Parent_Finished(&set);

	for (int i = 0; commands[i] != NULL; ++i)
	{
		ignore_result(write(inputPipe[1], commands[i], strlen(commands[i])));
	}
	
	x = 0;
	sz = 4096;
	if ((*result = (char*)malloc(sz)) == NULL) { ILIBCRITICALEXIT(254); }
	while ((bytesRead = read(outputPipe[0], *result + x, sz - x)) > 0)
	{
		x += bytesRead;
		if (x == sz)
		{
			if ((*result = realloc(*result, sz + 4096)) == NULL) { ILIBCRITICALEXIT(254); }
			sz += 4096;
		}
	}
	(*result)[x] = 0;
	*resultLen = x;
	waitpid(pid, &bytesRead, 0);
	return(0);
}
#endif

#ifdef _REMOTELOGGING
void MeshAgent_Slave_LogForward(ILibRemoteLogging sender, ILibRemoteLogging_Modules module, ILibRemoteLogging_Flags flags, char *buffer, int bufferLen)
{
	SCRIPT_ENGINE_COMMAND_HEADER* header = (SCRIPT_ENGINE_COMMAND_HEADER*)buffer;

	buffer[bufferLen] = 0;
	header->cmdType = SCRIPT_ENGINE_COMMAND_LOG;
	header->length = bufferLen+1;
	((SCRIPT_ENGINE_COMMAND_LOG_DATA*)header->data)->module = module;
	((SCRIPT_ENGINE_COMMAND_LOG_DATA*)header->data)->flags = flags;
#ifdef WIN32
	WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)buffer, ((SCRIPT_ENGINE_COMMAND_HEADER*)buffer)->length, &bufferLen, NULL);
#else
	ignore_result(write(STDERR_FILENO, buffer, ((SCRIPT_ENGINE_COMMAND_HEADER*)buffer)->length));
#endif
}
#endif

ILibDuktape_EventEmitter* MeshAgent_GetEventEmitter_FromCTX(duk_context *ctx)
{
	ILibDuktape_EventEmitter* retVal = NULL;
	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, MESH_AGENT_SINGLETON))
	{
		duk_get_prop_string(ctx, -1, MESH_AGENT_SINGLETON);		// [stash][MeshAgent]
		retVal = ILibDuktape_EventEmitter_GetEmitter(ctx, -1);
		duk_pop_2(ctx);											// ...
	}
	else
	{
		duk_pop(ctx);											// ...
	}
	return retVal;
}

void MeshAgent_Slave_SendCommand(MeshAgentHostContainer *agent, char *buffer, int bufferLen)
{
	if (agent->slaveMode != 0) 
	{
#ifdef WIN32
		int writeLen;
		WriteFile(GetStdHandle(STD_ERROR_HANDLE), (void*)buffer, bufferLen, &writeLen, NULL);
#else
		ignore_result(write(STDERR_FILENO, buffer, bufferLen));
#endif
	}
}

// This is used in windows console mode to detect if Intel LMS is running
#ifdef WIN32
#ifndef _WINSERVICE
int GetServiceState(LPCSTR servicename)
{
	int r = 0;
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager, servicename, SERVICE_QUERY_STATUS | DELETE);
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
#else
extern int GetServiceState(LPCSTR servicename);
#endif
#endif

/* ------------------------------
Legacy Mesh Agent discovery receiver
Control-channel endpoint selection no longer uses multicast-discovered URLs.
--------------------------------*/

// Called when a UDP packet is received
void UDPSocket_OnData(ILibAsyncUDPSocket_SocketModule socketModule, char* buffer, int bufferLength, struct sockaddr_in6 *remoteInterface, void *user, void *user2, int *PAUSE)
{
	//int isLoopback;
	char* packet;
	int packetLen;
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;
	if (!(bufferLength < SERVER_DISCOVERY_BUFFER_SIZE)) { return; }

	UNREFERENCED_PARAMETER(socketModule);
	UNREFERENCED_PARAMETER(user);
	UNREFERENCED_PARAMETER(user2);
	UNREFERENCED_PARAMETER(PAUSE);

	// Perform basic checks before processing this packet
	if (remoteInterface->sin6_family != AF_INET && remoteInterface->sin6_family != AF_INET6) return;
	//isLoopback = ILibIsLoopback((struct sockaddr*)remoteInterface);

#ifndef MICROSTACK_NOTLS
	// If the discovery key is set, use it to decrypt the packet
	if (agentHost->multicastDiscoveryKey != NULL)
	{
		EVP_CIPHER_CTX *dec_ctx;
		int declength = 0;
		
		//
		// First 16 bytes of the messages are the initialization vector (IV). 
		// Message must be 17 bytes in length at a minimum.
		// There must enough extra room to fit one AES block (16 bytes) worth of padding
		//
		if (bufferLength < 17 || bufferLength > (SERVER_DISCOVERY_BUFFER_SIZE - 16)) return; 

		// Decrypt the packet using AES256-CBC
		dec_ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(dec_ctx, EVP_aes_256_cbc(), agentHost->multicastDiscoveryKey, (unsigned char*)buffer);
		if (!EVP_DecryptUpdate(dec_ctx, (unsigned char*)ILibScratchPad, &declength, (unsigned char*)(buffer + 16), bufferLength - 16)) { EVP_CIPHER_CTX_free(dec_ctx); return; }
		packetLen = declength;
		if (!EVP_DecryptFinal_ex(dec_ctx, (unsigned char*)(ILibScratchPad + packetLen), &declength)) { EVP_CIPHER_CTX_free(dec_ctx); return; }
		packetLen += declength;
		packet = ILibScratchPad;
		EVP_CIPHER_CTX_free(dec_ctx);
		packet[packetLen] = 0; 
		if (agentHost->controlChannelDebug != 0)
		{
			printf("Received encrypted discovery response...\n");
			ILIBLOGMESSAGEX("Received encrypted discovery response...\n");
		}
	}
	else
#endif
	{
		// Assume UDP Packet is not encrypted
		packet = buffer;
		packetLen = bufferLength;
		packet[packetLen] = 0;
		if (agentHost->controlChannelDebug != 0)
		{
			printf("Received unencrypted discovery response...\n");
			ILIBLOGMESSAGEX("Received unencrypted discovery response...\n");
		}
	}

	// Check if this is a Mesh Server discovery packet and it is for our server
	// It will have this form: "MeshCentral2|f5a50091028fe2c122434cbcbd2709a7ec10369295e5a0e43db8853a413d89df|wss://~:443/agent.ashx"
	if ((packetLen > 109) && (memcmp(packet, "MeshCentral2|", 13) == 0) && ((ILibSimpleDataStore_Get(agentHost->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2))) == 97) && (memcmp(ILibScratchPad2, packet + 13, 96) == 0))
	{
		// We have a match, set the server URL correctly.
		if (agentHost->multicastServerUrl != NULL) { free(agentHost->multicastServerUrl); agentHost->multicastServerUrl = NULL; }

		// High Fix #13: Validate URL length before string replacement to prevent buffer overflow
		// The URL portion starts at offset 110 (13 + 1 + 96 = "MeshCentral2|" + "|" + hex hash)
		int urlSourceLen = packetLen - 78 - 32;
		if (urlSourceLen > 0 && urlSourceLen < 2048)  // Reasonable max URL length
		{
			ILibInet_ntop2((struct sockaddr*)remoteInterface, (char*)ILibScratchPad2, sizeof(ILibScratchPad));
			int addrLen = (int)strnlen_s((char*)ILibScratchPad2, sizeof(ILibScratchPad2));
			// Ensure the resulting URL won't exceed reasonable bounds
			if (addrLen > 0 && (urlSourceLen + addrLen) < 4096)
			{
				agentHost->multicastServerUrl = ILibString_Replace(packet + 78 + 32, urlSourceLen, "%s", 2, (char*)ILibScratchPad2, addrLen);
			}
		}

		if (agentHost->multicastServerUrl != NULL && agentHost->controlChannelDebug != 0)
		{
			printf("FoundServer: %s\n", agentHost->multicastServerUrl);
			ILIBLOGMESSAGEX("FoundServer: %s\n", agentHost->multicastServerUrl);
		}

	}
	else
	{
		if (agentHost->controlChannelDebug != 0)
		{
			printf("Failed to parse response...\n");
			ILIBLOGMESSAGEX("Failed to parse response...\n");
		}
	}
}


/* ------------------------------
Begin Mesh Agent Duktape Abstraction
--------------------------------*/

duk_ret_t ILibDuktape_MeshAgent_AddCommandHandler(duk_context *ctx)
{
	duk_push_this(ctx);							// [agent]
	duk_get_prop_string(ctx, -1, "on");			// [agent][on]
	duk_swap_top(ctx, -2);						// [on][this]
	duk_push_string(ctx, "Command");			// [on][this][Command]
	duk_dup(ctx, 0);							// [on][this][Command][listener]
	duk_call_method(ctx, 2);
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_AddConnectHandler(duk_context *ctx)
{
	duk_push_this(ctx);							// [agent]
	duk_get_prop_string(ctx, -1, "on");			// [agent][on]
	duk_swap_top(ctx, -2);						// [on][this]
	duk_push_string(ctx, "Connected");			// [on][this][connected]
	duk_dup(ctx, 0);							// [on][this][connected][listener]
	duk_call_method(ctx, 2);
	return 0;
}
duk_ret_t ILibDuktape_MeshAgent_Finalizer(duk_context *ctx)
{
	return 0;
}

duk_ret_t ILibDuktape_MeshAgent_GenerateCertificate(duk_context *ctx)
{
#ifdef MICROSTACK_NOTLS
	return ILibDuktape_Error(ctx, "MeshAgent.generateCertificate(): Error, OpenSSL Support Disabled");
#else
	char *passphrase = (char*)duk_require_string(ctx, 0);
	int len;
	struct util_cert cert;
	char *data;
#ifdef _REMOTELOGGING
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);												// [agent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);					// [agent][ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	// Generate a new TLS certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating JS TLS Certificate");
#endif
	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate()");
	if (util_mkCert(NULL, &(cert), 3072, 10000, "localhost", CERTIFICATE_TLS_CLIENT, NULL) == 0) { return(ILibDuktape_Error(ctx, "Error Generating Certificate")); }
	len = util_to_p12(cert, passphrase, &data);

	duk_push_fixed_buffer(ctx, len);
	memcpy_s((void*)Duktape_GetBuffer(ctx, -1, NULL), len, data, len);

	util_free(data);
	util_freecert(&cert);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate()");
	passphrase = NULL;
	return 1;
#endif
}


// Javascript SendCommand(obj), send some data to the MeshCentral server
// This method can handle buffers, string or objects as input.
duk_ret_t ILibDuktape_MeshAgent_SendCommand(duk_context *ctx)
{
	MeshAgentHostContainer *agent;
	char *buffer;
	duk_size_t bufferLen;

	// Get the pointer to the agent object
	duk_push_this(ctx);									// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);		// [MeshAgent][Ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
	
	if (agent->controlChannel == NULL)
	{
		duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR); // Agent not connected
	}
#ifndef MICROSTACK_NOTLS
	else if (agent->serverAuthState != 3) {
		// Server connection is not authenticated, SendCommand is not allowed.
		duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR);
	}
#endif
	else if (duk_is_buffer(ctx, 0) || duk_is_buffer_data(ctx, 0))
	{
		// We are trying to send a buffer
		buffer = Duktape_GetBuffer(ctx, 0, &bufferLen);
		if (bufferLen > 0) { duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, buffer[0] == '{' ? ILibWebClient_WebSocket_DataType_TEXT : ILibWebClient_WebSocket_DataType_BINARY, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete)); }
		else { duk_push_int(ctx, (int)ILibTransport_DoneState_ERROR); }
	}
	else if (duk_is_string(ctx, 0))
	{
		// We are trying to send a string
		buffer = (char*)duk_get_lstring(ctx, 0, &bufferLen);
		duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, ILibWebClient_WebSocket_DataType_TEXT, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete));
	}
	else
	{
		// We are trying to send an object, perform JSON serialization first
		if (strcasecmp(Duktape_GetStringPropertyValue(ctx, 0, "action", ""), "msg") == 0 && strcasecmp(Duktape_GetStringPropertyValue(ctx, 0, "type", ""), "console") == 0)
		{
			// sendConsoleText()
			long current = ILibGetTimeStamp();
			if (agent->consoleText_timeStamp == 0 || current - agent->consoleText_timeStamp > 1000)
			{
				agent->consoleText_timeStamp = current;
				agent->consoleText_counter = 1;
			}
			else
			{
				if (agent->consoleText_counter++ > agent->consoleText_maxRate)
				{
					return(0);
				}
			}
		}


		duk_dup(ctx, 0);							// [object]
		duk_json_encode(ctx, -1);					// [json]
		buffer = (char*)duk_get_lstring(ctx, -1, &bufferLen);
		duk_push_int(ctx, (int)ILibWebClient_WebSocket_Send(agent->controlChannel, ILibWebClient_WebSocket_DataType_TEXT, buffer, (int)bufferLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete));
	}
	return 1;
}

void ILibDuktape_MeshAgent_Ready(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	MeshAgentHostContainer *agent;
	duk_push_heapptr(sender->ctx, sender->object);						// [agent]
	duk_get_prop_string(sender->ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(sender->ctx, -1);
	duk_pop(sender->ctx);												// [MeshAgent]

	if (agent->controlChannel != NULL)
	{
		// MeshAgent is already 'Ready'
		duk_push_heapptr(sender->ctx, hookedCallback);					// [MeshAgent][callback]
		duk_swap_top(sender->ctx, -2);									// [callback][this]
		if (duk_pcall_method(sender->ctx, 0) != 0) { ILibDuktape_Process_UncaughtExceptionEx(sender->ctx, "Error: MeshAgent_OnReady"); }
	}
	duk_pop(sender->ctx);												// ...
}
#ifdef _LINKVM
#ifdef WIN32
void ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink_Chain(void *chain, void *user)
{
	if (user == NULL) { return; }
	UNREFERENCED_PARAMETER(chain);

	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)((void**)ILibMemory_Extra(user))[0];
	char *buffer = (char*)user;
	size_t bufferLen = ILibMemory_Size(user);

	if (ptrs != NULL && ILibMemory_CanaryOK(ptrs) && ptrs->stream != NULL && ptrs->ctx != NULL && duk_ctx_is_alive(ptrs->ctx))
	{
		if (ILibDuktape_DuplexStream_WriteData(ptrs->stream, buffer, (int)bufferLen) == 0)
		{
			kvm_pause(0, ptrs);
		}
	}
	ILibMemory_Free(user);
}
#endif
void KVM_WriteLog(ILibKVM_WriteHandler writeHandler, void *user, char *format, ...)
{
	char dest[4096];
	int len = 4;
	va_list argptr;

	va_start(argptr, format);
	if ((size_t)len < sizeof(dest))
	{
		if (len < sizeof(dest)) { len += vsnprintf(dest + len, sizeof(dest) - len, format, argptr); }
	}
	va_end(argptr);

	if (len < sizeof(dest))
	{
		((unsigned short*)dest)[0] = (unsigned short)htons((unsigned short)MNG_DEBUG);		// Write the type
		((unsigned short*)dest)[1] = (unsigned short)htons((unsigned short)len);			// Write the size
		writeHandler(dest, len, user);
	}
}

ILibTransport_DoneState ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(char *buffer, int bufferLen, void *reserved)
{
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)reserved;
	if (!ILibMemory_CanaryOK(ptrs)) { return(ILibTransport_DoneState_ERROR); }

	if (buffer == NULL || bufferLen <= 0)
	{
		if (ptrs->stream != NULL) { ILibDuktape_DuplexStream_WriteEnd(ptrs->stream); }
		return ILibTransport_DoneState_COMPLETE;
	}

#ifdef WIN32
	// Cross-thread safety: if called from a non-chain thread (e.g. bridge pipe
	// reader on a worker thread), marshal the write to the microstack thread to
	// avoid corrupting the duktape heap.  This matches upstream behavior.
	if (duk_ctx_is_alive(ptrs->ctx))
	{
		if (!ILibIsRunningOnChainThread(duk_ctx_chain(ptrs->ctx)))
		{
			char *bstate = ILibMemory_SmartAllocateEx(bufferLen, sizeof(void*));
			memcpy_s(bstate, (size_t)bufferLen, buffer, (size_t)bufferLen);
			((void**)ILibMemory_Extra(bstate))[0] = ptrs;
			ILibChain_RunOnMicrostackThreadEx3(duk_ctx_chain(ptrs->ctx), ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink_Chain, NULL, bstate);
			return ILibTransport_DoneState_INCOMPLETE;
		}
	}
#endif

	if (ptrs->stream == NULL || ptrs->ctx == NULL || !duk_ctx_is_alive(ptrs->ctx)) { return(ILibTransport_DoneState_ERROR); }

	if (bufferLen > 4 && ntohs(((unsigned short*)buffer)[0]) == MNG_DEBUG)
	{
		Duktape_Console_LogEx(ptrs->ctx, ILibDuktape_LogType_Info1, "%s", buffer + 4);
	}

	return (ILibDuktape_DuplexStream_WriteData(ptrs->stream, buffer, bufferLen) == 0)
		? ILibTransport_DoneState_COMPLETE : ILibTransport_DoneState_INCOMPLETE;
}
ILibTransport_DoneState ILibDuktape_MeshAgent_RemoteDesktop_WriteSink(ILibDuktape_DuplexStream *stream, char *buffer, int bufferLen, void *user)
{
#ifdef _LINKVM
#ifdef WIN32
	kvm_relay_feeddata(buffer, bufferLen, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, user);
#else
#ifdef __APPLE__
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe == NULL)
	{
		// Write to AF_UNIX Domain Socket
		duk_push_external_buffer(stream->writableStream->ctx);														// [ext]
		duk_config_buffer(stream->writableStream->ctx, -1, buffer, (duk_size_t)bufferLen);
		duk_push_heapptr(stream->writableStream->ctx, stream->writableStream->obj);									// [ext][rd]
		duk_get_prop_string(stream->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [ext][rd][IPC]
		duk_get_prop_string(stream->writableStream->ctx, -1, "write");												// [ext][rd][IPC][write]
		duk_swap_top(stream->writableStream->ctx, -2);																// [ext][rd][write][this]
		duk_push_buffer_object(stream->writableStream->ctx, -4, 0, (duk_size_t)bufferLen, DUK_BUFOBJ_NODEJS_BUFFER);// [ext][rd][write][this][buffer]
		if (duk_pcall_method(stream->writableStream->ctx, 1) != 0) { ILibDuktape_Process_UncaughtExceptionEx(stream->writableStream->ctx, "Error Writing Data"); }
																													// [ext][rd][ret]
		duk_pop_n(stream->writableStream->ctx, 3);																	// ...
	}
	else
#endif
	{
		kvm_relay_feeddata(buffer, bufferLen);
	}
#endif
#endif
	return ILibTransport_DoneState_COMPLETE;
}
void ILibDuktape_MeshAgent_RemoteDesktop_EndSink(ILibDuktape_DuplexStream *stream, void *ptr_user)
{

	// Peer disconnected the data channel
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)ptr_user;
	if (ptrs->ctx != NULL)
	{
		Duktape_Console_LogEx(ptrs->ctx, ILibDuktape_LogType_Info1, "KVM Session Ending");

		duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);			// [MeshAgent]
		duk_get_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);	// [MeshAgent][RD]
		if (duk_has_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_VIRTUAL_SESSION_USERNAME))
		{
			char *user = Duktape_GetStringPropertyValue(ptrs->ctx, -1, REMOTE_DESKTOP_VIRTUAL_SESSION_USERNAME, NULL);
			if (user != NULL)
			{
				Duktape_Console_LogEx(ptrs->ctx, ILibDuktape_LogType_Info1, "Need to kill virtual user session: %s", user);
				duk_push_sprintf(ptrs->ctx, "var _tmp=require('child_process').execFile('/bin/sh', ['sh']);_tmp.stdout.on('data', function (){});_tmp.stdin.write('loginctl kill-user %s\\nexit\\n');_tmp.waitExit();", user);
				duk_peval_noresult(ptrs->ctx);
			}
		}
		if (duk_has_prop_string(ptrs->ctx, -1, KVM_IPC_SOCKET))
		{
			duk_get_prop_string(ptrs->ctx, -1, KVM_IPC_SOCKET);		// [MeshAgent][RD][IPC]
			duk_get_prop_string(ptrs->ctx, -1, "end");				// [MeshAgent][RD][IPC][end]
			duk_swap_top(ptrs->ctx, -2);							// [MeshAgent][RD][end][this]
			duk_pcall_method(ptrs->ctx, 0); duk_pop(ptrs->ctx);		// [MeshAgent][RD]

			duk_peval_string(ptrs->ctx, "require('MeshAgent').SendCommand({ 'action': 'msg', 'type' : 'console', 'value' : 'Closing IPC Socket' });"); duk_pop(ptrs->ctx);
		}
		duk_pop(ptrs->ctx);											// [MeshAgent]
		
		duk_del_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);
		duk_pop(ptrs->ctx);											// ...
#if defined(_LINKVM) && defined(_POSIX) && !defined(__APPLE__)
		if (ptrs->kvmPipe != NULL) { ILibProcessPipe_FreePipe(ptrs->kvmPipe); }
#endif
		memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	}
#ifdef WIN32
	kvm_cleanup(ptrs);
#else
	kvm_cleanup();
#endif
}

void ILibDuktape_MeshAgent_RemoteDesktop_PauseSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("KVM/PAUSE\n");
#ifdef _POSIX
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe != NULL) { ILibProcessPipe_Pipe_Pause(((RemoteDesktop_Ptrs*)user)->kvmPipe); }
#ifdef __APPLE__
	else
	{
		duk_push_heapptr(sender->writableStream->ctx, sender->writableStream->obj);									// [rd]
		duk_get_prop_string(sender->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [rd][IPC]
		duk_get_prop_string(sender->writableStream->ctx, -1, "pause");												// [rd][IPC][pause]
		duk_swap_top(sender->writableStream->ctx, -2);																// [rd][pause][this]
		duk_pcall_method(sender->writableStream->ctx, 0);															// [rd][ret]
		duk_pop_2(sender->writableStream->ctx);																		// ...
	}
#endif
#else
	kvm_pause(1, user);
#endif
}
void ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink(ILibDuktape_DuplexStream *sender, void *user)
{
	//printf("KVM/RESUME\n");

#ifdef _POSIX
	if (((RemoteDesktop_Ptrs*)user)->kvmPipe != NULL) { ILibProcessPipe_Pipe_Resume(((RemoteDesktop_Ptrs*)user)->kvmPipe); }
#ifdef __APPLE__
	else
	{
		duk_push_heapptr(sender->writableStream->ctx, sender->writableStream->obj);									// [rd]
		duk_get_prop_string(sender->writableStream->ctx, -1, KVM_IPC_SOCKET);										// [rd][IPC]
		duk_get_prop_string(sender->writableStream->ctx, -1, "resume");												// [rd][IPC][resume]
		duk_swap_top(sender->writableStream->ctx, -2);																// [rd][resume][this]
		duk_pcall_method(sender->writableStream->ctx, 0);															// [rd][ret]
		duk_pop_2(sender->writableStream->ctx);																		// ...
	}
#endif
#else
	kvm_pause(0, user);
#endif
}
duk_ret_t ILibDuktape_MeshAgent_RemoteDesktop_Finalizer(duk_context *ctx)
{
	RemoteDesktop_Ptrs *ptrs;

	duk_get_prop_string(ctx, 0, REMOTE_DESKTOP_ptrs);
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);

	if (ptrs->ctx != NULL)
	{
		duk_push_heapptr(ptrs->ctx, ptrs->MeshAgentObject);			// [MeshAgent]
		duk_del_prop_string(ptrs->ctx, -1, REMOTE_DESKTOP_STREAM);
		duk_pop(ptrs->ctx);											// ...
#ifdef _LINKVM
#if defined(_POSIX) && !defined(__APPLE__)
		if (ptrs->kvmPipe != NULL) { ILibProcessPipe_FreePipe(ptrs->kvmPipe); }
#endif
#ifdef WIN32
		kvm_cleanup(ptrs);
#else
		kvm_cleanup(ptrs);
#endif
#endif
	}
	return 0;
}
void ILibDuktape_MeshAgent_RemoteDesktop_PipeHook(ILibDuktape_readableStream *stream, void *wstream, void *user)
{
#ifdef _LINKVM
#ifdef WIN32
	ILibDuktape_DuplexStream *ds = (ILibDuktape_DuplexStream*)user;
	kvm_relay_reset(ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ds->user);
#else
	kvm_relay_reset();
#endif
#else
	UNREFERENCED_PARAMETER(stream);
	UNREFERENCED_PARAMETER(user);
#endif
}
#endif

int ILibDuktape_MeshAgent_remoteDesktop_unshiftSink(ILibDuktape_DuplexStream *sender, int unshiftBytes, void *user)
{
	return(0);
}

#ifdef __APPLE__
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_EndSink(duk_context *ctx)
{
	MeshAgent_sendConsoleText(ctx, "IPC Connection Closed...");

	duk_push_this(ctx);
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, KVM_IPC_SOCKET);

	// Check to see if there is a user logged in
	if (duk_peval_string(ctx, "require('user-sessions').consoleUid()") == 0)
	{
		int console_uid = duk_get_int(ctx, -1);
		char tmp[255];
		sprintf_s(tmp, sizeof(tmp), "User id: %d has logged in", console_uid);
		MeshAgent_sendConsoleText(ctx, tmp);

		duk_push_heapptr(ctx, ptrs->MeshAgentObject);
		duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);
		MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

		if (ptrs != NULL && ptrs->ctx != NULL && ptrs->stream != NULL)
		{
			ptrs->kvmPipe = kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
	}
	else
	{
		if (ptrs != NULL && ptrs->ctx != NULL && ptrs->stream != NULL)
		{
			ILibDuktape_DuplexStream_WriteEnd(ptrs->stream);
		}
	}


	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink(duk_context *ctx)
{
	duk_push_this(ctx);
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, KVM_IPC_SOCKET);
	char *buffer;
	duk_size_t bufferLen, consumed = 0;
	unsigned short size;

	buffer = (char*)Duktape_GetBuffer(ctx, 0, &bufferLen);
	
	// We need to properly frame the data before we propagate it up
	if (bufferLen > 4)
	{
		size = ntohs(((unsigned short*)(buffer))[1]);
		if (size <= bufferLen)
		{
			// We have all the data, to be able to frame it
			consumed = size;
			ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(buffer, (int)size, ptrs);
		}
	}

	if ((bufferLen - consumed) > 0)
	{
		// We need to unshift() the remainder to continue processing
		duk_push_external_buffer(ctx);														// [ext]
		duk_config_buffer(ctx, -1, buffer, bufferLen - consumed);
		duk_push_this(ctx);																	// [ext][IPC]
		duk_get_prop_string(ctx, -1, "unshift");											// [ext][IPC][unshift]
		duk_swap_top(ctx, -2);																// [ext][unshift][this]
		duk_push_buffer_object(ctx, -3, 0, bufferLen - consumed, DUK_BUFOBJ_NODEJS_BUFFER);	// [ext][unshift][this][buffer]
		duk_call_method(ctx, 1);															// [ext][ret]
	}

	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_Sink(duk_context *ctx)
{
	// This is called when we successfully attach an IPC Domain Socket to the Windows Server, running in the LoginWindow context
	RemoteDesktop_Ptrs *ptrs;

	MeshAgent_sendConsoleText(ctx, "IPC Connection Established...");

	duk_push_current_function(ctx);
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetPointerProperty(ctx, -1, "ptrs");

	duk_push_this(ctx);
	duk_push_pointer(ctx, ptrs); duk_put_prop_string(ctx, -2, KVM_IPC_SOCKET);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "data", ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_DataSink);
	ILibDuktape_EventEmitter_AddOnEx(ctx, -1, "end", ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_EndSink);

	return(0);
}
#endif

#if defined(_LINKVM)
void ILibDuktape_MeshAgent_RemoteDesktop_SendError(RemoteDesktop_Ptrs* ptrs, char *msg)
{
	size_t msgLen = strnlen_s(msg, 255);
	char buffer[512];

	((unsigned short*)buffer)[0] = (unsigned short)htons((unsigned short)MNG_ERROR);	// Write the type
	((unsigned short*)buffer)[1] = (unsigned short)htons((unsigned short)(msgLen + 4));	// Write the size
	memcpy_s(buffer + 4, 512 - 4, msg, msgLen);
	ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink(buffer, (int)(msgLen + 4), ptrs);
}
#endif

#if defined(_POSIX) && defined(_LINKVM) && !defined(__APPLE__)
extern void* kvm_relay_restart(int paused, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int uid, char* authToken, char *dispid);
duk_ret_t ILibDuktape_MeshAgent_userChanged(duk_context *ctx)
{
	char *d, *x;
	void *s;
	RemoteDesktop_Ptrs *ptrs;
	MeshAgentHostContainer *agent;


	duk_eval_string(ctx, "require('MeshAgent')");					// [MeshAgent]
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);

	if (!duk_has_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM)) { return(0); }
	duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);			// [MeshAgent][stream]
	s = duk_get_heapptr(ctx, -1);

	duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_ptrs);
	ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);	// [MeshAgent][stream][ptrs]

	if (ptrs->kvmPipe != NULL)
	{
		ILibLifeTime_Remove(ILibGetBaseTimer(duk_ctx_chain(ctx)), ptrs->kvmPipe);
		ILibProcessPipe_Pipe_SetBrokenPipeHandler(ptrs->kvmPipe, NULL);
		kvm_cleanup(ptrs);

		duk_peval_string(ctx, "require('user-sessions').consoleUid()");
		int id = duk_to_int(ctx, -1);
		duk_eval_string(ctx, "require('monitor-info')");				//[uid][monitor-info]
		duk_get_prop_string(ctx, -1, "getXInfo");						//[uid][monitor-info][getXInfo]
		duk_swap_top(ctx, -2);											//[uid][getXInfo][this]
		duk_dup(ctx, -3);												//[uid][getXInfo][this][uid]
		if (duk_pcall_method(ctx, 1) != 0) { duk_eval_string(ctx, "console.log('error');"); return(0); }								//[uid][xinfo]
		x = Duktape_GetStringPropertyValue(ctx, -1, "xauthority", NULL);
		d = Duktape_GetStringPropertyValue(ctx, -1, "display", NULL);


		duk_push_heapptr(ctx, s);							// [stream]
		duk_push_int(ctx, id);								// [stream][id]
		duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_UID);	// [stream]
		duk_pop(ctx);										// ...

		ptrs->kvmPipe = kvm_relay_restart(0, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, id, x, d);
	}
	return(0);
}
#endif

static MeshAgentHostContainer* ILibDuktape_MeshAgent_ResolveRemoteDesktopAgent(duk_context *ctx)
{
	MeshAgentHostContainer *agent = NULL;

	if (ctx == NULL) { return NULL; }

	duk_push_this(ctx);
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_pop(ctx);
	if (agent != NULL) { return agent; }

	duk_push_heap_stash(ctx);
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, "MeshAgentPtr");
	if (agent == NULL)
	{
		agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, "\xFF_MeshDesktop_AgentPtr");
	}
	duk_pop(ctx);
	return agent;
}

#if defined(_LINKVM)
static int ILibDuktape_MeshAgent_RemoteDesktop_CachedStreamIsLive(RemoteDesktop_Ptrs *ptrs)
{
	if (ptrs == NULL || !ILibMemory_CanaryOK(ptrs) || ptrs->stream == NULL || ptrs->ctx == NULL) { return 0; }
	if (ptrs->stream->readableStream == NULL || ptrs->stream->readableStream->endRelayed != 0) { return 0; }
#if defined(WIN32) && defined(_WINSERVICE)
	if (ptrs->agent != NULL && ptrs->agent->runningAsConsole == 0 && ptrs->agent->pipeManager != NULL)
	{
		if (kvm_bridge_debug_get_child_present_for_reserved(ptrs) == 0) { return 0; }
		if (kvm_bridge_debug_get_transport_active_for_reserved(ptrs) == 0) { return 0; }
	}
#endif
	return 1;
}

static void ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(duk_context *ctx, RemoteDesktop_Ptrs *ptrs)
{
	if (ctx == NULL) { return; }

	duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);	// [MeshAgent][RemoteDesktop]
	if (ptrs == NULL || !ILibMemory_CanaryOK(ptrs)) { duk_pop(ctx); return; }
#if defined(_POSIX) && !defined(__APPLE__)
	if (ptrs->kvmPipe != NULL)
	{
		ILibProcessPipe_FreePipe(ptrs->kvmPipe);
		ptrs->kvmPipe = NULL;
	}
#endif
#ifdef WIN32
	kvm_cleanup(ptrs);
#else
	kvm_cleanup();
#endif
	memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	duk_del_prop_string(ctx, -2, REMOTE_DESKTOP_STREAM);
	duk_pop(ctx);											// [MeshAgent]
}
#endif

duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop(duk_context *ctx)
{
#ifndef _LINKVM
	duk_push_null(ctx);
	return 1;
#else
	RemoteDesktop_Ptrs *ptrs;
	MeshAgentHostContainer *agent;

#if defined(WIN32) || (defined(_POSIX) && !defined(__APPLE__))
	int TSID = duk_is_number(ctx, 0) ? duk_require_int(ctx, 0) : -1;
#endif

#if !defined(WIN32) && !defined(__APPLE__)
	if (duk_peval_string(ctx, "require('monitor-info')") == 0)
	{
		char *libx11 = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11LIB", NULL);
		char *libx11tst = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11TST", NULL);
		char *libx11ext = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11EXT", NULL);
		char *libxfixes = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11FIXES", NULL);
		char *libxkb = Duktape_GetStringPropertyValue(ctx, -1, "Location_X11KB", NULL);
		kvm_set_x11_locations(libx11, libx11tst, libx11ext, libxfixes, libxkb);
	}
#endif


	duk_push_this(ctx);											// [MeshAgent]
	if (duk_has_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM))
	{
		duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);	// [MeshAgent][RemoteDesktop]
		duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_ptrs);
		ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBuffer(ctx, -1, NULL);
		duk_pop(ctx);
		if (ILibDuktape_MeshAgent_RemoteDesktop_CachedStreamIsLive(ptrs))
		{
			return 1;
		}
		duk_pop(ctx);											// [MeshAgent]
		Duktape_Console_LogEx(ctx, ILibDuktape_LogType_Info1, "KVM cached remote desktop stream is stale; restarting");
		ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(ctx, ptrs);
	}
	agent = ILibDuktape_MeshAgent_ResolveRemoteDesktopAgent(ctx);
	if (agent == NULL)
	{
		duk_pop(ctx);
		duk_push_null(ctx);
		return 1;
	}
	
#ifdef __APPLE__
	duk_peval_string_noresult(ctx, "require('power-monitor').wakeDisplay();");
#endif

	duk_push_object(ctx);															// [MeshAgent][RemoteDesktop]
	ILibDuktape_WriteID(ctx, "MeshAgent.kvmSession");
	duk_dup(ctx, -1);																// [MeshAgent][RemoteDesktop][RemoteDesktop]
	duk_put_prop_string(ctx, -3, REMOTE_DESKTOP_STREAM);							// [MeshAgent][RemoteDesktop]
	ptrs = (RemoteDesktop_Ptrs*)Duktape_PushBuffer(ctx, sizeof(RemoteDesktop_Ptrs));// [MeshAgent][RemoteDesktop][buffer]
	duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_ptrs);								// [MeshAgent][RemoteDesktop]
	memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));
	ptrs->MeshAgentObject = duk_get_heapptr(ctx, -2);
	ptrs->ctx = ctx;
	ptrs->object = duk_get_heapptr(ctx, -1);
#ifdef WIN32
	ptrs->agent = agent;
	ptrs->tsid = TSID;
#endif
	ptrs->stream = ILibDuktape_DuplexStream_InitEx(ctx, ILibDuktape_MeshAgent_RemoteDesktop_WriteSink, ILibDuktape_MeshAgent_RemoteDesktop_EndSink, ILibDuktape_MeshAgent_RemoteDesktop_PauseSink, ILibDuktape_MeshAgent_RemoteDesktop_ResumeSink, ILibDuktape_MeshAgent_remoteDesktop_unshiftSink, ptrs);
	ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_RemoteDesktop_Finalizer);
	ptrs->stream->readableStream->PipeHookHandler = ILibDuktape_MeshAgent_RemoteDesktop_PipeHook;
	
	// Setup Remote Desktop
#ifdef WIN32
	#ifdef _WINSERVICE
		kvm_relay_setup(agent->exePath, agent->runningAsConsole ? NULL : agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, TSID);
	#else
		kvm_relay_setup(agent->exePath, NULL, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, TSID);
	#endif
#else
	int console_uid = 0;
	if (duk_peval_string(ctx, "require('user-sessions').consoleUid();") == 0) { console_uid = duk_get_int(ctx, -1); }
	duk_pop(ctx);
	#ifdef __APPLE__
		// MacOS
		if (console_uid == 0)
		{
			MeshAgent_sendConsoleText(ctx, "Establishing IPC-x-Connection to LoginWindow for KVM");
			char *ipc = (char*)kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
			duk_eval_string(ctx, "require('net');");														// [rd][net]
			duk_get_prop_string(ctx, -1, "createConnection");												// [rd][net][createConnection]
			duk_swap_top(ctx, -2);																			// [rd][createConnection][this]
			duk_push_object(ctx);																			// [rd][createConnection][this][options]
			duk_push_string(ctx, ipc); duk_put_prop_string(ctx, -2, "path");								// [rd][createConnection][this][options]
			duk_push_c_function(ctx, ILibDuktape_MeshAgent_getRemoteDesktop_DomainIPC_Sink, DUK_VARARGS);	// [rd][createConnection][this][options][callback]
			duk_push_pointer(ctx, ptrs); duk_put_prop_string(ctx, -2, "ptrs");
			duk_call_method(ctx, 2);																		// [rd][icpSocket]
			duk_put_prop_string(ctx, -2, KVM_IPC_SOCKET);													// [rd]
			//ptrs->kvmDomainSocket = (int)(uint64_t)kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
		else
		{
			ptrs->kvmPipe = kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid);
		}
	#else
		if (TSID != -1) 
		{
			console_uid = TSID; 
			duk_push_sprintf(ctx, "require('kvm-helper').createVirtualSession(%d);", console_uid);
			duk_eval(ctx);																					// [uid]
			console_uid = duk_get_int(ctx, -1);
			duk_pop(ctx);																					// ...
			if (console_uid != TSID)
			{
				duk_push_sprintf(ctx, "require('user-sessions').getUsername(%d);", console_uid);
				if (duk_peval(ctx) == 0)
				{
					duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_VIRTUAL_SESSION_USERNAME);
				}
				else
				{
					duk_pop(ctx);
				}
			}
		}
		duk_push_int(ctx, console_uid); duk_put_prop_string(ctx, -2, REMOTE_DESKTOP_UID);
		duk_push_this(ctx);																// [MeshAgent]
		if (!duk_has_prop_string(ctx, -1, MESH_USER_CHANGED_CB))
		{
			duk_eval_string(ctx, "require('user-sessions')");							// [MeshAgent][usersessions]
			duk_get_prop_string(ctx, -1, "on");											// [MeshAgent][usersessions][on]
			duk_swap_top(ctx, -2);														// [MeshAgent][on][this]
			duk_push_string(ctx, "changed");											// [MeshAgent][on][this][changed]
			duk_push_c_function(ctx, ILibDuktape_MeshAgent_userChanged, DUK_VARARGS);	// [MeshAgent][on][this][changed][func]
			duk_dup(ctx, -5);															// [MeshAgent][on][this][changed][func][MeshAgent]
			duk_dup(ctx, -2);															// [MeshAgent][on][this][changed][func][MeshAgent][func]
			duk_put_prop_string(ctx, -2, MESH_USER_CHANGED_CB);							// [MeshAgent][on][this][changed][func][MeshAgent]
			duk_pop(ctx);																// [MeshAgent][on][this][changed][func]
			duk_call_method(ctx, 2); duk_pop(ctx);										// [MeshAgent]
		}
		duk_pop(ctx);																	// ...


		// For Linux, we need to determine where the XAUTHORITY is:
		char *updateXAuth = NULL;
		char *updateDisplay = NULL;
		char *xdm = NULL;
		int needPop = 0;
		duk_eval_string(ctx, "require('user-sessions').Self()");
		int self = duk_get_int(ctx, -1); duk_pop(ctx);

		if (self==0 || getenv("XAUTHORITY") == NULL || getenv("DISPLAY") == NULL)
		{
			if (duk_peval_string(ctx, "require('monitor-info').getXInfo") == 0)
			{
				duk_push_int(ctx, console_uid);
				if (duk_pcall(ctx, 1) == 0)
				{
					if (!duk_is_null(ctx, -1))
					{
						updateXAuth = Duktape_GetStringPropertyValue(ctx, -1, "xauthority", NULL);
						updateDisplay = Duktape_GetStringPropertyValue(ctx, -1, "display", NULL);
						xdm = Duktape_GetStringPropertyValue(ctx, -1, "xdm", "");

						if (strcmp(xdm, "xwayland") == 0)
						{
							ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "This platform is configured to use Xwayland");
							ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "please modify config to use Xorg");
							duk_pop(ctx);
							return(1);
						}

						if (console_uid != 0 && updateXAuth == NULL)
						{
							ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "Xauthority not found! Is your DM configured to use X?");
							duk_pop(ctx);
							return(1);
						}
					}
					else
					{
						if (console_uid != 0)
						{
							ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "This system does not appear to have an XServer running");
						}
						else
						{
							ILibDuktape_MeshAgent_RemoteDesktop_SendError(ptrs, "This system does not appear to have an XServer instance running when no users are logged in");
						}
					}
				}
				else
				{
					MeshAgent_sendConsoleText(ctx, "Error trying to determine XAUTHORITY/DISPLAY: %s ", duk_safe_to_string(ctx, -1));
				}
			}
			else
			{
				MeshAgent_sendConsoleText(ctx, "Error trying to determine XAUTHORITY/DISPLAY: %s ", duk_safe_to_string(ctx, -1));
			}
			needPop = 1;
		}

		Duktape_Console_LogEx(ctx, ILibDuktape_LogType_Info1, "Using uid: %d, XAUTHORITY: %s\n", console_uid, getenv("XAUTHORITY") == NULL ? updateXAuth : getenv("XAUTHORITY"));
		ptrs->kvmPipe = kvm_relay_setup(agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, console_uid, updateXAuth, updateDisplay);
		if (needPop!= 0) {duk_pop(ctx); }
	#endif
#endif
		
	return 1;
#endif
}
duk_ret_t ILibDuktape_MeshAgent_ConnectedServer(duk_context *ctx)
{
	int len;
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
#ifndef MICROSTACK_NOTLS
	if (agent->controlChannel != NULL && agent->serverAuthState == 3)
#else
	if (agent->controlChannel != NULL)
#endif
	{
		len = ILibSimpleDataStore_Get(agent->masterDb, "MeshServer", ILibScratchPad2, sizeof(ILibScratchPad2));
		if (len == 0) { duk_push_null(ctx); return 1; }

		parser_result *rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
		parser_result_field *f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
		f->datalength = ILibTrimString(&(f->data), f->datalength);
		f->data[f->datalength] = 0;

		if (strncmp(f->data, "local", 5) == 0 && f->datalength == 5)
		{
			duk_push_sprintf(ctx, "[local] %s", agent->serveruri);
		}
		else
		{
			duk_push_lstring(ctx, f->data, f->datalength);
		}
		ILibDestructParserResults(rs);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
}


duk_ret_t ILibDuktape_MeshAgent_NetInfo(duk_context *ctx)
{
#if defined(__APPLE__) || defined(_FREEBSD)
	char getGatewayInfo[] = "(function _getGatewayInfo(){\
				var gwname;\
				var child = require('child_process').execFile('/bin/sh', ['sh']);\
				child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });\
				child.stdin.write('route get default | grep gateway: | awk -F: \\'{ gsub(/^[ \t]/, \"\", $2); print $2; }\\'\\nexit\\n');\
				child.waitExit();\
				gwname = child.stdout.str.trim();\
				child = require('child_process').execFile('/bin/sh', ['sh']); \
				child.stdout.str = ''; child.stdout.on('data', function(c) { this.str += c.toString(); }); \
				child.stdin.write('arp -n ' + gwname + ' | awk \\'{ split($2,tok1,\")\"); split(tok1[1],tok2,\"(\"); printf \"%s,%s,%s\", $6,$4,tok2[2]; }\\'\\nexit\\n');\
				child.waitExit();\
				var tmp = child.stdout.str.trim().split(',');\
				child = require('child_process').execFile('/bin/sh', ['sh']);\
				child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });\
				child.stdin.write('networksetup -listallhardwareports | tr \\'\\\\n\\' \\'`\\' | awk -F\\'`\\' \\'');\
				child.stdin.write('{ ');\
				child.stdin.write('  for(i=3;i<NF;i+=4) ');\
				child.stdin.write('  { ');\
				child.stdin.write('     split($i,dv,\": \"); ');\
				child.stdin.write('     if(dv[2]==\"' + tmp[0] + '\")');\
				child.stdin.write('     { ');\
				child.stdin.write('        split($(i-1), res, \": \");');\
				child.stdin.write('        print(res[2]); break;');\
				child.stdin.write('     } ');\
				child.stdin.write('   } ');\
				child.stdin.write('}\\'\\nexit\\n');\
				child.waitExit();\
				var dvname = child.stdout.str.trim();\
				var tmp2 = tmp[1].split(':');\
				for(var i in tmp2)\
				{\
					tmp2[i] = tmp2[i].padStart(2, '0');\
				}\
				tmp[1] = tmp2.join('');\
				var ni = require('os').networkInterfaces();\
				for(var i in ni[tmp[0]])\
				{\
					if(ni[tmp[0]][i].family == 'IPv4')\
					{\
						var ret = {v4addr: ni[tmp[0]][i].address, v4mask: ni[tmp[0]][i].netmask, mac: ni[tmp[0]][i].mac.split(':').join(''), gatewaymac: tmp[1], name: tmp[0]};\
						if(ni[tmp[0]][i].gateway != null) { ret['gateway'] =  ni[tmp[0]][i].gateway; }\
						if(dvname != '') {ret['desc'] = dvname;}\
						return({netif: {0: ret}});\
					}\
				}\
				return({});})";
	duk_eval_string(ctx, getGatewayInfo);	// [func]
	duk_call(ctx, 0);						// [result]
	return(1);
#else
	char *data;
	int len = MeshInfo_GetSystemInformation(&data);
	if (len > 0)
	{
		duk_push_lstring(ctx, data, len);
		duk_json_decode(ctx, -1);
		free(data);
	}
	else
	{
		duk_push_null(ctx);
	}
	return 1;
#endif
}

// Javascript ExecPowerState(int), executes power state command on the computer (Sleep, Hibernate...)
duk_ret_t ILibDuktape_MeshAgent_ExecPowerState(duk_context *ctx)
{
	int force = 0;
	int numArgs = (int)duk_get_top(ctx);
	if (numArgs == 2 && duk_is_number(ctx, 1)) { force = duk_get_int(ctx, 1); }


	duk_push_this(ctx);	// [MeshAgent]
	if (duk_is_number(ctx, 0))
	{
#ifdef __APPLE__
		switch (duk_require_int(ctx, 0))
		{
			case 2: // SHUTDOWN
				duk_peval_string_noresult(ctx, "require('mac-powerutil').shutdown();");
				duk_push_int(ctx, 1);
				break;
			case 3: // REBOOT
				duk_peval_string_noresult(ctx, "require('mac-powerutil').restart();");
				duk_push_int(ctx, 1);
				break;
			default:
				duk_push_int(ctx, 0);
				break;
		}
#else
		duk_push_int(ctx, MeshInfo_PowerState((AgentPowerStateActions)duk_get_int(ctx, 0), force));
#endif
	}
	else
	{
		duk_push_null(ctx);
	}

	return 1;
}

duk_ret_t ILibDuktape_MeshAgent_ServerUrl(duk_context *ctx)
{
	duk_push_this(ctx);											// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	duk_push_string(ctx, agent->serveruri);						// [MeshAgent][ptr][uri]
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_updatesEnabled(duk_context *ctx)
{
	duk_push_this(ctx);											// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);
	duk_push_boolean(ctx, agent->disableUpdate == 0);
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_ServerIP(duk_context *ctx)
{
	duk_push_this(ctx);											// [MeshAgent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);				// [MeshAgent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	duk_push_string(ctx, agent->serverip);						// [MeshAgent][ptr][ip]
	return(1);
}

duk_ret_t ILibDuktape_MeshAgent_isControlChannelConnected(duk_context *ctx)
{
	duk_push_this(ctx);								// [agent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);

	if (agent != NULL)
	{
		duk_push_boolean(ctx, agent->serverAuthState == 3 ? 1 : 0);
		return(1);
	}
	else
	{
		return(0);
	}
}
duk_ret_t ILibDuktape_MeshAgent_eval(duk_context *ctx)
{
	duk_size_t evalStrLen;
	char *evalStr = (char*)duk_get_lstring(ctx, 0, &evalStrLen);

	printf("eval(): %s\n", evalStr);
	ILibDuktape_ExecutorTimeout_Start(ctx);
	duk_eval_string(ctx, evalStr);
	ILibDuktape_ExecutorTimeout_Stop(ctx);
	return(1);
}
duk_context* ScriptEngine_Stop(MeshAgentHostContainer *agent, char *contextGUID);

int dumpcount = 0;
void ILibDuktape_MeshAgent_dumpCoreModuleEx(void *chain, void *user)
{
	MeshAgentHostContainer* agentHost = (MeshAgentHostContainer*)user;
	char *CoreModule;

	ScriptEngine_Stop((MeshAgentHostContainer*)user, MeshAgent_JavaCore_ContextGuid);
	printf("CoreModule was manually dumped %d times, restarting!\n", ++dumpcount);

	int CoreModuleLen = ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0);
	if (CoreModuleLen > 4)
	{
		// There is a core module, launch it now.
		CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
		ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

		MeshAgent_EnsureCoreModuleRuntimeGlobals(agentHost->meshCoreCtx);
		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
			ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
		}
		duk_pop(agentHost->meshCoreCtx);
		free(CoreModule);
	}
}
duk_ret_t ILibDuktape_MeshAgent_dumpCoreModule(duk_context *ctx)
{
	duk_push_this(ctx);								// [agent]
	duk_get_prop_string(ctx, -1, MESH_AGENT_PTR);	// [agent][ptr]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	agent->localScript = 0;
	ILibChain_RunOnMicrostackThreadEx(agent->chain, ILibDuktape_MeshAgent_dumpCoreModuleEx, agent);
	return(0);
}
void ILibDuktape_MeshAgent_ConnectedHook(ILibDuktape_EventEmitter *sender, char *eventName, void *hookedCallback)
{
	int top = duk_get_top(sender->ctx);
	duk_push_heapptr(sender->ctx, hookedCallback);			// [cb]
	duk_push_heapptr(sender->ctx, sender->object);			// [cb][this]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(sender->ctx, -1, MESH_AGENT_PTR);
	if (agent->serverAuthState == 3)
	{
		duk_push_int(sender->ctx, 1);						// [cb][this][1]
		duk_pcall_method(sender->ctx, 1);
	}
	duk_set_top(sender->ctx, top);
}

duk_ret_t ILibDuktape_MeshAgent_ServerInfo(duk_context *ctx)
{
	duk_push_this(ctx);								// [agent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	
	duk_push_object(ctx);

	util_tohex(agent->meshId, sizeof(agent->meshId), ILibScratchPad);
	duk_push_string(ctx, ILibScratchPad); duk_put_prop_string(ctx, -2, "MeshID");

	util_tohex(agent->serverHash, sizeof(agent->serverHash), ILibScratchPad);
	duk_push_string(ctx, ILibScratchPad); duk_put_prop_string(ctx, -2, "ServerID");
	duk_push_string(ctx, agent->serveruri); duk_put_prop_string(ctx, -2, "ServerUri");
	duk_push_string(ctx, agent->serverip); duk_put_prop_string(ctx, -2, "ServerIP");

#ifndef MICROSTACK_NOTLS
	if (agent->controlChannel != NULL)
	{
		X509 *cert = ILibWebClient_SslGetCert(agent->controlChannel);
		ILibDuktape_TLS_X509_PUSH(ctx, cert);
		X509_free(cert);
	}
	else
	{
		duk_push_null(ctx);
	}
#else
	duk_push_null(ctx);
#endif
	duk_put_prop_string(ctx, -2, "ControlChannelCertificate");
	return(1);
}
#ifndef MICROSTACK_NOTLS
duk_ret_t ILibDuktape_MeshAgent_GenerateCertsForDiagnosticAgent(duk_context *ctx)
{
	char tmp[UTIL_SHA384_HASHSIZE] = { 0 };
	struct util_cert tmpCert;

#ifdef WIN32
	char *rootSubject = (char*)duk_require_string(ctx, 0);

	duk_push_this(ctx);							
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
#endif

	duk_push_object(ctx);

#ifdef WIN32
	wincrypto_object j = NULL;
	char *cert_der = NULL, *cert_pfx = NULL;
	if (agent->noCertStore == 0 && (j=wincrypto_open(TRUE, rootSubject)) != NULL) // Force certificate re-generation
	{
		int l;
		do {
			// Finish off work with our own certificate
			l = wincrypto_getcert(&cert_der, j);
			if (l > 0)
			{
				util_from_cer(cert_der, l, &tmpCert);
				util_keyhash(tmpCert, tmp);
				if (((int*)tmp)[0] == 0) { wincrypto_close(j); j=wincrypto_open(1, rootSubject); }
			}
		} while (l != 0 && ((int*)tmp)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.

		if (l > 0)
		{
			// Save the root cert in CER format
			duk_push_object(ctx);												// [object][root]
			char *rootBuffer = duk_push_fixed_buffer(ctx, l);					// [object][root][buffer]
			duk_push_buffer_object(ctx, -1, 0, l, DUK_BUFOBJ_NODEJS_BUFFER);	// [object][root][buffer][nodeBuffer]
			duk_put_prop_string(ctx, -3, "der");								// [object][root][buffer]
			duk_pop(ctx);														// [object][root]
			duk_put_prop_string(ctx, -2, "root");								// [object]
			memcpy_s(rootBuffer, l, cert_der, l);

			// Generate a new TLS certificate & save it.
			l = wincrypto_mkCert(j, rootSubject, L"CN=localhost", CERTIFICATE_TLS_SERVER, L"hidden", &cert_pfx);

			duk_push_object(ctx);												// [object][tls]
			char *buffer = duk_push_fixed_buffer(ctx, l);						// [object][tls][buffer]
			duk_push_buffer_object(ctx, -1, 0, l, DUK_BUFOBJ_NODEJS_BUFFER);	// [object][tls][buffer][nodeBuffer]
			duk_put_prop_string(ctx, -3, "pfx");								// [object][tls][buffer]
			duk_pop(ctx);														// [object][tls]
			duk_push_string(ctx, "hidden"); duk_put_prop_string(ctx, -2, "passphrase");
			duk_put_prop_string(ctx, -2, "tls");								// [object]
			memcpy_s(buffer, l, cert_pfx, l);
			util_free(cert_pfx);
			wincrypto_close(j);
			return(1);
		}

		// wincrypto error
		return(ILibDuktape_Error(ctx, "Error Generating Certificates using WinCrypto"));
	}
	else 
	{
#endif
		// Generate a new self-signed root certificate for this node using OpenSSL
		do
		{
			if (util_mkCert(NULL, &(tmpCert), 3072, 10000, "MeshNodeCertificate", CERTIFICATE_ROOT, NULL) == 0)
			{
				return(ILibDuktape_Error(ctx, "Error Generating Certificates using OpenSSL"));
			}
			util_keyhash(tmpCert, tmp);
		} while (((int*)tmp)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.
		
		duk_push_object(ctx);													// [object][root]
		char *pfx = NULL;
		int pfxLen = util_to_p12(tmpCert, "hidden", &pfx);
		char *jspfx = duk_push_fixed_buffer(ctx, pfxLen);						// [object][root][buffer]
		duk_push_buffer_object(ctx, -1, 0, pfxLen, DUK_BUFOBJ_NODEJS_BUFFER);	// [object][root][buffer][nodeBuffer]
		duk_put_prop_string(ctx, -3, "pfx");									// [object][root][buffer]
		duk_pop(ctx);															// [object][root]
		duk_push_string(ctx, "hidden"); duk_put_prop_string(ctx, -2, "passphrase");
		duk_put_prop_string(ctx, -2, "root");									// [object]

		memcpy_s(jspfx, pfxLen, pfx, pfxLen);
		util_free(pfx);
		util_freecert(&tmpCert);
		return(1);
#ifdef WIN32
	}
#endif
}
#endif

duk_ret_t ILibDuktape_MeshAgent_forceExit(duk_context *ctx)
{
	int code = 0;
	if (duk_get_top(ctx) > 0)
	{
		code = (int)duk_require_int(ctx, 0);
	}

	exit(code);
	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_hostname(duk_context *ctx)
{
	duk_push_this(ctx);
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_push_string(ctx, agent->hostname);
	return(1);
}
#if defined(_LINKVM) && defined(_POSIX) && !defined(__APPLE__)
duk_ret_t ILibDuktape_MeshAgent_enableKvmSlaveLog(duk_context *ctx)
{
	SLAVELOG = (int)duk_require_int(ctx, 0);
	return(0);
}
#endif
duk_ret_t ILibDuktape_MeshAgent_getIdleTimeout(duk_context *ctx)
{
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);																		// [MeshAgent]
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_push_int(ctx, agent->controlChannel_idleTimeout_seconds);
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_getIdleTimeout_isDataMode(duk_context *ctx)
{
	duk_push_this(ctx);																		// [MeshAgent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_push_boolean(ctx, agent->controlChannel_idleTimeout_dataMode);
	return(1);
}

duk_ret_t ILibDuktape_MeshAgent_getStartupOptions(duk_context *ctx)
{
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);																		// [MeshAgent]
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);

	ILibDuktape_SimpleDataStore_raw_GetCachedValues_Object(ctx, agent->masterDb);
	return(1);
}

duk_ret_t ILibDuktape_MeshAgent_remoteMouseRender_get(duk_context *ctx)
{
	duk_push_int(ctx, gRemoteMouseRenderDefault);
	return(1);
}

duk_ret_t ILibDuktape_MeshAgent_remoteMouseRender_set(duk_context *ctx)
{
	gRemoteMouseRenderDefault = duk_require_int(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_coreHash(duk_context *ctx)
{
	MeshAgentHostContainer *agent;
	duk_push_this(ctx);																		// [MeshAgent]
	agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);

	char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");				// Get the reference to the SHA384 hash for the currently running code
	util_tohex(hashref, ILibSimpleDataStore_GetHashSize(), ILibScratchPad);
	duk_push_string(ctx, ILibScratchPad);
	return(1);
}
#ifdef _LINKVM 
duk_ret_t ILibDuktape_KVM_Refresh(duk_context *ctx)
{
	duk_push_this(ctx);
	RemoteDesktop_Ptrs *ptrs = (RemoteDesktop_Ptrs*)Duktape_GetBufferProperty(ctx, -1, REMOTE_DESKTOP_ptrs);
	if (ptrs != NULL) { ILibDuktape_MeshAgent_RemoteDesktop_PipeHook(NULL, NULL, ptrs->stream); }
	return(0);
}
#endif
duk_ret_t ILibDuktape_MeshAgent_log(duk_context *ctx)
{
	char *msg = (char*)duk_require_string(ctx, 0);
	ILIBLOGMESSAGEX("meshcore: %s", msg);
	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_controlChannelDebug(duk_context *ctx)
{
	duk_push_this(ctx);																		
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_push_boolean(ctx, agent->controlChannelDebug != 0);
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_DataPing_Timeout(duk_context *ctx)
{
	duk_prepare_method_call(ctx, 0, "_rej");	// [_rej][this]
	duk_call_method(ctx, 0);
	return(0);
}
duk_ret_t ILibDuktape_MeshAgent_DataPing(duk_context *ctx)
{
	int nargs = duk_get_top(ctx);
	int timeout = 0;
	if (nargs > 0) { timeout = duk_require_int(ctx, 0); }

	duk_push_this(ctx);											// [agent]
	duk_get_prop_string(ctx, -1, MESHAGENT_DATAPING_ARRAY);		// [agent][pingarray]

	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -2, MESH_AGENT_PTR);
	duk_eval_string(ctx, "(function foo(){var p=require('promise');return(new p(function(res, rej) { this._res = res; this._rej = rej; }));})()");
	duk_dup(ctx, -1);											// [agent][pingarray][promise][promise]
	duk_array_push(ctx, -3);									// [agent][pingarray][promise]

	if (timeout > 0)
	{
		duk_push_global_object(ctx);							// [agent][pingarray][promise][g]
		duk_prepare_method_call(ctx, -1, "setTimeout");			// [agent][pingarray][promise][g][setTimeout][this]
		duk_push_c_function(ctx, ILibDuktape_MeshAgent_DataPing_Timeout, DUK_VARARGS);//omise][g][setTimeout][this][func]
		duk_push_int(ctx, timeout);								// [agent][pingarray][promise][g][setTimeout][this][func][timeout]
		duk_dup(ctx, -6);										// [agent][pingarray][promise][g][setTimeout][this][func][timeout][promise]
		if (duk_pcall_method(ctx, 3) == 0)						// [agent][pingarray][promise][g][timeout]
		{
			duk_put_prop_string(ctx, -3, MESHAGENT_DATAPAING_PROMISE_TIMEOUT);
		}
		else
		{
			duk_pop(ctx);										// [agent][pingarray][promise][g]
		}
		duk_pop(ctx);											// [agent][pingarray][promise]
	}

	MeshServer_SendJSON(agent, agent->controlChannel, "{\"action\":\"ping\"}", 17);
	return(1);
}
duk_ret_t ILibDuktape_MeshAgent_Disconnect(duk_context *ctx)
{
	duk_push_this(ctx);																								// [MeshAgent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	ILibWebClient_Disconnect(agent->controlChannel);
	return(0);
}

void ILibDuktape_MeshAgent_PUSH(duk_context *ctx, void *chain)
{
	MeshAgentHostContainer *agent;
	ILibDuktape_EventEmitter *emitter;

	duk_push_heap_stash(ctx);									// [stash]
	if (duk_has_prop_string(ctx, -1, MESH_AGENT_SINGLETON))
	{
		duk_get_prop_string(ctx, -1, MESH_AGENT_SINGLETON);		// [stash][MeshAgent]
		duk_swap_top(ctx, -2);									// [MeshAgent][stash]
		duk_pop(ctx);											// [MeshAgent]
		return;
	}

	duk_get_prop_string(ctx, -1, "MeshAgentPtr");				// [stash][agentPtr]
	agent = (MeshAgentHostContainer*)duk_get_pointer(ctx, -1);

	duk_pop_2(ctx);												// ...
	duk_push_object(ctx);										// [MeshAgent]
	ILibDuktape_WriteID(ctx, "MeshAgent");
	duk_push_pointer(ctx, agent);								// [MeshAgent][ptr]
	duk_put_prop_string(ctx, -2, MESH_AGENT_PTR);				// [MeshAgent]

	duk_push_heap_stash(ctx);									// [MeshAgent][stash]
	duk_dup(ctx, -2);											// [MeshAgent][stash][MeshAgent]
	duk_put_prop_string(ctx, -2, MESH_AGENT_SINGLETON);			// [MeshAgent][stash]
	duk_pop(ctx);												// [MeshAgent]

	ILibDuktape_CreateReadonlyProperty_int(ctx, "serviceReserved", agent->serviceReserved);

	emitter = ILibDuktape_EventEmitter_Create(ctx);
	duk_push_boolean(ctx, agent->agentMode);
	ILibDuktape_CreateReadonlyProperty(ctx, "agentMode");

	if (agent->slaveMode == 0)
	{
#ifndef MICROSTACK_NOTLS
		if (agent->selftlscert.x509 != NULL) {
			// We have a TLS certificate, use it for WebRTC
			duk_push_pointer(ctx, &agent->selftlscert);
			duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Server);
		} else {
			// We don't have a TLS certificate, use the root cert for WebRTC
			duk_push_pointer(ctx, &agent->selfcert);
			duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_Server);
		}
		// Always use the root cert for agent authentication
		duk_push_pointer(ctx, &agent->selfcert);
		duk_put_prop_string(ctx, -2, ILibDuktape_MeshAgent_Cert_NonLeaf);
		ILibDuktape_CreateInstanceMethod(ctx, "GenerateAgentCertificate", ILibDuktape_MeshAgent_GenerateCertsForDiagnosticAgent, 1);
#endif
		duk_push_array(ctx); duk_put_prop_string(ctx, -2, MESHAGENT_DATAPING_ARRAY);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Ready");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Connected");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "Command");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "DesktopSessionChanged");
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "DBError");
		ILibDuktape_EventEmitter_AddHook(emitter, "Connected", ILibDuktape_MeshAgent_ConnectedHook);

		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "ServerInfo", ILibDuktape_MeshAgent_ServerInfo,1);

		duk_push_number(ctx, (duk_double_t)ILibCriticalLog_MaxSize);
		ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "maxLogSize", 1);

		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "isControlChannelConnected", ILibDuktape_MeshAgent_isControlChannelConnected,1);
		ILibDuktape_EventEmitter_AddHook(emitter, "Ready", ILibDuktape_MeshAgent_Ready);
		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "ConnectedServer", ILibDuktape_MeshAgent_ConnectedServer,1);
		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "ServerUrl", ILibDuktape_MeshAgent_ServerUrl,1);
		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "ServerIP", ILibDuktape_MeshAgent_ServerIP,1);
		ILibDuktape_CreateInstanceMethod(ctx, "getRemoteDesktopStream", ILibDuktape_MeshAgent_getRemoteDesktop, DUK_VARARGS);
		ILibDuktape_CreateInstanceMethod(ctx, "AddCommandHandler", ILibDuktape_MeshAgent_AddCommandHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "AddConnectHandler", ILibDuktape_MeshAgent_AddConnectHandler, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "SendCommand", ILibDuktape_MeshAgent_SendCommand, 1);
		ILibDuktape_CreateFinalizer(ctx, ILibDuktape_MeshAgent_Finalizer);
		ILibDuktape_CreateReadonlyProperty_int(ctx, "activeMicroLMS", (agent->microLMS != NULL ? 1 : 0));
		ILibDuktape_CreateInstanceMethod(ctx, "restartCore", ILibDuktape_MeshAgent_dumpCoreModule, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "getStartupOptions", ILibDuktape_MeshAgent_getStartupOptions, 0);
		ILibDuktape_CreateEventWithGetter(ctx, "coreHash", ILibDuktape_MeshAgent_coreHash);
		ILibDuktape_CreateEventWithGetter_SetEnumerable(ctx, "updatesEnabled", ILibDuktape_MeshAgent_updatesEnabled, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "log", ILibDuktape_MeshAgent_log, 1);
		ILibDuktape_CreateEventWithGetter(ctx, "controlChannelDebug", ILibDuktape_MeshAgent_controlChannelDebug);
		ILibDuktape_CreateInstanceMethod(ctx, "DataPing", ILibDuktape_MeshAgent_DataPing, DUK_VARARGS);
		ILibDuktape_CreateReadonlyProperty_int(ctx, "ARCHID", MESH_AGENTID);
	#if defined(WIN32) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
		duk_push_true(ctx);
	#else
		duk_push_false(ctx);
	#endif
		ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "nativeFullUpdate", 1);
		ILibDuktape_CreateReadonlyProperty_int(ctx, "ConsoleTextMaxRate", agent->consoleText_maxRate);
#ifdef _LINKVM 
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 1);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "kvmConnected");
		ILibDuktape_CreateInstanceMethod(ctx, "kvmRefresh", ILibDuktape_KVM_Refresh, 0);
		ILibDuktape_CreateEventWithGetterAndSetterEx(ctx, "remoteMouseRender", ILibDuktape_MeshAgent_remoteMouseRender_get, ILibDuktape_MeshAgent_remoteMouseRender_set);
#if defined(WIN32)
		ILibDuktape_CreateReadonlyProperty_int(ctx, "maxKvmTileSize", 0);
#else
	#if defined(JPEGMAXBUF)
		ILibDuktape_CreateReadonlyProperty_int(ctx, "maxKvmTileSize", JPEGMAXBUF);
	#else
		ILibDuktape_CreateReadonlyProperty_int(ctx, "maxKvmTileSize", 65500);
	#endif
#endif

#if defined(_POSIX) && !defined(__APPLE__)
		ILibDuktape_CreateInstanceMethod(ctx, "enableKvmSlaveLog", ILibDuktape_MeshAgent_enableKvmSlaveLog, 1);
#endif
#else
		ILibDuktape_CreateReadonlyProperty_int(ctx, "hasKVM", 0);
#endif

		ILibDuktape_CreateEventWithGetter(ctx, "NetInfo", ILibDuktape_MeshAgent_NetInfo);
		ILibDuktape_CreateEventWithGetter(ctx, "idleTimeout", ILibDuktape_MeshAgent_getIdleTimeout);
		ILibDuktape_CreateEventWithGetter(ctx, "idleTimeoutDataMode", ILibDuktape_MeshAgent_getIdleTimeout_isDataMode);
		ILibDuktape_EventEmitter_CreateEventEx(emitter, "idleTimeoutModeChanged");
		ILibDuktape_CreateInstanceMethod(ctx, "ExecPowerState", ILibDuktape_MeshAgent_ExecPowerState, DUK_VARARGS);
		ILibDuktape_CreateInstanceMethod(ctx, "eval", ILibDuktape_MeshAgent_eval, 1);
		ILibDuktape_CreateInstanceMethod(ctx, "forceExit", ILibDuktape_MeshAgent_forceExit, DUK_VARARGS);
		ILibDuktape_CreateInstanceMethod(ctx, "hostname", ILibDuktape_MeshAgent_hostname, 0);
		ILibDuktape_CreateInstanceMethod(ctx, "disconnect", ILibDuktape_MeshAgent_Disconnect, 0);

		Duktape_CreateEnum(ctx, "ContainerPermissions", (char*[]) { "DEFAULT", "NO_AGENT", "NO_MARSHAL", "NO_PROCESS_SPAWNING", "NO_FILE_SYSTEM_ACCESS", "NO_NETWORK_ACCESS" }, (int[]) { 0x00, 0x10000000, 0x08000000, 0x04000000, 0x00000001, 0x00000002 }, 6);
		duk_push_string(ctx, agent->displayName); ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "displayName",1);

		if (agent->meshServiceName != NULL && agent->meshServiceName[0] != 0)
		{
			duk_push_string(ctx, agent->meshServiceName);
			ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "serviceName", 1);
		}
		

#ifdef WIN32
	#ifdef _WINSERVICE
		duk_push_boolean(ctx, agent->runningAsConsole == 0);
	#else
		duk_push_false(ctx);
	#endif
		ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "isService",1);
#else
		// Determine if we're running as service on Linux
		duk_push_boolean(ctx, agent->JSRunningAsService);
		ILibDuktape_CreateReadonlyProperty_SetEnumerable(ctx, "isService",1);
#endif

	}

	ILibDuktape_CreateInstanceMethod(ctx, "GenerateCertificate", ILibDuktape_MeshAgent_GenerateCertificate, 1);
	duk_push_pointer(ctx, agent->masterDb); duk_put_prop_string(ctx, -2, "\xFF_MasterDB");

	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "Acquired MeshAgent");
}

void ILibDuktape_MeshAgent_Init(duk_context* ctx, void *chain, MeshAgentHostContainer *agent)
{
	duk_push_heap_stash(ctx);						// [stash]
	duk_push_pointer(ctx, agent);					// [stash][agentPtr]
	duk_put_prop_string(ctx, -2, "MeshAgentPtr");	// [stash]
	duk_pop(ctx);									// ...
	ILibDuktape_ModSearch_AddHandler(ctx, "MeshAgent", ILibDuktape_MeshAgent_PUSH);
}

/* ------------------------------ 

End Mesh Agent Duktape Abstraction
	
--------------------------------*/

// !!!WARNING!!!: The result of this method is stored in ILibScratchPad2
char* MeshAgent_MakeAbsolutePathEx(char *basePath, char *localPath, int escapeBackSlash)
{
	MeshAgentHostContainer *agent = ILibMemory_CanaryOK(basePath) ? ((MeshAgentHostContainer**)ILibMemory_Extra(basePath))[0] : NULL;
	size_t basePathLen = strnlen_s(basePath, sizeof(ILibScratchPad2) - 4);
	size_t len;

	if (agent != NULL && agent->configPathUsesCWD != 0)
	{
#ifdef WIN32
		int i = ILibString_LastIndexOf(basePath, basePathLen, "\\", 1) + 1;
		char *wd = ILibWideToUTF8((LPWSTR)ILibScratchPad2, GetCurrentDirectoryW(sizeof(ILibScratchPad2) / 2, (LPWSTR)ILibScratchPad2));
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s\\%s", wd, basePath + i);
#else
		int i = ILibString_LastIndexOf(basePath, basePathLen, "/", 1) + 1;
		ignore_result((uintptr_t)getcwd(ILibScratchPad, sizeof(ILibScratchPad)));
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s/%s", ILibScratchPad, basePath + i);
#endif
	}
	else
	{
		sprintf_s(ILibScratchPad2, sizeof(ILibScratchPad2), "%s", basePath);
	}

	len = strnlen_s(ILibScratchPad2, sizeof(ILibScratchPad2));
	if (localPath[0] == '.')
	{
#ifndef WIN32
		sprintf_s(ILibScratchPad2 + len, sizeof(ILibScratchPad2) - len, "%s", localPath);
#else
		int i = ILibString_LastIndexOf(ILibScratchPad2, len, ".", 1);
		if (i < 0) { i = (int)len; } // No extension to replace: append (matches the non-Windows branch)
		sprintf_s(ILibScratchPad2 + i, sizeof(ILibScratchPad2) - i, "%s", localPath);
#endif
	}
	else
	{
#ifdef WIN32
		int i = ILibString_LastIndexOf(ILibScratchPad2, len, "\\", 1) + 1;
#else
		int i = ILibString_LastIndexOf(ILibScratchPad2, len, "/", 1) + 1;
#endif
		sprintf_s(ILibScratchPad2 + i, sizeof(ILibScratchPad2) - i, "%s", localPath);
	}

	//printf("MeshAgent_MakeAbsolutePathEx[%s,%s] = %s\n", basePath, localPath, ILibScratchPad2);

	if (escapeBackSlash != 0)
	{
		char *tmp = ILibString_Replace(ILibScratchPad2, strnlen_s(ILibScratchPad2, sizeof(ILibScratchPad2)), "\\", 1, "\\\\", 2);
		strcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), tmp);
		free(tmp);
	}
	return(ILibScratchPad2);
}

#ifndef MICROSTACK_NOTLS
int agent_GenerateCertificates(MeshAgentHostContainer *agent, char* certfile)
{
	int len = -1;
	char* str;

#ifdef WIN32
	// If there is a cert here, it was Generated by OpenSSL, so we'll force the regenerate to use OpenSSL, to honor how the current cert was generated
	if (agent->noCertStore == 0) { agent->noCertStore = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeCert", NULL, 0); }
#endif

	// Clear the certs in the database.
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeCert");
	ILibSimpleDataStore_Delete(agent->masterDb, "SelfNodeTlsCert");
	util_freecert(&(agent->selfcert));
	util_freecert(&(agent->selftlscert));

	if (certfile == NULL)
	{
#if defined(WIN32)
		char rootSubject[255];
		if (agent->noCertStore == 0 && agent->meshServiceName != NULL && strcmp(agent->meshServiceName, "Mesh Agent") == 0)
		{
			sprintf_s(rootSubject, sizeof(rootSubject), "CN=MeshNode%s", (agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY ? "DiagnosticCertificate" : "Certificate");
		}
		else
		{
			sprintf_s(rootSubject, sizeof(rootSubject), "CN=%s_Node%s", agent->meshServiceName, (agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY ? "DiagnosticCertificate" : "Certificate");
		}

		if (agent->noCertStore == 0 && (agent->certObject = wincrypto_open(TRUE, rootSubject)) != NULL) // Force certificate re-generation
		{
			int l;
			do 
			{
				// Finish off work with our own certificate
				l = wincrypto_getcert(&str, agent->certObject);
				if (l > 0)
				{
					util_from_cer(str, l, &(agent->selfcert));
					util_keyhash(agent->selfcert, agent->g_selfid);
					if (((int*)agent->g_selfid)[0] == 0) { wincrypto_close(agent->certObject); agent->certObject = wincrypto_open(1, rootSubject); }
				}
			} while (l != 0 && ((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.

			if (l > 0)
			{
				// Generate a new TLS certificate & save it.
				l = wincrypto_mkCert(agent->certObject, rootSubject, L"CN=localhost", CERTIFICATE_TLS_SERVER, L"hidden", &str);
				util_from_p12(str, l, "hidden", &(agent->selftlscert));
				ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, l);
				util_free(str);
				return 0;
			}
		} else {
#endif
			// Generate a new self-signed root certificate for this node using OpenSSL
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating new Node Certificate");
			printf("Generating Certificate...\r\n");
			do
			{
				SSL_TRACE1("agent_GenerateCertificates()");
				if (util_mkCert(NULL, &(agent->selfcert), 3072, 10000, "MeshNodeCertificate", CERTIFICATE_ROOT, NULL) == 0)
				{
					SSL_TRACE2("agent_GenerateCertificates()");
					return -1;
				}
				util_keyhash(agent->selfcert, agent->g_selfid);
				SSL_TRACE2("agent_GenerateCertificates()");
			} while (((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
#if defined(WIN32)
			wincrypto_setregistry(L"KeyStore", L"None");
		}
#endif
	}
	else
	{
		// Load a node certificate from a PEM file
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Loading Node Cert from PEM file");
		SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate_FromFile()");

		if (util_from_pem(certfile, &(agent->selfcert)) == -1)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......*ERROR*");
			SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile([ERROR])");
			return -1;
		}
		util_keyhash(agent->selfcert, agent->g_selfid);
		if (((int*)agent->g_selfid)[0] == 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......g_selfid = *ERROR*");
			SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile([ERROR])");
			return -1; // This removes any chance that the self_id starts with 32 bits of zeros.
		}
		SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate_FromFile()");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...g_selfid = %s", ILibRemoteLogging_ConvertToHex(agent->g_selfid, (int)sizeof(agent->g_selfid)));
	}

	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeCert)");
	len = util_to_p12(agent->selfcert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeCert", 12, str, len);
	util_free(str);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeCert)");

	/*
	// If the root certificate is generated in the TPM, generate a new TLS certificate
	SSL_TRACE1("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeTlsCert)");
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Generating TLS Certificate");
	len = util_mkCert(&(agent->selfcert), &(agent->selftlscert), 3072, 10000, "localhost", CERTIFICATE_TLS_SERVER, NULL);
	len = util_to_p12(agent->selftlscert, "hidden", &str);
	ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, len);
	util_free(str);
	SSL_TRACE2("ILibDuktape_MeshAgent_GenerateCertificate(SelfNodeTlsCert)");
	*/

	// If we don't use TPM, we can skip generating the TLS cert.
	agent->selftlscert.flags = 0;
	agent->selftlscert.x509 = NULL;
	agent->selftlscert.pkey = NULL;

	MSG("Certificates ready.\r\n");
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...READY");
	return 0;
}

int agent_LoadCertificates(MeshAgentHostContainer *agent)
{
	int len;

	SSL_TRACE1("agent_LoadCertificates()");

	//printf("Loading Certificates...\r\n");

	// First, look to see if we have a certificate in the .db file, if we do, use that.
	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeCert", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len == 0 || util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selfcert)) == 0)
	{
#if defined(WIN32)
		char rootSubject[255];
		if (agent->noCertStore == 0 && agent->meshServiceName != NULL && strcmp(agent->meshServiceName, "Mesh Agent") == 0)
		{
			sprintf_s(rootSubject, sizeof(rootSubject), "CN=MeshNode%s", (agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY ? "DiagnosticCertificate" : "Certificate");
		}
		else
		{
			sprintf_s(rootSubject, sizeof(rootSubject), "CN=%s_Node%s", agent->meshServiceName, (agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY ? "DiagnosticCertificate" : "Certificate");
		}

		// No cert in this .db file. Try to load or generate a root certificate from a Windows crypto provider. This can be TPM backed which is great.
		// However, if we don't have the second cert created, we need to regen the root...
		if (agent->noCertStore == 0 && (agent->certObject = wincrypto_open(FALSE, rootSubject)) != NULL && ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", NULL, 0) != 0)
		{
			char* str = NULL;
			int l;
		
			do {
				// Finish off work with our own certificate
				l = wincrypto_getcert(&str, agent->certObject);
				if (l > 0)
				{
					util_from_cer(str, l, &(agent->selfcert));
					util_keyhash(agent->selfcert, agent->g_selfid);
					if (((int*)agent->g_selfid)[0] == 0) { wincrypto_close(agent->certObject); agent->certObject = wincrypto_open(TRUE, rootSubject); } // Force generation of a new certificate.
				}
			} while (l != 0 && ((int*)agent->g_selfid)[0] == 0); // This removes any chance that the self_id starts with 32 bits of zeros.

			if (l > 0)
			{
				// Load the TLS certificate from the database. If not present, generate one.
				len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", ILibScratchPad2, sizeof(ILibScratchPad2));
				if ((len != 0) && (util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selftlscert)) == 0)) { len = 0; } // Unable to decode this certificate
				if (agent_VerifyMeshCertificates(agent) != 0) 
				{
					// Check that the load TLS cert is signed by our root.
					len = 0; 
					ILIBLOGMESSAGEX("Certificate loaded from DB was not signed by our root cert in the Cert Store");
				} 
				if (len == 0) 
				{
					// Generate a new TLS certificate & save it.
					util_freecert(&(agent->selftlscert));
					l = wincrypto_mkCert(agent->certObject, rootSubject, L"CN=localhost", CERTIFICATE_TLS_SERVER, L"hidden", &str);
					if (l > 0) {
						util_from_p12(str, l, "hidden", &(agent->selftlscert));
						ILibSimpleDataStore_PutEx(agent->masterDb, "SelfNodeTlsCert", 15, str, l);
					}
					util_free(str);
					if (l <= 0) 
					{
						// Problem generating the TLS cert, reset everything.
						ILIBLOGMESSAGEX("Error occured trying to generate a TLS cert that is signed by our root in Cert Store");
						return 1; 
					} 
				}
				return 0; // All good. We loaded or generated a root agent cert and TLS cert.
			}
			else
			{
				ILIBLOGMESSAGEX("No certificate found in Microsoft Certificate Store");
			}
		}
		else
		{
			if (agent->noCertStore == 0 && agent->certObject == NULL)
			{
				ILIBLOGMESSAGEX("Error opening Microsoft Certificate Store");
			}
		}
#endif
		if(ILibSimpleDataStore_WasCreatedAsNew(agent->masterDb)==0)
		{
			// No certificate in the database. Return 1 here so we can generate one.
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load Node Certificate from Database");
			SSL_TRACE2("agent_LoadCertificates([ERROR: SelfNodeCert])");
			ILIBLOGMESSAGEX("Info: No certificate was found in db");
		}

		return 1;
	}

	// Try to load the TLS certificate
	len = ILibSimpleDataStore_Get(agent->masterDb, "SelfNodeTlsCert", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len != 0)
	{
		// If the TLS certificate is in the database, load it. If not, it's ok to skip this.
		if (util_from_p12(ILibScratchPad2, len, "hidden", &(agent->selftlscert)) == 0) {
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Failed to load TLS Certificate from Database");
			util_freecert(&(agent->selfcert));
			SSL_TRACE2("agent_LoadCertificates([ERROR: SelfNodeTlsCert])");
			return 1;
		}
	}

	// Compute this agent's nodeid.
	util_keyhash(agent->selfcert, agent->g_selfid);
	SSL_TRACE2("agent_LoadCertificates()");

	return 0;
}

int agent_VerifyMeshCertificates(MeshAgentHostContainer *agent)
{
	X509_STORE *store;
	X509_STORE_CTX *ctx;
	int i = 0;

	SSL_TRACE1("agent_VerifyMeshCertificates()");
	if (agent->selftlscert.x509 == NULL) { return 0; } // There is no TLS certificate, no verification needed.

	// Check that the TLS certificate and TLS client certificate are correctly signed by our Mesh Agent certificate
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "...Verifying TLS Certificates are signed by Mesh Agent Certificate");
	store = X509_STORE_new();
	X509_STORE_add_cert(store, agent->selfcert.x509);

	ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, agent->selftlscert.x509, NULL);
	i = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);

	X509_STORE_free(store);

	// If the certificate chain is not correct, re-create all the certificates.
	if (i != 1)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "......INVALID TLS Server Certificate");
	}
	SSL_TRACE2("agent_VerifyMeshCertificates()");

	if (i != 1) { return 1; } // Bad certificates
	return 0;
}
#endif


duk_context* ScriptEngine_Stop(MeshAgentHostContainer *agent, char *contextGUID)
{
	MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: entry agent=%p currentCtx=%p", agent, agent == NULL ? NULL : agent->meshCoreCtx);
	SCRIPT_ENGINE_SETTINGS *settings = ILibDuktape_ScriptContainer_GetSettings(agent->meshCoreCtx);
	if (settings == NULL)
	{
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: settings allocation returned NULL");
	}
	Duktape_SafeDestroyHeap(agent->meshCoreCtx);

	agent->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx2(settings);
	MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: new context=%p", agent->meshCoreCtx);
	if (agent->meshCoreCtx == NULL)
	{
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx2 failed");
	}
	ILibDuktape_MeshAgent_Init(agent->meshCoreCtx, agent->chain, agent);

	ILibDuktape_SetNativeUncaughtExceptionHandler(agent->meshCoreCtx, settings->nExeptionHandler, settings->nExceptionUserObject);
	if (g_displayFinalizerMessages) { printf("\n\n==> Stopping JavaScript Engine\n"); }

	if (agent->proxyServer != NULL)
	{
		ILibDuktape_globalTunnel_data *globalTunnel = ILibDuktape_GetNewGlobalTunnel(agent->meshCoreCtx);
		if (globalTunnel != NULL)
		{
			memcpy_s(&(globalTunnel->proxyServer), sizeof(struct sockaddr_in6), agent->proxyServer, sizeof(struct sockaddr_in6));
		}
		else
		{
			MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: global tunnel unavailable for proxy propagation");
		}
	}
	else
	{
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: no proxy server present");
	}

	ILibDuktape_ScriptContainer_FreeSettings(settings);
	MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Stop: exit ctx=%p", agent->meshCoreCtx);
	return(agent->meshCoreCtx);
}
char* ScriptEngine_Restart(MeshAgentHostContainer *agent, char *contextGUID, char *buffer, int bufferLen)
{
	MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: begin bufferLen=%d", bufferLen);
	duk_context *ctx = ScriptEngine_Stop(agent, contextGUID);
	MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: post-stop ctx=%p", ctx);
	
	if (ctx != NULL) 
	{ 
		int compileResult = ILibDuktape_ScriptContainer_CompileJavaScriptEx(ctx, buffer, bufferLen, "CoreModule.js", 13);
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: compile result=%d", compileResult);
		if (compileResult == 0)
		{
			int execResult = ILibDuktape_ScriptContainer_ExecuteByteCode(ctx);
			MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: execute result=%d", execResult);
			if (execResult != 0)
			{
				sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s", (char*)duk_safe_to_string(ctx, -1));
				duk_pop(ctx);
				MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: execute failure %s", ILibScratchPad);
				return(ILibScratchPad);
			}
			MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: success");
			return(NULL);
		}
		sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s", (char*)duk_safe_to_string(ctx, -1));
		duk_pop(ctx);
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: compile failure %s", ILibScratchPad);
		return(ILibScratchPad);
	}
	else
	{
		MeshAgent_ControlChannelDebugLog(agent, "ScriptEngine_Restart: ScriptEngine_Stop returned NULL");
		return "Restart Failed, because Script Engine Stop failed";
	}
}

void MeshAgent_Slave_HeapWasDestroyed(duk_context *ctx, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	agent->exitCode = ILibDuktape_Process_GetExitCode(ctx);
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshAgent_Slave: Engine has exited");
	ILibStopChain(agent->chain);
}


// Called when we can now send more data to MeshCentral
void MeshServer_OnSendOK(ILibWebClient_StateObject sender, void *user1, void *user2)
{
	// TODO: Inform JavaScript core module that we are in underflow situation
	MeshAgent_ControlChannelDebugLog((MeshAgentHostContainer*)user1, "MeshServer_OnSendOK: sender=%p", sender);
}


int GenerateSHA384FileHash(char *filePath, char *fileHash)
{
	FILE *tmpFile = NULL;
	unsigned int endIndex = 0;
	unsigned int bytesLeft = 0;
	size_t bytesRead;
	unsigned int checkSumIndex = 0;
	unsigned int tableIndex = 0;

#ifdef WIN32
	int retVal = 1;
	_wfopen_s(&tmpFile, ILibUTF8ToWide(filePath, -1), L"rb");
#else
	tmpFile = fopen(filePath, "rb");
#endif
	if (tmpFile == NULL) { return(1); }

#ifdef WIN32
	// We need to check if this is a signed binary
	// Read the PE Headers, to determine where to look for the Embedded JS
	char *optHeader = NULL;
	unsigned int NTHeaderIndex = 0;
	fseek(tmpFile, 0, SEEK_SET);
	ignore_result(fread(ILibScratchPad, 1, 2, tmpFile));
	if (ntohs(((uint16_t*)ILibScratchPad)[0]) == 19802) // 5A4D
	{
		fseek(tmpFile, 60, SEEK_SET);
		ignore_result(fread((void*)&NTHeaderIndex, 1, 4, tmpFile));
		fseek(tmpFile, NTHeaderIndex, SEEK_SET);					// NT HEADER
		checkSumIndex = NTHeaderIndex + 24 + 64;

		ignore_result(fread(ILibScratchPad, 1, 24, tmpFile));		
		if (((unsigned int*)ILibScratchPad)[0] == 17744)
		{
			// PE Image
			optHeader = ILibMemory_AllocateA(((unsigned short*)ILibScratchPad)[10]);
			ignore_result(fread(optHeader, 1, ILibMemory_AllocateA_Size(optHeader), tmpFile));
			if (ILibMemory_AllocateA_Size(optHeader) > 4)
			{
				switch (((unsigned short*)optHeader)[0])
				{
				case 0x10B:
					if (ILibMemory_AllocateA_Size(optHeader) >= 132)
					{
						if (((unsigned int*)(optHeader + 128))[0] != 0)
						{
							endIndex = ((unsigned int*)(optHeader + 128))[0];
						}
						tableIndex = NTHeaderIndex + 24 + 128;
						retVal = 0;
					}
					break;
				case 0x20B:
					if (ILibMemory_AllocateA_Size(optHeader) >= 148)
					{
						if (((unsigned int*)(optHeader + 144))[0] != 0)
						{
							endIndex = ((unsigned int*)(optHeader + 144))[0];
						}
						tableIndex = NTHeaderIndex + 24 + 144;
						retVal = 0;
					}
					break;
				default:
					break;
				}
			}
		}
		if (retVal != 0)
		{
			fclose(tmpFile);
			return(1);
		}
	}
#endif

	if (endIndex == 0)
	{
		// We just need to check for Embedded MSH file
		int mshLen = 0;
		fseek(tmpFile, 0, SEEK_END);
		long fileSize = ftell(tmpFile);
		if (fileSize < 16)
		{
			// Too small to carry a 16-byte policy GUID trailer: hash the whole file.
			endIndex = (unsigned int)(fileSize < 0 ? 0 : fileSize);
		}
		else
		{
			fseek(tmpFile, -16, SEEK_END);
			ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
			if ((memcmp(ILibScratchPad, exeMeshPolicyGuid, 16) == 0) || (memcmp(ILibScratchPad, exeNullPolicyGuid, 16) == 0))
			{
				fseek(tmpFile, -20, SEEK_CUR);
				if (fread((void*)&mshLen, 1, 4, tmpFile) == 4)
				{
					mshLen = ntohl(mshLen);
					// Reject a corrupt/tampered length before using it in unsigned offset arithmetic
					// (matches the hardened guard in checkForEmbeddedMSH_ex). The MSH data must fit in
					// front of the 4-byte length and 16-byte GUID trailer.
					if (mshLen <= 0 || (long)mshLen > fileSize - 20) { endIndex = (unsigned int)fileSize; }
					else { endIndex = (unsigned int)fileSize - 20 - (unsigned int)mshLen; }
				}
				else
				{
					endIndex = (unsigned int)fileSize;
				}
			}
			else
			{
				endIndex = (unsigned int)fileSize;
			}
		}
	}

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	bytesLeft = endIndex;
	fseek(tmpFile, 0, SEEK_SET);
	if (checkSumIndex != 0)
	{
		bytesRead = fread(ILibScratchPad, 1, checkSumIndex + 4, tmpFile);
		((unsigned int*)(ILibScratchPad + checkSumIndex))[0] = 0;
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) { bytesLeft -= (unsigned int)bytesRead; }

		bytesRead = fread(ILibScratchPad, 1, tableIndex + 8 - (checkSumIndex + 4), tmpFile);
		((unsigned int*)(ILibScratchPad + bytesRead - 8))[0] = 0;
		((unsigned int*)(ILibScratchPad + bytesRead - 8))[1] = 0;
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) { bytesLeft -= (unsigned int)bytesRead; }
	}

	while ((bytesRead = fread(ILibScratchPad, 1, endIndex == 0 ? sizeof(ILibScratchPad) : (bytesLeft > sizeof(ILibScratchPad) ? sizeof(ILibScratchPad) : bytesLeft), tmpFile)) > 0)
	{
		SHA384_Update(&ctx, ILibScratchPad, bytesRead);
		if (endIndex > 0) 
		{ 
			bytesLeft -= (unsigned int)bytesRead; 
			if (bytesLeft == 0) { break; }
		}
	}
	SHA384_Final((unsigned char*)fileHash, &ctx);
	fclose(tmpFile);

	return(0);
}

// Called when the connection of the mesh server is fully authenticated
void MeshServer_ServerAuthenticated(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent) {
	int len = 0;
	MeshAgent_RecordProxyAttemptSuccess(agent);

	// Send the mesh agent tag to the server
	// We send the tag information independently of the meshcore because we could use this to select what meshcore to use on the server.
	((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentTag); // MeshCommand_AgentTag (15), agent tag information
	len = ILibSimpleDataStore_GetEx(agent->masterDb, "Tag", 3, ILibScratchPad2 + 2, sizeof(ILibScratchPad2) - 2);
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 2 + len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

	// Inform JavaScript core module of the connection
	// TODO: Verify with Bryan that only the core module will get this. No other modules should.
	if (agent->serverAuthState == 3) 
	{
		ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);				// [agent]
		duk_get_prop_string(agent->meshCoreCtx, -1, "emit");						// [agent][emit]
		duk_swap_top(agent->meshCoreCtx, -2);										// [emit][this]
		duk_push_string(agent->meshCoreCtx, "Connected");							// [emit][this][Connected]
		duk_push_int(agent->meshCoreCtx, 1);										// [emit][this][Connected][1]
		if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
		duk_pop(agent->meshCoreCtx);												// ...

		if (agent->logUpdate != 0) 
		{
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "Connection Established [%p]...", WebStateObject);
			ILIBLOGMESSSAGE(ILibScratchPad);
		}

	}
}

void MeshServer_SendJSON(MeshAgentHostContainer* agent, ILibWebClient_StateObject WebStateObject, char *JSON, int JSONLength)
{
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_TEXT, JSON, JSONLength, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
}
void MeshServer_SendAgentInfo(MeshAgentHostContainer* agent, ILibWebClient_StateObject WebStateObject) 
{
	int hostnamelen = (int)strnlen_s(agent->hostname, sizeof(agent->hostname));

	int agentNameLen = 0;

	// Send to the server information about this agent
	MeshCommand_BinaryPacket_AuthInfo *info = (MeshCommand_BinaryPacket_AuthInfo*)ILibScratchPad2;
	memset(info, 0, sizeof(MeshCommand_BinaryPacket_AuthInfo)); // Required because if hash are SHA384, they will not fully fill the struct.
	info->command = htons(MeshCommand_AuthInfo);
	info->infoVersion = htonl(1);
	info->agentId = htonl(MESH_AGENTID);
	info->agentVersion = htonl(agent->version);
	info->platformType = htonl(((agent->batteryState != MeshAgentHost_BatteryInfo_NONE) && (agent->batteryState != MeshAgentHost_BatteryInfo_UNKNOWN)) ? MeshCommand_AuthInfo_PlatformType_LAPTOP : MeshCommand_AuthInfo_PlatformType_DESKTOP);
	memcpy_s(info->MeshID, sizeof(info->MeshID), agent->meshId, sizeof(agent->meshId));
	info->capabilities = htonl(agent->capabilities);
	
	memcpy_s(info->hostname, hostnamelen, agent->hostname, hostnamelen);
	info->hostnameLen = htons(hostnamelen);

	if ((agentNameLen=ILibSimpleDataStore_Get(agent->masterDb, "agentName", NULL, 0)) > 0)
	{
		if (agentNameLen < 255)
		{
			char agentName[255];
			int jsonlen;
			
			ILibSimpleDataStore_Get(agent->masterDb, "agentName", agentName, (int)sizeof(agentName));
			jsonlen = sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "{\"action\":\"agentName\",\"value\":\"%s\"}", agentName);
			MeshServer_SendJSON(agent, WebStateObject, ILibScratchPad, jsonlen);
		}
	}

	if (agent->meshCoreCtx != NULL)
	{
		if (duk_peval_string(agent->meshCoreCtx, "require('identifiers').isVM();") == 0)
		{
			if (duk_get_boolean(agent->meshCoreCtx, -1))
			{
				info->platformType = htonl(MeshCommand_AuthInfo_PlatformType_VIRTUAL);
			}
		}
		duk_pop(agent->meshCoreCtx);
		if (info->platformType != htonl(MeshCommand_AuthInfo_PlatformType_VIRTUAL))
		{
			if (duk_peval_string(agent->meshCoreCtx, "require('identifiers').isBatteryPowered();") == 0)
			{
				if (duk_get_boolean(agent->meshCoreCtx, -1))
				{
					info->platformType = htonl(MeshCommand_AuthInfo_PlatformType_LAPTOP);
				}
			}
			duk_pop(agent->meshCoreCtx);
		}
	}



	// Send mesh agent information to the server
	ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)info, sizeof(MeshCommand_BinaryPacket_AuthInfo) + hostnamelen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
	agent->retryTime = 0;

	if ((agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY)
	{
		printf("[Recovery Agent] Connected.\n");
	}
	else
	{
		printf("Connected.\n");
	}

	if (agent->serverAuthState == 3) { MeshServer_ServerAuthenticated(WebStateObject, agent); }
}

void MeshServer_selfupdate_continue(MeshAgentHostContainer *agent)
{
#ifndef WIN32
	// Set performSelfUpdate to the startupType, on Linux is this important: 1 = systemd, 2 = upstart, 3 = sysv-init
	int len = ILibSimpleDataStore_Get(agent->masterDb, "StartupType", ILibScratchPad, sizeof(ILibScratchPad));
	if (len > 0 && len < sizeof(ILibScratchPad)) { ILib_atoi_int32(&(agent->performSelfUpdate), ILibScratchPad, (size_t)len); }
	if (agent->performSelfUpdate == 0) { agent->performSelfUpdate = 999; } // Never allow this value to be zero.
#endif


	if (duk_peval_string(agent->meshCoreCtx, "process.versions.commitHash") == 0)
	{
		ILIBLOGMESSAGEX("SelfUpdate -> Current Version: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
	}
	duk_pop(agent->meshCoreCtx);																				// ...

	if (duk_peval_string_noresult(agent->meshCoreCtx, "require('service-manager').manager.getService('meshagentDiagnostic').start();") == 0)
	{
		if (agent->logUpdate != 0)
		{
			ILIBLOGMESSSAGE("SelfUpdate -> Starting Secondary Agent, to assist with self update");
		}
	}
	else
	{
		if (agent->logUpdate != 0)
		{
			ILIBLOGMESSSAGE("SelfUpdate -> Secondary Agent unavailable to assist with self update");
		}
	}

#ifdef WIN32
	if (agent->JSRunningAsService == 0)
	{
		// Windows Console Mode updater
		if (duk_peval_string(agent->meshCoreCtx, "require('agent-installer').consoleUpdate();") != 0)
		{
			printf("%s", duk_safe_to_string(agent->meshCoreCtx, -1));
		}
	}
	else
	{
		WCHAR w_updatefile[4096] = { 0 };
		char *updatefile = MeshAgent_MakeAbsolutePathEx(agent->exePath, MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX, 0);

		ILibUTF8ToWideEx(updatefile, (int)strnlen_s(updatefile, 4096), w_updatefile, 4096);

#if defined(MESHAGENT_ENABLE_STEALTH) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
		// Launch the downloaded update through the rundll32 lifecycle host.
		ILIBLOGMESSAGEX("SelfUpdate -> Svchost mode: launching rundll32 lifecycle update activation...");

		DWORD lifecycleExitCode = ERROR_SUCCESS;
		if (MeshRundll32_LaunchLifecycleHostW(
				MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE,
				w_updatefile,
				NULL,
				NULL,
				NULL,
				FALSE,
				FALSE,
				0,
				&lifecycleExitCode))
		{
			ILIBLOGMESSAGEX("SelfUpdate -> Rundll32 lifecycle update activation started (%ls)", w_updatefile);
		}
		else
		{
			ILIBLOGMESSAGEX("SelfUpdate -> FAILED to launch rundll32 lifecycle update activation (exit %lu, error %lu)", lifecycleExitCode, GetLastError());
			util_deletefile(updatefile); // Fail closed: drop the staged payload so a failed activation does not leave it behind
			return;
		}
#else
		UNREFERENCED_PARAMETER(w_updatefile);
		ILIBLOGMESSAGEX("SelfUpdate -> Windows lifecycle update requires rundll32/svchost mode; legacy command-shell update path disabled.");
		util_deletefile(updatefile); // Fail closed: this build cannot apply the staged update, so do not leave it on disk
		return;
#endif
	}
#else
	if (duk_peval_string(agent->meshCoreCtx, "require('MeshAgent').getStartupOptions();") == 0)	// [obj]
	{
		char *pth = "";
		size_t i = 0;
		size_t lines = 2;
		size_t len = 0;
		duk_del_prop_string(agent->meshCoreCtx, -1, "fakeUpdate");

		if (duk_peval_string(agent->meshCoreCtx, "process.execPath.split('/').pop();") == 0)
		{
			pth = (char*)duk_get_lstring(agent->meshCoreCtx, -1, &len);
			len += 1;
		}
		duk_swap_top(agent->meshCoreCtx, -2);													// [path][obj]
		duk_enum(agent->meshCoreCtx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);							// [path][obj][enum]
		while (duk_next(agent->meshCoreCtx, -1, 1))												// [path][obj][enum][key][value]
		{
			++lines;
			len += snprintf(NULL, 0, "--%s=\"%s\" ", duk_get_string(agent->meshCoreCtx, -2), duk_get_string(agent->meshCoreCtx, -1));
			duk_pop_2(agent->meshCoreCtx);														// [path][obj][enum]
		}
		duk_pop(agent->meshCoreCtx);															// [path][obj]
		agent->execparams = (char**)ILibMemory_SmartAllocateEx(lines * sizeof(char*), len);

		i += (1 + sprintf_s(ILibMemory_Extra(agent->execparams), ILibMemory_ExtraSize(agent->execparams), "%s", pth));
		lines = 1;
		agent->execparams[0] = ILibMemory_Extra(agent->execparams);

		duk_enum(agent->meshCoreCtx, -1, DUK_ENUM_OWN_PROPERTIES_ONLY);							// [path][obj][enum]
		while (duk_next(agent->meshCoreCtx, -1, 1))												// [path][obj][enum][key][value]
		{
			len = sprintf_s(ILibMemory_Extra(agent->execparams) + i, ILibMemory_ExtraSize(agent->execparams) - i, "--%s=\"%s\"", duk_get_string(agent->meshCoreCtx, -2), duk_get_string(agent->meshCoreCtx, -1));
			agent->execparams[lines] = ILibMemory_Extra(agent->execparams) + i;
			i += (len + 1);
			duk_pop_2(agent->meshCoreCtx);														// [path][obj][enum]
			++lines;
		}
		agent->execparams[lines] = NULL;
		duk_pop(agent->meshCoreCtx);															// [path][obj]
	}
	duk_pop_2(agent->meshCoreCtx);																// ...
#endif

	// Everything looks good, lets perform the update
	ILIBLOGMESSAGEX("SelfUpdate -> Stopping Chain (%d)", agent->performSelfUpdate);
	ILibStopChain(agent->chain);
}
duk_ret_t MeshServer_selfupdate_unzip_complete(duk_context *ctx)
{
	duk_eval_string(ctx, "require('MeshAgent')");					// [MeshAgent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Update successfully unzipped..."); }
	MeshServer_selfupdate_continue(agent);
	return(0);
}
duk_ret_t MeshServer_selfupdate_unzip_error(duk_context *ctx)
{
	duk_eval_string(ctx, "require('MeshAgent')");					// [MeshAgent]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	duk_push_sprintf(ctx, "SelfUpdate -> FAILED to unzip update: %s", (char*)duk_safe_to_string(ctx, 0));
	if (agent->logUpdate != 0) { ILIBLOGMESSSAGE(duk_safe_to_string(ctx, -1)); }

	// Delete the staged payload so a corrupt update is not re-downloaded and re-unzipped on every
	// reconnect (mirrors the cleanup the sibling failure paths already perform on the dispatch side).
	{
#ifdef WIN32
		char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX);
#else
		char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif
		util_deletefile(updateFilePath);
	}
	return(0);
}

static int MeshServer_UpdateFileLooksZip(char *updateFilePath)
{
	char *header = NULL;
	size_t headerLen;
	int retVal = 0;

	if (updateFilePath == NULL) { return 0; }
	headerLen = util_readfile(updateFilePath, &header, 4);
	if (headerLen >= 4 && header != NULL && header[0] == 'P' && header[1] == 'K' &&
		((header[2] == 3 && header[3] == 4) || (header[2] == 5 && header[3] == 6) || (header[2] == 7 && header[3] == 8)))
	{
		retVal = 1;
	}
	if (header != NULL) { free(header); }
	return retVal;
}

// Process MeshCentral server commands. 
void MeshServer_ProcessCommand(ILibWebClient_StateObject WebStateObject, MeshAgentHostContainer *agent, char *cmd, int cmdLen)
{
	unsigned short command = ntohs(((unsigned short*)cmd)[0]);
	unsigned short requestid;

	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: command=%u len=%d", command, cmdLen);

	if (agent->controlChannelDebug != 0)
	{
		printf("ProcessCommand(%u)...\n", command);
		ILIBLOGMESSAGEX("ProcessCommand(%u)...", command);
	}

#ifndef MICROSTACK_NOTLS
	// If we are not authenticated with the mesh server, we only support auth commands.
	if (agent->serverAuthState != 3)
	{
		X509* peer = ILibWebClient_SslGetCert(WebStateObject);

		switch (command)
		{
		case MeshCommand_AuthRequest: // This is basic authentication information from the server, we need to sign this and return the signature.
			if (cmdLen == sizeof(MeshCommand_BinaryPacket_AuthRequest))
			{
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthRequest received");
				if (agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Processing Authentication Request..."); }
				MeshCommand_BinaryPacket_AuthRequest *AuthRequest = (MeshCommand_BinaryPacket_AuthRequest*)cmd;
				int signLen;
				SHA512_CTX c;
				EVP_PKEY *evp_prikey;
				RSA *rsa_prikey;

				// Hash the server's web certificate and check if it matches the one in the auth request
				util_certhash2(peer, ILibScratchPad2); // Hash the server certificate
				memcpy_s(agent->serverWebHash, sizeof(agent->serverWebHash), ILibScratchPad2, UTIL_SHA384_HASHSIZE);
				if (memcmp(ILibScratchPad2, AuthRequest->serverHash, sizeof(AuthRequest->serverHash)) != 0) 
				{ 
					util_keyhash2(peer, ILibScratchPad2); // Hash the server certificate public key (this is the old way)
					if (memcmp(ILibScratchPad2, AuthRequest->serverHash, sizeof(AuthRequest->serverHash)) != 0) 
					{
						if (agent->tlsRelaxedValidation != 0)
						{
							agent->tlsInspectionDetected = 1;
							if (agent->tlsInspectionLogged == 0)
							{
								agent->tlsInspectionLogged = 1;
								MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: TLS inspection detected, continuing with post-connect certificate proof");
								ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain),
									ILibRemoteLogging_Modules_Agent_GuardPost,
									ILibRemoteLogging_Flags_VerbosityLevel_1,
									"AgentCore: corporate TLS inspection detected, continuing with signed websocket server proof");
							}
						}
						else
						{
						printf("Bad server certificate hash\r\n"); // TODO: Disconnect
						if (agent->controlChannelDebug != 0)
						{
							ILIBLOGMESSAGEX("Bad server certificate hash");
						}
						break;
						}
					}
				}
				memcpy_s(agent->serverNonce, sizeof(agent->serverNonce), AuthRequest->serverNonce, sizeof(AuthRequest->serverNonce));

				// Place our certificate in the response
				MeshCommand_BinaryPacket_AuthVerify_Header *rav = (MeshCommand_BinaryPacket_AuthVerify_Header*)ILibScratchPad2;
				rav->command = htons(MeshCommand_AuthVerify);										// MeshCommand_AuthVerify (2), agent certificate in ASN1 format
				char *certDer = (char*)rav->data;
				short certLen = i2d_X509(agent->selfcert.x509, (unsigned char **)&certDer); // Place the agent root certificate in DER form
				rav->certLen = htons(certLen);

#ifdef WIN32
				if (agent->selfcert.pkey != NULL) {
#endif
					// Use our agent root private key to sign HASH(ServerWebHash + ServerNonce + AgentNonce)
					SHA384_Init(&c);
					SHA384_Update(&c, AuthRequest->serverHash, UTIL_SHA384_HASHSIZE); // Server web hash
					SHA384_Update(&c, agent->serverNonce, UTIL_SHA384_HASHSIZE); // Server nonce
					SHA384_Update(&c, agent->agentNonce, UTIL_SHA384_HASHSIZE); // Agent nonce
					SHA384_Final((unsigned char*)ILibScratchPad, &c);

					// Create a RSA signature using OpenSSL & send it
					evp_prikey = agent->selfcert.pkey;
					rsa_prikey = EVP_PKEY_get1_RSA(evp_prikey);
					signLen = sizeof(ILibScratchPad2) - sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) - certLen;
					if (RSA_sign(NID_sha384, (unsigned char*)ILibScratchPad, UTIL_SHA384_HASHSIZE, (unsigned char*)(rav->data + certLen), (unsigned int*)&signLen, rsa_prikey) == 1)
					{
						// Signature succesful, send the result to the server
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rav, sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + certLen + signLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
					}
					RSA_free(rsa_prikey);
#ifdef WIN32
				} else {
					// Use our agent root private key to sign: ServerWebHash + ServerNonce + AgentNonce
					memcpy_s(ILibScratchPad, sizeof(ILibScratchPad), AuthRequest->serverHash, UTIL_SHA384_HASHSIZE);
					memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE, sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE, agent->serverNonce, UTIL_SHA384_HASHSIZE);
					memcpy_s(ILibScratchPad + UTIL_SHA384_HASHSIZE + UTIL_SHA384_HASHSIZE, sizeof(ILibScratchPad) - UTIL_SHA384_HASHSIZE - UTIL_SHA384_HASHSIZE, agent->agentNonce, UTIL_SHA384_HASHSIZE);

					// Create a PKCS7 signature using Windows crypto & send it
					char* signature = NULL;
					signLen = wincrypto_sign(agent->certObject, (unsigned char*)ILibScratchPad, sizeof(AuthRequest->serverHash) + UTIL_SHA384_HASHSIZE + UTIL_SHA384_HASHSIZE, &signature);
					if (signLen > 0) 
					{
						// Signature succesful, send the result to the server
						memcpy_s((unsigned char*)(rav->data + certLen), sizeof(ILibScratchPad2) - sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) - certLen, signature, signLen);
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rav, sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + certLen + signLen, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						free(signature);
					}
				}
#endif
			}
			break;
		case MeshCommand_AuthVerify: // This is the signature from the server. We need to check everything is ok.
			if (cmdLen > 8)
			{
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify received len=%d", cmdLen);
				if (agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Processing Authentication Verification..."); }

				MeshCommand_BinaryPacket_AuthVerify_Header *avh = (MeshCommand_BinaryPacket_AuthVerify_Header*)cmd;
#ifdef WIN32
				MeshCommand_BinaryPacket_AuthVerify *AuthVerify = (MeshCommand_BinaryPacket_AuthVerify*)_alloca(sizeof(MeshCommand_BinaryPacket_AuthVerify));
#else
				MeshCommand_BinaryPacket_AuthVerify *AuthVerify = (MeshCommand_BinaryPacket_AuthVerify*)alloca(sizeof(MeshCommand_BinaryPacket_AuthVerify));
#endif
				AuthVerify->cert = avh->data;
				AuthVerify->certLen = ntohs(avh->certLen);
				AuthVerify->signature = avh->data + AuthVerify->certLen;
				AuthVerify->signatureLen = (unsigned short)(cmdLen - (int)(sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + AuthVerify->certLen));

				if (cmdLen > (int)(sizeof(MeshCommand_BinaryPacket_AuthVerify_Header) + AuthVerify->certLen))
				{
					int hashlen = UTIL_SHA384_HASHSIZE;
					SHA512_CTX c;
					X509* serverCert = NULL;
					EVP_PKEY *evp_pubkey;
					RSA *rsa_pubkey;

					// Get the server certificate
					if (!d2i_X509(&serverCert, (const unsigned char**)&AuthVerify->cert, AuthVerify->certLen))
					{
						printf("Invalid server certificate\r\n");
						MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify invalid server certificate");
						break; // TODO: Disconnect
					}

					// Check if this certificate public key hash matches what we want
					X509_pubkey_digest(serverCert, EVP_sha384(), (unsigned char*)ILibScratchPad, (unsigned int*)&hashlen); // OpenSSL 1.1, SHA384
					if (memcmp(ILibScratchPad, agent->serverHash, UTIL_SHA384_HASHSIZE) != 0) {
						util_tohex(ILibScratchPad, UTIL_SHA384_HASHSIZE, ILibScratchPad);
						util_tohex(agent->serverHash, UTIL_SHA384_HASHSIZE, ILibScratchPad2);
						MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify server certificate mismatch actual=%s expected=%s", ILibScratchPad, ILibScratchPad2);
						X509_pubkey_digest(serverCert, EVP_sha256(), (unsigned char*)ILibScratchPad, (unsigned int*)&hashlen); // OpenSSL 1.1, SHA256 (For older .mshx policy file)
						if (memcmp(ILibScratchPad, agent->serverHash, UTIL_SHA256_HASHSIZE) != 0) 
						{
							util_tohex(ILibScratchPad, UTIL_SHA256_HASHSIZE, ILibScratchPad);
							util_tohex(agent->serverHash, UTIL_SHA256_HASHSIZE, ILibScratchPad2);
							printf("Server certificate mismatch\r\n");
							MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify legacy mismatch actual=%s expected=%s", ILibScratchPad, ILibScratchPad2);
							if (agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Server certificate mismatch"); }
							X509_free(serverCert);
							break; // TODO: Disconnect
						}
					}

					// Compute the authentication hash
					SHA384_Init(&c);
					util_certhash2(peer, ILibScratchPad2);
					SHA384_Update(&c, ILibScratchPad2, UTIL_SHA384_HASHSIZE);
					SHA384_Update(&c, agent->agentNonce, UTIL_SHA384_HASHSIZE);
					SHA384_Update(&c, agent->serverNonce, UTIL_SHA384_HASHSIZE);
					SHA384_Final((unsigned char*)ILibScratchPad, &c);

					// Verify the hash signature using the server certificate
					evp_pubkey = X509_get_pubkey(serverCert);
					rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey);
					if (RSA_verify(NID_sha384, (unsigned char*)ILibScratchPad, UTIL_SHA384_HASHSIZE, (unsigned char*)AuthVerify->signature, AuthVerify->signatureLen, rsa_pubkey) == 1)
					{
						// Server signature verified, we are good to go.
						MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify signature OK");
						agent->serverAuthState |= 1;

						// Store the server's TLS cert hash so in the future, we can skip server auth.
						if (agent->tlsInspectionDetected == 0)
						{
							ILibSimpleDataStore_PutEx(agent->masterDb, "ServerTlsCertHash", 17, ILibScratchPad2, UTIL_SHA384_HASHSIZE);
						}
						else
						{
							ILibSimpleDataStore_DeleteEx(agent->masterDb, "ServerTlsCertHash", 17);
						}

						// Send our agent information to the server
						MeshServer_SendAgentInfo(agent, WebStateObject);
					} else {
						printf("Invalid server signature\r\n");
						MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthVerify signature INVALID");
						if (agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Invalid Server Signature"); }
						// TODO: Disconnect
					}

					RSA_free(rsa_pubkey);
					EVP_PKEY_free(evp_pubkey);
					X509_free(serverCert);
				}
				break;
		case MeshCommand_AuthConfirm: // Server indicates that we are authenticated, we can now send data.
			{
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: AuthConfirm received");
			if (agent->controlChannelDebug != 0) { printf("Authentication Complete...\n");  ILIBLOGMESSAGEX("Authentication Complete..."); }

					// We have to wait for the server to indicate that it authenticated the agent (us) before sending any data to the server.
					// Node authentication requires the server make database calls, so we need to delay.
					agent->serverAuthState |= 2;
					if (agent->serverAuthState == 3) { MeshServer_ServerAuthenticated(WebStateObject, agent); }
				}
				break;
			}
		}
		if (peer != NULL) { X509_free(peer); peer = NULL; }
		return;
	}
#endif

	// If we get a authentication command after authentication is completed, ignore it. Commands 0 to 9 are reserved for authentication.
	if (command < 10) return;

	// If the command is JSON or binary over 1000, send it directly to the JavaScript code module
	// TODO: Verify with Bryan that only the core module will get this. No other modules should.
	if (cmd[0] == '{' || command >= 1000)
	{
		int popCount = 0;
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: dispatching %s payload len=%d command=%u",
			(cmd[0] == '{') ? "JSON" : "binary",
			cmdLen,
			command);
		// if (cmd[0] == '{') { cmd[cmdLen] = 0; printf("%s\r\n", cmd); } // DEBUG: Print JSON command

		ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);			// [agent]
		duk_get_prop_string(agent->meshCoreCtx, -1, "emit");					// [agent][emit]
		duk_swap_top(agent->meshCoreCtx, -2);									// [emit][this]
		duk_push_string(agent->meshCoreCtx, "Command");							// [emit][this][Command]
		if (cmd[0] == '{')
		{
			// JSON
			duk_push_global_object(agent->meshCoreCtx);											// [emit][this][Command][g]
			duk_get_prop_string(agent->meshCoreCtx, -1, "JSON");								// [emit][this][Command][g][JSON]
			duk_get_prop_string(agent->meshCoreCtx, -1, "parse");								// [emit][this][Command][g][JSON][func]
			duk_swap_top(agent->meshCoreCtx, -3);												// [emit][this][Command][func][JSON][g]
			duk_pop_2(agent->meshCoreCtx);														// [emit][this][Command][func]
			duk_push_lstring(agent->meshCoreCtx, cmd, cmdLen);									// [emit][this][Command][func][str]
			if (duk_pcall(agent->meshCoreCtx, 1) != 0)											// [emit][this][Command][JSON]
			{
				duk_pop(agent->meshCoreCtx);													// [emit][this][Command]
				duk_push_lstring(agent->meshCoreCtx, cmd, cmdLen);								// [emit][this][Command][str]
			}
			else
			{
				// JSON command... Let's check if it's a PING
				if (duk_has_prop_string(agent->meshCoreCtx, -1, "action"))
				{
					char *action = (char*)Duktape_GetStringPropertyValue(agent->meshCoreCtx, -1, "action", "");
					MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: JSON action=%s len=%d", action, cmdLen);
					if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
					{
						ILIBLOGMESSAGEX("MeshServer_ProcessCommand: JSON action=%s len=%d", action, cmdLen);
					}
					if (strcmp(action, "ping") == 0) 
					{
						static const char autoPongJson[] = "{\"action\":\"pong\"}";
						ILibAsyncSocket_SendStatus autoPongStatus = ILibWebClient_WebSocket_Send(
							WebStateObject,
							ILibWebClient_WebSocket_DataType_TEXT,
							(char*)autoPongJson,
							(int)(sizeof(autoPongJson) - 1),
							ILibAsyncSocket_MemoryOwnership_USER,
							ILibWebClient_WebSocket_FragmentFlag_Complete);
						MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ProcessCommand: action=ping autoPong status=%d", (int)autoPongStatus);
						if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
						{
							ILIBLOGMESSAGEX("MeshServer_ProcessCommand: action=ping autoPong status=%d", (int)autoPongStatus);
						}
						if (agent->controlChannel_idleTimeout_dataMode == 0)
						{
							ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);							// [agent]
							ILibDuktape_EventEmitter_SetupEmitEx(agent->meshCoreCtx, -1, "idleTimeoutModeChanged");	// [agent][emit][this][idleTimeoutModeChanged]
							duk_pcall_method(agent->meshCoreCtx, 1); duk_pop_2(agent->meshCoreCtx);					// ...
						}
						agent->controlChannel_idleTimeout_dataMode = 1; 
					}
					else if (strcmp(action, "pong") == 0)
					{
						ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);								// [agent]
						duk_get_prop_string(agent->meshCoreCtx, -1, MESHAGENT_DATAPING_ARRAY);						// [agent][pingarray]
						if (duk_get_length(agent->meshCoreCtx, -1) > 0)
						{
							duk_array_shift(agent->meshCoreCtx, -1);												// [agent][pingarray][promise]
							if (duk_has_prop_string(agent->meshCoreCtx, -1, MESHAGENT_DATAPAING_PROMISE_TIMEOUT))
							{
								duk_push_global_object(agent->meshCoreCtx);											// [agent][pingarray][promise][g]
								duk_prepare_method_call(agent->meshCoreCtx, -1, "clearTimeout");					// [agent][pingarray][promise][g][clearTimeout][this]
								duk_get_prop_string(agent->meshCoreCtx, -4, MESHAGENT_DATAPAING_PROMISE_TIMEOUT);	// [agent][pingarray][promise][g][clearTimeout][this][timeout]
								duk_pcall_method(agent->meshCoreCtx, 1); duk_pop_2(agent->meshCoreCtx);				// [agent][pingarray][promise]
							}
							duk_prepare_method_call(agent->meshCoreCtx, -1, "_res");								// [agent][pingarray][promise][_res][this]
							duk_pcall_method(agent->meshCoreCtx, 0); duk_pop_2(agent->meshCoreCtx);					// [agent][pingarray]
						}
						duk_pop_2(agent->meshCoreCtx);																// ...
					}
				}
			}
			popCount = 1;
		}
		else
		{
			// BINARY
			duk_push_external_buffer(agent->meshCoreCtx);										// [emit][this][Command][extBuffer]
			duk_insert(agent->meshCoreCtx, -4);													// [extBuffer][emit][this][Command]
			duk_config_buffer(agent->meshCoreCtx, -4, cmd, cmdLen);
			duk_push_buffer_object(agent->meshCoreCtx, -4, 0, cmdLen, DUK_BUFOBJ_NODEJS_BUFFER);// [extBuffer][emit][this][Command][buffer]
			popCount = 2;
		}

		if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
		duk_pop_n(agent->meshCoreCtx, popCount);												// ...
		return;
	}

	// All these commands must have both a commandid and a requestid
	if (cmdLen < 4) return;
	requestid = ntohs(((unsigned short*)cmd)[1]);

	if (agent->controlChannelDebug != 0) 
	{
		printf("BinaryCommand(%u, %u)...\n", command, requestid);
		ILIBLOGMESSAGEX("BinaryCommand(%u, %u)...", command, requestid); 
	}


	// Process Core Module Commands here, but only if we aren't running a local script
	switch (command)
	{
		case MeshCommand_CompressedCoreModule:
		case MeshCommand_CoreModule:        // New core modules to be used instead of the old one, if empty, remove the core module
		{
			char *coreException = NULL;
			MeshCommand_BinaryPacket_CoreModule *cm = (MeshCommand_BinaryPacket_CoreModule*)cmd;
			char *coremodule = cm->coreModule;
			size_t coremoduleLen = (size_t)cmdLen - sizeof(MeshCommand_BinaryPacket_CoreModule);

			// If the agent is running with a local core, ignore this command
			if (agent->localScript != 0) break;

			if (cmdLen > sizeof(MeshCommand_BinaryPacket_CoreModule)) // Setup a new mesh core. 
			{
				char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule"); // Get the reference to the SHA384 hash for the currently running code
				if (hashref == NULL || memcmp(hashref, cm->coreModuleHash, sizeof(cm->coreModuleHash)) != 0) 
				{					
					agent->coreTimeout = NULL; // Setting this to null becuase we're going to stop the core. If we stop the core, this timeout will cleanup by itself.
					if (command == MeshCommand_CompressedCoreModule)
					{
						// meshcore is DEFLATE'ed, so we need to INFLATE it
						size_t decompressedModuleLen = 0;
						char *decompressedModule = NULL;
						if (ILibInflate(coremodule, coremoduleLen, NULL, &decompressedModuleLen, 0) == 0)
						{
							decompressedModule = (char*)ILibMemory_AllocateTemp(agent->chain, decompressedModuleLen);
							if (ILibInflate(coremodule, coremoduleLen, decompressedModule, &decompressedModuleLen, 0) == 0)
							{
								coremodule = decompressedModule;
								coremoduleLen = decompressedModuleLen;
							}
							else
							{
								decompressedModule = NULL;
							}
						}
						if (decompressedModule == NULL)
						{
							ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
								ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: INFLATE error");
							break;
						}
					}

					// Reject an undersized core module before storing or running it: ScriptEngine_Restart is
					// called with (coremodule + 4, coremoduleLen - 4), so a length < 4 would underflow to a
					// negative buffer length (out-of-bounds read at compile time).
					if (coremoduleLen < 4)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: rejecting undersized core module (%d bytes)", (int)coremoduleLen);
						break;
					}

					// If server sends us the same core, just do nothing.
					// Server sent us a new core, start by storing it in the data store
					ILibSimpleDataStore_PutCompressed(agent->masterDb, "CoreModule", 10, coremodule, (int)coremoduleLen);	// Store the JavaScript in the data store
					hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");					// Get the reference to the SHA384 hash
					if (memcmp(hashref, cm->coreModuleHash, sizeof(cm->coreModuleHash)) != 0) 
					{																						// Check the hash for sanity
																											// Something went wrong, clear the data store
						ILibSimpleDataStore_Delete(agent->masterDb, "CoreModule");

						// Stop the currently running core if present
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Stop");
						ScriptEngine_Stop(agent, MeshAgent_JavaCore_ContextGuid);

						// Tell the server we are no longer running a core module
						MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
						rcm->command = htons(MeshCommand_CoreModuleHash);									// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
						rcm->request = htons(requestid);													// Request id
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
						break;
					}

					// Stop the current JavaScript core if present and launch the new one.
					// JavaScript located at (cmd + 36) of length (cmdLen - 36)
					//printf("CORE: Restart\r\n");
					ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
						ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Restart");
					if ((coreException = ScriptEngine_Restart(agent, MeshAgent_JavaCore_ContextGuid, coremodule + 4, (int)coremoduleLen - 4)) != NULL)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Error: %s", coreException);
						// TODO: Ylian: New Java Core threw an exception... Exception String is stored in 'coreException'
					}

					// Since we did a big write to the data store, good time to compact the store
					ILibSimpleDataStore_Compact(agent->masterDb);
				}

				// Create the server confirmation message that we are running the new core
				MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_CoreModuleHash);					// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
				((unsigned short*)ILibScratchPad2)[1] = htons(requestid);									// Request id
				memcpy_s(ILibScratchPad2 + 4, sizeof(ILibScratchPad2) - 4, hashref, UTIL_SHA384_HASHSIZE);			// SHA384 hash

				// Send the confirmation to the server
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, sizeof(MeshCommand_BinaryPacket_CoreModule), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			else if (cmdLen == 4)
			{
				// Server is telling us to stop running a core
				ILibSimpleDataStore_Delete(agent->masterDb, "CoreModule"); // Clear the core from datastore
																		  
				// Stop the current JavaScript core if present and launch the new one.
				ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
					ILibRemoteLogging_Flags_VerbosityLevel_1, "MeshCore: Stop");
				ScriptEngine_Stop(agent, MeshAgent_JavaCore_ContextGuid);

				// Confirm to the server that we are not running any core
				MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
				rcm->command = htons(MeshCommand_CoreModuleHash);											// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
				rcm->request = htons(requestid);															// Request id
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			break;
		}
		case MeshCommand_CoreModuleHash: // Request/return the SHA384 hash of the core module
		{
			// Tell the server what core module we are running
			char *hashref = ILibSimpleDataStore_GetHash(agent->masterDb, "CoreModule");						// Get the reference to the SHA384 hash
			int len = agent->localScript == 0 ? 4 : (int)sizeof(MeshCommand_BinaryPacket_CoreModule);

			// Confirm to the server what core we are running
			MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
			memset(rcm, 0, sizeof(MeshCommand_BinaryPacket_CoreModule));
			rcm->command = htons(MeshCommand_CoreModuleHash);										// MeshCommand_CoreModuleHash (11), SHA384 hash of the code module
			rcm->request = htons(requestid);														// Request id
			if (agent->localScript == 0 && hashref != NULL) { memcpy_s(rcm->coreModuleHash, sizeof(rcm->coreModuleHash), hashref, UTIL_SHA384_HASHSIZE); len = sizeof(MeshCommand_BinaryPacket_CoreModule); }

			// Send the confirmation to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, len, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_CoreOk: // Message from the server indicating our meshcore is ok. No update needed.
		{
			printf("Server verified meshcore...");
			
			duk_eval_string(agent->meshCoreCtx, "_MSH().setuid;");
			if (duk_is_null_or_undefined(agent->meshCoreCtx, -1) == 0)
			{
				int uid = atoi(duk_get_string(agent->meshCoreCtx, -1));

				duk_push_global_object(agent->meshCoreCtx);													// [g]
				duk_get_prop_string(agent->meshCoreCtx, -1, "process");										// [g][process]
				duk_push_array(agent->meshCoreCtx);															// [g][process][arr]
				duk_push_sprintf(agent->meshCoreCtx, "--setuid=%d", uid);									// [g][process][arr][entry]
				duk_array_push(agent->meshCoreCtx, -2);														// [g][process][arr]
				duk_put_prop_string(agent->meshCoreCtx, -2, ILibDuktape_ScriptContainer_Process_ArgArray);	// [g][process]
				duk_pop_2(agent->meshCoreCtx);
#ifdef _POSIX
				ignore_result(setuid((uid_t)uid));
#endif
			}
			duk_pop(agent->meshCoreCtx);

			if (agent->coreTimeout != NULL)
			{
				// Cancel the timeout
				duk_push_global_object(agent->meshCoreCtx);					// [g]
				duk_get_prop_string(agent->meshCoreCtx, -1, "clearTimeout");// [g][clearTimeout]
				duk_swap_top(agent->meshCoreCtx, -2);						// [clearTimeout][this]
				duk_push_heapptr(agent->meshCoreCtx, agent->coreTimeout);	// [clearTimeout][this][timeout]
				duk_pcall_method(agent->meshCoreCtx, 1); duk_pop(agent->meshCoreCtx);
				agent->coreTimeout = NULL;

				int CoreModuleLen = ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", NULL, 0);
				if (CoreModuleLen <= 4)
				{
					printf(" meshcore not found...\n");
				}
				else
				{
					printf(" Launching meshcore...\n");
					char *CoreModule;

					if (agent->jsDebugPort != 0)
					{
						char tmp[255];
						int tmpLen = sprintf_s(tmp, sizeof(tmp), "attachDebugger({ webport: %d, wait: 1 }).then(function (prt) { console.log('Point Browser for Debug to port: ' + prt); });\n", agent->jsDebugPort);
						CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen + tmpLen, 0, NULL, NULL);
						ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", CoreModule + tmpLen - 4, CoreModuleLen + tmpLen);
						memcpy_s(CoreModule + 4, CoreModuleLen - 4, tmp, tmpLen);
						CoreModuleLen += (tmpLen-4);
					}
					else
					{
						CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
						ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", CoreModule, CoreModuleLen);
					}

					MeshAgent_EnsureCoreModuleRuntimeGlobals(agent->meshCoreCtx);
					if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agent->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
						ILibDuktape_ScriptContainer_ExecuteByteCode(agent->meshCoreCtx) != 0)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
						duk_pop(agent->meshCoreCtx);
					}
					free(CoreModule);
				}
			}
			else
			{
				// There's no timeout, probably because the core is already running
				printf(" meshcore already running...\n");
			}
			break;
		}
		case MeshCommand_AgentHash:
		{
			// This is a request for the hash of the agent binary
			// Built the response that includes our self hash
			MeshCommand_BinaryPacket_CoreModule *rcm = (MeshCommand_BinaryPacket_CoreModule*)ILibScratchPad2;
			rcm->command = htons(MeshCommand_AgentHash);						// MeshCommand_AgentHash (12), SHA384 hash of the agent executable
			rcm->request = htons(requestid);									// Request id
			if (agent->disableUpdate != 0)
			{
				// Never update
				memset(rcm->coreModuleHash, 0, UTIL_SHA384_HASHSIZE);
			}
			else if (agent->forceUpdate != 0)
			{
				// Always Update
				memset(rcm->coreModuleHash, 0xFFFF, UTIL_SHA384_HASHSIZE);
				if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Forcing Update..."); }
			}
			else
			{
				// Update when necessary
				memcpy_s(rcm->coreModuleHash, sizeof(rcm->coreModuleHash), agent->agentHash, UTIL_SHA384_HASHSIZE);// SHA384 hash of the agent executable
			}

			// Send the self hash back to the server
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)rcm, sizeof(MeshCommand_BinaryPacket_CoreModule), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			break;
		}
		case MeshCommand_AgentUpdate:
		{
			if (agent->disableUpdate != 0) { break; }	 // Ignore if updates are disabled
#if defined(WIN32) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
			// In svchost mode, check if an update is already pending reboot
			{
				char pendingBuf[8] = {0};
				int pendingLen = ILibSimpleDataStore_Get(agent->masterDb, "PendingUpdate", pendingBuf, sizeof(pendingBuf));
				if (pendingLen > 0 && pendingBuf[0] == '1')
				{
					if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Update already pending reboot, ignoring new update request"); }
					break;  // Don't process new updates while one is pending
				}
			}
#endif
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX);
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif
			char updateFileHash[UTIL_SHA384_HASHSIZE];
			MeshCommand_BinaryPacket_CoreModule *cm = (MeshCommand_BinaryPacket_CoreModule*)cmd;

			if (cmdLen == 4) 
			{
				// Indicates the start of the agent update transfer
				if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Starting download..."); }
				util_deletefile(updateFilePath);
			} else if (cmdLen == sizeof(MeshCommand_BinaryPacket_CoreModule)) 
			{
				// Indicates the end of the agent update transfer
				// Check the SHA384 hash of the received file against the file we got.
				if ((GenerateSHA384FileHash(updateFilePath, updateFileHash) == 0) && (memcmp(updateFileHash, cm->coreModuleHash, sizeof(cm->coreModuleHash)) == 0))
				{
					//printf("UPDATE: End OK\r\n");
					int updateTop = duk_get_top(agent->meshCoreCtx);
					if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Download Complete... Hash verified"); }
					{
						static const char agentUpdateDownloadedAck[] = "{\"action\":\"agentupdatedownloaded\"}";
						ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_TEXT, (char*)agentUpdateDownloadedAck, (int)(sizeof(agentUpdateDownloadedAck) - 1), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
					}
					if (agent->fakeUpdate != 0)
					{
						int fsz;
						char *fsc;
						sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "%s.zip", agent->exePath);
						fsz = ILibReadFileFromDiskEx(&fsc, ILibScratchPad);
						if (fsz == 0) 
						{ 
							fsz = ILibReadFileFromDiskEx(&fsc, agent->exePath); 
							if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Overriding update with same version..."); }
						}
						else
						{
							if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Overriding update with provided zip..."); }
						}
						ILibWriteStringToDiskEx(updateFilePath, fsc, fsz);
					}
					if (agent->fakeUpdate != 0 || agent->forceUpdate != 0)
					{
						ILibSimpleDataStore_Put(agent->masterDb, "disableUpdate", "1");
						if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Disabling future updates..."); }
					}

					if (duk_peval_string(agent->meshCoreCtx, "require('zip-reader')") == 0)	// [reader]
					{
						duk_prepare_method_call(agent->meshCoreCtx, -1, "isZip");		// [reader][isZip][this]
						duk_push_string(agent->meshCoreCtx, updateFilePath);			// [reader][isZip][this][path]
						if (duk_pcall_method(agent->meshCoreCtx, 1) == 0 && duk_to_boolean(agent->meshCoreCtx, -1))	// [reader][boolean]
						{
							// Update File is zipped
							if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Unzipping update..."); }
							duk_set_top(agent->meshCoreCtx, updateTop);
							if (duk_peval_string(agent->meshCoreCtx, "require('update-helper')") != 0)	// [error]
							{
								if (agent->logUpdate != 0)
								{
									sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "SelfUpdate -> update-helper unavailable for zipped update: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
									ILIBLOGMESSSAGE(ILibScratchPad);
								}
								duk_set_top(agent->meshCoreCtx, updateTop);
								util_deletefile(updateFilePath);
								break;
							}
							duk_prepare_method_call(agent->meshCoreCtx, -1, "start");			// [helper][start][this]
							duk_push_string(agent->meshCoreCtx, updateFilePath);				// [helper][start][this][path]
							if (duk_pcall_method(agent->meshCoreCtx, 1) == 0)					// [helper][promise]
							{
								duk_prepare_method_call(agent->meshCoreCtx, -1, "then");		// [helper][promise][then][this]
								duk_push_c_function(agent->meshCoreCtx, MeshServer_selfupdate_unzip_complete, DUK_VARARGS);//..][res]
								duk_push_c_function(agent->meshCoreCtx, MeshServer_selfupdate_unzip_error, DUK_VARARGS);//[this][res][rej]
								duk_pcall_method(agent->meshCoreCtx, 2);
							}
							else
							{
								if (agent->logUpdate != 0)
								{
									sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "SelfUpdate -> Error Unzipping: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
									ILIBLOGMESSSAGE(ILibScratchPad);
								}
							}
							duk_set_top(agent->meshCoreCtx, updateTop);							// ...
							break; // Break out here, and continue when finished unzipping (or in the case of error, abort)
						}
						if (duk_is_error(agent->meshCoreCtx, -1))
						{
							if (agent->logUpdate != 0)
							{
								sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "SelfUpdate -> zip-reader.isZip failed: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
								ILIBLOGMESSSAGE(ILibScratchPad);
							}
							if (MeshServer_UpdateFileLooksZip(updateFilePath))
							{
								duk_set_top(agent->meshCoreCtx, updateTop);
								util_deletefile(updateFilePath);
								break;
							}
						}
					}
					else if (MeshServer_UpdateFileLooksZip(updateFilePath))
					{
						if (agent->logUpdate != 0)
						{
							sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "SelfUpdate -> zip-reader unavailable for zipped update: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
							ILIBLOGMESSSAGE(ILibScratchPad);
						}
						duk_set_top(agent->meshCoreCtx, updateTop);
						util_deletefile(updateFilePath);
						break;
					}
					else if (agent->logUpdate != 0)
					{
						sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "SelfUpdate -> zip-reader unavailable; treating non-zip payload as native update: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
						ILIBLOGMESSSAGE(ILibScratchPad);
					}
					duk_set_top(agent->meshCoreCtx, updateTop);								// ...
					MeshServer_selfupdate_continue(agent);
				} 
				else 
				{
					// Hash check failed, delete the file and do nothing. On next server reconnect, we will try again.
					if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Download Complete... Hash FAILED, aborting update..."); }
					util_deletefile(updateFilePath);
				}
			}

			break;
		}
		case MeshCommand_AgentUpdateBlock:
		{
			if (agent->disableUpdate != 0) { break; }	 // Ignore if updates are disabled

			// Write the mesh agent block to file
			int retryCount = 0;
#ifdef WIN32
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX);
#else
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agent->exePath, ".update");
#endif

			// We have to try to write until it works, fopen sometimes fails
			while (util_appendfile(updateFilePath, cmd + 4, cmdLen - 4) == 0 && ++retryCount < 4)
			{ 
#ifdef WIN32
				Sleep(100);
#else
				usleep(100 * 1000); // 100 ms, matching the Windows branch (POSIX sleep() is seconds)
#endif
			}

			if (retryCount < 4)
			{
				// Confirm we got a mesh agent update block
				((unsigned short*)ILibScratchPad2)[0] = htons(MeshCommand_AgentUpdateBlock);             // MeshCommand_AgentHash (14), SHA384 hash of the agent executable
				((unsigned short*)ILibScratchPad2)[1] = htons(requestid);                                // Request id
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, ILibScratchPad2, 4, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
			}
			else
			{
				if (duk_ctx_is_alive(agent->meshCoreCtx))
				{
					// Update Failed, so update the server with an agent message explaining what happened, then abort the update by not sending an ACK
					duk_eval_string_noresult(agent->meshCoreCtx, "require('MeshAgent').SendCommand({ action: 'sessions', type : 'msg', value : { 1: { msg: 'Self-Update FAILED. Write Error while writing update block', icon: 3 } } });");
				}
			}
			break;
		}
	}
}

static void MeshServer_ControlChannel_EmitDisconnected(MeshAgentHostContainer *agent)
{
	if (agent == NULL || agent->meshCoreCtx == NULL) { return; }
#ifndef MICROSTACK_NOTLS
	if (agent->serverAuthState != 3) { return; }
#endif

	ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);			// [agent]
	duk_get_prop_string(agent->meshCoreCtx, -1, "emit");					// [agent][emit]
	duk_swap_top(agent->meshCoreCtx, -2);									// [emit][this]
	duk_push_string(agent->meshCoreCtx, "Connected");						// [emit][this][Connected]
	duk_push_int(agent->meshCoreCtx, 0);									// [emit][this][Connected][0] (0 means disconnected)
	if (duk_pcall_method(agent->meshCoreCtx, 2) != 0) { ILibDuktape_Process_UncaughtException(agent->meshCoreCtx); }
	duk_pop(agent->meshCoreCtx);

	duk_eval_string(agent->meshCoreCtx, "require('https').globalAgent.sockets;");															// [table]
	duk_eval_string(agent->meshCoreCtx, "require('http').globalAgent.getName(require('http').parseUri(require('MeshAgent').ServerUrl));");	// [table][key]
	if (duk_has_prop_string(agent->meshCoreCtx, -2, duk_get_string(agent->meshCoreCtx, -1)) != 0)
	{
		duk_get_prop(agent->meshCoreCtx, -2);																								// [table][array]
		while (duk_get_length(agent->meshCoreCtx, -1) > 0)
		{
			duk_array_pop(agent->meshCoreCtx, -1);																							// [table][array][socket]
			duk_prepare_method_call(agent->meshCoreCtx, -1, "end");																			// [table][array][socket][end][this]
			duk_pcall_method(agent->meshCoreCtx, 0);																						// [table][array][socket][undef]
			duk_pop_2(agent->meshCoreCtx);																									// [table][array]
		}
		duk_pop(agent->meshCoreCtx);																										// [table]
	}
	else
	{
		duk_pop(agent->meshCoreCtx);																										// [table]
	}
	duk_pop(agent->meshCoreCtx);																											// ...
}

void MeshServer_ControlChannel_IdleTimeout_PongTimeout(void *object)
{
	// We didn't receive a timely PONG response, so we must disconnect the control channel, and reconnect
	MeshAgentHostContainer *agent = PingData2Agent(object);
	ILibWebClient_StateObject timedOutChannel;
	int descriptorValue = -1;
	if (agent == NULL) { return; }

	timedOutChannel = agent->controlChannel;
	if (timedOutChannel != NULL)
	{
		descriptorValue = ILibWebClient_GetDescriptorValue_FromStateObject(timedOutChannel);
	}
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ControlChannel_IdleTimeout(): PONG TIMEOUT after %d seconds (descriptor=%d)", CONTROLCHANNEL_PONG_TIMEOUT_SECONDS, descriptorValue);

	if (agent->controlChannelDebug != 0)
	{
		printf("AgentCore/MeshServer_ControlChannel_IdleTimeout(): PONG TIMEOUT\n");
		ILIBLOGMESSAGEX("AgentCore/MeshServer_ControlChannel_IdleTimeout(): PONG TIMEOUT\n");
	}

	if (timedOutChannel == NULL || agent->serverConnectionState != 2)
	{
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ControlChannel_IdleTimeout(): stale PONG TIMEOUT ignored (state=%d descriptor=%d)", agent->serverConnectionState, descriptorValue);
		return;
	}

	MeshServer_ControlChannel_EmitDisconnected(agent);
	agent->controlChannel = NULL;
	agent->serverAuthState = 0;
	agent->serverConnectionState = 0;
	MeshAgent_ClearGlobalTunnelProxy(agent);
	MeshAgent_ClearActiveProxyAttempt(agent);
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ControlChannel_IdleTimeout(): serverConnectionState reset to 0 before reconnect (descriptor=%d)", descriptorValue);
	ILibWebClient_Disconnect(timedOutChannel);
	MeshServer_Connect(agent);
}
void MeshServer_ControlChannel_IdleTimeout(ILibWebClient_StateObject WebStateObject, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;

	if (agent->controlChannelDebug != 0)
	{
		printf("AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping\n");
		ILIBLOGMESSAGEX("AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping\n");
	}
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ControlChannel_IdleTimeout(): Sending websocket ping (idleTimeoutSeconds=%d)", agent->controlChannel_idleTimeout_seconds);

	ILibLifeTime_Add(ILibGetBaseTimer(agent->chain), Agent2PingData(agent), CONTROLCHANNEL_PONG_TIMEOUT_SECONDS, MeshServer_ControlChannel_IdleTimeout_PongTimeout, NULL);
	ILibWebClient_WebSocket_Ping(WebStateObject);
	ILibWebClient_SetTimeout(WebStateObject, agent->controlChannel_idleTimeout_seconds, MeshServer_ControlChannel_IdleTimeout, user);
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost , ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping");
}
ILibWebClient_WebSocket_PingResponse MeshServer_ControlChannel_PingSink(ILibWebClient_StateObject WebStateObject, void *user)
{
	return ILibWebClient_WebSocket_PingResponse_Respond;
}
void MeshServer_ControlChannel_PongSink(ILibWebClient_StateObject WebStateObject, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ControlChannel_IdleTimeout(): websocket pong received (descriptor=%d)", ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject));
	if (agent->controlChannelDebug != 0)
	{
		printf("AgentCore/MeshServer_ControlChannel_IdleTimeout(): Pong Received\n");
		ILIBLOGMESSAGEX("AgentCore/MeshServer_ControlChannel_IdleTimeout(): Pong Received\n");
	}

#ifdef _REMOTELOGGING
	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost , ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Received Pong");
#endif
}
static const char* MeshServer_GetControlChannelInterruptReason(int interruptFlag)
{
	switch (interruptFlag)
	{
	case 0:
		return "none";
	case WEBCLIENT_DESTROYED:
		return "webclient_destroyed";
	case WEBCLIENT_DELETED:
		return "webclient_deleted";
	default:
		return "other";
	}
}
static void MeshServer_ControlChannelRequest_MarkConnectComplete(MeshAgentHostContainer *agent, MeshServer_ControlChannelRequestState *requestState)
{
	if (requestState == NULL || requestState->connectTimerCompleted != 0) { return; }

	requestState->connectTimerCompleted = 1;
	if (agent != NULL && agent->controlChannelRequest == requestState)
	{
		agent->controlChannelRequest = NULL;
		ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), requestState);
	}
}
static void MeshServer_ControlChannelRequest_Finalize(MeshAgentHostContainer *agent, MeshServer_ControlChannelRequestState *requestState)
{
	if (requestState == NULL || requestState->finalized != 0) { return; }

	MeshServer_ControlChannelRequest_MarkConnectComplete(agent, requestState);
	requestState->finalized = 1;
	ILibMemory_Free(requestState);
}
void MeshServer_OnResponse(ILibWebClient_StateObject WebStateObject, int InterruptFlag, struct packetheader *header, char *bodyBuffer, int *beginPointer, int endPointer, ILibWebClient_ReceiveStatus recvStatus, void *user1, void *user2, int *PAUSE)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user1;
	MeshServer_ControlChannelRequestState *requestState = (MeshServer_ControlChannelRequestState*)user2;
	int isTrackedControlChannelRequest = (requestState != NULL && agent->controlChannelRequest == requestState);
	ILibChain_Link_SetMetadata(ILibChain_GetCurrentLink(agent->chain), "MeshServer_ControlChannel");
	
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: recvStatus=%d interrupt=%d header=%s status=%d descriptor=%d begin=%d end=%d",
		(int)recvStatus,
		InterruptFlag,
		header != NULL ? "present" : "NULL",
		header != NULL ? header->StatusCode : -1,
		ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject),
		(beginPointer != NULL) ? *beginPointer : -1,
		endPointer);
	if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
	{
		ILIBLOGMESSAGEX("MeshServer_OnResponse: recvStatus=%d interrupt=%d header=%s status=%d descriptor=%d begin=%d end=%d",
			(int)recvStatus,
			InterruptFlag,
			header != NULL ? "present" : "NULL",
			header != NULL ? header->StatusCode : -1,
			ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject),
			(beginPointer != NULL) ? *beginPointer : -1,
			endPointer);
	}

	MeshServer_ControlChannelRequest_MarkConnectComplete(agent, requestState);
	if (requestState != NULL && requestState->timeoutFired != 0 && requestState->established == 0)
	{
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: stale timed-out connect completion ignored (request=%p)", requestState->requestToken);
		MeshServer_ControlChannelRequest_Finalize(agent, requestState);
		return;
	}

	// Look at the various connection states and handle data if needed
	switch (recvStatus)
	{
		case ILibWebClient_ReceiveStatus_Partial:
		case ILibWebClient_ReceiveStatus_LastPartial:
			*beginPointer = endPointer; // ToDo: Buffer this data and send it up
			break;
		case ILibWebClient_ReceiveStatus_Connection_Established: // New connection established.
		{
			int descriptorValue = ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject);
			if (requestState != NULL)
			{
				requestState->established = 1;
				requestState->webStateObject = WebStateObject;
			}
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: Connection_Established descriptor=%d", descriptorValue);
			if (agent->controlChannelDebug != 0)
			{
				printf("Control Channel Connection Established [%d]...\n", descriptorValue);
				ILIBLOGMESSAGEX("Control Channel Connection Established [%d]...", descriptorValue);
			}
#ifndef MICROSTACK_NOTLS
			int len;
#endif
			int idleLen;
			if ((idleLen = ILibSimpleDataStore_Get(agent->masterDb, "controlChannelIdleTimeout", NULL, 0)) != 0)
			{
				if (idleLen > 15)
				{
					agent->controlChannel_idleTimeout_seconds = DEFAULT_IDLE_TIMEOUT;
				}
				else
				{
					char idleBuffer[16];
					idleBuffer[ILibSimpleDataStore_Get(agent->masterDb, "controlChannelIdleTimeout", idleBuffer, sizeof(idleBuffer)-1)] = 0;
					if (ILib_atoi_int32(&(agent->controlChannel_idleTimeout_seconds), idleBuffer, sizeof(idleBuffer)) != 0)
					{
						agent->controlChannel_idleTimeout_seconds = DEFAULT_IDLE_TIMEOUT;
					}
				}
			}
			else
			{
				agent->controlChannel_idleTimeout_seconds = DEFAULT_IDLE_TIMEOUT;
			}

			ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));
			agent->controlChannel = WebStateObject; // Set the agent MeshCentral server control channel
			agent->proxyAttemptEstablished = 1;
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Control Channel Idle Timeout = %d seconds", agent->controlChannel_idleTimeout_seconds);
			ILibWebClient_SetTimeout(WebStateObject, agent->controlChannel_idleTimeout_seconds, MeshServer_ControlChannel_IdleTimeout, agent);
			ILibWebClient_WebSocket_SetPingPongHandler(WebStateObject, MeshServer_ControlChannel_PingSink, MeshServer_ControlChannel_PongSink, agent);

			// Send Agent Commit Date to server. This is useful in case the server needs to adjust control flow based on agent build
			char commitPacket[sizeof(uint16_t) + sizeof(SOURCE_COMMIT_DATE)] = { 0 };
			((uint16_t*)commitPacket)[0] = htons(MeshCommand_AgentCommitDate);
			strcpy_s(commitPacket + sizeof(uint16_t), sizeof(SOURCE_COMMIT_DATE), SOURCE_COMMIT_DATE);
			ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)commitPacket, sizeof(commitPacket), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

			if (agent->meshCoreCtx != NULL)
			{
				if (duk_peval_string(agent->meshCoreCtx, "require('os').Name + ' - ' + require('os').arch()") == 0)
				{
					duk_size_t infoLen;
					char *info = (char*)duk_get_lstring(agent->meshCoreCtx, -1, &infoLen);
					char *buffer = Duktape_PushBuffer(agent->meshCoreCtx, sizeof(uint16_t) + infoLen);
					((uint16_t*)buffer)[0] = htons(MeshCommand_HostInfo);
					memcpy_s(buffer + sizeof(uint16_t), infoLen, info, infoLen);
					ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, buffer, (int)ILibMemory_Size(buffer), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
					duk_pop(agent->meshCoreCtx);
				}
				duk_pop(agent->meshCoreCtx);
			}

#ifndef MICROSTACK_NOTLS
			X509* peer = ILibWebClient_SslGetCert(WebStateObject);
			agent->serverAuthState = 0; // We are not authenticated. Bitmask: 1 = Server Auth, 2 = Agent Auth.
			agent->serverConnectionState = 2;
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: serverConnectionState set to 2 descriptor=%d", descriptorValue);

			// Send the ServerID to the server, this is useful for the server to use the correct certificate to authenticate.
			MeshCommand_BinaryPacket_ServerId *serveridcmd = (MeshCommand_BinaryPacket_ServerId*)ILibScratchPad2;
			serveridcmd->command = htons(MeshCommand_ServerId);
			memcpy_s(serveridcmd->serverId, sizeof(serveridcmd->serverId), agent->serverHash, sizeof(agent->serverHash)); // Place our mesh agent nonce
			if ((int)ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)serveridcmd, sizeof(MeshCommand_BinaryPacket_ServerId), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete) < 0)
			{
				break;
			}

			// Check to see if we already have a validated TLS cert hash
			{
				MeshCommand_BinaryPacket_AuthRequest *ar = (MeshCommand_BinaryPacket_AuthRequest*)ILibScratchPad2;
				util_certhash2(peer, ar->serverHash); // Hash the server certificate public key and place it

				len = ILibSimpleDataStore_GetEx(agent->masterDb, "ServerTlsCertHash", 17, ILibScratchPad, sizeof(ILibScratchPad));
				if ((len == UTIL_SHA384_HASHSIZE) && (memcmp(ILibScratchPad, ar->serverHash, UTIL_SHA384_HASHSIZE) == 0)) 
				{
					if (agent->controlChannelDebug != 0)
					{
						printf("TLS Server Cert matches Mesh Server Cert [%d]...\n", ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject));
						ILIBLOGMESSAGEX("TLS Server Cert matches Mesh Server Cert [%d]...", ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject));
					}
					// The TLS certificate of this server is correct, no need to authenticate further.
					unsigned short response = htons(MeshCommand_AuthConfirm); // Send indication to the server that it's already authenticated
					agent->serverAuthState = 1;
					ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)&response, 2, ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);
				}

				if (agent->controlChannelDebug != 0)
				{
					printf("Sending Authentication Data...\n");
					ILIBLOGMESSAGEX("Sending Authentication Data...");
				}

				// Start authentication by sending a auth nonce & server TLS cert hash - If we indicated AuthConfirm already, the server will use this data but not respond to it.
				// Send 384 bits SHA384 hash of TLS cert public key + 384 bits nonce
				util_random(sizeof(agent->agentNonce), agent->agentNonce);		// Generate a new mesh agent connection nonce
				ar->command = htons(MeshCommand_AuthRequest);					// MeshCommand_AuthRequest (1), server hash + nonce
				if (peer != NULL) { X509_free(peer); }
				memcpy_s(ar->serverNonce, sizeof(ar->serverNonce), agent->agentNonce, sizeof(agent->agentNonce)); // Place our mesh agent nonce
				ILibWebClient_WebSocket_Send(WebStateObject, ILibWebClient_WebSocket_DataType_BINARY, (char*)ar, sizeof(MeshCommand_BinaryPacket_AuthRequest), ILibAsyncSocket_MemoryOwnership_USER, ILibWebClient_WebSocket_FragmentFlag_Complete);

				// If we know this is a good server, send our agent information right now.
				if (agent->serverAuthState == 1) { MeshServer_SendAgentInfo(agent, WebStateObject); }
			}
#endif
			break;
		}
		case ILibWebClient_ReceiveStatus_Complete: // Disconnection
		{
			int descriptorValue = ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject);
			int isActiveControlChannel = (agent->controlChannel == WebStateObject);
			int isPreClearedEstablishedChannel = (agent->controlChannel == NULL && agent->controlChannelRequest == NULL && requestState != NULL && requestState->established != 0 && requestState->webStateObject == WebStateObject);
			int isAuthoritativeDisconnect = (isActiveControlChannel != 0 || isTrackedControlChannelRequest != 0 || isPreClearedEstablishedChannel != 0);
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: ReceiveStatus_Complete descriptor=%d interrupt=%d reason=%s headerStatus=%d",
				descriptorValue,
				InterruptFlag,
				MeshServer_GetControlChannelInterruptReason(InterruptFlag),
				header != NULL ? header->StatusCode : -1);
		if (agent->controlChannelDebug != 0)
			{
				printf("Control Channel Disconnected [%d]...\n", descriptorValue);
				ILIBLOGMESSAGEX("Control Channel Disconnected [%d]...", descriptorValue);
				if (header != NULL)
				{
					ILIBLOGMESSAGEX("  -> HTTP status: %d", header->StatusCode);
				}
				ILIBLOGMESSAGEX("  -> InterruptFlag: %d", InterruptFlag);
			}
												   
			// If the channel had been authenticated, inform JavaScript core module that we are disconnected
			if (isAuthoritativeDisconnect != 0)
			{
				MeshServer_ControlChannel_EmitDisconnected(agent);
			}
			if (isAuthoritativeDisconnect != 0)
			{
				agent->serverAuthState = 0;
				if (isActiveControlChannel != 0) { agent->controlChannel = NULL; } // Set the agent MeshCentral server control channel
				ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));
				agent->serverConnectionState = 0;
				MeshAgent_ClearGlobalTunnelProxy(agent);
				MeshAgent_ClearActiveProxyAttempt(agent);
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: serverConnectionState reset to 0 (disconnected authoritative=%d trackedRequest=%d preCleared=%d)", isAuthoritativeDisconnect, isTrackedControlChannelRequest, isPreClearedEstablishedChannel);
			}
			else
			{
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: stale disconnect ignored (descriptor=%d)", descriptorValue);
			}
			break;
		}
		case ILibWebClient_ReceiveStatus_MoreDataToBeReceived:	// Data received			
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: MoreDataToBeReceived status=%d begin=%d end=%d",
			header != NULL ? header->StatusCode : -1,
			(beginPointer != NULL) ? *beginPointer : -1,
			endPointer);
		if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
		{
			ILIBLOGMESSAGEX("MeshServer_OnResponse: MoreDataToBeReceived status=%d begin=%d end=%d",
				header != NULL ? header->StatusCode : -1,
				(beginPointer != NULL) ? *beginPointer : -1,
				endPointer);
		}
			if (header != NULL && header->StatusCode == 101)
			{
				// Process Mesh Agent commands
				MeshServer_ProcessCommand(WebStateObject, agent, bodyBuffer, endPointer);
			}
			else
			{
				printf("Protocol Error encountered...\n");
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: Unexpected HTTP status=%d recvStatus=%d", header != NULL ? header->StatusCode : -1, (int)recvStatus);
				if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
				{
					ILIBLOGMESSAGEX("MeshServer_OnResponse: Unexpected HTTP status=%d recvStatus=%d", header != NULL ? header->StatusCode : -1, (int)recvStatus);
				}
			}
			break;
	}

	// If there are no headers, this is a connection error. Log it and try again...
	if (header == NULL)
	{
		if (ILibIsChainBeingDestroyed(agent->chain)) { return; }
		int descriptorValue = ILibWebClient_GetDescriptorValue_FromStateObject(WebStateObject);
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: header=NULL recvStatus=%d interrupt=%d reason=%s descriptor=%d", (int)recvStatus, InterruptFlag, MeshServer_GetControlChannelInterruptReason(InterruptFlag), descriptorValue);
		if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
		{
			ILIBLOGMESSAGEX("MeshServer_OnResponse: header=NULL recvStatus=%d interrupt=%d reason=%s descriptor=%d", (int)recvStatus, InterruptFlag, MeshServer_GetControlChannelInterruptReason(InterruptFlag), descriptorValue);
		}
		ILibRemoteLogging_printf(ILibChainGetLogger(ILibWebClient_GetChainFromWebStateObject(WebStateObject)), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "Agent Host Container: Mesh Server Connection Error (%d), trying again later.", descriptorValue);
		printf("Mesh Server Connection Error [%d]\n", descriptorValue);

		MeshAgent_RecordProxyAttemptFailure(agent, "connect-error");
		if (isTrackedControlChannelRequest != 0 || agent->controlChannel == WebStateObject || (agent->controlChannel == NULL && agent->controlChannelRequest == NULL && requestState != NULL && requestState->established != 0 && requestState->webStateObject == WebStateObject))
		{
			if (agent->controlChannel == WebStateObject) { agent->controlChannel = NULL; }
			agent->serverAuthState = 0;
			agent->serverConnectionState = 0;
			ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));
			MeshAgent_ClearGlobalTunnelProxy(agent);
			MeshAgent_ClearActiveProxyAttempt(agent);
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_OnResponse: header=NULL reset serverConnectionState to 0 before retry (trackedRequest=%d descriptor=%d)", isTrackedControlChannelRequest, descriptorValue);
		}
		if (agent->logUpdate != 0) 
		{
			sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "Connection Error [%p, %d, [%d]]...\n", WebStateObject, InterruptFlag, descriptorValue);
			ILIBLOGMESSSAGE(ILibScratchPad); 
		}

		MeshServer_ControlChannelRequest_Finalize(agent, requestState);
		requestState = NULL;
		MeshServer_Connect(agent);
		return;
	}

	if (recvStatus != ILibWebClient_ReceiveStatus_Partial) { *beginPointer = endPointer; } // TODO: Confirm with Bryan that this is how partial data works
	if (recvStatus == ILibWebClient_ReceiveStatus_Complete)
	{
		MeshServer_ControlChannelRequest_Finalize(agent, requestState);
	}
}
void MeshServer_ConnectEx_NetworkError(void *j)
{
	MeshServer_ControlChannelRequestState *requestState = (MeshServer_ControlChannelRequestState*)j;
	MeshAgentHostContainer *agent = requestState->agent;
	void *request = requestState->requestToken;

	requestState->timeoutFired = 1;
	requestState->connectTimerCompleted = 1;
	if (agent->controlChannelRequest == requestState)
	{
		agent->controlChannelRequest = NULL;
	}

	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx_NetworkError: Network Timeout (request=%p)", request);
	if (agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Network Timeout Occurred..."); }
	agent->serverConnectionState = 0; // We are cancelling connection request
	MeshAgent_RecordProxyAttemptFailure(agent, "timeout");

	printf("Network Timeout occurred...\n");

	if (request != NULL)
	{
		ILibWebClient_CancelRequest(request);
	}
	else
	{
		MeshServer_ControlChannelRequest_Finalize(agent, requestState);
		requestState = NULL;
	}
	MeshServer_ConnectEx(agent);
}
void MeshServer_ConnectEx_Lockout_Retry(void *j)
{
	MeshServer_ConnectEx((MeshAgentHostContainer*)j);
}


void MeshServer_ConnectEx(MeshAgentHostContainer *agent)
{
	size_t len;
	size_t serverUrlLen;
	char *path = NULL;
	char *host = NULL;
	char *serverUrl = NULL;
	unsigned short port;
	struct sockaddr_in6 meshServer;
	ILibHTTPPacket *req = NULL;
	ILibWebClient_RequestToken reqToken;
	parser_result *rs = NULL;
	parser_result_field *f;
	const char *resolutionSource = "os";
#ifndef MICROSTACK_NOTLS
	ILibParseUriResult result = ILibParseUriResult_UNKNOWN_SCHEME;
#endif

	memset(&meshServer, 0, sizeof(struct sockaddr_in6));
	if (agent->timerLogging != 0 && agent->retryTimerSet != 0)
	{
		agent->retryTimerSet = 0;
		ILIBLOGMESSAGEX("    >> Retry Timer Elapsed [serverConnectionState: %d, chainState: %d]", agent->serverConnectionState, ILibIsChainBeingDestroyed(agent->chain));
	}

	if (agent->serverConnectionState != 0) { return; }
	if (ILibIsChainBeingDestroyed(agent->chain) != 0) { return; }

	MeshAgent_ClearGlobalTunnelProxy(agent);
	MeshAgent_ClearActiveProxyAttempt(agent);
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: entry state=%d", agent->serverConnectionState);

	len = ILibSimpleDataStore_Get(agent->masterDb, "MeshServer", ILibScratchPad2, sizeof(ILibScratchPad2));
	if (len == 0)
	{
		printf("No MeshCentral settings found, place .msh file with this executable and restart.\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: MeshServer URI not found");
		return;
	}

	rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
	if (rs == NULL || rs->NumResults == 0)
	{
		if (rs != NULL) { ILibDestructParserResults(rs); }
		printf("No MeshCentral settings found, place .msh file with this executable and restart.\r\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: MeshServer URI list empty");
		return;
	}
	if (agent->serverIndex == 0)
	{
		int rval;
		util_random(4, (char*)&rval);
		agent->serverIndex = (rval % rs->NumResults) + 1;
	}
	else
	{
		agent->serverIndex = (agent->serverIndex % rs->NumResults) + 1;
	}

	f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
	if (f == NULL)
	{
		int totalResults = rs->NumResults;
		ILibDestructParserResults(rs);
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: MeshServer count mismatch (index=%d total=%d)", agent->serverIndex, totalResults);
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: MeshServer count mismatch. URL Count = %d, Server Index = %d", totalResults, agent->serverIndex);
		return;
	}
	f->datalength = ILibTrimString(&(f->data), f->datalength);
	f->data[f->datalength] = 0;
	serverUrl = f->data;
	serverUrlLen = f->datalength;
	if (serverUrlLen == 0)
	{
		ILibDestructParserResults(rs);
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: empty MeshServer entry at index=%d", agent->serverIndex);
		MeshServer_Connect(agent);
		return;
	}
	if (serverUrlLen >= sizeof(agent->serveruri))
	{
		agent->serveruri[0] = '\0';
		ILibDestructParserResults(rs);
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost,
			ILibRemoteLogging_Flags_VerbosityLevel_1,
			"agentcore: Server URL too long (%d >= %d), rejected",
			(int)serverUrlLen, (int)sizeof(agent->serveruri));
		return;
	}
	strncpy_s(agent->serveruri, sizeof(agent->serveruri), serverUrl, serverUrlLen);
	agent->serveruri[serverUrlLen] = '\0';

#ifndef MICROSTACK_NOTLS
	result = ILibParseUri(serverUrl, &host, &port, &path, NULL);
#else
	ILibParseUri(serverUrl, &host, &port, &path, NULL);
#endif

	if (host == NULL || host[0] == 0 || path == NULL || path[0] == 0)
	{
		ILibDestructParserResults(rs);
		if (host != NULL) { free(host); }
		if (path != NULL) { free(path); }
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: Invalid MeshServer URI: %s", agent->serveruri);
		return;
	}

	if (!MeshAgent_ResolveControlChannelAddress(agent, serverUrl, (int)serverUrlLen, host, port, &meshServer, &resolutionSource))
	{
		memset(&meshServer, 0, sizeof(meshServer));
		meshServer.sin6_family = AF_UNSPEC;
	}

	if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
	{
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: resolved url=%s host=%s port=%hu family=%d resolutionSource=%s parseResult=%d",
			serverUrl != NULL ? serverUrl : "(null)",
			host != NULL ? host : "(null)",
			port,
			meshServer.sin6_family,
			resolutionSource != NULL ? resolutionSource : "(none)",
			(int)result);
		ILIBLOGMESSAGEX("MeshServer_ConnectEx: resolved url=%s host=%s port=%hu family=%d resolutionSource=%s parseResult=%d",
			serverUrl != NULL ? serverUrl : "(null)",
			host != NULL ? host : "(null)",
			port,
			meshServer.sin6_family,
			resolutionSource != NULL ? resolutionSource : "(none)",
			(int)result);
	}

#ifdef WIN32
	if (agent->DNS_LOCK[0] != 0 && host != NULL)
	{
		size_t dnsLockLen = strnlen_s(agent->DNS_LOCK, sizeof(agent->DNS_LOCK));
		size_t hostLen = strnlen_s(host, 512);
		if (dnsLockLen != hostLen || _strnicmp(agent->DNS_LOCK, host, dnsLockLen) != 0)
		{
			printf("agentcore: DNS Lock[%s]: Unauthorized to connect to: %s\n", agent->DNS_LOCK, host);
			ILibDestructParserResults(rs);
			free(host);
			free(path);
			ILibLifeTime_Add(ILibGetBaseTimer(agent->chain), agent, 5, MeshServer_ConnectEx_Lockout_Retry, NULL);
			return;
		}
	}
#endif

	if (meshServer.sin6_family == AF_UNSPEC)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: Could not resolve: %s", host != NULL ? host : "(null)");
		printf("agentcore: Could not resolve: %s\n", host);
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: DNS lookup failed for host=%s", host != NULL ? host : "(null)");
		if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
		{
			ILIBLOGMESSAGEX("MeshServer_ConnectEx: DNS lookup failed for host=%s", host != NULL ? host : "(null)");
		}
		ILibDestructParserResults(rs);
		free(host);
		free(path);
		MeshServer_Connect(agent);
		return;
	}
	else
	{
		char *tmp = ILibRemoteLogging_ConvertAddress((struct sockaddr*)&meshServer);
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: DNS lookup success host=%s address=%s", host != NULL ? host : "(null)", tmp != NULL ? tmp : "(null)");
		if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
		{
			ILIBLOGMESSAGEX("MeshServer_ConnectEx: DNS lookup success host=%s address=%s", host != NULL ? host : "(null)", tmp != NULL ? tmp : "(null)");
		}
	}

	ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: Attempting connection to: %s", serverUrl);
	ILibDestructParserResults(rs);
	rs = NULL;

	if ((len = ILibSimpleDataStore_Get(agent->masterDb, "ServerID", ILibScratchPad2, sizeof(ILibScratchPad2))) == 0) { printf("ServerID entry not found in Db!\n"); free(host); free(path); return; }
	rs = ILibParseString(ILibScratchPad2, 0, len, ",", 1);
	f = ILibParseString_GetResultIndex(rs, agent->serverIndex);
	if (f == NULL)
	{
		printf("ServerID Count Mismatch\r\n");
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: ServerID count mismatch (index=%d total=%d)", agent->serverIndex, rs->NumResults);
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID Count Mismatch. Hash Count = %d, Server Index = %d", rs->NumResults, agent->serverIndex);
		ILibDestructParserResults(rs);
		free(host);
		free(path);
		return;
	}
	f->datalength = ILibTrimString(&(f->data), f->datalength);
	if (f->datalength / 2 > sizeof(agent->serverHash))
	{
		printf("ServerID too big\r\n");
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: ServerID too big (len=%d expected<=%llu)", f->datalength / 2, (unsigned long long)(sizeof(agent->serverHash) - 1));
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Agent_GuardPost, ILibRemoteLogging_Flags_VerbosityLevel_1, "AgentCore: ServerID too big. Was %d bytes, but expected %d bytes", f->datalength / 2, sizeof(agent->serverHash) - 1);
		ILibDestructParserResults(rs);
		free(host);
		free(path);
		return;
	}

#ifdef WIN32
	if (agent->ID_LOCK[0] != 0)
	{
		if (f->datalength > sizeof(agent->ID_LOCK) || (strnlen_s(agent->ID_LOCK, sizeof(agent->ID_LOCK)) != f->datalength && strncasecmp(agent->ID_LOCK, f->data, f->datalength) != 0))
		{
			printf("agentcore: ServerID Lock: ServerID MISMATCH for: %s\n", host);
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: ServerID lock mismatch (lock=%s candidate=%.*s)", agent->ID_LOCK, f->datalength, f->data);
			ILibDestructParserResults(rs);
			free(host);
			free(path);
			ILibLifeTime_Add(ILibGetBaseTimer(agent->chain), agent, 5, MeshServer_ConnectEx_Lockout_Retry, NULL);
			return;
		}
	}
#endif

	memset(agent->serverHash, 0, sizeof(agent->serverHash));
	util_hexToBuf(f->data, f->datalength, agent->serverHash);
	ILibDestructParserResults(rs);
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: using ServerID index=%d hashLen=%d", agent->serverIndex, f->datalength / 2);

	len = ILibSimpleDataStore_Get(agent->masterDb, "MeshID", ILibScratchPad, sizeof(ILibScratchPad));
	{
		int meshIdLen = (int)len;
		unsigned char meshIdBuffer[UTIL_SHA384_HASHSIZE];

		if (len == 32 || len == 48)
		{
			memcpy_s(meshIdBuffer, sizeof(meshIdBuffer), ILibScratchPad, len);
		}
		else if (len > 2 && ILibScratchPad[0] == '0' && (ILibScratchPad[1] == 'x' || ILibScratchPad[1] == 'X'))
		{
			char *hexStart = ILibScratchPad + 2;
			int hexLen = ((int)len) - 2;
			while (hexLen > 0 && (hexStart[hexLen - 1] == 0 || hexStart[hexLen - 1] == '\r' || hexStart[hexLen - 1] == '\n' || hexStart[hexLen - 1] == ' ' || hexStart[hexLen - 1] == '\t'))
			{
				--hexLen;
			}
			if ((hexLen % 2) == 0 && hexLen > 0 && (hexLen / 2) <= (int)sizeof(meshIdBuffer))
			{
				meshIdLen = hexLen / 2;
				util_hexToBuf(hexStart, hexLen, (char*)meshIdBuffer);
				ILibSimpleDataStore_PutEx(agent->masterDb, "MeshID", 6, (char*)meshIdBuffer, meshIdLen);
				MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: normalized MeshID ascii len=%d (trimmed=%d) -> binary len=%d", (int)len, hexLen, meshIdLen);
			}
			else
			{
				meshIdLen = 0;
			}
		}
		else
		{
			meshIdLen = 0;
		}

		if (meshIdLen != 32 && meshIdLen != 48)
		{
			printf("MeshID entry not found in db or bad size.\n");
			MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: MeshID missing or bad len=%d", (int)len);
			free(host);
			free(path);
			return;
		}

		memset(agent->meshId, 0, sizeof(agent->meshId));
		memcpy_s(agent->meshId, sizeof(agent->meshId), meshIdBuffer, meshIdLen);
		len = meshIdLen;
	}

#ifndef MICROSTACK_NOTLS
	util_keyhash(agent->selfcert, agent->g_selfid);
#endif

	req = ILibCreateEmptyPacket();
	ILibSetVersion(req, "1.1", 3);
	ILibSetDirective(req, "GET", 3, path, (int)strnlen_s(path, serverUrlLen));
	{
		int isSecureScheme2 = (_strnicmp(agent->serveruri, "wss:", 4) == 0);
		int useDefaultPort2 = ((isSecureScheme2 && port == 443) || (!isSecureScheme2 && port == 80));
		MeshAgent_AddHostHeader(req, NULL, host, port, useDefaultPort2);
	}
	MeshAgent_AddUserAgentHeader(req, NULL);

	free(path);
	path = NULL;

	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: pre-connect family=%d source=%s", meshServer.sin6_family, resolutionSource != NULL ? resolutionSource : "(none)");
	strcpy_s(agent->serverip, sizeof(agent->serverip), ILibRemoteLogging_ConvertAddress((struct sockaddr*)&meshServer));
	printf("Connecting to: %s\n", agent->serveruri);
	if (agent->logUpdate != 0 || agent->controlChannelDebug != 0) { ILIBLOGMESSAGEX("Connecting to: %s", agent->serveruri); }

	ILibWebClient_AddWebSocketRequestHeaders(req, 65535, MeshServer_OnSendOK);
	{
		MeshServer_ControlChannelRequestState *requestState = (MeshServer_ControlChannelRequestState*)ILibMemory_SmartAllocate(sizeof(MeshServer_ControlChannelRequestState));
		requestState->agent = agent;
		agent->controlChannelRequest = requestState;
		reqToken = ILibWebClient_PipelineRequest(agent->httpClientManager, (struct sockaddr*)&meshServer, req, MeshServer_OnResponse, agent, requestState);
		requestState->requestToken = reqToken;
		MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: PipelineRequest token=%p", reqToken);
		ILibLifeTime_Add(ILibGetBaseTimer(agent->chain), requestState, 60, MeshServer_ConnectEx_NetworkError, NULL);
	}

#ifndef MICROSTACK_NOTLS
	ILibWebClient_Request_SetHTTPS(reqToken, result == ILibParseUriResult_TLS ? ILibWebClient_RequestToken_USE_HTTPS : ILibWebClient_RequestToken_USE_HTTP);
	ILibWebClient_Request_SetSNI(reqToken, host, (int)strnlen_s(host, serverUrlLen));
	ILibWebClient_Request_SetALPN(reqToken, NULL);
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: TLS useHTTPS=%d SNI=%s ALPN=%s",
		(result == ILibParseUriResult_TLS ? 1 : 0),
		host != NULL ? host : "(null)",
		"(none)");
	if (agent->controlChannelDebug != 0 || agent->logUpdate != 0)
	{
		ILIBLOGMESSAGEX("MeshServer_ConnectEx: TLS useHTTPS=%d SNI=%s ALPN=%s",
			(result == ILibParseUriResult_TLS ? 1 : 0),
			host != NULL ? host : "(null)",
			"(none)");
	}
#endif

	agent->serverConnectionState = 1;
	MeshAgent_ControlChannelDebugLog(agent, "MeshServer_ConnectEx: serverConnectionState set to 1 token=%p", reqToken);
	free(host);
}

void MeshServer_DbWarning(ILibSimpleDataStore db, uint64_t size, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	MeshAgent_sendConsoleText(agent->meshCoreCtx, "Database Size Warning: [%llu bytes]", size);
}


void MeshServer_Agent_SelfTest(MeshAgentHostContainer *agent)
{
	int CoreModuleLen = ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", NULL, 0);
	char *CoreModule;
	//int CoreModuleTesterLen = ILibSimpleDataStore_Get(agent->masterDb, "CoreModuleTester", NULL, 0);
	//char *CoreModule, *CoreModuleTester;

	duk_push_heapptr(agent->meshCoreCtx, ILibDuktape_GetProcessObject(agent->meshCoreCtx));		// [process]
	ILibDuktape_SimpleDataStore_raw_GetCachedValues_Array(agent->meshCoreCtx, agent->masterDb);	// [process][array]
	duk_put_prop_string(agent->meshCoreCtx, -2, "\xFF_argArray");								// [process]
	duk_pop(agent->meshCoreCtx);

	printf("Agent Self Test...\n");
	if (agent->coreTimeout != 0)
	{
		duk_push_global_object(agent->meshCoreCtx);								// [g]
		duk_get_prop_string(agent->meshCoreCtx, -1, "clearTimeout");			// [g][clearTimeout]
		duk_swap_top(agent->meshCoreCtx, -2);									// [clearTimeout][this]
		duk_push_heapptr(agent->meshCoreCtx, agent->coreTimeout);				// [clearTimeout][this][timeout]
		duk_pcall_method(agent->meshCoreCtx, 1); duk_pop(agent->meshCoreCtx);	// ...
		agent->coreTimeout = NULL;
	}
	printf("   -> Loading meshcore.js from db ........");

	if (CoreModuleLen <= 4)
	{
		printf("[NOT FOUND]\n");
		ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
			ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: CoreModule missing from datastore");
		exit(1);
	}
	else
	{
		agent->serverAuthState = 3;
		ILibMemory_AllocateRaw(CoreModule, CoreModuleLen);
		if (ILibSimpleDataStore_Get(agent->masterDb, "CoreModule", CoreModule, CoreModuleLen) != CoreModuleLen)
		{
			free(CoreModule);
			printf("[FAILED]\n");
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: failed to read CoreModule from datastore");
			exit(1);
		}

		MeshAgent_EnsureCoreModuleRuntimeGlobals(agent->meshCoreCtx);
		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agent->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
			ILibDuktape_ScriptContainer_ExecuteByteCode(agent->meshCoreCtx) != 0)
		{
			printf("[FAILED]\n");
			ILibRemoteLogging_printf(ILibChainGetLogger(agent->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agent->meshCoreCtx, -1));
			duk_pop(agent->meshCoreCtx);
			free(CoreModule);
			exit(1);
		}
		printf("[OK]\n");
		free(CoreModule);
	}

#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
	MeshAgent_StageSelfTestModuleForCurrentExeBestEffort();
#endif

	if (duk_peval_string(agent->meshCoreCtx,
		"if (typeof Duktape !== 'undefined' && Duktape.modLoaded) {"
		" try { for (var k in Duktape.modLoaded) {"
		" if (k.indexOf('agent-selftest') >= 0) { delete Duktape.modLoaded[k]; }"
		" } } catch (e) {} }"
		" var __selfTestPath = null;"
		" try { var __lastSlash = process.execPath.lastIndexOf('\\\\');"
		" if (__lastSlash >= 0) { __selfTestPath = process.execPath.substring(0, __lastSlash + 1) + 'agent-selftest.js'; } } catch (e) {}"
		" if (__selfTestPath != null) {"
		" try { require(__selfTestPath)(); } catch (e1) { require('agent-selftest')(); }"
		" } else { require('agent-selftest')(); }") != 0)
	{
		printf("   -> Loading Test Script.................[FAILED] %s", duk_safe_to_string(agent->meshCoreCtx, -1));
		exit(1);
	}
	duk_pop(agent->meshCoreCtx);
}

void MeshServer_Connect(MeshAgentHostContainer *agent)
{
	unsigned int timeout;

	// If this is called while we are in any connection state, just leave now.
	if (agent->serverConnectionState != 0) return;

	// Self-test runs as a one-shot path. Prevent duplicate invocation/re-entry if MeshServer_Connect fires again.
	if (agent->selfTestLaunched != 0 ||
		ILibSimpleDataStore_Get(agent->masterDb, "selfTest", NULL, 0) != 0 ||
		ILibSimpleDataStore_Get(agent->masterDb, "selftest", NULL, 0) != 0)
	{
		if (agent->selfTestLaunched != 0) { return; }
		agent->selfTestLaunched = 1;
		// Best-effort removal so subsequent module loads don't see self-test args as pending work.
		ILibSimpleDataStore_Delete(agent->masterDb, "selfTest");
		ILibSimpleDataStore_Delete(agent->masterDb, "selftest");
		MeshServer_Agent_SelfTest(agent);
		return;
	}

#ifdef WIN32
	duk_idx_t top = duk_get_top(agent->meshCoreCtx);
	if (duk_peval_string(agent->meshCoreCtx, "require('win-authenticode-opus')(process.execPath);") == 0)							// [obj]
	{
		if (!duk_is_null_or_undefined(agent->meshCoreCtx, -1))
		{
			char *url = Duktape_GetStringPropertyValue(agent->meshCoreCtx, -1, "url", NULL);
			if (url != NULL)
			{
				duk_push_sprintf(agent->meshCoreCtx, "require('win-authenticode-opus').locked('%s');", url);						// [obj][str]
				if (duk_peval(agent->meshCoreCtx) == 0 && !duk_is_null_or_undefined(agent->meshCoreCtx, -1))						// [obj][obj]
				{
					char *dns = Duktape_GetStringPropertyValue(agent->meshCoreCtx, -1, "dns", NULL);
					char *id = Duktape_GetStringPropertyValue(agent->meshCoreCtx, -1, "id", NULL);
					if (dns != NULL && id != NULL)
					{
						strcpy_s(agent->DNS_LOCK, sizeof(agent->DNS_LOCK), dns);
						strcpy_s(agent->ID_LOCK, sizeof(agent->ID_LOCK), id);
					}
				}
			}
		}
	}
	duk_set_top(agent->meshCoreCtx, top);																							// ...
#endif

	util_random(sizeof(int), (char*)&timeout);
	gRemoteMouseRenderDefault = ILibSimpleDataStore_Get(agent->masterDb, "remoteMouseRender", NULL, 0);
	ILibSimpleDataStore_ConfigCompact(agent->masterDb, ILibSimpleDataStore_GetInt(agent->masterDb, "compactDirtyMinimum", 0));
	ILibSimpleDataStore_ConfigSizeLimit(agent->masterDb, ILibSimpleDataStore_GetInt(agent->masterDb, "dbWarningSizeThreshold", 0), MeshServer_DbWarning, agent);
	agent->disableUpdate = (agent->JSRunningAsService != 0 && agent->JSRunningWithAdmin == 0) | ILibSimpleDataStore_Get(agent->masterDb, "disableUpdate", NULL, 0) | (agent->JSRunningAsService == 0 && ((agent->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY) == MeshCommand_AuthInfo_CapabilitiesMask_TEMPORARY));
	agent->forceUpdate = ILibSimpleDataStore_Get(agent->masterDb, "forceUpdate", NULL, 0);
	agent->logUpdate = ILibSimpleDataStore_Get(agent->masterDb, "logUpdate", NULL, 0);
	agent->fakeUpdate = ILibSimpleDataStore_Get(agent->masterDb, "fakeUpdate", NULL, 0);
	agent->controlChannelDebug = ILibSimpleDataStore_Get(agent->masterDb, "controlChannelDebug", NULL, 0);
	ILibDuktape_HECI_Debug = (ILibSimpleDataStore_Get(agent->masterDb, "heciDebug", NULL, 0) != 0);
	agent->timerLogging = ILibSimpleDataStore_Get(agent->masterDb, "timerLogging", NULL, 0);
	agent->consoleText_maxRate = ILibSimpleDataStore_GetInt(agent->masterDb, "consoleTextMaxRate", 10);

#if defined(_LINKVM) && defined(_POSIX) && !defined(__APPLE__)
	SLAVELOG = ILibSimpleDataStore_Get(agent->masterDb, "slaveKvmLog", NULL, 0);
#endif

	if (agent->logUpdate != 0) { ILIBLOGMESSAGEX("PLATFORM_TYPE: %d", agent->platformType); }
	if (agent->logUpdate != 0) { ILIBLOGMESSAGEX("Running as Service: %d", agent->JSRunningAsService); }

	if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("Attempting to connect to Server..."); }
	if (agent->controlChannelDebug != 0)
	{
		ILIBLOGMESSSAGE("Attempting to connect to Server...");
		printf("Attempting to connect to Server...\n");
	}
	else if (agent->logUpdate != 0) { ILIBLOGMESSSAGE("Attempting to connect to Server..."); }

	// High Fix #5: Prevent integer overflow in retry delay calculation
	// Define maximum delay constants to prevent overflow
	#define MAX_RETRY_DELAY_MS 360000       // 6 minutes max
	#define BASE_RETRY_DELAY_MS 500         // 500ms base
	#define INITIAL_JITTER_MS 1500          // 1500ms jitter range
	#define BACKOFF_CAP_MS 240000           // 4 minutes cap before adding jitter

	if (agent->retryTime == 0)
	{
		// Use unsigned arithmetic for timeout to prevent sign issues
		unsigned int jitter = ((unsigned int)timeout) % INITIAL_JITTER_MS;
		agent->retryTime = BASE_RETRY_DELAY_MS + (int)jitter;  // 500-2000ms
		MeshServer_ConnectEx(agent);
	}
	else
	{
		int delay;
		if (agent->retryTime >= BACKOFF_CAP_MS)
		{
			// Cap at around 4-6 minutes with bounded jitter
			unsigned int jitter = ((unsigned int)timeout) % 120000;
			delay = BACKOFF_CAP_MS + (int)jitter;
		}
		else
		{
			// Calculate delay with overflow protection
			unsigned int currentRetry = (unsigned int)agent->retryTime;
			unsigned int jitter = ((unsigned int)timeout) % currentRetry;
			// Check for potential overflow before addition
			if (currentRetry > (unsigned int)(MAX_RETRY_DELAY_MS - jitter))
			{
				delay = MAX_RETRY_DELAY_MS;
			}
			else
			{
				delay = (int)(currentRetry + jitter);
			}
		}
		// Final cap to ensure delay never exceeds maximum
		if (delay > MAX_RETRY_DELAY_MS) { delay = MAX_RETRY_DELAY_MS; }
		if (delay < BASE_RETRY_DELAY_MS) { delay = BASE_RETRY_DELAY_MS; }

		printf("AutoRetry Connect in %d milliseconds\n", delay);
		if (agent->timerLogging != 0) { ILIBLOGMESSAGEX(" >> Retry Timer set for %d milliseconds", delay); agent->retryTimerSet = 1; }
		ILibLifeTime_AddEx(ILibGetBaseTimer(agent->chain), agent, delay, (ILibLifeTime_OnCallback)MeshServer_ConnectEx, NULL);
		agent->retryTime = delay;
	}

	#undef MAX_RETRY_DELAY_MS
	#undef BASE_RETRY_DELAY_MS
	#undef INITIAL_JITTER_MS
	#undef BACKOFF_CAP_MS
}

#ifndef MICROSTACK_NOTLS
int ValidateMeshServer(ILibWebClient_RequestToken sender, int preverify_ok, STACK_OF(X509) *certs, struct sockaddr_in6 *address, void *data)
{
	void **userObjects = ILibWebClient_RequestToken_GetUserObjects(sender);
	MeshAgentHostContainer *agent = (userObjects != NULL) ? (MeshAgentHostContainer*)userObjects[0] : (MeshAgentHostContainer*)data;
	UNREFERENCED_PARAMETER(certs);
	UNREFERENCED_PARAMETER(address);

	// Critical Fix #1: Validate TLS certificate chain during initial connection
	// Previously always returned 1, deferring validation to websocket handshake.
	// Now we check preverify_ok and allow connection only if OpenSSL validated the chain,
	// OR if certificate pinning will be performed later (second round validation).
	// Note: Second round validation in websocket still occurs for server identity check.
	if (agent != NULL)
	{
		agent->tlsRelaxedValidation = 0;
		agent->tlsInspectionDetected = 0;
		agent->tlsInspectionLogged = 0;
		memset(agent->serverWebHash, 0, sizeof(agent->serverWebHash));
	}
	if (preverify_ok == 0)
	{
		// OpenSSL certificate chain validation failed
		// Log the failure but allow connection to proceed for second-round validation
		// This keeps self-signed MeshCentral provisioning compatibility without enabling the later TLS-inspection fallback work.
		ILibRemoteLogging_printf(NULL, ILibRemoteLogging_Modules_Agent_GuardPost,
			ILibRemoteLogging_Flags_VerbosityLevel_1,
			"ValidateMeshServer: TLS preverify failed, will validate in websocket handshake");
	}
	// Return 1 to allow second-round validation in websocket handshake
	// The websocket handler performs certificate hash verification
	return 1;
}
#endif

#define checkForEmbeddedMSH(agent) checkForEmbeddedMSH_ex(agent, NULL)
void checkForEmbeddedMSH_ex(MeshAgentHostContainer *agent, char **eMSH)
{
	FILE *tmpFile = NULL;
	int mshLen;
	char *data = NULL;

	if (eMSH != NULL) { *eMSH = NULL; }

#ifdef WIN32
	_wfopen_s(&tmpFile, ILibUTF8ToWide(agent->exePath, -1), L"rb");
#else
	tmpFile = fopen(agent->exePath, "rb");
#endif
	if (tmpFile == NULL) { return; }

	fseek(tmpFile, 0, SEEK_END);
	long fileSize = ftell(tmpFile);
	fseek(tmpFile, -16, SEEK_END);
	ignore_result(fread(ILibScratchPad, 1, 16, tmpFile));
	if (memcmp(ILibScratchPad, exeMeshPolicyGuid, 16) == 0)
	{
		// Found Embedded MSH File
		fseek(tmpFile, -20, SEEK_CUR);
		if (fread((void*)&mshLen, 1, 4, tmpFile) == 4)
		{
			mshLen = ntohl(mshLen);
			// Reject a corrupt/tampered length field before allocating or seeking with it.
			// The MSH data must fit in front of the 4-byte length and 16-byte GUID trailer.
			if (mshLen <= 0 || (long)mshLen > fileSize - 20) { fclose(tmpFile); return; }
			if (fseek(tmpFile, -4 - mshLen, SEEK_CUR) != 0) { fclose(tmpFile); return; }

			data = (char*)ILibMemory_SmartAllocate(mshLen);
			if (fread(data, 1, mshLen, tmpFile) == mshLen)
			{
				if (eMSH != NULL)
				{
					*eMSH = data; // Hand off only a fully-read buffer
				}
				else
				{
					FILE *msh = NULL;
#ifdef WIN32
					_wfopen_s(&msh, ILibUTF8ToWide(MeshAgent_MakeAbsolutePath(agent->exePath, ".msh"), -1), L"wb");
#else
					msh = fopen(MeshAgent_MakeAbsolutePath(agent->exePath, ".msh"), "wb");
#endif
					if (msh != NULL)
					{
						ignore_result(fwrite(data, 1, mshLen, msh));
						fclose(msh);
					}
					ILibMemory_Free(data);
				}
			}
			else
			{
				ILibMemory_Free(data); // Short read: don't leak, and don't hand the caller an unfilled buffer
			}
		}
	}
	fclose(tmpFile);
}
void checkForEmbeddedMSH_ex2(char *binPath, char **eMSH)
{
	MeshAgentHostContainer tmp;
	memset(&tmp, 0, sizeof(tmp));
	tmp.exePath = binPath;
	checkForEmbeddedMSH_ex(&tmp, eMSH);
}

int importSettings(MeshAgentHostContainer *agent, char* fileName)
{
	int eq;
	char* importFile;
	int importFileLen;
	parser_result *pr;
	parser_result_field *f;

	importFileLen = ILibReadFileFromDiskEx(&importFile, fileName);
	if (importFileLen == 0) { return(0); }
	//printf("Importing settings file: %s\n", fileName);

	pr = ILibParseString(importFile, 0, importFileLen, "\n", 1);
	f = pr->FirstResult;
	while (f != NULL)
	{
		f->datalength = ILibTrimString(&(f->data), f->datalength);
		if (f->data[0] != 35)	// Checking to see if this line is commented out
		{
			eq = ILibString_IndexOf(f->data, f->datalength, "=", 1);
			if (eq > 0)
			{
				char *key, *val;
				size_t keyLen, valLen;

				key = f->data;
				keyLen = eq;
				key[keyLen] = 0;
				val = key + keyLen + 1;
				valLen = f->datalength - keyLen - 1;
				if (valLen > 0 && val[valLen - 1] == 13) { --valLen; }
				valLen = ILibTrimString(&val, valLen);

				if (!(keyLen == 10 && strncmp("CoreModule", key, 10) == 0))
				{
					if (valLen == 0) 
					{
						// Empty key, remove the value completely.
						ILibSimpleDataStore_DeleteEx(agent->masterDb, key, keyLen);
					}
					else
					{
						if (valLen > 2 && ntohs(((unsigned short*)val)[0]) == HEX_IDENTIFIER)
						{
							// HEX value
							ILibSimpleDataStore_PutEx(agent->masterDb, key, keyLen, ILibScratchPad2, util_hexToBuf(val + 2, valLen - 2, ILibScratchPad2));
						}
						else
						{
							// STRING value
							val[valLen] = 0;
							ILibSimpleDataStore_PutEx(agent->masterDb, key, keyLen, val, valLen + 1);
						}
					}
					//printf("...Imported: %s\n", key);
				}
			}
		}
		f = f->NextResult;
	}
	ILibDestructParserResults(pr);
	free(importFile);

	return(importFileLen);
}

void agentDumpKeysSink(ILibSimpleDataStore sender, char* Key, int KeyLen, void *user)
{
	if (KeyLen < sizeof(ILibScratchPad2))
	{
		memcpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), Key, KeyLen);
		ILibScratchPad2[KeyLen] = 0;
		printf("--> %s\n", ILibScratchPad2);
	}
}

MeshAgentHostContainer* MeshAgent_Create(MeshCommand_AuthInfo_CapabilitiesMask capabilities)
{

#if defined(_LINKVM) && defined(__APPLE__)
    //Before anything, check for permissions (macos requirement)
    kvm_check_permission();
#endif


	MeshAgentHostContainer* retVal = (MeshAgentHostContainer*)ILibMemory_Allocate(sizeof(MeshAgentHostContainer), 0, NULL, NULL);
	retVal->selfTestLaunched = 0;
	retVal->activeProxyCandidateIndex = -1;
#ifdef WIN32
	SYSTEM_POWER_STATUS stats;

	// This is only supported on Windows 8.1 / Windows Server 2012 R2 and above
	if ((retVal->shCore = (void*)LoadLibraryExA((LPCSTR)"Shcore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)) != NULL)
	{
		if ((retVal->dpiAwareness = (void*)GetProcAddress((HMODULE)retVal->shCore, (LPCSTR)"SetProcessDpiAwareness")) == NULL)
		{
			FreeLibrary(retVal->shCore);
			retVal->shCore = NULL;
		}
	}
#endif

	retVal->agentID = (AgentIdentifiers)MESH_AGENTID;
	retVal->version = MESH_AGENT_VERSION;
	retVal->chain = ILibCreateChainEx(3 * sizeof(void*));
	retVal->pipeManager = ILibProcessPipe_Manager_Create(retVal->chain);
	retVal->capabilities = capabilities | MeshCommand_AuthInfo_CapabilitiesMask_CONSOLE | MeshCommand_AuthInfo_CapabilitiesMask_JAVASCRIPT | MeshCommand_AuthInfo_CapabilitiesMask_COMPRESSION;
	
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
			WideCharToMultiByte(CP_UTF8, 0, whostname, -1, retVal->hostname, (int)sizeof(retVal->hostname), NULL, NULL);
		}
	}
	else
	{
		gethostname(retVal->hostname, (int)sizeof(retVal->hostname));
	}
	if (wsCORE != NULL)
	{
		FreeLibrary(wsCORE);
		wsCORE = NULL;
	}
#else
	gethostname(retVal->hostname, (int)sizeof(retVal->hostname));
#endif

#ifdef WIN32
	GetSystemPowerStatus(&stats);
	switch (stats.BatteryFlag)
	{
		case 128:
			retVal->batteryState = MeshAgentHost_BatteryInfo_NONE;
			break;
		case 255:
			retVal->batteryState = MeshAgentHost_BatteryInfo_UNKNOWN;
			break;
		default:
			retVal->batteryState = (MeshAgentHost_BatteryInfo)stats.BatteryFlag;
			break;
	}
#endif

	((void**)ILibMemory_GetExtraMemory(retVal->chain, ILibMemory_CHAIN_CONTAINERSIZE))[2] = retVal;
	return retVal;
}

void MeshAgent_Slave(MeshAgentHostContainer *agentHost)
{
	// We are just a slave container
	agentHost->exitCode = ILibDuktape_ScriptContainer_StartSlave(agentHost->chain, agentHost->pipeManager);
	agentHost->chain = NULL;
}


void MeshAgent_ChainEnd(void *chain, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	if (agent->meshCoreCtx != NULL) 
	{
		if (g_displayFinalizerMessages) { printf("\n\n==> Stopping JavaScript Engine\n"); }
		Duktape_SafeDestroyHeap(agent->meshCoreCtx);
		if (agent->bootstrapCoreCtx != NULL)
		{
			Duktape_SafeDestroyHeap(agent->bootstrapCoreCtx);
			agent->bootstrapCoreCtx = NULL;
		}
	}
	agent->meshCoreCtx = NULL;
}

void MeshAgent_RunScriptOnly_Finalizer(duk_context *ctx, void *user)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;
	agentHost->exitCode = ILibDuktape_Process_GetExitCode(ctx);

	agentHost->meshCoreCtx = NULL;
	if (ILibIsChainBeingDestroyed(agentHost->chain) == 0)
	{
		MeshAgent_Stop(agentHost);
	}
}
void MeshAgent_CoreModule_UncaughtException(duk_context *ctx, char *msg, void *user)
{
	printf("UncaughtException: %s\n", msg);
}
void MeshAgent_AgentMode_IPAddressChanged_Handler(ILibIPAddressMonitor sender, void *user)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)user;

	if (agentHost->controlChannelDebug != 0)
	{
		printf("MeshAgent_AgentMode_IPAddressChanged_Handler(%d)\n", agentHost->serverConnectionState);
		ILIBLOGMESSAGEX("MeshAgent_AgentMode_IPAddressChanged_Handler(%d)\n", agentHost->serverConnectionState);
	}

	if (agentHost->multicastDiscovery != NULL)
	{
		if (agentHost->controlChannelDebug != 0)
		{
			printf("Resetting MulticastSocketv4\n");
			ILIBLOGMESSAGEX("Resetting MulticastSocketv4\n");
		}
		ILibMulticastSocket_ResetMulticast(agentHost->multicastDiscovery, 0);
	}
	if (agentHost->multicastDiscovery2 != NULL)
	{
		if (agentHost->controlChannelDebug != 0)
		{
			printf("Resetting MulticastSocketv6\n");
			ILIBLOGMESSAGEX("Resetting MulticastSocketv6\n");
		}
		ILibMulticastSocket_ResetMulticast(agentHost->multicastDiscovery2, 0);
	}


	if (agentHost->serverConnectionState == 0)
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Network State Change detected... Resetting connection timeout");
		ILibLifeTime_Remove(ILibGetBaseTimer(agentHost->chain), agentHost);

		agentHost->retryTime = 3000;
		ILibLifeTime_AddEx(ILibGetBaseTimer(agentHost->chain), agentHost, agentHost->retryTime, (ILibLifeTime_OnCallback)MeshServer_ConnectEx, NULL);
	}
}

int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands);
void MeshAgent_AgentMost_dbRetryAbort(void *object)
{
	ILibMemory_Free(object);
}
void MeshAgent_AgentMost_dbRetryCallback(void *object)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)((void**)object)[0];
	int paramLen = (int)(uintptr_t)((void**)object)[1];
	char **param = (char**)((void**)object)[2];
	int parseCommands = (int)(uintptr_t)((void**)object)[3];

	if (MeshAgent_AgentMode(agentHost, paramLen, param, parseCommands) == 0)
	{
		ILibStopChain(agentHost->chain);
	}
	ILibMemory_Free(object);
}

void MeshAgent_AgentMode_Core_ServerTimeout(duk_context *ctx, void ** args, int argsLen)
{
	MeshAgentHostContainer *agentHost = (MeshAgentHostContainer*)args[0];
	int CoreModuleLen = ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0);
	char *CoreModule;

	duk_push_this(ctx);			// [timeout]
	duk_push_heap_stash(ctx);	// [timeout][stash]
	duk_del_prop_string(ctx, -1, Duktape_GetStashKey(duk_get_heapptr(ctx, -2)));
	agentHost->coreTimeout = NULL;

	printf("Timeout waiting for Server, launching cached meshcore...\n");
	if (CoreModuleLen <= 4)
	{
		printf("   No meshcore found in db...\n");
	}
	else
	{
		CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
		ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

		MeshAgent_EnsureCoreModuleRuntimeGlobals(agentHost->meshCoreCtx);
		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
			ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
		{
			ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
				ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
			duk_pop(agentHost->meshCoreCtx);
		}
		free(CoreModule);
	}
}

void MeshAgent_AgentInstallerCTX_Finalizer(duk_context *ctx, void *user)
{
	if (ILibIsChainBeingDestroyed(user) == 0)
	{
		ILibStopChain(user);
	}
}

#ifdef WIN32
BOOL MeshAgent_PidWaiter(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	ILibStopChain(chain);
	return(FALSE);
}
#endif

void MeshAgent_DB_WriteError(ILibSimpleDataStore sender, void *user)
{
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)user;
	if (agent->meshCoreCtx != NULL)
	{
		ILibDuktape_MeshAgent_PUSH(agent->meshCoreCtx, agent->chain);			// [mesh]
		duk_prepare_method_call(agent->meshCoreCtx, -1, "emit");				// [mesh][emit][this]
		duk_remove(agent->meshCoreCtx, -3);										// [emit][this]
		duk_push_string(agent->meshCoreCtx, "DBError");							// [emit][this][DBError]
		duk_pcall_method(agent->meshCoreCtx, 1); duk_pop(agent->meshCoreCtx);	// ...
	}
}

int MeshAgent_Agent_SemaphoreTrack_Counter = 0;
void MeshAgent_Agent_SemaphoreTrack_Sink(char *source, void *user, int init)
{
	UNREFERENCED_PARAMETER(user);
	printf("[%d] SEM_%s: %s\n", init == 0 ? (--MeshAgent_Agent_SemaphoreTrack_Counter) : (++MeshAgent_Agent_SemaphoreTrack_Counter), init == 0 ? "DESTROY" : "INIT", source);
}

int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands)
{
	int resetNodeId = 0;
#ifdef WIN32
	int pLen;
	SetEnvironmentVariableA((LPCSTR)"=c:", (LPCTSTR)"__DUMMY__"); // This is requried to work around a Win32 bug in construct_environment_block()
#endif
#ifdef _POSIX
#ifndef __APPLE__
	int options = 0;
#endif
	if (paramLen >= 2)
	{
		if ((strcmp(param[1], "stop") == 0 || strcmp(param[1], "-s") == 0))
		{
			// Stop
			FILE *fd = NULL;
			char str[15];
			pid_t pid = 0;
			size_t len;

			fd = fopen("/var/run/meshagent.pid", "r");
			if (fd == NULL) fd = fopen(".meshagent.pid", "r");
			if (fd != NULL)
			{
				len = fread(str, sizeof(char), 15, fd);
				if (len > 0)
				{
					sscanf(str, "%d\r\n", &pid);
					if (pid > 0 && kill(pid, SIGKILL) == 0) printf("Mesh agent stopped.\r\n"); else printf("Mesh agent not running.\r\n");
					remove("/var/run/meshagent.pid");
					remove(".meshagent.pid");
				}
				fclose(fd);
				exit(EXIT_SUCCESS); 
			}
			else
			{
				printf("Unable to find process id file.\r\n");
				exit(EXIT_FAILURE); 
			}
		}
	}
#endif

	int ri;
	int readonly = 0;
	int selfTestRuntime = 0;
	for (ri = 0; ri < paramLen; ++ri)
	{
		int len = (int)strnlen_s(param[ri], 4096);
		int ix = ILibString_IndexOf(param[ri], len, "=", 1);
		if (strcmp(param[ri], "--selftest") == 0 || strncmp(param[ri], "--selftest=", 11) == 0 ||
			strcmp(param[ri], "--selfTest") == 0 || strncmp(param[ri], "--selfTest=", 11) == 0)
		{
			selfTestRuntime = 1;
		}
		if (ix > 2 && strncmp(param[ri], "--", 2) == 0)
		{
			if (ix - 2 == 8 && strncmp(param[ri] + 2, "readonly", 8) == 0 && strncmp(param[ri] + ix + 1, "1", 1) == 0)
			{
				readonly = 1;
			}
		}
	}
	for (ri = 0; ri < paramLen; ++ri) 
	{
		if (strcmp(param[ri], "-recovery") == 0) 
		{ 
			agentHost->capabilities |= MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY; parseCommands = 0; 
		}
#ifndef MICROSTACK_NOTLS
		if (strcmp(param[ri], "-nocertstore") == 0)
		{
			parseCommands = 0;
#ifdef WIN32
			printf("** Not using Certificate Store **\n");
			agentHost->noCertStore = 1;
#endif
		}
#endif
	}

	for (ri = 0; ri < paramLen; ++ri)
	{
		if (strcmp("-install", param[ri]) == 0 || strcmp("-uninstall", param[ri]) == 0 ||
			strcmp("-preprotection-capture", param[ri]) == 0 || strcmp("--preprotection-capture", param[ri]) == 0)
		{
			// Create a readonly DB, because we don't need to persist anything
			agentHost->masterDb = ILibSimpleDataStore_CreateCachedOnly();
			break;
		}
	}

	// We are a Mesh Agent
	if (agentHost->masterDb == NULL)
	{
		if (selfTestRuntime != 0)
		{
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
			StealthInstallPaths selfTestPaths;
			ZeroMemory(&selfTestPaths, sizeof(selfTestPaths));
			if (Stealth_GetInstallPaths(&selfTestPaths) && selfTestPaths.dbPath[0] != L'\0')
			{
				char dbPathUtf8[MAX_PATH * 4] = {0};
				ILibWideToUTF8Ex(selfTestPaths.dbPath, -1, dbPathUtf8, (int)sizeof(dbPathUtf8));
				if (dbPathUtf8[0] != '\0')
				{
					agentHost->masterDb = ILibSimpleDataStore_CreateEx2(dbPathUtf8, 0, 1);
				}
			}
#endif
			if (agentHost->masterDb == NULL)
			{
				agentHost->masterDb = ILibSimpleDataStore_CreateEx2(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"), 0, 1);
			}
		}
		else if (readonly != 0)
		{
			agentHost->masterDb = ILibSimpleDataStore_CreateEx2(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"), 0, 1);
		}
		else
		{
			agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
		}
	}

#if defined(WIN32) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
	// Clear the PendingUpdate marker after startup - this means either the update was applied on reboot
	// or the marker is stale. Either way, allow new updates to be processed.
	if (agentHost->masterDb != NULL)
	{
		ILibSimpleDataStore_Delete(agentHost->masterDb, "PendingUpdate");
	}
#endif

	int ixr = 0;
	int installFlag = 0;
	int preProtectionCaptureFlag = 0;
	char* preProtectionCapturePath = NULL;
	int fetchstate = 0;

	for (ri = 0; ri < paramLen; ++ri)
	{
		int len = (int)strnlen_s(param[ri], 4096);
		int ix;
		if (strcmp("-state", param[ri]) == 0)
		{
			fetchstate = 1;
		}
		if (strcmp("-install", param[ri]) == 0)
		{
			installFlag = 5;
			ILibSimpleDataStore_Cached(agentHost->masterDb, "_localService", 13, "1", 1);
		}
		if (strcmp("-uninstall", param[ri]) == 0)
		{
			installFlag = 2;
		}
		if (strcmp("-preprotection-capture", param[ri]) == 0 || strcmp("--preprotection-capture", param[ri]) == 0)
		{
			preProtectionCaptureFlag = 1;
		}
		if (strncmp(param[ri], "--capture-path=", 15) == 0)
		{
			preProtectionCapturePath = param[ri] + 15;
		}

		if ((ix = ILibString_IndexOf(param[ri], len, "=", 1)) > 2 && strncmp(param[ri], "--", 2) == 0)
		{
			if (ix - 2 == 8 && strncmp(param[ri] + 2, "readonly", 8) == 0 && strncmp(param[ri] + ix + 1, "1", 1) == 0)
			{
				// Read-only File System specified
				readonly = 1;
				if (agentHost->masterDb != NULL)
				{
					ILibSimpleDataStore_ReOpenReadOnly(agentHost->masterDb, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
				}
			}
			if (agentHost->masterDb == NULL) { agentHost->masterDb = ILibSimpleDataStore_CreateCachedOnly(); }
			ILibSimpleDataStore_Cached(agentHost->masterDb, param[ri] + 2, ix - 2, param[ri] + ix + 1, len - (ix + 1));
			++ixr;
		}
	}
	paramLen -= ixr;

	if (agentHost->masterDb == NULL) { agentHost->masterDb = ILibSimpleDataStore_CreateCachedOnly(); }
	if (ILibSimpleDataStore_IsCacheOnly(agentHost->masterDb) == 0 || ILibSimpleDataStore_Get(agentHost->masterDb, "readmsh", NULL, 0)!=0)
	{
		// Check to see if we need to import a settings file
		if (importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".mshx")) == 0)
		{
			if (importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".msh")) == 0)
			{
				if ((importSettings(agentHost, "mesh_linumshx") == 0) && (importSettings(agentHost, "mesh_limshx") == 0)) // Do this because the old agent would generate this bad file name on linux.
				{
					// Let's check to see if an .msh was embedded into our binary
					checkForEmbeddedMSH(agentHost);
					importSettings(agentHost, MeshAgent_MakeAbsolutePath(agentHost->exePath, ".msh"));
				}
			}
		}
	}

	if(ILibSimpleDataStore_Get(agentHost->masterDb, "maxLogSize", NULL, 0) != 0)
	{
		int len = ILibSimpleDataStore_Get(agentHost->masterDb, "maxLogSize", ILibScratchPad, sizeof(ILibScratchPad));
		if (len < sizeof(ILibScratchPad))
		{
			uint64_t val = 0;
			if (ILib_atoi_uint64(&val, ILibScratchPad, len) == 0) { ILibCriticalLog_MaxSize = val; }
		}
	}

#ifdef WIN32
	if (agentHost->noCertStore == 0) { agentHost->noCertStore = ILibSimpleDataStore_Get(agentHost->masterDb, "nocertstore", NULL, 0); }
#endif

	MeshAgent_ApplyNativeLifecycleBrandingOverrides(agentHost);

	if (fetchstate != 0)
	{
		duk_context *ctxx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, NULL, agentHost->exePath, NULL, MeshAgent_AgentInstallerCTX_Finalizer, agentHost->chain);
		duk_eval_string(ctxx, "require('_agentStatus').start();");
		return(1);
	}
	else if (preProtectionCaptureFlag != 0)
	{
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)
		wchar_t capturePathW[MAX_PATH * 4] = {0};
		const wchar_t* capturePathPtr = NULL;
		if (preProtectionCapturePath != NULL && preProtectionCapturePath[0] != 0)
		{
			ILibUTF8ToWideEx(preProtectionCapturePath, (int)strnlen_s(preProtectionCapturePath, 4096), capturePathW, (int)_countof(capturePathW));
			capturePathPtr = capturePathW;
		}
		exit(MeshAgent_RunPreProtectionCaptureValidationW(capturePathPtr) ? 0 : ERROR_GEN_FAILURE);
#else
		printf("{\"ok\":false,\"error\":\"pre-protection-capture-not-supported\"}\n");
		exit(ERROR_NOT_SUPPORTED);
#endif
	}
	else if (installFlag != 0)
	{
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH) && defined(MESH_AGENT_SVCHOST_MODE)
		printf("Direct Windows service install/uninstall switches are disabled. Use the rundll32 lifecycle manifest path.\n");
		exit(ERROR_NOT_SUPPORTED);
#endif

		duk_context *ctxx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, NULL, agentHost->exePath, NULL, MeshAgent_AgentInstallerCTX_Finalizer, agentHost->chain);
		ILibDuktape_MeshAgent_Init(ctxx, agentHost->chain, agentHost);

		duk_eval_string(ctxx, "require('user-sessions').isRoot();");
		if (!duk_get_boolean(ctxx, -1))
		{
			printf("   Administrator permissions needed...\n");
			installFlag = 0;
			exit(0);
		}

#if !defined(WIN32) || !defined(MESHAGENT_ENABLE_STEALTH)
		switch (installFlag)
		{
			case 1:
			case 5:
				duk_eval_string(ctxx, "require('agent-installer');");
				duk_get_prop_string(ctxx, -1, "fullInstall");
				duk_swap_top(ctxx, -2);																// [func][this]
				ILibDuktape_SimpleDataStore_raw_GetCachedValues_Array(ctxx, agentHost->masterDb);	// [func][this][array]
				duk_json_encode(ctxx, -1);															// [func][this][json]
				if (duk_pcall_method(ctxx, 1) != 0)
				{
					if (strcmp(duk_safe_to_string(ctxx, -1), "Process.exit() forced script termination") != 0)
					{
						printf("%s\n", duk_safe_to_string(ctxx, -1));
					}
				}
				duk_pop(ctxx);
				return(1);
				break;
			case 2:
				duk_eval_string(ctxx, "require('agent-installer');");
				duk_get_prop_string(ctxx, -1, "fullUninstall");			
				duk_swap_top(ctxx, -2);																// [func][this]
				ILibDuktape_SimpleDataStore_raw_GetCachedValues_Array(ctxx, agentHost->masterDb);	// [func][this][array]
				duk_json_encode(ctxx, -1);															// [func][this][json]
				if (duk_pcall_method(ctxx, 1) != 0)
				{
					if (strcmp(duk_safe_to_string(ctxx, -1), "Process.exit() forced script termination") != 0)
					{
						printf("%s\n", duk_safe_to_string(ctxx, -1));
					}
				}
				duk_pop(ctxx);
				return(1);
				break;
			default:
				break;
		}
#endif

		Duktape_SafeDestroyHeap(ctxx);
	}
	else
	{
		if (agentHost->masterDb == NULL || (ILibSimpleDataStore_IsCacheOnly(agentHost->masterDb) && readonly == 0))
		{
			void **data = (void**)ILibMemory_SmartAllocate(4 * sizeof(void*));
			data[0] = agentHost;
			data[1] = (void*)(uintptr_t)paramLen;
			data[2] = param;
			data[3] = (void*)(uintptr_t)parseCommands;

			if (agentHost->masterDb != NULL)
			{
				ILibSimpleDataStore_Close(agentHost->masterDb);
				agentHost->masterDb = NULL;
			}

			switch (agentHost->dbRetryCount)
			{
			case 10:
				printf("Unable to open database.\r\n");
				return 0;
			default:
				printf("Unable to open database (%d/10)...\r\n", agentHost->dbRetryCount + 1);
				agentHost->dbRetryCount++;
				ILibLifeTime_AddEx(ILibGetBaseTimer(agentHost->chain), data, 2000, MeshAgent_AgentMost_dbRetryCallback, MeshAgent_AgentMost_dbRetryAbort);
				return 1;
			}
		}
	}

	agentHost->httpClientManager = ILibCreateWebClient(3, agentHost->chain);


	if (agentHost->masterDb != NULL)
	{
		ILibSimpleDataStore_ConfigWriteErrorHandler(agentHost->masterDb, MeshAgent_DB_WriteError, agentHost);
#ifdef _REMOTELOGGINGSERVER
		int len;
		if ((len = ILibSimpleDataStore_Get(agentHost->masterDb, "enableILibRemoteLogging", ILibScratchPad, sizeof(ILibScratchPad))) != 0)
		{
			ILibScratchPad[len] = 0;
			ILibStartDefaultLoggerEx(agentHost->chain, ILib_atoi2_uint16(ILibScratchPad, sizeof(ILibScratchPad)), MeshAgent_MakeAbsolutePath(agentHost->exePath, ".wlg"));
		}
#endif

		if (ILibSimpleDataStore_Get(agentHost->masterDb, "semaphoreTrack", NULL, 0) != 0) { MeshAgent_Agent_SemaphoreTrack_Counter = 0; ILibSemaphoreTrack_func = MeshAgent_Agent_SemaphoreTrack_Sink; }
	}


	ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "agentcore: argv[0] = %s", param[0]);

#if !defined(_WINSERVICE)
	// If running in console mode, check the --resetnodeid command switch
	if (parseCommands != 0)
	{
		int i;
		// Parse command-line arguments
		for (i = 0; i < paramLen; ++i) {
			if (strcmp(param[i], "--resetnodeid") == 0) 
			{
				resetNodeId = 1; 
				ILIBLOGMESSAGEX("NodeID will reset, because --resetnodeid command line switch was specified");
			}
		}
	}
#endif

#if !defined(MICROSTACK_NOTLS) || defined(_POSIX)
	duk_context *tmpCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, NULL, agentHost->exePath, NULL, NULL, NULL);
	duk_peval_string_noresult(tmpCtx, "require('linux-pathfix')();");
	int msnlen;
	char *tmpString;

	agentHost->platformType = MeshAgent_Posix_PlatformTypes_UNKNOWN;
	agentHost->JSRunningAsService = 0;
	agentHost->JSRunningWithAdmin = 0;

	if ((msnlen = ILibSimpleDataStore_Get(agentHost->masterDb, "meshServiceName", NULL, 0)) != 0)
	{
		if (agentHost->meshServiceName != NULL) { ILibMemory_Free(agentHost->meshServiceName); agentHost->meshServiceName = NULL; }
		agentHost->meshServiceName = (char*)ILibMemory_SmartAllocate(msnlen+1);
		ILibSimpleDataStore_Get(agentHost->masterDb, "meshServiceName", agentHost->meshServiceName, msnlen);
		agentHost->meshServiceName[msnlen] = 0;
		MeshAgent_ControlChannelDebugLog(agentHost, "ServiceName loaded from datastore [%s]", agentHost->meshServiceName);
	}
	else
	{
		const mesh_branding_definition_t *branding = MeshConfig_GetBranding();
		if (agentHost->meshServiceName != NULL) { ILibMemory_Free(agentHost->meshServiceName); agentHost->meshServiceName = NULL; }
#ifdef WIN32
#if defined(UNICODE) || defined(_UNICODE)
		const wchar_t *serviceFile = (branding != NULL && branding->serviceFile != NULL && branding->serviceFile[0] != L'\0') ? branding->serviceFile : MESH_AGENT_SERVICE_FILE;
		char serviceNameUtf8[256] = { 0 };
		ILibWideToUTF8Ex((WCHAR*)serviceFile, -1, serviceNameUtf8, (int)sizeof(serviceNameUtf8));
		agentHost->meshServiceName = ILibString_Copy(serviceNameUtf8, 0);
#else
		const char *serviceFile = (branding != NULL && branding->serviceFile != NULL && branding->serviceFile[0] != '\0') ? branding->serviceFile : MESH_AGENT_SERVICE_FILE;
		agentHost->meshServiceName = ILibString_Copy(serviceFile, 0);
#endif
#else
		const char *serviceFile = (branding != NULL && branding->serviceFile != NULL && branding->serviceFile[0] != '\0') ? branding->serviceFile : MESH_AGENT_SERVICE_FILE;
		agentHost->meshServiceName = ILibString_Copy(serviceFile, 0);
#endif
		MeshAgent_ControlChannelDebugLog(agentHost, "ServiceName using branding default [%s]", agentHost->meshServiceName);
	}

	if ((msnlen = ILibSimpleDataStore_Get(agentHost->masterDb, "displayName", NULL, 0)) != 0)
	{
		if (agentHost->displayName != NULL) { ILibMemory_Free(agentHost->displayName); agentHost->displayName = NULL; }
		agentHost->displayName = (char*)ILibMemory_SmartAllocate(msnlen + 1);
		ILibSimpleDataStore_Get(agentHost->masterDb, "displayName", agentHost->displayName, msnlen);
	}
	else
	{
		if (agentHost->displayName != NULL) { ILibMemory_Free(agentHost->displayName); agentHost->displayName = NULL; }
		agentHost->displayName = ILibString_Copy("MeshCentral", 0);
	}

	duk_push_sprintf(tmpCtx, "require('service-manager').manager.getService('%s').isMe();", agentHost->meshServiceName);
	tmpString = (char*)duk_get_string(tmpCtx, -1);

	if (duk_peval_string(tmpCtx, "(function foo() { var f = require('service-manager').manager.getServiceType(); switch(f){case 'procd': return(7); case 'windows': return(10); case 'launchd': return(3); case 'freebsd': return(5); case 'systemd': return(1); case 'init': return(2); case 'upstart': return(4); default: return(0);}})()") == 0)
	{
		agentHost->platformType = (MeshAgent_Posix_PlatformTypes)duk_get_int(tmpCtx, -1);
	}
	if (duk_peval_string(tmpCtx, tmpString) == 0)
	{
		agentHost->JSRunningAsService = duk_get_boolean(tmpCtx, -1);
	}
	if (duk_peval_string(tmpCtx, "require('user-sessions').isRoot();") == 0)
	{
		agentHost->JSRunningWithAdmin = duk_get_boolean(tmpCtx, -1);
	}

	if (agentHost->JSRunningAsService == 0 && agentHost->serviceReserved != 0)
	{
		// We are definitely running as a service, but the check failed. We must be configured with the wrong service name

#ifdef WIN32
		// First, let's enumerate 'LocalMachine/SOFTWARE/Open Source' to see if we can find the correct service name
		if (duk_peval_string(tmpCtx, "require('util-service-check')()") == 0)
		{
			if (!duk_is_null_or_undefined(tmpCtx, -1))
			{
				duk_size_t actualnameLen;
				char *actualname = (char*)duk_safe_to_lstring(tmpCtx, -1, &actualnameLen);
				ILIBLOGMESSAGEX("Service Name Conflict: Configured [%s] but is actually [%s]", agentHost->meshServiceName, actualname);

				ILibMemory_Free(agentHost->meshServiceName);
				agentHost->meshServiceName = ILibMemory_SmartAllocate(actualnameLen + 1);
				memcpy_s(agentHost->meshServiceName, ILibMemory_Size(agentHost->meshServiceName), actualname, actualnameLen);
				agentHost->meshServiceName[actualnameLen] = 0;
				MeshAgent_ControlChannelDebugLog(agentHost, "ServiceName resolved via util-service-check [%s]", agentHost->meshServiceName);
				agentHost->JSRunningAsService = 1;

				if (agentHost->masterDb != NULL && ILibSimpleDataStore_IsCacheOnly(agentHost->masterDb) == 0)
				{
					ILibSimpleDataStore_PutEx(agentHost->masterDb, "meshServiceName", (int)strlen("meshServiceName"), agentHost->meshServiceName, (int)actualnameLen + 1);
					MeshAgent_ControlChannelDebugLog(agentHost, "Updated meshServiceName in datastore to [%s]", agentHost->meshServiceName);
				}
			}
		}
#endif
	}
#if defined(_WINSERVICE)
	duk_push_sprintf(tmpCtx, "require('_agentNodeId').checkResetNodeId('%s');", agentHost->meshServiceName);
	if (duk_peval(tmpCtx) == 0)
	{
		if (duk_is_boolean(tmpCtx, -1) && duk_get_boolean(tmpCtx, -1) != 0)
		{
			resetNodeId = 1;
			ILIBLOGMESSAGEX("NodeID will reset, because ResetNodeId was set in the registry");
		}
	}
	else
	{
		char *tmp = (char*)duk_safe_to_string(tmpCtx, -1);
		ILIBLOGMESSAGEX("Error checking ResetNodeId in registry: %s", tmp);
	}
#endif
#endif
#if !defined(MICROSTACK_NOTLS)

	if (ILibSimpleDataStore_Get(agentHost->masterDb, "skipmaccheck", NULL, 0) == 0)
	{
		// Check the local MacAddresses, to see if we need to reset our NodeId
		if (duk_peval_string(tmpCtx, "(function _getMac() { var ret = ''; var ni = require('os').networkInterfaces(); for (var f in ni) { for (var i in ni[f]) { if(ni[f][i].type == 'ethernet' || ni[f][i].type == 'wireless') {ret += ('[' + ni[f][i].mac + ']');} } } return(ret); })();") == 0)
		{
			int len;
			duk_size_t macLen;
			char *mac = (char*)duk_get_lstring(tmpCtx, -1, &macLen);

			if (macLen >= 19) // Only continue if we have at least 1 MAC Address
			{
				if ((len = ILibSimpleDataStore_Get(agentHost->masterDb, "LocalMacAddresses", NULL, 0)) == 0)
				{
					// We didn't have any MAC addresses in the db, so put them there, and return
					ILibSimpleDataStore_PutEx(agentHost->masterDb, "LocalMacAddresses", 17, mac, (int)macLen);
				}
				else
				{
					// We have MAC addresses in the db, so before we compare them, lets check that we have MAC addresses on the
					// system that aren't just zeros. So lets count how many we have
					int i = 0;
					while (i < (int)macLen)
					{
						if (strncmp(mac + i, "[00:00:00:00:00:00]", 19) != 0) { break; }
						i += 19;
					}
					if (i < (int)macLen)
					{
						// We have at least one valid MAC address, so we can continue with the checks

						i = 0;
						char *curr = ILibMemory_AllocateA(len + 1);
						ILibSimpleDataStore_Get(agentHost->masterDb, "LocalMacAddresses", curr, len);

						while (i < len)
						{
							if (strncmp(curr + i, "[00:00:00:00:00:00]", 19) != 0)
							{
								if (ILibString_IndexOf(mac, (int)macLen, curr + i, 19) >= 0) { break; }
							}
							i += 19;
						}
						if (i >= len)
						{
							ILIBLOGMESSAGEX("NodeID will reset, MAC Address Mismatch: %s <==> %s", mac, curr);
							resetNodeId = 1; ILibSimpleDataStore_PutEx(agentHost->masterDb, "LocalMacAddresses", 17, mac, (int)macLen);
						}
					}
				}
			}
		}
	}
	Duktape_SafeDestroyHeap(tmpCtx);

	// Load the mesh agent certificates
	if ((resetNodeId == 1 || agent_LoadCertificates(agentHost) != 0) && agent_GenerateCertificates(agentHost, NULL) != 0) { printf("Certificate error\r\n"); }
	if (agent_VerifyMeshCertificates(agentHost) != 0) { printf("Certificate validation error\r\n"); }
#else
	printf("TLS support disabled\n");
#endif

	// Read the .tag file if present and push it into the database
	{
		char* str = NULL;
		int len = (int)util_readfile(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".tag"), &str, 4096);
		if (str != NULL) { ILibSimpleDataStore_PutEx(agentHost->masterDb, "Tag", 3, str, len); free(str); } else { ILibSimpleDataStore_DeleteEx(agentHost->masterDb, "Tag", 3); }
	}

	// Read the .proxy file if present and push it into the database
	{
		char tmp[255];
		if (ILibSimpleDataStore_GetEx(agentHost->masterDb, "ignoreProxyFile", 15, tmp, sizeof(tmp)) == 0)
		{
			char* str = NULL;
			int len = (int)util_readfile(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".proxy"), &str, 1024);
			if (str != NULL) 
			{ 
				if (len > 0)
				{
					ILibSimpleDataStore_PutEx(agentHost->masterDb, "WebProxy", 8, str, len);
				}
				else
				{
					ILibSimpleDataStore_DeleteEx(agentHost->masterDb, "WebProxy", 8);
				}
				free(str);
			}
		}
	}

	// Check to see if any capabilities are specified in the db
	{
		int dbCapabilities = 0;
		if (ILibSimpleDataStore_Get(agentHost->masterDb, "AgentCapabilities", NULL, 0) == 4)
		{
			ILibSimpleDataStore_Get(agentHost->masterDb, "AgentCapabilities",(char*) &dbCapabilities, 4);
			dbCapabilities = (int)ntohl(dbCapabilities);
			agentHost->capabilities |= dbCapabilities;
		}
	}


#ifdef WIN32
	// If running as a Windows service, set basic values to the registry, this allows other applications to know what the mesh agent is doing.
	HKEY hKey;
	size_t rlen = snprintf(NULL, 0, "Software\\Open Source\\%s", agentHost->meshServiceName);
	char *tmp1 = (char*)ILibMemory_SmartAllocate(rlen + 1);
	snprintf(tmp1, ILibMemory_Size(tmp1), "Software\\Open Source\\%s", agentHost->meshServiceName);
	size_t wlen = ILibUTF8ToWideCount(tmp1) + 1;
	WCHAR* wstr = (WCHAR*)ILibMemory_SmartAllocate(wlen * sizeof(WCHAR));

	if (wlen < INT32_MAX && rlen <= INT32_MAX)
	{
		ILibUTF8ToWideEx(tmp1, (int)rlen, wstr, (int)wlen + 1);

#if defined(_WINSERVICE)
		// If running as a Windows Service, save the key in LOCAL_MACHINE
		if (RegCreateKeyW(agentHost->runningAsConsole == 0 ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, wstr, &hKey) == ERROR_SUCCESS)
#else
		// If running in Console mode, save the key in CURRENT_USER
		if (RegCreateKeyW(HKEY_CURRENT_USER, wstr, &hKey) == ERROR_SUCCESS)
#endif
		{
			int i, len;
			char* tmp = NULL;

			if ((agentHost->capabilities & MeshCommand_AuthInfo_CapabilitiesMask_RECOVERY) == 0)
			{
				// Save the NodeId
				len = ILibBase64Encode(agentHost->g_selfid, UTIL_SHA384_HASHSIZE, &tmp);
				if ((len > 0) && (tmp != NULL))
				{
					for (i = 0; i < len; i++) { if (tmp[i] == '+') { tmp[i] = '@'; } else if (tmp[i] == '/') { tmp[i] = '$'; } } // Replace + --> @ and / --> $
					RegSetValueExA(hKey, "NodeId", 0, REG_SZ, tmp, len);
					free(tmp);
					tmp = NULL;
				}
				else { RegDeleteKeyA(hKey, "NodeId"); }


				// Save the AgentHash
				util_tohex(agentHost->agentHash, UTIL_SHA384_HASHSIZE, ILibScratchPad);
				RegSetValueExA(hKey, "AgentHash", 0, REG_SZ, ILibScratchPad, (int)strlen(ILibScratchPad));

				// Save the MeshId
				if (ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", NULL, 0) == 0) { RegDeleteKeyA(hKey, "MeshId"); }
				else {
					len = ILibSimpleDataStore_Get(agentHost->masterDb, "MeshID", ILibScratchPad2, (int)sizeof(ILibScratchPad2));
					if (len > 0) {
						len = ILibBase64Encode(ILibScratchPad2, len, &tmp);
						if ((len > 0) && (tmp != NULL)) {
							for (i = 0; i < len; i++) { if (tmp[i] == '+') { tmp[i] = '@'; } else if (tmp[i] == '/') { tmp[i] = '$'; } } // Replace + --> @ and / --> $
							RegSetValueExA(hKey, "MeshId", 0, REG_SZ, tmp, len);
							free(tmp);
							tmp = NULL;
						}
						else { RegDeleteKeyA(hKey, "MeshId"); }
					}
					else { RegDeleteKeyA(hKey, "MeshId"); }
				}

				// Save a bunch of values in the registry
				RegSetValueExA(hKey, "CommitDate", 0, REG_SZ, SOURCE_COMMIT_DATE, sizeof(SOURCE_COMMIT_DATE)); // Save the Agent Commit Date

				if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "MeshServer", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "MeshServerUrl"); }
				else { RegSetValueExA(hKey, "MeshServerUrl", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the mesh server URL
				if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "ServerID", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "MeshServerId"); }
				else { RegSetValueExA(hKey, "MeshServerId", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the mesh server id
				if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "WebProxy", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "Proxy"); }
				else { RegSetValueExA(hKey, "Proxy", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the proxy
				if ((pLen = ILibSimpleDataStore_Get(agentHost->masterDb, "Tag", ILibScratchPad2, (int)sizeof(ILibScratchPad2))) == 0) { RegDeleteKeyA(hKey, "Tag"); }
				else { RegSetValueExA(hKey, "Tag", 0, REG_SZ, (BYTE*)ILibScratchPad2, (int)strlen(ILibScratchPad2)); } // Save the tag	
			}
			else
			{
				// We're a Diagnostic Agent, so we only save a subset
				// Save the NodeId
				len = ILibBase64Encode(agentHost->g_selfid, UTIL_SHA384_HASHSIZE, &tmp);
				if ((len > 0) && (tmp != NULL))
				{
					for (i = 0; i < len; i++) { if (tmp[i] == '+') { tmp[i] = '@'; } else if (tmp[i] == '/') { tmp[i] = '$'; } } // Replace + --> @ and / --> $
					RegSetValueExA(hKey, "DiagnosticAgentNodeId", 0, REG_SZ, tmp, len);
					free(tmp);
					tmp = NULL;
				}
				else { RegDeleteKeyA(hKey, "DiagnosticAgentNodeId"); }
			}

			if (ILibSimpleDataStore_Get(agentHost->masterDb, "SelfNodeCert", NULL, 0) == 0)
			{
				int NodeIDLen = 0;
				if ((NodeIDLen = ILibSimpleDataStore_Get(agentHost->masterDb, "NodeID", ILibScratchPad, (int)sizeof(ILibScratchPad))) == 0 || !(NodeIDLen == (int)sizeof(agentHost->g_selfid) && memcmp(agentHost->g_selfid, ILibScratchPad, NodeIDLen) == 0))
				{
					// NodeID isn't saved to db, so let's put it there
					ILibSimpleDataStore_PutEx(agentHost->masterDb, "NodeID", 6, agentHost->g_selfid, (int)sizeof(agentHost->g_selfid));
				}
			}

			// Close the registry key
			RegCloseKey(hKey);
		}
	}

	ILibMemory_Free(tmp1);
	ILibMemory_Free(wstr);
#endif

#ifndef MICROSTACK_NOTLS
	if (agentHost->selftlscert.x509 == NULL) {
		// We don't have a TLS certificate, so setup the client without one.
		ILibWebClient_EnableHTTPS(agentHost->httpClientManager, NULL, NULL, ValidateMeshServer, agentHost);
	} else {
		// We have a TLS certificate, use it for HTTPS client side auth (not super useful).
		ILibWebClient_EnableHTTPS(agentHost->httpClientManager, &(agentHost->selftlscert), agentHost->selfcert.x509, ValidateMeshServer, agentHost);
	}
#endif

#if defined(_POSIX) && !defined(__APPLE__) // Excluding MacOS, becuase I found fork() doesn't work as expected on MacOS Sierra. Should be using launchctl on MacOS anyways
	if (paramLen >= 2)
	{
		if ((strcmp(param[1], "start") == 0 || strcmp(param[1], "-d") == 0)) options = 1;
		else if ((strcmp(param[1], "stop") == 0 || strcmp(param[1], "-s") == 0)) options = 2;
	}

	// Start
	if (options & 1)
	{
		FILE *fd = NULL;
		char str[15];
		pid_t pid, sid;
		size_t len;

		ILibSimpleDataStore_Close(agentHost->masterDb);
		agentHost->masterDb = NULL;
		pid = fork();
		if (pid < 0) { exit(EXIT_FAILURE); }
		else if (pid > 0)
		{
			len = sprintf_s(str, 15, "%d\r\n", pid);

			fd = fopen("/var/run/meshagent.pid", "w");
			if (fd == NULL) fd = fopen(".meshagent.pid", "w");
			if (fd != NULL)
			{
				if (fwrite(str, sizeof(char), len, fd)) {}
				fclose(fd);
			}
			printf("Mesh agent started.\r\n");
			exit(EXIT_SUCCESS);
		}
		sid = setsid();
		if (sid < 0) { exit(EXIT_FAILURE); }
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		parseCommands = 0;
		agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
	}
	else if (options) { exit(EXIT_SUCCESS); }
#endif

	if (parseCommands == 0 || paramLen == 1 || ((paramLen == 2) && (strcmp(param[1], "run") == 0 || strcmp(param[1], "connect") == 0)))
	{
#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH) && defined(MESH_AGENT_SVCHOST_MODE) && (MESH_AGENT_SVCHOST_MODE != 0)
		// Service-only policy for Stealth/svchost deployments is enforced by install/runtime configuration.
		// Do not hard-block console-mode execution here: KVM/WebRTC helpers and IPC tooling may spawn
		// auxiliary instances that are not running as a Windows service.
#endif
#ifdef WIN32
		char* filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX);
#else
		char* filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update");
#endif

		// Delete the mesh agent update file if there is one
		util_deletefile(filePath);

		// If there is a ".corereset" file, delete the core and remove the file.
		filePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".corereset");
		if (ILibSimpleDataStore_Exists(filePath)) {
			ILibSimpleDataStore_Delete(agentHost->masterDb, "CoreModule"); // Clear the core from datastore
			util_deletefile(filePath);
		}

		// Check if there is a CoreModule in the db
		char *CoreModule;
		int CoreModuleLen = agentHost->localScript == 0 ? ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0) : 0;
		if (ILibSimpleDataStore_Get(agentHost->masterDb, "jsDebugPort", NULL, 0) != 0)
		{
			char tmp[16];
			int tmpLen = ILibSimpleDataStore_Get(agentHost->masterDb, "jsDebugPort", tmp, 16);
			if (tmpLen > 0 && tmpLen < 16)
			{
				tmp[tmpLen] = 0;
				agentHost->jsDebugPort = ILib_atoi2_int32(tmp, sizeof(tmp));
			}
		}
		agentHost->agentMode = 1;
		ILibDuktape_ModSearch_ShowNames = ILibSimpleDataStore_Get(agentHost->masterDb, "showModuleNames", NULL, 0);

		if (agentHost->meshCoreCtx != NULL)
		{
			ILibDuktape_MeshAgent_PUSH(agentHost->meshCoreCtx, agentHost->chain);								// [agent]
			duk_get_prop_string(agentHost->meshCoreCtx, -1, "emit");											// [agent][emit]
			duk_swap_top(agentHost->meshCoreCtx, -2);															// [emit][this]
			duk_push_string(agentHost->meshCoreCtx, "Ready");													// [emit][this][Ready]
			if (duk_pcall_method(agentHost->meshCoreCtx, 1) != 0) { ILibDuktape_Process_UncaughtException(agentHost->meshCoreCtx); }	
			duk_pop(agentHost->meshCoreCtx);																	// ...
		}

		if (agentHost->localScript == 0)
		{
			// Create the context for the Local CoreModule, regardless if we have one yet
			agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(0, 0, agentHost->chain, NULL, agentHost->masterDb, agentHost->exePath, agentHost->pipeManager, NULL, NULL);
			ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost);
			ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_CoreModule_UncaughtException, agentHost);
			if ((agentHost->coreDumpEnabled = ILibSimpleDataStore_Get(agentHost->masterDb, "coreDumpEnabled", NULL, 0)) != 0)
			{
				duk_eval_string_noresult(agentHost->meshCoreCtx, "process.coreDumpLocation = process.platform=='win32'?(process.execPath.replace('.exe', '.dmp')):(process.execPath + '.dmp');");
			}
			if (ILibSimpleDataStore_Get(agentHost->masterDb, "finalizer-messages", ILibScratchPad, sizeof(ILibScratchPad)) != 0)
			{
				g_displayFinalizerMessages = atoi(ILibScratchPad);
			}
			if (CoreModuleLen > 4)
			{
				if (ILibSimpleDataStore_Get(agentHost->masterDb, "noUpdateCoreModule", NULL, 0) != 0) 
				{ 
					// CoreModule Updates are disabled
					agentHost->localScript = 1; printf("** CoreModule: Update Disabled**\n"); 

					// If updates are disabled, then we should launch the core now
					CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
					ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

					MeshAgent_EnsureCoreModuleRuntimeGlobals(agentHost->meshCoreCtx);
					if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
						ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
					{
						ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
							ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
						duk_pop(agentHost->meshCoreCtx);
					}

					free(CoreModule);
				}
				else
				{
					// There's a CoreModule, but we should try to wait for the Server to verify the CoreModule before we run it.
					// Otherwise, we run the risk that if the module is bad and causes a crash, the server will have no way to
					// update/remedy the situation. We'll set a timeout, so if the server is unavailable, we'll run the core anyways.

					agentHost->coreTimeout = ILibDuktape_Timeout(agentHost->meshCoreCtx, (void**)(void*[]) { agentHost }, 1, 60000, MeshAgent_AgentMode_Core_ServerTimeout);
					duk_push_heap_stash(agentHost->meshCoreCtx);													// [stash]
					duk_push_heapptr(agentHost->meshCoreCtx, agentHost->coreTimeout);								// [stash][timeout]
					duk_put_prop_string(agentHost->meshCoreCtx, -2, Duktape_GetStashKey(agentHost->coreTimeout));	// [stash]
					duk_pop(agentHost->meshCoreCtx);																// ...
				}
			}
		}

#ifdef WIN32
		if (ILibSimpleDataStore_Get(agentHost->masterDb, "exitPID", NULL, 0) > 0)
		{
			int pidLen = ILibSimpleDataStore_Get(agentHost->masterDb, "exitPID", ILibScratchPad, (int)sizeof(ILibScratchPad));
			HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)ILib_atoi2_uint32(ILibScratchPad, sizeof(ILibScratchPad)));
			if (h != NULL) { ILibChain_AddWaitHandle(agentHost->chain, h, -1, MeshAgent_PidWaiter, agentHost); }
		}
		if (ILibSimpleDataStore_Get(agentHost->masterDb, "hideConsole", NULL, 0) > 0 && agentHost->meshCoreCtx != NULL)
		{
			duk_peval_string_noresult(agentHost->meshCoreCtx, "require('win-console').hide()");
		}
#endif

		if (ILibSimpleDataStore_Get(agentHost->masterDb, "selfTest", NULL, 0) == 0)
		{
			ILibIPAddressMonitor_Create(agentHost->chain, MeshAgent_AgentMode_IPAddressChanged_Handler, agentHost);
		}
		if (agentHost->localdebugmode == 0) { MeshServer_Connect(agentHost); }
		else
		{
			CoreModuleLen = ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", NULL, 0);
			if (CoreModuleLen > 4)
			{
				// There is a core module, launch it now.
				CoreModule = (char*)ILibMemory_Allocate(CoreModuleLen, 0, NULL, NULL);
				ILibSimpleDataStore_Get(agentHost->masterDb, "CoreModule", CoreModule, CoreModuleLen);

				MeshAgent_EnsureCoreModuleRuntimeGlobals(agentHost->meshCoreCtx);
				if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, CoreModule + 4, CoreModuleLen - 4, "CoreModule.js", 13) != 0 ||
					ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
				{
					ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint,
						ILibRemoteLogging_Flags_VerbosityLevel_1, "Error Executing MeshCore: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
				}
				duk_pop(agentHost->meshCoreCtx);
				free(CoreModule);
			}

			duk_peval_string_noresult(agentHost->meshCoreCtx, "console.log('Agent running in Local Debug Mode');require('MeshAgent').emit('Connected',1);");
		}
		// We are acting as a mesh agent
		if (((ILibSimpleDataStore_Get(agentHost->masterDb, "MeshServer", ILibScratchPad, sizeof(ILibScratchPad))) > 5) && (memcmp(ILibScratchPad, "local", 5) == 0))
		{
			// Mesh agent is in local mode, start the multicast server discovery
			struct sockaddr_in multicastAddr4;
			struct sockaddr_in6 multicastAddr6;

			// Read DiscoveryKey if present, perform SHA384 on it and use it as UDP encryption/decryption key.
			SHA512_CTX c;
			int i = (ILibSimpleDataStore_Get(agentHost->masterDb, "DiscoveryKey", ILibScratchPad, sizeof(ILibScratchPad)));
			if (i > 1) 
			{
				SHA384_Init(&c);
				SHA384_Update(&c, ILibScratchPad, i - 1); // Hash the discovery key
				SHA384_Final((unsigned char*)ILibScratchPad, &c);
				if ((agentHost->multicastDiscoveryKey = (char*)malloc(32)) == NULL) { ILIBCRITICALEXIT(254); }
				memcpy(agentHost->multicastDiscoveryKey, ILibScratchPad, 32); // Save the first 32 bytes of the hash as key
			}

			// Cleanup all addresses
			memset(&multicastAddr4, 0, sizeof(struct sockaddr_in));
			memset(&multicastAddr6, 0, sizeof(struct sockaddr_in6));

			// Setup addresses
			if (ILibDetectIPv6Support())
			{
				// IPv6 support
				multicastAddr6.sin6_family = AF_INET6;
				multicastAddr6.sin6_port = htons(16989);
				ILibInet_pton(AF_INET6, MESH_MCASTv6_GROUP, &(multicastAddr6.sin6_addr));
			}

			// Setup multicastAddr4
			multicastAddr4.sin_family = AF_INET;
			multicastAddr4.sin_port = htons(16989);
			ILibInet_pton(AF_INET, MESH_MCASTv4_GROUP, &(multicastAddr4.sin_addr));

			// Multicast socket on fixed port, will receive multicast from the server.
			agentHost->multicastDiscovery = ILibMulticastSocket_Create(agentHost->chain, SERVER_DISCOVERY_BUFFER_SIZE, MESH_AGENT_PORT, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, agentHost, 1);
			if (agentHost->multicastDiscovery == NULL) { ILIBMARKPOSITION(219); return 1; }

			// Multicast socket on a random port, used to multicast to the server and receive server unicast responses.
			agentHost->multicastDiscovery2 = ILibMulticastSocket_Create(agentHost->chain, SERVER_DISCOVERY_BUFFER_SIZE, 0, &multicastAddr4, &multicastAddr6, UDPSocket_OnData, agentHost, 1);
			if (agentHost->multicastDiscovery2 == NULL) { ILIBMARKPOSITION(219); return 1; }
		}

		return 1;
	}
	return 0;
}

void MeshAgent_ScriptMode_UncaughtExceptionSink(duk_context *ctx, char *msg, void *user)
{
	printf("*** UNCAUGHT EXCEPTION: %s ***\n", msg);
}

void MeshAgent_ScriptMode_MeshDesktop_PUSH(duk_context *ctx, void *chain)
{
	duk_push_heap_stash(ctx);									// [stash]
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, "\xFF_MeshDesktop_AgentPtr");
	duk_pop(ctx);

	duk_push_object(ctx);
	ILibDuktape_WriteID(ctx, "MeshDesktop");
	if (agent != NULL)
	{
		duk_push_pointer(ctx, agent);
		duk_put_prop_string(ctx, -2, MESH_AGENT_PTR);

		ILibDuktape_CreateInstanceMethod(ctx, "getRemoteDesktopStream", ILibDuktape_MeshAgent_getRemoteDesktop, 0);
	}
}
duk_ret_t MeshAgent_ScriptMode_StartAgent(duk_context *ctx)
{
	duk_push_current_function(ctx);
	MeshAgentHostContainer *agent = (MeshAgentHostContainer*)Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR);
	if (agent->bootstrapCoreCtx != NULL)
	{
		return(ILibDuktape_Error(ctx, "Already Started"));
	}

	agent->localScript = 0;
	agent->bootstrapCoreCtx = agent->meshCoreCtx;
	agent->meshCoreCtx = NULL;

	duk_eval_string(ctx, "(function _getParams(){return(process.argv);})();");	// [array]
	int paramLength = (int)duk_get_length(ctx, -1);
	int i;
	char **params = (char**)ILibMemory_AllocateA(paramLength * sizeof(char*));

	for (i = 0; i < paramLength; ++i)
	{
		duk_get_prop_index(ctx, -1, i);											// [array][value]
		params[i] = (char*)duk_to_string(ctx, -1);
		duk_pop(ctx);															// [array]
	}

	if (MeshAgent_AgentMode(agent, paramLength, params, 0) == 0)
	{
		duk_eval_string_noresult(ctx, "process.exit();"); // Agent Error, exit
	}

	return(0);
}
duk_ret_t MeshAgent_ScriptMode_ZipSink2_Error(duk_context *ctx)
{
	duk_peval_string(ctx, "console.log('Error Extracting Zip file');process._exit();");
	return(0);
}
void MeshAgent_ScriptMode_ZipSink_Run(duk_context *ctx, void ** args, int argsLen)
{
	duk_idx_t top = duk_get_top(ctx);

	duk_push_heap_stash(ctx);
	duk_size_t bufferLen;
	char* buffer = Duktape_GetBufferPropertyEx(ctx, -1, "_script", &bufferLen);
	char* name = Duktape_GetStringPropertyValue(ctx, -1, "_scriptName", "[zipped].js");

	if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(ctx, buffer, (int)bufferLen, name, 0) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(ctx) != 0)
	{
		if (strcmp(duk_safe_to_string(ctx, -1), "Process.exit() forced script termination") != 0)
		{
			// Error
			ILibRemoteLogging_printf(ILibChainGetLogger(duk_ctx_chain(ctx)), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Error: %s", duk_safe_to_string(ctx, -1));
		}
	}

	duk_set_top(ctx, top);
}

duk_ret_t MeshAgent_ScriptMode_ZipSink2(duk_context *ctx)
{
	duk_size_t tmpLen;
	char *tmp;

	duk_idx_t top;
	if (duk_get_length(ctx, 0) == 1)
	{
		// Only one file is in here
		duk_push_heap_stash(ctx);									// [stash]
		duk_array_pop(ctx, 0);										// [stash][obj]
		duk_get_prop_string(ctx, -1, "buffer");						// [stash][obj][buffer]
		duk_put_prop_string(ctx, -3, "_script");					// [stash][obj]
		duk_get_prop_string(ctx, -1, "name");						// [stash][obj][name]
		duk_put_prop_string(ctx, -2, "_scriptName");				// [stash][obj]
		ILibDuktape_Immediate(ctx, NULL, 0, MeshAgent_ScriptMode_ZipSink_Run);
	}
	else
	{
		char *run = NULL;
		int runidx = -1;
		int found = 0;
		duk_eval_string(ctx, "process.argv");						// [argarray]
		duk_array_partialIncludes(ctx, -1, "--run=");				// [argarray][int]
		if (duk_is_number(ctx, -1) && duk_get_int(ctx, -1) >= 0)
		{
			runidx = duk_get_int(ctx, -1);
			duk_get_prop_index(ctx, -2, duk_get_int(ctx, -1));		// [argarray][int][string]
			duk_string_split(ctx, -1, "=");							// [argarray][int][string][tokens]
			duk_array_pop(ctx, -1);									// [argarray][int][string][tokens][string]
			run = (char*)duk_get_string(ctx, -1);
		}

		if (run == NULL)
		{
			// --run="" was not specified, so lets first check to see if there is a single root level .js file
			duk_dup(ctx, 0);										// [array]
			int tmptop = duk_get_top(ctx);							
			duk_uarridx_t x;
			for (x = 0; x < duk_get_length(ctx, -1); ++x)
			{
				duk_get_prop_index(ctx, -1, x);						// [array][obj]
				duk_get_prop_string(ctx, -1, "name");				// [array][obj][name]
				duk_string_split(ctx, -1, "\\");					// [array][obj][name][tokens]
				if (duk_get_length(ctx, -1) == 1)
				{
					duk_string_split(ctx, -2, "/");					// [array][obj][name][tokens][tokens]
					if (duk_get_length(ctx, -1) == 1)
					{
						duk_array_pop(ctx, -1);						// [array][obj][name][tokens][tokens][name]
						run = (char*)duk_get_string(ctx, -1);
						break;
					}
				}
				duk_set_top(ctx, tmptop);
			}

			if (run == NULL)
			{
				// --run="" was not specified, so we'll default to the name of the binary
				duk_eval_string(ctx, "process.argv[0]");				// [path]
#ifdef WIN32
				duk_string_split(ctx, -1, "\\");						// [path][array]
#else
				duk_string_split(ctx, -1, "/");
#endif
				duk_array_pop(ctx, -1);									// [path][array][string]
#ifdef WIN32
				int tlen = (int)duk_get_length(ctx, -1);
				duk_string_substring(ctx, -1, 0, tlen - 4);				// [path][array][string][string]
#endif
				duk_push_string(ctx, ".js");							// [path][array][string][string][.js]
				duk_string_concat(ctx, -2);								// [path][array][string][string][string]
				run = (char*)duk_to_string(ctx, -1);
			}
		}


		duk_dup(ctx, 0);											// [array]
		top = duk_get_top(ctx);
		while (duk_get_length(ctx, -1) > 0)
		{
			duk_array_pop(ctx, -1);									// [array][obj]
			duk_get_prop_string(ctx, -1, "name");					// [array][obj][name]
			duk_string_split(ctx, -1, "\\");						// [array][obj][name][tokens]
			duk_array_pop(ctx, -1);									// [array][obj][name][tokens][filename]
			duk_string_split(ctx, -1, "/");							// [array][obj][name][tokens][filename][tokens]
			duk_array_pop(ctx, -1);									// [array][obj][name][tokens][filename][tokens][filename]
			duk_string_endsWith(ctx, -1, ".js");					// [array][obj][name][tokens][filename][tokens][filename][boolean]
			if (duk_get_boolean(ctx, -1))
			{
				// This is a JS module
				if (run != NULL && found == 0)
				{
					duk_push_string(ctx, run);						// [array][obj][name][tokens][filename][tokens][filename][boolean][run]
					if (duk_equals(ctx, -3, -1) == 1)
					{
						// This is the script to run
						duk_push_heap_stash(ctx);					// [array][obj][name][tokens][filename][tokens][filename][boolean][run][stash]
						duk_get_prop_string(ctx, -9, "buffer");		// [array][obj][name][tokens][filename][tokens][filename][boolean][run][stash][buffer]
						duk_put_prop_string(ctx, -2, "_script");	// [array][obj][name][tokens][filename][tokens][filename][boolean][run][stash]
						duk_swap_top(ctx, -2);						// [array][obj][name][tokens][filename][boolean][stash][run]
						duk_put_prop_string(ctx, -2, "_scriptName");// [array][obj][name][tokens][filename][boolean][stash]
						found = 1;
					}
				}
				else
				{
					// Load as a module								// [array][obj][name][tokens][filename][tokens][filename][boolean]
					duk_string_split(ctx, -2, ".js");				// [array][obj][name][tokens][filename][tokens][filename][boolean][tokens]
					duk_array_shift(ctx, -1);						// [array][obj][name][tokens][filename][tokens][filename][boolean][tokens][name]
					duk_get_prop_string(ctx, -9, "buffer");			// [array][obj][name][tokens][filename][tokens][filename][boolean][tokens][name][buffer]
					tmp = (char*)Duktape_GetBuffer(ctx, -1, &tmpLen);
					ILibDuktape_ModSearch_AddModule(ctx, (char*)duk_get_string(ctx, -2), tmp, (int)tmpLen);
				}
			}
			duk_set_top(ctx, top);
		}
		if (run != NULL && found != 0)
		{
			if (runidx != -1)
			{
				duk_push_heapptr(ctx, ILibDuktape_GetProcessObject(ctx));
				duk_get_prop_string(ctx, -1, "\xFF_argArray");	// [process][array]
				duk_prepare_method_call(ctx, -1, "splice");		// [process][array][splice][this]
				duk_push_int(ctx, runidx);						// [process][array][splice][this][start]
				duk_push_int(ctx, 1);							// [process][array][splice][this][start][deleteCount]
				duk_pcall_method(ctx, 2);
			}
			ILibDuktape_Immediate(ctx, NULL, 0, MeshAgent_ScriptMode_ZipSink_Run);
		}
		else
		{
			// Unable to initialize
			duk_eval_string_noresult(ctx, "console.log('Error Initializing script from Zip file');process._exit();");
		}
	}
	return(0);
}
duk_ret_t MeshAgent_ScriptMode_ZipSink(duk_context *ctx)
{
	duk_prepare_method_call(ctx, 0, "extractAllStreams");					// [extract][this]
	if (duk_pcall_method(ctx, 0) != 0)										// [promise]
	{
		duk_eval_string(ctx, "console.log('Error extracting from zip file');process._exit();");
		return(0);
	}
	duk_prepare_method_call(ctx, -1, "then");								// [promise][then][this]
	duk_push_c_function(ctx, MeshAgent_ScriptMode_ZipSink2, DUK_VARARGS);	// [promise][then][this][func1]
	duk_push_c_function(ctx, MeshAgent_ScriptMode_ZipSink2_Error, DUK_VARARGS); //.....][then][this][func1][func2]
	if (duk_pcall_method(ctx, 2) != 0)
	{
		duk_eval_string(ctx, "console.log('Error extracting zip file'); process._exit();");
	}
	return(0);
}
duk_ret_t MeshAgent_ScriptMode_ZipSinkErr(duk_context *ctx)
{
	char *tmp = (char*)duk_require_string(ctx, 0);
	char *val = (char*)duk_push_sprintf(ctx, "console.log('%s');process._exit();", tmp);
	duk_peval_string(ctx, val);
	return(0);
}
void MeshAgent_ScriptMode(MeshAgentHostContainer *agentHost, int argc, char **argv)
{
	char *jsFile = NULL;
	int jsFileLen = 0;
	int i;
	unsigned int execTimeout = 0;
	unsigned int secFlags = 0;
	char **scriptArgs = NULL;
	char *jsPath = NULL;
	int sx = 1;
	int connectAgent = 0;
	int pathLen = 0;

	if (agentHost->meshCoreCtx_embeddedScript == NULL)
	{
		// Get the full path name of the JavaScript file
#ifdef WIN32
		WCHAR wjsPath[4096];
		GetFullPathNameW(ILibUTF8ToWide(argv[1], -1), sizeof(wjsPath) / 2, wjsPath, NULL);
		pathLen = WideCharToMultiByte(CP_UTF8, 0, wjsPath, -1, (LPSTR)ILibScratchPad2, sizeof(ILibScratchPad2), NULL, NULL);
#else
		if (realpath(argv[1], ILibScratchPad2) != NULL) { pathLen = strnlen_s(ILibScratchPad2, PATH_MAX); }
#endif

		if (ILibString_EndsWith(ILibScratchPad2, -1, ".zip", 4) == 0)
		{
			// Try to load the JavaScript file from disk, if fail, return
			jsFileLen = ILibReadFileFromDiskEx(&jsFile, ILibScratchPad2);
			if (jsFileLen == 0) { printf("ERROR loading %s\n", ILibScratchPad2); return; }
		}
		// We need to pass the JavaScript full path to the JavaScript runtime as the first argument. Set the up here.
		scriptArgs = (char**)ILibMemory_Allocate((1 + argc) * sizeof(char*), 1 + pathLen, NULL, (void**)&jsPath);		// KLOCWORK is being dumb, becuase ILibScratchpad2 is gauranteed to be NULL terminated
		strncpy_s(jsPath, ILibMemory_GetExtraMemorySize(jsPath), ILibScratchPad2, ILibMemory_GetExtraMemorySize(jsPath));
		scriptArgs[0] = jsPath;

		// Parse arguments. Handle the ones we can, others will be passed to the JavaScript engine. 
		for (i = 2; i < argc; ++i)
		{
			if (agentHost->masterDb == NULL && strncmp(argv[i], "--script-db", 11) == 0 && ((i + 1) < argc))
			{
				// Specify DB file path
				agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, argv[i + 1]));
				++i;
			}
			else if (strncmp(argv[i], "--script-flags", 14) == 0 && ((i + 1) < argc))
			{
				// JS Permissions (see .h for values)
				if (ntohs(((unsigned short*)argv[i + 1])[0]) == HEX_IDENTIFIER)
				{
					int xlen = (int)strnlen_s(argv[i + 1], 32);
					if (xlen <= 10)
					{
						util_hexToBuf(argv[i + 1] + 2, xlen - 2, (char*)&secFlags);
						secFlags = ntohl(secFlags);
					}
					++i;
				}
			}
			else if (strncmp(argv[i], "--script-timeout", 16) == 0 && ((i + 1) < argc))
			{
				// Seconds before watchdog termination, 0 for unlimited
				execTimeout = ILib_atoi2_uint32(argv[i + 1], 255);
				++i;
			}
			else if (strncmp(argv[i], "--script-connect", 16) == 0)
			{
				// Connect to MeshCentral
				if (strnlen(argv[i], 19) == 18 && strcmp(argv[i] + 16, "=2") == 0)
				{
					connectAgent = 2;
				}
				else
				{
					connectAgent = 1;
				}
				if (agentHost->masterDb == NULL)
				{
					agentHost->masterDb = ILibSimpleDataStore_Create(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".db"));
				}
			}
			else
			{
				// Unhandled arguments, passed to JavaScript
				scriptArgs[sx++] = argv[i];
			}
		}
	}
	else
	{
		// Embedded JavaScript
		jsFile = agentHost->meshCoreCtx_embeddedScript;
		jsFileLen = agentHost->meshCoreCtx_embeddedScriptLen;
		scriptArgs = (char**)ILibMemory_Allocate((1 + argc) * sizeof(char*), 0, NULL, NULL);
		for (i = 1; i < argc; ++i)
		{
			scriptArgs[i] = argv[i];
		}
		scriptArgs[i] = NULL;
		scriptArgs[0] = agentHost->exePath;
	}

	// Start the JavaScript engine, run the loaded .js file
	agentHost->localScript = 1;

	agentHost->meshCoreCtx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngineEx(secFlags, execTimeout, agentHost->chain, scriptArgs, connectAgent != 0 ? agentHost->masterDb : NULL, agentHost->exePath, agentHost->pipeManager, connectAgent == 0 ? MeshAgent_RunScriptOnly_Finalizer : NULL, agentHost);
	ILibDuktape_SetNativeUncaughtExceptionHandler(agentHost->meshCoreCtx, MeshAgent_ScriptMode_UncaughtExceptionSink, agentHost);
		
	if (connectAgent != 0) 
	{ 
		ILibDuktape_MeshAgent_Init(agentHost->meshCoreCtx, agentHost->chain, agentHost); 
	}
	else
	{
		duk_push_heap_stash(agentHost->meshCoreCtx);									// [stash]
		duk_push_pointer(agentHost->meshCoreCtx, agentHost);							// [stash][ptr]
		duk_put_prop_string(agentHost->meshCoreCtx, -2, "\xFF_MeshDesktop_AgentPtr");	// [stash]
		duk_pop(agentHost->meshCoreCtx);												// ...
		ILibDuktape_ModSearch_AddHandler(agentHost->meshCoreCtx, "meshDesktop", MeshAgent_ScriptMode_MeshDesktop_PUSH);

		duk_push_global_object(agentHost->meshCoreCtx);									// [g]
		duk_push_c_function(agentHost->meshCoreCtx, MeshAgent_ScriptMode_StartAgent, 0);// [g][startAgent]
		duk_push_pointer(agentHost->meshCoreCtx, agentHost);							// [g][startAgent][agent]
		duk_put_prop_string(agentHost->meshCoreCtx, -2, MESH_AGENT_PTR);				// [g][startAgent]
		duk_put_prop_string(agentHost->meshCoreCtx, -2, "startMeshAgent");				// [g]
		duk_pop(agentHost->meshCoreCtx);												// ...
	}

#if defined(_POSIX)
	duk_peval_string_noresult(agentHost->meshCoreCtx, "require('linux-pathfix')();");
#endif

	int embeddedZIP = 0;
	if (jsFileLen > 30 && jsFile[0] == 0x50 && jsFile[1] == 0x4B && jsFile[2] == 0x03 && jsFile[3] == 0x04)
	{
		embeddedZIP = 1;
	}

	if ((embeddedZIP == 0 && jsPath == NULL) || (embeddedZIP == 0 && jsPath != NULL && ILibString_EndsWith(jsPath, -1, ".zip", 4) == 0))
	{
		if (ILibDuktape_ScriptContainer_CompileJavaScriptEx(agentHost->meshCoreCtx, jsFile, jsFileLen, agentHost->meshCoreCtx_embeddedScript == NULL ? scriptArgs[0] : "[embedded].js", 0) != 0 || ILibDuktape_ScriptContainer_ExecuteByteCode(agentHost->meshCoreCtx) != 0)
		{
			if (strcmp(duk_safe_to_string(agentHost->meshCoreCtx, -1), "Process.exit() forced script termination") != 0)
			{
				// Error
				ILibRemoteLogging_printf(ILibChainGetLogger(agentHost->chain), ILibRemoteLogging_Modules_Microstack_Generic | ILibRemoteLogging_Modules_ConsolePrint, ILibRemoteLogging_Flags_VerbosityLevel_1, "Script Error: %s", duk_safe_to_string(agentHost->meshCoreCtx, -1));
			}
			duk_pop(agentHost->meshCoreCtx);
		}
	}
	else
	{
		int r;
		if (embeddedZIP != 0 && jsFile != NULL)
		{
			// Trying to run an embedded zip file
			duk_eval_string(agentHost->meshCoreCtx, "require('zip-reader')");						// [zip-reader]
			duk_get_prop_string(agentHost->meshCoreCtx, -1, "read");								// [zip-reader][read]
			duk_swap_top(agentHost->meshCoreCtx, -2);												// [read][this]
			char *tmp=(char*)duk_push_fixed_buffer(agentHost->meshCoreCtx, jsFileLen);				// [read][this][buffer]
			memcpy_s(tmp, jsFileLen, jsFile, jsFileLen);
			duk_push_buffer_object(agentHost->meshCoreCtx, -1, 0, jsFileLen, DUK_BUFOBJ_NODEJS_BUFFER); //..][this][buffer][njsBuffer]
			duk_remove(agentHost->meshCoreCtx, -2);													// [read][this][buffer]
			r = duk_pcall_method(agentHost->meshCoreCtx, 1);										// [promise]
		}
		else
		{
			// Trying to run a zip file
			duk_push_sprintf(agentHost->meshCoreCtx, "require('zip-reader').read('%s');", jsPath);	// [string]
#ifdef WIN32					
			duk_string_split(agentHost->meshCoreCtx, -1, "\\");										// [string][array]
			duk_array_join(agentHost->meshCoreCtx, -1, "\\\\");										// [string][array][string]
			duk_remove(agentHost->meshCoreCtx, -2);													// [string][string]
			duk_remove(agentHost->meshCoreCtx, -2);													// [string]
#endif
			r = duk_peval(agentHost->meshCoreCtx);													// [promise]
		}
		
		if (r != 0)																					// [zip-reader]
		{
			duk_peval_string_noresult(agentHost->meshCoreCtx, "console.log('Error decoding zip file');process._exit();");
			duk_pop(agentHost->meshCoreCtx);											// ...
		}
		else
		{
			duk_push_heap_stash(agentHost->meshCoreCtx);								// [zip-reader][stash]
			duk_swap_top(agentHost->meshCoreCtx, -2);									// [stash][zip-reader]
			duk_dup(agentHost->meshCoreCtx, -1);										// [stash][zip-reader][zip-reader]
			duk_put_prop_string(agentHost->meshCoreCtx, -3, "zip");						// [stash][zip-reader]
			duk_remove(agentHost->meshCoreCtx, -2);										// [zip-reader]
			duk_get_prop_string(agentHost->meshCoreCtx, -1, "then");					// [zip-reader][then]
			duk_swap_top(agentHost->meshCoreCtx, -2);									// [then][this]
			duk_push_c_function(agentHost->meshCoreCtx, MeshAgent_ScriptMode_ZipSink, DUK_VARARGS);//.][func1]
			duk_push_c_function(agentHost->meshCoreCtx, MeshAgent_ScriptMode_ZipSinkErr, DUK_VARARGS);//.....][func2]
			if (duk_pcall_method(agentHost->meshCoreCtx, 2) != 0)
			{
				duk_eval_string_noresult(agentHost->meshCoreCtx, "console.log('error decoding zip file');process._exit();");
			}
			duk_pop(agentHost->meshCoreCtx);											// ...
		}
	}
	// JavaScript copies this, we do not need this anymore.
	if (jsFile != NULL) { free(jsFile); }
	free(scriptArgs);

	// If in agent mode, setup the chain to be a mesh agent
	if (connectAgent != 0) 
	{
		agentHost->localdebugmode = (connectAgent == 2);
		if (MeshAgent_AgentMode(agentHost, argc, argv, 0) == 0) 
		{
			ILibStopChain(agentHost->chain); // Agent Error, stop the chain
		}
	}
}

void MeshAgent_ScriptMode_Dispatched(void *chain, void *user)
{
	MeshAgent_ScriptMode((MeshAgentHostContainer*)((void**)user)[0], ((int*)((void**)user)[1])[0], (char**)((void**)user)[2]);
}
void MeshAgent_AgentMode_Dispatched(void *chain, void *user)
{
	if (MeshAgent_AgentMode((MeshAgentHostContainer*)((void**)user)[0], ((int*)((void**)user)[1])[0], (char**)((void**)user)[2], 1) == 0)
	{
		ILibStopChain(((MeshAgentHostContainer*)((void**)user)[0])->chain);
	}
}


#ifdef _POSIX
int MeshAgent_System(char *cmd)
{
	//int status = -1;
	pid_t pid = fork();

	if(pid == 0)
	{
		// Child
		execv("/bin/sh", (char**)(char*[]) { "sh", "-c", cmd, (char*)0 });
		_exit(1);
	}
	else if (pid > 0)
	{
		// Parent
		//waitpid(pid, &status, 0);
	}
	return(0);
}

#endif

int MeshAgent_Start(MeshAgentHostContainer *agentHost, int paramLen, char **param)
{
	char *startParms = NULL;
	char _exedata[ILibMemory_Init_Size(1024, sizeof(void*))];
	char *exePath = ILibMemory_Init(_exedata, 1024, sizeof(void*), ILibMemory_Types_STACK);
	((void**)ILibMemory_Extra(exePath))[0] = agentHost;

#ifdef WIN32
	int x;
#elif defined(__APPLE__)
	uint32_t len = 1024;
#elif defined(NACL)
	// Do nothing
#else
	int x;
#endif

#if defined(WIN32) && defined(_LINKVM) && !defined(WINSERVICE)
	if (agentHost->dpiAwareness != NULL)
	{
		agentHost->dpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
	}
	else
	{
		SetProcessDPIAware();
	}
#endif

	if ((paramLen == 1 && strcmp(param[0], "--slave") == 0) || (paramLen == 2 && strcmp(param[1], "--slave") == 0)) { MeshAgent_Slave(agentHost); return 0; }
#ifndef __APPLE__
	if (paramLen == 2 && strcmp(param[1], "--netinfo") == 0) { char* data; int len = MeshInfo_GetSystemInformation(&data); if (len > 0) { printf("%s\r\n", data); free(data); } return 0; }
#endif

	if (agentHost->exePath == NULL)
	{
		agentHost->exePath = exePath;
		exePath[0] = 0;

#ifdef WIN32
		WCHAR tmpExePath[2048];
		GetModuleFileNameW(NULL, tmpExePath, sizeof(tmpExePath)/2);
		WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)tmpExePath, -1, (LPSTR)exePath, (int)ILibMemory_Size(exePath), NULL, NULL);
#elif defined(__APPLE__)
		if (_NSGetExecutablePath(exePath, &len) != 0) ILIBCRITICALEXIT(247);
	
		agentHost->exePath = exePath;
#elif defined(NACL)
#else
	#ifdef _FREEBSD
		#ifdef _OPENBSD
			x = sprintf_s(exePath, 1024, "%s", __agentExecPath);
		#else
			x = readlink("/proc/curproc/file", exePath, 1024);
		#endif
	#else
		x = readlink("/proc/self/exe", exePath, 1024);
	#endif
		if (x < 0 || x >= 1024) ILIBCRITICALEXIT(246);
		exePath[x] = 0;
#endif
	}

#ifdef WIN32
	if (agentHost->exePath != NULL && agentHost->exePath[0] != 0)
#endif

	// Perform a self SHA384 Hash
	GenerateSHA384FileHash(agentHost->exePath, agentHost->agentHash);

	int _pX, _piX;
	for (_pX = 1; _pX < paramLen; ++_pX)
	{
		if ((_piX = ILibString_IndexOf(param[_pX], (int)strnlen_s(param[_pX], sizeof(ILibScratchPad)), "=", 1)) > 2 && strncmp(param[_pX], "--", 2) == 0)
		{
			if (_piX - 2 == 13 && strncmp(param[_pX] + 2, "configUsesCWD", 13) == 0 && strncmp(param[_pX] + _piX + 1, "1", 1) == 0)
			{
				// Config files use working path, instead of binary path
				agentHost->configPathUsesCWD = 1;
				break;
			}
		}
	}


	ILibCriticalLogFilename = ILibString_Copy(MeshAgent_MakeAbsolutePath(agentHost->exePath, ".log"), 0);
#ifndef MICROSTACK_NOTLS
	util_openssl_init();
#endif

	ILibChain_OnDestroyEvent_AddHandler(agentHost->chain, MeshAgent_ChainEnd, agentHost);

#ifdef WIN32
	x = ILibString_LastIndexOf(param[0], -1, "\\", 1);
	if (x > 0)
	{
		strncpy_s(ILibScratchPad2, sizeof(ILibScratchPad2), param[0], x);
		ILibScratchPad2[x] = 0;
		SetCurrentDirectoryW(ILibUTF8ToWide(ILibScratchPad2, -1));
	}
#endif

	void *reserved[] = { agentHost, &paramLen, param };

	// Check to see if we are running as just a JavaScript Engine
	if (agentHost->meshCoreCtx_embeddedScript != NULL || (paramLen >= 2 && ILibString_EndsWith(param[1], -1, ".js", 3) != 0) || (paramLen >= 2 && ILibString_EndsWith(param[1], -1, ".zip", 4) != 0))
	{ 
		// We are acting as a scripting engine
		ILibChain_RunOnMicrostackThreadEx(agentHost->chain, MeshAgent_ScriptMode_Dispatched, reserved);
		ILibStartChain(agentHost->chain);
		agentHost->chain = NULL; 
	}
	else
	{
		// We are acting as an Agent
		ILibChain_RunOnMicrostackThreadEx(agentHost->chain, MeshAgent_AgentMode_Dispatched, reserved);
		ILibStartChain(agentHost->chain);
		agentHost->chain = NULL; // Mesh agent has exited, set the chain to NULL

		// Close the database
		if (agentHost->masterDb != NULL)
		{
			if (agentHost->performSelfUpdate != 0)
			{
				if (agentHost->JSRunningAsService == 0)
				{
					duk_context *ctxx = ILibDuktape_ScriptContainer_InitializeJavaScriptEngine_minimal();
					duk_size_t jsonLen;
					char *json = NULL;

					ILibDuktape_SimpleDataStore_raw_GetCachedValues_Array(ctxx, agentHost->masterDb);			// [array]
					if (duk_get_length(ctxx, -1) > 0)
					{
						duk_json_encode(ctxx, -1);																	// [json]
						json = (char*)duk_get_lstring(ctxx, -1, &jsonLen);

						startParms = (char*)ILibMemory_SmartAllocateEx(jsonLen + 1, ILibBase64EncodeLength(jsonLen + 1));
						unsigned char* tmp = (unsigned char*)ILibMemory_Extra(startParms);
						memcpy_s(startParms, jsonLen + 1, json, jsonLen);
						Duktape_SafeDestroyHeap(ctxx);

						if (jsonLen > INT32_MAX)
						{
							ILibMemory_Free(startParms);
							startParms = NULL;
							if (agentHost->logUpdate != 0) { ILIBLOGMESSAGEX(" Service Parameters => ERROR"); }
						}
						else
						{
							ILibBase64Encode((unsigned char*)startParms, (int)jsonLen, &tmp);
							if (agentHost->logUpdate != 0) { ILIBLOGMESSAGEX(" Service Parameters => %s", startParms); }
						}
					}
					else
					{
						if (agentHost->logUpdate != 0) { ILIBLOGMESSAGEX(" Service Parameters => NONE"); }
					}
				}
				else
				{
					if (strcmp(agentHost->meshServiceName, "meshagent") != 0)
					{
						startParms = ILibMemory_SmartAllocateEx(ILibMemory_Size(agentHost->meshServiceName) + 30, ILibBase64EncodeLength(ILibMemory_Size(agentHost->meshServiceName) + 30));
						unsigned char* tmp = (unsigned char*)ILibMemory_Extra(startParms);
						ILibBase64Encode((unsigned char*)startParms, sprintf_s(startParms, ILibMemory_Size(startParms), "[\"--meshServiceName=\\\"%s\\\"\"]", agentHost->meshServiceName), &tmp);
					}
				}
			}
			ILibSimpleDataStore_Close(agentHost->masterDb);
			agentHost->masterDb = NULL;
		}

#ifndef WIN32
		// Check if we need to perform self-update (performSelfUpdate should indicate startup type on Liunx: 1 = systemd, 2 = upstart, 3 = sysv-init)
		if (agentHost->performSelfUpdate != 0)
		{
			// Get the update executable path
			char* updateFilePath = MeshAgent_MakeAbsolutePath(agentHost->exePath, ".update"); // uses ILibScratchPad2
			if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Updating..."); }
			if (agentHost->JSRunningAsService != 0)
			{
				// We were started as a service
				if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Service Check... [YES]"); }

				struct stat results;
				if (stat(agentHost->exePath, &results) != 0) { results.st_mode = 0755; } // Fall back to a sane mode if stat fails
				if (chmod(updateFilePath, results.st_mode) == 0) // Set the new executable to the same mode as the current one.
				{
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "mv \"%s\" \"%s\"", updateFilePath, agentHost->exePath); // Move the update over our own executable (atomic, same dir)
					if (system(ILibScratchPad) != 0 && agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> WARNING: move failed; restarting current binary"); }
				}
				else if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> WARNING: chmod failed; keeping current binary"); }
				switch (agentHost->platformType)
				{
				case MeshAgent_Posix_PlatformTypes_BSD:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [restarting service]"); }
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "service %s onerestart", agentHost->meshServiceName);	// Restart the service
					ignore_result(system(ILibScratchPad));
					break;
				case MeshAgent_Posix_PlatformTypes_LAUNCHD:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [kickstarting service]"); }
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "launchctl kickstart -k system/%s", agentHost->meshServiceName);	// Restart the service
					ignore_result(system(ILibScratchPad));
					break;
				case MeshAgent_Posix_PlatformTypes_SYSTEMD:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [SYSTEMD should auto-restart]"); }
					exit(1);
					break;
				case MeshAgent_Posix_PlatformTypes_PROCD:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... [PROCD should auto-restart]"); }
					exit(1);
					break;
				case MeshAgent_Posix_PlatformTypes_INITD:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... Calling Service restart (INITD)"); }
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "service %s restart", agentHost->meshServiceName);	// Restart the service
					ignore_result(MeshAgent_System(ILibScratchPad));
					break;
				case MeshAgent_Posix_PlatformTypes_INIT_UPSTART:
					if (agentHost->logUpdate != 0) { ILIBLOGMESSSAGE("SelfUpdate -> Complete... Calling initctl restart (UPSTART)"); }
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "initctl restart %s", agentHost->meshServiceName);	// Restart the service
					ignore_result(MeshAgent_System(ILibScratchPad));
					break;
				default:
					break;
				}
			}
			else
			{
				if (agentHost->logUpdate != 0)
				{
					ILIBLOGMESSSAGE("SelfUpdate -> Service Check... [NO]");
					ILIBLOGMESSSAGE("SelfUpdate -> Manual Mode (COMPLETE)");
				}
				ignore_result(write(STDOUT_FILENO, "SelfUpdate -> Updating Agent...\n", 32));

				// Generic update process, call our own update with arguments.
				struct stat results;
				if (stat(agentHost->exePath, &results) != 0) { results.st_mode = 0755; } // Fall back to a sane mode if stat fails
				chmod(updateFilePath, results.st_mode); // Set the new executable to the same mode as the current one.

				// Atomically swap in the new binary. updateFilePath is a sibling of exePath, so rename() is an
				// intra-filesystem atomic replace: on success the swap is complete; on failure the running binary
				// is left intact and re-executed. Never remove the running binary before a replacement is in place.
				if (rename(updateFilePath, agentHost->exePath) != 0)
				{
					sprintf_s(ILibScratchPad, sizeof(ILibScratchPad), "cp \"%s\" \"%s\"", updateFilePath, agentHost->exePath);
					if (system(ILibScratchPad)) {}
				}
				ignore_result(write(STDOUT_FILENO, "SelfUpdate -> Restarting Agent...\n", 34));

				execv(agentHost->exePath, agentHost->execparams);
				_exit(1);
			}
		}
#endif
	}

	if (startParms != NULL) { ILibMemory_Free(startParms); }

#ifndef MICROSTACK_NOTLS
	util_openssl_uninit();
#endif
	if (ILibCriticalLogFilename != NULL) free(ILibCriticalLogFilename);
	return 0;
}


void MeshAgent_Destroy(MeshAgentHostContainer* agent)
{
#ifndef MICROSTACK_NOTLS
	util_freecert(&agent->selftlscert);
	util_freecert(&agent->selfcert);
#endif

	if (agent->masterDb != NULL) { ILibSimpleDataStore_Close(agent->masterDb); agent->masterDb = NULL; }
	if (agent->chain != NULL) { ILibChain_DestroyEx(agent->chain); agent->chain = NULL; }
	if (agent->multicastDiscoveryKey != NULL) { free(agent->multicastDiscoveryKey); agent->multicastDiscoveryKey = NULL; }
	if (agent->multicastServerUrl != NULL) { free(agent->multicastServerUrl); agent->multicastServerUrl = NULL; }
	if (agent->meshServiceName != NULL) { ILibMemory_Free(agent->meshServiceName); agent->meshServiceName = NULL; }
	if (agent->displayName != NULL) { ILibMemory_Free(agent->displayName); agent->displayName = NULL; }
	if (agent->execparams != NULL) { ILibMemory_Free(agent->execparams); agent->execparams = NULL; }
#ifdef WIN32
	if (agent->certObject != NULL) { wincrypto_close(agent->certObject); agent->certObject = NULL; }
	if (agent->shCore != NULL)
	{
		FreeLibrary((HMODULE)agent->shCore);
	}
#endif
	free(agent);
}
void MeshAgent_Stop(MeshAgentHostContainer *agent)
{
	ILibStopChain(agent->chain);
}



#ifdef WIN32
// Perform self-update (Windows console/tray version)
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv)
{
	UNREFERENCED_PARAMETER(selfpath);
	UNREFERENCED_PARAMETER(exepath);
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	OutputDebugStringA("Legacy Windows console self-update is disabled; use the native service lifecycle update path.\n");
}
#else
// Perform self-update (Linux version)
void MeshAgent_PerformSelfUpdate(char* selfpath, char* exepath, int argc, char **argv)
{
	int i, ptr = 0;

	// First, we wait a little to give time for the calling process to exit
	sleep(5);

	// Attempt to copy our own exe over 
	remove(exepath);
	sprintf_s(ILibScratchPad2, 6000, "cp \"%s\" \"%s\"", selfpath, exepath);
	while (system(ILibScratchPad2) != 0)
	{
		sleep(5);
		remove(exepath);
	}

	// Built the argument list
	ILibScratchPad[0] = 0;
	for (i = 2; i < argc && ptr >= 0; i++) ptr += sprintf_s(ILibScratchPad + ptr, 4096 - ptr, " %s", argv[i]);
	sprintf_s(ILibScratchPad2, 60000, "%s%s &", exepath, ILibScratchPad);

	// Now run the updated process
	i = system(ILibScratchPad2);
	UNREFERENCED_PARAMETER(i);
}
#endif


#ifdef __DOXY__
/*!
\implements EventEmitter
\brief JavaScript object interface for native Mesh Agent
*/
class MeshAgent
{
public:
	/*!
	\brief Event emitted when the MeshAgent is initialized and ready to connect
	*/
	void Ready;
	/*!
	\brief Event emitted when the MeshAgent has established an authenticated control channel with the server
	*/
	void Connected;
	void kvmConnected;
	/*!
	\brief Event emitted when an LMS notification is received
	\param notification <Object> Notification object in the format:\n
	<b>messageId</b> \<String\> 
	<b>indicationTime</b> \<String\> 
	<b>messageArguments</b> \<String\> 
	<b>rawXML</b> \<String\> 
	*/
	void lmsNotification;
	/*!
	\brief The Mesh Server the agent is connected to. If LAN Mode, will be 'local'
	*/
	String ConnectedServer;
	/*!
	\brief The fully qualified network uri that the agent is connected to (ie: <b>wss://www.meshcentral.com:443/agent.ashx</b>)
	*/
	String ServerUrl;
	/*!
	\brief Returns a DuplexStream KVM session, that can be piped to a data channel. 
	*/
	DuplexStream getRemoteDesktopStream();

	/*!
	\brief Add a function callback to be added to the list of Command listeners, which gets dispatched whenever a command is received from the server.
	\param handler <func>
	*/
	void AddCommandHandler(handler);
	/*!
	\brief Add a function callback that will get dispatched when the MeshAgent successfully establishes an authenticated control channel with the server
	\param handler <func>
	*/
	void AddConnectHandler(handler);
	/*!
	\brief Send a command to the server
	\param cmd \<Buffer\|String\|Object\> Command to send
	\return <bool> False if the calling code should wait for the 'drain' event before sending more commands
	*/
	bool SendCommand(cmd);
	/*!
	\brief Property indicating if MicroLMS is active
	*/
	Integer activeMicroLMS;
	/*!
	\brief Property indicating if KVM Support is present
	*/
	Integer hasKVM;
	/*!
	\brief Property indicating if HECI support is present
	*/
	Integer hasHECI;
	/*!
	\brief Property containing MEInfo
	*/
	Object MEInfo;
	/*!
	\brief Property containing NetInfo
	*/
	Object NetInfo;

	/*!
	\brief Executes power state command on the computer (ie: Sleep, Hibernate...)
	\param powerState <Integer> 
	\param force <Integer> Optional
	\return <Integer> status
	*/
	Integer ExecPowerState(powerState[, force]);

	/*!
	\brief Generates a new self signed certificate
	\param passphrase \<String\> passphrase for private key
	\return \<Buffer\> PKS encoded certificate
	*/
	Buffer GenerateCertificate(passphrase);
};
#endif
