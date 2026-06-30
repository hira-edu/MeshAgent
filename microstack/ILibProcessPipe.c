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

#include <assert.h>
#ifdef MEMORY_CHECK
#define MEMCHECK(x) x
#else
#define MEMCHECK(x)
#endif

#if defined(WIN32) && !defined(_WIN32_WCE)
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#include <windows.h>
#include <WtsApi32.h>
#endif


#include "ILibParsers.h"
#include "ILibRemoteLogging.h"
#include "ILibProcessPipe.h"
#if defined(WIN32)
#include "../meshservice/rundll32_contract.h"
#endif
#ifndef WIN32
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#if !defined( __APPLE__) && !defined(_FREEBSD)
	#include <pty.h>
#else
	#if defined(__APPLE__)
		#include <util.h>
	#else
		#include <termios.h>
#ifdef _OPENBSD
		#include <util.h>
#else
		#include <libutil.h>
#endif
	#endif
#endif
#endif


#define CONSOLE_SCREEN_WIDTH 80
#define CONSOLE_SCREEN_HEIGHT 25

#ifdef WIN32
#ifndef ERROR_ACCESS_DISABLED_BY_POLICY
#define ERROR_ACCESS_DISABLED_BY_POLICY 1260L
#endif
typedef BOOL(WINAPI* ILibProcessPipe_CreateEnvironmentBlockFn)(LPVOID*, HANDLE, BOOL);
typedef BOOL(WINAPI* ILibProcessPipe_DestroyEnvironmentBlockFn)(LPVOID);
static char g_ILibProcessPipe_LastPolicyDecision[64] = { 0 };
static char g_ILibProcessPipe_LastPolicyClass[64] = { 0 };
static char g_ILibProcessPipe_LastBridgePolicyRejectReason[64] = { 0 };
static DWORD g_ILibProcessPipe_LastPolicyError = ERROR_SUCCESS;
static DWORD g_ILibProcessPipe_LastPolicySpawnType = 0;
static ULONGLONG g_ILibProcessPipe_LastPolicyCommandHash = 0;

int ILibProcessPipe_GetLastWindowsSpawnPolicyDecisionA(char* decision, size_t decisionLen, char* policyClass, size_t policyClassLen, DWORD* errorOut, DWORD* spawnTypeOut, unsigned long long* commandHashOut)
{
	if (decision != NULL && decisionLen > 0) { strncpy_s(decision, decisionLen, g_ILibProcessPipe_LastPolicyDecision, _TRUNCATE); }
	if (policyClass != NULL && policyClassLen > 0) { strncpy_s(policyClass, policyClassLen, g_ILibProcessPipe_LastPolicyClass, _TRUNCATE); }
	if (errorOut != NULL) { *errorOut = g_ILibProcessPipe_LastPolicyError; }
	if (spawnTypeOut != NULL) { *spawnTypeOut = g_ILibProcessPipe_LastPolicySpawnType; }
	if (commandHashOut != NULL) { *commandHashOut = (unsigned long long)g_ILibProcessPipe_LastPolicyCommandHash; }
	return (g_ILibProcessPipe_LastPolicyDecision[0] != 0) ? 1 : 0;
}

int ILibProcessPipe_GetLastWindowsSpawnPolicyBridgeReasonA(char* reason, size_t reasonLen)
{
	if (reason != NULL && reasonLen > 0) { strncpy_s(reason, reasonLen, g_ILibProcessPipe_LastBridgePolicyRejectReason, _TRUNCATE); }
	return (g_ILibProcessPipe_LastBridgePolicyRejectReason[0] != 0) ? 1 : 0;
}

static void ILibProcessPipe_SetBridgePolicyRejectReasonA(const char* reason)
{
	strncpy_s(g_ILibProcessPipe_LastBridgePolicyRejectReason, sizeof(g_ILibProcessPipe_LastBridgePolicyRejectReason), reason == NULL ? "unknown" : reason, _TRUNCATE);
}

static int ILibProcessPipe_IsUserSessionSpawnType(ILibProcessPipe_SpawnTypes spawnType)
{
	return (spawnType == ILibProcessPipe_SpawnTypes_USER ||
		spawnType == ILibProcessPipe_SpawnTypes_WINLOGON ||
		spawnType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER);
}
static void ILibProcessPipe_NormalizePathA(const char *value, char *normalized, size_t normalizedLen)
{
	char scratch[MAX_PATH * 4];
	DWORD fullLen = 0;
	size_t len = 0;

	if (normalized == NULL || normalizedLen == 0) { return; }
	if (value == NULL || value[0] == 0)
	{
		normalized[0] = 0;
		return;
	}

	strncpy_s(scratch, sizeof(scratch), value, _TRUNCATE);
	normalized[0] = 0;
	while (scratch[0] == ' ' || scratch[0] == '\t') { memmove(scratch, scratch + 1, strnlen_s(scratch, sizeof(scratch))); }
	len = strnlen_s(scratch, sizeof(scratch));
	while (len > 0 && (scratch[len - 1] == ' ' || scratch[len - 1] == '\t'))
	{
		scratch[len - 1] = 0;
		--len;
	}
	if (len >= 2 && scratch[0] == '"' && scratch[len - 1] == '"')
	{
		memmove(scratch, scratch + 1, len - 2);
		scratch[len - 2] = 0;
	}

	fullLen = GetFullPathNameA(scratch, (DWORD)normalizedLen, normalized, NULL);
	if (fullLen == 0 || fullLen >= normalizedLen)
	{
		strncpy_s(normalized, normalizedLen, scratch, _TRUNCATE);
	}
	for (len = 0; normalized[len] != 0; ++len)
	{
		if (normalized[len] == '/') { normalized[len] = '\\'; }
	}
}
static int ILibProcessPipe_IsExactSystemRundll32TargetA(char* target)
{
	char normalizedTarget[MAX_PATH * 4];
	char systemRundll32[MAX_PATH * 4];
	char normalizedSystemRundll32[MAX_PATH * 4];
	DWORD systemLen;

	if (target == NULL || target[0] == 0) { return 0; }
	ILibProcessPipe_NormalizePathA(target, normalizedTarget, sizeof(normalizedTarget));
	if (normalizedTarget[0] == 0) { return 0; }

	systemRundll32[0] = 0;
	normalizedSystemRundll32[0] = 0;
	systemLen = GetSystemDirectoryA(systemRundll32, (UINT)sizeof(systemRundll32));
	if (systemLen == 0 || systemLen >= sizeof(systemRundll32)) { return 0; }
	if (strcat_s(systemRundll32, sizeof(systemRundll32), "\\rundll32.exe") != 0) { return 0; }

	ILibProcessPipe_NormalizePathA(systemRundll32, normalizedSystemRundll32, sizeof(normalizedSystemRundll32));
	if (normalizedSystemRundll32[0] == 0) { return 0; }
	return _stricmp(normalizedTarget, normalizedSystemRundll32) == 0;
}
static int ILibProcessPipe_StringEndsWithA(const char* value, const char* suffix)
{
	size_t valueLen;
	size_t suffixLen;

	if (value == NULL || suffix == NULL) { return 0; }
	valueLen = strnlen_s(value, MAX_PATH * 4);
	suffixLen = strnlen_s(suffix, 64);
	if (valueLen == 0 || suffixLen == 0 || valueLen < suffixLen) { return 0; }
	return _stricmp(value + (valueLen - suffixLen), suffix) == 0;
}
static void ILibProcessPipe_SetModuleEntryRejectReasonA(const char* reasonPrefix, const char* reason)
{
	char scratch[64];
	if (reason == NULL || reason[0] == 0) { reason = "unknown"; }
	if (reasonPrefix == NULL || reasonPrefix[0] == 0)
	{
		ILibProcessPipe_SetBridgePolicyRejectReasonA(reason);
		return;
	}
	sprintf_s(scratch, sizeof(scratch), "%s-%s", reasonPrefix, reason);
	ILibProcessPipe_SetBridgePolicyRejectReasonA(scratch);
}
static int ILibProcessPipe_TryParseRundll32ModuleEntryA(const char* value, const char* expectedEntry, char* modulePath, size_t modulePathLen, const char* reasonPrefix)
{
	const char* cursor = value;
	const char* moduleStart = NULL;
	const char* moduleEnd = NULL;
	size_t moduleLen = 0;
	size_t entryLen = 0;
	char rawModulePath[MAX_PATH * 4];

	if (modulePath != NULL && modulePathLen > 0) { modulePath[0] = 0; }
	if (modulePath == NULL || modulePathLen == 0) { return 0; }
	if (cursor == NULL) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "null"); return 0; }
	if (expectedEntry == NULL || expectedEntry[0] == 0) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "entry-empty"); return 0; }
	while (*cursor == ' ' || *cursor == '\t') { ++cursor; }
	if (*cursor == '"')
	{
		moduleStart = ++cursor;
		while (*cursor != 0 && *cursor != '"') { ++cursor; }
		if (*cursor != '"') { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "quote-close"); return 0; }
		moduleEnd = cursor;
		++cursor;
	}
	else
	{
		moduleStart = cursor;
		while (*cursor != 0 && *cursor != ',') { ++cursor; }
		moduleEnd = cursor;
	}

	while (moduleEnd > moduleStart && (moduleEnd[-1] == ' ' || moduleEnd[-1] == '\t')) { --moduleEnd; }
	while (*cursor == ' ' || *cursor == '\t') { ++cursor; }
	if (moduleEnd <= moduleStart) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "path-empty"); return 0; }
	if (*cursor != ',') { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "comma"); return 0; }
	++cursor;
	entryLen = strnlen_s(expectedEntry, 64);
	if (_strnicmp(cursor, expectedEntry, entryLen) != 0) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "entry"); return 0; }
	cursor += entryLen;
	if (*cursor != 0) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "tail"); return 0; }

	moduleLen = (size_t)(moduleEnd - moduleStart);
	if (moduleLen == 0 || moduleLen >= sizeof(rawModulePath)) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "length"); return 0; }
	memcpy_s(rawModulePath, sizeof(rawModulePath), moduleStart, moduleLen);
	rawModulePath[moduleLen] = 0;
	ILibProcessPipe_NormalizePathA(rawModulePath, modulePath, modulePathLen);
	if (modulePath[0] == 0) { ILibProcessPipe_SetModuleEntryRejectReasonA(reasonPrefix, "path-empty"); return 0; }
	return 1;
}
static int ILibProcessPipe_IsApprovedRundll32ModuleEntryA(const char* value, const char* expectedEntry)
{
	char modulePath[MAX_PATH * 4];

	if (!ILibProcessPipe_TryParseRundll32ModuleEntryA(value, expectedEntry, modulePath, sizeof(modulePath), "module")) { return 0; }
	return ILibProcessPipe_StringEndsWithA(modulePath, ".dll");
}
static int ILibProcessPipe_IsExactBridgeModuleDllPathA(const char* modulePath, const char* expectedEntry)
{
	HMODULE bridgeModule = NULL;
	char normalizedModulePath[MAX_PATH * 4];
	char bridgeModulePath[MAX_PATH * 4];
	char normalizedBridgeModulePath[MAX_PATH * 4];
	HANDLE requestedHandle = INVALID_HANDLE_VALUE;
	HANDLE bridgeHandle = INVALID_HANDLE_VALUE;
	BY_HANDLE_FILE_INFORMATION requestedInfo;
	BY_HANDLE_FILE_INFORMATION bridgeInfo;
	FARPROC bridgeExport = NULL;
	DWORD bridgeModulePathLen;
	int sameFile = 0;

	if (modulePath == NULL || modulePath[0] == 0 || expectedEntry == NULL || expectedEntry[0] == 0) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-empty"); return 0; }
	memset(&requestedInfo, 0, sizeof(requestedInfo));
	memset(&bridgeInfo, 0, sizeof(bridgeInfo));
	ILibProcessPipe_NormalizePathA(modulePath, normalizedModulePath, sizeof(normalizedModulePath));
	if (normalizedModulePath[0] == 0 || !ILibProcessPipe_StringEndsWithA(normalizedModulePath, ".dll")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-extension"); return 0; }
	if (!GetModuleHandleExA(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&ILibProcessPipe_IsExactBridgeModuleDllPathA,
		&bridgeModule))
	{
		ILibProcessPipe_SetBridgePolicyRejectReasonA("module-owner");
		return 0;
	}
	bridgeExport = GetProcAddress(bridgeModule, expectedEntry);
	if (bridgeExport == NULL) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-export"); return 0; }
	bridgeModulePathLen = GetModuleFileNameA(bridgeModule, bridgeModulePath, (DWORD)sizeof(bridgeModulePath));
	if (bridgeModulePathLen == 0 || bridgeModulePathLen >= sizeof(bridgeModulePath)) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-path"); return 0; }
	ILibProcessPipe_NormalizePathA(bridgeModulePath, normalizedBridgeModulePath, sizeof(normalizedBridgeModulePath));
	if (normalizedBridgeModulePath[0] == 0 || !ILibProcessPipe_StringEndsWithA(normalizedBridgeModulePath, ".dll")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-owner-extension"); return 0; }
	requestedHandle = CreateFileA(normalizedModulePath, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (requestedHandle == INVALID_HANDLE_VALUE) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-requested-open"); return 0; }
	bridgeHandle = CreateFileA(normalizedBridgeModulePath, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (bridgeHandle == INVALID_HANDLE_VALUE)
	{
		CloseHandle(requestedHandle);
		ILibProcessPipe_SetBridgePolicyRejectReasonA("module-owner-open");
		return 0;
	}
	if (GetFileInformationByHandle(requestedHandle, &requestedInfo) && GetFileInformationByHandle(bridgeHandle, &bridgeInfo))
	{
		sameFile = (requestedInfo.dwVolumeSerialNumber == bridgeInfo.dwVolumeSerialNumber &&
			requestedInfo.nFileIndexHigh == bridgeInfo.nFileIndexHigh &&
			requestedInfo.nFileIndexLow == bridgeInfo.nFileIndexLow) ? 1 : 0;
	}
	else
	{
		ILibProcessPipe_SetBridgePolicyRejectReasonA("module-file-info");
	}
	CloseHandle(bridgeHandle);
	CloseHandle(requestedHandle);
	if (!sameFile) { ILibProcessPipe_SetBridgePolicyRejectReasonA("module-file-id"); }
	return sameFile;
}
static int ILibProcessPipe_IsApprovedBridgeModuleArgumentA(const char* value)
{
	char modulePath[MAX_PATH * 4];

	if (!ILibProcessPipe_TryParseRundll32ModuleEntryA(value, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A, modulePath, sizeof(modulePath), "module")) { return 0; }
	return ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A);
}
static int ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(const char* value)
{
	char modulePath[MAX_PATH * 4];

	if (!ILibProcessPipe_TryParseRundll32ModuleEntryA(value, MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_A, modulePath, sizeof(modulePath), "console-module")) { return 0; }
	return ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_A);
}
static int ILibProcessPipe_IsApprovedBridgePipeNameA(const char* value, const char* suffix)
{
	const char* prefix = "\\\\.\\pipe\\MeshKvm_";
	size_t valueLen;
	size_t prefixLen;
	size_t suffixLen;
	size_t i;

	if (value == NULL || suffix == NULL) { return 0; }
	valueLen = strnlen_s(value, MAX_PATH * 4);
	prefixLen = strnlen_s(prefix, 64);
	suffixLen = strnlen_s(suffix, 16);
	if (valueLen <= (prefixLen + suffixLen)) { return 0; }
	if (_strnicmp(value, prefix, prefixLen) != 0) { return 0; }
	if (_stricmp(value + (valueLen - suffixLen), suffix) != 0) { return 0; }
	for (i = prefixLen; i < valueLen - suffixLen; ++i)
	{
		char c = value[i];
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
		{
			return 0;
		}
	}
	return 1;
}
static int ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(const char* value, const char* suffix)
{
	const char* prefix = "\\\\.\\pipe\\MeshConsoleBridge_";
	size_t valueLen;
	size_t prefixLen;
	size_t suffixLen;
	size_t i;

	if (value == NULL || suffix == NULL) { return 0; }
	valueLen = strnlen_s(value, MAX_PATH * 4);
	prefixLen = strnlen_s(prefix, 64);
	suffixLen = strnlen_s(suffix, 16);
	if (valueLen <= (prefixLen + suffixLen)) { return 0; }
	if (_strnicmp(value, prefix, prefixLen) != 0) { return 0; }
	if (_stricmp(value + (valueLen - suffixLen), suffix) != 0) { return 0; }
	for (i = prefixLen; i < valueLen - suffixLen; ++i)
	{
		char c = value[i];
		if (!((c >= '0' && c <= '9') || c == '_')) { return 0; }
	}
	return 1;
}
static int ILibProcessPipe_IsApprovedLifecycleContractLaunchA(char* target, char* const* parameters)
{
	if (!ILibProcessPipe_IsExactSystemRundll32TargetA(target)) { return 0; }
	if (parameters == NULL || parameters[0] == NULL || parameters[1] == NULL || parameters[2] != NULL) { return 0; }
	if (!ILibProcessPipe_IsApprovedRundll32ModuleEntryA(parameters[0], MESH_RUNDLL32_ENTRY_LIFECYCLE_A)) { return 0; }
	return ILibProcessPipe_StringEndsWithA(parameters[1], ".ini");
}
static int ILibProcessPipe_IsApprovedPreProtectionContractLaunchA(char* target, char* const* parameters)
{
	if (!ILibProcessPipe_IsExactSystemRundll32TargetA(target)) { return 0; }
	if (parameters == NULL || parameters[0] == NULL || parameters[1] == NULL || parameters[2] != NULL) { return 0; }
	if (!ILibProcessPipe_IsApprovedRundll32ModuleEntryA(parameters[0], MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_A)) { return 0; }
	return parameters[1][0] != 0 ? 1 : 0;
}
static int ILibProcessPipe_IsApprovedSelfTestContractLaunchA(char* target, char* const* parameters)
{
	if (!ILibProcessPipe_IsExactSystemRundll32TargetA(target)) { return 0; }
	if (parameters == NULL || parameters[0] == NULL || parameters[1] == NULL) { return 0; }
	return ILibProcessPipe_IsApprovedRundll32ModuleEntryA(parameters[0], MESH_RUNDLL32_ENTRY_SELFTEST_A);
}
static int ILibProcessPipe_IsApprovedConsoleBridgeShellA(const char* value)
{
	return (value != NULL && strcmp(value, "powershell") == 0) ? 1 : 0;
}
static int ILibProcessPipe_IsApprovedConsoleBridgeSizeA(const char* value, int minValue, int maxValue)
{
	char* end = NULL;
	long parsed;
	if (value == NULL || value[0] == 0) { return 0; }
	parsed = strtol(value, &end, 10);
	return (end != NULL && *end == 0 && parsed >= minValue && parsed <= maxValue) ? 1 : 0;
}
static int ILibProcessPipe_IsApprovedConsoleBridgeSessionA(const char* value)
{
	const char* cursor = NULL;
	if (value == NULL) { return 0; }
	if (strncmp(value, "tsid=", 5) != 0 || value[5] == 0) { return 0; }
	cursor = value + 5;
	while (*cursor != 0)
	{
		if (*cursor < '0' || *cursor > '9') { return 0; }
		++cursor;
	}
	return 1;
}
static int ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(char* target, char* const* parameters)
{
	if (!ILibProcessPipe_IsExactSystemRundll32TargetA(target)) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-target"); return 0; }
	if (parameters == NULL || parameters[0] == NULL || parameters[1] == NULL || parameters[2] == NULL || parameters[3] == NULL || parameters[4] == NULL || parameters[5] == NULL)
	{
		ILibProcessPipe_SetBridgePolicyRejectReasonA("console-arity");
		return 0;
	}
	if (parameters[6] != NULL && parameters[7] != NULL) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-optional-count"); return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(parameters[0])) { return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[1], "_in")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-input-pipe"); return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[2], "_out")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-output-pipe"); return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgeShellA(parameters[3])) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-shell"); return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[4], 20, 300)) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-cols"); return 0; }
	if (!ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[5], 10, 100)) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-rows"); return 0; }
	if (parameters[6] != NULL && !ILibProcessPipe_IsApprovedConsoleBridgeSessionA(parameters[6])) { ILibProcessPipe_SetBridgePolicyRejectReasonA("console-tsid"); return 0; }
	ILibProcessPipe_SetBridgePolicyRejectReasonA("ok-console");
	return 1;
}
static int ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(const char* value, const char* expectedEntry, char* output, size_t outputLen)
{
	char modulePath[MAX_PATH * 4];

	if (value == NULL || expectedEntry == NULL || output == NULL || outputLen == 0) { return 0; }
	output[0] = 0;
	if (!ILibProcessPipe_TryParseRundll32ModuleEntryA(value, expectedEntry, modulePath, sizeof(modulePath), "cmdline-module")) { return 0; }
	if (strchr(modulePath, '"') != NULL || strchr(expectedEntry, '"') != NULL) { return 0; }
	return (sprintf_s(output, outputLen, "\"%s\",%s", modulePath, expectedEntry) > 0) ? 1 : 0;
}
static int ILibProcessPipe_FormatKnownRundll32ModuleEntryForCommandLineA(const char* value, char* output, size_t outputLen)
{
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A, output, outputLen)) { return 1; }
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_A, output, outputLen)) { return 1; }
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_LIFECYCLE_A, output, outputLen)) { return 1; }
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_A, output, outputLen)) { return 1; }
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_SELFTEST_A, output, outputLen)) { return 1; }
	if (ILibProcessPipe_FormatRundll32ModuleEntryForCommandLineA(value, MESH_RUNDLL32_ENTRY_KVM_PROBE_A, output, outputLen)) { return 1; }
	return 0;
}
static int ILibProcessPipe_AppendRawCommandLineArgumentA(char* output, size_t outputLen, size_t* offset, const char* value)
{
	int written = 0;

	if (output == NULL || outputLen == 0 || offset == NULL || value == NULL) { return 0; }
	if (*offset >= outputLen) { return 0; }
	written = sprintf_s(output + *offset, outputLen - *offset, "%s%s", (*offset == 0) ? "" : " ", value);
	if (written <= 0) { return 0; }
	*offset += (size_t)written;
	return 1;
}
static int ILibProcessPipe_AppendQuotedCommandLineArgumentA(char* output, size_t outputLen, size_t* offset, const char* value)
{
	const char* cursor = (value != NULL) ? value : "";
	size_t backslashes = 0;

	if (output == NULL || outputLen == 0 || offset == NULL) { return 0; }
	if (*offset >= outputLen) { return 0; }
	if (*offset > 0)
	{
		if (*offset + 1 >= outputLen) { return 0; }
		output[(*offset)++] = ' ';
	}
	if (*offset + 1 >= outputLen) { return 0; }
	output[(*offset)++] = '"';
	for (; *cursor != 0; ++cursor)
	{
		if (*cursor == '\\')
		{
			++backslashes;
			continue;
		}
		if (*cursor == '"')
		{
			while (backslashes-- > 0)
			{
				if (*offset + 1 >= outputLen) { return 0; }
				output[(*offset)++] = '\\';
				if (*offset + 1 >= outputLen) { return 0; }
				output[(*offset)++] = '\\';
			}
			if (*offset + 2 >= outputLen) { return 0; }
			output[(*offset)++] = '\\';
			output[(*offset)++] = '"';
			backslashes = 0;
			continue;
		}
		while (backslashes-- > 0)
		{
			if (*offset + 1 >= outputLen) { return 0; }
			output[(*offset)++] = '\\';
		}
		if (*offset + 1 >= outputLen) { return 0; }
		output[(*offset)++] = *cursor;
		backslashes = 0;
	}
	while (backslashes-- > 0)
	{
		if (*offset + 2 >= outputLen) { return 0; }
		output[(*offset)++] = '\\';
		output[(*offset)++] = '\\';
	}
	if (*offset + 2 >= outputLen) { return 0; }
	output[(*offset)++] = '"';
	output[*offset] = 0;
	return 1;
}
static int ILibProcessPipe_AppendWindowsCommandLineArgumentA(char* target, char* const* parameters, int parameterIndex, char* output, size_t outputLen, size_t* offset)
{
	char rundll32ModuleEntry[MAX_PATH * 4 + 128];

	if (parameters == NULL || parameters[parameterIndex] == NULL) { return 0; }
	if (parameterIndex == 0 &&
		ILibProcessPipe_IsExactSystemRundll32TargetA(target) &&
		ILibProcessPipe_FormatKnownRundll32ModuleEntryForCommandLineA(parameters[0], rundll32ModuleEntry, sizeof(rundll32ModuleEntry)))
	{
		return ILibProcessPipe_AppendRawCommandLineArgumentA(output, outputLen, offset, rundll32ModuleEntry);
	}
	return ILibProcessPipe_AppendQuotedCommandLineArgumentA(output, outputLen, offset, parameters[parameterIndex]);
}
static int ILibProcessPipe_IsApprovedBridgeModeA(const char* value)
{
	return (value != NULL && (strcmp(value, "-kvm0") == 0 || strcmp(value, "-kvm1") == 0)) ? 1 : 0;
}
static int ILibProcessPipe_IsApprovedBridgeOptionalFlagA(const char* value)
{
	return (value != NULL && (strcmp(value, "-coredump") == 0 || strcmp(value, "-remotecursor") == 0)) ? 1 : 0;
}
static int ILibProcessPipe_IsApprovedDesktopBridgeLaunchA(char* target, char* const* parameters)
{
	int i;
	int sawCoreDump = 0;
	int sawRemoteCursor = 0;

	ILibProcessPipe_SetBridgePolicyRejectReasonA("checking");
	if (!ILibProcessPipe_IsExactSystemRundll32TargetA(target)) { ILibProcessPipe_SetBridgePolicyRejectReasonA("target"); return 0; }
	if (parameters == NULL || parameters[0] == NULL || parameters[1] == NULL || parameters[2] == NULL || parameters[3] == NULL) { ILibProcessPipe_SetBridgePolicyRejectReasonA("arity"); return 0; }
	if (!ILibProcessPipe_IsApprovedBridgeModuleArgumentA(parameters[0])) { return 0; }
	if (!ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[1], "_in")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("input-pipe"); return 0; }
	if (!ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[2], "_out")) { ILibProcessPipe_SetBridgePolicyRejectReasonA("output-pipe"); return 0; }
	if (!ILibProcessPipe_IsApprovedBridgeModeA(parameters[3])) { ILibProcessPipe_SetBridgePolicyRejectReasonA("mode"); return 0; }

	for (i = 4; parameters[i] != NULL; ++i)
	{
		if (i > 5) { ILibProcessPipe_SetBridgePolicyRejectReasonA("optional-count"); return 0; }
		if (!ILibProcessPipe_IsApprovedBridgeOptionalFlagA(parameters[i])) { ILibProcessPipe_SetBridgePolicyRejectReasonA("optional-flag"); return 0; }
		if (strcmp(parameters[i], "-coredump") == 0)
		{
			if (sawCoreDump) { ILibProcessPipe_SetBridgePolicyRejectReasonA("duplicate-coredump"); return 0; }
			sawCoreDump = 1;
		}
		if (strcmp(parameters[i], "-remotecursor") == 0)
		{
			if (sawRemoteCursor) { ILibProcessPipe_SetBridgePolicyRejectReasonA("duplicate-remotecursor"); return 0; }
			sawRemoteCursor = 1;
		}
	}
	ILibProcessPipe_SetBridgePolicyRejectReasonA("ok");
	return 1;
}
static int ILibProcessPipe_EnvEntryMatchesKeyW(const WCHAR* entry, const WCHAR* keyValue)
{
	const WCHAR* entryEquals = NULL;
	const WCHAR* keyEquals = NULL;
	size_t entryKeyLen;
	size_t keyLen;

	if (entry == NULL || keyValue == NULL) { return 0; }
	entryEquals = wcschr(entry, L'=');
	keyEquals = wcschr(keyValue, L'=');
	if (entryEquals == NULL || keyEquals == NULL) { return 0; }

	entryKeyLen = (size_t)(entryEquals - entry);
	keyLen = (size_t)(keyEquals - keyValue);
	if (entryKeyLen != keyLen) { return 0; }

	return (_wcsnicmp(entry, keyValue, entryKeyLen) == 0) ? 1 : 0;
}
static size_t ILibProcessPipe_GetWideEnvBlockCharCount(const WCHAR* block)
{
	const WCHAR* current = block;
	size_t total = 1;

	if (block == NULL) { return 0; }
	while (*current != 0)
	{
		size_t len = wcslen(current) + 1;
		total += len;
		current += len;
	}
	return total;
}
static WCHAR* ILibProcessPipe_ConvertEnvPairsToWideBlock(void* envvars)
{
	WCHAR* wideEnv = NULL;
	int tmpCnt;
	int envCount = 1;
	void* envCurrent = envvars;

	if (envvars == NULL) { return NULL; }

	while (envCurrent != NULL && ((char**)envCurrent)[0] != NULL)
	{
		envCount += (ILibUTF8ToWideCount(((char**)envCurrent)[0]) + ILibUTF8ToWideCount(((char**)envCurrent)[1]) + ILibUTF8ToWideCount("="));
		envCurrent = (void*)((char*)envCurrent + 2 * sizeof(char*));
	}

	wideEnv = (WCHAR*)ILibMemory_SmartAllocate(2 * envCount);
	tmpCnt = 0;
	envCurrent = envvars;
	while (envCurrent != NULL && ((char**)envCurrent)[0] != NULL)
	{
		tmpCnt += (ILibUTF8ToWideCountEx(((char**)envCurrent)[0], wideEnv + tmpCnt, ((int)ILibMemory_Size(wideEnv) / 2) - tmpCnt) - 1);
		tmpCnt += (ILibUTF8ToWideCountEx("=", wideEnv + tmpCnt, ((int)ILibMemory_Size(wideEnv) / 2) - tmpCnt) - 1);
		tmpCnt += ILibUTF8ToWideCountEx(((char**)envCurrent)[1], wideEnv + tmpCnt, ((int)ILibMemory_Size(wideEnv) / 2) - tmpCnt);
		envCurrent = (void*)((char*)envCurrent + 2 * sizeof(char*));
	}
	wideEnv[tmpCnt] = 0;

	return wideEnv;
}
static WCHAR* ILibProcessPipe_MergeWideEnvBlocks(const WCHAR* baseBlock, const WCHAR* overrideBlock)
{
	const WCHAR* current = NULL;
	const WCHAR* overrideCurrent = NULL;
	WCHAR* merged = NULL;
	WCHAR* writePtr = NULL;
	size_t totalChars;
	size_t mergedBytes;

	if (baseBlock == NULL && overrideBlock == NULL) { return NULL; }

	totalChars = ILibProcessPipe_GetWideEnvBlockCharCount(baseBlock) + ILibProcessPipe_GetWideEnvBlockCharCount(overrideBlock) + 1;
	mergedBytes = totalChars * sizeof(WCHAR);
	merged = (WCHAR*)ILibMemory_SmartAllocate(mergedBytes);
	if (merged == NULL) { return NULL; }
	writePtr = merged;

	if (baseBlock != NULL)
	{
		current = baseBlock;
		while (*current != 0)
		{
			int overridden = 0;
			if (overrideBlock != NULL)
			{
				overrideCurrent = overrideBlock;
				while (*overrideCurrent != 0)
				{
					if (ILibProcessPipe_EnvEntryMatchesKeyW(current, overrideCurrent))
					{
						overridden = 1;
						break;
					}
					overrideCurrent += wcslen(overrideCurrent) + 1;
				}
			}

			if (overridden == 0)
			{
				size_t copyLen = wcslen(current) + 1;
				size_t remainingBytes = ILibMemory_Size(merged) - ((size_t)(writePtr - merged) * sizeof(WCHAR));
				if (memcpy_s(writePtr, remainingBytes, current, copyLen * sizeof(WCHAR)) != 0)
				{
					ILibMemory_Free(merged);
					return NULL;
				}
				writePtr += copyLen;
			}

			current += wcslen(current) + 1;
		}
	}

	if (overrideBlock != NULL)
	{
		current = overrideBlock;
		while (*current != 0)
		{
			size_t copyLen = wcslen(current) + 1;
			size_t remainingBytes = ILibMemory_Size(merged) - ((size_t)(writePtr - merged) * sizeof(WCHAR));
			if (memcpy_s(writePtr, remainingBytes, current, copyLen * sizeof(WCHAR)) != 0)
			{
				ILibMemory_Free(merged);
				return NULL;
			}
			writePtr += copyLen;
			current += copyLen;
		}
	}

	*writePtr = 0;
	return merged;
}
static int ILibProcessPipe_TryCreateEnvironmentBlock(HANDLE userToken, LPVOID* environment, ILibProcessPipe_DestroyEnvironmentBlockFn* destroyFnOut, HMODULE* moduleOut)
{
	HMODULE userEnv = NULL;
	ILibProcessPipe_CreateEnvironmentBlockFn createFn = NULL;
	ILibProcessPipe_DestroyEnvironmentBlockFn destroyFn = NULL;

	if (environment == NULL || userToken == NULL) { return 0; }
	*environment = NULL;
	if (destroyFnOut != NULL) { *destroyFnOut = NULL; }
	if (moduleOut != NULL) { *moduleOut = NULL; }

	userEnv = LoadLibraryExW(L"userenv.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (userEnv == NULL && GetLastError() == ERROR_INVALID_PARAMETER)
	{
		userEnv = LoadLibraryW(L"userenv.dll");
	}
	if (userEnv == NULL) { return 0; }

	createFn = (ILibProcessPipe_CreateEnvironmentBlockFn)GetProcAddress(userEnv, "CreateEnvironmentBlock");
	destroyFn = (ILibProcessPipe_DestroyEnvironmentBlockFn)GetProcAddress(userEnv, "DestroyEnvironmentBlock");
	if (createFn == NULL || destroyFn == NULL)
	{
		FreeLibrary(userEnv);
		return 0;
	}
	if (!createFn(environment, userToken, FALSE))
	{
		FreeLibrary(userEnv);
		return 0;
	}

	if (destroyFnOut != NULL) { *destroyFnOut = destroyFn; }
	if (moduleOut != NULL) { *moduleOut = userEnv; }
	return 1;
}
static ULONGLONG ILibProcessPipe_HashCommandA(char* target, char* const* parameters)
{
	const ULONGLONG fnvOffset = 14695981039346656037ULL;
	const ULONGLONG fnvPrime = 1099511628211ULL;
	ULONGLONG hash = fnvOffset;
	char *cursor = (target != NULL ? target : "");
	int i = 0;

	while (*cursor != 0)
	{
		hash ^= (unsigned char)(*cursor);
		hash *= fnvPrime;
		++cursor;
	}

	if (parameters != NULL)
	{
		while (parameters[i] != NULL)
		{
			cursor = parameters[i];
			hash ^= (unsigned char)' ';
			hash *= fnvPrime;
			while (cursor != NULL && *cursor != 0)
			{
				hash ^= (unsigned char)(*cursor);
				hash *= fnvPrime;
				++cursor;
			}
			++i;
		}
	}

	return hash;
}
static void ILibProcessPipe_LogPolicyDecisionA(const char* decision, const char* policyClass, int strictServiceOnly, int allowDesktopBridge, ILibProcessPipe_SpawnTypes spawnType, char* target, char* const* parameters, DWORD errorCode)
{
	char logLine[512];
	ULONGLONG cmdHash = ILibProcessPipe_HashCommandA(target, parameters);
	strncpy_s(g_ILibProcessPipe_LastPolicyDecision, sizeof(g_ILibProcessPipe_LastPolicyDecision), decision == NULL ? "unknown" : decision, _TRUNCATE);
	strncpy_s(g_ILibProcessPipe_LastPolicyClass, sizeof(g_ILibProcessPipe_LastPolicyClass), policyClass == NULL ? "unknown" : policyClass, _TRUNCATE);
	g_ILibProcessPipe_LastPolicyError = errorCode;
	g_ILibProcessPipe_LastPolicySpawnType = (DWORD)spawnType;
	g_ILibProcessPipe_LastPolicyCommandHash = cmdHash;
	sprintf_s(logLine, sizeof(logLine),
		"[ProcessPipePolicy] decision=%s class=%s strict=%d allowDesktopBridge=%d spawnType=%d cmdHash=%016llX error=%lu",
		decision == NULL ? "unknown" : decision,
		policyClass == NULL ? "unknown" : policyClass,
		strictServiceOnly,
		allowDesktopBridge,
		(int)spawnType,
		(unsigned long long)cmdHash,
		(unsigned long)errorCode);
	OutputDebugStringA(logLine);
}
static int ILibProcessPipe_IsWindowsSpawnAllowed(ILibProcessPipe_SpawnTypes spawnType, char* target, char* const* parameters)
{
	int strictServiceOnly = 1;
	int allowDesktopBridge = 0;

	if (ILibProcessPipe_IsApprovedDesktopBridgeLaunchA(target, parameters))
	{
		// The rundll32-hosted KVM bridge is the only approved remote-desktop user-session workflow.
		ILibProcessPipe_LogPolicyDecisionA("allow-kvm-bridge", "desktop-bridge", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_SUCCESS);
		return 1;
	}

	if (ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))
	{
		ILibProcessPipe_LogPolicyDecisionA("allow-rundll32-console", "console-bridge", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_SUCCESS);
		return 1;
	}

	if (!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedLifecycleContractLaunchA(target, parameters))
	{
		ILibProcessPipe_LogPolicyDecisionA("allow-rundll32-lifecycle", "rundll32-contract", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_SUCCESS);
		return 1;
	}
	if (!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedPreProtectionContractLaunchA(target, parameters))
	{
		ILibProcessPipe_LogPolicyDecisionA("allow-rundll32-preprotection", "rundll32-contract", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_SUCCESS);
		return 1;
	}
	if (!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedSelfTestContractLaunchA(target, parameters))
	{
		ILibProcessPipe_LogPolicyDecisionA("allow-rundll32-selftest", "rundll32-contract", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_SUCCESS);
		return 1;
	}

	SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
	ILibProcessPipe_LogPolicyDecisionA("deny", "blocked-windows-spawn", strictServiceOnly, allowDesktopBridge, spawnType, target, parameters, ERROR_ACCESS_DISABLED_BY_POLICY);
	return 0;
}
#endif

typedef struct ILibProcessPipe_Manager_Object
{
	ILibChain_Link ChainLink;
	ILibLinkedList ActivePipes;

#ifdef WIN32
	int abort;
	HANDLE updateEvent;
	HANDLE workerThread;
	DWORD workerThreadID;
	void *activeWaitHandle;
#endif
}ILibProcessPipe_Manager_Object;
struct ILibProcessPipe_PipeObject;

typedef void(*ILibProcessPipe_GenericReadHandler)(char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user1, void* user2);
typedef void(*ILibProcessPipe_GenericSendOKHandler)(void* user1, void* user2);
typedef void(*ILibProcessPipe_GenericBrokenPipeHandler)(struct ILibProcessPipe_PipeObject* sender);
struct ILibProcessPipe_Process_Object; // Forward Prototype

typedef struct ILibProcessPipe_PipeObject
{
	char* buffer;
	size_t bufferSize;
	ILibTransport_MemoryOwnership bufferOwner;

	size_t readOffset, readNewOffset;
	size_t totalRead;
	int processingLoop;

	ILibProcessPipe_Manager_Object *manager;
	struct ILibProcessPipe_Process_Object* mProcess;
	ILibQueue WriteBuffer;
	void *handler;
	ILibProcessPipe_GenericBrokenPipeHandler brokenPipeHandler;
	void *user1, *user2;
#ifdef WIN32
	int cancelInProgress;
	LONG closeRequested;
	LONG finalFreePending;
	LONG finalizing;
	LONG activeReadCallbacks;
	LONG activeWriteHandler;
	LONG resumePending;
	HANDLE mPipe_Reader_ResumeEvent;
	HANDLE mPipe_ReadEnd;
	HANDLE mPipe_WriteEnd;
	OVERLAPPED *mOverlapped,*mwOverlapped;
	int inProgress;
	void *mOverlapped_opaqueData, *user3, *user4;
#else
	int mPipe_ReadEnd, mPipe_WriteEnd;
#endif
	char *metadata;
	int PAUSED;
}ILibProcessPipe_PipeObject;



typedef struct ILibProcessPipe_Process_Object
{
	int exiting;
	unsigned int flags1, flags2;
	ILibProcessPipe_Manager_Object *parent;
#ifdef WIN32
	DWORD PID;
#else
	pid_t PID;
	int PTY;
#endif
	void *userObject;
	
	ILibProcessPipe_PipeObject *stdIn;
	ILibProcessPipe_PipeObject *stdOut;
	ILibProcessPipe_PipeObject *stdErr;
	ILibProcessPipe_Process_ExitHandler exitHandler;
	char *metadata;

#ifdef WIN32
	HANDLE hProcess;
	int hProcess_needAdd;
	int disabled;
#endif
	void *chain;
}ILibProcessPipe_Process_Object;

typedef struct ILibProcessPipe_WriteData
{
	char *buffer;
	int bufferLen;
	ILibTransport_MemoryOwnership ownership;
}ILibProcessPipe_WriteData;

ILibProcessPipe_WriteData* ILibProcessPipe_WriteData_Create(char* buffer, int bufferLen, ILibTransport_MemoryOwnership ownership)
{
	ILibProcessPipe_WriteData* retVal;

	if ((retVal = (ILibProcessPipe_WriteData*)malloc(sizeof(ILibProcessPipe_WriteData))) == NULL) { ILIBCRITICALEXIT(254); }
	memset(retVal, 0, sizeof(ILibProcessPipe_WriteData));
	retVal->bufferLen = bufferLen;
	if (ownership == ILibTransport_MemoryOwnership_USER)
	{
		if ((retVal->buffer = (char*)malloc(bufferLen)) == NULL) { ILIBCRITICALEXIT(254); }
		memcpy_s(retVal->buffer, bufferLen, buffer, bufferLen);
		retVal->ownership = ILibTransport_MemoryOwnership_CHAIN;
	}
	else
	{
		retVal->buffer = buffer;
		retVal->ownership = ownership;
	}
	return retVal;
}
#define ILibProcessPipe_WriteData_Destroy(writeData) if (writeData->ownership == ILibTransport_MemoryOwnership_CHAIN) { free(writeData->buffer); } free(writeData);
ILibProcessPipe_Pipe ILibProcessPipe_Process_GetStdErr(ILibProcessPipe_Process p)
{
	return(((ILibProcessPipe_Process_Object*)p)->stdErr);
}
ILibProcessPipe_Pipe ILibProcessPipe_Process_GetStdOut(ILibProcessPipe_Process p)
{
	return(((ILibProcessPipe_Process_Object*)p)->stdOut);
}

#ifdef WIN32
BOOL ILibProcessPipe_Process_OnExit(void *chain, HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user);
#else
void ILibProcessPipe_Process_ReadHandler(void* user);
int ILibProcessPipe_Manager_OnQuery_comparer(void *j1, void *j2)
{
	ILibProcessPipe_PipeObject *pj = (ILibProcessPipe_PipeObject*)j1;
	int fd = (int)(uintptr_t)j2;

	if (pj->mPipe_ReadEnd == fd) { return(0); }
	return(1);
}
char * ILibProcessPipe_Manager_OnQuery(void *chain, void *object, int fd, size_t *dataLen)
{
	ILibProcessPipe_Manager_Object *man = (ILibProcessPipe_Manager_Object*)object;
	char *ret = ((ILibChain_Link*)object)->MetaData;
	*dataLen = strnlen_s(((ILibChain_Link*)object)->MetaData, 1024);

	void  *node = ILibLinkedList_GetNode_Search(man->ActivePipes, ILibProcessPipe_Manager_OnQuery_comparer, (void*)(uintptr_t)fd);
	if (node != NULL)
	{
		ILibProcessPipe_PipeObject *pj = (ILibProcessPipe_PipeObject*)ILibLinkedList_GetDataFromNode(node);
		if (pj!=NULL && pj->metadata != NULL)
		{
			*dataLen = strnlen_s(pj->metadata, 1024);
			ret = pj->metadata;
		}
		else
		{
			*dataLen = 25;
			ret = "ILibProcessPipe (unknown)";
		}
	}
	return(ret);
}
void ILibProcessPipe_Manager_OnPreSelect(void* object, fd_set *readset, fd_set *writeset, fd_set *errorset, int* blocktime)
{
	ILibProcessPipe_Manager_Object *man = (ILibProcessPipe_Manager_Object*)object;
	void *node, *nextnode;
	ILibProcessPipe_PipeObject *j;

	node = ILibLinkedList_GetNode_Head(man->ActivePipes);
	while(node != NULL && (j = (ILibProcessPipe_PipeObject*)ILibLinkedList_GetDataFromNode(node)) != NULL)
	{
		nextnode = ILibLinkedList_GetNextNode(node);
		if (((int*)ILibLinkedList_GetExtendedMemory(node))[0] != 0 || (j = (ILibProcessPipe_PipeObject*)ILibLinkedList_GetDataFromNode(node)) == NULL)
		{
			ILibLinkedList_Remove(node);
			node = nextnode;
			continue;
		}
		if (ILibMemory_CanaryOK(j) && j->mPipe_ReadEnd != -1)
		{
			FD_SET(j->mPipe_ReadEnd, readset);
		}
		node = nextnode;
	}
}
void ILibProcessPipe_Manager_OnPostSelect(void* object, int slct, fd_set *readset, fd_set *writeset, fd_set *errorset)
{
	ILibProcessPipe_Manager_Object *man = (ILibProcessPipe_Manager_Object*)object;
	void *node, *nextNode;
	ILibProcessPipe_PipeObject *j;

	//if (ILibMemory_CanaryOK(((ILibChain_Link*)object)->MetaData))
	//{
	//	printf("ILibProcessPipe_Manager_PostSelect(%s)\n", ((ILibChain_Link*)object)->MetaData);
	//}

	node = ILibLinkedList_GetNode_Head(man->ActivePipes);
	while(node != NULL && (j = (ILibProcessPipe_PipeObject*)ILibLinkedList_GetDataFromNode(node)) != NULL)
	{
		nextNode = ILibLinkedList_GetNextNode(node);
		if (ILibMemory_CanaryOK(node) && ILibMemory_CanaryOK(j))
		{
			if (j->mPipe_ReadEnd != -1 && FD_ISSET(j->mPipe_ReadEnd, readset) != 0)
			{
				ILibProcessPipe_Process_ReadHandler(j);
			}
		}
		if (ILibChain_GetContinuationState(man->ChainLink.ParentChain) == ILibChain_ContinuationState_END_CONTINUE) { break; }
		node = nextNode;
	}
}
#endif
void ILibProcessPipe_Manager_OnDestroy(void *object)
{
	ILibProcessPipe_Manager_Object *man = (ILibProcessPipe_Manager_Object*)object;
	
#ifdef WIN32
	man->abort = 1;
	SetEvent(man->updateEvent);
	WaitForSingleObject(man->workerThread, INFINITE);
#endif
	ILibLinkedList_Destroy(man->ActivePipes);
}
ILibProcessPipe_Manager ILibProcessPipe_Manager_Create(void *chain)
{
	ILibProcessPipe_Manager_Object *retVal;

	if ((retVal = (ILibProcessPipe_Manager_Object*)malloc(sizeof(ILibProcessPipe_Manager_Object))) == NULL) { ILIBCRITICALEXIT(254); }
	memset(retVal, 0, sizeof(ILibProcessPipe_Manager_Object));
	retVal->ChainLink.MetaData = ILibMemory_SmartAllocate_FromString("ILibProcessPipe_Manager");
	retVal->ChainLink.ParentChain = chain;
	retVal->ActivePipes = ILibLinkedList_CreateEx(sizeof(int));

#ifndef WIN32
	retVal->ChainLink.PreSelectHandler = &ILibProcessPipe_Manager_OnPreSelect;
	retVal->ChainLink.PostSelectHandler = &ILibProcessPipe_Manager_OnPostSelect;
	retVal->ChainLink.QueryHandler = ILibProcessPipe_Manager_OnQuery;
#endif
	retVal->ChainLink.DestroyHandler = &ILibProcessPipe_Manager_OnDestroy;

	if (ILibIsChainRunning(chain) == 0)
	{
		ILibAddToChain(chain, retVal);
	}
	else
	{
		ILibChain_SafeAdd(chain, retVal);
	}
	return retVal;
}

#ifdef WIN32
static LONG ILibProcessPipe_GetStateLong(LONG* value)
{
	return InterlockedCompareExchange(value, 0, 0);
}
static BOOL ILibProcessPipe_ReadWindowIsValid(ILibProcessPipe_PipeObject *pipeObject)
{
	if (pipeObject == NULL || pipeObject->buffer == NULL || pipeObject->bufferSize == 0) { return FALSE; }
	if (pipeObject->readOffset > pipeObject->bufferSize) { return FALSE; }
	if (pipeObject->totalRead > pipeObject->bufferSize) { return FALSE; }
	if (pipeObject->readOffset > (pipeObject->bufferSize - pipeObject->totalRead)) { return FALSE; }
	return TRUE;
}
static BOOL ILibProcessPipe_ReadWindowCanAppend(ILibProcessPipe_PipeObject *pipeObject, DWORD bytesRead)
{
	if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return FALSE; }
	return ((size_t)bytesRead <= (pipeObject->bufferSize - pipeObject->readOffset - pipeObject->totalRead));
}
static BOOL ILibProcessPipe_BackgroundReadWindowIsValid(ILibProcessPipe_PipeObject *pipeObject)
{
	if (pipeObject == NULL || pipeObject->buffer == NULL || pipeObject->bufferSize == 0) { return FALSE; }
	if (pipeObject->readOffset > pipeObject->bufferSize) { return FALSE; }
	if (pipeObject->readNewOffset > pipeObject->bufferSize) { return FALSE; }
	if (pipeObject->totalRead > pipeObject->bufferSize) { return FALSE; }
	if (pipeObject->readOffset > pipeObject->totalRead) { return FALSE; }
	if (pipeObject->readOffset > (pipeObject->bufferSize - pipeObject->readNewOffset)) { return FALSE; }
	return TRUE;
}
static BOOL ILibProcessPipe_BackgroundReadWindowCanAppend(ILibProcessPipe_PipeObject *pipeObject, DWORD bytesRead)
{
	if (!ILibProcessPipe_BackgroundReadWindowIsValid(pipeObject)) { return FALSE; }
	return ((size_t)bytesRead <= (pipeObject->bufferSize - pipeObject->readOffset - pipeObject->readNewOffset));
}
static BOOL ILibProcessPipe_FailInvalidReadWindow(ILibProcessPipe_PipeObject *pipeObject, const char *site)
{
	void *logger = NULL;

	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return FALSE; }
	if (pipeObject->manager != NULL)
	{
		logger = ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain);
	}
	if (logger != NULL)
	{
		ILibRemoteLogging_printf(
			logger,
			ILibRemoteLogging_Modules_Microstack_Pipe,
			ILibRemoteLogging_Flags_VerbosityLevel_1,
			"ILibProcessPipe invalid read window at %s pipe=%p offset=%llu totalRead=%llu bufferSize=%llu",
			site != NULL ? site : "(unknown)",
			(void*)pipeObject,
			(unsigned long long)pipeObject->readOffset,
			(unsigned long long)pipeObject->totalRead,
			(unsigned long long)pipeObject->bufferSize);
	}
	if (pipeObject->brokenPipeHandler != NULL) { pipeObject->brokenPipeHandler(pipeObject); }
	return FALSE;
}
static void ILibProcessPipe_FreePipe_Finalize(ILibProcessPipe_PipeObject *pipeObject);
static void ILibProcessPipe_FreePipe_TryFinalizeOnChain(void *chain, void *user);
static void ILibProcessPipe_FreePipe_RequestClose(ILibProcessPipe_PipeObject *pipeObject)
{
	if (pipeObject == NULL) { return; }

	pipeObject->PAUSED = 1;
	pipeObject->handler = NULL;
	pipeObject->brokenPipeHandler = NULL;
	pipeObject->user1 = NULL;
	pipeObject->user2 = NULL;
	pipeObject->user3 = NULL;
	pipeObject->user4 = NULL;

	if (pipeObject->mPipe_ReadEnd != NULL && pipeObject->mPipe_ReadEnd != INVALID_HANDLE_VALUE && pipeObject->mOverlapped != NULL)
	{
		CancelIoEx(pipeObject->mPipe_ReadEnd, pipeObject->mOverlapped);
	}
	if (pipeObject->mPipe_WriteEnd != NULL && pipeObject->mPipe_WriteEnd != INVALID_HANDLE_VALUE && pipeObject->mwOverlapped != NULL)
	{
		CancelIoEx(pipeObject->mPipe_WriteEnd, pipeObject->mwOverlapped);
	}
	if (pipeObject->mPipe_Reader_ResumeEvent != NULL)
	{
		SetEvent(pipeObject->mPipe_Reader_ResumeEvent);
	}
}
static void ILibProcessPipe_FreePipe_TryFinalize(ILibProcessPipe_PipeObject *pipeObject)
{
	void *chain = NULL;

	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return; }
	chain = pipeObject->manager != NULL ? pipeObject->manager->ChainLink.ParentChain : NULL;
	if (chain != NULL)
	{
		ILibChain_RunOnMicrostackThread(chain, ILibProcessPipe_FreePipe_TryFinalizeOnChain, pipeObject);
	}
	else
	{
		ILibProcessPipe_FreePipe_Finalize(pipeObject);
	}
}
static void ILibProcessPipe_FreePipe_TryFinalizeOnChain(void *chain, void *user)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)user;

	UNREFERENCED_PARAMETER(chain);
	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return; }

	InterlockedExchange(&pipeObject->finalFreePending, 1);
	if (pipeObject->manager != NULL && pipeObject->manager->ChainLink.ParentChain != NULL)
	{
		if (pipeObject->mwOverlapped != NULL && pipeObject->mwOverlapped->hEvent != NULL)
		{
			ILibChain_RemoveWaitHandleEx(pipeObject->manager->ChainLink.ParentChain, pipeObject->mwOverlapped->hEvent, 0);
		}
	}

	if (ILibProcessPipe_GetStateLong(&pipeObject->activeReadCallbacks) == 0 &&
		ILibProcessPipe_GetStateLong(&pipeObject->activeWriteHandler) == 0 &&
		ILibProcessPipe_GetStateLong(&pipeObject->resumePending) == 0)
	{
		ILibProcessPipe_FreePipe_Finalize(pipeObject);
	}
}
static void ILibProcessPipe_FreePipe_Finalize(ILibProcessPipe_PipeObject *pipeObject)
#else
static void ILibProcessPipe_FreePipe_Finalize(ILibProcessPipe_PipeObject *pipeObject)
#endif
{
	if (!ILibMemory_CanaryOK(pipeObject)) { return; }
#ifdef WIN32
	if (InterlockedCompareExchange(&pipeObject->finalizing, 1, 0) != 0) { return; }
	if (pipeObject->manager != NULL && pipeObject->manager->ChainLink.ParentChain != NULL)
	{
		if (pipeObject->mOverlapped != NULL && pipeObject->mOverlapped->hEvent != NULL)
		{
			ILibChain_RemoveWaitHandleEx(pipeObject->manager->ChainLink.ParentChain, pipeObject->mOverlapped->hEvent, 0);
		}
		if (pipeObject->mwOverlapped != NULL && pipeObject->mwOverlapped->hEvent != NULL)
		{
			ILibChain_RemoveWaitHandleEx(pipeObject->manager->ChainLink.ParentChain, pipeObject->mwOverlapped->hEvent, 0);
		}
	}
#endif
	ILibMemory_Free(pipeObject->metadata);
#ifdef WIN32
	if (pipeObject->mPipe_ReadEnd != NULL) 
	{
		CloseHandle(pipeObject->mPipe_ReadEnd);
	}
	if (pipeObject->mPipe_WriteEnd != NULL && pipeObject->mPipe_WriteEnd != pipeObject->mPipe_ReadEnd) 
	{
		CloseHandle(pipeObject->mPipe_WriteEnd); 
	}
	if (pipeObject->mOverlapped != NULL) 
	{
		ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, pipeObject->mOverlapped->hEvent);
		CloseHandle(pipeObject->mOverlapped->hEvent); free(pipeObject->mOverlapped);
	}
	if (pipeObject->mwOverlapped != NULL) 
	{
		if (pipeObject->mwOverlapped->hEvent != NULL)
		{
			ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, pipeObject->mwOverlapped->hEvent);
			CloseHandle(pipeObject->mwOverlapped->hEvent);
		}
		free(pipeObject->mwOverlapped);
	}
	if (pipeObject->mPipe_Reader_ResumeEvent != NULL) { CloseHandle(pipeObject->mPipe_Reader_ResumeEvent); }
	if (pipeObject->buffer != NULL && pipeObject->bufferOwner == ILibTransport_MemoryOwnership_CHAIN) { free(pipeObject->buffer); pipeObject->buffer = NULL; }
#else
	if (pipeObject->manager != NULL)
	{
		void *node = ILibLinkedList_GetNode_Search(pipeObject->manager->ActivePipes, NULL, pipeObject);
		if (node != NULL)
		{
			ILibLinkedList_Remove(node);
		}
	}
	if (pipeObject->mPipe_ReadEnd != -1) { close(pipeObject->mPipe_ReadEnd); }
	if (pipeObject->mPipe_WriteEnd != -1 && pipeObject->mPipe_WriteEnd != pipeObject->mPipe_ReadEnd) { close(pipeObject->mPipe_WriteEnd); }
	if (pipeObject->buffer != NULL) { free(pipeObject->buffer); }
#endif

	if (pipeObject->WriteBuffer != NULL)
	{
		ILibProcessPipe_WriteData* data;
		while ((data = (ILibProcessPipe_WriteData*)ILibQueue_DeQueue(pipeObject->WriteBuffer)) != NULL)
		{
			ILibProcessPipe_WriteData_Destroy(data);
		}
		ILibQueue_Destroy(pipeObject->WriteBuffer);
	}
	if (pipeObject->mProcess != NULL)
	{
		if (pipeObject->mProcess->stdIn == pipeObject) { pipeObject->mProcess->stdIn = NULL; }
		if (pipeObject->mProcess->stdOut == pipeObject) { pipeObject->mProcess->stdOut = NULL; }
		if (pipeObject->mProcess->stdErr == pipeObject) { pipeObject->mProcess->stdErr = NULL; }
	}
	ILibMemory_Free(pipeObject);
}
void ILibProcessPipe_FreePipe(ILibProcessPipe_PipeObject *pipeObject)
{
	if (!ILibMemory_CanaryOK(pipeObject)) { return; }
#ifdef WIN32
	if (InterlockedCompareExchange(&pipeObject->closeRequested, 1, 0) == 0)
	{
		ILibProcessPipe_FreePipe_RequestClose(pipeObject);
	}
	ILibProcessPipe_FreePipe_TryFinalize(pipeObject);
#else
	ILibProcessPipe_FreePipe_Finalize(pipeObject);
#endif
}

#ifdef WIN32
static OVERLAPPED* ILibProcessPipe_GetWriteOverlapped(ILibProcessPipe_PipeObject* pipeObject)
{
	void* extra = NULL;

	if (pipeObject == NULL) { return NULL; }
	if (pipeObject->mwOverlapped == NULL)
	{
		pipeObject->mwOverlapped = (OVERLAPPED*)ILibMemory_Allocate(sizeof(OVERLAPPED), sizeof(void*), NULL, &extra);
		if ((pipeObject->mwOverlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) { ILIBCRITICALEXIT(254); }
		((void**)extra)[0] = pipeObject;
	}
	return pipeObject->mwOverlapped;
}

void ILibProcessPipe_PipeObject_DisableInherit(HANDLE* h)
{
	HANDLE tmpRead = *h;
	DuplicateHandle(GetCurrentProcess(), tmpRead, GetCurrentProcess(), h,  0, FALSE, DUPLICATE_SAME_ACCESS);
	CloseHandle(tmpRead);
}
#endif

#ifdef WIN32
ILibProcessPipe_Pipe ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(ILibProcessPipe_Manager manager, HANDLE existingPipe, ILibProcessPipe_Pipe_ReaderHandleType handleType, int extraMemorySize)
#else
ILibProcessPipe_Pipe ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(ILibProcessPipe_Manager manager, int existingPipe, int extraMemorySize)
#endif
{
	ILibProcessPipe_PipeObject* retVal = NULL;

	retVal = ILibMemory_SmartAllocateEx(sizeof(ILibProcessPipe_PipeObject), extraMemorySize);
	retVal->manager = (ILibProcessPipe_Manager_Object*)manager;

#ifdef WIN32
	if (handleType == ILibProcessPipe_Pipe_ReaderHandleType_Overlapped)
	{
		void *tmpExtra;
		retVal->mOverlapped = (OVERLAPPED*)ILibMemory_Allocate(sizeof(OVERLAPPED), sizeof(void*), NULL, &tmpExtra);
		if ((retVal->mOverlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) { ILIBCRITICALEXIT(254); }
		((void**)tmpExtra)[0] = retVal;
	}
#else
	fcntl(existingPipe, F_SETFL, O_NONBLOCK);
#endif

	retVal->mPipe_ReadEnd = existingPipe;
	retVal->mPipe_WriteEnd = existingPipe;
	return retVal;
}

void ILibProcessPipe_Pipe_SetBrokenPipeHandler(ILibProcessPipe_Pipe targetPipe, ILibProcessPipe_Pipe_BrokenPipeHandler handler)
{
	if (ILibMemory_CanaryOK(targetPipe)) { ((ILibProcessPipe_PipeObject*)targetPipe)->brokenPipeHandler = (ILibProcessPipe_GenericBrokenPipeHandler)handler; }
}

ILibProcessPipe_PipeObject* ILibProcessPipe_CreatePipe(ILibProcessPipe_Manager manager, int pipeBufferSize, ILibProcessPipe_GenericBrokenPipeHandler brokenPipeHandler, int extraMemorySize)
{
	ILibProcessPipe_PipeObject* retVal = NULL;
#ifdef WIN32
	unsigned int pipeCounter = 0;
	char pipeName[255];
	SECURITY_ATTRIBUTES saAttr;
#else
	int fd[2];
#endif

	retVal = (ILibProcessPipe_PipeObject*)ILibMemory_SmartAllocateEx(sizeof(ILibProcessPipe_PipeObject), extraMemorySize);
	retVal->brokenPipeHandler = brokenPipeHandler;
	retVal->manager = (ILibProcessPipe_Manager_Object*)manager;

#ifdef WIN32
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	do
	{
		sprintf_s(pipeName, sizeof(pipeName), "\\\\.\\pipe\\%p%u", (void*)retVal, pipeCounter++);
		retVal->mPipe_ReadEnd = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 1, pipeBufferSize, pipeBufferSize, 0, &saAttr);
		if (retVal->mPipe_ReadEnd == (HANDLE)INVALID_HANDLE_VALUE) { ILIBCRITICALEXIT(254); }
	} while (retVal->mPipe_ReadEnd == (HANDLE)ERROR_ACCESS_DENIED);

	if ((retVal->mOverlapped = (struct _OVERLAPPED*)malloc(sizeof(struct _OVERLAPPED))) == NULL) { ILIBCRITICALEXIT(254); }
	memset(retVal->mOverlapped, 0, sizeof(struct _OVERLAPPED));
	if ((retVal->mOverlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) { ILIBCRITICALEXIT(254); }

	retVal->mPipe_WriteEnd = CreateFileA(pipeName, GENERIC_WRITE, 0, &saAttr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (retVal->mPipe_WriteEnd == INVALID_HANDLE_VALUE) { ILIBCRITICALEXIT(254); }
#else
	if(pipe(fd)==0) 
	{
		fcntl(fd[0], F_SETFL, O_NONBLOCK); 
		fcntl(fd[1], F_SETFL, O_NONBLOCK);
		retVal->mPipe_ReadEnd = fd[0];
		retVal->mPipe_WriteEnd = fd[1];
	}
#endif
	
	return retVal;
}

void ILibProcessPipe_Process_Destroy(ILibProcessPipe_Process_Object *p)
{
	if (!ILibMemory_CanaryOK(p)) { return; }

	if (p->exiting != 0) { return; }
	if (p->stdIn != NULL) { ILibProcessPipe_FreePipe(p->stdIn); }
	if (p->stdOut != NULL) { ILibProcessPipe_FreePipe(p->stdOut); }
	if (p->stdErr != NULL) { ILibProcessPipe_FreePipe(p->stdErr); }
	if (p->metadata != NULL) { ILibMemory_Free(p->metadata); }
#ifdef WIN32
	if (p->hProcess != NULL) { CloseHandle(p->hProcess); }
#endif
	ILibMemory_Free(p);
}
#ifndef WIN32
void ILibProcessPipe_Process_BrokenPipeSink_DestroyHandler(void *object)
{
	ILibProcessPipe_Process_Destroy((ILibProcessPipe_Process_Object*)object);
}
void ILibProcessPipe_Process_BrokenPipeSink(ILibProcessPipe_Pipe sender)
{
	ILibProcessPipe_Process_Object *p = ((ILibProcessPipe_PipeObject*)sender)->mProcess;
	int status;
	if (ILibIsRunningOnChainThread(((ILibProcessPipe_PipeObject*)sender)->manager->ChainLink.ParentChain) != 0)
	{
		// This was called from the Reader
		if (p->exitHandler != NULL)
		{

			waitpid((pid_t)p->PID, &status, 0);
			p->exitHandler(p, WEXITSTATUS(status), p->userObject);
		}

		// Unwind the stack, and destroy the process object
		ILibLifeTime_Add(ILibGetBaseTimer(p->parent->ChainLink.ParentChain), p, 0, ILibProcessPipe_Process_BrokenPipeSink_DestroyHandler, NULL);
	}
}
#endif

void ILibProcessPipe_Process_SoftKill(ILibProcessPipe_Process p)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)p;
	if (!ILibMemory_CanaryOK(p)) { return; }

#ifdef WIN32
	TerminateProcess(j->hProcess, 1067);
#else
	int code;
	kill((pid_t)j->PID, SIGKILL);
	waitpid((pid_t)j->PID, &code, 0);
#endif
}

void ILibProcessPipe_Process_HardKill(ILibProcessPipe_Process p)
{
	if (!ILibMemory_CanaryOK(p)) { return; }

	ILibProcessPipe_Process_SoftKill(p);
	ILibProcessPipe_Process_Destroy(p);
}
#ifdef WIN32
ILibProcessPipe_Process ILibProcessPipe_Manager_SpawnProcessEx5(ILibProcessPipe_Manager pipeManager, char* target, char* const* parameters, ILibProcessPipe_SpawnTypes spawnType, void *sid, void *envvars, int extraMemorySize, ILibProcessPipe_ProcessPreStartHandler preStartHandler, void* preStartUser)
#else
ILibProcessPipe_Process ILibProcessPipe_Manager_SpawnProcessEx4(ILibProcessPipe_Manager pipeManager, char* target, char* const* parameters, ILibProcessPipe_SpawnTypes spawnType, void *sid, void *envvars, int extraMemorySize)
#endif
{
	ILibProcessPipe_Process_Object* retVal = NULL;
	int needSetSid = ((spawnType & ILibProcessPipe_SpawnTypes_POSIX_DETACHED) == ILibProcessPipe_SpawnTypes_POSIX_DETACHED);
	if (needSetSid != 0) { spawnType ^= ILibProcessPipe_SpawnTypes_POSIX_DETACHED; }

#ifdef WIN32
	STARTUPINFOW info = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	SECURITY_ATTRIBUTES saAttr;
	char* parms = NULL;
	char* commandLine = NULL;
	DWORD sessionId = 0;
	HANDLE token = NULL, userToken = NULL, procHandle = NULL;
	LPVOID tokenEnvironment = NULL;
	ILibProcessPipe_DestroyEnvironmentBlockFn destroyEnvironmentBlock = NULL;
	HMODULE userEnvModule = NULL;
	WCHAR* overrideEnvironment = NULL;
	WCHAR* mergedEnvironment = NULL;
	void* processEnvironment = NULL;
	DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | (needSetSid != 0 ? (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP) : 0x00);
	// BUGFIX: Prevent taskbar flash during process spawn by explicitly hiding window in STARTUPINFO.
	// CREATE_NO_WINDOW alone can allow brief window flash before taking effect.
	// Setting STARTF_USESHOWWINDOW + SW_HIDE ensures window is hidden from creation.
	int allocParms = 0;
	int allocCommandLine = 0;
	
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&info, sizeof(STARTUPINFOW));
	if (preStartHandler != NULL) { creationFlags |= CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB; }

	if (!ILibProcessPipe_IsWindowsSpawnAllowed(spawnType, target, parameters)) { return(NULL); }

	if (spawnType != ILibProcessPipe_SpawnTypes_SPECIFIED_USER && spawnType != ILibProcessPipe_SpawnTypes_DEFAULT && (sessionId = WTSGetActiveConsoleSessionId()) == 0xFFFFFFFF) { return(NULL); } // No session attached to console, but requested to execute as logged in user
	if (spawnType != ILibProcessPipe_SpawnTypes_DEFAULT && spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		if (spawnType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER) { sessionId = (DWORD)(uint64_t)sid; }
		procHandle = GetCurrentProcess();
		if (OpenProcessToken(procHandle, TOKEN_DUPLICATE | TOKEN_QUERY, &token) == 0) { ILIBMARKPOSITION(2); return(NULL); }
		if (DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT, 0, SecurityImpersonation, TokenPrimary, &userToken) == 0) { CloseHandle(token); ILIBMARKPOSITION(2); return(NULL); }
		if (SetTokenInformation(userToken, (TOKEN_INFORMATION_CLASS)TokenSessionId, &sessionId, sizeof(sessionId)) == 0) { CloseHandle(token); CloseHandle(userToken); ILIBMARKPOSITION(2); return(NULL); }
		info.lpDesktop = (spawnType == ILibProcessPipe_SpawnTypes_WINLOGON) ? L"Winsta0\\Winlogon" : L"winsta0\\default";
		if (ILibProcessPipe_TryCreateEnvironmentBlock(userToken, &tokenEnvironment, &destroyEnvironmentBlock, &userEnvModule) != 0)
		{
			processEnvironment = tokenEnvironment;
		}
	}
	if (parameters != NULL && parameters[0] != NULL)
	{
		int i = 0;
		size_t sz = 1;
		size_t offset = 0;

		while (parameters[i] != NULL)
		{
			sz += (strnlen_s(parameters[i], 32768) * 2) + 8;
			++i;
		}
		parms = (char*)malloc(sz);
		if (parms == NULL)
		{
			SetLastError(ERROR_OUTOFMEMORY);
			return(NULL);
		}
		parms[0] = 0;
		i = 0;
		allocParms = 1;

		while (parameters[i] != NULL)
		{
			if (!ILibProcessPipe_AppendWindowsCommandLineArgumentA(target, parameters, i, parms, sz, &offset))
			{
				free(parms);
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return(NULL);
			}
			++i;
		}
	}

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
#else
	pid_t pid;
#endif

	retVal = (ILibProcessPipe_Process_Object*)ILibMemory_SmartAllocate(sizeof(ILibProcessPipe_Process_Object));
	if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		retVal->stdErr = ILibProcessPipe_CreatePipe(pipeManager, 4096, NULL, extraMemorySize);
		retVal->stdErr->mProcess = retVal;
	}
	retVal->parent = (ILibProcessPipe_Manager_Object*)pipeManager;
	retVal->chain = retVal->parent->ChainLink.ParentChain;
#ifdef WIN32
	WCHAR tmp1[4096];
	WCHAR tmp2[4096];

	info.cb = sizeof(STARTUPINFOW);
	// BUGFIX: Explicitly hide window to prevent taskbar flash
	info.dwFlags |= STARTF_USESHOWWINDOW;
	info.wShowWindow = SW_HIDE;

	if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		retVal->stdIn = ILibProcessPipe_CreatePipe(pipeManager, 4096, NULL, extraMemorySize);
		retVal->stdIn->mProcess = retVal;
		retVal->stdOut = ILibProcessPipe_CreatePipe(pipeManager, 4096, NULL, extraMemorySize);
		retVal->stdOut->mProcess = retVal;

		ILibProcessPipe_PipeObject_DisableInherit(&(retVal->stdIn->mPipe_WriteEnd));
		ILibProcessPipe_PipeObject_DisableInherit(&(retVal->stdOut->mPipe_ReadEnd));
		ILibProcessPipe_PipeObject_DisableInherit(&(retVal->stdErr->mPipe_ReadEnd));

		info.hStdError = retVal->stdErr->mPipe_WriteEnd;
		info.hStdInput = retVal->stdIn->mPipe_ReadEnd;
		info.hStdOutput = retVal->stdOut->mPipe_WriteEnd;
		info.dwFlags |= STARTF_USESTDHANDLES;
	}

	if (envvars != NULL)
	{
		overrideEnvironment = ILibProcessPipe_ConvertEnvPairsToWideBlock(envvars);
		if (processEnvironment != NULL && overrideEnvironment != NULL)
		{
			mergedEnvironment = ILibProcessPipe_MergeWideEnvBlocks((WCHAR*)processEnvironment, overrideEnvironment);
			if (mergedEnvironment != NULL)
			{
				processEnvironment = mergedEnvironment;
			}
		}
		else if (overrideEnvironment != NULL)
		{
			processEnvironment = overrideEnvironment;
		}
	}

	if (target != NULL && target[0] != 0)
	{
		size_t targetLen = strnlen_s(target, 32768);
		size_t parmsLen = (parms != NULL) ? strnlen_s(parms, 32768) : 0;
		size_t commandLineLen = targetLen + parmsLen + 4;

		commandLine = (char*)malloc(commandLineLen);
		if (commandLine == NULL)
		{
			if (allocParms != 0) { free(parms); }
			if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
			{
				ILibProcessPipe_FreePipe(retVal->stdErr);
				ILibProcessPipe_FreePipe(retVal->stdOut);
				ILibProcessPipe_FreePipe(retVal->stdIn);
			}
			ILibMemory_Free(retVal);
			if (token != NULL) { CloseHandle(token); }
			if (userToken != NULL) { CloseHandle(userToken); }
			if (mergedEnvironment != NULL) { ILibMemory_Free(mergedEnvironment); }
			if (overrideEnvironment != NULL) { ILibMemory_Free(overrideEnvironment); }
			if (tokenEnvironment != NULL && destroyEnvironmentBlock != NULL) { destroyEnvironmentBlock(tokenEnvironment); }
			if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
			return(NULL);
		}
		allocCommandLine = 1;
		if (parmsLen > 0)
		{
			sprintf_s(commandLine, commandLineLen, "\"%s\" %s", target, parms);
		}
		else
		{
			sprintf_s(commandLine, commandLineLen, "\"%s\"", target);
		}
	}


	// Build WIDE command line directly via MultiByteToWideChar to avoid any
	// intermediate helper issues. The command line MUST be proper UTF-16;
	// ANSI bytes interpreted as UTF-16 pairs garble
	// pipe names and break the named-pipe KVM bridge.
	{
		char* cmdLineSrc = (commandLine != NULL) ? commandLine : target;
		int wTargetLen = MultiByteToWideChar(CP_UTF8, 0, target, -1, tmp1, (int)(sizeof(tmp1) / sizeof(WCHAR)));
		int wCmdLen = MultiByteToWideChar(CP_UTF8, 0, cmdLineSrc, -1, tmp2, (int)(sizeof(tmp2) / sizeof(WCHAR)));
		BOOL createOk = FALSE;

		if (spawnType == ILibProcessPipe_SpawnTypes_DEFAULT || spawnType == ILibProcessPipe_SpawnTypes_DETACHED)
		{
			createOk = CreateProcessW(tmp1, tmp2, NULL, NULL, spawnType == ILibProcessPipe_SpawnTypes_DETACHED ? FALSE : TRUE, creationFlags, processEnvironment, NULL, &info, &processInfo);
		}
		else
		{
			createOk = CreateProcessAsUserW(userToken, tmp1, tmp2, NULL, NULL, TRUE, creationFlags, processEnvironment, NULL, &info, &processInfo);
		}
		if (!createOk)
		{
			int ll = GetLastError();
			if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
			{
				ILibProcessPipe_FreePipe(retVal->stdErr);
				ILibProcessPipe_FreePipe(retVal->stdOut);
				ILibProcessPipe_FreePipe(retVal->stdIn);
			}
			if (allocParms != 0) { free(parms); }
			if (allocCommandLine != 0) { free(commandLine); }
			ILibMemory_Free(retVal);
			if (token != NULL) { CloseHandle(token); }
			if (userToken != NULL) { CloseHandle(userToken); }
			if (mergedEnvironment != NULL) { ILibMemory_Free(mergedEnvironment); }
			if (overrideEnvironment != NULL) { ILibMemory_Free(overrideEnvironment); }
			if (tokenEnvironment != NULL && destroyEnvironmentBlock != NULL) { destroyEnvironmentBlock(tokenEnvironment); }
			if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
			SetLastError(ll);
			return(NULL);
		}
		if (preStartHandler != NULL)
		{
			DWORD preStartError = ERROR_SUCCESS;
			if (!preStartHandler(processInfo.hProcess, processInfo.hThread, processInfo.dwProcessId, preStartUser, &preStartError))
			{
				int ll = (int)(preStartError != ERROR_SUCCESS ? preStartError : GetLastError());
				if (ll == ERROR_SUCCESS) { ll = ERROR_ACCESS_DENIED; }
				TerminateProcess(processInfo.hProcess, 1067);
				WaitForSingleObject(processInfo.hProcess, 2000);
				if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
				if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
				if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
				{
					ILibProcessPipe_FreePipe(retVal->stdErr);
					ILibProcessPipe_FreePipe(retVal->stdOut);
					ILibProcessPipe_FreePipe(retVal->stdIn);
				}
				if (allocParms != 0) { free(parms); }
				if (allocCommandLine != 0) { free(commandLine); }
				ILibMemory_Free(retVal);
				if (token != NULL) { CloseHandle(token); }
				if (userToken != NULL) { CloseHandle(userToken); }
				if (mergedEnvironment != NULL) { ILibMemory_Free(mergedEnvironment); }
				if (overrideEnvironment != NULL) { ILibMemory_Free(overrideEnvironment); }
				if (tokenEnvironment != NULL && destroyEnvironmentBlock != NULL) { destroyEnvironmentBlock(tokenEnvironment); }
				if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
				SetLastError(ll);
				return(NULL);
			}
			if (ResumeThread(processInfo.hThread) == (DWORD)-1)
			{
				int ll = GetLastError();
				if (ll == ERROR_SUCCESS) { ll = ERROR_GEN_FAILURE; }
				TerminateProcess(processInfo.hProcess, 1067);
				WaitForSingleObject(processInfo.hProcess, 2000);
				if (processInfo.hThread != NULL) { CloseHandle(processInfo.hThread); }
				if (processInfo.hProcess != NULL) { CloseHandle(processInfo.hProcess); }
				if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
				{
					ILibProcessPipe_FreePipe(retVal->stdErr);
					ILibProcessPipe_FreePipe(retVal->stdOut);
					ILibProcessPipe_FreePipe(retVal->stdIn);
				}
				if (allocParms != 0) { free(parms); }
				if (allocCommandLine != 0) { free(commandLine); }
				ILibMemory_Free(retVal);
				if (token != NULL) { CloseHandle(token); }
				if (userToken != NULL) { CloseHandle(userToken); }
				if (mergedEnvironment != NULL) { ILibMemory_Free(mergedEnvironment); }
				if (overrideEnvironment != NULL) { ILibMemory_Free(overrideEnvironment); }
				if (tokenEnvironment != NULL && destroyEnvironmentBlock != NULL) { destroyEnvironmentBlock(tokenEnvironment); }
				if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
				SetLastError(ll);
				return(NULL);
			}
		}
	}

	if (mergedEnvironment != NULL) { ILibMemory_Free(mergedEnvironment); }
	if (overrideEnvironment != NULL) { ILibMemory_Free(overrideEnvironment); }
	if (tokenEnvironment != NULL && destroyEnvironmentBlock != NULL) { destroyEnvironmentBlock(tokenEnvironment); }
	if (userEnvModule != NULL) { FreeLibrary(userEnvModule); }
	if (allocParms != 0) { free(parms); }
	if (allocCommandLine != 0) { free(commandLine); }
	if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		CloseHandle(retVal->stdOut->mPipe_WriteEnd);	retVal->stdOut->mPipe_WriteEnd = NULL;
		CloseHandle(retVal->stdErr->mPipe_WriteEnd);	retVal->stdErr->mPipe_WriteEnd = NULL;
		CloseHandle(retVal->stdIn->mPipe_ReadEnd);		retVal->stdIn->mPipe_ReadEnd = NULL;
	}
	retVal->hProcess = processInfo.hProcess;
	if (processInfo.hThread != NULL) CloseHandle(processInfo.hThread);
	retVal->PID = processInfo.dwProcessId;
	
	if (token != NULL) { CloseHandle(token); token = NULL; }
	if (userToken != NULL) { CloseHandle(userToken); userToken = NULL; }
#else
	int UID = (int)(uint64_t)(ILibPtrCAST)sid;
	sigset_t sset;
	sigset_t *set = NULL;
	char **vars = NULL;
	if (envvars != NULL)
	{
		int i, z, vlen = 0;
		for (i = 0; ((char**)envvars)[i] != NULL; i += 2)
		{
			vlen += (strnlen_s(((char**)envvars)[i], sizeof(ILibScratchPad2)) + 2 + strnlen_s(((char**)envvars)[i + 1], sizeof(ILibScratchPad2)));
		}
		vars = (char**)ILibMemory_SmartAllocateEx(((i / 2) + 1) * sizeof(char*), vlen + sizeof(int));
		((int*)ILibMemory_Extra(vars))[0] = sizeof(int);
		for (i = 0; ((char**)envvars)[i] != NULL; i += 2)
		{
			z = ((int*)ILibMemory_Extra(vars))[0];
			vars[i / 2] = (char*)ILibMemory_Extra(vars) + z;
			z += sprintf_s((char*)ILibMemory_Extra(vars) + z, ILibMemory_ExtraSize(vars) - z, "%s=%s", ((char**)envvars)[i], ((char**)envvars)[i + 1]);
			++z;
			((int*)ILibMemory_Extra(vars))[0] = z;
		}
	}

	if (spawnType == ILibProcessPipe_SpawnTypes_TERM)
	{
		int pipe;
		struct winsize w;
		struct termios tios;
		char **options = (char**)envvars;
		int flags = 0;
		memset(&tios, 0, sizeof(tios));

		w.ws_row = CONSOLE_SCREEN_HEIGHT;
		w.ws_col = CONSOLE_SCREEN_WIDTH;
		w.ws_xpixel = 0;
		w.ws_ypixel = 0;


		while (options != NULL && options[0] != NULL)
		{
			if (strcasecmp("LINES", options[0]) == 0)
			{
				w.ws_row = ILib_atoi2_uint16(options[1], 0);
			}
			else if (strcasecmp("COLUMNS", options[0]) == 0)
			{
				w.ws_col = ILib_atoi2_uint16(options[1], 0);
			}	
			else if (strcasecmp("c_iflag", options[0]) == 0)
			{
				flags = 1;
				tios.c_iflag = (tcflag_t)ILib_atoi2_uint32(options[1], 0);
			}
			else if (strcasecmp("c_oflag", options[0]) == 0)
			{
				flags = 1;
				tios.c_oflag = (tcflag_t)ILib_atoi2_uint32(options[1], 0);
			}
			else if (strcasecmp("c_cflag", options[0]) == 0)
			{
				flags = 1;
				tios.c_cflag = (tcflag_t)ILib_atoi2_uint32(options[1], 0);
			}
			else if (strcasecmp("c_lflag", options[0]) == 0)
			{
				flags = 1;
				tios.c_lflag = (tcflag_t)ILib_atoi2_uint32(options[1], 0);
			}

			options += 2;
		}



		pid = forkpty(&pipe, NULL, flags == 0 ? NULL : &tios, &w);
		if (pid > 0)
		{
			retVal->PTY = pipe;
			retVal->stdIn = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(pipeManager, pipe, extraMemorySize);
			retVal->stdOut = ILibProcessPipe_Pipe_CreateFromExistingWithExtraMemory(pipeManager, pipe, extraMemorySize);

			retVal->stdIn->mProcess = retVal;
			ILibProcessPipe_Pipe_SetBrokenPipeHandler(retVal->stdOut, ILibProcessPipe_Process_BrokenPipeSink);
			retVal->stdOut->mProcess = retVal;
		}
	}
	else
	{
		if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
		{
			retVal->stdIn = ILibProcessPipe_CreatePipe(pipeManager, 4096, NULL, extraMemorySize);
			retVal->stdIn->mProcess = retVal;
			retVal->stdOut = ILibProcessPipe_CreatePipe(pipeManager, 4096, (ILibProcessPipe_GenericBrokenPipeHandler)ILibProcessPipe_Process_BrokenPipeSink, extraMemorySize);
			retVal->stdOut->mProcess = retVal;
		}
#ifdef __APPLE__
		if (needSetSid == 0)
		{
			set = &sset;
			ILibVForkPrepareSignals_Parent_Init(set);
			pid = vfork();
		}
		else
		{
			pid = fork();
		}
#else
		set = &sset;
		ILibVForkPrepareSignals_Parent_Init(set);
		pid = vfork();
#endif
	}
	if (pid < 0)
	{
		if (set != NULL) { ILibVForkPrepareSignals_Parent_Finished(set); }
		if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
		{
			ILibProcessPipe_FreePipe(retVal->stdErr);
			ILibProcessPipe_FreePipe(retVal->stdOut);
			ILibProcessPipe_FreePipe(retVal->stdIn);
		}
		ILibMemory_Free(vars);
		ILibMemory_Free(retVal);
		return(NULL);
	}
	if (pid == 0)
	{
		if (set != NULL)
		{
			ILibVForkPrepareSignals_Child();
		}
		if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED && spawnType != ILibProcessPipe_SpawnTypes_TERM)
		{
			close(retVal->stdErr->mPipe_ReadEnd); //close read end of stderr pipe
			dup2(retVal->stdErr->mPipe_WriteEnd, STDERR_FILENO);
			close(retVal->stdErr->mPipe_WriteEnd);
		}
		if (spawnType == ILibProcessPipe_SpawnTypes_TERM)
		{
			putenv("TERM=xterm-256color");
			close(retVal->stdErr->mPipe_ReadEnd); //close read end of stderr pipe
		}
		else
		{
			if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
			{
				close(retVal->stdIn->mPipe_WriteEnd); //close write end of stdin pipe
				close(retVal->stdOut->mPipe_ReadEnd); //close read end of stdout pipe

				dup2(retVal->stdIn->mPipe_ReadEnd, STDIN_FILENO);
				dup2(retVal->stdOut->mPipe_WriteEnd, STDOUT_FILENO);

				close(retVal->stdIn->mPipe_ReadEnd);
				close(retVal->stdOut->mPipe_WriteEnd);

				int f = fcntl(STDIN_FILENO, F_GETFL);
				f &= ~O_NONBLOCK;
				fcntl(STDIN_FILENO, F_SETFL, f);

				f = fcntl(STDOUT_FILENO, F_GETFL);
				f &= ~O_NONBLOCK;
				fcntl(STDOUT_FILENO, F_SETFL, f);
			}
		}
		if (UID != -1 && UID != 0)
		{
			ignore_result(setuid((uid_t)UID));
		}
		if (needSetSid != 0)
		{
			ignore_result(setsid());
		}

		if (vars != NULL)
		{
			execve(target, parameters, vars);
		}
		else
		{
			execv(target, parameters);
		}
		_exit(1);
	}
	if (set != NULL) { ILibVForkPrepareSignals_Parent_Finished(set); }
	if (spawnType != ILibProcessPipe_SpawnTypes_TERM && spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		close(retVal->stdIn->mPipe_ReadEnd); retVal->stdIn->mPipe_ReadEnd = -1;
		close(retVal->stdOut->mPipe_WriteEnd); retVal->stdOut->mPipe_WriteEnd = -1;
	}
	if (spawnType != ILibProcessPipe_SpawnTypes_DETACHED)
	{
		close(retVal->stdErr->mPipe_WriteEnd); retVal->stdErr->mPipe_WriteEnd = -1;
	}
	retVal->PID = pid;
	ILibMemory_Free(vars);
#endif
	return retVal;
}
#ifdef WIN32
ILibProcessPipe_Process ILibProcessPipe_Manager_SpawnProcessEx4(ILibProcessPipe_Manager pipeManager, char* target, char* const* parameters, ILibProcessPipe_SpawnTypes spawnType, void *sid, void *envvars, int extraMemorySize)
{
	return ILibProcessPipe_Manager_SpawnProcessEx5(pipeManager, target, parameters, spawnType, sid, envvars, extraMemorySize, NULL, NULL);
}
#endif
int ILibProcessPipe_Process_IsDetached(ILibProcessPipe_Process p)
{
	return(((ILibProcessPipe_Process_Object*)p)->stdErr == NULL && ((ILibProcessPipe_Process_Object*)p)->stdIn == NULL && ((ILibProcessPipe_Process_Object*)p)->stdOut == NULL);
}

#ifdef WIN32
BOOL ILibProcessPipe_Process_ReadHandler(void *chain, HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user)
#else
void ILibProcessPipe_Process_ReadHandler(void* user)
#endif
{
#ifdef WIN32
	if (errors != ILibWaitHandle_ErrorStatus_NONE) { return(FALSE); }
#endif
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)user;
	size_t consumed;
	int err=0;
	
#ifdef WIN32
	int firstPass = 1;
	DWORD bytesRead = 0;
	UNREFERENCED_PARAMETER(event);
#else
	int bytesRead = 0;
#endif
	pipeObject->processingLoop = 1;
	do
	{
#ifdef WIN32
		err = 0;
		if (firstPass != 0)
		{
			firstPass = 0;
			if (pipeObject->inProgress != 0)
			{
				if (GetOverlappedResult(pipeObject->mPipe_ReadEnd, pipeObject->mOverlapped, &bytesRead, FALSE) == 0 || bytesRead == 0)
				{
					pipeObject->inProgress = 0;
					err = GetLastError();
					if (err == ERROR_IO_PENDING) { return(TRUE); }
					break;
				}
				pipeObject->inProgress = 0;
			}
		}
#else
		bytesRead = (int)read(pipeObject->mPipe_ReadEnd, pipeObject->buffer + pipeObject->readOffset + pipeObject->totalRead, pipeObject->bufferSize - pipeObject->totalRead);
		if (bytesRead <= 0)
		{
			break;
		}

#endif
#ifdef WIN32
		if (!ILibProcessPipe_ReadWindowCanAppend(pipeObject, bytesRead)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadHandler.Append"); }
#endif
		pipeObject->totalRead += bytesRead;
		ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: %u bytes read on Pipe: %p", bytesRead, (void*)pipeObject);

		if (pipeObject->handler == NULL)
		{
			//
			// Since the user doesn't care about the data, we'll just empty the buffer
			//
			pipeObject->readOffset = 0;
			pipeObject->totalRead = 0;
			continue;
		}

		while (pipeObject->PAUSED == 0)
		{
			consumed = 0;
			ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_5, "ProcessPipe: buffer/%p offset/%d totalRead/%d", (void*)pipeObject->buffer, pipeObject->readOffset, pipeObject->totalRead);
#ifdef WIN32
			if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadHandler.BeforeHandler"); }
#endif
			((ILibProcessPipe_GenericReadHandler)pipeObject->handler)(pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead, &consumed, pipeObject->user1, pipeObject->user2);
#ifdef WIN32
			if (consumed > pipeObject->totalRead) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadHandler.Consumed"); }
#endif
			if (consumed == 0)
			{
				//
				// None of the buffer was consumed
				//
				ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: No bytes consumed on Pipe: %p", (void*)pipeObject);

				//
				// We need to move the memory to the start of the buffer, or else we risk running past the end, if we keep reading like this
				//
#ifdef WIN32
				if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadHandler.Compact"); }
#endif
				memmove_s(pipeObject->buffer, pipeObject->bufferSize, pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead);
				pipeObject->readOffset = 0;

				break; // Break out of inner while loop
			}
			else if (consumed == pipeObject->totalRead)
			{
				//
				// Entire Buffer was consumed
				//
				pipeObject->readOffset = 0;
				pipeObject->totalRead = 0;

				ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: ReadBuffer drained on Pipe: %p", (void*)pipeObject);
				break; // Break out of inner while loop
			}
			else
			{
				//
				// Only part of the buffer was consumed
				//
				pipeObject->readOffset += consumed;
				pipeObject->totalRead -= consumed;
			}
		}

		if (pipeObject->bufferSize - pipeObject->totalRead == 0)
		{
			pipeObject->buffer = (char*)realloc(pipeObject->buffer, pipeObject->bufferSize * 2);
			if (pipeObject->buffer == NULL) { ILIBCRITICALEXIT(254); }
			pipeObject->bufferSize = pipeObject->bufferSize * 2;
		}
#ifdef WIN32
		if (pipeObject->PAUSED == 0)
		{
			pipeObject->inProgress = 1;
			if (ReadFile(pipeObject->mPipe_ReadEnd, pipeObject->buffer + pipeObject->readOffset + pipeObject->totalRead, (DWORD)(pipeObject->bufferSize - pipeObject->totalRead), &bytesRead, pipeObject->mOverlapped) != TRUE)
			{
				if (GetLastError() == ERROR_IO_PENDING) { return(TRUE); }
				break;
			}
		}
#endif
	}
#ifdef WIN32
	while (pipeObject->PAUSED == 0); // Note: This is actually the end of a do-while loop
	if(bytesRead == 0 || (err != ERROR_IO_PENDING && err != 0 && pipeObject->PAUSED == 0))
#else
	while(pipeObject->PAUSED == 0); // Note: This is actually the end of a do-while loop
	err = 0;
	if (bytesRead == 0 || ((err = errno) != EAGAIN && errno != EWOULDBLOCK && pipeObject->PAUSED == 0))
#endif
	{
		//printf("Broken Pipe(%p)? (err: %d, PAUSED: %d, totalRead: %d\n", pipeObject->mPipe_ReadEnd, err, pipeObject->PAUSED, pipeObject->totalRead);
		//
		// Broken Pipe
		//
		ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[ReadHandler]: BrokenPipe(%d) on Pipe: %p", err, (void*)pipeObject);
#ifndef WIN32
		void *pipenode = ILibLinkedList_GetNode_Search(pipeObject->manager->ActivePipes, NULL, pipeObject);
		if (pipenode != NULL)
		{
			// Flag this node for removal
			((int*)ILibLinkedList_GetExtendedMemory(pipenode))[0] = 1;
		}
#endif
		if (pipeObject->brokenPipeHandler != NULL) 
		{
			((ILibProcessPipe_GenericBrokenPipeHandler)pipeObject->brokenPipeHandler)(pipeObject); 
		}
#ifdef WIN32
		return(FALSE);
#else
		return;
#endif
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: Pipe: %p [EMPTY]", (void*)pipeObject);
	}
	pipeObject->processingLoop = 0;
	ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[ReadHandler]: Pipe: %p [EMPTY]", (void*)pipeObject);

#ifdef WIN32
	return(TRUE);
#else
	return;
#endif
}
#ifdef WIN32
BOOL ILibProcessPipe_Process_WindowsWriteHandler(void *chain, HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)user;
	OVERLAPPED* writeOverlapped = ILibProcessPipe_GetWriteOverlapped(pipeObject);
	BOOL result;
	BOOL keepWaitHandle = TRUE;
	DWORD bytesWritten;
	ILibProcessPipe_WriteData* data;
	
	UNREFERENCED_PARAMETER(event);
	if (errors != ILibWaitHandle_ErrorStatus_NONE || pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return(FALSE); }
	InterlockedExchange(&pipeObject->activeWriteHandler, 1);
	if (writeOverlapped == NULL) { keepWaitHandle = FALSE; goto done; }
	if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0)
	{
		ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent);
		keepWaitHandle = FALSE;
		goto done;
	}
	result = GetOverlappedResult(pipeObject->mPipe_WriteEnd, writeOverlapped, &bytesWritten, FALSE);
	if (result == FALSE)
	{ 
		// Broken Pipe
		ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent);
		ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[WriteHandler]: BrokenPipe(%d) on Pipe: %p", GetLastError(), (void*)pipeObject);
		if (pipeObject->brokenPipeHandler != NULL) { ((ILibProcessPipe_GenericBrokenPipeHandler)pipeObject->brokenPipeHandler)(pipeObject); }
		ILibProcessPipe_FreePipe(pipeObject);
		keepWaitHandle = FALSE;
		goto done;
	}

	ILibQueue_Lock(pipeObject->WriteBuffer);
	while ((data = (ILibProcessPipe_WriteData*)ILibQueue_DeQueue(pipeObject->WriteBuffer)) != NULL)
	{
		ILibProcessPipe_WriteData_Destroy(data);
		data = (ILibProcessPipe_WriteData*)ILibQueue_PeekQueue(pipeObject->WriteBuffer);
		if (data != NULL)
		{
			result = WriteFile(pipeObject->mPipe_WriteEnd, data->buffer, data->bufferLen, NULL, writeOverlapped);
			if (result == TRUE) { continue; }
			if (GetLastError() != ERROR_IO_PENDING)
			{
				// Broken Pipe
				ILibQueue_UnLock(pipeObject->WriteBuffer);
				ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[WriteHandler]: BrokenPipe(%d) on Pipe: %p", GetLastError(), (void*)pipeObject);
				ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent);
				if (pipeObject->brokenPipeHandler != NULL) { ((ILibProcessPipe_GenericBrokenPipeHandler)pipeObject->brokenPipeHandler)(pipeObject); }
				ILibProcessPipe_FreePipe(pipeObject);
				keepWaitHandle = FALSE;
				goto done;
			}
			break;
		}
	}
	if (ILibQueue_IsEmpty(pipeObject->WriteBuffer) != 0)
	{
		ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent);
		ILibQueue_UnLock(pipeObject->WriteBuffer);
		if (pipeObject->handler != NULL) ((ILibProcessPipe_GenericSendOKHandler)pipeObject->handler)(pipeObject->user1, pipeObject->user2);
		keepWaitHandle = FALSE;
	}
	else
	{
		ILibQueue_UnLock(pipeObject->WriteBuffer);
	}
done:
	InterlockedExchange(&pipeObject->activeWriteHandler, 0);
	if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0 &&
		ILibProcessPipe_GetStateLong(&pipeObject->activeReadCallbacks) == 0 &&
		ILibProcessPipe_GetStateLong(&pipeObject->resumePending) == 0)
	{
		ILibProcessPipe_FreePipe_TryFinalizeOnChain(chain, pipeObject);
	}
	return(keepWaitHandle);
}
#endif
void ILibProcessPipe_Process_SetWriteHandler(ILibProcessPipe_PipeObject *pipeObject, ILibProcessPipe_GenericSendOKHandler handler, void* user1, void* user2)
{
	pipeObject->handler = (void*)handler;
	pipeObject->user1 = user1;
	pipeObject->user2 = user2;
}

void ILibProcessPipe_Process_StartPipeReaderWriterEx(void *object)
{
	ILibProcessPipe_PipeObject* pipeObject = (ILibProcessPipe_PipeObject*)object;
	ILibLinkedList_AddTail(pipeObject->manager->ActivePipes, pipeObject);
}

void ILibProcessPipe_Pipe_Pause(ILibProcessPipe_Pipe pipeObject)
{
	ILibProcessPipe_PipeObject *p = (ILibProcessPipe_PipeObject*)pipeObject;
	p->PAUSED = 1;

#ifdef WIN32
	if (p->mOverlapped == NULL)
	{
		// Overlapped isn't supported, so using a separate reader thread
		ResetEvent(p->mPipe_Reader_ResumeEvent);
	}
	else
	{
		ILibRemoteLogging_printf(ILibChainGetLogger(p->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "ProcessPipe.Pause(): Opaque = %p",(void*)p->mOverlapped_opaqueData);
		//ILibChain_RemoveWaitHandle(p->manager->ChainLink.ParentChain, p->mOverlapped->hEvent);
	}
#else
	ILibLinkedList_Remove(ILibLinkedList_GetNode_Search(p->manager->ActivePipes, NULL, pipeObject));
#endif
}


void ILibProcessPipe_Pipe_ResumeEx_ContinueProcessing(ILibProcessPipe_PipeObject *p)
{
	size_t consumed;
	p->PAUSED = 0;
	p->processingLoop = 1;
	while (p->PAUSED == 0 && p->totalRead > 0)
	{
		consumed = 0;
#ifdef WIN32
		if (!ILibProcessPipe_ReadWindowIsValid(p)) { ILibProcessPipe_FailInvalidReadWindow(p, "ResumeEx.BeforeHandler"); return; }
#endif
		((ILibProcessPipe_GenericReadHandler)p->handler)(p->buffer + p->readOffset, p->totalRead, &consumed, p->user1, p->user2);
#ifdef WIN32
		if (consumed > p->totalRead) { ILibProcessPipe_FailInvalidReadWindow(p, "ResumeEx.Consumed"); return; }
#endif
		if (consumed == 0)
		{
			//
			// None of the buffer was consumed
			//
			ILibRemoteLogging_printf(ILibChainGetLogger(p->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: No bytes consumed on Pipe: %p", (void*)p);

			//
			// We need to move the memory to the start of the buffer, or else we risk running past the end, if we keep reading like this
			//
#ifdef WIN32
			if (!ILibProcessPipe_ReadWindowIsValid(p)) { ILibProcessPipe_FailInvalidReadWindow(p, "ResumeEx.Compact"); return; }
#endif
			memmove_s(p->buffer, p->bufferSize, p->buffer + p->readOffset, p->totalRead);
			p->readOffset = 0;
			break;
		}
		else if (consumed == p->totalRead)
		{
			//
			// Entire Buffer was consumed
			//
			p->readOffset = 0;
			p->totalRead = 0;

			ILibRemoteLogging_printf(ILibChainGetLogger(p->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_5, "ILibProcessPipe[ReadHandler]: ReadBuffer drained on Pipe: %p", (void*)p);
			break; // Break out of inner while loop
		}
		else
		{
			//
			// Only part of the buffer was consumed
			//
			p->readOffset += consumed;
			p->totalRead -= consumed;
		}
	}
	p->processingLoop = 0;
}

void ILibProcessPipe_Pipe_ResumeEx(ILibProcessPipe_PipeObject* p)
{
	if (!ILibMemory_CanaryOK(p)) { return; }
	ILibRemoteLogging_printf(ILibChainGetLogger(p->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Generic, ILibRemoteLogging_Flags_VerbosityLevel_1, "ProcessPipe.ResumeEx(): processingLoop = %d", p->processingLoop);

#ifdef WIN32
	ILibChain_AddWaitHandle(p->manager->ChainLink.ParentChain, p->mOverlapped->hEvent, -1, ILibProcessPipe_Process_ReadHandler, p);
	p->PAUSED = 0;
#else
	ILibProcessPipe_Pipe_ResumeEx_ContinueProcessing(p);
	if (p->PAUSED == 0)
	{
		ILibLifeTime_Add(ILibGetBaseTimer(p->manager->ChainLink.ParentChain), p, 0, &ILibProcessPipe_Process_StartPipeReaderWriterEx, NULL); // Need to context switch to Chain Thread
	}
#endif
}

#ifdef WIN32
BOOL ILibProcessPipe_Process_Pipe_ReadExHandler(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user);
static BOOL ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user);
static void ILibProcessPipe_Pipe_Resume_Continue(ILibProcessPipe_PipeObject *p)
{
	if (p == NULL || !ILibMemory_CanaryOK(p) || p->manager == NULL) { return; }
	if (ILibProcessPipe_GetStateLong(&p->closeRequested) != 0 || p->PAUSED != 0) { return; }

	ILibProcessPipe_Process_Pipe_ReadExHandler(p->manager->ChainLink.ParentChain, p->mPipe_ReadEnd, ILibWaitHandle_ErrorStatus_NONE, NULL, 0, p);
	if (p->mProcess != NULL && p->mProcess->hProcess_needAdd != 0 && p->mProcess->disabled == 0)
	{
		p->mProcess->hProcess_needAdd = 0;
		ILibChain_AddWaitHandle(p->manager->ChainLink.ParentChain, p->mProcess->hProcess, -1, ILibProcessPipe_Process_OnExit, p->mProcess);
	}
}
static void ILibProcessPipe_Pipe_Resume_OnChain(void *chain, void *user)
{
	ILibProcessPipe_PipeObject *p = (ILibProcessPipe_PipeObject*)user;

	UNREFERENCED_PARAMETER(chain);
	if (p == NULL || !ILibMemory_CanaryOK(p)) { return; }

	InterlockedExchange(&p->resumePending, 0);
	if (ILibProcessPipe_GetStateLong(&p->closeRequested) != 0)
	{
		if (ILibProcessPipe_GetStateLong(&p->activeReadCallbacks) == 0 && ILibProcessPipe_GetStateLong(&p->activeWriteHandler) == 0)
		{
			ILibProcessPipe_FreePipe_TryFinalizeOnChain(p->manager != NULL ? p->manager->ChainLink.ParentChain : NULL, p);
		}
		return;
	}
	ILibProcessPipe_Pipe_Resume_Continue(p);
}
static BOOL ILibProcessPipe_Process_ScheduleRead(ILibProcessPipe_PipeObject *pipeObject)
{
	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject) || pipeObject->manager == NULL || pipeObject->mOverlapped == NULL) { return FALSE; }
	if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0) { return FALSE; }
	if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ScheduleRead"); }

	InterlockedIncrement(&pipeObject->activeReadCallbacks);
	ILibChain_ReadEx2(
		pipeObject->manager->ChainLink.ParentChain,
		pipeObject->mPipe_ReadEnd,
		pipeObject->mOverlapped,
		pipeObject->buffer + pipeObject->readOffset + pipeObject->totalRead,
		(DWORD)(pipeObject->bufferSize - pipeObject->totalRead),
		ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch,
		pipeObject,
		pipeObject->metadata);
	return TRUE;
}
static BOOL ILibProcessPipe_Process_Pipe_ReadExHandler_Dispatch(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)user;
	BOOL ret = FALSE;

	if (pipeObject != NULL && ILibMemory_CanaryOK(pipeObject))
	{
		if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) == 0)
		{
			ret = ILibProcessPipe_Process_Pipe_ReadExHandler(chain, h, status, buffer, bytesRead, user);
		}
		if (InterlockedDecrement(&pipeObject->activeReadCallbacks) == 0 &&
			ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0 &&
			ILibProcessPipe_GetStateLong(&pipeObject->activeWriteHandler) == 0 &&
			ILibProcessPipe_GetStateLong(&pipeObject->resumePending) == 0)
		{
			ILibProcessPipe_FreePipe_TryFinalizeOnChain(chain, pipeObject);
		}
	}
	return ret;
}
#endif
void ILibProcessPipe_Pipe_Resume(ILibProcessPipe_Pipe pipeObject)
{
	ILibProcessPipe_PipeObject *p = (ILibProcessPipe_PipeObject*)pipeObject;
	if (!ILibMemory_CanaryOK(p)) { return; }
#ifdef WIN32
	if (p->mOverlapped == NULL)
	{
		SetEvent(p->mPipe_Reader_ResumeEvent);
	}
	else
	{
		void *chain = (p->manager != NULL) ? p->manager->ChainLink.ParentChain : NULL;
		p->PAUSED = 0;
		if (ILibProcessPipe_GetStateLong(&p->closeRequested) != 0) { return; }

		// Overlapped Resume() must run on the owning chain thread. Calling the read state machine
		// directly from an arbitrary control thread races readOffset/totalRead bookkeeping, and
		// calling it from inside an active read callback re-enters the parser recursively. Defer
		// both cases onto the chain thread so buffered data is resumed from one authoritative owner.
		if (chain != NULL &&
			(ILibProcessPipe_GetStateLong(&p->activeReadCallbacks) != 0 || ILibIsRunningOnChainThread(chain) == 0))
		{
			if (InterlockedCompareExchange(&p->resumePending, 1, 0) == 0)
			{
				ILibChain_RunOnMicrostackThreadEx3(chain, ILibProcessPipe_Pipe_Resume_OnChain, ILibProcessPipe_Pipe_Resume_OnChain, p);
			}
			return;
		}
		ILibProcessPipe_Pipe_Resume_Continue(p);
	}
#else
	ILibProcessPipe_Pipe_ResumeEx(p);
#endif
}

#ifdef WIN32
DWORD ILibProcessPipe_Pipe_BackgroundReader(void *arg)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)arg;
	DWORD bytesRead = 0;
	size_t consumed = 0;

	while (pipeObject->PAUSED == 0 || WaitForSingleObject(pipeObject->mPipe_Reader_ResumeEvent, INFINITE) == WAIT_OBJECT_0)
	{
		// Pipe is in ACTIVE state
		pipeObject->PAUSED = 0;

		while(consumed != 0 && pipeObject->PAUSED == 0 && pipeObject->totalRead > pipeObject->readOffset)
		{
			if (!ILibProcessPipe_BackgroundReadWindowIsValid(pipeObject)) { ILibProcessPipe_FailInvalidReadWindow(pipeObject, "BackgroundReader.BeforeHandler"); ILibProcessPipe_FreePipe(pipeObject); return 0; }
			((ILibProcessPipe_GenericReadHandler)pipeObject->handler)(pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead - pipeObject->readOffset, &consumed, pipeObject->user1, pipeObject->user2);
			if (consumed > (pipeObject->totalRead - pipeObject->readOffset)) { ILibProcessPipe_FailInvalidReadWindow(pipeObject, "BackgroundReader.Consumed"); ILibProcessPipe_FreePipe(pipeObject); return 0; }
			if (consumed == 0)
			{
				memmove_s(pipeObject->buffer, pipeObject->bufferSize, pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead - pipeObject->readOffset);
				pipeObject->readNewOffset = pipeObject->totalRead - pipeObject->readOffset;
				pipeObject->totalRead -= pipeObject->readOffset;
				pipeObject->readOffset = 0;
			}
			else if (consumed == (pipeObject->totalRead - pipeObject->readOffset))
			{
				// Entire buffer consumed
				pipeObject->readOffset = 0;
				pipeObject->totalRead = 0;
				pipeObject->readNewOffset = 0;
				consumed = 0;
			}
			else
			{
				// Partial Consumed
				pipeObject->readOffset += consumed;
			}
		}

		if (pipeObject->PAUSED == 1) { continue; }
		if (!ILibProcessPipe_BackgroundReadWindowIsValid(pipeObject)) { ILibProcessPipe_FailInvalidReadWindow(pipeObject, "BackgroundReader.BeforeRead"); ILibProcessPipe_FreePipe(pipeObject); return 0; }
		if (!ReadFile(pipeObject->mPipe_ReadEnd, pipeObject->buffer + pipeObject->readOffset + pipeObject->readNewOffset, (DWORD)(pipeObject->bufferSize - pipeObject->readOffset - pipeObject->readNewOffset), &bytesRead, NULL)) { break; }

		consumed = 0;
		if (!ILibProcessPipe_BackgroundReadWindowCanAppend(pipeObject, bytesRead)) { ILibProcessPipe_FailInvalidReadWindow(pipeObject, "BackgroundReader.Append"); ILibProcessPipe_FreePipe(pipeObject); return 0; }
		pipeObject->totalRead += bytesRead;
		((ILibProcessPipe_GenericReadHandler)pipeObject->handler)(pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead - pipeObject->readOffset, &consumed, pipeObject->user1, pipeObject->user2);
		if (consumed > (pipeObject->totalRead - pipeObject->readOffset)) { ILibProcessPipe_FailInvalidReadWindow(pipeObject, "BackgroundReader.InitialConsumed"); ILibProcessPipe_FreePipe(pipeObject); return 0; }
		pipeObject->readOffset += consumed;
		if (consumed == 0) 
		{ 
			pipeObject->readNewOffset = pipeObject->totalRead - pipeObject->readOffset;
		}
	}

	if (pipeObject->brokenPipeHandler != NULL) { pipeObject->brokenPipeHandler(pipeObject); }
	ILibProcessPipe_FreePipe(pipeObject);

	return 0;
}
#endif
#ifdef WIN32
BOOL ILibProcessPipe_Process_Pipe_ReadExHandler(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, char *buffer, DWORD bytesRead, void* user)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)user;
	ILibProcessPipe_GenericReadHandler handler;
	size_t consumed = 0;
	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return(FALSE); }
	if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0) { return(FALSE); }
	handler = (ILibProcessPipe_GenericReadHandler)pipeObject->handler;
	if (handler == NULL) { return(FALSE); }
	if (status == ILibWaitHandle_ErrorStatus_NONE)
	{
		ILIBLOGMESSAGEX2(LOGEX_PROCESSPIPE, "ReadExHandler[%p](%p) -> TotalRead: %llu, bytesRead: %llu", h, buffer, pipeObject->totalRead, bytesRead);
		if (!ILibProcessPipe_ReadWindowCanAppend(pipeObject, bytesRead)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadExHandler.Append"); }
		pipeObject->totalRead += bytesRead;
		do
		{
			if (pipeObject->PAUSED == 0)
			{
				if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadExHandler.BeforeHandler"); }
				ILIBLOGMESSAGEX2(LOGEX_PROCESSPIPE, " ReadExHandler(%p, %llu, %llu); [%llu]", pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead, consumed, pipeObject->readOffset);
				handler(pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead, &consumed, pipeObject->user1, pipeObject->user2);
				if (consumed > pipeObject->totalRead) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadExHandler.Consumed"); }
				pipeObject->readOffset += consumed;
				pipeObject->totalRead -= consumed;
				ILIBLOGMESSAGEX2(LOGEX_PROCESSPIPE, "  -> readOffset: %llu, totalRead: %llu, consumed: %llu, PAUSE: %d", pipeObject->readOffset, pipeObject->totalRead, consumed, pipeObject->PAUSED);
			}
		} while (pipeObject->PAUSED == 0 && consumed != 0 && pipeObject->totalRead > 0);

		if (pipeObject->totalRead == 0) { pipeObject->readOffset = 0; }
		if (pipeObject->PAUSED == 0)
		{
			if (pipeObject->readOffset > 0)
			{
				if (!ILibProcessPipe_ReadWindowIsValid(pipeObject)) { return ILibProcessPipe_FailInvalidReadWindow(pipeObject, "ReadExHandler.Compact"); }
				memmove_s(pipeObject->buffer, pipeObject->bufferSize, pipeObject->buffer + pipeObject->readOffset, pipeObject->totalRead);
				pipeObject->readOffset = 0;
			}
			else if (pipeObject->totalRead == pipeObject->bufferSize)
			{
				ILibMemory_ReallocateRaw(&(pipeObject->buffer), pipeObject->bufferSize * 2);
				pipeObject->bufferSize = pipeObject->bufferSize * 2;
			}
			ILIBLOGMESSAGEX2(LOGEX_PROCESSPIPE, "ILibChain_ReadEx2() => (%p, %llu, %llu)", pipeObject->buffer, pipeObject->readOffset + pipeObject->totalRead, pipeObject->bufferSize - pipeObject->totalRead);
			return(ILibProcessPipe_Process_ScheduleRead(pipeObject));
		}
		else
		{
			ILIBLOGMESSAGEX2(LOGEX_PROCESSPIPE, "HANDLE will get removed");
			return(FALSE);
		}
	}
	else
	{
		// I/O Errors
		return(FALSE);
	}
}
#endif
void ILibProcessPipe_Pipe_ResetMetadata(ILibProcessPipe_Pipe p, char *metadata)
{
	ILibProcessPipe_PipeObject *pipeObject = (ILibProcessPipe_PipeObject*)p;
	const char* metadataValue = (metadata != NULL) ? metadata : "";
	size_t metadataLen;
#ifdef WIN32
	void* chain = NULL;
	HANDLE waitHandle = NULL;
#endif

	if (pipeObject == NULL || !ILibMemory_CanaryOK(pipeObject)) { return; }

	metadataLen = strnlen_s(metadataValue, 1024);
	ILibMemory_Free(pipeObject->metadata);
	pipeObject->metadata = (char*)ILibMemory_SmartAllocate(metadataLen + 1);
	memcpy_s(pipeObject->metadata, ILibMemory_Size(pipeObject->metadata), metadataValue, metadataLen);
	pipeObject->metadata[metadataLen] = 0;

#ifdef WIN32
	chain = (pipeObject->mProcess != NULL && pipeObject->mProcess->chain != NULL) ?
		pipeObject->mProcess->chain :
		(pipeObject->manager != NULL ? pipeObject->manager->ChainLink.ParentChain : NULL);
	if (pipeObject->mOverlapped != NULL)
	{
		waitHandle = pipeObject->mOverlapped->hEvent;
	}
	else if (pipeObject->mwOverlapped != NULL)
	{
		waitHandle = pipeObject->mwOverlapped->hEvent;
	}
	if (chain != NULL && waitHandle != NULL)
	{
		ILibChain_WaitHandle_UpdateMetadata(chain, waitHandle, pipeObject->metadata);
	}
#endif
}
void ILibProcessPipe_Process_ResetMetadata(ILibProcessPipe_Process p, char *metadata)
{
	char tmp[1024];
	ILibProcessPipe_Process_Object *j = (ILibProcessPipe_Process_Object*)p;
	const char* metadataValue = (metadata != NULL) ? metadata : "";
	if (j == NULL || !ILibMemory_CanaryOK(j)) { return; }

	if (j->stdOut != NULL)
	{
		sprintf_s(tmp, sizeof(tmp), "(stdout) %s", metadataValue);
		ILibProcessPipe_Pipe_ResetMetadata(j->stdOut, tmp);
	}

	if (j->stdErr != NULL)
	{
		sprintf_s(tmp, sizeof(tmp), "(stderr) %s", metadataValue);
		ILibProcessPipe_Pipe_ResetMetadata(j->stdErr, tmp);
	}

	ILibMemory_Free(j->metadata);
	j->metadata = (char*)ILibMemory_SmartAllocate(8 + strnlen_s(metadataValue, 1024));
	sprintf_s(j->metadata, ILibMemory_Size(j->metadata), "%s [EXIT]", metadataValue);

#ifdef WIN32
	ILibChain_WaitHandle_UpdateMetadata(j->chain, j->hProcess, j->metadata);
#endif
}
char *ILibProcessPipe_Process_GetMetadata(ILibProcessPipe_Process p)
{
	return(((ILibProcessPipe_Process_Object*)p)->metadata);
}
void ILibProcessPipe_Process_StartPipeReaderEx(ILibProcessPipe_PipeObject *pipeObject, int bufferSize, ILibProcessPipe_GenericReadHandler handler, void* user1, void* user2, char *metadata)
{
	if ((pipeObject->buffer = (char*)malloc(bufferSize)) == NULL) { ILIBCRITICALEXIT(254); }
	pipeObject->bufferSize = bufferSize;
	pipeObject->handler = (void*)handler;
	pipeObject->user1 = user1;
	pipeObject->user2 = user2;
	if (metadata != NULL) { pipeObject->metadata = metadata; }

#ifdef WIN32
	if (pipeObject->mOverlapped != NULL)
	{
		// This PIPE supports Overlapped I/O
		pipeObject->readOffset = 0;
		pipeObject->totalRead = 0;
		ILibProcessPipe_Process_ScheduleRead(pipeObject);
	}
	else
	{
		// This PIPE does NOT support overlapped I/O, so we have to fake it with a background thread
		pipeObject->mPipe_Reader_ResumeEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
		ILibSpawnNormalThread(&ILibProcessPipe_Pipe_BackgroundReader, pipeObject);
	}
#else
	ILibLifeTime_Add(ILibGetBaseTimer(pipeObject->manager->ChainLink.ParentChain), pipeObject, 0, &ILibProcessPipe_Process_StartPipeReaderWriterEx, NULL); // Need to context switch to Chain Thread
#endif
}
void ILibProcessPipe_Process_PipeHandler_StdOut(char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user1, void *user2)
{
	ILibProcessPipe_Process_Object *j = (ILibProcessPipe_Process_Object*)user1;
	if (user2 != NULL)
	{
		((ILibProcessPipe_Process_OutputHandler)user2)(j, buffer, bufferLen, bytesConsumed, j->userObject);
	}
}
void ILibProcessPipe_Process_PipeHandler_StdIn(void *user1, void *user2)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)user1;
	ILibProcessPipe_Process_SendOKHandler sendOk = (ILibProcessPipe_Process_SendOKHandler)user2;

	if (sendOk != NULL) sendOk(j, j->userObject);
}

#ifdef WIN32
void ILibProcessPipe_Process_OnExit_ChainSink(void *chain, void *user)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)user;
	DWORD exitCode;
	BOOL result;
	if (j->disabled != 0) { return; }

	result = GetExitCodeProcess(j->hProcess, &exitCode);
	j->exiting = 1;
	j->exitHandler(j, exitCode, j->userObject);
	j->exiting ^= 1;
	
	if (j->exiting == 0) { ILibProcessPipe_Process_Destroy(j); }
}
#ifdef WIN32
void __stdcall ILibProcessPipe_Process_OnExit_ChainSink_APC(ULONG_PTR obj)
{
	ILibProcessPipe_Process_OnExit_ChainSink(NULL, (void*)obj);
}
#endif
BOOL ILibProcessPipe_Process_OnExit(void *chain, HANDLE event, ILibWaitHandle_ErrorStatus errors, void* user)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)user;
	if (errors != ILibWaitHandle_ErrorStatus_NONE) { return(FALSE); }

	UNREFERENCED_PARAMETER(event);
	ILibChain_RemoveWaitHandle(j->chain, j->hProcess);

	if ((j->stdOut->PAUSED != 0 && j->stdOut->totalRead > 0) || (j->stdErr->PAUSED != 0 && j->stdErr->totalRead > 0))
	{
		j->hProcess_needAdd = 1;
		return(TRUE);
	}
	else
	{
		if (j->exitHandler != NULL)
		{
			ILibProcessPipe_Process_OnExit_ChainSink(j->chain, user);
		}
		else
		{
			ILibProcessPipe_Process_Destroy(j);
		}
		return(FALSE);
	}
}
#endif
void ILibProcessPipe_Process_UpdateUserObject(ILibProcessPipe_Process module, void *userObj)
{
	((ILibProcessPipe_Process_Object*)module)->userObject = userObj;
}
#ifdef WIN32
void ILibProcessPipe_Process_RemoveHandlers(ILibProcessPipe_Process module)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)module;
	if (j != NULL && ILibMemory_CanaryOK(j))
	{
		j->disabled = 1;
		ILibChain_RemoveWaitHandle(j->chain, j->hProcess);
	}
}
#endif
void ILibProcessPipe_Process_AddHandlers(ILibProcessPipe_Process module, int bufferSize, ILibProcessPipe_Process_ExitHandler exitHandler, ILibProcessPipe_Process_OutputHandler stdOut, ILibProcessPipe_Process_OutputHandler stdErr, ILibProcessPipe_Process_SendOKHandler sendOk, void *user)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)module;
	if (j != NULL && ILibMemory_CanaryOK(j))
	{
		j->userObject = user;
		j->exitHandler = exitHandler;

		if (j->stdOut->metadata == NULL) { j->stdOut->metadata = "process_handle_stdout"; }
		if (j->stdErr->metadata == NULL) { j->stdErr->metadata = "process_handle_stderr"; }
		if (j->metadata == NULL) { j->metadata = "process_handle_exit"; }

		ILibProcessPipe_Process_StartPipeReaderEx(j->stdOut, bufferSize, &ILibProcessPipe_Process_PipeHandler_StdOut, j, stdOut, NULL);
		ILibProcessPipe_Process_StartPipeReaderEx(j->stdErr, bufferSize, &ILibProcessPipe_Process_PipeHandler_StdOut, j, stdErr, NULL);
		ILibProcessPipe_Process_SetWriteHandler(j->stdIn, &ILibProcessPipe_Process_PipeHandler_StdIn, j, sendOk);
#ifdef WIN32
		ILibChain_AddWaitHandleEx(j->parent->ChainLink.ParentChain, j->hProcess, -1, ILibProcessPipe_Process_OnExit, j, j->metadata);
#endif
	}
}
#ifdef WIN32
void ILibProcessPipe_Process_GetWaitHandles(ILibProcessPipe_Process p, HANDLE *hProcess, HANDLE *read, HANDLE *write, HANDLE *error)
{
	ILibProcessPipe_Process_Object* j = (ILibProcessPipe_Process_Object*)p;
	if (hProcess != NULL) { *hProcess = NULL; }
	if (read != NULL) { *read = NULL; }
	if (write != NULL) { *write = NULL; }
	if (error != NULL) { *error = NULL; }
	if (j == NULL || !ILibMemory_CanaryOK(j)) { return; }
	if (hProcess != NULL) { *hProcess = j->hProcess; }
	if (read != NULL && j->stdOut != NULL && j->stdOut->mOverlapped != NULL) { *read = j->stdOut->mOverlapped->hEvent; }
	if (error != NULL && j->stdErr != NULL && j->stdErr->mOverlapped != NULL) { *error = j->stdErr->mOverlapped->hEvent; }
	if (write != NULL && j->stdIn != NULL && j->stdIn->mOverlapped != NULL) { *write = j->stdIn->mOverlapped->hEvent; }
}
#endif
void ILibProcessPipe_Pipe_Close(ILibProcessPipe_Pipe po)
{
	ILibProcessPipe_PipeObject* pipeObject = (ILibProcessPipe_PipeObject*)po;
	if (pipeObject != NULL)
	{
#ifdef WIN32
		CloseHandle(pipeObject->mPipe_WriteEnd);
		pipeObject->mPipe_WriteEnd = NULL;
#else
		close(pipeObject->mPipe_WriteEnd);
		pipeObject->mPipe_WriteEnd = -1;
#endif
	}
}

ILibTransport_DoneState ILibProcessPipe_Pipe_Write(ILibProcessPipe_Pipe po, char* buffer, int bufferLen, ILibTransport_MemoryOwnership ownership)
{
	ILibProcessPipe_PipeObject* pipeObject = (ILibProcessPipe_PipeObject*)po;
	ILibTransport_DoneState retVal = ILibTransport_DoneState_ERROR;
	ILibProcessPipe_WriteData* pendingData = NULL;
#ifdef WIN32
	OVERLAPPED* writeOverlapped = NULL;
#endif

	if (pipeObject == NULL)
	{
		return(ILibTransport_DoneState_ERROR);
	}
#ifdef WIN32
	if (ILibProcessPipe_GetStateLong(&pipeObject->closeRequested) != 0)
	{
		return(ILibTransport_DoneState_ERROR);
	}
#endif

	if (pipeObject->WriteBuffer == NULL)
	{
		pipeObject->WriteBuffer = ILibQueue_Create();
	}

	ILibQueue_Lock(pipeObject->WriteBuffer);
	if (ILibQueue_IsEmpty(pipeObject->WriteBuffer) == 0)
	{
		ILibQueue_EnQueue(pipeObject->WriteBuffer, ILibProcessPipe_WriteData_Create(buffer, bufferLen, ownership));
	}
	else
	{
#ifdef WIN32
		BOOL result;
		pendingData = ILibProcessPipe_WriteData_Create(buffer, bufferLen, ownership);
		writeOverlapped = ILibProcessPipe_GetWriteOverlapped(pipeObject);
		if (writeOverlapped == NULL)
		{
			if (pendingData != NULL) { ILibProcessPipe_WriteData_Destroy(pendingData); }
			ILibQueue_UnLock(pipeObject->WriteBuffer);
			return(ILibTransport_DoneState_ERROR);
		}
		result = WriteFile(pipeObject->mPipe_WriteEnd, pendingData->buffer, pendingData->bufferLen, NULL, writeOverlapped);
		if (result == TRUE)
		{
			retVal = ILibTransport_DoneState_COMPLETE;
			ILibProcessPipe_WriteData_Destroy(pendingData);
			pendingData = NULL;
		}
#else
		int result = (int)write(pipeObject->mPipe_WriteEnd, buffer, bufferLen);
		while (result >= 0 && result < bufferLen)
		{
			buffer += result;
			bufferLen -= result;
			result = (int)write(pipeObject->mPipe_WriteEnd, buffer, bufferLen);
		}
		if (result == bufferLen) { retVal = ILibTransport_DoneState_COMPLETE; }
#endif
		else
		{
#ifdef WIN32
			if (GetLastError() == ERROR_IO_PENDING)
#else
			if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
#endif
			{
				retVal = ILibTransport_DoneState_INCOMPLETE;
				ILibQueue_EnQueue(pipeObject->WriteBuffer, pendingData);
				pendingData = NULL;
#ifdef WIN32
				ILibChain_AddWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent, -1, ILibProcessPipe_Process_WindowsWriteHandler, pipeObject);
#else
				ILibLifeTime_Add(ILibGetBaseTimer(pipeObject->manager->ChainLink.ParentChain), pipeObject, 0, &ILibProcessPipe_Process_StartPipeReaderWriterEx, NULL); // Need to context switch to Chain Thread
#endif
			}
			else
			{
				if (pipeObject->manager != NULL)
				{
#ifdef WIN32
					ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[Write]: BrokenPipe(%d) on Pipe: %p", GetLastError(), (void*)pipeObject);
#else
					ILibRemoteLogging_printf(ILibChainGetLogger(pipeObject->manager->ChainLink.ParentChain), ILibRemoteLogging_Modules_Microstack_Pipe, ILibRemoteLogging_Flags_VerbosityLevel_1, "ILibProcessPipe[Write]: BrokenPipe(%d) on Pipe: %p", result < 0 ? errno : 0, (void*)pipeObject);
#endif
				}
				ILibQueue_UnLock(pipeObject->WriteBuffer);
				if (pipeObject->brokenPipeHandler != NULL)
				{
#ifdef WIN32
					if (pipeObject->manager != NULL)
					{
						ILibChain_RemoveWaitHandle(pipeObject->manager->ChainLink.ParentChain, writeOverlapped->hEvent);
					}
#endif
					if (pendingData != NULL) { ILibProcessPipe_WriteData_Destroy(pendingData); pendingData = NULL; }
					((ILibProcessPipe_GenericBrokenPipeHandler)pipeObject->brokenPipeHandler)(pipeObject);
				}
				else if (pendingData != NULL)
				{
					ILibProcessPipe_WriteData_Destroy(pendingData);
					pendingData = NULL;
				}
				ILibProcessPipe_FreePipe(pipeObject);
				return(ILibTransport_DoneState_ERROR);
			}
		}
	}
	ILibQueue_UnLock(pipeObject->WriteBuffer);
	
	return retVal;
}
void ILibProcessPipe_Process_CloseStdIn(ILibProcessPipe_Process p)
{
	ILibProcessPipe_Process_Object *j = (ILibProcessPipe_Process_Object*)p;
	if (ILibMemory_CanaryOK(j))
	{
		ILibProcessPipe_Pipe_Close(j->stdIn);
	}
}
ILibTransport_DoneState ILibProcessPipe_Process_WriteStdIn(ILibProcessPipe_Process p, char* buffer, int bufferLen, ILibTransport_MemoryOwnership ownership)
{
	ILibProcessPipe_Process_Object *j = (ILibProcessPipe_Process_Object*)p;
	if (ILibMemory_CanaryOK(j))
	{
		return(ILibProcessPipe_Pipe_Write(j->stdIn, buffer, bufferLen, ownership));
	}
	else
	{
		return(ILibTransport_DoneState_ERROR);
	}
}

void ILibProcessPipe_Pipe_ReadSink(char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user1, void* user2)
{
	ILibProcessPipe_Pipe target = (ILibProcessPipe_Pipe)user1;

	if (user2 != NULL) { ((ILibProcessPipe_Pipe_ReadHandler)user2)(target, buffer, bufferLen, bytesConsumed); }
}
void ILibProcessPipe_Pipe_AddPipeReadHandler(ILibProcessPipe_Pipe targetPipe, int bufferSize, ILibProcessPipe_Pipe_ReadHandler OnReadHandler)
{
	ILibProcessPipe_Process_StartPipeReader(targetPipe, bufferSize, &ILibProcessPipe_Pipe_ReadSink, targetPipe, OnReadHandler);
}
#ifdef WIN32
BOOL ILibProcessPipe_Pipe_ReadEx_sink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	ILibProcessPipe_PipeObject *j = (ILibProcessPipe_PipeObject*)user;
	DWORD bytesRead = 0;

	if (status == ILibWaitHandle_ErrorStatus_INVALID_HANDLE) { return(FALSE); }

	if (GetOverlappedResult(j->mPipe_ReadEnd, j->mOverlapped, &bytesRead, FALSE))
	{
		if (j->user2 != NULL) { ((ILibProcessPipe_Pipe_ReadExHandler)j->user2)(j, j->user1, 0, j->buffer, (int)bytesRead); }
	}
	else
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			return(TRUE);
		}
		else
		{
			if (j->user2 != NULL) { ((ILibProcessPipe_Pipe_ReadExHandler)j->user2)(j, j->user1, 1, j->buffer, 0); }
		}
	}

	return(FALSE);
}
int ILibProcessPipe_Pipe_ReadEx(ILibProcessPipe_Pipe targetPipe, char *buffer, int bufferLength, void *user, ILibProcessPipe_Pipe_ReadExHandler OnReadHandler)
{
	ILibProcessPipe_PipeObject *j = (ILibProcessPipe_PipeObject*)targetPipe;
	DWORD bytesRead = 0;
	int ret = 0;

	if (ReadFile(j->mPipe_ReadEnd, buffer, bufferLength, &bytesRead, j->mOverlapped))
	{
		// Complete
		if (OnReadHandler != NULL) { OnReadHandler(j, user, 0, buffer, (int)bytesRead); }
	}
	else
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			j->buffer = buffer;
			j->bufferSize = bufferLength;
			j->bufferOwner = ILibTransport_MemoryOwnership_USER;
			j->user1 = user;
			j->user2 = OnReadHandler;
			ILibChain_AddWaitHandle(j->manager->ChainLink.ParentChain, j->mOverlapped->hEvent, -1, ILibProcessPipe_Pipe_ReadEx_sink, j);
		}
		else
		{
			ret = 1;
		}
	}
	return(ret);
}
BOOL ILibProcessPipe_Pipe_WriteEx_sink(void *chain, HANDLE h, ILibWaitHandle_ErrorStatus status, void* user)
{
	ILibProcessPipe_PipeObject *j = (ILibProcessPipe_PipeObject*)user;
	DWORD bytesWritten;

	if (GetOverlappedResult(j->mPipe_WriteEnd, j->mwOverlapped, &bytesWritten, FALSE))
	{
		if (j->user4 != NULL)
		{
			((ILibProcessPipe_Pipe_WriteExHandler)j->user4)(j, j->user3, bytesWritten > 0 ? 0 : 1, (int)bytesWritten);
		}
	}
	else
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			return(TRUE);
		}
		else
		{
			if (j->user4 != NULL)
			{
				((ILibProcessPipe_Pipe_WriteExHandler)j->user4)(j, j->user3, 1, 0);
			}
		}
	}
	return(FALSE);
}
ILibTransport_DoneState ILibProcessPipe_Pipe_WriteEx(ILibProcessPipe_Pipe targetPipe, char *buffer, int bufferLength, void *user, ILibProcessPipe_Pipe_WriteExHandler OnWriteHandler)
{
	ILibProcessPipe_PipeObject *j = (ILibProcessPipe_PipeObject*)targetPipe;
	if (j->mwOverlapped == NULL)
	{
		void **extra;
		j->mwOverlapped = (OVERLAPPED*)ILibMemory_Allocate(sizeof(OVERLAPPED), sizeof(void*), NULL, (void**)&extra);
		if ((j->mwOverlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) { ILIBCRITICALEXIT(254); }
		extra[0] = j;
	}
	j->user3 = user;
	j->user4 = OnWriteHandler;

	if (!WriteFile(j->mPipe_WriteEnd, buffer, bufferLength, NULL, j->mwOverlapped))
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			ILibChain_AddWaitHandle(j->manager->ChainLink.ParentChain, j->mwOverlapped->hEvent, -1, ILibProcessPipe_Pipe_WriteEx_sink, j);
			return(ILibTransport_DoneState_INCOMPLETE);
		}
		// Error
		if (OnWriteHandler != NULL) { OnWriteHandler(j, user, 1, 0); }
		return(ILibTransport_DoneState_ERROR);
	}
	else
	{
		// Write completed
		if (OnWriteHandler != NULL) { OnWriteHandler(j, user, 0, bufferLength); }
		return(ILibTransport_DoneState_COMPLETE);
	}


//	ILibProcessPipe_PipeObject *j = (ILibProcessPipe_PipeObject*)targetPipe;
//	if (j->mwOverlapped == NULL)
//	{
//		void **extra;
//		j->mwOverlapped = (OVERLAPPED*)ILibMemory_Allocate(sizeof(OVERLAPPED), sizeof(void*), NULL, (void**)&extra);
//		extra[0] = j;
//}
//	j->user3 = user;
//	j->user4 = OnWriteHandler;
//	if (!WriteFileEx(j->mPipe_WriteEnd, buffer, bufferLength, j->mwOverlapped, ILibProcessPipe_Pipe_Write_CompletionRoutine))
//	{
//		return(GetLastError());
//	}
//	else
//	{
//		return(0);
//	}
}
DWORD ILibProcessPipe_Process_GetPID(ILibProcessPipe_Process p) { return(p != NULL ? (DWORD)((ILibProcessPipe_Process_Object*)p)->PID : 0); }
#else
pid_t ILibProcessPipe_Process_GetPID(ILibProcessPipe_Process p) { return(p != NULL ? (pid_t)((ILibProcessPipe_Process_Object*)p)->PID : 0); }
int ILibProcessPipe_Process_GetPTY(ILibProcessPipe_Process p) { return(p != NULL ? ((ILibProcessPipe_Process_Object*)p)->PTY : 0); }
#endif
