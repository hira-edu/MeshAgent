#ifndef SERVICE_UTILS_H
#define SERVICE_UTILS_H

#include <windows.h>
#include "../microstack/ILibCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL ServiceUtil_PathsReferToSameFileW(const wchar_t* left, const wchar_t* right);

void ServiceUtil_DebugPrintfA(const char* format, ...);
void ServiceUtil_DebugPrintfW(const wchar_t* format, ...);
void ServiceUtil_DebugLastErrorA(const char* context);
void ServiceUtil_DebugLastErrorW(const wchar_t* context);

#define SERVICE_UTIL_SHA256_STRING_LENGTH   (UTIL_SHA256_HASHSIZE * 2)
BOOL ServiceUtil_ComputeFileSha256W(const wchar_t* path, wchar_t* hexOut, size_t hexOutLen);


/* Dynamic path resolution for service data directory.
 * Uses SHGetKnownFolderPath(FOLDERID_ProgramData) to get ProgramData path,
 * then appends the service/application name subdirectory.
 * Returns FALSE if path cannot be determined.
 */
BOOL ServiceUtil_GetDataDirectoryW(const wchar_t* serviceName, wchar_t* outPath, size_t outPathSize);

/* Build a full path within the data directory */
BOOL ServiceUtil_GetDataFilePathW(const wchar_t* serviceName, const wchar_t* fileName, wchar_t* outPath, size_t outPathSize);

/* Ensure data directory exists, creating if necessary */
BOOL ServiceUtil_EnsureDataDirectoryW(const wchar_t* serviceName);

/* Token and XPath utilities for task scheduler */
void ServiceUtil_BuildSanitizedToken(const wchar_t* input, wchar_t* output, size_t outputSize);
void ServiceUtil_FormatServiceStopXPath(const wchar_t* serviceName, wchar_t* xPath, size_t xPathSize);

/* Service protection - protects SERVICE object in SCM from stop commands */
BOOL ServiceUtil_ProtectServiceFromTermination(const wchar_t* serviceName);

/*
 * Process protection - protects the PROCESS from TerminateProcess() calls.
 * CRITICAL: This is different from ServiceUtil_ProtectServiceFromTermination()!
 * - ServiceUtil_ProtectServiceFromTermination() = blocks SCM stop requests.
 * - ServiceUtil_ProtectCurrentProcess() = blocks Task Manager kill, TerminateProcess(), etc.
 */
BOOL ServiceUtil_ProtectCurrentProcess(void);
BOOL ServiceUtil_ProtectProcessByHandle(HANDLE hProcess);

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_UTILS_H */
