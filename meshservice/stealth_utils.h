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

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_UTILS_H */
