#ifndef STEALTH_UTILS_H
#define STEALTH_UTILS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void Stealth_DebugPrintfA(const char* format, ...);
void Stealth_DebugPrintfW(const wchar_t* format, ...);
void Stealth_DebugLastErrorA(const char* context);
void Stealth_DebugLastErrorW(const wchar_t* context);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_UTILS_H */
