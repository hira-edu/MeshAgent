#ifndef SERVICE_BUNDLE_H
#define SERVICE_BUNDLE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL ServiceBundle_WriteToPath(const wchar_t* destination);

#ifdef __cplusplus
}
#endif

#endif /* SERVICE_BUNDLE_H */
