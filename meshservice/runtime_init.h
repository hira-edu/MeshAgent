// Runtime initialization helpers for lab/testing builds
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initializes optional runtime features when enabled.
// Safe no-op when MESHAGENT_ENABLE_RUNTIME_FEATURES is not defined.
void RuntimeInit_EnableOptionalFeatures(void);

#ifdef __cplusplus
}
#endif

