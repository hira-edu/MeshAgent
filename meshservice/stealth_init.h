// Stealth initialization helpers for lab/testing builds
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initializes optional stealth features when enabled.
// Safe no-op when MESHAGENT_ENABLE_STEALTH is not defined.
void Stealth_InitLabFeatures(void);

#ifdef __cplusplus
}
#endif

