/*
    Windows agent update contract shared by download/activation and lifecycle code.
*/
#ifndef MESHCORE_CONFIG_UPDATE_DEFINES_H
#define MESHCORE_CONFIG_UPDATE_DEFINES_H

#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX ".update.pkg"
// modules/update-helper.js extracts a compressed package to this sibling first.
#define MESHAGENT_WINDOWS_UPDATE_UNZIPPED_SUFFIX MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX "_unzipped"
// Update-hold keys written by earlier builds. Nothing reads them; they are deleted as stale state.
#define MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY   "UpdateActivationTargetHash"
#define MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY  "UpdateActivationFailureHash"
#define MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS   600000

#endif /* MESHCORE_CONFIG_UPDATE_DEFINES_H */
