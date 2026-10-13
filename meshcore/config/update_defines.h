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
// Attempt record for the package last handed to the lifecycle host:
// "1 <attempts> <unix time of last handoff> <96 hex SHA-384>".
#define MESHAGENT_UPDATE_RETRY_STATE_KEY         "UpdateRetryState"
// Automatic retries of one package wait 1, 2, 4, 8, 16 hours, then 24 hours each.
#define MESHAGENT_UPDATE_RETRY_BASE_SECONDS      3600
#define MESHAGENT_UPDATE_RETRY_MAX_SECONDS       86400
// Default for datastore key updateMinUptimeSeconds; 0 leaves the check off.
#define MESHAGENT_UPDATE_MIN_UPTIME_SECONDS      0
// While deferred, readiness is rechecked this often; the agent reconnects once it clears.
#define MESHAGENT_UPDATE_RENEGOTIATE_RECHECK_SECONDS 300

#endif /* MESHCORE_CONFIG_UPDATE_DEFINES_H */
