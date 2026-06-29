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

#if defined(_LINKVM)
#include "microstack/ILibParsers.h"

typedef ILibTransport_DoneState(*ILibKVM_WriteHandler)(char *buffer, int bufferLen, void *reserved);

#define KVM_BRIDGE_CONNECT_TIMEOUT_MS 5000
#define KVM_BRIDGE_CONNECT_DELAY_ENV_A "STEALTH_KVM_BRIDGE_CONNECT_DELAY_MS"
#define KVM_BRIDGE_CONNECT_DELAY_ENV_W L"STEALTH_KVM_BRIDGE_CONNECT_DELAY_MS"
#define KVM_PENDING_PROBE_REFRESH 0x01
#define KVM_PENDING_PROBE_DISPLAYS 0x02
#define KVM_PENDING_PROBE_INPUTLOCK 0x04

int kvm_relay_feeddata(char* buf, int len, ILibKVM_WriteHandler writeHandler, void *reserved);
void kvm_pause(int pause, void *reserved);
int kvm_relay_setup(char* exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid);
void kvm_cleanup(void *reserved);
void kvm_setupSasPermissions();
void kvm_relay_reset(ILibKVM_WriteHandler writeHandler, void *reserved);
void kvm_relay_request_display_list(ILibKVM_WriteHandler writeHandler, void *reserved);
void kvm_relay_query_input_lock(ILibKVM_WriteHandler writeHandler, void *reserved);
const char* kvm_get_current_desktop_name();
void kvm_set_force_default_desktop(int enabled);
void KVM_TraceStartupF(const char* format, ...);
#ifdef WIN32
typedef struct KvmBridgeDebugSnapshot
{
	int childPresent;
	DWORD childPid;
	int transportActive;
	DWORD processSessionId;
	int processTSIDExplicit;
	ULONGLONG sessionStartTickMs;
	ULONGLONG lastInputTickMs;
	ULONGLONG lastOutputTickMs;
	ULONGLONG lastScreenTickMs;
	unsigned short lastInputType;
	unsigned short lastOutputType;
	unsigned int pendingProbeMask;
	ULONGLONG pendingProbeSinceTickMs;
} KvmBridgeDebugSnapshot;
void kvm_notify_session_change(DWORD eventType, DWORD sessionId);
int kvm_bridge_debug_get_child_present(void);
DWORD kvm_bridge_debug_get_child_pid(void);
int kvm_bridge_debug_get_child_present_for_reserved(void *reserved);
DWORD kvm_bridge_debug_get_child_pid_for_reserved(void *reserved);
int kvm_bridge_debug_is_child_exit_signaled(void);
int kvm_bridge_debug_get_restart_suppressed(void);
int kvm_bridge_debug_peek_pending_session_restart(DWORD* eventTypeOut, DWORD* sessionIdOut);
DWORD kvm_bridge_debug_get_process_session_id(void);
DWORD kvm_bridge_debug_get_process_session_id_for_reserved(void *reserved);
int kvm_bridge_debug_force_process_session_id_for_reserved(void *reserved, DWORD sessionId);
int kvm_bridge_debug_get_transport_active(void);
int kvm_bridge_debug_get_transport_active_for_reserved(void *reserved);
int kvm_bridge_debug_get_last_bridge_available(void);
int kvm_bridge_debug_get_last_used_bridge(void);
int kvm_bridge_debug_get_last_fallback_used(void);
int kvm_bridge_debug_get_last_used_bridge_for_reserved(void *reserved);
int kvm_bridge_debug_get_last_fallback_used_for_reserved(void *reserved);
DWORD kvm_bridge_debug_get_last_bridge_failure_error(void);
DWORD kvm_bridge_debug_get_last_bridge_failure_stage(void);
DWORD kvm_bridge_debug_get_last_bridge_failure_spawn_type(void);
DWORD kvm_bridge_debug_get_last_launch_attempt_count(void);
DWORD kvm_bridge_debug_get_last_successful_spawn_type(void);
DWORD kvm_bridge_debug_get_last_successful_spawn_attempt_ordinal(void);
DWORD kvm_bridge_debug_get_consecutive_failures(void);
DWORD kvm_bridge_debug_get_last_backoff_delay_ms(void);
DWORD kvm_bridge_debug_get_spawn_attempt_count(void);
int kvm_bridge_debug_is_retry_scheduled(void);
int kvm_bridge_debug_get_registered_context_count(void);
int kvm_bridge_debug_get_snapshot_for_reserved(void *reserved, KvmBridgeDebugSnapshot* snapshotOut);
#endif

#endif
