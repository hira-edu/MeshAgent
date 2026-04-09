const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const kvmSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');

    const kvmHeader = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmSourcePath, 'utf8');
    const agentcore = fs.readFileSync(agentcorePath, 'utf8');

    const checks = {
        headerExportsSnapshot: kvmHeader.includes('typedef struct KvmBridgeDebugSnapshot'),
        headerExportsResyncHelpers: kvmHeader.includes('void kvm_relay_request_display_list') && kvmHeader.includes('void kvm_relay_query_input_lock'),
        headerExportsSnapshotGetter: kvmHeader.includes('int kvm_bridge_debug_get_snapshot_for_reserved'),
        kvmTracksPendingProbes: kvmSource.includes('KVM_PENDING_PROBE_REFRESH') &&
            kvmSource.includes('kvm_bridge_debug_arm_pending_probe') &&
            kvmSource.includes('kvm_bridge_debug_clear_pending_probe'),
        kvmTracksInputOutputTicks: kvmSource.includes('gKvmLastInputTickMs') &&
            kvmSource.includes('gKvmLastOutputTickMs') &&
            kvmSource.includes('gKvmLastScreenTickMs') &&
            kvmSource.includes('kvm_bridge_debug_note_input') &&
            kvmSource.includes('kvm_bridge_debug_note_output'),
        kvmExportsSnapshotGetter: kvmSource.includes('int kvm_bridge_debug_get_snapshot_for_reserved(void *reserved, KvmBridgeDebugSnapshot* snapshotOut)'),
        agentcoreHasNoWatchdogState: !agentcore.includes('REMOTE_DESKTOP_WATCHDOG_STARTUP_TIMEOUT_MS') &&
            !agentcore.includes('watchdogSessionStartTickMs') &&
            !agentcore.includes('watchdogRequiredScreenTickMs') &&
            !agentcore.includes('watchdogRecoveryAttempts'),
        agentcoreHasNoWatchdogHelpers: !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_BeginLogicalSession') &&
            !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_SetupKvmSession') &&
            !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_RequestResync') &&
            !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_RecoverSession') &&
            !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_Watchdog') &&
            !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_RemoveWatchdog'),
        agentcoreCachedStreamReuseIsPassive: !agentcore.includes('cached-stream-reuse') &&
            !agentcore.includes('cached-stream-stale') &&
            !agentcore.includes('kvm_bridge_debug_get_child_present_for_reserved') &&
            !agentcore.includes('kvm_bridge_debug_get_transport_active_for_reserved'),
        agentcoreInitialSetupUsesDirectRelay: agentcore.includes('kvm_relay_setup(agent->exePath, agent->runningAsConsole ? NULL : agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, TSID);') &&
            agentcore.includes('kvm_relay_setup(agent->exePath, NULL, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs, TSID);'),
        agentcoreHasNoSetupFailureCallback: !agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_SetupFailedCallback') &&
            !agentcore.includes('Unable to start remote desktop session')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({
        kvmHeaderPath,
        kvmSourcePath,
        agentcorePath,
        checks
    }, null, 2) + '\n');
}

main();
