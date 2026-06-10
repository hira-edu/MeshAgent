const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractSpan(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    if (start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span: ${startMarker}`);
    }
    return source.slice(start, end);
}

function main() {
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const kvmSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const inputSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'input.c');
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');

    const kvmHeader = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmSourcePath, 'utf8');
    const inputSource = fs.readFileSync(inputSourcePath, 'utf8');
    const agentcore = fs.readFileSync(agentcorePath, 'utf8');
    const discardCachedStream = extractSpan(
        agentcore,
        'static void ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream',
        'duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop'
    );

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
        agentcoreCachedStreamValidatesNativeBridgeState:
            agentcore.includes('static int ILibDuktape_MeshAgent_RemoteDesktop_CachedStreamIsLive(RemoteDesktop_Ptrs *ptrs)') &&
            agentcore.includes('ptrs->stream->readableStream->endRelayed != 0') &&
            agentcore.includes('kvm_bridge_debug_get_child_present_for_reserved(ptrs)') &&
            agentcore.includes('kvm_bridge_debug_get_transport_active_for_reserved(ptrs)') &&
            agentcore.includes('static void ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(duk_context *ctx, RemoteDesktop_Ptrs *ptrs)') &&
            agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(ctx, ptrs);'),
        kvmPipeBreakClearsTransportActive: kvmSource.includes('static void kvm_relay_bridge_pipe_broken_handler') &&
            kvmSource.includes('ctx->transportActive = 0;') &&
            kvmSource.includes('gKvmTransportActive = 0;'),
        inputDoesNotForegroundCurrentWindow: !inputSource.includes('SetForegroundWindow(windowHandle)') &&
            !inputSource.includes('KVM_LogInputApiFailure("SetForegroundWindow(key)"') &&
            !inputSource.includes('KVM_LogInputApiFailure("SetForegroundWindow(unicode)"'),
        discardCachedStreamKeepsObjectAliveThroughNativeCleanup:
            discardCachedStream.includes('duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);') &&
            discardCachedStream.includes('kvm_cleanup(ptrs);') &&
            discardCachedStream.includes('memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));') &&
            discardCachedStream.includes('duk_del_prop_string(ctx, -2, REMOTE_DESKTOP_STREAM);') &&
            discardCachedStream.includes('duk_pop(ctx);') &&
            discardCachedStream.indexOf('duk_get_prop_string(ctx, -1, REMOTE_DESKTOP_STREAM);') <
                discardCachedStream.indexOf('kvm_cleanup(ptrs);') &&
            discardCachedStream.indexOf('kvm_cleanup(ptrs);') <
                discardCachedStream.indexOf('memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));') &&
            discardCachedStream.indexOf('memset(ptrs, 0, sizeof(RemoteDesktop_Ptrs));') <
                discardCachedStream.indexOf('duk_del_prop_string(ctx, -2, REMOTE_DESKTOP_STREAM);') &&
            discardCachedStream.indexOf('duk_del_prop_string(ctx, -2, REMOTE_DESKTOP_STREAM);') <
                discardCachedStream.lastIndexOf('duk_pop(ctx);'),
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
        inputSourcePath,
        agentcorePath,
        checks
    }, null, 2) + '\n');
}

main();
