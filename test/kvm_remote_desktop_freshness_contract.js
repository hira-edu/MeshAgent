const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
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
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const kvmSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const tileSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'tile.cpp');
    const inputSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'input.c');
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');

    const kvmHeader = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmSourcePath, 'utf8');
    const tileSource = fs.readFileSync(tileSourcePath, 'utf8');
    const inputSource = fs.readFileSync(inputSourcePath, 'utf8');
    const agentcore = fs.readFileSync(agentcorePath, 'utf8');
    const discardCachedStream = extractSpan(
        agentcore,
        'static void ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream',
        'duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop'
    );
    const feedDataBlock = extractSpan(
        kvmSource,
        'int kvm_relay_feeddata',
        'static int kvm_relay_select_session_id'
    );
    const probeOutputBlock = extractSpan(
        kvmSource,
        'static unsigned int kvm_bridge_debug_probe_mask_for_output',
        'static void kvm_bridge_debug_note_output'
    );
    const dxgiCaptureBlock = extractSpan(
        tileSource,
        'static int tile_dxgi_capture_frame',
        'static int tile_wgc_initialize'
    );
    const wgcIdleBlock = extractSpan(
        tileSource,
        'static int tile_wgc_handle_idle_frame',
        'static int tile_dxgi_target_changed'
    );

    const checks = {
        headerExportsSnapshot: kvmHeader.includes('typedef struct KvmBridgeDebugSnapshot'),
        headerExportsResyncHelpers: kvmHeader.includes('void kvm_relay_request_display_list') && kvmHeader.includes('void kvm_relay_query_input_lock'),
        headerExportsPendingProbeBits: kvmHeader.includes('#define KVM_PENDING_PROBE_REFRESH 0x01') &&
            kvmHeader.includes('#define KVM_PENDING_PROBE_DISPLAYS 0x02') &&
            kvmHeader.includes('#define KVM_PENDING_PROBE_INPUTLOCK 0x04'),
        headerExportsSnapshotGetter: kvmHeader.includes('int kvm_bridge_debug_get_snapshot_for_reserved'),
        kvmTracksPendingProbes: kvmSource.includes('KVM_PENDING_PROBE_REFRESH') &&
            kvmSource.includes('kvm_bridge_debug_arm_pending_probe') &&
            kvmSource.includes('kvm_bridge_debug_clear_pending_probe'),
        kvmRefreshProbeRequiresPictureOutput:
            probeOutputBlock.includes('case MNG_KVM_PICTURE:') &&
            !probeOutputBlock.includes('case MNG_KVM_SCREEN:'),
        kvmTracksInputOutputTicks: kvmSource.includes('gKvmLastInputTickMs') &&
            kvmSource.includes('gKvmLastOutputTickMs') &&
            kvmSource.includes('gKvmLastScreenTickMs') &&
            kvmSource.includes('kvm_bridge_debug_note_input') &&
            kvmSource.includes('kvm_bridge_debug_note_output'),
        kvmExportsSnapshotGetter: kvmSource.includes('int kvm_bridge_debug_get_snapshot_for_reserved(void *reserved, KvmBridgeDebugSnapshot* snapshotOut)'),
        kvmRefreshProbeTimeoutRespawnsRundll32Bridge:
            kvmSource.includes('#define KVM_REFRESH_PROBE_TIMEOUT_MS (KVM_BRIDGE_CONNECT_TIMEOUT_MS * 2)') &&
            kvmSource.includes('static int kvm_relay_handle_refresh_probe_timeout(KvmRelayContext* ctx, const char* source)') &&
            kvmSource.includes('respawning rundll32 KVM bridge') &&
            kvmSource.includes('kvm_relay_cache_refresh_probe_for_respawn(ctx);') &&
            kvmSource.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);') &&
            kvmSource.includes('kvm_schedule_retry_timer_delay(KVM_REFRESH_PROBE_TIMEOUT_MS);') &&
            kvmSource.includes('gChildProcess == NULL && gKvmPipeMgr != NULL') &&
            kvmSource.includes('kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);'),
        kvmServiceFeeddataRespawnsSameRundll32Bridge:
            kvmSource.includes('static int kvm_relay_prepare_bridge_respawn_from_input') &&
            kvmSource.includes('service-mode KVM input routed to rundll32 bridge respawn') &&
            feedDataBlock.includes('kvm_relay_prepare_bridge_respawn_from_input(ctx, buf, len, "write-failed", writeError)') &&
            feedDataBlock.includes('kvm_relay_prepare_bridge_respawn_from_input(ctx, buf, len, "no-child", ERROR_SUCCESS)') &&
            feedDataBlock.includes('ctx != NULL && gKvmPipeMgr != NULL && gKvmExePath != NULL && gKvmWriteHandler != NULL') &&
            feedDataBlock.indexOf('kvm_relay_prepare_bridge_respawn_from_input(ctx, buf, len, "no-child", ERROR_SUCCESS)') <
                feedDataBlock.indexOf('while ((len2 = kvm_server_inputdata'),
        kvmReplayCachesOperatorRefreshForRespawn:
            kvmSource.includes('static void kvm_relay_cache_refresh_probe_for_respawn(KvmRelayContext* ctx)') &&
            kvmSource.includes('MNG_KVM_REFRESH') &&
            kvmSource.includes('kvm_relay_input_is_replayable_after_respawn') &&
            kvmSource.includes('kvm_relay_cache_control_packet(ctx, buffer, bufferLen)'),
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
            agentcore.includes('KvmBridgeDebugSnapshot snapshot') &&
            agentcore.includes('kvm_bridge_debug_get_snapshot_for_reserved(ptrs, &snapshot)') &&
            agentcore.includes('snapshot.childPresent == 0 || snapshot.transportActive == 0') &&
            agentcore.includes('snapshot.lastScreenTickMs == 0') &&
            agentcore.includes('snapshot.pendingProbeMask & KVM_PENDING_PROBE_REFRESH') &&
            agentcore.includes('snapshot.pendingProbeSinceTickMs') &&
            agentcore.includes('REMOTE_DESKTOP_REFRESH_PROBE_TIMEOUT_MS') &&
            agentcore.includes('static void ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(duk_context *ctx, RemoteDesktop_Ptrs *ptrs)') &&
            agentcore.includes('ILibDuktape_MeshAgent_RemoteDesktop_DiscardCachedStream(ctx, ptrs);'),
        dxgiCachedFramesAreBounded:
            tileSource.includes('static const int TILE_DXGI_IDLE_RESET_THRESHOLD = 4;') &&
            tileSource.includes('static int tile_dxgi_handle_idle_frame') &&
            tileSource.includes('tile_dxgi_schedule_retry_ex(gdiReason, 1);') &&
            dxgiCaptureBlock.includes('return tile_dxgi_handle_idle_frame(buffer, bufferSize, "gdi:dxgi-timeout", "dxgi:cached-timeout");') &&
            dxgiCaptureBlock.includes('return tile_dxgi_handle_idle_frame(buffer, bufferSize, "gdi:dxgi-no-present", "dxgi:cached-no-present");') &&
            dxgiCaptureBlock.includes('gDxgiCapture.idleFramePolls = 0;'),
        wgcIdleResetClearsCachedFrame:
            wgcIdleBlock.includes('tile_wgc_schedule_retry_ex(gdiReason, 1);'),
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

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        kvmHeaderPath,
        kvmSourcePath,
        tileSourcePath,
        inputSourcePath,
        agentcorePath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_remote_desktop_freshness_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
