const fs = require('fs');
const path = require('path');

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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const bridgePath = path.resolve('meshservice', 'stealth_svchost.c');
    const agentcoreSource = fs.readFileSync(agentcorePath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const bridgeSource = fs.readFileSync(bridgePath, 'utf8');
    const closeBridgeStart = kvmSource.indexOf('static void kvm_relay_close_bridge_transport(KvmRelayContext* ctx)');
    const closeBridgeEnd = closeBridgeStart >= 0 ? kvmSource.indexOf('\nstatic BOOL kvm_relay_resolve_rundll32_pathW', closeBridgeStart) : -1;
    const closeBridgeBlock = (closeBridgeStart >= 0 && closeBridgeEnd > closeBridgeStart) ? kvmSource.slice(closeBridgeStart, closeBridgeEnd) : '';

    const checks = {
        agentcoreMapsPausedWriteToIncomplete:
            /ILibDuktape_DuplexStream_WriteData\(ptrs->stream,\s*buffer,\s*bufferLen\)\s*==\s*0\)\s*\?\s*ILibTransport_DoneState_COMPLETE\s*:\s*ILibTransport_DoneState_INCOMPLETE/.test(agentcoreSource),
        agentcoreChainHopIsExplicitAndNoLegacyPretendSuccess:
            agentcoreSource.includes('ILibChain_RunOnMicrostackThreadEx3(duk_ctx_chain(ptrs->ctx), ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink_Chain, NULL, bstate);') &&
            !agentcoreSource.includes("return ILibTransport_DoneState_COMPLETE;\t\t// Always returning complete, because we'll let the stream object handle flow control"),
        bridgePauseUsesProtocolPacket: kvmSource.includes('static BOOL kvm_relay_write_bridge_pause(KvmRelayContext* ctx, int pause)') &&
            kvmSource.includes('((unsigned short*)pausePacket)[0] = (unsigned short)htons((unsigned short)MNG_KVM_PAUSE);'),
        masterBridgePauseRoutesOverPipe: kvmSource.includes('static BOOL kvm_relay_set_bridge_pause_state(KvmRelayContext* ctx, int normalizedPause, int forcePacket)') &&
            kvmSource.includes('if ((forcePacket != 0 || previousState != normalizedPause) && !kvm_relay_write_bridge_pause(ctx, normalizedPause))'),
        masterSyncsInitialBridgePauseState: kvmSource.includes('if (!kvm_relay_set_bridge_pause_state(ctx, 0, 1))'),
        masterPausesBridgeReadPipeOnBackpressure: kvmSource.includes('ILibProcessPipe_Pipe_Pause(ctx->bridgeReadPipe);') &&
            kvmSource.includes('ILibProcessPipe_Pipe_Resume(ctx->bridgeReadPipe);'),
        bridgeReadHandlerHonorsDownstreamBackpressure: kvmSource.includes('writeState = writeHandler(buffer, size, reserved);') &&
            kvmSource.includes('case ILibTransport_DoneState_INCOMPLETE:') &&
            kvmSource.includes('kvm_relay_set_bridge_pause_state(ctx, 1, 0);'),
        setupSeedsPausedBridgeState: kvmSource.includes('InterlockedExchange(&ctx->bridgeProtocolPauseState, 1);') &&
            kvmSource.includes('g_pause = 1;') &&
            kvmSource.includes('kvm_relay_reset_cached_control_state(ctx);'),
        restartPreservesDesiredPauseStateForFreshSpawn: kvmSource.includes('int desiredPause = (paused != 0 ? 1 : 0);') &&
            kvmSource.includes('desiredPause = kvm_relay_get_bridge_pause_state(ctx);') &&
            kvmSource.includes('InterlockedExchange(&ctx->bridgeProtocolPauseState, desiredPause);'),
        closeBridgeNoLongerForcesPauseReset: closeBridgeBlock.length > 0 &&
            !closeBridgeBlock.includes('InterlockedExchange(&ctx->bridgeProtocolPauseState, 1);'),
        pauseSinkStoresDesiredPauseOnContext: kvmSource.includes('if (gChildProcess == NULL)') &&
            kvmSource.includes('g_pause = normalizedPause;') &&
            kvmSource.includes('InterlockedExchange(&ctx->bridgeProtocolPauseState, normalizedPause);'),
        preAttachBridgeInputIsCachedNotMisrouted: kvmSource.includes('if (childUsesBridge != 0)') &&
            kvmSource.includes('kvm_relay_cache_control_packet(ctx, buf, len)') &&
            kvmSource.includes('Dropping pre-attach bridge input'),
        cachedBridgeStateReplaysAfterAttach: kvmSource.includes('static BOOL kvm_relay_flush_cached_control_packets(KvmRelayContext* ctx)') &&
            kvmSource.includes('if (bridgeClientConnected && bridgeTransportAttached && !kvm_relay_flush_cached_control_packets(ctx))') &&
            kvmSource.includes('if (!kvm_relay_flush_cached_control_packets(ctx))'),
        slaveWaitsOnLocalPauseOnly: kvmSource.includes('while (!g_shutdown && g_pause != 0)') &&
            !kvmSource.includes('while (!g_shutdown && (g_pause != 0 || g_remotepause != 0))'),
        slaveRecordsRemotePauseRequests: kvmSource.includes('g_remotepause = block[4];') &&
            kvmSource.includes('"KVM [SLAVE]: Remote %s requested"'),
        bridgeWriteSinkFailsOnBrokenPipe: bridgeSource.includes('outputHandle = (ctx->stdOutHandle != NULL && ctx->stdOutHandle != INVALID_HANDLE_VALUE) ? ctx->stdOutHandle : ctx->dataPipeHandle;') &&
            bridgeSource.includes('if (!WriteFile(outputHandle, buffer, (DWORD)bufferLen, &written, NULL))') &&
            bridgeSource.includes('ctx->writeError = GetLastError();') &&
            bridgeSource.includes('if (ctx->writeError == ERROR_SUCCESS) { ctx->writeError = ERROR_BROKEN_PIPE; }') &&
            bridgeSource.includes('if (written != (DWORD)bufferLen)') &&
            bridgeSource.includes('ctx->writeError = ERROR_WRITE_FAULT;') &&
            bridgeSource.includes('return ILibTransport_DoneState_ERROR;') &&
            bridgeSource.includes('return ILibTransport_DoneState_COMPLETE;'),
        bridgeChildPreservesUpstreamPauseModeSelection: bridgeSource.includes('if (Stealth_KvmBridgeHasTokenW(cmdLine, L"-kvm0"))') &&
            bridgeSource.includes('StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm0");') &&
            bridgeSource.includes('StringCchCopyW(ctx->arg1, _countof(ctx->arg1), L"-kvm1");')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `flow-control contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            agentcorePath,
            kvmPath,
            bridgePath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_flow_control_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
