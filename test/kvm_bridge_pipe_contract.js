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

function readSource(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
	const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
	const tilePath = path.resolve('meshcore', 'KVM', 'Windows', 'tile.cpp');
	const bridgePath = path.resolve('meshservice', 'stealth_svchost.c');
	const smokePath = path.resolve('test', 'rundll32_bridge_smoke.js');
	const kvmSource = readSource(kvmPath);
	const tileSource = readSource(tilePath);
	const bridgeSource = readSource(bridgePath);
	const smokeSource = readSource(smokePath);

    const checks = {
        masterBuildsGuidPipeBaseName: kvmSource.includes('\\\\\\\\.\\\\pipe\\\\MeshKvm_%ls'),
        masterBuildsInputAndOutputPipeNames: kvmSource.includes('kvm_relay_build_bridge_pipe_namesW') &&
            kvmSource.includes('L"%ls_in"') &&
            kvmSource.includes('L"%ls_out"'),
        masterUsesRestrictedPipeDacl: kvmSource.includes('KVM_BRIDGE_PIPE_DACL_SDDL = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)(A;;GA;;;SU)"') &&
            kvmSource.includes('ConvertStringSecurityDescriptorToSecurityDescriptorW(KVM_BRIDGE_PIPE_DACL_SDDL'),
        masterCreatesDirectionalOverlappedPipes: kvmSource.includes('static BOOL kvm_relay_create_bridge_server_pipeW(const WCHAR* pipeName, DWORD pipeOpenMode, HANDLE* pipeOut)') &&
            kvmSource.includes('pipeOpenMode | FILE_FLAG_OVERLAPPED') &&
            kvmSource.includes('kvm_relay_create_bridge_server_pipeW(bridgeInputPipeNameW, PIPE_ACCESS_OUTBOUND, &ctx->bridgeInputPipeHandle)') &&
            kvmSource.includes('kvm_relay_create_bridge_server_pipeW(bridgeOutputPipeNameW, PIPE_ACCESS_INBOUND, &ctx->bridgeOutputPipeHandle)'),
        masterUsesExplicitPipeBuffers: kvmSource.includes('DWORD pipeBufferSize = 1024 * 1024;') &&
            (kvmSource.includes('pipeBufferSize,\n\t\tpipeBufferSize,') || kvmSource.includes('pipeBufferSize,\r\n\t\tpipeBufferSize,')),
        masterWaitsAsyncForPipeClient: kvmSource.includes('ConnectNamedPipe(pipeHandle, &overlapped)') && kvmSource.includes('ERROR_IO_PENDING'),
        masterAttachesAsyncReadPipeTransportAndDedicatedWriteHandle: kvmSource.includes('ILibProcessPipe_Pipe_CreateFromExisting(ctx->pipeMgr, duplicatedOutputPipe') &&
            kvmSource.includes('ctx->bridgeInputPipeHandle == NULL || ctx->bridgeInputPipeHandle == INVALID_HANDLE_VALUE') &&
            kvmSource.includes('WriteFile(ctx->bridgeInputPipeHandle, buffer, (DWORD)bufferLen, NULL, &overlapped)'),
        masterReadsPacketsFromPipe: kvmSource.includes('kvm_relay_bridge_pipe_read_handler') && kvmSource.includes('kvm_relay_consume_output_buffer'),
        masterWritesInputToPipe: kvmSource.includes('static BOOL kvm_relay_write_bridge_input(KvmRelayContext* ctx, char* buffer, int bufferLen)') &&
            kvmSource.includes('kvm_relay_write_bridge_input(ctx, buf, len)') &&
            kvmSource.includes('kvm_relay_write_bridge_input(ctx, packet->buffer, packet->bufferLen)'),
        masterWritesPausePacketsToPipe: kvmSource.includes('static BOOL kvm_relay_write_bridge_pause(KvmRelayContext* ctx, int pause)') && kvmSource.includes('MNG_KVM_PAUSE') && kvmSource.includes('kvm_relay_write_bridge_pause(ctx, normalizedPause)'),
        slaveStartupPacketsHonorWriteBackpressure:
            kvmSource.includes('static ILibTransport_DoneState kvm_server_write_packet_checked(') &&
            kvmSource.includes('static int kvm_server_wait_for_remote_resume(') &&
            kvmSource.includes('kvm_server_write_packet_checked(writeHandler, (char*)buffer, 8, reserved, "resolution")') &&
            kvmSource.includes('kvm_server_write_packet_checked(writeHandler, (char*)buffer, 8, reserved, "refresh-resolution")') &&
            kvmSource.includes('kvm_server_write_packet_checked(writeHandler, dwData + 4') &&
            kvmSource.includes('kvm_server_write_packet_checked(writeHandler, (char*)buf, (int)tilesize, reserved, "picture")') &&
            kvmSource.includes('kvm_server_wait_for_remote_resume("startup-output")') &&
            kvmSource.includes('kvm_server_set_remote_pause_state(block[4])') &&
            kvmSource.includes('g_pause = 1;') &&
            kvmSource.includes('ILibTransport_DoneState_ERROR') &&
            !kvmSource.includes('Pausing here seems to fix connection issues') &&
            !kvmSource.includes('Sleep(100); // Pausing here'),
		slaveSerializesSharedTileState:
			kvmSource.includes('static INIT_ONCE gKvmTileInfoLockOnce = INIT_ONCE_STATIC_INIT;') &&
            kvmSource.includes('static CRITICAL_SECTION gKvmTileInfoLock;') &&
            kvmSource.includes('static LONG gKvmTileInfoGeneration = 0;') &&
            kvmSource.includes('InitOnceExecuteOnce(&gKvmTileInfoLockOnce, kvm_server_initialize_tile_info_lock, NULL, NULL)') &&
            kvmSource.includes('static struct tileInfo_t **kvm_server_allocate_tile_info(') &&
            kvmSource.includes('static int kvm_server_reset_tile_info_locked(') &&
            kvmSource.includes('oldTileInfo = tileInfo;') &&
            kvmSource.includes('tileInfo = newTileInfo;') &&
            kvmSource.includes('InterlockedIncrement(&gKvmTileInfoGeneration);') &&
            kvmSource.includes('captureTileGeneration = InterlockedCompareExchange(&gKvmTileInfoGeneration, 0, 0);') &&
            kvmSource.includes('kvm_server_reset_tile_info_locked("startup-crc", 1, 0)') &&
            kvmSource.includes('kvm_server_reset_tile_info_locked("refresh", 1, 0)') &&
            kvmSource.includes('kvm_server_reset_tile_info_locked("frame-scan"') &&
			kvmSource.includes('kvm_server_free_tile_info(cleanupTileInfo, cleanupTileHeightCount)') &&
			!kvmSource.includes('ILIBCRITICALEXIT(254)'),
		slaveSkipsCaptureWhenDesktopUnavailable:
			kvmSource.includes('int gKvmDesktopCaptureReady = 1;') &&
			kvmSource.includes('int desktopAccessReady = 1;') &&
			kvmSource.includes('desktopAccessReady = 0;') &&
			kvmSource.includes('gKvmDesktopCaptureReady = desktopAccessReady;') &&
			tileSource.includes('extern int gKvmDesktopCaptureReady;') &&
			tileSource.includes('if (!gKvmDesktopCaptureReady)') &&
			tileSource.includes('KVM capture: target desktop is not accessible; skipping capture backends'),
		runtimeSmokeRejectsTimeoutExit:
			smokeSource.includes('bridge log used timeout-based helper exit') &&
			smokeSource.includes("line.includes('KvmSessionBridgeW mainloop exited') ||") &&
			!smokeSource.includes("line.includes('KvmSessionBridgeW mainloop shutdown timed out after')),\n\t\t\t'bridge log missing controlled exit line'"),
		masterWaitsAndAttachesPipeInLiveSpawnPath: kvmSource.includes('!kvm_relay_build_bridge_pipe_namesW(bridgeInputPipeNameW') &&
            kvmSource.includes('!kvm_relay_create_bridge_server_pipeW(bridgeInputPipeNameW, PIPE_ACCESS_OUTBOUND, &ctx->bridgeInputPipeHandle)') &&
            kvmSource.includes('!kvm_relay_create_bridge_server_pipeW(bridgeOutputPipeNameW, PIPE_ACCESS_INBOUND, &ctx->bridgeOutputPipeHandle)') &&
            kvmSource.includes('!kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeInputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange)') &&
            kvmSource.includes('!kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeOutputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange)') &&
            kvmSource.includes('InterlockedExchange(&ctx->childUsesBridge, 1);') &&
            kvmSource.includes('!kvm_relay_attach_bridge_transport(ctx, ctx->bridgeInputPipeHandle, ctx->bridgeOutputPipeHandle)'),
        slaveParsesPipeArguments: bridgeSource.includes('static int Stealth_KvmBridgeExtractPipeNamesW(') &&
            bridgeSource.includes('_wcsnicmp(tokenBuffer, L"\\\\\\\\.\\\\pipe\\\\", 9) != 0') &&
            bridgeSource.includes('destination = (pipeCount == 0) ? controlPipeName : dataPipeName;'),
        slaveConnectsDirectionalPipes: bridgeSource.includes('CreateFileW(controlPipeName, GENERIC_READ') &&
            bridgeSource.includes('CreateFileW(dataPipeName, GENERIC_WRITE'),
        slaveRejectsLegacySinglePipeFallback: bridgeSource.includes('rejected unsupported transport contract') &&
            !bridgeSource.includes('useLegacySinglePipeBridge') &&
            !bridgeSource.includes('CreateFileW(controlPipeName, GENERIC_READ | GENERIC_WRITE'),
        slaveRedirectsPipeToStdHandles: bridgeSource.includes('SetStdHandle(STD_INPUT_HANDLE, bridgeStdIn)') && bridgeSource.includes('SetStdHandle(STD_OUTPUT_HANDLE, bridgeStdOut)')
            && bridgeSource.includes('kvmConsoleMode = 1;')
            && bridgeSource.includes('return kvm_server_mainloop(mainloopParam);')
            && bridgeSource.includes('mainloopParam[0] = Stealth_KvmBridgeWriteSink;')
            && bridgeSource.includes('mainloopParam[1] = &ctx;')
            && bridgeSource.includes('Stealth_KvmBridgeInputThread')
            && bridgeSource.includes('inputThread == NULL && ctx.firstOutputLogged != 0 && g_shutdown == 0')
            && bridgeSource.includes('KvmSessionBridgeW input thread started after first output')
            && bridgeSource.includes('KvmSessionBridgeW input pipe closed')
            && bridgeSource.includes('PeekNamedPipe(inputHandle')
            && bridgeSource.includes('static BOOL Stealth_KvmBridgePipeDisconnected(')
            && bridgeSource.includes('GetNamedPipeHandleStateW(pipeHandle')
            && bridgeSource.includes('KvmSessionBridgeW control pipe disconnected')
            && bridgeSource.includes('KvmSessionBridgeW data pipe disconnected')
            && !bridgeSource.includes('We do NOT create a second Stealth_KvmBridgeInputThread')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `named-pipe contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
		files: {
			kvmPath,
			tilePath,
			smokePath,
			bridgePath
		},
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_pipe_contract.json'), report);
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
