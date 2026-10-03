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

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} not found`);
    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${signature} body start not found`);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        const ch = source[i];
        if (ch === '{') {
            depth += 1;
        } else if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`${signature} body end not found`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
	const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
	const tilePath = path.resolve('meshcore', 'KVM', 'Windows', 'tile.cpp');
	const bridgePath = path.resolve('meshservice', 'service_host.c');
	const smokePath = path.resolve('test', 'runtime_host_bridge_smoke.js');
	const kvmSource = readSource(kvmPath);
	const tileSource = readSource(tilePath);
	const bridgeSource = readSource(bridgePath);
	const smokeSource = readSource(smokePath);
	const pipeSddlBody = extractFunction(kvmSource, 'static BOOL kvm_relay_build_bridge_pipe_sddlW(WCHAR* sddl, size_t sddlLen)');
	const pipeCreateBody = extractFunction(kvmSource, 'static BOOL kvm_relay_create_bridge_server_pipeW(const WCHAR* pipeName, DWORD pipeOpenMode, HANDLE* pipeOut)');
	const verifyClientBody = extractFunction(kvmSource, 'static BOOL kvm_relay_verify_bridge_client(HANDLE pipeHandle, DWORD expectedPid, DWORD* errorOut)');
	const writeInputBody = extractFunction(kvmSource, 'static BOOL kvm_relay_write_bridge_input(KvmRelayContext* ctx, char* buffer, int bufferLen)\n{');
	const abandonStalledBody = extractFunction(kvmSource, 'static void kvm_relay_abandon_stalled_bridge(KvmRelayContext* ctx)');
	const inputDataBody = extractFunction(kvmSource, 'int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void *reserved)');
	const refreshCaseStart = inputDataBody.indexOf('case MNG_KVM_REFRESH:');
	assert(refreshCaseStart >= 0, 'MNG_KVM_REFRESH case not found');
	const refreshCaseEnd = inputDataBody.indexOf('case ', refreshCaseStart + 'case MNG_KVM_REFRESH:'.length);
	const refreshCaseBody = inputDataBody.slice(refreshCaseStart, refreshCaseEnd > refreshCaseStart ? refreshCaseEnd : undefined);
	const refreshHeaderBody = extractFunction(kvmSource, 'static int kvm_server_send_refresh_header(ILibKVM_WriteHandler writeHandler, void *reserved)');
	const captureLoopBody = extractFunction(kvmSource, 'DWORD WINAPI kvm_server_mainloop_ex(LPVOID parm)');
	const frameScanLockIndex = captureLoopBody.indexOf('kvm_server_enter_tile_info_lock("frame-scan")');
	const frameScanGenerationIndex = captureLoopBody.indexOf('if (captureTileGeneration != InterlockedCompareExchange(&gKvmTileInfoGeneration, 0, 0))', frameScanLockIndex);
	const refreshResetIndex = captureLoopBody.indexOf('kvm_server_reset_tile_info_locked("refresh", 1, 0)');
	const frameScanResetIndex = captureLoopBody.indexOf('kvm_server_reset_tile_info_locked("frame-scan"');
	const frameScanUnlockIndex = captureLoopBody.indexOf('kvm_server_leave_tile_info_lock();', frameScanResetIndex);
	const refreshConsumeIndex = captureLoopBody.indexOf('if (InterlockedExchange(&gKvmRefreshRequested, 0) != 0)');

    const checks = {
        masterBuildsGuidPipeBaseName: kvmSource.includes('\\\\\\\\.\\\\pipe\\\\MeshKvm_%ls'),
        masterBuildsInputAndOutputPipeNames: kvmSource.includes('kvm_relay_build_bridge_pipe_namesW') &&
            kvmSource.includes('L"%ls_in"') &&
            kvmSource.includes('L"%ls_out"'),
        masterRestrictsPipeDaclToServiceAccount: kvmSource.includes('#define KVM_BRIDGE_PIPE_DACL_SDDL L"D:P(A;;GA;;;SY)"') &&
            pipeSddlBody.includes('OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)') &&
            pipeSddlBody.includes('GetTokenInformation(token, TokenUser, &tokenUser') &&
            pipeSddlBody.includes('IsWellKnownSid(tokenUser.user.User.Sid, WinLocalSystemSid)') &&
            pipeSddlBody.includes('ConvertSidToStringSidW(tokenUser.user.User.Sid, &sidText)') &&
            pipeCreateBody.includes('kvm_relay_build_bridge_pipe_sddlW(pipeDaclSddl, _countof(pipeDaclSddl))') &&
            pipeCreateBody.includes('ConvertStringSecurityDescriptorToSecurityDescriptorW(pipeDaclSddl') &&
            !kvmSource.includes(';;;IU)') &&
            !kvmSource.includes(';;;SU)'),
        masterPipesAreLocalAndFirstInstance: pipeCreateBody.includes('pipeOpenMode | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE') &&
            pipeCreateBody.includes('PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS'),
        masterVerifiesPipeClientIsLaunchedHelper: verifyClientBody.includes('GetNamedPipeClientProcessId(pipeHandle, &clientPid)') &&
            verifyClientBody.includes('(DWORD)clientPid != expectedPid') &&
            verifyClientBody.includes('errorCode = ERROR_ACCESS_DENIED;') &&
            kvmSource.includes('!kvm_relay_verify_bridge_client(ctx->bridgeInputPipeHandle, ILibProcessPipe_Process_GetPID(gChildProcess), &lastError)') &&
            kvmSource.includes('!kvm_relay_verify_bridge_client(ctx->bridgeOutputPipeHandle, ILibProcessPipe_Process_GetPID(gChildProcess), &lastError)') &&
            kvmSource.indexOf('!kvm_relay_verify_bridge_client(ctx->bridgeInputPipeHandle') < kvmSource.indexOf('!kvm_relay_attach_bridge_transport(ctx, ctx->bridgeInputPipeHandle, ctx->bridgeOutputPipeHandle)') &&
            kvmSource.indexOf('!kvm_relay_verify_bridge_client(ctx->bridgeOutputPipeHandle') < kvmSource.indexOf('!kvm_relay_attach_bridge_transport(ctx, ctx->bridgeInputPipeHandle, ctx->bridgeOutputPipeHandle)'),
        masterBoundsBridgeInputWrites: kvmSource.includes('#define KVM_BRIDGE_INPUT_WRITE_TIMEOUT_MS 2000') &&
            writeInputBody.includes('WaitForSingleObject(overlapped.hEvent, KVM_BRIDGE_INPUT_WRITE_TIMEOUT_MS)') &&
            writeInputBody.includes('CancelIoEx(ctx->bridgeInputPipeHandle, &overlapped)') &&
            writeInputBody.indexOf('CancelIoEx(ctx->bridgeInputPipeHandle, &overlapped)') < writeInputBody.indexOf('GetOverlappedResult(ctx->bridgeInputPipeHandle, &overlapped, &bytesWritten, TRUE)') &&
            writeInputBody.includes('GetOverlappedResult(ctx->bridgeInputPipeHandle, &overlapped, &bytesWritten, FALSE)') &&
            writeInputBody.includes('kvm_relay_abandon_stalled_bridge(ctx);'),
        masterTerminatesStalledHelper: abandonStalledBody.includes('InterlockedExchange(&ctx->bridgeTransportAttached, 0);') &&
            abandonStalledBody.includes('ILibProcessPipe_Process_SoftKill(childProcess);'),
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
		// The frame scan holds the tile lock across blocking output writes, so the
		// input path (bridge input thread, kvm_mainloopinput_ex, chain thread) must
		// only flag a refresh; the capture thread answers it and resets the CRCs.
		slaveRefreshDoesNotTakeTileLockOnInputPath:
			kvmSource.includes('static volatile LONG gKvmRefreshRequested = 0;') &&
			refreshCaseBody.includes('InterlockedExchange(&gKvmRefreshRequested, 1);') &&
			!refreshCaseBody.includes('tile_info_lock') &&
			!refreshCaseBody.includes('reset_tile_info') &&
			!refreshCaseBody.includes('writeHandler') &&
			!refreshCaseBody.includes('kvm_send_display_list') &&
			refreshHeaderBody.includes('MNG_KVM_SCREEN') &&
			refreshHeaderBody.includes('kvm_send_display_list(writeHandler, reserved);') &&
			captureLoopBody.includes('InterlockedExchange(&gKvmRefreshRequested, 0);') &&
			refreshConsumeIndex >= 0 &&
			captureLoopBody.includes('if (!kvm_server_send_refresh_header(writeHandler, reserved)) { break; }') &&
			refreshConsumeIndex < frameScanLockIndex &&
			frameScanLockIndex < frameScanGenerationIndex &&
			frameScanGenerationIndex < refreshResetIndex &&
			refreshResetIndex < frameScanResetIndex &&
			frameScanResetIndex < frameScanUnlockIndex &&
			captureLoopBody.includes('InterlockedCompareExchange(&gKvmRefreshRequested, 0, 0) == 0'),
		slaveSkipsCaptureWhenDesktopUnavailable:
			kvmSource.includes('int gKvmDesktopCaptureReady = 1;') &&
			kvmSource.includes('result->accessible = 0;') &&
			kvmSource.includes('gKvmDesktopCaptureReady = bind.accessible;') &&
			tileSource.includes('extern int gKvmDesktopCaptureReady;') &&
			tileSource.includes('if (!gKvmDesktopCaptureReady)') &&
			tileSource.includes('KVM capture: target desktop is not accessible; skipping GDI capture'),
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
        slaveParsesPipeArguments: bridgeSource.includes('static int KvmBridge_ExtractPipeNamesW(') &&
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
            && bridgeSource.includes('mainloopParam[0] = KvmBridge_WriteSink;')
            && bridgeSource.includes('mainloopParam[1] = &ctx;')
            && bridgeSource.includes('KvmBridge_InputThread')
            && bridgeSource.includes('inputThread == NULL && ctx.firstOutputLogged != 0 && g_shutdown == 0')
            && bridgeSource.includes('KvmSessionBridgeW input thread started after first output')
            && bridgeSource.includes('KvmSessionBridgeW input pipe closed')
            && bridgeSource.includes('CreateFileW(controlPipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL)')
            && bridgeSource.includes('ReadFile(inputHandle, packetBuffer + len, (DWORD)(sizeof(packetBuffer) - len), NULL, &overlapped)')
            && bridgeSource.includes('GetOverlappedResult(inputHandle, &overlapped, &read, TRUE)')
            && !bridgeSource.includes('PeekNamedPipe(inputHandle')
            && bridgeSource.includes('static BOOL KvmBridge_PipeDisconnected(')
            && bridgeSource.includes('GetNamedPipeHandleStateW(pipeHandle')
            && bridgeSource.includes('KvmSessionBridgeW control pipe disconnected')
            && bridgeSource.includes('KvmSessionBridgeW data pipe disconnected')
            && !bridgeSource.includes('We do NOT create a second KvmBridge_InputThread')
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
