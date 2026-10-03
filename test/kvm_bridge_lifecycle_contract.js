const fs = require('fs');
const path = require('path');

// Static contract for the Windows KVM session bridge lifecycle: per-session
// context isolation, nest-safe activation, bounded transport I/O, restart
// backoff, output framing validation, and the helper's input/shutdown path.

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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunction(source, signature) {
    // Skip forward declarations: the definition is the occurrence whose
    // signature is followed directly by the opening brace.
    let start = source.indexOf(signature);
    while (start >= 0 && !/^\s*\{/.test(source.slice(start + signature.length, start + signature.length + 8))) {
        start = source.indexOf(signature, start + signature.length);
    }
    assert(start >= 0, `${signature} definition not found`);
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

function countOccurrences(source, needle) {
    let count = 0;
    let index = source.indexOf(needle);
    while (index >= 0) {
        count += 1;
        index = source.indexOf(needle, index + needle.length);
    }
    return count;
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const bridgePath = path.resolve('meshservice', 'service_host.c');
    const kvm = fs.readFileSync(kvmPath, 'utf8').replace(/\r\n?/g, '\n');
    const kvmHeader = fs.readFileSync(kvmHeaderPath, 'utf8');
    const bridge = fs.readFileSync(bridgePath, 'utf8');

    const ensureLock = extractFunction(kvm, 'static void kvm_relay_ensure_registry_lock()');
    const lookup = extractFunction(kvm, 'static KvmRelayContext* kvm_relay_lookup_context(void* reserved)');
    const loadContext = extractFunction(kvm, 'static void kvm_relay_load_context(KvmRelayContext* ctx)');
    const activate = extractFunction(kvm, 'static void kvm_relay_activate_context(KvmRelayContext* ctx)');
    const deactivate = extractFunction(kvm, 'static void kvm_relay_deactivate_context()');
    const getContext = extractFunction(kvm, 'static KvmRelayContext* kvm_relay_get_context()');
    const cacheControl = extractFunction(kvm, 'static BOOL kvm_relay_cache_control_packet(KvmRelayContext* ctx, char* buffer, int bufferLen)');
    const respawn = extractFunction(kvm, 'static int kvm_relay_prepare_bridge_respawn_from_input(KvmRelayContext* ctx, char* buffer, int bufferLen, const char* reason, DWORD errorCode)');
    const writeInput = extractFunction(kvm, 'static BOOL kvm_relay_write_bridge_input(KvmRelayContext* ctx, char* buffer, int bufferLen)');
    const brokenPipe = extractFunction(kvm, 'static void kvm_relay_bridge_pipe_broken_handler(ILibProcessPipe_Pipe sender)');
    const consumeOutput = extractFunction(kvm, 'static void kvm_relay_consume_output_buffer(KvmRelayContext* ctx, char *buffer, size_t bufferLen, size_t* bytesConsumed)');
    const createPipe = extractFunction(kvm, 'static BOOL kvm_relay_create_bridge_server_pipeW(const WCHAR* pipeName, DWORD pipeOpenMode, HANDLE* pipeOut)');
    const verifyClient = extractFunction(kvm, 'static BOOL kvm_relay_verify_bridge_client(HANDLE pipeHandle, DWORD expectedPid, DWORD* errorOut)');
    const destroy = extractFunction(kvm, 'static void kvm_relay_destroy_context(KvmRelayContext* ctx)');
    const attach = extractFunction(kvm, 'static BOOL kvm_relay_attach_bridge_transport(KvmRelayContext* ctx, HANDLE inputPipeHandle, HANDLE outputPipeHandle)');
    const spawnSuccess = extractFunction(kvm, 'static void kvm_record_spawn_success(void *reserved, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler)');
    const healthy = extractFunction(kvm, 'static void kvm_record_healthy_output(void)');
    const retryTimer = extractFunction(kvm, 'static void kvm_retry_timer_callback(void* object)');
    const scheduleDelay = extractFunction(kvm, 'static void kvm_schedule_retry_timer_delay(DWORD delayMs)');
    const scheduleBackoff = extractFunction(kvm, 'static void kvm_schedule_retry_timer_at_least(DWORD minimumDelayMs)');
    const probeTimeout = extractFunction(kvm, 'static int kvm_relay_handle_refresh_probe_timeout(KvmRelayContext* ctx, const char* source)');
    const setPauseState = extractFunction(kvm, 'static BOOL kvm_relay_set_bridge_pause_state(KvmRelayContext* ctx, int normalizedPause, int forcePacket)');
    const restartAfterFailure = extractFunction(kvm, 'static void kvm_relay_schedule_restart_after_failure(DWORD restartError, const char* source)');
    const feeddata = extractFunction(kvm, 'int kvm_relay_feeddata(char* buf, int len, ILibKVM_WriteHandler writeHandler, void *reserved)');
    const pause = extractFunction(kvm, 'void kvm_pause(int pause, void *reserved)');
    const exitHandler = extractFunction(kvm, 'void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)');
    const stdoutHandler = extractFunction(kvm, 'void kvm_relay_StdOutHandler(ILibProcessPipe_Process sender, char *buffer, size_t bufferLen, size_t* bytesConsumed, void* user)');
    const restart = extractFunction(kvm, 'int kvm_relay_restart(int paused, void *pipeMgr, char *exePath, ILibKVM_WriteHandler writeHandler, void *reserved)');
    const setup = extractFunction(kvm, 'int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)');
    const cleanup = extractFunction(kvm, 'void kvm_cleanup(void *reserved)');
    const sessionChange = extractFunction(kvm, 'static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');
    const notify = extractFunction(kvm, 'void kvm_notify_session_change(DWORD eventType, DWORD sessionId)');
    const abortLaunch = extractFunction(kvm, 'static int kvm_relay_session_change_aborts_launch(const KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int startSessionUsable)');
    const snapshot = extractFunction(kvm, 'int kvm_bridge_debug_get_snapshot_for_reserved(void *reserved, KvmBridgeDebugSnapshot* snapshotOut)');
    const requestShutdown = extractFunction(kvm, 'void kvm_server_request_shutdown(void)');
    const inputThread = extractFunction(bridge, 'static DWORD WINAPI KvmBridge_InputThread(LPVOID user)');
    const bridgeEntry = extractFunction(bridge, 'void CALLBACK KvmSessionBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)');
    const shutdownCause = extractFunction(bridge, 'static DWORD KvmBridge_ShutdownCause(const ServiceKvmBridgeContext* ctx)');
    const setExitReason = extractFunction(kvm, 'static void kvm_server_set_exit_reason(DWORD reason)');
    const captureExitReason = extractFunction(kvm, 'static DWORD kvm_server_capture_exit_reason(DWORD captureFailure)');

    const checks = {
        callbackInstanceDoesNotSelectHelperModule:
            bridgeEntry.includes('ServiceHost_InitializePaths(NULL);') &&
            !bridgeEntry.includes('ServiceHost_InitializePaths(hinstDLL)'),
        registryLockInitializedOnce:
            ensureLock.includes('InitOnceExecuteOnce(&gKvmRelayLocksOnce, kvm_relay_initialize_locks, NULL, NULL);') &&
            !kvm.includes('gKvmRelayContextLockInitialized'),
        reservedLookupNeverFallsBackToAnotherSession:
            lookup.includes('return kvm_relay_get_registered_context(reserved);') &&
            getContext.includes('return gKvmActiveContext;') &&
            !getContext.includes('kvm_relay_lookup_context'),
        nestedActivationKeepsLiveGlobals:
            activate.includes('if (previous != NULL && previous == ctx) { return; }') &&
            activate.includes('if (previous != NULL) { kvm_relay_capture_context(previous); }') &&
            activate.includes('gKvmActivationStack[gKvmActivationDepth] = previous;') &&
            deactivate.includes('previous = gKvmActivationStack[gKvmActivationDepth];') &&
            deactivate.includes('if (previous == gKvmActiveContext) { return; }') &&
            deactivate.includes('kvm_relay_load_context(previous);') &&
            !deactivate.includes('kvm_relay_capture_context('),
        feeddataResolvesSessionUnderLockAndDropsOrphanInput:
            feeddata.indexOf('kvm_relay_lock();') >= 0 &&
            feeddata.indexOf('kvm_relay_lock();') < feeddata.indexOf('ctx = kvm_relay_find_context_by_reserved(reserved);') &&
            feeddata.includes('if (ctx == NULL && kvmConsoleMode == 0)') &&
            feeddata.includes('Dropping input for session without relay'),
        detachedBridgeInputCachesOnlyReplayableControl:
            feeddata.includes('!kvm_relay_input_is_replayable_after_respawn(buf, len) || !kvm_relay_cache_control_packet(ctx, buf, len)') &&
            cacheControl.includes('ctx->cachedControlPacketCount >= KVM_BRIDGE_MAX_CACHED_CONTROL_PACKETS') &&
            kvm.includes('#define KVM_BRIDGE_MAX_CACHED_CONTROL_PACKETS 64'),
        pauseResolvesSessionUnderLockAndRespawnsOnWriteFailure:
            pause.indexOf('kvm_relay_lock();') < pause.indexOf('ctx = kvm_relay_lookup_context(reserved);') &&
            pause.includes('if (ctx == NULL && reserved != NULL)') &&
            pause.includes('kvm_relay_prepare_bridge_respawn_from_input(ctx, NULL, 0, "pause-write-failed"'),
        cleanupIgnoresUnknownSessionAndDefersNestedDestroy:
            cleanup.includes('with no relay context consoleMode=%d') &&
            cleanup.includes('kvm_server_signal_remote_resume_waiters();') &&
            cleanup.includes('if (destroyNow && kvm_relay_context_is_active_in_outer_frame(ctx))') &&
            cleanup.includes('ILibLifeTime_AddEx(ILibGetBaseTimer(gILibChain), ctx, 0, &kvm_retry_timer_callback, NULL);'),
        nestedCleanupKeepsStoppingHelperForOuterCapture:
            // An outer frame that still has this context live captures the globals after
            // cleanup returns; cleanup must leave the helper it is stopping in them.
            cleanup.indexOf('ctx->childProcess = childProcessForExit;') > 0 &&
            cleanup.indexOf('ctx->childProcess = childProcessForExit;') < cleanup.lastIndexOf('kvm_relay_deactivate_context();') &&
            cleanup.lastIndexOf('kvm_relay_deactivate_context();') < cleanup.indexOf('if (gKvmActiveContext == ctx)\n\t{') &&
            cleanup.indexOf('if (gKvmActiveContext == ctx)\n\t{') < cleanup.indexOf('kvm_relay_load_context(ctx);') &&
            cleanup.indexOf('kvm_relay_load_context(ctx);') < cleanup.indexOf('if (destroyNow && kvm_relay_context_is_active_in_outer_frame(ctx))') &&
            loadContext.includes('gChildProcess = ctx->childProcess;'),
        bridgeInputWritesAreBounded:
            writeInput.includes('waitResult = WaitForSingleObject(overlapped.hEvent, KVM_BRIDGE_INPUT_WRITE_TIMEOUT_MS);') &&
            writeInput.includes('CancelIoEx(ctx->bridgeInputPipeHandle, &overlapped);') &&
            writeInput.includes('kvm_relay_abandon_stalled_bridge(ctx);') &&
            countOccurrences(writeInput, 'GetOverlappedResult(ctx->bridgeInputPipeHandle, &overlapped, &bytesWritten, TRUE)') === 1,
        failedLaunchesFreeUnattachedHelpers:
            !restart.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);') &&
            countOccurrences(restart, 'ILibProcessPipe_Process_HardKill(gChildProcess);') >= 7,
        bridgePipesAcceptOnlyTheSpawnedLocalHelper:
            createPipe.includes('FILE_FLAG_FIRST_PIPE_INSTANCE') &&
            createPipe.includes('PIPE_REJECT_REMOTE_CLIENTS') &&
            verifyClient.includes('GetNamedPipeClientProcessId(pipeHandle, &clientPid)') &&
            verifyClient.includes('(DWORD)clientPid != expectedPid') &&
            !restart.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);') &&
            restart.includes('kvm_relay_verify_bridge_client(ctx->bridgeInputPipeHandle, ILibProcessPipe_Process_GetPID(gChildProcess), &lastError)') &&
            restart.includes('kvm_relay_verify_bridge_client(ctx->bridgeOutputPipeHandle, ILibProcessPipe_Process_GetPID(gChildProcess), &lastError)'),
        outputFramingIsValidated:
            consumeOutput.includes('if (jumboLen < 4 || jumboLen > KVM_BRIDGE_MAX_JUMBO_PAYLOAD)') &&
            consumeOutput.includes('kvm_relay_fail_bridge_protocol(ctx, "jumbo-length"') &&
            consumeOutput.includes('else if (bufferLen >= 4)') &&
            consumeOutput.includes('kvm_relay_fail_bridge_protocol(ctx, "packet-length"') &&
            !consumeOutput.includes('(int)ntohl(') &&
            stdoutHandler.includes('Dropping unframed KVM stdout data') &&
            !stdoutHandler.includes('(int)ntohl('),
        healthyOutputResetsBackoffOnlyAfterStableRun:
            consumeOutput.includes('(GetTickCount64() - gKvmSessionStartTickMs) >= KVM_BRIDGE_HEALTHY_RESET_MS') &&
            consumeOutput.includes('kvm_record_healthy_output();') &&
            !healthy.includes('gKvmRetryScheduled = 0;') &&
            !spawnSuccess.includes('gKvmRetryScheduled = 0;') &&
            !spawnSuccess.includes('gKvmRegisteredContextCount ='),
        retryTimerKeepsEarliestDeadline:
            scheduleDelay.includes('if (gKvmRetryScheduled != 0 && gKvmRetryDueTickMs != 0 && gKvmRetryDueTickMs <= dueTickMs)') &&
            scheduleBackoff.includes('gKvmRestartNotBeforeTickMs = GetTickCount64() + (ULONGLONG)backoffDelayMs;') &&
            retryTimer.includes('if (gKvmRestartNotBeforeTickMs > now)') &&
            retryTimer.includes('kvm_schedule_retry_timer_delay(ageMs + KVM_REFRESH_PROBE_RECHECK_FLOOR_MS < KVM_REFRESH_PROBE_TIMEOUT_MS ?'),
        // A paused viewer has told the helper to stop sending pictures: the refresh probe is not timed
        // while paused, restarts its window on resume, and never re-arms below a floor (no spin).
        refreshProbeIgnoresPausedViewer:
            probeTimeout.includes('if (InterlockedCompareExchange(&ctx->bridgeProtocolPauseState, 0, 0) != 0) { return 0; }') &&
            retryTimer.includes('InterlockedCompareExchange(&ctx->bridgeProtocolPauseState, 0, 0) == 0') &&
            retryTimer.includes('KVM_REFRESH_PROBE_RECHECK_FLOOR_MS);') &&
            setPauseState.includes('if (previousState != 0 && normalizedPause == 0 && ctx == gKvmActiveContext') &&
            setPauseState.includes('gKvmPendingProbeSinceTickMs = GetTickCount64();'),
        // While a viewer is attached a failed launch is never final and the relay never gives up:
        // there is no restart limit and the viewer is not closed.
        failedRestartsBackOffAndKeepRetrying:
            restartAfterFailure.includes('if (restartError == ERROR_OPERATION_ABORTED) { return; }') &&
            restartAfterFailure.includes('++g_restartcount;') &&
            restartAfterFailure.includes('kvm_schedule_retry_timer_at_least(KVM_BRIDGE_MIN_RETRY_DELAY_MS);') &&
            retryTimer.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "timer");') &&
            sessionChange.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "session-change");') &&
            respawn.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "input");') &&
            setup.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "setup");') &&
            !kvm.includes('KVM_RESTART_LIMIT') &&
            !retryTimer.includes('closeWriteHandler') &&
            !respawn.includes('restart limit reached'),
        inputRespawnRespectsPendingBackoff:
            respawn.includes('if (gKvmRetryScheduled != 0 && gKvmRestartNotBeforeTickMs > GetTickCount64())') &&
            respawn.includes('service-mode KVM input respawn deferred to pending backoff'),
        brokenPipeReplacesHelperThatOutlivesTransport:
            brokenPipe.includes('kvm_schedule_retry_timer_delay(KVM_BRIDGE_BROKEN_PIPE_GRACE_MS);') &&
            retryTimer.includes('bridge helper outlived its transport pid=%u; terminating'),
        exitHandlerIgnoresSupersededHelperAndIntentionalKills:
            exitHandler.includes('bridge child exit ignored for superseded helper') &&
            exitHandler.includes('intentionalExit = (gKvmChildExitSignaled != 0);') &&
            exitHandler.includes('if (intentionalExit == 0 && ((exitCode != 0 && captureExitReason == NULL) || uptimeMs < KVM_BRIDGE_HEALTHY_RESET_MS))') &&
            exitHandler.includes('if (uptimeMs >= KVM_BRIDGE_HEALTHY_RESET_MS)') &&
            // Only a shut-down relay ends the viewer's stream; logoff or disconnect keeps it attached.
            exitHandler.includes('notifyClosed = (g_shutdown != 0) ? 1 : 0;'),
        // Uptime counts from this launch's attach: a helper that dies before attaching must not
        // inherit the previous helper's start and look healthy, which would clear the backoff.
        helperUptimeCountsFromThisLaunch:
            exitHandler.includes('uptimeMs = (gKvmSessionStartTickMs != 0) ? (GetTickCount64() - gKvmSessionStartTickMs) : 0;') &&
            /\+\+gKvmSpawnAttemptCount;[\s\S]*?gKvmSessionStartTickMs = 0;[\s\S]*?user->ctx = ctx;/.test(restart) &&
            spawnSuccess.includes('gKvmSessionStartTickMs = GetTickCount64();'),
        refreshProbeWindowStartsAtAttach:
            attach.includes('gKvmPendingProbeSinceTickMs = GetTickCount64();') &&
            kvm.includes('if (gKvmChildExitSignaled != 0) { return 0; }'),
        sessionChangeSignalsUnderSignalLockAndDispatchesOnChain:
            notify.includes('kvm_relay_signal_lock();') &&
            notify.includes('kvm_relay_signal_unlock();') &&
            !notify.includes('kvm_relay_lock();') &&
            !notify.includes('gKvmActiveContext') &&
            notify.includes('ILibChain_RunOnMicrostackThreadEx2(chain, kvm_relay_dispatch_session_change_on_chain, request, 1);') &&
            destroy.includes('kvm_relay_signal_lock();'),
        sessionLockKeepsHelperOnLockScreen:
            sessionChange.includes('if (eventType == WTS_SESSION_LOCK)') &&
            sessionChange.includes('session lock keeps KVM helper attached') &&
            !sessionChange.includes('case WTS_SESSION_LOCK:') &&
            sessionChange.indexOf('if (eventType == WTS_SESSION_LOCK)') < sessionChange.indexOf('gKvmRestartSuppressed = 1;') &&
            abortLaunch.includes('if (ctx == NULL || eventType == WTS_SESSION_LOCK) { return 0; }') &&
            sessionChange.includes('else if (gChildProcess != NULL && gKvmChildExitSignaled == 0)') &&
            kvm.includes('OpenDesktopW(L"Winlogon"'),
        // A failed first launch keeps the context registered and retries instead of orphaning the
        // viewer's stream; destroy still removes any timer keyed by the context.
        failedSetupKeepsContextAndRetries:
            setup.includes('g_shutdown = 0;') &&
            setup.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "setup");') &&
            !setup.includes('kvm_relay_unregister_context_locked(ctx);\n\t\t\tif (gILibChain != NULL') &&
            destroy.includes('if (timer != NULL) { ILibLifeTime_Remove(timer, ctx); }'),
        snapshotReadsUnderRelayLock:
            snapshot.indexOf('kvm_relay_lock();') < snapshot.indexOf('ctx = kvm_relay_find_context_by_reserved(reserved);') &&
            countOccurrences(snapshot, 'kvm_relay_unlock();') === 2,
        // Refusals and transport errors exit with their own codes so the relay logs the reason and backs
        // off; the code is the shutdown's cause, captured before cancelling I/O adds its own errors.
        helperExitsWithFailureCodes:
            bridgeEntry.includes('ExitProcess(ERROR_INVALID_PARAMETER);') &&
            bridgeEntry.includes('bridgeExitCode = KvmBridge_ErrorOr(GetLastError(), ERROR_PIPE_NOT_CONNECTED);') &&
            bridgeEntry.indexOf('bridgeExitCode = KvmBridge_ShutdownCause(&ctx);') >= 0 &&
            bridgeEntry.indexOf('bridgeExitCode = KvmBridge_ShutdownCause(&ctx);') <
                bridgeEntry.indexOf('KvmBridge_CancelTransportIo(&ctx, bridgeStdIn, bridgeStdOut);') &&
            bridgeEntry.includes('ExitProcess(bridgeExitCode);'),
        // A helper that cannot capture stops itself with a dedicated code (desktop out of reach,
        // capture failing, or capture never starting), so the relay can tell it from a crash or a
        // closed transport. Transport errors still take precedence as the cause.
        helperCaptureFailuresExitWithDedicatedCodes:
            kvmHeader.includes('#define KVM_HELPER_EXIT_DESKTOP_INACCESSIBLE\t0x20004B01UL') &&
            kvmHeader.includes('#define KVM_HELPER_EXIT_CAPTURE_FAILED\t\t\t0x20004B02UL') &&
            kvmHeader.includes('#define KVM_HELPER_EXIT_CAPTURE_STARTUP_FAILED\t0x20004B03UL') &&
            kvmHeader.includes('DWORD kvm_server_get_exit_reason(void);') &&
            setExitReason.includes('InterlockedCompareExchange(&gKvmServerExitReason, (LONG)reason, 0);') &&
            captureExitReason.includes('gKvmCaptureDesktopFailedStage != NULL') &&
            countOccurrences(kvm, 'kvm_server_set_exit_reason(') === 4 &&
            /if \(g_shutdown == 0\)\s*\{\s*DWORD exitReason = kvm_server_capture_exit_reason\(KVM_HELPER_EXIT_CAPTURE_FAILED\);[\s\S]*?kvm_server_set_exit_reason\(exitReason\);\s*\}\s*KVMDEBUG\("get_desktop_buffer\(\) failed, shutting down"[^\n]*\n\s*g_shutdown = 1;/.test(kvm) &&
            kvm.includes('InterlockedExchange(&gKvmServerExitReason, 0);') &&
            shutdownCause.indexOf('ctx->readError') < shutdownCause.indexOf('ctx->writeError') &&
            shutdownCause.indexOf('ctx->writeError') < shutdownCause.indexOf('kvm_server_get_exit_reason()') &&
            countOccurrences(bridgeEntry, 'bridgeExitCode = KvmBridge_ShutdownCause(&ctx);') === 2 &&
            !bridgeEntry.includes('bridgeExitCode = (ctx.readError != ERROR_SUCCESS) ? ctx.readError : ctx.writeError;'),
        // A capture exit after a healthy run restarts without backoff and is reported as a warning,
        // not as a broken start.
        relayReportsCaptureExitsSeparately:
            exitHandler.includes('const char* captureExitReason = kvm_helper_exit_reason_name((DWORD)exitCode);') &&
            exitHandler.includes('if (intentionalExit == 0 && captureExitReason != NULL)') &&
            exitHandler.includes('L"CAPTURE_UNAVAILABLE",\n\t\t\tEVENTLOG_WARNING_TYPE,') &&
            exitHandler.includes('if (exitCode != 0 && captureExitReason == NULL)') &&
            exitHandler.indexOf('if (intentionalExit == 0 && captureExitReason != NULL)') < exitHandler.indexOf('kvm_schedule_retry_timer();'),
        rejectedPipeClientsReachEventLog:
            countOccurrences(kvm, 'kvm_bridge_report_outcome_event(L"CLIENT_REJECTED"') === 2,
        helperShutdownWakesStartupResumeWait:
            kvmHeader.includes('void kvm_server_request_shutdown(void);') &&
            requestShutdown.includes('g_shutdown = 1;') &&
            requestShutdown.includes('kvm_server_signal_remote_resume_waiters();') &&
            bridgeEntry.includes('kvm_server_request_shutdown();') &&
            inputThread.includes('kvm_server_request_shutdown();'),
        helperInputReadsBlockInsteadOfPolling:
            bridgeEntry.includes('FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED') &&
            inputThread.includes('ReadFile(inputHandle, packetBuffer + len, (DWORD)(sizeof(packetBuffer) - len), NULL, &overlapped)') &&
            inputThread.includes('GetOverlappedResult(inputHandle, &overlapped, &read, TRUE)') &&
            inputThread.includes('CloseHandle(overlapped.hEvent);') &&
            !inputThread.includes('PeekNamedPipe(') &&
            !inputThread.includes('Sleep(')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `kvm bridge lifecycle contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: { kvmPath, kvmHeaderPath, bridgePath },
        checks
    };

    if (evidenceDir) {
        ensureDir(evidenceDir);
        fs.writeFileSync(path.join(evidenceDir, 'kvm_bridge_lifecycle_contract.json'), JSON.stringify(report, null, 2));
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
