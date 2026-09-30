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
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const svchostPath = path.resolve('meshservice', 'service_host.c');
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8').replace(/\r\n?/g, '\n');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const svchostSource = fs.readFileSync(svchostPath, 'utf8');
    const relaySetupBody = extractFunction(kvmSource, 'int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)');
    const sessionChangeBody = extractFunction(kvmSource, 'static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');
    const sessionNotifyBody = extractFunction(kvmSource, 'void kvm_notify_session_change(DWORD eventType, DWORD sessionId)');
    const sessionDispatchBody = extractFunction(kvmSource, 'static void kvm_relay_dispatch_session_change_on_chain(void* chain, void* user)');
    const destroyContextBody = extractFunction(kvmSource, 'static void kvm_relay_destroy_context(KvmRelayContext* ctx)');
    const sessionClassifierBody = extractFunction(kvmSource, 'static int kvm_relay_session_change_affects_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int queryUserToken, int* ignoreReasonOut)');
    const abortLaunchBody = extractFunction(kvmSource, 'static int kvm_relay_session_change_aborts_launch(const KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int startSessionUsable)');
    const sessionMatchBody = extractFunction(kvmSource, 'static int kvm_relay_session_matches_context(const KvmRelayContext* ctx, DWORD sessionId)');
    const exitHandlerBody = extractFunction(kvmSource, 'void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)');
    const bindChainBody = extractFunction(kvmSource, 'static void kvm_relay_bind_dispatch_chain(void* chain)');
    const chainDestroyedBody = extractFunction(kvmSource, 'static void kvm_relay_dispatch_chain_destroyed(void* chain, void* user)');
    const retryTimerBody = extractFunction(kvmSource, 'static void kvm_retry_timer_callback(void* object)');
    const sessionArmBody = extractFunction(kvmSource, 'static int kvm_relay_arm_session_change_wait(KvmRelayContext* ctx, LONG expectedGeneration, HANDLE* eventOut, DWORD* errorOut)');
    const pipeWaitBody = extractFunction(kvmSource, 'static BOOL kvm_relay_wait_for_bridge_client(KvmRelayContext* ctx, HANDLE bridgePipeHandle, DWORD timeoutMs, LONG expectedSessionGeneration, DWORD* errorOut, BOOL* sessionChangedOut)');
    const svchostControlBody = extractFunction(svchostSource, 'DWORD WINAPI ServiceHost_CtrlHandler(');
    const armFirstGenerationCheck = sessionArmBody.indexOf('if (kvm_relay_session_generation_changed(ctx, expectedGeneration))');
    const armResetEvent = sessionArmBody.indexOf('ResetEvent(eventHandle);');
    const armSecondGenerationCheck = sessionArmBody.indexOf('if (kvm_relay_session_generation_changed(ctx, expectedGeneration))', armResetEvent);

    const checks = {
        headerExportsSessionChangeHook: kvmHeaderSource.includes('void kvm_notify_session_change(DWORD eventType, DWORD sessionId);'),
        serviceMainForwardsSessionChanges: serviceMainSource.includes('kvm_notify_session_change(eventType, sessionId);'),
        svchostForwardsSessionChanges:
            svchostControlBody.includes('case SERVICE_CONTROL_SESSIONCHANGE:') &&
            svchostControlBody.includes('WTSSESSION_NOTIFICATION* sessionNotification = (WTSSESSION_NOTIFICATION*)lpEventData;') &&
            svchostControlBody.includes('sessionId = sessionNotification->dwSessionId;') &&
            svchostControlBody.includes('ServiceUtil_DebugPrintfA("[svchost] Forwarding KVM session change event=%lu session=%lu"') &&
            svchostControlBody.includes('kvm_notify_session_change(dwEventType, sessionId);'),
        svchostMirrorsServiceSessionChangeForwarding:
            svchostSource.includes('#include "service_integration.h"') &&
            svchostControlBody.includes('ServiceIntegration_HandleSessionChange(dwEventType, sessionId);'),
        svchostControlHandlerDefersFinalStopToServiceMain:
            svchostControlBody.includes('ServiceHost_RequestAgentStop();') &&
            svchostControlBody.includes('Stop requested asynchronously; waiting for MeshAgent_Start to return') &&
            svchostControlBody.includes('Shutdown requested asynchronously; waiting for MeshAgent_Start to return') &&
            !svchostControlBody.includes('MeshAgent_Stop(g_ServiceHostAgent);') &&
            !svchostControlBody.includes('g_ServiceHostAgent = NULL;') &&
            !svchostControlBody.includes('g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;') &&
            svchostSource.includes('ILibChain_RunOnMicrostackThreadEx3(agent->chain, ServiceHost_StopAgentOnChain, NULL, NULL);') &&
            svchostSource.includes('int startResult = MeshAgent_Start(g_ServiceHostAgent, startArgc, startArgv);') &&
            svchostSource.includes('g_ServiceHostAgent = NULL;') &&
            svchostSource.includes('g_ServiceHostStatus.dwCurrentState = SERVICE_STOPPED;'),
        relayDefinesSessionChangeDispatcher: kvmSource.includes('static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)'),
        relayDispatchesSessionChangesPerContext:
            sessionDispatchBody.includes('kvm_relay_lock();') &&
            sessionDispatchBody.includes('snapshot[i] = gKvmRelayContexts[i];') &&
            sessionDispatchBody.includes('kvm_relay_handle_session_change_for_context(snapshot[i], request->eventType, request->sessionId);') &&
            sessionDispatchBody.includes('kvm_relay_unlock();') &&
            sessionDispatchBody.includes('free(request);'),
        // Only an event that makes an in-flight launch pointless aborts it: a stop of the context's
        // session, or a start that moves an auto-selected context to another session. A lock never does.
        relaySignalsOnlyLaunchInvalidatingEvents:
            sessionNotifyBody.includes('if (kvm_relay_session_change_aborts_launch(ctx, eventType, sessionId, startSessionUsable))') &&
            sessionNotifyBody.includes('(void)kvm_relay_signal_session_change(ctx, eventType, sessionId);') &&
            abortLaunchBody.includes('if (ctx == NULL || eventType == WTS_SESSION_LOCK) { return 0; }') &&
            abortLaunchBody.includes('if (kvm_session_event_is_stop(eventType)) { return sessionMatches; }') &&
            abortLaunchBody.includes('return (ctx->processTSIDExplicit == 0 && kvm_session_id_is_valid(sessionId) && !sessionMatches && startSessionUsable) ? 1 : 0;'),
        // The service control handler must return promptly and must not touch a context it cannot keep alive.
        relayNotifyNeverTakesRelayLockOrReadsActiveContext:
            sessionNotifyBody.includes('kvm_relay_signal_lock();') &&
            sessionNotifyBody.includes('kvm_relay_signal_unlock();') &&
            !sessionNotifyBody.includes('kvm_relay_lock();') &&
            !sessionNotifyBody.includes('TryEnterCriticalSection') &&
            !sessionNotifyBody.includes('gKvmActiveContext') &&
            !sessionNotifyBody.includes('kvm_relay_handle_session_change_for_context(') &&
            !sessionNotifyBody.includes('kvm_relay_restart('),
        // WTS RPCs run before the signal lock; the chain is read and used under it, so its destroy
        // hook cannot release it mid-queue.
        relayNotifyQueuesUnderSignalLockAfterRpcs:
            sessionNotifyBody.includes('startSessionUsable = kvm_session_id_exists(sessionId);') &&
            sessionNotifyBody.indexOf('startSessionUsable = kvm_session_id_exists(sessionId);') < sessionNotifyBody.indexOf('kvm_relay_signal_lock();') &&
            sessionNotifyBody.includes('chain = gKvmDispatchChain;') &&
            sessionNotifyBody.indexOf('kvm_relay_signal_lock();') < sessionNotifyBody.indexOf('ILibChain_RunOnMicrostackThreadEx2(chain, kvm_relay_dispatch_session_change_on_chain, request, 1);') &&
            sessionNotifyBody.indexOf('ILibChain_RunOnMicrostackThreadEx2(chain, kvm_relay_dispatch_session_change_on_chain, request, 1);') < sessionNotifyBody.indexOf('kvm_relay_signal_unlock();') &&
            !sessionNotifyBody.includes('gILibChain'),
        relayDispatchChainClearedOnChainDestroy:
            bindChainBody.includes('ILibChain_OnDestroyEvent_AddHandler(chain, kvm_relay_dispatch_chain_destroyed, NULL);') &&
            chainDestroyedBody.includes('kvm_relay_signal_lock();') &&
            chainDestroyedBody.includes('if (gKvmDispatchChain == chain) { gKvmDispatchChain = NULL; }') &&
            relaySetupBody.includes('kvm_relay_bind_dispatch_chain(gILibChain);'),
        relayRegistryStoresAreInterlocked:
            kvmSource.includes('InterlockedExchangePointer((PVOID volatile*)&gKvmRelayContexts[i], ctx);') &&
            kvmSource.includes('InterlockedExchangePointer((PVOID volatile*)&gKvmRelayContexts[i], NULL);'),
        relayDestroyRemovesContextTimer:
            destroyContextBody.includes('if (timer != NULL) { ILibLifeTime_Remove(timer, ctx); }'),
        // A failed first launch keeps the context and retries, so the viewer's stream is never orphaned.
        relayFailedSetupKeepsContextAndRetries:
            relaySetupBody.includes('g_shutdown = 0;') &&
            relaySetupBody.includes('kvm_relay_schedule_restart_after_failure(GetLastError(), "setup");') &&
            !relaySetupBody.includes('kvm_relay_destroy_context(ctx);\n\t\t\treturn 0;\n\t\t}\n\t\tkvm_relay_deactivate_context();'),
        // Only a shut-down relay ends the viewer's stream; a session stop keeps the viewer attached.
        relaySessionStopKeepsViewerAttached:
            exitHandlerBody.includes('notifyClosed = (g_shutdown != 0) ? 1 : 0;') &&
            !exitHandlerBody.includes('restart limit reached'),
        // No restart limit while the viewer is attached; short-lived exits back off, a stable run resets.
        relayRestartsWithoutLimitAndBacksOffShortLivedExits:
            exitHandlerBody.includes('if (uptimeMs >= KVM_BRIDGE_HEALTHY_RESET_MS)') &&
            exitHandlerBody.includes('if (intentionalExit == 0 && (exitCode != 0 || uptimeMs < KVM_BRIDGE_HEALTHY_RESET_MS))') &&
            exitHandlerBody.includes('kvm_schedule_retry_timer();') &&
            !kvmSource.includes('KVM_RESTART_LIMIT') &&
            !retryTimerBody.includes('closeWriteHandler'),
        relayDestroyWaitsForInFlightSessionSignal:
            destroyContextBody.indexOf('kvm_relay_signal_lock();') >= 0 &&
            destroyContextBody.indexOf('ctx->sessionChangeEvent = NULL;') > destroyContextBody.indexOf('kvm_relay_signal_lock();') &&
            destroyContextBody.indexOf('kvm_relay_signal_unlock();') > destroyContextBody.indexOf('ctx->sessionChangeEvent = NULL;') &&
            destroyContextBody.indexOf('CloseHandle(sessionChangeEvent);') > destroyContextBody.indexOf('kvm_relay_signal_unlock();') &&
            destroyContextBody.indexOf('ILibMemory_Free(ctx);') > destroyContextBody.indexOf('kvm_relay_signal_unlock();'),
        relayLocksInitializeOnce:
            kvmSource.includes('static INIT_ONCE gKvmRelayLocksOnce = INIT_ONCE_STATIC_INIT;') &&
            kvmSource.includes('InitOnceExecuteOnce(&gKvmRelayLocksOnce, kvm_relay_initialize_locks, NULL, NULL);') &&
            kvmSource.includes('InitializeCriticalSection(&gKvmRelaySignalLock);'),
        relayDefinesSessionChangeCancelEpoch:
            kvmSource.includes('HANDLE sessionChangeEvent;') &&
            kvmSource.includes('LONG sessionChangeGeneration;') &&
            kvmSource.includes('ctx->sessionChangeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);') &&
            destroyContextBody.includes('CloseHandle(sessionChangeEvent);') &&
            kvmSource.includes('static LONG kvm_relay_signal_session_change(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)'),
        relaySessionChangeWaitArmPreventsLostSignal:
            armFirstGenerationCheck >= 0 &&
            armResetEvent > armFirstGenerationCheck &&
            armSecondGenerationCheck > armResetEvent &&
            sessionArmBody.includes('SetEvent(eventHandle);') &&
            sessionArmBody.includes('*errorOut = ERROR_OPERATION_ABORTED;'),
        relayPipeConnectWaitObservesSessionCancel:
            kvmSource.includes('WaitForMultipleObjects(2, waitHandles, FALSE, timeoutMs)') &&
            kvmSource.includes('kvm_relay_wait_for_bridge_client(KvmRelayContext* ctx, HANDLE bridgePipeHandle, DWORD timeoutMs, LONG expectedSessionGeneration, DWORD* errorOut, BOOL* sessionChangedOut)') &&
            kvmSource.includes('ERROR_OPERATION_ABORTED'),
        relayPipeConnectWaitReportsSessionAbortAtEveryBoundary:
            pipeWaitBody.includes('if (kvm_relay_session_generation_changed(ctx, expectedSessionGeneration))') &&
            pipeWaitBody.includes('if (errorCode == ERROR_OPERATION_ABORTED && sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }') &&
            pipeWaitBody.includes('else if (waitResult == WAIT_OBJECT_0 + 1)') &&
            pipeWaitBody.includes('if (ok && kvm_relay_session_generation_changed(ctx, expectedSessionGeneration))') &&
            pipeWaitBody.includes('if (sessionChangedOut != NULL) { *sessionChangedOut = TRUE; }'),
        relaySessionCancelIsContextScoped:
            kvmSource.includes('restartSessionGeneration = kvm_relay_get_session_change_generation(ctx);') &&
            kvmSource.includes('kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeInputPipeHandle') &&
            kvmSource.includes('kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeOutputPipeHandle') &&
            !kvmSource.includes('static LONG gKvmSessionChangeGeneration = 0;') &&
            !kvmSource.includes('static HANDLE gKvmSessionChangeEvent = NULL;'),
        relaySessionMatchDoesNotWildcardKnownTsid:
            sessionMatchBody.includes('(ctx->processSessionId == 0 && ctx->processTSID < 0)') &&
            !sessionMatchBody.includes('ctx->processSessionId == 0 ||') &&
            sessionClassifierBody.includes('sessionMatches = kvm_relay_session_matches_context(ctx, sessionId);') &&
            kvmSource.includes('ctx->processSessionId = gKvmProcessSessionId;'),
        relayDrainsCancelledPipeConnect:
            kvmSource.includes('static void kvm_relay_cancel_bridge_pipe_connect(HANDLE pipeHandle, OVERLAPPED* overlapped)') &&
            kvmSource.includes('CancelIoEx(pipeHandle, overlapped)') &&
            kvmSource.includes('GetOverlappedResult(pipeHandle, overlapped, &ignored, TRUE)') &&
            kvmSource.includes('kvm_relay_cancel_bridge_pipe_connect(pipeHandle, &overlapped);'),
        relayAbortsInterruptedLaunchWithoutRamasFallback:
            kvmSource.includes('launchAbortedBySessionChange') &&
            kvmSource.includes('bridge stdin connect aborted by session change generation') &&
            kvmSource.includes('bridge stdout connect aborted by session change generation') &&
            kvmSource.includes('if (launchAbortedBySessionChange)'),
        relaySuppressesRestartOnDisconnect: kvmSource.includes('gKvmRestartSuppressed = 1;') &&
            kvmSource.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);'),
        relayRetainsPendingRestartReason: kvmSource.includes('gKvmPendingSessionRestartEvent = eventType;') &&
            kvmSource.includes('gKvmPendingSessionRestartSessionId = sessionId;'),
        relayRestartsSuppressedHelperOnConnect: kvmSource.includes('gKvmRestartSuppressed = 0;') &&
            kvmSource.includes('if (gChildProcess == NULL && g_shutdown == 0 && gKvmPipeMgr != NULL && gKvmExePath != NULL && gKvmWriteHandler != NULL)') &&
            kvmSource.includes('kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);'),
        relayRestartBranchIsServiceOnly:
            sessionChangeBody.includes('#ifdef _WINSERVICE') &&
            sessionChangeBody.includes('kvm_relay_restart(1, gKvmPipeMgr, gKvmExePath, gKvmWriteHandler, gKvmDebugReserved);') &&
            sessionChangeBody.includes('#endif'),
        relayRebindsToNewSession: kvmSource.includes('gProcessTSID = (int)sessionId;') &&
            kvmSource.includes('gKvmProcessSessionId = sessionId;'),
        relayPreservesExplicitVsAutoSelectedTsid:
            kvmHeaderSource.includes('int processTSIDExplicit;') &&
            kvmSource.includes('static int gKvmProcessTSIDExplicit = 0;') &&
            kvmSource.includes('int processTSIDExplicit;') &&
            relaySetupBody.includes('int requestedTsid = tsid;') &&
            relaySetupBody.includes('int explicitTsid = (requestedTsid >= 0) ? 1 : 0;') &&
            relaySetupBody.includes('tsid = kvm_relay_select_session_id(requestedTsid);') &&
            relaySetupBody.includes('ctx->processTSIDExplicit = explicitTsid;') &&
            relaySetupBody.includes('gKvmProcessTSIDExplicit = explicitTsid;'),
        relayExplicitTsidStillFiltersMismatchedSessions:
            sessionClassifierBody.includes('explicitTsid = (ctx->processTSIDExplicit != 0);') &&
            sessionClassifierBody.includes('if (explicitTsid && !sessionMatches)') &&
            sessionClassifierBody.includes('KVM_SESSION_CHANGE_IGNORE_EXPLICIT_MISMATCH'),
        relayAutoSelectedTsidAllowsNewStartSessionRebind:
            sessionChangeBody.includes('rebindToNewSession = (!explicitTsid && ctx->processSessionId != 0 && ctx->processSessionId != sessionId);') &&
            sessionChangeBody.includes('gProcessTSID = (int)sessionId;') &&
            sessionChangeBody.includes('gKvmProcessSessionId = sessionId;') &&
            sessionChangeBody.includes('g_restartcount = 0;'),
        relayAutoSelectedTsidQueuesTokenUnavailableStartSession:
            sessionClassifierBody.includes('startEvent = kvm_session_event_is_start(eventType);') &&
            sessionClassifierBody.includes('!kvm_session_id_has_user_token(sessionId)') &&
            kvmSource.includes('#define KVM_SESSION_START_TOKEN_RETRY_DELAY_MS 500') &&
            kvmSource.includes('#define KVM_SESSION_START_TOKEN_RETRY_MAX 20') &&
            kvmSource.includes('static int kvm_session_id_exists(DWORD sessionId)') &&
            kvmSource.includes('WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessionInfo, &sessionCount)') &&
            sessionChangeBody.includes('kvm_session_id_exists(sessionId)') &&
            sessionChangeBody.includes('gKvmPendingUnqueryableStartEvent = eventType;') &&
            sessionChangeBody.includes('gKvmPendingUnqueryableStartSessionId = sessionId;') &&
            sessionChangeBody.includes('session start queued for token retry') &&
            sessionNotifyBody.includes('startSessionUsable = kvm_session_id_exists(sessionId);') &&
            abortLaunchBody.includes('startSessionUsable') &&
            retryTimerBody.includes('kvm_retry_pending_unqueryable_start(ctx)') &&
            kvmSource.includes('kvm_relay_handle_session_change_for_context(ctx, eventType, sessionId);'),
        relayAutoSelectedTsidDoesNotPinLiveOldChildOnValidStart:
            !sessionChangeBody.includes('session start ignored for unrelated auto-selected KVM session while current child active') &&
            sessionChangeBody.includes('if (rebindToNewSession && gChildProcess != NULL)') &&
            sessionChangeBody.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);'),
        relayAutoSelectedTsidIgnoresUnrelatedStopSession:
            sessionClassifierBody.includes('if (!explicitTsid && stopEvent && !sessionMatches)') &&
            sessionChangeBody.includes('session stop ignored for unrelated auto-selected KVM session'),
        relayCoversRemoteConnectAndDisconnect:
            sessionChangeBody.includes('case WTS_REMOTE_CONNECT:') &&
            sessionChangeBody.includes('case WTS_REMOTE_DISCONNECT:') &&
            serviceMainSource.includes('ServiceUtil_DebugPrintfA("[ServiceMain] Forwarding KVM session change event=%lu session=%lu"') &&
            svchostControlBody.includes('ServiceUtil_DebugPrintfA("[svchost] Forwarding KVM session change event=%lu session=%lu"'),
        relayRebindsLiveOldChildThroughExistingExitLifecycle:
            sessionChangeBody.includes('if (rebindToNewSession && gChildProcess != NULL)') &&
            sessionChangeBody.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);') &&
            kvmSource.includes('if (gKvmRestartSuppressed != 0 || g_shutdown != 0)') &&
            kvmSource.includes('kvm_schedule_retry_timer();'),
        debugSnapshotExposesTsidSelectionContract:
            kvmHeaderSource.includes('int processTSIDExplicit;') &&
            kvmSource.includes('snapshotOut->processTSIDExplicit = ctx->processTSIDExplicit;')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `session-change contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmHeaderPath,
            kvmPath,
            serviceMainPath,
            svchostPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_session_change_contract.json'), report);
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
