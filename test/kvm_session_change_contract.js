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
    const svchostPath = path.resolve('meshservice', 'stealth_svchost.c');
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const svchostSource = fs.readFileSync(svchostPath, 'utf8');
    const relaySetupBody = extractFunction(kvmSource, 'int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)');
    const sessionChangeBody = extractFunction(kvmSource, 'static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');
    const sessionNotifyBody = extractFunction(kvmSource, 'void kvm_notify_session_change(DWORD eventType, DWORD sessionId)');
    const sessionClassifierBody = extractFunction(kvmSource, 'static int kvm_relay_session_change_affects_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int queryUserToken, int* ignoreReasonOut)');
    const signalRelevantBody = extractFunction(kvmSource, 'static int kvm_relay_signal_session_change_if_relevant(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');
    const retryTimerBody = extractFunction(kvmSource, 'static void kvm_retry_timer_callback(void* object)');
    const sessionArmBody = extractFunction(kvmSource, 'static int kvm_relay_arm_session_change_wait(KvmRelayContext* ctx, LONG expectedGeneration, HANDLE* eventOut, DWORD* errorOut)');
    const pipeWaitBody = extractFunction(kvmSource, 'static BOOL kvm_relay_wait_for_bridge_client(KvmRelayContext* ctx, HANDLE bridgePipeHandle, DWORD timeoutMs, LONG expectedSessionGeneration, DWORD* errorOut, BOOL* sessionChangedOut)');
    const svchostControlBody = extractFunction(svchostSource, 'DWORD WINAPI Stealth_SvchostCtrlHandler(');
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
            svchostControlBody.includes('Stealth_DebugPrintfA("[svchost] Forwarding KVM session change event=%lu session=%lu"') &&
            svchostControlBody.includes('kvm_notify_session_change(dwEventType, sessionId);'),
        svchostMirrorsStealthSessionChangeForwarding:
            svchostSource.includes('#include "stealth_integration.h"') &&
            svchostControlBody.includes('StealthIntegration_HandleSessionChange(dwEventType, sessionId);'),
        svchostControlHandlerDefersFinalStopToServiceMain:
            svchostControlBody.includes('MeshAgent_Stop(g_SvchostAgent);') &&
            svchostControlBody.includes('Stop requested; waiting for MeshAgent_Start to return') &&
            svchostControlBody.includes('Shutdown requested; waiting for MeshAgent_Start to return') &&
            !svchostControlBody.includes('g_SvchostAgent = NULL;') &&
            !svchostControlBody.includes('g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;') &&
            svchostSource.includes('int startResult = MeshAgent_Start(g_SvchostAgent, startArgc, startArgv);') &&
            svchostSource.includes('g_SvchostAgent = NULL;') &&
            svchostSource.includes('g_SvchostStatus.dwCurrentState = SERVICE_STOPPED;'),
        relayDefinesSessionChangeDispatcher: kvmSource.includes('static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)'),
        relayDispatchesSessionChangesPerContext: kvmSource.includes('kvm_relay_handle_session_change_for_context(snapshot[i], eventType, sessionId);'),
        relaySignalsOnlyRelevantSessionContexts:
            sessionNotifyBody.includes('kvm_relay_signal_session_change_if_relevant(snapshot[i], eventType, sessionId)') &&
            sessionNotifyBody.includes('preSignaled = kvm_relay_signal_session_change_if_relevant(preSignaledContext, eventType, sessionId);') &&
            !sessionNotifyBody.includes('(void)kvm_relay_signal_session_change(eventType, sessionId);'),
        relayPreSignalsRelevantActiveContextBeforeBlockingOnRelayLock:
            sessionNotifyBody.includes('TryEnterCriticalSection(&gKvmRelayContextLock)') &&
            sessionNotifyBody.indexOf('preSignaled = kvm_relay_signal_session_change_if_relevant(preSignaledContext, eventType, sessionId);') <
                sessionNotifyBody.indexOf('kvm_relay_lock();'),
        relayDefinesSessionChangeCancelEpoch:
            kvmSource.includes('HANDLE sessionChangeEvent;') &&
            kvmSource.includes('LONG sessionChangeGeneration;') &&
            kvmSource.includes('ctx->sessionChangeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);') &&
            kvmSource.includes('CloseHandle(ctx->sessionChangeEvent);') &&
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
            sessionClassifierBody.includes('(ctx->processSessionId == 0 && ctx->processTSID < 0)') &&
            !sessionClassifierBody.includes('ctx->processSessionId == 0 ||') &&
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
            signalRelevantBody.includes('KVM_SESSION_CHANGE_IGNORE_UNQUERYABLE_START') &&
            signalRelevantBody.includes('kvm_session_id_exists(sessionId)') &&
            signalRelevantBody.includes('kvm_relay_signal_session_change(ctx, eventType, sessionId)') &&
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
            serviceMainSource.includes('Stealth_DebugPrintfA("[ServiceMain] Forwarding KVM session change event=%lu session=%lu"') &&
            svchostControlBody.includes('Stealth_DebugPrintfA("[svchost] Forwarding KVM session change event=%lu session=%lu"'),
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
