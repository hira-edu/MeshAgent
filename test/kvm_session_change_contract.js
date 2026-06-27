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
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const relaySetupBody = extractFunction(kvmSource, 'int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)');
    const sessionChangeBody = extractFunction(kvmSource, 'static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');

    const checks = {
        headerExportsSessionChangeHook: kvmHeaderSource.includes('void kvm_notify_session_change(DWORD eventType, DWORD sessionId);'),
        serviceMainForwardsSessionChanges: serviceMainSource.includes('kvm_notify_session_change(eventType, sessionId);'),
        relayDefinesSessionChangeDispatcher: kvmSource.includes('static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)'),
        relayDispatchesSessionChangesPerContext: kvmSource.includes('kvm_relay_handle_session_change_for_context(snapshot[i], eventType, sessionId);'),
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
            sessionChangeBody.includes('explicitTsid = (ctx->processTSIDExplicit != 0);') &&
            sessionChangeBody.includes('if (explicitTsid && !sessionMatches)') &&
            sessionChangeBody.includes('return;'),
        relayAutoSelectedTsidAllowsNewStartSessionRebind:
            sessionChangeBody.includes('rebindToNewSession = (!explicitTsid && ctx->processSessionId != 0 && ctx->processSessionId != sessionId);') &&
            sessionChangeBody.includes('gProcessTSID = (int)sessionId;') &&
            sessionChangeBody.includes('gKvmProcessSessionId = sessionId;') &&
            sessionChangeBody.includes('g_restartcount = 0;'),
        relayAutoSelectedTsidRejectsNonInteractiveStartSession:
            sessionChangeBody.includes('startEvent = kvm_session_event_is_start(eventType);') &&
            sessionChangeBody.includes('!kvm_session_id_has_user_token(sessionId)') &&
            sessionChangeBody.includes('session start ignored for auto-selected KVM because session has no queryable user token'),
        relayAutoSelectedTsidDoesNotPinLiveOldChildOnValidStart:
            !sessionChangeBody.includes('session start ignored for unrelated auto-selected KVM session while current child active') &&
            sessionChangeBody.includes('if (rebindToNewSession && gChildProcess != NULL)') &&
            sessionChangeBody.includes('ILibProcessPipe_Process_SoftKill(gChildProcess);'),
        relayAutoSelectedTsidIgnoresUnrelatedStopSession:
            sessionChangeBody.includes('if (!explicitTsid && stopEvent && !sessionMatches)') &&
            sessionChangeBody.includes('session stop ignored for unrelated auto-selected KVM session'),
        relayCoversRemoteConnectAndDisconnect:
            sessionChangeBody.includes('case WTS_REMOTE_CONNECT:') &&
            sessionChangeBody.includes('case WTS_REMOTE_DISCONNECT:') &&
            serviceMainSource.includes('Stealth_DebugPrintfA("[ServiceMain] Forwarding KVM session change event=%lu session=%lu"'),
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
            serviceMainPath
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
