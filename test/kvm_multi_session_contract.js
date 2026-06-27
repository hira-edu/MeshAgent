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
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const agentcoreSource = fs.readFileSync(agentcorePath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const sessionSelectorBody = extractFunction(kvmSource, 'static int kvm_relay_select_session_id(int requestedTsid)');
    const returnActiveConsoleIndex = sessionSelectorBody.indexOf('if (bestActiveConsole != 0) { return (int)bestActiveConsole; }');
    const returnActiveIndex = sessionSelectorBody.indexOf('if (bestActive != 0) { return (int)bestActive; }');
    const returnConnectedConsoleIndex = sessionSelectorBody.indexOf('if (bestConnectedConsole != 0) { return (int)bestConnectedConsole; }');
    const returnConnectedIndex = sessionSelectorBody.indexOf('if (bestConnected != 0) { return (int)bestConnected; }');
    const returnStaleConsoleIndex = sessionSelectorBody.indexOf('if (bestConsole != 0) { return (int)bestConsole; }');

    const checks = {
        exportsReservedPause: kvmHeaderSource.includes('void kvm_pause(int pause, void *reserved);'),
        exportsReservedCleanup: kvmHeaderSource.includes('void kvm_cleanup(void *reserved);'),
        exportsReservedDebugPid: kvmHeaderSource.includes('DWORD kvm_bridge_debug_get_child_pid_for_reserved(void *reserved);'),
        exportsContextCount: kvmHeaderSource.includes('int kvm_bridge_debug_get_registered_context_count(void);'),
        definesRelayContextRegistry: kvmSource.includes('#define KVM_MAX_RELAY_CONTEXTS 16') && kvmSource.includes('static KvmRelayContext* gKvmRelayContexts[KVM_MAX_RELAY_CONTEXTS] = { 0 };'),
        exactReservedLookupHelper: kvmSource.includes('static KvmRelayContext* kvm_relay_get_registered_context(void* reserved)'),
        multiSessionSelectionUsesWtsEnumerate: kvmSource.includes('WTSEnumerateSessionsExW'),
        multiSessionSelectionValidatesToken: kvmSource.includes('WTSQueryUserToken'),
        multiSessionSelectionTracksPriorityBuckets:
            sessionSelectorBody.includes('bestActiveConsole') &&
            sessionSelectorBody.includes('bestActive') &&
            sessionSelectorBody.includes('bestConnectedConsole') &&
            sessionSelectorBody.includes('bestConnected') &&
            sessionSelectorBody.includes('bestConsole'),
        multiSessionSelectionDoesNotPreferStaleConsoleOverActiveSession:
            returnActiveConsoleIndex >= 0 &&
            returnActiveIndex > returnActiveConsoleIndex &&
            returnConnectedConsoleIndex > returnActiveIndex &&
            returnConnectedIndex > returnConnectedConsoleIndex &&
            returnStaleConsoleIndex > returnConnectedIndex,
        multiSessionSelectionOnlyTreatsConsoleAsHighestPriorityWhenActive:
            sessionSelectorBody.includes('if (sessionInfo[i].State == WTSActive)') &&
            sessionSelectorBody.includes('if (isConsoleSession)') &&
            sessionSelectorBody.includes('if (bestActiveConsole == 0) { bestActiveConsole = sessionId; }'),
        setupRejectsDuplicateReservedContext: kvmSource.includes('kvm_relay_setup() reserved session already exists'),
        feeddataRoutesByReserved: kvmSource.includes('ctx = kvm_relay_find_context_by_reserved(reserved);'),
        pauseRoutesByReserved: kvmSource.includes('void kvm_pause(int pause, void *reserved)') && kvmSource.includes('kvm_relay_lookup_context(reserved);'),
        cleanupAcceptsReservedContext: kvmSource.includes('void kvm_cleanup(void *reserved)'),
        sessionChangeDispatchesAllContexts: kvmSource.includes('snapshot[KVM_MAX_RELAY_CONTEXTS]') && kvmSource.includes('kvm_relay_handle_session_change_for_context(snapshot[i], request->eventType, request->sessionId);'),
        reservedDebugIntrospectionExists: kvmSource.includes('kvm_bridge_debug_get_child_pid_for_reserved') && kvmSource.includes('kvm_bridge_debug_get_registered_context_count'),
        agentcoreWindowsPauseUsesReserved: agentcoreSource.includes('kvm_pause(1, user);') && agentcoreSource.includes('kvm_pause(0, user);'),
        agentcoreWindowsCleanupUsesReserved: agentcoreSource.includes('kvm_cleanup(ptrs);'),
        serviceProbeExists: serviceMainSource.includes('MeshService_RunKvmMultiSessionProbeCommand') && serviceMainSource.includes('-kvm-multi-session-probe')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `multi-session contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmHeaderPath,
            kvmPath,
            agentcorePath,
            serviceMainPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_multi_session_contract.json'), report);
        writeText(path.join(evidenceDir, 'contract-summary.txt'), [
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
