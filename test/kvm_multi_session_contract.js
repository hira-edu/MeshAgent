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
    const kvmHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.h');
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const agentcoreSource = fs.readFileSync(agentcorePath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');

    const checks = {
        exportsReservedPause: kvmHeaderSource.includes('void kvm_pause(int pause, void *reserved);'),
        exportsReservedCleanup: kvmHeaderSource.includes('void kvm_cleanup(void *reserved);'),
        exportsReservedDebugPid: kvmHeaderSource.includes('DWORD kvm_bridge_debug_get_child_pid_for_reserved(void *reserved);'),
        exportsContextCount: kvmHeaderSource.includes('int kvm_bridge_debug_get_registered_context_count(void);'),
        definesRelayContextRegistry: kvmSource.includes('#define KVM_MAX_RELAY_CONTEXTS 16') && kvmSource.includes('static KvmRelayContext* gKvmRelayContexts[KVM_MAX_RELAY_CONTEXTS] = { 0 };'),
        exactReservedLookupHelper: kvmSource.includes('static KvmRelayContext* kvm_relay_get_registered_context(void* reserved)'),
        multiSessionSelectionUsesWtsEnumerate: kvmSource.includes('WTSEnumerateSessionsExW'),
        multiSessionSelectionValidatesToken: kvmSource.includes('WTSQueryUserToken'),
        multiSessionSelectionTracksPriorityBuckets: kvmSource.includes('bestConsole') && kvmSource.includes('bestActive') && kvmSource.includes('bestConnected'),
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
