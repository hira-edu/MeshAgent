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

    const kvmHeader = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8').replace(/\r\n?/g, '\n');
    const agentcoreSource = fs.readFileSync(agentcorePath, 'utf8').replace(/\r\n?/g, '\n');

    const relaySetupBody = extractFunction(kvmSource, 'int kvm_relay_setup(char *exePath, void *processPipeMgr, ILibKVM_WriteHandler writeHandler, void *reserved, int tsid)');
    const cleanupBody = extractFunction(kvmSource, 'void kvm_cleanup(void *reserved)');
    const sessionChangeBody = extractFunction(kvmSource, 'static void kvm_relay_handle_session_change_for_context(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId)');
    const exitHandlerBody = extractFunction(kvmSource, 'void kvm_relay_ExitHandler(ILibProcessPipe_Process sender, int exitCode, void* user)');
    const destroyContextBody = extractFunction(kvmSource, 'static void kvm_relay_destroy_context(KvmRelayContext* ctx)');

    const checks = {
        headerExportsLingerHelpers:
            kvmHeader.includes('void kvm_set_helper_linger_seconds(int seconds);') &&
            kvmHeader.includes('int kvm_get_helper_linger_seconds(void);') &&
            kvmHeader.includes('void kvm_relay_shutdown_all_parked_helpers(void);') &&
            kvmHeader.includes('int kvm_bridge_debug_get_parked_context_count(void);'),

        contextTracksParkedStateAndProcessUser:
            kvmSource.includes('int parked;') &&
            kvmSource.includes('ULONGLONG parkedTickMs;') &&
            kvmSource.includes('char lingerTimerToken;') &&
            kvmSource.includes('struct KvmRelayProcessUser* processUser;'),

        destroyCleansUpLingerTimerAndProcessUser:
            destroyContextBody.includes('ILibLifeTime_Remove(timer, &ctx->lingerTimerToken);') &&
            destroyContextBody.includes('ctx->processUser = NULL;'),

        definesLingerTimerCallbackAndShutdownAll:
            kvmSource.includes('static void kvm_relay_linger_timer_callback(void* object)') &&
            kvmSource.includes('void kvm_relay_shutdown_all_parked_helpers(void)'),

        cleanupParksHealthyHelperWhenLingerEnabled:
            cleanupBody.includes('lingerSeconds = kvm_get_helper_linger_seconds();') &&
            cleanupBody.includes('kvm_relay_set_bridge_pause_state(ctx, 1, 1);') &&
            cleanupBody.includes('ctx->parked = 1;') &&
            cleanupBody.includes('ctx->writeHandler = NULL;') &&
            cleanupBody.includes('ctx->reserved = NULL;') &&
            cleanupBody.includes('gKvmWriteHandler = NULL;') &&
            cleanupBody.includes('gKvmDebugReserved = NULL;') &&
            cleanupBody.includes('gKvmRestartSuppressed = 1;') &&
            cleanupBody.includes('ILibLifeTime_AddEx(timer, &ctx->lingerTimerToken, lingerSeconds * 1000, &kvm_relay_linger_timer_callback, NULL);'),

        relaySetupReattachesParkedContext:
            relaySetupBody.includes('KvmRelayContext* parkedCtx = kvm_relay_find_parked_context_locked(targetSessionId, explicitTsid, selectedTsid);') &&
            relaySetupBody.includes('parkedCtx->reserved = reserved;') &&
            relaySetupBody.includes('parkedCtx->writeHandler = writeHandler;') &&
            relaySetupBody.includes('parkedCtx->parked = 0;') &&
            relaySetupBody.includes('kvm_relay_set_bridge_pause_state(parkedCtx, 0, 1);') &&
            relaySetupBody.includes('kvm_relay_reset(writeHandler, reserved);'),

        exitHandlerHandlesParkedHelperExitWithoutRestart:
            exitHandlerBody.includes('if (ctx != NULL && ctx->parked != 0)') &&
            exitHandlerBody.includes('ILibLifeTime_Remove(timer, &ctx->lingerTimerToken);') &&
            exitHandlerBody.includes('ctx->parked = 0;') &&
            exitHandlerBody.includes('ctx->destroyPending = 1;'),

        sessionChangeTerminatesParkedHelper:
            sessionChangeBody.includes('if (ctx != NULL && ctx->parked != 0)') &&
            sessionChangeBody.includes('ILibLifeTime_Remove(timer, &ctx->lingerTimerToken);') &&
            sessionChangeBody.includes('ctx->parked = 0;') &&
            sessionChangeBody.includes('ctx->destroyPending = 1;'),

        agentcorePlumbsLingerFromMasterDb:
            agentcoreSource.includes('kvmHelperLingerSeconds') &&
            agentcoreSource.includes('kvm_set_helper_linger_seconds(atoi(lingerBuf));')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `helper linger contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmHeaderPath,
            kvmPath,
            agentcorePath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_helper_linger_contract.json'), report);
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
