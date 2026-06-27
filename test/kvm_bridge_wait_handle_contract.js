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
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const processPipeSource = fs.readFileSync(processPipePath, 'utf8');

    const checks = {
        hardeningUsesPreStartCreateHandle:
            kvmSource.includes('static BOOL kvm_relay_bridge_pre_start_handler(HANDLE childProcessHandle') &&
            kvmSource.includes('kvm_relay_harden_bridge_process_handle(childProcessHandle'),
        productionSpawnUsesPreStartHardening:
            kvmSource.includes('ILibProcessPipe_Manager_SpawnProcessEx5(') &&
            kvmSource.includes('&kvm_relay_bridge_pre_start_handler'),
        processPipeSupportsPreStartCallback:
            processPipeSource.includes('ILibProcessPipe_ProcessPreStartHandler preStartHandler') &&
            processPipeSource.includes('preStartHandler(processInfo.hProcess, processInfo.hThread, processInfo.dwProcessId, preStartUser, &preStartError)'),
        preStartSpawnSuspendsAndBreaksAway:
            processPipeSource.includes('creationFlags |= CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB;') &&
            processPipeSource.includes('ResumeThread(processInfo.hThread)'),
        shutdownRequestsProcessHandleOnly: kvmSource.includes('ILibProcessPipe_Process_GetWaitHandles(gChildProcess, &childProcessHandle, NULL, NULL, NULL);'),
        waitHandleHardeningFallbackStillProcessOnly: kvmSource.includes('ILibProcessPipe_Process_GetWaitHandles(childProcess, &childProcessHandle, NULL, NULL, NULL);'),
        waitHandleGetterInitializesOptionalOutputs:
            processPipeSource.includes('if (hProcess != NULL) { *hProcess = NULL; }') &&
            processPipeSource.includes('if (read != NULL) { *read = NULL; }') &&
            processPipeSource.includes('if (write != NULL) { *write = NULL; }') &&
            processPipeSource.includes('if (error != NULL) { *error = NULL; }'),
        waitHandleGetterRejectsInvalidProcess: processPipeSource.includes('if (j == NULL || !ILibMemory_CanaryOK(j)) { return; }'),
        waitHandleGetterGuardsPipeOutputs:
            processPipeSource.includes('read != NULL && j->stdOut != NULL && j->stdOut->mOverlapped != NULL') &&
            processPipeSource.includes('error != NULL && j->stdErr != NULL && j->stdErr->mOverlapped != NULL') &&
            processPipeSource.includes('write != NULL && j->stdIn != NULL && j->stdIn->mOverlapped != NULL')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `bridge wait-handle contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath,
            processPipePath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_wait_handle_contract.json'), report);
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
