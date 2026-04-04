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
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const kvmHeaderSource = fs.readFileSync(kvmHeaderPath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');

    const checks = {
        headerExportsSessionChangeHook: kvmHeaderSource.includes('void kvm_notify_session_change(DWORD eventType, DWORD sessionId);'),
        serviceMainForwardsSessionChanges: serviceMainSource.includes('kvm_notify_session_change(eventType, sessionId);'),
        relayDefinesSessionChangeDispatcher: kvmSource.includes('static void kvm_relay_handle_session_change(void* chain, void* user)'),
        relaySuppressesRestartOnDisconnect: kvmSource.includes('stopping helper and suppressing restart'),
        relayRetainsContextWhileSuppressed: kvmSource.includes('helper exit retained while session restart is suppressed'),
        relayRestartsSuppressedHelperOnConnect: kvmSource.includes('restarting suppressed helper'),
        relayRebindsToNewSession: kvmSource.includes('moving helper from session %u to %u')
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
