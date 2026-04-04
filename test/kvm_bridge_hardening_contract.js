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
    const watchdogPath = path.resolve('meshservice', 'stealth_watchdog.c');
    const watchdogHeaderPath = path.resolve('meshservice', 'stealth_watchdog.h');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const watchdogSource = fs.readFileSync(watchdogPath, 'utf8');
    const watchdogHeaderSource = fs.readFileSync(watchdogHeaderPath, 'utf8');

    const checks = {
        hasBridgeHardeningHelper: kvmSource.includes('static BOOL kvm_relay_harden_bridge_process'),
        protectsBridgeProcessHandle: kvmSource.includes('Stealth_ProtectProcessByHandle(childProcessHandle)'),
        getsSharedJobObject: kvmSource.includes('Watchdog_GetOrCreateJobObject()'),
        assignsBridgeToJobObject: kvmSource.includes('AssignProcessToJobObject(jobObject, childProcessHandle)'),
        failsSpawnWhenHardeningFails: kvmSource.includes('rundll32 bridge hardening failed'),
        exportsJobGetter: watchdogHeaderSource.includes('HANDLE Watchdog_GetOrCreateJobObject(void);'),
        createsJobOnDemand: watchdogSource.includes('static BOOL Watchdog_EnsureJobObjectLocked(void)'),
        keepsKillOnCloseLimit: watchdogSource.includes('JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE'),
        reusesJobFromGetter: watchdogSource.includes('HANDLE Watchdog_GetOrCreateJobObject(void)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `hardening contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath,
            watchdogPath,
            watchdogHeaderPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_hardening_contract.json'), report);
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
