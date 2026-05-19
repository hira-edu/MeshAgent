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
    const smokePath = path.resolve('test', 'rundll32_bridge_smoke.js');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const smokeSource = fs.readFileSync(smokePath, 'utf8');

    const checks = {
        relayDefinesBridgeShutdownHelper: kvmSource.includes('static BOOL kvm_relay_stop_bridge_process(DWORD timeoutMs)'),
        relaySendsDisconnectPacket: kvmSource.includes('Requesting bridge helper shutdown over pipe') && kvmSource.includes('MNG_KVM_DISCONNECT'),
        relayWaitsForBridgeExit: kvmSource.includes('WaitForSingleObject(childProcessHandle, timeoutMs)'),
        relayFallsBackToTerminateProcess: kvmSource.includes('TerminateProcess(childProcessHandle, 0)'),
        relayHandlesIntentionalPipeBreak: kvmSource.includes('Bridge pipe disconnected during intentional shutdown'),
        slaveConsumesDisconnectPacket: kvmSource.includes('case MNG_KVM_DISCONNECT:') && kvmSource.includes('KVM [SLAVE]: Received disconnect request'),
        cleanupUsesGracefulShutdown: kvmSource.includes('kvm_relay_stop_bridge_process(5000)') && kvmSource.includes('Attempting graceful child shutdown'),
        smokeSupportsDisconnectPacketMode: smokeSource.includes("case 'disconnect-packet':") && smokeSource.includes('controlSocket.write(buildPacket(59))')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `bridge shutdown contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath,
            smokePath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_shutdown_contract.json'), report);
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
