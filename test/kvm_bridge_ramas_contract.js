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
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');

    const checks = {
        hasRamasCandidateBuilder: kvmSource.includes('static int kvm_build_ramas_candidates'),
        ordersSpecifiedUserFirst: kvmSource.includes('ordered[0] = ILibProcessPipe_SpawnTypes_SPECIFIED_USER;'),
        ordersFirstWinlogonSecond: kvmSource.includes('ordered[1] = ILibProcessPipe_SpawnTypes_WINLOGON;'),
        ordersUserThird: kvmSource.includes('ordered[2] = ILibProcessPipe_SpawnTypes_USER;'),
        ordersSecondWinlogonFourth: kvmSource.includes('ordered[3] = ILibProcessPipe_SpawnTypes_WINLOGON;'),
        rotatesFromWinlogon: kvmSource.includes('case ILibProcessPipe_SpawnTypes_WINLOGON:') && kvmSource.includes('startIndex = 1;'),
        rotatesFromUser: kvmSource.includes('case ILibProcessPipe_SpawnTypes_USER:') && kvmSource.includes('startIndex = 2;'),
        usesCandidateBuilderAtRestart: kvmSource.includes('candidateCount = kvm_build_ramas_candidates(primaryType, gProcessTSID >= 0 ? 1 : 0, candidates, _countof(candidates));'),
        bridgePrimaryPrefersWinlogon: kvmSource.includes('if (bridgeAvailable && primaryType != ILibProcessPipe_SpawnTypes_WINLOGON)') && kvmSource.includes('primaryType = ILibProcessPipe_SpawnTypes_WINLOGON;'),
        bridgeRetainsWinlogonAcrossRestarts: kvmSource.includes('gProcessSpawnType = usedBridgePath ? ILibProcessPipe_SpawnTypes_WINLOGON :'),
        usesGuidPipeNames: kvmSource.includes('CoCreateGuid(&guid)') && kvmSource.includes('StringFromGUID2(&guid, guidText'),
        logsAttemptSessionAndPipe: kvmSource.includes('Spawning rundll32 KVM attempt=%d/%d as %s tsid=%d mode=%s transport=named-pipe input=%s output=%s'),
        logsConnectedAttemptResult: kvmSource.includes('rundll32 KVM launched (attempt=%d/%d, spawnType=%s, tsid=%d)'),
        logsFailedAttemptResult:
            kvmSource.includes('bridge stdin connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)') &&
            kvmSource.includes('bridge stdout connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `ramas contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_ramas_contract.json'), report);
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
