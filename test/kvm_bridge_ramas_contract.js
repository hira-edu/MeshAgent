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
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const agentSelfTestPath = path.resolve('modules', 'agent-selftest.js');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const agentcoreSource = fs.readFileSync(agentcorePath, 'utf8');
    const agentSelfTestSource = fs.readFileSync(agentSelfTestPath, 'utf8');

    const checks = {
        removesRamasCandidateBuilder: !kvmSource.includes('static int kvm_build_ramas_candidates'),
        removesRamasForcedFailover: !kvmSource.includes('STEALTH_KVM_FORCE_PRIMARY_FAILOVER') && !kvmSource.includes('kvm_should_force_primary_failover'),
        removesRamasSelfTestSimulation:
            !agentcoreSource.includes('ramasFallback') &&
            !agentcoreSource.includes('RAMAS fallback') &&
            !agentSelfTestSource.includes('ramasFallback') &&
            !agentSelfTestSource.includes('RAMAS fallback'),
        removesSelfTestTunnelFallbackProbe:
            !agentSelfTestSource.includes('sessionCapabilityProbe') &&
            !agentSelfTestSource.includes('sessionTunnelSupported') &&
            !agentSelfTestSource.includes('TUNNEL FALLBACK') &&
            !agentSelfTestSource.includes('Tunnel transport unavailable.....[SKIPPED]') &&
            agentSelfTestSource.includes('KVM tunnel for core dump.........[FAILED]'),
        usesSingleConfiguredSpawnCandidate:
            kvmSource.includes('ILibProcessPipe_SpawnTypes candidates[1];') &&
            kvmSource.includes('candidates[0] = primaryType;') &&
            kvmSource.includes('candidateCount = 1;'),
        rejectsInvalidSpecifiedUserWithoutFallback:
            kvmSource.includes('primaryType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER && gProcessTSID < 0') &&
            kvmSource.includes('gKvmLastBridgeFailureError = ERROR_INVALID_PARAMETER;'),
        bridgeRetainsActualSuccessfulSpawnType: kvmSource.includes('gProcessSpawnType = successfulType;'),
        usesGuidPipeNames: kvmSource.includes('CoCreateGuid(&guid)') && kvmSource.includes('StringFromGUID2(&guid, guidText'),
        logsAttemptSessionAndPipe: kvmSource.includes('Spawning rundll32 KVM attempt=%d/%d as %s tsid=%d mode=%s transport=named-pipe input=%s output=%s'),
        logsConnectedAttemptResult: kvmSource.includes('rundll32 KVM launched (attempt=%d/%d, spawnType=%s, tsid=%d)'),
        logsFailedAttemptResult:
            kvmSource.includes('bridge stdin connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)') &&
            kvmSource.includes('bridge stdout connect failed (error=%u, elapsedMs=%llu, timeoutMs=%u, spawnType=%d, tsid=%d)'),
        fallbackTelemetryDefaultsFalse: kvmSource.includes('gKvmLastFallbackUsed = 0;')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `strict rundll32 bridge contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath,
            agentcorePath,
            agentSelfTestPath
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
