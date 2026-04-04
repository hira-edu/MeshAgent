const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

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
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');

    assert(fs.existsSync(exePath), `diagnostic executable missing at ${exePath}`);

    const result = childProcess.spawnSync(exePath, ['-svchost-status'], {
        windowsHide: true,
        encoding: 'utf8'
    });
    if (result.error) {
        throw result.error;
    }

    const stdout = (result.stdout || '').trim();
    const stderr = result.stderr || '';
    let json = null;

    try {
        json = JSON.parse(stdout);
    } catch (error) {
        throw new Error(`Failed to parse svchost-status JSON\nstdout:\n${stdout}\nstderr:\n${stderr}\nparse error: ${error.message}`);
    }

    assert(json.phase === 'svchost-status', `unexpected phase ${json.phase}`);
    assert(json.processProtection && json.processProtection.collected === true, 'processProtection diagnostics were not collected');
    assert(Array.isArray(json.processProtection.entries), 'processProtection.entries is not an array');
    assert(json.processProtection.protectedProcessCount > 0, 'no protected processes were reported');
    assert(json.processProtection.protectedLightCount > 0, 'no ProtectedLight processes were reported');

    const protectedLightEntries = json.processProtection.entries.filter((entry) => entry && entry.isProtectedLight === true);
    assert(protectedLightEntries.length > 0, 'no ProtectedLight entries were present in the diagnostics array');
    assert(protectedLightEntries.every((entry) => entry.type === 'ProtectedLight'), 'ProtectedLight entries did not report the expected type');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        exitCode: result.status,
        success: true,
        diagnostics: json,
        protectedLightImageNames: protectedLightEntries.map((entry) => entry.imageName)
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'ppl_diagnostic_runtime.json'), report);
        writeText(path.join(evidenceDir, 'svchost_status.json'), stdout + '\n');
        writeText(path.join(evidenceDir, 'stderr.txt'), stderr);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `EXIT_CODE=${report.exitCode}`,
            `PROTECTED_PROCESS_COUNT=${json.processProtection.protectedProcessCount}`,
            `PROTECTED_LIGHT_COUNT=${json.processProtection.protectedLightCount}`,
            `PROTECTED_LIGHT_IMAGES=${report.protectedLightImageNames.join(',')}`
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
