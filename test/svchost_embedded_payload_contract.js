const childProcess = require('child_process');
const crypto = require('crypto');
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

function sha256File(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex').toUpperCase();
}

function extractEmbeddedPayload(exePath) {
    const script = [
        'import hashlib, json, pathlib, sys',
        'import deploy',
        'payload = deploy.extract_embedded_svchost_payload(pathlib.Path(sys.argv[1]))',
        'print(json.dumps({"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest().upper()}))'
    ].join('\n');
    const result = childProcess.spawnSync('python', ['-c', script, exePath], {
        cwd: path.resolve(__dirname, '..'),
        encoding: 'utf8',
        windowsHide: true,
        timeout: 120000
    });
    if (result.status !== 0) {
        throw new Error(`embedded payload extraction failed: ${result.stderr || result.stdout || result.error}`);
    }
    return JSON.parse(result.stdout);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');

    assert(fs.existsSync(exePath), `missing x64 agent package: ${exePath}`);
    assert(fs.existsSync(dllPath), `missing x64 svchost DLL: ${dllPath}`);

    const embedded = extractEmbeddedPayload(exePath);
    const dllSha256 = sha256File(dllPath);
    const dllSize = fs.statSync(dllPath).size;
    const checks = {
        embeddedPayloadPresent: embedded.size > 0,
        embeddedPayloadMatchesDllHash: embedded.sha256 === dllSha256,
        embeddedPayloadMatchesDllSize: embedded.size === dllSize
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        embedded,
        dll: {
            size: dllSize,
            sha256: dllSha256
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'svchost_embedded_payload_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `EXE=${exePath}`,
            `DLL=${dllPath}`,
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
