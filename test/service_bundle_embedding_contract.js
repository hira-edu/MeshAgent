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

function extractEmbeddedServiceBundle(exePath) {
    const script = [
        'import hashlib, json, pathlib, sys',
        'import deploy',
        'bundle = deploy.extract_embedded_service_bundle(pathlib.Path(sys.argv[1]))',
        'print(json.dumps({"size": len(bundle), "sha256": hashlib.sha256(bundle).hexdigest().upper()}))'
    ].join('\n');
    const result = childProcess.spawnSync('python', ['-c', script, exePath], {
        cwd: path.resolve(__dirname, '..'),
        encoding: 'utf8',
        windowsHide: true,
        timeout: 120000
    });
    if (result.status !== 0) {
        throw new Error(`embedded service-bundle extraction failed: ${result.stderr || result.stdout || result.error}`);
    }
    return JSON.parse(result.stdout);
}

function buildChecks(embedded, dllSha256, dllSize) {
    const present = embedded.size > 0;
    const hashMatches = embedded.sha256 === dllSha256;
    const sizeMatches = embedded.size === dllSize;
    return {
        embeddedServiceBundlePresent: present,
        embeddedServiceBundleMatchesDllHash: hashMatches,
        embeddedServiceBundleMatchesDllSize: sizeMatches
    };
}

function buildLegacyChecks(embedded, dllSha256, dllSize) {
    const present = embedded.size > 0;
    const hashMatches = embedded.sha256 === dllSha256;
    const sizeMatches = embedded.size === dllSize;
    return {
        // Exact compatibility schema used only by the legacy entry point.
        embeddedPayloadPresent: present,
        embeddedPayloadMatchesDllHash: hashMatches,
        embeddedPayloadMatchesDllSize: sizeMatches
    };
}

function main(options = {}) {
    const args = parseArgs(process.argv);
    const legacyEvidence = options.legacyEvidence === true || args['legacy-evidence-schema'] === true;
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const requestedArchitecture = args.architecture ? String(args.architecture).toLowerCase() : null;
    if (requestedArchitecture != null && !['x64', 'arm64'].includes(requestedArchitecture)) {
        throw new Error(`unsupported architecture: ${requestedArchitecture}`);
    }
    if ((args.exe || args.dll) && (!args.exe || !args.dll || !requestedArchitecture || legacyEvidence)) {
        throw new Error('Explicit bundle inputs require --exe, --dll and --architecture without legacy evidence');
    }
    const allDefinitions = [
        ['x64', path.resolve('meshservice', 'x64', 'MeshServiceRuntime', 'MeshService-2022.exe'), path.resolve('meshservice', 'x64', 'MeshServiceBundle', 'MeshService-2022.dll')],
        ['arm64', path.resolve('meshservice', 'ARM64', 'MeshServiceRuntime', 'MeshService-2022.exe'), path.resolve('meshservice', 'ARM64', 'MeshServiceBundle', 'MeshService-2022.dll')]
    ];
    const definitions = args.exe ? [[requestedArchitecture, path.resolve(args.exe), path.resolve(args.dll)]] : legacyEvidence ? allDefinitions.slice(0, 1) :
        (requestedArchitecture == null ? allDefinitions : allDefinitions.filter(([architecture]) => architecture === requestedArchitecture));
    const architectures = {};

    for (const [architecture, exePath, dllPath] of definitions) {
        assert(fs.existsSync(exePath), `missing ${architecture} agent package: ${exePath}`);
        assert(fs.existsSync(dllPath), `missing ${architecture} service bundle DLL: ${dllPath}`);

        const embedded = extractEmbeddedServiceBundle(exePath);
        const dllSha256 = sha256File(dllPath);
        const dllSize = fs.statSync(dllPath).size;
        const checks = legacyEvidence ?
            buildLegacyChecks(embedded, dllSha256, dllSize) :
            buildChecks(embedded, dllSha256, dllSize);

        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${architecture}.${name} failed`);
        }
        architectures[architecture] = {
            exePath,
            dllPath,
            embedded,
            dll: { size: dllSize, sha256: dllSha256 },
            checks
        };
    }

    const report = legacyEvidence ? {
        generatedUtc: new Date().toISOString(),
        exePath: architectures.x64.exePath,
        dllPath: architectures.x64.dllPath,
        embedded: architectures.x64.embedded,
        dll: architectures.x64.dll,
        checks: architectures.x64.checks
    } : {
        generatedUtc: new Date().toISOString(),
        architectures
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'service_bundle_embedding_contract.json'), report);
        const summary = legacyEvidence ? [
            `GENERATED_UTC=${report.generatedUtc}`,
            `EXE=${report.exePath}`,
            `DLL=${report.dllPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(report.checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ] : [
            `GENERATED_UTC=${report.generatedUtc}`,
            ...Object.entries(architectures).flatMap(([architecture, result]) => [
                `${architecture.toUpperCase()}_EXE=${result.exePath}`,
                `${architecture.toUpperCase()}_DLL=${result.dllPath}`
            ]),
            'SUCCESS=true',
            `CHECKS=${Object.entries(architectures).flatMap(([architecture, result]) => Object.entries(result.checks).map(([name, passed]) => `${architecture}.${name}:${passed}`)).join(',')}`
        ];
        writeText(path.join(evidenceDir, 'summary.txt'), summary.join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

if (require.main === module) {
    try {
        main();
    } catch (error) {
        console.error(error && error.stack ? error.stack : String(error));
        process.exit(1);
    }
}

module.exports = { buildChecks, buildLegacyChecks, main };
