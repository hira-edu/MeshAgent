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

function evaluateSource(source) {
    const hasStateChange = source.includes('obj.xxStateChange(3);') || source.includes('r.xxStateChange(3)');
    return {
        omitsCustomDesktopSyncHelper: !source.includes('xxSendInitialDesktopSync'),
        omitsForcedDesktopStartupControls: !source.includes('SendCompressionLevel') &&
            !source.includes('SendUnPause') &&
            !source.includes('SendRemoteInputLock(2)') &&
            !source.includes('SendRefresh'),
        connectPathDoesNotInjectDesktopSync:
            hasStateChange &&
            !source.includes('obj.xxStateChange(3);\n                obj.xxSendInitialDesktopSync();') &&
            !source.includes('xxStateChange(3),r.xxSendInitialDesktopSync(),')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const redirPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1.js');
    const redirMinPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1-min.js');
    const source = fs.readFileSync(redirPath, 'utf8');
    const sourceMin = fs.readFileSync(redirMinPath, 'utf8');

    const checks = {
        standard: evaluateSource(source),
        minified: evaluateSource(sourceMin)
    };

    for (const [assetName, assetChecks] of Object.entries(checks)) {
        for (const [name, passed] of Object.entries(assetChecks)) {
            assert(passed, `${assetName}.${name} failed`);
        }
    }

    const report = {
        redirPath,
        redirMinPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_agent_redir_initial_kvm_sync_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `REDIR_PATH=${redirPath}`,
            `REDIR_MIN_PATH=${redirMinPath}`,
            'SUCCESS=true',
            `STANDARD_CHECKS=${Object.entries(checks.standard).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `MINIFIED_CHECKS=${Object.entries(checks.minified).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
