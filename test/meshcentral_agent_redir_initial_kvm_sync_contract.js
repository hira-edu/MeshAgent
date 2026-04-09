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

function evaluateRedirSource(source) {
    return {
        omitsCustomDesktopSyncHelper: !source.includes('xxSendInitialDesktopSync'),
        kvmConnectDefersConnectedState:
            source.includes('if (obj.protocol != 2) { obj.xxStateChange(3); }') ||
            source.includes('2!=r.protocol&&r.xxStateChange(3)'),
        transportHandshakeStillSendsProtocol:
            source.includes('obj.socket.send(obj.protocol);') ||
            source.includes('r.socket.send(r.protocol)')
    };
}

function evaluateDesktopSource(source) {
    return {
        firstScreenPromotesConnectedState:
            source.includes('if (obj.parent != null && obj.parent.State < 3) { obj.parent.xxStateChange(3); }') ||
            source.includes('null!=n.parent&&n.parent.State<3&&n.parent.xxStateChange(3)')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const redirPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1.js');
    const redirMinPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1-min.js');
    const desktopPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-desktop-0.0.2.js');
    const desktopMinPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-desktop-0.0.2-min.js');
    const source = fs.readFileSync(redirPath, 'utf8');
    const sourceMin = fs.readFileSync(redirMinPath, 'utf8');
    const desktopSource = fs.readFileSync(desktopPath, 'utf8');
    const desktopMinSource = fs.readFileSync(desktopMinPath, 'utf8');

    const checks = {
        standard: evaluateRedirSource(source),
        minified: evaluateRedirSource(sourceMin),
        desktopStandard: evaluateDesktopSource(desktopSource),
        desktopMinified: evaluateDesktopSource(desktopMinSource)
    };

    for (const [assetName, assetChecks] of Object.entries(checks)) {
        for (const [name, passed] of Object.entries(assetChecks)) {
            assert(passed, `${assetName}.${name} failed`);
        }
    }

    const report = {
        redirPath,
        redirMinPath,
        desktopPath,
        desktopMinPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_agent_redir_initial_kvm_sync_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `REDIR_PATH=${redirPath}`,
            `REDIR_MIN_PATH=${redirMinPath}`,
            `DESKTOP_PATH=${desktopPath}`,
            `DESKTOP_MIN_PATH=${desktopMinPath}`,
            'SUCCESS=true',
            `STANDARD_CHECKS=${Object.entries(checks.standard).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `MINIFIED_CHECKS=${Object.entries(checks.minified).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `DESKTOP_STANDARD_CHECKS=${Object.entries(checks.desktopStandard).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `DESKTOP_MINIFIED_CHECKS=${Object.entries(checks.desktopMinified).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
