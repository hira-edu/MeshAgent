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

function extractFileMapBlock(source) {
    const startMarker = 'FILE_MAP = {';
    const endMarker = '\ndef build_remote_cmd';
    const start = source.indexOf(startMarker);
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    return (start >= 0 && end > start) ? source.slice(start, end) : '';
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const deployPath = path.resolve('..', 'MeshCentral', 'deploy-server.py');
    const source = fs.readFileSync(deployPath, 'utf8');
    const fileMap = extractFileMapBlock(source);
    const requiredEntries = [
        'meshdesktopmultiplex.js',
        'meshagent.js',
        'public/scripts/agent-redir-ws-0.1.1.js',
        'public/scripts/agent-redir-ws-0.1.1-min.js',
        'public/scripts/agent-desktop-0.0.2.js',
        'public/scripts/agent-desktop-0.0.2-min.js'
    ];

    const checks = {
        fileMapLocated: fileMap.length > 0
    };

    for (const entry of requiredEntries) {
        checks[`maps:${entry}`] = fileMap.includes(`"${entry}":`);
    }

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        deployPath,
        requiredEntries,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_server_deploy_mapping_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `DEPLOY_PATH=${deployPath}`,
            'SUCCESS=true',
            `REQUIRED_ENTRIES=${requiredEntries.join(',')}`,
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
