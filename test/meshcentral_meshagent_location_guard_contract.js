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
    const meshagentPath = path.resolve('..', 'MeshCentral', 'meshagent.js');
    const source = fs.readFileSync(meshagentPath, 'utf8');
    const startMarker = '    function ChangeAgentLocationInfo(command) {';
    const endMarker = '        // Check that the mesh exists';
    const start = source.indexOf(startMarker);
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    const block = start >= 0 && end > start ? source.slice(start, end) : '';

    const checks = {
        functionLocated: block.length > 0,
        nullGuardPresent: block.includes('if ((obj.agentInfo == null) || (obj.agentInfo.capabilities & 0x40)) return;'),
        unsafeGuardRemoved: !block.includes('if (obj.agentInfo.capabilities & 0x40) return;')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        meshagentPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_meshagent_location_guard_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `MESHAGENT_PATH=${meshagentPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
