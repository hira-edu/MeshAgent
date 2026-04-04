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

function loadText(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const meshcorePath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.js');
    const recoverycorePath = path.resolve('..', 'MeshCentral', 'agents', 'recoverycore.js');

    const agentcoreSource = loadText(agentcorePath);
    const meshcoreSource = loadText(meshcorePath);
    const recoverycoreSource = loadText(recoverycorePath);

    const checks = {
        agentcorePublishesNativeFullUpdate: agentcoreSource.includes('"nativeFullUpdate"'),
        meshcoreHasSupportProbe: meshcoreSource.includes('function windows_supportsNativeFullUpdate(agentfilename)'),
        meshcoreProbesUpdaterVersion: meshcoreSource.includes("'-updaterversion'"),
        meshcoreUsesFullUpdate: meshcoreSource.includes("'-fullupdate'") && meshcoreSource.includes("'--update-source=\"' + updateExePath + '\"'"),
        meshcoreUsesFallbackBeforeLegacyPath: meshcoreSource.includes("if (windows_tryNativeFullUpdate(name, agentfilename, sessionid)) { return; }") && meshcoreSource.includes('windows_execve(name, agentfilename, sessionid);'),
        recoverycoreHasSupportProbe: recoverycoreSource.includes('function windows_supportsNativeFullUpdate(agentfilename)'),
        recoverycoreProbesUpdaterVersion: recoverycoreSource.includes("'-updaterversion'"),
        recoverycoreUsesFullUpdate: recoverycoreSource.includes("'-fullupdate'") && recoverycoreSource.includes("'--update-source=\"' + updateExePath + '\"'"),
        recoverycoreUsesFallbackBeforeLegacyPath: recoverycoreSource.includes("if (windows_tryNativeFullUpdate(name, agentfilename, sessionid)) { return; }") && recoverycoreSource.includes('windows_execve(name, agentfilename, sessionid);')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        agentcorePath,
        meshcorePath,
        recoverycorePath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_svchost_selfupdate_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `AGENTCORE_PATH=${agentcorePath}`,
            `MESHCORE_PATH=${meshcorePath}`,
            `RECOVERYCORE_PATH=${recoverycorePath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
