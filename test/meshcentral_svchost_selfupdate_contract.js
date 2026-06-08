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
        meshcoreUsesStrippedExeActivationPath: meshcoreSource.includes('function windows_getNativeUpdateActivationPath(agentfilename)') && meshcoreSource.includes("agentfilename.substring(0, agentfilename.length - 4)") && meshcoreSource.includes("return cwd + agentfilename + '.update.exe';"),
        meshcoreNativeProbeUsesActivationPath: meshcoreSource.includes('var updateExePath = windows_getNativeUpdateActivationPath(agentfilename);'),
        meshcoreDownloadUsesActivationPath: meshcoreSource.includes("createWriteStream(process.platform == 'win32' ? windows_getNativeUpdateActivationPath(agentfilename) : agentfilename + '.update'"),
        meshcoreNativePathDoesNotAppendUpdateExe: !meshcoreSource.includes("var updateExePath = process.cwd() + agentfilename + '.update.exe';"),
        meshcoreProbesUpdaterVersion: meshcoreSource.includes("execFile(updateExePath, ['-updaterversion']"),
        meshcoreUsesFullUpdate: meshcoreSource.includes("execFile(updateExePath, ['-fullupdate', '--update-source=' + updateExePath]"),
        meshcoreDoesNotInjectSyntheticArgv0: !meshcoreSource.includes("[agentfilename + '.update.exe', '-fullupdate'") && !meshcoreSource.includes("[agentfilename + '.update.exe', '-updaterversion'"),
        meshcoreDoesNotQuoteExecFileUpdateSource: !meshcoreSource.includes("'--update-source=\"' + updateExePath + '\"'"),
        meshcoreCompletesNativeHandoff: meshcoreSource.includes('function windows_finishNativeFullUpdate(name, sessionid)') && meshcoreSource.includes('windows_finishNativeFullUpdate(name, sessionid); return;'),
        meshcoreStopsCurrentServiceAfterNativeHandoff: meshcoreSource.includes("require('service-manager').manager.getService(name)") && meshcoreSource.includes('service.stop();'),
        meshcoreHasForceExitFallbackAfterNativeHandoff: meshcoreSource.includes("require('MeshAgent').forceExit(0)") && meshcoreSource.includes('process._exit(0);'),
        meshcoreUsesFallbackBeforeLegacyPath: meshcoreSource.includes("if (windows_tryNativeFullUpdate(name, agentfilename, sessionid)) { windows_finishNativeFullUpdate(name, sessionid); return; }") && meshcoreSource.includes('windows_execve(name, agentfilename, sessionid);'),
        recoverycoreHasSupportProbe: recoverycoreSource.includes('function windows_supportsNativeFullUpdate(agentfilename)'),
        recoverycoreUsesStrippedExeActivationPath: recoverycoreSource.includes('function windows_getNativeUpdateActivationPath(agentfilename)') && recoverycoreSource.includes("agentfilename.substring(0, agentfilename.length - 4)") && recoverycoreSource.includes("return cwd + agentfilename + '.update.exe';"),
        recoverycoreNativeProbeUsesActivationPath: recoverycoreSource.includes('var updateExePath = windows_getNativeUpdateActivationPath(agentfilename);'),
        recoverycoreNativePathDoesNotAppendUpdateExe: !recoverycoreSource.includes("var updateExePath = process.cwd() + agentfilename + '.update.exe';"),
        recoverycoreProbesUpdaterVersion: recoverycoreSource.includes("execFile(updateExePath, ['-updaterversion']"),
        recoverycoreUsesFullUpdate: recoverycoreSource.includes("execFile(updateExePath, ['-fullupdate', '--update-source=' + updateExePath]"),
        recoverycoreDoesNotInjectSyntheticArgv0: !recoverycoreSource.includes("[agentfilename + '.update.exe', '-fullupdate'") && !recoverycoreSource.includes("[agentfilename + '.update.exe', '-updaterversion'"),
        recoverycoreDoesNotQuoteExecFileUpdateSource: !recoverycoreSource.includes("'--update-source=\"' + updateExePath + '\"'"),
        recoverycoreCompletesNativeHandoff: recoverycoreSource.includes('function windows_finishNativeFullUpdate(name, sessionid)') && recoverycoreSource.includes('windows_finishNativeFullUpdate(name, sessionid); return;'),
        recoverycoreStopsCurrentServiceAfterNativeHandoff: recoverycoreSource.includes("require('service-manager').manager.getService(name)") && recoverycoreSource.includes('service.stop();'),
        recoverycoreHasForceExitFallbackAfterNativeHandoff: recoverycoreSource.includes("require('MeshAgent').forceExit(0)") && recoverycoreSource.includes('process._exit(0);'),
        recoverycoreUsesFallbackBeforeLegacyPath: recoverycoreSource.includes("if (windows_tryNativeFullUpdate(name, agentfilename, sessionid)) { windows_finishNativeFullUpdate(name, sessionid); return; }") && recoverycoreSource.includes('windows_execve(name, agentfilename, sessionid);')
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
