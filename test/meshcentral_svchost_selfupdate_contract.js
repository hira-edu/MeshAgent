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
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function loadOptionalText(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
    } catch (e) {
        return null;
    }
}

function findTokens(source, tokens) {
    if (source == null) {
        return [];
    }
    return tokens.filter((token) => source.includes(token));
}

function formatTokenList(tokens) {
    return tokens.length > 0 ? tokens.map((token) => JSON.stringify(token)).join(',') : 'none';
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const agentInstallerPath = path.resolve('modules', 'agent-installer.js');
    const meshcorePath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.js');
    const recoverycorePath = path.resolve('..', 'MeshCentral', 'agents', 'recoverycore.js');

    const agentcoreSource = loadText(agentcorePath);
    const agentInstallerSource = loadText(agentInstallerPath);
    const meshcoreSource = loadOptionalText(meshcorePath);
    const recoverycoreSource = loadOptionalText(recoverycorePath);

    const meshcentralLegacyTokens = ['.update.exe', '_wexecve', 'cmd.exe', '-b64exec ', '-fullupdate'];
    const meshcoreLegacyHits = findTokens(meshcoreSource, meshcentralLegacyTokens);
    const recoverycoreLegacyHits = findTokens(recoverycoreSource, meshcentralLegacyTokens);
    const externalMeshCentralDrift = meshcoreLegacyHits.length > 0 || recoverycoreLegacyHits.length > 0;

    const checks = {
        agentcorePublishesNativeFullUpdate: agentcoreSource.includes('"nativeFullUpdate"'),
        agentcoreProbesZipHeaderBeforeOptionalJsUnzip: agentcoreSource.includes('static int MeshServer_UpdateFileLooksZip(char *updateFilePath)') &&
            agentcoreSource.includes('MeshServer_UpdateFileLooksZip(updateFilePath)'),
        agentcoreGuardsOptionalZipModules: agentcoreSource.includes('duk_peval_string(agent->meshCoreCtx, "require(\'zip-reader\')")') &&
            agentcoreSource.includes('duk_peval_string(agent->meshCoreCtx, "require(\'update-helper\')")') &&
            !agentcoreSource.includes('duk_eval_string(agent->meshCoreCtx, "require(\'zip-reader\')");\t// [reader]') &&
            !agentcoreSource.includes('duk_eval_string(agent->meshCoreCtx, "require(\'update-helper\')");\t// [helper]'),
        agentcoreRawPayloadContinuesWhenZipReaderMissing: agentcoreSource.includes('SelfUpdate -> zip-reader unavailable; treating non-zip payload as native update') &&
            agentcoreSource.includes('SelfUpdate -> zip-reader unavailable for zipped update'),
        agentcoreUsesPackageUpdateSuffix: agentcoreSource.includes('#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX ".update.pkg"'),
        agentcoreSelfUpdateLaunchesRundll32Lifecycle: agentcoreSource.includes('SelfUpdate -> Svchost mode: launching rundll32 lifecycle update activation') &&
            agentcoreSource.includes('MeshRundll32_LaunchLifecycleHostW(') &&
            agentcoreSource.includes('MESH_RUNDLL32_LIFECYCLE_ACTION_UPDATE') &&
            agentcoreSource.includes('w_updatefile'),
        agentcoreFailsClosedWhenRundll32Unavailable: agentcoreSource.includes('SelfUpdate -> Windows lifecycle update requires rundll32/svchost mode; legacy command-shell update path disabled.') &&
            agentcoreSource.includes('util_deletefile(updatefile); // Fail closed'),
        agentcoreDoesNotUseLegacyWindowsUpdateExe: !agentcoreSource.includes('.update.exe') &&
            !agentcoreSource.includes('_wexecve') &&
            !agentcoreSource.includes('-fullupdate'),
        agentInstallerUpdateSourceFeedsLifecycleBinary: agentInstallerSource.includes('function getWindowsNativeUpdateSource(parms)') &&
            agentInstallerSource.includes("updateSource = parms.getParameter('update-source', null);") &&
            agentInstallerSource.includes('var updateSource = getWindowsNativeUpdateSource(parms);') &&
            agentInstallerSource.includes("runWindowsNativeLifecycle('update', parms, updateSource != null ? { binary: updateSource } : null);"),
        agentInstallerLifecycleManifestRecordsSelectedSourceExe: agentInstallerSource.includes('SourceExe=') &&
            agentInstallerSource.includes('sanitizeWindowsLifecycleManifestValue(targetBinary)') &&
            agentInstallerSource.includes('findWindowsLifecycleServiceDll(targetBinary, actionName, parms, cleanupPaths)'),
        agentInstallerDoesNotUseLegacyUpdateExe: !agentInstallerSource.includes("'.update.exe'") &&
            !agentInstallerSource.includes('".update.exe"')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        agentcorePath,
        agentInstallerPath,
        meshcorePath,
        recoverycorePath,
        externalMeshCentralDrift,
        meshcoreLegacyHits,
        recoverycoreLegacyHits,
        meshcentralSourcesAvailable: meshcoreSource != null && recoverycoreSource != null,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_svchost_selfupdate_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `AGENTCORE_PATH=${agentcorePath}`,
            `AGENT_INSTALLER_PATH=${agentInstallerPath}`,
            `MESHCORE_PATH=${meshcorePath}`,
            `RECOVERYCORE_PATH=${recoverycorePath}`,
            'SUCCESS=true',
            `EXTERNAL_MESHCENTRAL_DRIFT=${externalMeshCentralDrift}`,
            `MESHCORE_LEGACY_HITS=${formatTokenList(meshcoreLegacyHits)}`,
            `RECOVERYCORE_LEGACY_HITS=${formatTokenList(recoverycoreLegacyHits)}`,
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
