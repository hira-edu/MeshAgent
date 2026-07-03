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

function windowsUpdaterFailsClosedBeforeDirectReplacement(source) {
    if (source == null) {
        return false;
    }
    const updateStart = source.indexOf('function agentUpdate_Start(updateurl, updateoptions)');
    const body = updateStart >= 0 ? source.substring(updateStart) : source;
    const topGuard = body.indexOf("if (process.platform == 'win32')");
    const httpsStart = body.indexOf("require('https').get(options)");
    const platformGuard = body.indexOf("process.platform != 'freebsd' && process.platform != 'linux'");
    const directUnlink = body.indexOf("require('fs').unlinkSync(process.execPath)");
    const directCopy = body.indexOf("require('fs').copyFileSync(process.cwd() + agentfilename + '.update', process.execPath)");
    const postGuardUpdateBlock = platformGuard >= 0 && directCopy > platformGuard ? body.substring(platformGuard, directCopy + 512) : '';

    return topGuard >= 0 &&
        httpsStart > topGuard &&
        platformGuard >= 0 &&
        directUnlink > platformGuard &&
        directCopy > platformGuard &&
        !postGuardUpdateBlock.includes("require('service-manager').manager.getService(name)") &&
        body.includes('Self Update disabled for this platform; native service lifecycle is required.');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const agentInstallerPath = path.resolve('modules', 'agent-installer.js');
    const stealthInstallerPath = path.resolve('meshservice', 'stealth_installer.c');
    const rootMeshcorePath = path.resolve('..', 'MeshCentral', 'meshcore.js');
    const rootMeshcoreMinPath = path.resolve('..', 'MeshCentral', 'meshcore.min.js');
    const meshcorePath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.js');
    const meshcoreMinPath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.min.js');
    const meshcentralDataMeshcorePath = path.resolve('..', 'MeshCentral', 'meshcentral-data', 'meshcore.js');
    const recoverycorePath = path.resolve('..', 'MeshCentral', 'agents', 'recoverycore.js');

    const agentcoreSource = loadText(agentcorePath);
    const agentInstallerSource = loadText(agentInstallerPath);
    const stealthInstallerSource = loadText(stealthInstallerPath);
    const rootMeshcoreSource = loadOptionalText(rootMeshcorePath);
    const rootMeshcoreMinSource = loadOptionalText(rootMeshcoreMinPath);
    const meshcoreSource = loadOptionalText(meshcorePath);
    const meshcoreMinSource = loadOptionalText(meshcoreMinPath);
    const meshcentralDataMeshcoreSource = loadOptionalText(meshcentralDataMeshcorePath);
    const recoverycoreSource = loadOptionalText(recoverycorePath);

    const meshcentralLegacyTokens = ['.update.exe', '_wexecve', '-b64exec ', '-fullupdate', 'windows_getNativeUpdateActivationPath', 'windows_tryNativeFullUpdate', 'windows_execve'];
    const rootMeshcoreLegacyHits = findTokens(rootMeshcoreSource, meshcentralLegacyTokens);
    const rootMeshcoreMinLegacyHits = findTokens(rootMeshcoreMinSource, meshcentralLegacyTokens);
    const meshcoreLegacyHits = findTokens(meshcoreSource, meshcentralLegacyTokens);
    const meshcoreMinLegacyHits = findTokens(meshcoreMinSource, meshcentralLegacyTokens);
    const meshcentralDataMeshcoreLegacyHits = findTokens(meshcentralDataMeshcoreSource, meshcentralLegacyTokens);
    const recoverycoreLegacyHits = findTokens(recoverycoreSource, meshcentralLegacyTokens);
    const externalMeshCentralDrift = rootMeshcoreLegacyHits.length > 0 ||
        rootMeshcoreMinLegacyHits.length > 0 ||
        meshcoreLegacyHits.length > 0 ||
        meshcoreMinLegacyHits.length > 0 ||
        meshcentralDataMeshcoreLegacyHits.length > 0 ||
        recoverycoreLegacyHits.length > 0;

    const checks = {
        meshcentralSourcesAvailableNoLegacyUpdater: meshcoreSource != null &&
            meshcoreMinSource != null &&
            meshcentralDataMeshcoreSource != null &&
            recoverycoreSource != null &&
            (rootMeshcoreSource == null || (rootMeshcoreLegacyHits.length === 0 && rootMeshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'))) &&
            (rootMeshcoreMinSource == null || (rootMeshcoreMinLegacyHits.length === 0 && rootMeshcoreMinSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'))) &&
            meshcoreLegacyHits.length === 0 &&
            meshcoreMinLegacyHits.length === 0 &&
            meshcentralDataMeshcoreLegacyHits.length === 0 &&
            recoverycoreLegacyHits.length === 0 &&
            meshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            meshcoreMinSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            meshcentralDataMeshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            recoverycoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'),
        meshcentralJavaScriptUpdaterCannotTouchWindowsProcessImage: windowsUpdaterFailsClosedBeforeDirectReplacement(meshcoreSource) &&
            windowsUpdaterFailsClosedBeforeDirectReplacement(meshcoreMinSource) &&
            windowsUpdaterFailsClosedBeforeDirectReplacement(meshcentralDataMeshcoreSource) &&
            windowsUpdaterFailsClosedBeforeDirectReplacement(recoverycoreSource) &&
            (rootMeshcoreSource == null || windowsUpdaterFailsClosedBeforeDirectReplacement(rootMeshcoreSource)) &&
            (rootMeshcoreMinSource == null || windowsUpdaterFailsClosedBeforeDirectReplacement(rootMeshcoreMinSource)),
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
        agentcoreWaitsForRundll32LifecycleResult: agentcoreSource.includes('#define MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS 600000') &&
            agentcoreSource.includes('MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY "UpdateActivationTargetHash"') &&
            agentcoreSource.includes('MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY "UpdateActivationFailureHash"') &&
            agentcoreSource.includes('TRUE,\n\t\t\t\tMESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS') &&
            agentcoreSource.includes('SelfUpdate -> Rundll32 lifecycle update activation completed') &&
            agentcoreSource.includes('SelfUpdate -> FAILED rundll32 lifecycle update activation') &&
            agentcoreSource.includes('keeping current agent online'),
        agentcoreHoldsFailedPackageHash: agentcoreSource.includes('MeshAgent_RecordUpdateActivationTargetHash(agent->masterDb, cm->coreModuleHash)') &&
            agentcoreSource.includes('MeshAgent_ReadUpdateActivationFailureHash(agent->masterDb, failedActivationHash)') &&
            agentcoreSource.includes('SelfUpdate -> holding failed update package hash to prevent same-package activation loop') &&
            agentcoreSource.includes('SelfUpdate -> Same update package previously failed activation; suppressing repeat activation'),
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
            !agentInstallerSource.includes('".update.exe"'),
        stealthInstallerPromotesFailedActivationHold: stealthInstallerSource.includes('STEALTH_UPDATE_ACTIVATION_TARGET_KEY "UpdateActivationTargetHash"') &&
            stealthInstallerSource.includes('STEALTH_UPDATE_ACTIVATION_FAILURE_KEY "UpdateActivationFailureHash"') &&
            stealthInstallerSource.includes('Stealth_RecordUpdateActivationFailureHold(&paths);') &&
            stealthInstallerSource.includes('Stealth_ClearUpdateActivationHolds(&paths, L"[UPDATE]");') &&
            stealthInstallerSource.includes('Recorded failed update activation package hash hold')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        agentcorePath,
        agentInstallerPath,
        stealthInstallerPath,
        rootMeshcorePath,
        rootMeshcoreMinPath,
        meshcorePath,
        meshcoreMinPath,
        meshcentralDataMeshcorePath,
        recoverycorePath,
        externalMeshCentralDrift,
        rootMeshcoreLegacyHits,
        rootMeshcoreMinLegacyHits,
        meshcoreLegacyHits,
        meshcoreMinLegacyHits,
        meshcentralDataMeshcoreLegacyHits,
        recoverycoreLegacyHits,
        meshcentralSourcesAvailable: meshcoreSource != null && meshcoreMinSource != null && meshcentralDataMeshcoreSource != null && recoverycoreSource != null,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_svchost_selfupdate_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `AGENTCORE_PATH=${agentcorePath}`,
            `AGENT_INSTALLER_PATH=${agentInstallerPath}`,
            `STEALTH_INSTALLER_PATH=${stealthInstallerPath}`,
            `ROOT_MESHCORE_PATH=${rootMeshcorePath}`,
            `ROOT_MESHCORE_MIN_PATH=${rootMeshcoreMinPath}`,
            `MESHCORE_PATH=${meshcorePath}`,
            `MESHCORE_MIN_PATH=${meshcoreMinPath}`,
            `MESHCENTRAL_DATA_MESHCORE_PATH=${meshcentralDataMeshcorePath}`,
            `RECOVERYCORE_PATH=${recoverycorePath}`,
            'SUCCESS=true',
            `EXTERNAL_MESHCENTRAL_DRIFT=${externalMeshCentralDrift}`,
            `ROOT_MESHCORE_LEGACY_HITS=${formatTokenList(rootMeshcoreLegacyHits)}`,
            `ROOT_MESHCORE_MIN_LEGACY_HITS=${formatTokenList(rootMeshcoreMinLegacyHits)}`,
            `MESHCORE_LEGACY_HITS=${formatTokenList(meshcoreLegacyHits)}`,
            `MESHCORE_MIN_LEGACY_HITS=${formatTokenList(meshcoreMinLegacyHits)}`,
            `MESHCENTRAL_DATA_MESHCORE_LEGACY_HITS=${formatTokenList(meshcentralDataMeshcoreLegacyHits)}`,
            `RECOVERYCORE_LEGACY_HITS=${formatTokenList(recoverycoreLegacyHits)}`,
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
