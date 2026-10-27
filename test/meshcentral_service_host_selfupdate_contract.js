const fs = require('fs');
const path = require('path');
const { forkFile, meshcentralRoot } = require('./lib/meshcentral_paths');

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

// A missing or empty required input fails the contract and says what it was for.
function loadText(filePath, purpose) {
    let text;
    try {
        text = fs.readFileSync(filePath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`required input missing: ${filePath} (${purpose})`, { cause: error });
        }
        throw error;
    }
    assert(text.trim().length > 0, `required input is empty: ${filePath} (${purpose})`);
    return text.replace(/\r\n?/g, '\n');
}

// Optional inputs are declared, not discovered: only a missing file is tolerated, it is recorded in
// absentOptionalInputs (and so in the report), and any other read error or an empty file still fails.
function loadOptionalText(filePath, purpose, absentOptionalInputs) {
    if (!fs.existsSync(filePath)) {
        absentOptionalInputs[filePath] = purpose;
        console.error(`optional input absent, not checked: ${filePath} (${purpose})`);
        return null;
    }
    return loadText(filePath, purpose);
}

function extractFunction(source, signature) {
    let start = source.indexOf(signature);
    assert(start >= 0, `missing function: ${signature}`);
    let bodyStart = source.indexOf('{', start);
    let prototypeEnd = source.indexOf(';', start);
    while (prototypeEnd >= 0 && prototypeEnd < bodyStart) {
        start = source.indexOf(signature, prototypeEnd + 1);
        assert(start >= 0, `missing function body: ${signature}`);
        bodyStart = source.indexOf('{', start);
        prototypeEnd = source.indexOf(';', start);
    }
    assert(bodyStart > start, `missing function body: ${signature}`);

    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`unterminated function body: ${signature}`);
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
    const atomicRename = body.indexOf('renameSync(stagedUpdatePath, process.execPath)');

    return topGuard >= 0 &&
        httpsStart > topGuard &&
        platformGuard >= 0 &&
        directUnlink < 0 &&
        directCopy < 0 &&
        atomicRename > platformGuard &&
        body.includes('Self Update disabled for this platform; native service lifecycle is required.');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const updateContractPath = path.resolve('meshcore', 'config', 'update_defines.h');
    const agentInstallerPath = path.resolve('modules', 'agent-installer.js');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const runtimeHostContractPath = path.resolve('meshservice', 'runtime_host_contract.c');
    const serviceInstallerPath = path.resolve('meshservice', 'service_deployment.c');
    const rootMeshcorePath = forkFile('meshcore.js');
    const rootMeshcoreMinPath = forkFile('meshcore.min.js');
    const meshcorePath = forkFile('agents/meshcore.js');
    const meshcoreMinPath = forkFile('agents/meshcore.min.js');
    const meshcentralDataMeshcorePath = path.join(meshcentralRoot(), 'meshcentral-data', 'meshcore.js');
    const recoverycorePath = forkFile('agents/recoverycore.js');

    const agentcoreSource = loadText(agentcorePath, 'agent core whose native self-update path is checked');
    const updateContractSource = loadText(updateContractPath, 'update constants header');
    const agentInstallerSource = loadText(agentInstallerPath, 'agent installer module whose update delegation is checked');
    const serviceMainSource = loadText(serviceMainPath, 'service entry whose self-update ingress is checked');
    const runtimeHostContractSource = loadText(runtimeHostContractPath, 'runtime host whose lifecycle host is checked');
    const serviceInstallerSource = loadText(serviceInstallerPath, 'service deployment whose update transaction is checked');
    // The tracked MeshCentral agent cores are required. The other cores are optional by layout:
    // root meshcore.js / meshcore.min.js exist in no current layout, and meshcentral-data/meshcore.js
    // is an untracked deploy leftover that Stage 1 removes (SSOT D16, D18). Each is checked when present.
    const absentOptionalInputs = {};
    const rootMeshcoreSource = loadOptionalText(rootMeshcorePath, 'legacy-layout MeshCentral root agent core', absentOptionalInputs);
    const rootMeshcoreMinSource = loadOptionalText(rootMeshcoreMinPath, 'legacy-layout MeshCentral root minified agent core', absentOptionalInputs);
    const meshcoreSource = loadText(meshcorePath, 'tracked MeshCentral agent core whose JavaScript updater must stay disabled on Windows');
    const meshcoreMinSource = loadText(meshcoreMinPath, 'tracked MeshCentral minified agent core whose JavaScript updater must stay disabled on Windows');
    const meshcentralDataMeshcoreSource = loadOptionalText(meshcentralDataMeshcorePath, 'untracked meshcentral-data agent core left by earlier deploys', absentOptionalInputs);
    const recoverycoreSource = loadText(recoverycorePath, 'tracked MeshCentral recovery core whose JavaScript updater must stay disabled on Windows');
    const agentcoreSelfUpdate = extractFunction(agentcoreSource, 'void MeshServer_selfupdate_continue(MeshAgentHostContainer *agent)');
    const nativeJsUpdateActivation = extractFunction(agentcoreSource, 'static duk_ret_t ILibDuktape_MeshAgent_ActivateNativeUpdate(duk_context *ctx)');
    const jsUpdateActivation = extractFunction(agentInstallerSource, 'function runWindowsNativeUpdateActivation(parms)');
    const jsWindowsUpdate = extractFunction(agentInstallerSource, 'function windowsNativeUpdate(isservice, b64)');
    const jsPackageLifecycleActions = extractFunction(agentInstallerSource, 'function isWindowsPackageLifecycleAction(actionName)');
    const nativeUpdateIngress = extractFunction(serviceMainSource, 'static int MeshService_RunSelfUpdateIngress(int argc, WCHAR** wideArgv)');
    const lifecycleHost = extractFunction(runtimeHostContractSource, 'void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)');
    const lifecycleDispatcher = extractFunction(serviceInstallerSource, 'static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig)');

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
            recoverycoreSource != null &&
            (rootMeshcoreSource == null || (rootMeshcoreLegacyHits.length === 0 && rootMeshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'))) &&
            (rootMeshcoreMinSource == null || (rootMeshcoreMinLegacyHits.length === 0 && rootMeshcoreMinSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'))) &&
            meshcoreLegacyHits.length === 0 &&
            meshcoreMinLegacyHits.length === 0 &&
            (meshcentralDataMeshcoreSource == null || meshcentralDataMeshcoreLegacyHits.length === 0) &&
            recoverycoreLegacyHits.length === 0 &&
            meshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            meshcoreMinSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            (meshcentralDataMeshcoreSource == null || meshcentralDataMeshcoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.')) &&
            recoverycoreSource.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.'),
        meshcentralJavaScriptUpdaterCannotTouchWindowsProcessImage: windowsUpdaterFailsClosedBeforeDirectReplacement(meshcoreSource) &&
            windowsUpdaterFailsClosedBeforeDirectReplacement(meshcoreMinSource) &&
            (meshcentralDataMeshcoreSource == null || windowsUpdaterFailsClosedBeforeDirectReplacement(meshcentralDataMeshcoreSource)) &&
            windowsUpdaterFailsClosedBeforeDirectReplacement(recoverycoreSource) &&
            (rootMeshcoreSource == null || windowsUpdaterFailsClosedBeforeDirectReplacement(rootMeshcoreSource)) &&
            (rootMeshcoreMinSource == null || windowsUpdaterFailsClosedBeforeDirectReplacement(rootMeshcoreMinSource)),
        agentcorePublishesNativeFullUpdate: agentcoreSource.includes('"nativeFullUpdate"') &&
            agentcoreSource.includes('"activateNativeUpdate"'),
        agentcoreProbesZipHeaderBeforeOptionalJsUnzip: agentcoreSource.includes('static int MeshServer_UpdateFileLooksZip(char *updateFilePath)') &&
            agentcoreSource.includes('MeshServer_UpdateFileLooksZip(updateFilePath)'),
        agentcoreGuardsOptionalZipModules: agentcoreSource.includes('duk_peval_string(agent->meshCoreCtx, "require(\'zip-reader\')")') &&
            agentcoreSource.includes('duk_peval_string(agent->meshCoreCtx, "require(\'update-helper\')")') &&
            !agentcoreSource.includes('duk_eval_string(agent->meshCoreCtx, "require(\'zip-reader\')");\t// [reader]') &&
            !agentcoreSource.includes('duk_eval_string(agent->meshCoreCtx, "require(\'update-helper\')");\t// [helper]'),
        agentcoreRawPayloadContinuesWhenZipReaderMissing: agentcoreSource.includes('SelfUpdate -> zip-reader unavailable; treating non-zip payload as native update') &&
            agentcoreSource.includes('SelfUpdate -> zip-reader unavailable for zipped update'),
        windowsUpdateConstantsHaveSingleHeaderAuthority:
            /#define\s+MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX\s+"\.update\.pkg"/.test(updateContractSource) &&
            /#define\s+MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY\s+"UpdateActivationTargetHash"/.test(updateContractSource) &&
            /#define\s+MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY\s+"UpdateActivationFailureHash"/.test(updateContractSource) &&
            /#define\s+MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS\s+600000/.test(updateContractSource) &&
            agentcoreSource.includes('#include "config/update_defines.h"') &&
            serviceInstallerSource.includes('#include "../meshcore/config/update_defines.h"') &&
            !agentcoreSource.includes('#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX') &&
            !serviceInstallerSource.includes('#define SERVICE_UPDATE_ACTIVATION_TARGET_KEY'),
        agentcoreSelfUpdateLaunchesRuntimeHostLifecycle: agentcoreSelfUpdate.includes('SelfUpdate -> Launching compatibility lifecycle update activation') &&
            agentcoreSelfUpdate.includes('MeshServer_StartUpdateActivation(agent, w_updatefile)') &&
            agentcoreSource.includes('MeshRuntimeHost_StartLifecycleHostW(MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE') &&
            !agentcoreSelfUpdate.includes('MeshRuntimeHost_LaunchLifecycleHostW('),
        agentcoreObservesRuntimeHostLifecycleNonblocking: updateContractSource.includes('#define MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS   600000') &&
            agentcoreSource.includes('ILibChain_AddWaitHandle(agent->chain, activation->launch.process, MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS') &&
            agentcoreSource.includes('MeshRuntimeHost_CompleteLifecycleHostW(&(activation->launch), &exitCode)') &&
            agentcoreSource.includes('MeshRuntimeHost_ReleaseLifecycleHostW(&(activation->launch))') &&
            agentcoreSource.includes('SelfUpdate -> RuntimeHost lifecycle update activation completed') &&
            agentcoreSource.includes('SelfUpdate -> FAILED compatibility lifecycle update activation') &&
            agentcoreSource.includes('keeping current agent online'),
        agentcoreKeepsNoUpdateHolds: !agentcoreSource.includes('MeshAgent_RecordUpdateActivationTargetHash') &&
            !agentcoreSource.includes('MeshAgent_ReadUpdateActivationFailureHash') &&
            !agentcoreSource.includes('suppressing repeat activation') &&
            agentcoreSource.includes('ILibSimpleDataStore_Delete(agent->masterDb, "UpdateActivationTargetHash");') &&
            agentcoreSource.includes('ILibSimpleDataStore_Delete(agent->masterDb, "UpdateActivationFailureHash");'),
        agentcoreFailsClosedWhenRuntimeHostUnavailable: agentcoreSource.includes('SelfUpdate -> Native lifecycle update requires the compatibility runtime; legacy command-shell path disabled.') &&
            agentcoreSelfUpdate.includes('MeshServer_FailUpdateActivation(agent, 1); // Fail closed'),
        agentcoreDoesNotUseLegacyWindowsUpdateExe: !agentcoreSource.includes('.update.exe') &&
            !agentcoreSource.includes('_wexecve') &&
            !agentcoreSource.includes('-fullupdate'),
        agentInstallerUpdateDelegatesToNativeActivation:
            jsWindowsUpdate.includes('runWindowsNativeUpdateActivation(parms);') &&
            !jsWindowsUpdate.includes('runWindowsNativeLifecycle') &&
            jsUpdateActivation.includes("meshAgent = require('MeshAgent');") &&
            jsUpdateActivation.includes('prepareWindowsNativeLifecycleParameters(parms);') &&
            jsUpdateActivation.includes('meshAgent.activateNativeUpdate(updateSource, updateDll, displayName, description)') &&
            !jsUpdateActivation.includes('runWindowsChildProcessAndCapture') &&
            !jsUpdateActivation.includes("'-fullupdate'"),
        agentInstallerHasNoDirectUpdateManifestPath:
            !agentInstallerSource.includes("runWindowsNativeLifecycle('update'") &&
            !jsPackageLifecycleActions.includes("actionName == 'update'"),
        agentInstallerDoesNotUseLegacyUpdateExe: !agentInstallerSource.includes("'.update.exe'") &&
            !agentInstallerSource.includes('".update.exe"'),
        nativeUpdateIngressesConvergeOnSharedLauncher:
            agentcoreSelfUpdate.includes('MeshServer_StartUpdateActivation(agent, w_updatefile)') &&
            agentcoreSource.includes('MeshRuntimeHost_StartLifecycleHostW(MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE') &&
            nativeJsUpdateActivation.includes('MeshAgent_RunNativeServiceFullUpdate(') &&
            nativeUpdateIngress.includes('MeshRuntimeHost_LaunchLifecycleHostW(') &&
            lifecycleHost.includes('ServiceDeploy_RunLifecycleHostOperation('),
        oneNativeUpdateTransactionExecutor:
            (serviceInstallerSource.match(/static BOOL ServiceDeploy_ApplyUpdateFlow\([^;{]*\)\s*\{/g) || []).length === 1 &&
            lifecycleDispatcher.includes('ok = ServiceDeploy_ApplyUpdateFlow(sourceExePath, sourceDllPath, requireConfig);'),
        serviceInstallerOnlyClearsStaleHolds: serviceInstallerSource.includes('MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY') &&
            serviceInstallerSource.includes('MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY') &&
            serviceInstallerSource.includes('ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]")') &&
            !serviceInstallerSource.includes('ServiceDeploy_RecordUpdateActivationFailureHold') &&
            !serviceInstallerSource.includes('Recorded failed update activation package hash hold')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        agentcorePath,
        updateContractPath,
        agentInstallerPath,
        serviceMainPath,
        runtimeHostContractPath,
        serviceInstallerPath,
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
        absentOptionalInputs,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_service_host_selfupdate_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `AGENTCORE_PATH=${agentcorePath}`,
            `AGENT_INSTALLER_PATH=${agentInstallerPath}`,
            `SERVICE_INSTALLER_PATH=${serviceInstallerPath}`,
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
            `ABSENT_OPTIONAL_INPUTS=${Object.keys(absentOptionalInputs).join(',') || 'none'}`,
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
