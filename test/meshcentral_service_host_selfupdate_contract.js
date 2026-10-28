'use strict';
// The SHA-384 self-update ingress, in three parts.
//
// 1. Executed: the JavaScript updater agentUpdate_Start in the MeshCentral fork's agent cores
//    (agents/meshcore.js and agents/recoverycore.js) runs with injected https, fs, hash stream and
//    MeshAgent. On Windows it refuses before any request or file access. Elsewhere it refuses
//    without a valid SHA-384 hash, keeps the current agent on an HTTP error or a hash mismatch,
//    replaces the binary on Linux/FreeBSD only by renaming the verified staged file over it, and on
//    any other platform deletes the staged file and refuses.
// 2. Executed: the agent installer's Windows update (modules/agent-installer.js) hands the staged
//    package to the native MeshAgent.activateNativeUpdate and never starts a child process; console
//    agents and runtimes without native activation fail.
// 3. Read: the native sources (agentcore.c, ServiceMain.c, runtime_host_contract.c,
//    service_deployment.c, update_defines.h) cannot run in Node. Their checks slice the named
//    functions, and a missing function or file fails. The native transfer itself is exercised by
//    test/native_update_hash_runtime.py on a build.
const assert = require('assert');
const path = require('path');
const vm = require('vm');
const { EventEmitter } = require('events');
const { forkFile } = require('./lib/meshcentral_paths');
const { readSource, extractFunction, compileDefinitions, evidenceDirFromArgs, writeEvidence, runCases } = require('./lib/source_extract');

const WINDOWS_DISABLED = 'Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.';
const VALID_HASH = 'ab'.repeat(48);
const LEGACY_UPDATER_TOKENS = ['.update.exe', '_wexecve', '-b64exec ', '-fullupdate', 'windows_getNativeUpdateActivationPath', 'windows_tryNativeFullUpdate', 'windows_execve'];

const paths = {
    meshcore: forkFile('agents/meshcore.js'),
    recoverycore: forkFile('agents/recoverycore.js'),
    agentInstaller: path.resolve(__dirname, '..', 'modules', 'agent-installer.js'),
    agentcore: path.resolve(__dirname, '..', 'meshcore', 'agentcore.c'),
    updateDefines: path.resolve(__dirname, '..', 'meshcore', 'config', 'update_defines.h'),
    serviceMain: path.resolve(__dirname, '..', 'meshservice', 'ServiceMain.c'),
    runtimeHostContract: path.resolve(__dirname, '..', 'meshservice', 'runtime_host_contract.c'),
    serviceDeployment: path.resolve(__dirname, '..', 'meshservice', 'service_deployment.c')
};

// ---- 1. The JavaScript updater in the agent cores --------------------------------------------

const UPDATER_GLOBALS = ['process', 'require', 'sendConsoleText', 'sendAgentMessage', 'agentUpdate_ReportFailure', 'getServerTargetUrlEx',
    'linux_execv', 'bsd_execv', 'setTimeout', 'windows_getCommandLine', '_getPotentialServiceNames',
    // recoverycore: true only on agents built before 2020-01-21
    'needStreamFix'];

function updater(source, platform) {
    const execPath = (platform === 'win32') ? 'C:\\Agent\\MeshAgent.exe' : '/usr/local/mesh/meshagent';
    const log = { console: [], agentMessages: [], sent: [], failures: 0, fs: [], required: [], requests: [], timers: [], execv: [] };
    const fs = {
        createWriteStream(file) { log.fs.push(['createWriteStream', file]); return new EventEmitter(); },
        unlinkSync(file) { log.fs.push(['unlinkSync', file]); },
        statSync(file) { log.fs.push(['statSync', file]); return { mode: 0o755 }; },
        chmodSync(file) { log.fs.push(['chmodSync', file]); },
        renameSync(from, to) { log.fs.push(['renameSync', from, to]); },
        copyFileSync(from, to) { log.fs.push(['copyFileSync', from, to]); }
    };
    const modules = {
        MeshAgent: { ARCHID: 6, serviceName: 'meshagent', ServerUrl: 'wss://server.invalid/agent.ashx', ServerInfo: null, SendCommand(command) { log.sent.push(command); } },
        fs,
        'service-manager': { manager: { getService() { return { isMe: () => true, close() {}, restart() {} }; } } },
        http: { parseUri(url) { const u = new URL(url); return { host: u.hostname, port: u.port, path: u.pathname + u.search }; } },
        https: { get(options) { const request = new EventEmitter(); log.requests.push({ options, request }); return request; } },
        SHA384Stream: { create() { return new EventEmitter(); } }
    };
    const start = compileDefinitions([extractFunction(source, 'function agentUpdate_Start(updateurl, updateoptions)')], UPDATER_GLOBALS, 'agentUpdate_Start')(
        { platform, execPath },
        (name) => { log.required.push(name); assert(name in modules, 'unexpected require(' + JSON.stringify(name) + ')'); return modules[name]; },
        (text) => log.console.push(String(text)),
        (text) => log.agentMessages.push(String(text)),
        () => { log.failures += 1; },
        (url) => url.replace(/^\*/, 'wss://server.invalid'),
        (...args) => log.execv.push(['linux'].concat(args)),
        (...args) => log.execv.push(['freebsd'].concat(args)),
        (fn, ms) => { log.timers.push(ms); return {}; },
        () => [],
        () => [],
        false
    );
    return { start, log, execPath, staged: execPath + '.update' };
}

// Answers the update request with an HTTP status and, for 200, a body whose SHA-384 is digestHex.
function respond(u, status, digestHex, closeFirst) {
    assert.strictEqual(u.log.requests.length, 1, 'one download request');
    const image = new EventEmitter();
    image.statusCode = status;
    image.piped = [];
    image.pipe = (target) => image.piped.push(target);
    image.resume = () => {};
    u.log.requests[0].request.emit('response', image);
    if (status !== 200) { return; }
    const [file, hash] = image.piped;
    assert(file && hash, 'the body is piped to the staged file and the hash stream');
    if (closeFirst) { file.emit('close'); hash.emit('hash', Buffer.from(digestHex, 'hex')); }
    else { hash.emit('hash', Buffer.from(digestHex, 'hex')); file.emit('close'); }
}

const replacedExecutable = (u) => u.log.fs.filter((op) => (op[0] === 'renameSync' || op[0] === 'copyFileSync') && op[2] === u.execPath);

function updaterCases(source) {
    return {
        windowsRefusesBeforeAnyRequestOrFile() {
            const u = updater(source, 'win32');
            u.start('*/meshagents?id=4', { hash: VALID_HASH });
            assert(u.log.console.includes(WINDOWS_DISABLED) && u.log.agentMessages.includes(WINDOWS_DISABLED), 'the refusal is reported');
            assert.deepStrictEqual(u.log.requests, [], 'no download');
            assert.deepStrictEqual(u.log.fs, [], 'no file access');
            assert.deepStrictEqual(u.log.required, [], 'no module is loaded');
        },
        missingOrInvalidHashIsRefused() {
            for (const options of [null, {}, { hash: 'ab'.repeat(32) }, { hash: 'zz'.repeat(48) }, { hash: 42 }]) {
                const u = updater(source, 'linux');
                u.start('*/meshagents?id=6', options);
                assert(u.log.console.includes('Self Update refused because a valid SHA-384 hash was not supplied.'), JSON.stringify(options));
                assert.strictEqual(u.log.failures, 1, 'the failure is reported to the server');
                assert.deepStrictEqual(u.log.requests, [], 'no download without a hash');
            }
        },
        verifiedDownloadReplacesTheBinaryByRename() {
            for (const closeFirst of [false, true]) {
                const u = updater(source, 'linux');
                u.start('*/meshagents?id=6', { hash: VALID_HASH.toUpperCase() });
                assert.strictEqual(u.log.requests[0].options.path, '/meshagents?id=6');
                respond(u, 200, VALID_HASH, closeFirst);
                assert.deepStrictEqual(u.log.fs.find((op) => op[0] === 'createWriteStream'), ['createWriteStream', u.staged], 'the download is staged beside the binary');
                assert.deepStrictEqual(replacedExecutable(u), [['renameSync', u.staged, u.execPath]], 'the verified file is renamed over the binary, once');
                assert(!u.log.fs.some((op) => op[0] === 'unlinkSync' && op[1] === u.execPath), 'the running binary is never deleted');
                assert(u.log.sent.some((command) => command.action === 'agentupdatedownloaded'), 'the server is told the download verified');
                assert.strictEqual(u.log.execv.length, 1, 'the agent restarts into the new binary');
                assert.strictEqual(u.log.failures, 0);
            }
        },
        hashMismatchKeepsTheCurrentAgent() {
            const u = updater(source, 'linux');
            u.start('*/meshagents?id=6', { hash: VALID_HASH });
            respond(u, 200, 'cd'.repeat(48));
            assert.deepStrictEqual(replacedExecutable(u), [], 'a mismatching download never replaces the binary');
            assert.strictEqual(u.log.execv.length, 0);
            assert(u.log.console.some((line) => line.includes('FAILED hash check')), 'the mismatch is reported');
            assert.strictEqual(u.log.timers.length, 1, 'one retry is scheduled');
            assert(u.log.timers[0] > 0);
            assert(!u.log.sent.some((command) => command.action === 'agentupdatedownloaded'));
        },
        httpErrorKeepsTheCurrentAgent() {
            const u = updater(source, 'linux');
            u.start('*/meshagents?id=6', { hash: VALID_HASH });
            respond(u, 404);
            assert.strictEqual(u.log.failures, 1);
            assert(!u.log.fs.some((op) => op[0] === 'createWriteStream'), 'nothing is staged');
        },
        otherPlatformsRefuseBeforeAnyRequestOrFile() {
            for (const platform of ['darwin', 'android']) {
                const u = updater(source, platform);
                u.start('*/meshagents?id=16', { hash: VALID_HASH });
                assert(u.log.console.includes('Self Update disabled for this platform; native service lifecycle is required.'), platform);
                assert.deepStrictEqual(u.log.requests, [], platform + ': no download');
                assert.deepStrictEqual(u.log.fs, [], platform + ': no file access');
                assert.strictEqual(u.log.failures, 1, platform + ': the failure is reported to the server');
            }
        },
        noLegacyWindowsUpdater() {
            const hits = LEGACY_UPDATER_TOKENS.filter((token) => source.includes(token));
            assert.deepStrictEqual(hits, [], 'legacy Windows updater code');
        }
    };
}

// ---- 2. The agent installer's Windows update ------------------------------------------------

function installer(source, meshAgent) {
    const log = { exits: [], stdout: [], activations: [], childProcess: [] };
    const childProcess = new Proxy({}, { get(target, name) { return () => { log.childProcess.push(String(name)); throw new Error('child_process.' + String(name) + ' must not be used'); }; } });
    const agent = Object.assign({
        nativeFullUpdate: true,
        activateNativeUpdate(...args) { log.activations.push(args); return true; }
    }, meshAgent);
    const sandbox = {
        Buffer, console, JSON, Array, Object, String, Error, parseInt,
        module: { exports: {} },
        _MSH: () => ({ displayName: 'Fixture Agent', description: 'Fixture "quoted" description' }),
        process: { platform: 'win32', exit(code) { log.exits.push(code); }, stdout: { write(text) { log.stdout.push(text); } }, execPath: 'C:\\Agent\\MeshAgent.exe' },
        require(name) {
            if (name === 'child_process') { return childProcess; }
            if (name === 'MeshAgent') { return agent; }
            throw new Error('unexpected require(' + JSON.stringify(name) + ')');
        }
    };
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox, { filename: paths.agentInstaller });
    return { sandbox, log };
}

const updateParameters = (parms) => Buffer.from(JSON.stringify(parms)).toString('base64');

function installerCases(source) {
    return {
        serviceUpdateUsesNativeActivation() {
            const { sandbox, log } = installer(source);
            assert.strictEqual(sandbox.module.exports.update, sandbox.windowsNativeUpdate, 'Windows update entry is windowsNativeUpdate');
            sandbox.windowsNativeUpdate(true, updateParameters(['--update-source=C:\\Stage\\agent.update.pkg', '--update-dll=C:\\Stage\\MeshService.dll']));
            assert.deepStrictEqual(log.activations, [['C:\\Stage\\agent.update.pkg', 'C:\\Stage\\MeshService.dll', 'Fixture Agent', 'Fixture quoted description']]);
            assert.deepStrictEqual(log.exits, [0]);
            assert.deepStrictEqual(log.childProcess, [], 'no child process');
        },
        consoleAgentUpdateIsRefused() {
            const { sandbox, log } = installer(source);
            assert.throws(() => sandbox.windowsNativeUpdate(false, updateParameters(['--update-source=C:\\Stage\\agent.update.pkg'])), /Windows console self-update is disabled/);
            assert.deepStrictEqual(log.activations, []);
        },
        missingStagedPackageFails() {
            const { sandbox, log } = installer(source);
            sandbox.windowsNativeUpdate(true, updateParameters([]));
            assert(log.stdout.some((line) => line.includes('requires an explicit staged package path')));
            assert.deepStrictEqual(log.exits, [1]);
        },
        runtimeWithoutNativeActivationFails() {
            const { sandbox, log } = installer(source, { nativeFullUpdate: false });
            sandbox.windowsNativeUpdate(true, updateParameters(['--update-source=C:\\Stage\\agent.update.pkg']));
            assert(log.stdout.some((line) => line.includes('activation is unavailable')));
            assert.deepStrictEqual(log.activations, []);
            assert.deepStrictEqual(log.exits, [1]);
        },
        rejectedActivationFails() {
            const { sandbox, log } = installer(source, { activateNativeUpdate() { return false; } });
            sandbox.windowsNativeUpdate(true, updateParameters(['--update-source=C:\\Stage\\agent.update.pkg']));
            assert(log.stdout.some((line) => line.includes('did not accept the staged package')));
            assert.deepStrictEqual(log.exits, [1]);
        },
        updateIsNotAPackageLifecycleAction() {
            const { sandbox } = installer(source);
            assert.strictEqual(sandbox.isWindowsPackageLifecycleAction('update'), false);
            assert.strictEqual(sandbox.isWindowsPackageLifecycleAction('install'), true);
        },
        noLegacyUpdateExe() {
            assert(!source.includes("'.update.exe'") && !source.includes('".update.exe"'), 'legacy .update.exe path');
            assert(!source.includes("runWindowsNativeLifecycle('update'"), 'no direct update manifest path');
        }
    };
}

// ---- 3. Native sources (read, not executed) -------------------------------------------------

function nativeCases(sources) {
    const { agentcore, updateDefines, serviceMain, runtimeHostContract, serviceDeployment } = sources;
    const selfUpdate = extractFunction(agentcore, 'void MeshServer_selfupdate_continue(MeshAgentHostContainer *agent)');
    const activate = extractFunction(agentcore, 'static duk_ret_t ILibDuktape_MeshAgent_ActivateNativeUpdate(duk_context *ctx)');
    const ingress = extractFunction(serviceMain, 'static int MeshService_RunSelfUpdateIngress(int argc, WCHAR** wideArgv)');
    const lifecycleHost = extractFunction(runtimeHostContract, 'void CALLBACK MeshLifecycleHostW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)');
    const dispatcher = extractFunction(serviceDeployment, 'static BOOL ServiceDeploy_RunLifecycleOperation(ServiceLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL requireConfig)');
    return {
        agentcorePublishesNativeUpdate() {
            assert(agentcore.includes('"nativeFullUpdate"') && agentcore.includes('"activateNativeUpdate"'));
        },
        zipPayloadIsProbedAndOptionalModulesGuarded() {
            assert(agentcore.includes('static int MeshServer_UpdateFileLooksZip(char *updateFilePath)') && agentcore.includes('MeshServer_UpdateFileLooksZip(updateFilePath)'));
            assert(agentcore.includes('duk_peval_string(agent->meshCoreCtx, "require(\'zip-reader\')")'));
            assert(agentcore.includes('duk_peval_string(agent->meshCoreCtx, "require(\'update-helper\')")'));
            assert(!agentcore.includes('duk_eval_string(agent->meshCoreCtx, "require(\'zip-reader\')");'));
            assert(!agentcore.includes('duk_eval_string(agent->meshCoreCtx, "require(\'update-helper\')");'));
            assert(agentcore.includes('SelfUpdate -> zip-reader unavailable; treating non-zip payload as native update'));
            assert(agentcore.includes('SelfUpdate -> zip-reader unavailable for zipped update'));
        },
        updateConstantsHaveOneHeader() {
            assert(/#define\s+MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX\s+"\.update\.pkg"/.test(updateDefines));
            assert(/#define\s+MESHAGENT_UPDATE_ACTIVATION_TARGET_KEY\s+"UpdateActivationTargetHash"/.test(updateDefines));
            assert(/#define\s+MESHAGENT_UPDATE_ACTIVATION_FAILURE_KEY\s+"UpdateActivationFailureHash"/.test(updateDefines));
            assert(/#define\s+MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS\s+600000/.test(updateDefines));
            assert(agentcore.includes('#include "config/update_defines.h"'));
            assert(serviceDeployment.includes('#include "../meshcore/config/update_defines.h"'));
            assert(!agentcore.includes('#define MESHAGENT_WINDOWS_UPDATE_PACKAGE_SUFFIX'));
            assert(!serviceDeployment.includes('#define SERVICE_UPDATE_ACTIVATION_TARGET_KEY'));
        },
        selfUpdateStartsTheLifecycleHostAndFailsClosed() {
            assert(selfUpdate.includes('SelfUpdate -> Launching compatibility lifecycle update activation'));
            assert(selfUpdate.includes('MeshServer_StartUpdateActivation(agent, w_updatefile)'));
            assert(!selfUpdate.includes('MeshRuntimeHost_LaunchLifecycleHostW('), 'the self-update path does not block on the host');
            assert(selfUpdate.includes('MeshServer_FailUpdateActivation(agent, 1); // Fail closed'));
            assert(agentcore.includes('MeshRuntimeHost_StartLifecycleHostW(MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE'));
            assert(agentcore.includes('SelfUpdate -> Native lifecycle update requires the compatibility runtime; legacy command-shell path disabled.'));
        },
        lifecycleHostIsObservedWithoutBlocking() {
            assert(agentcore.includes('ILibChain_AddWaitHandle(agent->chain, activation->launch.process, MESHAGENT_UPDATE_ACTIVATION_TIMEOUT_MS'));
            assert(agentcore.includes('MeshRuntimeHost_CompleteLifecycleHostW(&(activation->launch), &exitCode)'));
            assert(agentcore.includes('MeshRuntimeHost_ReleaseLifecycleHostW(&(activation->launch))'));
            assert(agentcore.includes('SelfUpdate -> RuntimeHost lifecycle update activation completed'));
            assert(agentcore.includes('SelfUpdate -> FAILED compatibility lifecycle update activation'));
            assert(agentcore.includes('keeping current agent online'));
        },
        noUpdateHoldsAreKept() {
            for (const removed of ['MeshAgent_RecordUpdateActivationTargetHash', 'MeshAgent_ReadUpdateActivationFailureHash', 'suppressing repeat activation']) {
                assert(!agentcore.includes(removed), removed);
            }
            assert(agentcore.includes('ILibSimpleDataStore_Delete(agent->masterDb, "UpdateActivationTargetHash");'));
            assert(agentcore.includes('ILibSimpleDataStore_Delete(agent->masterDb, "UpdateActivationFailureHash");'));
            assert(serviceDeployment.includes('ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]")'));
            assert(!serviceDeployment.includes('ServiceDeploy_RecordUpdateActivationFailureHold'));
            assert(!serviceDeployment.includes('Recorded failed update activation package hash hold'));
        },
        noLegacyUpdateExe() {
            for (const token of ['.update.exe', '_wexecve', '-fullupdate']) { assert(!agentcore.includes(token), token); }
        },
        ingressesConvergeOnOneTransaction() {
            assert(activate.includes('MeshAgent_RunNativeServiceFullUpdate('));
            assert(ingress.includes('MeshRuntimeHost_LaunchLifecycleHostW('));
            assert(lifecycleHost.includes('ServiceDeploy_RunLifecycleHostOperation('));
            assert.strictEqual((serviceDeployment.match(/static BOOL ServiceDeploy_ApplyUpdateFlow\([^;{]*\)\s*\{/g) || []).length, 1, 'one update transaction executor');
            assert(dispatcher.includes('ok = ServiceDeploy_ApplyUpdateFlow(sourceExePath, sourceDllPath, requireConfig);'));
        }
    };
}

// ---- Run ------------------------------------------------------------------------------------

const report = { paths, results: {} };
let failed = 0;
function group(name, cases) {
    const run = runCases('meshcentral_service_host_selfupdate_contract ' + name, cases);
    report.results[name] = run.results;
    failed += run.failed;
}

group('meshcore updater', updaterCases(readSource(paths.meshcore, 'MeshCentral agent core whose JavaScript updater is executed')));
group('recoverycore updater', updaterCases(readSource(paths.recoverycore, 'MeshCentral recovery core whose JavaScript updater is executed')));
group('agent installer', installerCases(readSource(paths.agentInstaller, 'agent installer whose Windows update delegation is executed')));
group('native sources', nativeCases({
    agentcore: readSource(paths.agentcore, 'agent core whose native self-update path is read'),
    updateDefines: readSource(paths.updateDefines, 'update constants header'),
    serviceMain: readSource(paths.serviceMain, 'service entry whose self-update ingress is read'),
    runtimeHostContract: readSource(paths.runtimeHostContract, 'runtime host whose lifecycle host is read'),
    serviceDeployment: readSource(paths.serviceDeployment, 'service deployment whose update transaction is read')
}));
if (failed) { process.exitCode = 1; }

const evidenceDir = evidenceDirFromArgs(process.argv);
if (evidenceDir) {
    writeEvidence(evidenceDir, 'meshcentral_service_host_selfupdate_contract', report, [
        'AGENTCORE_PATH=' + paths.agentcore,
        'AGENT_INSTALLER_PATH=' + paths.agentInstaller,
        'SERVICE_INSTALLER_PATH=' + paths.serviceDeployment,
        'MESHCORE_PATH=' + paths.meshcore,
        'RECOVERYCORE_PATH=' + paths.recoverycore,
        'SUCCESS=' + (failed === 0)
    ]);
}
