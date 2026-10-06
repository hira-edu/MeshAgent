'use strict';
// Executes source functions with injected SCM/filesystem failures; never installs a service.
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const root = path.resolve(__dirname, '..');
const installer = fs.readFileSync(path.join(root, 'modules/agent-installer.js'), 'utf8');
const serviceManager = fs.readFileSync(path.join(root, 'modules/service-manager.js'), 'utf8');
function extract(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, signature);
    const begin = source.indexOf('{', start);
    let depth = 1, end = begin + 1;
    while (depth && end < source.length) { depth += (source[end] === '{') - (source[end] === '}'); ++end; }
    assert.equal(depth, 0, signature);
    return source.slice(start, end);
}
function context(extra = {}) {
    const calls = [];
    const sandbox = {Buffer, module: {exports: {}}, global: {}, Date, calls,
        _MSH: () => ({}),
        console: {info1() {}, log() {}, setDestination() {}, setInfoLevel() {}, Destinations: {DISABLED: 0}},
        process: {platform: 'linux', execPath: '/tmp/newagent', pid: 1, env: {}, stdout: {write() {}}, stderr: {write() {}}, exit(code) {calls.push(['exit', code]);}},
        require(name) { if (name === 'child_process') return {}; throw Error('Unexpected require: ' + name); }, ...extra};
    vm.createContext(sandbox);
    vm.runInContext(`Object.defineProperty(Array.prototype, 'getParameter', {value: function(){throw Error('foreign parser');}});`, sandbox);
    vm.runInContext(installer, sandbox);
    return sandbox;
}
const c = context();
assert.equal(vm.runInContext(`installerParameter(['--meshServiceName="Old Agent"'], 'meshServiceName', 'meshagent')`, c), 'Old Agent');
assert.equal(vm.runInContext(`installerParameter(['--copy-msh=1'], 'copy-msh', '0')`, c), '1');
assert.equal(vm.runInContext(`installerParameter(['--copy-msh="1"'], 'copy-msh', '0')`, c), '1');
assert.throws(() => c.validateInstallerParameters({}), /array/);
assert.throws(() => c.validateInstallerParameters(['--name=x\nAction=uninstall']), /Invalid/);

let closed = 0;
const old = {name: 'OldAgent', appLocation: () => '/opt/old/legacy', appWorkingDirectory: () => '/opt/old', close() {closed++;}};
let parms = [];
assert.equal(c.preserveInstallerLocation(old, parms), '/opt/old/legacy');
assert.equal(c.installerParameter(parms, 'target', null), 'legacy');
assert.equal(c.installerParameter(parms, 'installPath', null), '/opt/old');
assert.throws(() => c.preserveInstallerLocation(old, ['--target=newagent']), /relocate/);
assert.throws(() => c.preserveInstallerLocation(old, ['--installPath=/opt/new']), /relocate/);
let stopped = 0, failed = 0, running = true;
const synchronous = {stop() {running = false;}, isRunning: () => running, close() {closed++;}};
c.stopInstallerService(synchronous, () => stopped++, () => failed++);
assert.equal(stopped, 1);
assert.equal(failed, 0);
running = true;
c.stopInstallerService({...synchronous, stop() {}}, () => stopped++, () => failed++);
assert.equal(stopped, 1, 'a failed stop cannot run destructive continuation');
assert.equal(failed, 1);
running = false;
assert.throws(() => c.stopInstallerService(synchronous, () => {throw Error('replacement failed');}, () => {}), /replacement failed/);

const absent = Object.assign(Error('absent'), {code: 'ENOENT'});
const manager = {getService(name) {if (name === 'OldAgent') return old; throw absent;}, enumerateService: () => [old]};
const lookup = context({require(name) {
    if (name === 'child_process') return {};
    if (name === 'service-manager') return {manager};
    throw Error(name);
}});
parms = [];
assert.equal(lookup.resolveInstallerService(parms, '/opt/old/legacy', false).name, 'OldAgent');
assert.equal(lookup.installerParameter(parms, 'meshServiceName', null), 'OldAgent');
manager.getService = () => {throw Object.assign(Error('access denied'), {code: 'EACCES'});};
assert.throws(() => lookup.resolveInstallerService([], null, false), /access denied/);

const win = vm.createContext({process: {env: {SystemRoot: 'C:\\Windows'}}});
vm.runInContext(extract(serviceManager, 'function windowsServiceExecutable('), win);
assert.equal(win.windowsServiceExecutable('"C:\\Old\\Agent.EXE" -run'), 'C:\\Old\\Agent.EXE');
assert.equal(win.windowsServiceExecutable('"C:\\old.exe.backup\\agent.exe" -run'), 'C:\\old.exe.backup\\agent.exe');
assert.equal(win.windowsServiceExecutable('%SYSTEMROOT%\\System32\\svchost.exe -k group'), 'C:\\Windows\\System32\\svchost.exe');
assert.throws(() => win.windowsServiceExecutable('"C:\\Old\\agent.exe'), /Invalid/);
assert.throws(() => win.windowsServiceExecutable('%MISSING%\\agent.exe'), /Unresolved/);

let now = 0, scheduled = [], results = [];
const stop = vm.createContext({retVal: {}, Date: {now: () => now},
    setTimeout(fn, delay, svc, promise) {scheduled.push(() => fn(svc, promise)); return scheduled.length;}});
vm.runInContext(extract(serviceManager, 'retVal._stopEx = function'), stop);
const svc = {_service: {}, name: 'Mesh Agent', status: {state: 'RUNNING', pid: 123}};
svc._stopEx = stop.retVal._stopEx;
const promise = {_stopRequested: true, _startTime: 0, _waitTime: 500, finish(error) {results.push(error ? 'failure' : 'stopped'); this._settled = true;}};
stop.retVal._stopEx(svc, promise);
assert.equal(scheduled.length, 1, 'RUNNING must continue polling');
assert.deepEqual(results, []);
now = 10001;
scheduled.shift()();
assert.deepEqual(results, ['failure'], 'RUNNING must hit the bounded deadline');
results = []; promise._settled = false; svc.status = {state: 'STOPPED', pid: 0};
stop.retVal._stopEx(svc, promise);
assert.deepEqual(results, ['stopped']);
console.log('Installer compatibility: isolated parsers, identity paths, discovery errors, stop gating, ImagePath and bounded Windows stop passed');

// The GUI package may name a new executable; reinstall must keep the incumbent DB basename.
const reinstall = context({_MSH: () => ({fileName: 'renamed-agent'})});
reinstall.resolveInstallerService = () => old;
let reinstallParameters;
reinstall.serviceExists = (location, args) => {reinstallParameters = args;};
reinstall.fullInstallEx([], null);
assert.equal(reinstall.installerParameter(reinstallParameters, 'target', null), 'legacy');
assert.throws(() => reinstall.fullInstallEx(['--target=other'], null), /relocate/);

// Duktape process.exit throws after setting the exit code; do not catch success as failure.
let exits = [], activationCount = 0;
const exitSignal = new Error('Process.exit() forced script termination');
const native = context();
native.process.platform = 'win32';
native.process.exit = code => {exits.push(code); throw exitSignal;};
native.require = name => {if (name === 'MeshAgent') return {nativeFullUpdate: true, activateNativeUpdate() {activationCount++; return true;}}; throw Error(name);};
assert.throws(() => native.windowsNativeUpdate(true, Buffer.from(JSON.stringify(['--update-source=C:\\stage.pkg'])).toString('base64')), e => e === exitSignal);
assert.deepEqual(exits, [0]);
assert.equal(activationCount, 1);

function updateScenario(failCopy, stillRunning) {
    let isRunning = true, writes = 0, copied = [], renamed = [], exitCodes = [];
    const service = {name: 'Mesh Agent', appLocation: () => '/opt/old/legacy', close() {},
        isRunning: () => isRunning, stop() {if (!stillRunning) isRunning = false;}, start() {isRunning = true;}};
    const sandbox = context();
    sandbox.process.execPath = '/opt/old/legacy.update';
    sandbox.process.exit = code => {exitCodes.push(code); throw exitSignal;};
    sandbox.require = name => {
        if (name === 'user-sessions') return {isRoot: () => true};
        if (name === 'service-manager') return {manager: {getService(n) {if (n === 'Mesh Agent') return service; throw absent;}, enumerateService: () => [service]}};
        if (name === 'fs') return {existsSync: () => true, statSync: () => ({mode: 0o751}), chmodSync() {}, unlinkSync() {},
            copyFileSync(from, to) {assert.equal(isRunning, false); writes++; if (failCopy) throw Error('disk full'); copied.push([from, to]);},
            renameSync(from, to) {renamed.push([from, to]);}};
        throw Error(name);
    };
    assert.throws(() => sandbox.sys_update(true), e => e === exitSignal);
    assert.deepEqual(exitCodes, [failCopy || stillRunning ? 1 : 0]);
    assert.equal(writes, stillRunning ? 0 : 1, 'no copy before confirmed stop and no retry loop');
    assert.equal(renamed.length, failCopy || stillRunning ? 0 : 1);
    assert.equal(isRunning, true, 'failed copy restarts original, successful update restarts service');
    if (renamed.length) assert.equal(renamed[0][1], '/opt/old/legacy');
}
updateScenario(false, false);
updateScenario(true, false);
updateScenario(false, true);
let statusOutput = 'ActiveState=inactive\nMainPID=0\n';
const systemd = vm.createContext({runSystemctl: () => statusOutput});
vm.runInContext(extract(serviceManager, 'function systemdIsRunning('), systemd);
assert.equal(systemd.systemdIsRunning('Mesh Agent'), false);
statusOutput = 'ActiveState=deactivating\nMainPID=20\n';
assert.equal(systemd.systemdIsRunning('Mesh Agent'), true);
statusOutput = '';
assert.throws(() => systemd.systemdIsRunning('Mesh Agent'), /verify/);
console.log('Installer integration: incumbent basename, runtime exit semantics, stop/copy failures and systemd state verification passed');
const nodeIdSource = fs.readFileSync(path.join(root, 'modules/_agentNodeId.js'), 'utf8');
const nodeId = vm.createContext({Buffer, process: {platform: 'win32'}, _MSH: () => ({meshServiceName: 'stale-name'}), require: () => ({serviceName: 'ActualServiceKey', isService: true})});
vm.runInContext(['_runtimeServiceName', '_runningAsWindowsService', '_provisionedServiceName', '_meshName', '_meshDbPath'].map(n => extract(nodeIdSource, 'function ' + n + '(')).join('\n'), nodeId);
assert.equal(nodeId._meshName(), 'ActualServiceKey', 'running service: SCM key wins over stale provisioning name');
assert.equal(nodeId._meshDbPath('C:\\old.exe.backup\\Agent.EXE'), 'C:\\old.exe.backup\\Agent.db');
// Console probes (-name, state): the registry key holding this agent's NodeID identifies a legacy
// install whose SCM key differs from both the runtime default and the package provisioning name.
const legacyNodeId = Buffer.from('legacy-node').toString('hex');
nodeId._meshNodeId = () => legacyNodeId;
nodeId.require = name => name === 'MeshAgent' ? {serviceName: 'BrandingDefault', isService: false} : {HKEY: {LocalMachine: 1, CurrentUser: 2},
    QueryKey(hive, key, value) {
        if (hive !== 1) throw Error('no HKCU entries');
        if (value == null) return {subkeys: ['Other Product', 'Mesh Agent']};
        if (key.endsWith('\\Mesh Agent')) return Buffer.from('legacy-node').toString('base64').split('+').join('@').split('/').join('$');
        throw Error('missing NodeId');
    }};
assert.equal(nodeId._meshName(), 'Mesh Agent', 'console probe discovers the legacy SCM key by NodeID');
nodeId._meshNodeId = () => '';
assert.equal(nodeId._meshName(), 'stale-name', 'without a NodeID the provisioning name precedes the branding default');
nodeId._MSH = () => ({});
assert.equal(nodeId._meshName(), 'BrandingDefault', 'runtime default is the last console fallback');
nodeId.require = name => name === 'MeshAgent' ? {} : {HKEY: {LocalMachine: 1, CurrentUser: 2}};
assert.equal(nodeId._meshName(), null, 'unknown key resolves to null instead of throwing or inventing Mesh Agent');
for (const moduleName of ['umhctl', 'RecoveryCore']) {
    const source = fs.readFileSync(path.join(root, 'modules/' + moduleName + '.js'), 'utf8');
    let lookupError = Object.assign(Error('denied'), {code: 'EWIN32'}), cleaned = 0, result;
    const recovery = vm.createContext({process: {platform: 'win32'},
        require: () => ({manager: {getService() {throw lookupError;}, uninstallService() {throw Error('must not be called');}}}),
        umhctlGetMasterServiceCandidateNames: () => ['MasterService'],
        umhctlCleanupManagedMasterServiceBinaries() {cleaned++; return true;}, sendConsoleText() {}});
    vm.runInContext(['umhctlNormalizeExecutablePath', 'umhctlIsServiceNotFoundError', 'umhctlQueryMasterServiceWindowsState', 'umhctlForceRemoveMasterServiceWindowsService'].map(n => extract(source, 'function ' + n + '(')).join('\n'), recovery);
    assert.equal(recovery.umhctlNormalizeExecutablePath('"C:\\old.exe.backup\\MasterService.EXE" --service'), 'C:\\old.exe.backup\\MasterService.EXE');
    assert.equal(recovery.umhctlNormalizeExecutablePath('"C:\\broken.exe'), null);
    assert.equal(recovery.umhctlNormalizeExecutablePath('C:\\ProgramData\\UserModeHook'), 'C:\\ProgramData\\UserModeHook', 'directory normalization remains usable by managed-root checks');
    assert.equal(recovery.umhctlQueryMasterServiceWindowsState().available, false);
    recovery.umhctlForceRemoveMasterServiceWindowsService(null, 'C:\\Agent', null, value => {result = value;});
    assert.equal(result, false);
    assert.equal(cleaned, 0, 'denied lookup cannot become permission to remove binaries');
    lookupError = absent;
    recovery.umhctlForceRemoveMasterServiceWindowsService(null, 'C:\\Agent', null, value => {result = value;});
    assert.equal(result, true);
    assert.equal(cleaned, 1);
}
console.log('Recovery compatibility: active service key, uppercase DB basename, dotted paths and denied lookup cleanup gates passed');
c.preserveInstallerLocation({...old, escname: 'Mesh\\x20Agent'}, []);
assert.equal(c.global._installedServiceKey, 'Mesh\\x20Agent', 'retain exact systemd key, avoiding a second escape during reinstall');

// A service that becomes RUNNING after START_PENDING still receives one stop request.
now = 0; results = []; scheduled = []; let controls = 0;
promise._settled = false; promise._stopRequested = false;
svc.status = {state: 'START_PENDING', pid: 4};
svc._GM = {CreateVariable() {return {};}};
svc._proxy = {ControlService() {controls++; return {Val: 1};}};
stop.retVal._stopEx(svc, promise);
assert.equal(controls, 0);
svc.status.state = 'RUNNING'; scheduled.shift()();
assert.equal(controls, 1);
svc.status = {state: 'STOPPED', pid: 0}; scheduled.shift()();
assert.deepEqual(results, ['stopped']);
const legacyMsh = {MeshID: 'mesh', ServerID: 'server', MeshServer: 'wss://owned/agent.ashx'};
let candidates = [{...old, name: 'LegacyService'}], opened = [];
const discovery = context({_MSH: () => legacyMsh, require(name) {
    if (name === 'child_process') return {};
    if (name === 'service-manager') return {manager: {
        getService(key) {if (key === 'LegacyService') return candidates[0]; throw absent;},
        enumerateService: () => candidates
    }};
    if (name === 'fs') return {existsSync: file => file === '/opt/old/legacy.db'};
    if (name === 'SimpleDataStore') return {Create(file, options) {
        assert.equal(options.readOnly, true); opened.push(file);
        return {Get: key => legacyMsh[key], GetBuffer: key => key === 'SelfNodeCert' ? Buffer.from('identity') : null};
    }};
    throw Error(name);
}});
parms = [];
assert.equal(discovery.resolveInstallerService(parms, null, false).name, 'LegacyService');
assert.equal(discovery.installerParameter(parms, 'meshServiceName', null), 'LegacyService');
assert.deepEqual(opened, ['/opt/old/legacy.db']);
candidates.push({...old, name: 'OtherLegacy'});
assert.throws(() => discovery.resolveInstallerService([], null, false), /Multiple installed identities/);
const interactiveSource = fs.readFileSync(path.join(root, 'modules/interactive.js'), 'utf8');
let uiClosed = false;
const interactive = vm.createContext({require: () => ({manager: {getService: () => ({
    isRunning() {assert.equal(uiClosed, false, 'GUI must read status before closing the handle'); return true;}, close() {uiClosed = true;}
})}})});
vm.runInContext(extract(interactiveSource, 'function readInteractiveServiceStatus('), interactive);
assert.equal(interactive.readInteractiveServiceStatus('Mesh Agent').running, true);
assert.equal(uiClosed, true);
let cleanupMode = 'denied-lookup', continued = 0;
const cleanup = context({require(name) {
    if (name === 'child_process') return {};
    if (name === 'service-manager') return {manager: {
        uninstallService() {if (cleanupMode === 'uninstall') throw Error('uninstall failed');},
        getService() {if (cleanupMode === 'denied-lookup') throw Object.assign(Error('access denied'), {code: 'EACCES'}); throw absent;}
    }};
    if (name === 'fs') return {existsSync: () => false, readdirSync: () => ['old.db'], unlinkSync() {throw Error('database locked');}};
    throw Error(name);
}});
cleanup.uninstallService3 = () => {continued++;};
assert.throws(() => cleanup.uninstallService2(['_stop'], '/old.msh'), /access denied/);
cleanupMode = 'uninstall';
assert.throws(() => cleanup.uninstallService2(['_stop'], '/old.msh'), /Service uninstall failed/);
cleanupMode = 'data';
assert.throws(() => cleanup.uninstallService2(['_stop', '--_deleteData=1', '_workingDir=/opt/old', '_appPrefix=old'], '/old.msh'), /database locked/);
assert.equal(continued, 0, 'cleanup errors cannot continue into success or reinstall');
