const fs = require('fs');
const path = require('path');
const assert = require('assert');

function read(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
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
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated function: ${signature}`);
}

const repo = path.resolve(__dirname, '..');
const serverPath = path.resolve(repo, '..', 'MeshCentral', 'meshagent.js');
const corePaths = [
    path.resolve(repo, '..', 'MeshCentral', 'agents', 'meshcore.js'),
    path.resolve(repo, '..', 'MeshCentral', 'agents', 'meshcore.min.js'),
    path.resolve(repo, '..', 'MeshCentral', 'agents', 'recoverycore.js')
];
const agentcorePath = path.resolve(repo, 'meshcore', 'agentcore.c');
const installerPath = path.resolve(repo, 'meshservice', 'stealth_installer.c');
const fsBindingPath = path.resolve(repo, 'microscript', 'ILibDuktape_fs.c');
const updateHelperPath = path.resolve(repo, 'modules', 'update-helper.js');
const zipReaderPath = path.resolve(repo, 'modules', 'zip-reader.js');

const server = read(serverPath);
const agentcore = read(agentcorePath);
const installer = read(installerPath);
const fsBinding = read(fsBindingPath);
const updateHelper = read(updateHelperPath);
const zipReader = read(zipReaderPath);

const selectorFactory = new Function('obj', 'args', 'domain', 'parent', [
    extractFunction(server, 'function isWindowsServiceAgentArchitecture(agentId)'),
    extractFunction(server, 'function isWindowsAgentArchitecture(agentId)'),
    extractFunction(server, 'function compareAgentBinaryHash(agentExeInfo, agentHash)'),
    'return compareAgentBinaryHash;'
].join('\n'));

function select(id, agentHash, options = {}) {
    const obj = {
        agentInfo: { capabilities: 0 },
        AgentCommitDate: options.commitDate,
        agentUpdateFailureHash: options.failedHash
    };
    const args = { agentupdatesystem: options.system };
    const domain = {};
    const parent = { parent: { meshAgentBinaries: {} } };
    const compare = selectorFactory(obj, args, domain, parent);
    return compare({ id, hash: 'NEW', fileHash: 'RAW', zhash: 'ZIP' }, agentHash);
}

assert.strictEqual(select(3, 'OLD'), 1, 'Windows x86 service must use native update');
assert.strictEqual(select(4, 'OLD', { system: 2 }), 1, 'forced recovery mode must not select the disabled Windows JS updater');
assert.strictEqual(select(22, 'OLD'), 1, 'Windows MinCore service must use native update');
assert.strictEqual(select(43, 'OLD'), 1, 'Windows ARM64 service must use native update');
assert.strictEqual(select(1, 'OLD'), 0, 'Windows console binaries must not accept unsupported self-update');
assert.strictEqual(select(4, 'OLD', { failedHash: 'NEW' }), 0, 'raw failed package must suppress re-download');
assert.strictEqual(select(4, 'OLD', { failedHash: 'RAW' }), 0, 'served-file failed package must suppress re-download');
assert.strictEqual(select(4, 'OLD', { failedHash: 'ZIP' }), 0, 'compressed failed package must suppress re-download');
assert.strictEqual(select(4, 'OLD', { failedHash: 'OTHER' }), 1, 'a different package must remain eligible');

const manualUpdate = server.slice(server.indexOf("case 'agentupdate':"), server.indexOf("case 'agentupdatefailure':"));
assert(manualUpdate.includes('isWindowsServiceAgentArchitecture(obj.agentInfo.agentId)'), 'manual Windows update must branch to native routing');
assert(manualUpdate.includes('obj.sendBinary(common.ShortToStr(12) + common.ShortToStr(0));'), 'manual Windows update must request native hash negotiation');
assert(manualUpdate.includes('obj.agentUpdateRequestPending = true'), 'manual update requests must be coalesced');
assert(server.includes("obj.send(JSON.stringify({ action: 'agentupdatefailurecapability' }));"), 'server must advertise separate failure-status support before hash negotiation');
assert(server.includes('obj.agentUpdateTransferPending = true'), 'native transfers must be guarded against duplicate command-12 responses');
assert(server.includes("case 'agentupdatefailure':"), 'server must accept separate failed-package status');
assert(server.includes("case 'agentupdatefailed':"), 'server must restore the core after an update abort');
const updateFailedCase = server.slice(server.indexOf("case 'agentupdatefailed':"), server.indexOf("case 'agentupdatedownloaded':"));
const restoreCore = extractFunction(server, 'function restoreAgentCoreAfterUpdateFailure()');
assert(updateFailedCase.includes('restoreAgentCoreAfterUpdateFailure()'), 'update abort handling must invoke normal-core restoration');
assert(updateFailedCase.includes('if (obj.agentUpdate != null)'), 'agent-side aborts must clean an active server transfer');
assert(restoreCore.includes('common.ShortToStr(11)'), 'update abort handling must request normal core restoration');
assert(restoreCore.includes('delete obj.agentCoreUpdate'), 'recovery-core selection must be cleared after an update abort');
assert(server.includes("JSON.parse(msg).action == 'agentupdatefailed'"), 'terminal update aborts must be accepted during an active transfer');
assert(server.includes('agentExeInfo.zhash == obj.agentUpdateFailureHash'), 'server must recognize compressed failed-package hashes');

const agentHashCase = agentcore.slice(agentcore.indexOf('case MeshCommand_AgentHash:'), agentcore.indexOf('case MeshCommand_AgentUpdate:'));
assert(agentHashCase.includes('agentupdatefailure'), 'agent must report failed package separately');
assert(agentHashCase.includes('agent->agentHash'), 'agent must report the actual executable hash');
assert(agentHashCase.includes('agent->serverSupportsUpdateFailureStatus'), 'truthful failure reporting must be capability-gated');
assert(agentHashCase.indexOf('agent->agentHash') < agentHashCase.indexOf('agent->serverSupportsUpdateFailureStatus'), 'capable servers must receive installed identity separately from failure status');
assert(agentHashCase.includes('Legacy servers do not understand the separate failure frame'), 'older servers must retain same-package suppression compatibility');
assert(agentcore.includes('strcmp(action, "agentupdatefailurecapability") == 0'), 'agent must consume the server capability advertisement natively');
assert(agentcore.includes('static void MeshServer_ReportUpdateFailure(MeshAgentHostContainer *agent)'), 'agent must report native update aborts');
assert(agentcore.includes('"{\\"action\\":\\"agentupdatefailed\\"}"'), 'agent abort report must use the server restoration action');
const reportUpdateFailure = extractFunction(agentcore, 'static void MeshServer_ReportUpdateFailure(MeshAgentHostContainer *agent)');
assert(reportUpdateFailure.includes('if (!agent->serverSupportsUpdateFailureStatus)'), 'capable servers must restore the core without forced reconnect');
assert(reportUpdateFailure.includes('ILibWebClient_Disconnect(agent->controlChannel)'), 'old servers must recover a cleared core through reconnect after update abort');
assert(agentcore.includes('if (agent->JSRunningAsService == 0) { agent->disableUpdate = 1; }'), 'Windows console updates must be disabled at negotiation');
assert(agentcore.includes('Windows console update rejected; keeping current agent online'), 'defensive console path must not stop the chain');

const finalizer = extractFunction(installer, 'static BOOL Stealth_FinalizeUpdateTransaction(const StealthInstallPaths* paths, StealthUpdateTransaction* tx)');
assert(!finalizer.includes('tx->backupDir'), 'transaction finalizer must not delete rollback backups');
assert(installer.includes('static BOOL Stealth_DiscardUpdateBackup(StealthUpdateTransaction* tx)'), 'backup disposal must have an explicit commit-point helper');
const updateFlow = extractFunction(installer, 'static BOOL Stealth_ApplyUpdateFlow(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig)');
const lifecycleConverged = extractFunction(installer, 'static BOOL Stealth_IsPrimaryLifecycleConverged(const StealthLifecycleDiscovery* discovery, BOOL requirePendingClear)');
assert(updateFlow.indexOf('Stealth_RecordUpdateActivationFailureHold(&paths)') < updateFlow.indexOf('rollbackOk = Stealth_StartSvchostServiceAndWait'), 'failure hold must be written before rollback service restart');
assert(updateFlow.indexOf('Stealth_WaitForExpectedIdentity(paths.dbPath, &tx.postUpdateIdentity') < updateFlow.indexOf('Stealth_DiscardUpdateBackup(&tx)'), 'backup must survive post-update identity validation');
assert(updateFlow.includes('Preserving transaction artifacts after failed rollback'), 'failed rollback must preserve recovery artifacts');
assert(lifecycleConverged.includes('discovery->serviceRunning'), 'transaction commit health must require a running service');

assert(fsBinding.includes('bytesWritten != (int)length'), 'writeSync must reject short writes');
assert(fsBinding.includes('bytesWritten == bufferLen'), 'stream writes must complete the full chunk');
assert(fsBinding.includes('FS close/flush error'), 'flush failures must be surfaced');
assert(fsBinding.includes('data->writeError = 1'), 'native-pipe short writes must remain sticky until stream completion');
assert(fsBinding.includes('streamError ? "error" : "close"'), 'failed stream flushes must emit error instead of close');
assert(zipReader.includes('this.size = function size(name)'), 'zip metadata must expose expected extracted size');
assert(updateHelper.includes('actualSize != this.zipped.size(this.entryName)'), 'ZIP extraction must validate output size');
assert(updateHelper.includes('this.prom.source.crc != this.zipped.crc(this.entryName)'), 'ZIP extraction must validate output CRC');
assert(zipReader.includes("_eocdr.self._fail('ZIP end-of-central-directory record is missing')"), 'malformed ZIP metadata must reject instead of hanging');

for (const corePath of corePaths) {
    const core = read(corePath);
    const label = path.basename(corePath);
    assert(core.includes("typeof updateoptions.hash != 'string'"), `${label} must require SHA-384`);
    assert(core.includes('img.statusCode != 200'), `${label} must reject non-200 responses`);
    assert(core.includes('renameSync(stagedUpdatePath, process.execPath)'), `${label} must atomically replace POSIX executable`);
    assert(!core.includes("require('fs').unlinkSync(process.execPath)"), `${label} must not unlink the live executable first`);
    assert(core.includes("this._file.on('error'"), `${label} must observe staged-file write failures`);
    assert(core.includes("try { this._file = require('fs').createWriteStream(stagedUpdatePath"), `${label} must recover from synchronous staged-file open failures`);
    assert(core.includes('if (!self._fileClosed) { self._verifiedHash = h; return; }'), `${label} must wait for a successful staged-file close before activation`);
    assert(core.includes("SendCommand({ action: 'agentupdatefailed' })"), `${label} must request normal-core restoration after aborting an update`);
    assert(core.includes('agentupdateex https://server/path SHA384'), `${label} direct updates must require a hash`);
}

console.log(JSON.stringify({
    success: true,
    checks: {
        windowsNativeRouting: true,
        truthfulInstalledHash: true,
        rawAndCompressedFailureSuppression: true,
        rollbackBackupLifetime: true,
        preRestartFailurePersistence: true,
        strictStorageWrites: true,
        verifiedZipExtractionSize: true,
        atomicPosixReplacement: true,
        mandatoryHashAndHttpStatus: true
    }
}, null, 2));
