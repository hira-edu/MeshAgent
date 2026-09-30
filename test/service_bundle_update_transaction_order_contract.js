const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
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

function main() {
    const installer = read('meshservice/service_deployment.c');
    const updateFlow = extractFunction(installer, 'static BOOL ServiceDeploy_ApplyUpdateFlow(');
    const commit = extractFunction(installer, 'static BOOL ServiceDeploy_CommitUpdateTransaction(');
    const rollback = extractFunction(installer, 'static BOOL ServiceDeploy_RollbackUpdateTransaction(');
    const start = extractFunction(installer, 'static BOOL ServiceDeploy_StartServiceHostServiceAndWait(');
    assert(!installer.includes('ServiceDeploy_AttemptServiceHostStartupRepair'), 'startup must not bypass the package transaction to repair live files');
    assert(!start.includes('ServiceHost_RegisterServiceHostService') && !start.includes('ServiceDeploy_EnsureServiceHostDllFile'), 'SCM startup must not mutate registration or payload');

    const dllCommitIndex = commit.indexOf('tx->stagedDllReady');
    const exeCommitIndex = commit.indexOf('tx->stagedExeReady');
    assert(dllCommitIndex >= 0, 'update commit must explicitly handle staged DLL');
    assert(exeCommitIndex >= 0, 'update commit must explicitly handle staged EXE');
    assert(dllCommitIndex < exeCommitIndex, 'update commit must replace ServiceDll before host EXE');

    const dllInstallIndex = commit.indexOf('Security_InstallFiles(tx->stagedDllPath, paths->dllPath)');
    const exeInstallIndex = commit.indexOf('Security_InstallFiles(tx->stagedExePath, paths->exePath)');
    assert(dllInstallIndex >= 0 && exeInstallIndex >= 0, 'update commit must install both staged binaries');
    assert(dllInstallIndex < exeInstallIndex, 'staged ServiceDll install must precede staged EXE install');
    assert(
        commit.indexOf('ServiceDeploy_ValidateServiceHostPayloadDll(paths->dllPath)') < exeInstallIndex,
        'committed ServiceDll must validate before host EXE replacement'
    );

    const dllRollbackIndex = rollback.indexOf('tx->liveDllExists');
    const exeRollbackIndex = rollback.indexOf('tx->liveExeExists');
    assert(dllRollbackIndex >= 0, 'rollback must explicitly restore live DLL backup');
    assert(exeRollbackIndex >= 0, 'rollback must explicitly restore live EXE backup');
    assert(dllRollbackIndex < exeRollbackIndex, 'rollback must restore ServiceDll before host EXE');
    assert(
        installer.includes('ServiceDeploy_RecordUpdateActivationFailureHold(&paths);') &&
        installer.includes('ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]");'),
        'update transaction must clear activation holds on success and promote the target hold on failure'
    );
    const checkpointIndex = updateFlow.indexOf('ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_PREPARED)');
    const disableIndex = updateFlow.indexOf('ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_DISABLED)');
    const stopIndex = updateFlow.indexOf('ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000,');
    const autoStartIndex = updateFlow.indexOf('ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_AUTO_START)');
    const commitIndex = updateFlow.indexOf('ServiceDeploy_CommitUpdateTransaction(&paths, &tx)');
    assert(checkpointIndex >= 0 && disableIndex > checkpointIndex && stopIndex > disableIndex,
        'original launch policy must be durably checkpointed before disabling automatic launches and stopping');
    assert(updateFlow.indexOf('ServiceDeploy_ClearServiceRecovery(serviceKeyName)') > checkpointIndex,
        'SCM recovery actions may only change after the durable original checkpoint');
    assert(commitIndex > stopIndex && autoStartIndex > commitIndex,
        'automatic startup must stay disabled until the replacement files are committed');
    assert(updateFlow.includes('ServiceDeploy_SetServiceStartType(serviceKeyName, originalStartType)'),
        'rollback must restore the original startup policy');
    assert(
        updateFlow.includes('Failed to restore service auto-start during cleanup'),
        'update cleanup must log and fail closed if service auto-start restoration fails'
    );

    console.log(JSON.stringify({
        success: true,
        checks: {
            serviceDllCommittedBeforeExe: true,
            serviceDllValidatedBeforeExe: true,
            serviceDllRolledBackBeforeExe: true,
            updateActivationHoldConvergesWithTransaction: true,
            updateCheckpointsBeforeDisablingAutomaticLaunches: true,
            updateRestoresAutoStartAfterFileCommit: true,
            updateRestoresAutoStartDuringCleanup: true
        }
    }, null, 2));
}

main();
