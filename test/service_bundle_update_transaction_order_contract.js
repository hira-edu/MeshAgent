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
        installer.includes('ServiceDeploy_RecordUpdateActivationFailureHold(&paths)') &&
        installer.includes('ServiceDeploy_ClearUpdateActivationHolds(&paths, L"[UPDATE]")'),
        'update transaction must clear activation holds on success and promote the target hold on failure'
    );
    const checkpoint = updateFlow.indexOf('ServiceDeploy_WriteTransactionPhase(&tx, serviceKeyName, SERVICE_JOURNAL_PREPARED)');
    const disableStart = updateFlow.indexOf('ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_DISABLED)');
    const disableRecovery = updateFlow.indexOf('ServiceDeploy_ClearServiceRecovery(serviceKeyName)');
    const stop = updateFlow.indexOf('ServiceDeploy_StopServiceAndWait(serviceKeyName, 30000,');
    assert(checkpoint >= 0 && checkpoint < disableStart, 'durable original binding must precede start-policy mutation');
    assert(disableStart < stop && disableRecovery >= 0 && disableRecovery < stop,
        'SCM launches and recovery must be suspended before quiescing the old process');
    assert(updateFlow.includes('ServiceBinding_Restore(serviceKeyName, tx.originalBinding)'),
        'rollback must restore the captured original service policy');
    assert(updateFlow.includes('ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_AUTO_START)'),
        'successful activation must configure the new runtime for auto-start');

    console.log(JSON.stringify({
        success: true,
        checks: {
            serviceDllCommittedBeforeExe: true,
            serviceDllValidatedBeforeExe: true,
            serviceDllRolledBackBeforeExe: true,
            updateActivationHoldConvergesWithTransaction: true,
            durableCheckpointPrecedesStartPolicyMutation: true,
            updateSuspendsLaunchesBeforeStop: true,
            rollbackRestoresOriginalServicePolicy: true
        }
    }, null, 2));
}

main();
