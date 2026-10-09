const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

function read(relativePath) {
    return fs.readFileSync(path.resolve(relativePath), 'utf8').replace(/\r\n?/g, '\n');
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function: ${signature}`);
    const bodyStart = source.indexOf('{', start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth += 1;
        else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated function: ${signature}`);
}

const deployment = read('meshservice/service_deployment.c');
const serviceHost = read('meshservice/service_host.c');
const runtimeHeader = read('meshservice/runtime_host_contract.h');
const runtimeContract = read('meshservice/runtime_host_contract.c');
const journal = read('meshservice/service_transaction_journal.h');
const interruptedRecovery = extractFunction(deployment, 'static BOOL ServiceDeploy_RecoverInterruptedTransaction(void)');

assert(deployment.includes('BOOL ServiceDeploy_GetUpdateStartupDisposition('),
    'service deployment must expose an explicit startup disposition');
assert(deployment.includes('ServiceDeploy_QueryLifecycleOperationActive(&lifecycleActive)'),
    'startup disposition must distinguish an owned update from an abandoned checkpoint');
assert(deployment.includes('ServiceDeploy_QueryRecoveryStartupAuthorized(&recoveryStartAuthorized)') &&
    interruptedRecovery.includes('ServiceDeploy_CreateRecoveryStartupAuthorization(&recoveryStartupAuthorization)'),
    'the recovery helper must explicitly authorize only its own restored-service start');
assert(deployment.includes('record->phase != SERVICE_JOURNAL_ACTIVATING') &&
    deployment.includes('record->phase != SERVICE_JOURNAL_COMMITTED'),
    'only activation and committed reconciliation may start while the lifecycle mutex is owned');
assert(journal.includes('#define SERVICE_JOURNAL_ACTIVATING 5') &&
    journal.includes('ServiceJournal_PhaseRequiresBackups'),
    'activation-ready checkpoints must retain the rollback set');
assert(!deployment.includes('ServiceDeploy_SetServiceStartType(serviceKeyName, SERVICE_DISABLED)') &&
    !deployment.includes('ServiceDeploy_SetServiceStartType(serviceName, SERVICE_DISABLED)'),
    'update and interrupted recovery must not disable service startup');
assert(deployment.includes('ServiceDeploy_SuspendServiceRecoveryRestarters()'),
    'event-driven restarters must be suspended across intentional update stops');
assert(serviceHost.includes('ServiceHost_ApplyUpdateStartupDisposition(&stopForUpdateRecovery)') &&
    serviceHost.includes('MESH_RUNTIME_HOST_LIFECYCLE_ACTION_RECOVER_UPDATE') &&
    serviceHost.includes('MeshRuntimeHost_ReleaseLifecycleHostW(&launch)'),
    'ServiceMain must delegate abandoned recovery before creating the agent');
assert(serviceHost.indexOf('MeshAgent_Create(0)') > 0 &&
    serviceHost.indexOf('ServiceHost_ApplyUpdateStartupDisposition(&stopForUpdateRecovery)') <
    serviceHost.indexOf('MeshAgent_Create(0)'),
    'startup recovery must run before MeshAgent_Create');
const disposition = extractFunction(deployment, 'BOOL ServiceDeploy_GetUpdateStartupDisposition(');
assert(disposition.indexOf('GetFileAttributesW(tx.journalPath)') >= 0 &&
    disposition.indexOf('GetFileAttributesW(tx.journalPath)') < disposition.indexOf('ServiceDeploy_TransactionPathsSafe(&paths, &tx)'),
    'an absent checkpoint must proceed before state directory validation can block startup');
assert(runtimeHeader.includes('MESH_LIFECYCLE_ACTION_RECOVER_UPDATE_W L"recover-update"') &&
    runtimeContract.includes('MESH_RUNTIME_HOST_LIFECYCLE_ACTION_RECOVER_UPDATE'),
    'the recovery lifecycle action must round-trip through the manifest contract');
const delegatedRecovery = extractFunction(deployment, 'static BOOL ServiceDeploy_RunDelegatedUpdateRecovery(void)');
assert(deployment.includes('return ServiceDeploy_RunDelegatedUpdateRecovery();') &&
    delegatedRecovery.includes('ok = ServiceDeploy_RecoverInterruptedTransaction();') &&
    delegatedRecovery.includes('attempt <= 3'),
    'the recovery lifecycle host must invoke bounded transaction recovery under the mutex');
assert(delegatedRecovery.indexOf('if (!ok) { return FALSE; }') >= 0 &&
    delegatedRecovery.indexOf('if (!ok) { return FALSE; }') < delegatedRecovery.indexOf('ServiceDeploy_StartServiceHostServiceAndWait(serviceName, 30000)'),
    'delegated recovery must start the service only after the checkpoint is resolved');
assert(!interruptedRecovery.includes('UpdateActivationFailureHold') &&
    interruptedRecovery.includes('ServiceDeploy_StartServiceHostServiceAndWait(serviceName, 30000)'),
    'interrupted recovery must record no update hold and must not fail for a missing activation target');
assert(interruptedRecovery.includes('Restored service did not report its original identity in time') &&
    interruptedRecovery.includes('if (ok) { ok = ServiceDeploy_ResolveUpdateTransaction(&tx, serviceName); }'),
    'identity timeout must be advisory and the restored checkpoint must be resolved');

console.log(JSON.stringify({
    success: true,
    checks: {
        startupDispositionUsesLifecycleOwnership: true,
        restoredServiceStartExplicitlyAuthorized: true,
        quiescedPhasesCannotStartAgent: true,
        activationPhaseRetainsRollback: true,
        serviceStartTypeRemainsBootable: true,
        recoveryTriggersSuspendedDuringStop: true,
        abandonedRecoveryDelegatedBeforeAgentCreate: true,
        recoveryManifestActionRoundTrips: true,
        recoveryRecordsNoUpdateHold: true,
        identityTimeoutDoesNotRetainCheckpoint: true,
        absentCheckpointProceedsBeforeStateValidation: true,
        delegatedRecoveryRetriesThenStartsResolvedService: true
    }
}, null, 2));
