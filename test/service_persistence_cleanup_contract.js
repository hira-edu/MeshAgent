'use strict';
// Wiring checks supplement the native COM and orchestration fault harnesses.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'meshservice/service_deployment.c'), 'utf8');
function body(name) {
    const masked = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, m => ' '.repeat(m.length));
    const match = new RegExp('(?:static )?(?:BOOL|void|size_t) ' + name + '\\s*\\([^;{]+\\)\\s*\\{').exec(masked);
    assert(match, name);
    let end = match.index + match[0].length, depth = 1;
    while (depth) { depth += (masked[end] === '{') - (masked[end] === '}'); ++end; }
    return source.slice(match.index, end);
}
const cleanup = body('ServiceDeploy_RemoveScheduledTasks');
assert(cleanup.includes('!FaultRecovery_DeleteTask('));
assert(cleanup.includes('!FaultRecovery_RemoveServiceRecoveryMonitor('));
assert(cleanup.includes('!FaultRecovery_DeleteTasksByPrefix('));
assert(cleanup.includes('!FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix('));
assert(cleanup.includes('!ServiceDeploy_RemoveLegacyRecoveryArtifacts('));
assert(cleanup.indexOf('ServiceDeploy_QueryRecoveryArtifacts(') < cleanup.indexOf('return ServiceDeploy_ClearServiceRecoveryState();'));
assert(body('ServiceDeploy_SuspendServiceRecoveryRestarters').includes('return ServiceDeploy_RemoveScheduledTasks('));
const discovery = body('ServiceDeploy_DiscoverCurrentState');
for (const name of ['ServiceDeploy_QueryRunKeyPresence', 'ServiceDeploy_QueryRecoveryArtifacts', 'ServiceDeploy_QueryRecoveryStatePresence']) {
    assert(discovery.includes('!' + name + '('), `${name}: failed inspection must propagate`);
    assert(body('ServiceDeploy_RunUninstallValidation').includes(name + '('), `${name}: validation shares raw inspection`);
}
assert(discovery.includes('discovery->anyPersistenceArtifacts = rawRunPresent || rawTasksPresent || rawMonitorsPresent || rawStatePresent;'));
const uninstall = body('ServiceDeploy_ApplyUninstallFlow');
assert(uninstall.includes('!ServiceDeploy_RemoveRunKeyEntry('));
assert(uninstall.includes('!ServiceDeploy_RemoveScheduledTasks('));
assert(uninstall.includes('if (!ServiceDeploy_StopServiceAndWait('));
assert(uninstall.indexOf('!ServiceDeploy_RemoveScheduledTasks(') < uninstall.indexOf('ServiceHost_UnregisterServiceHostService('));
assert(uninstall.indexOf('if (!ServiceDeploy_StopServiceAndWait(') < uninstall.indexOf('ServiceDeploy_RemoveIncumbentFiles('));
assert(!uninstall.includes('success = TRUE;', uninstall.indexOf('ServiceLifecycleDiscovery finalState')));
const reconcile = body('ServiceDeploy_ReconcileCommittedTransaction');
assert(reconcile.indexOf('ServiceDeploy_CleanupConflictingServiceAliases(') < reconcile.indexOf('ServiceDeploy_ReconcileServiceRecovery('));
assert(body('ServiceDeploy_BuildTaskPrefixCandidates').includes('size_t modernCount = count;'));
assert(!body('ServiceDeploy_BuildTaskPrefixCandidates').includes('capacity, SERVICE_FALLBACK_SERVICE_NAME)'));
console.log('Persistence wiring: checked cleanup, raw discovery/validation, quiesce ordering, alias reconciliation and scoped prefixes passed');
