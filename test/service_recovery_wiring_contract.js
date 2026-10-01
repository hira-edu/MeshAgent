const fs = require('fs');
const path = require('path');

function read(relativePath) {
    return fs.readFileSync(path.resolve(relativePath), 'utf8').replace(/\r\n?/g, '\n');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`service recovery wiring contract failed: ${message}`);
    }
}

// Returns the body of a C/C++ function definition by name: the occurrence whose
// parameter list is followed by the opening brace, so prototypes and call sites
// are skipped.
function extractFunction(source, name) {
    let start = source.indexOf(name + '(');
    while (start >= 0) {
        let depth = 0;
        let i = start + name.length;
        for (; i < source.length; ++i) {
            if (source[i] === '(') {
                depth += 1;
            } else if (source[i] === ')') {
                depth -= 1;
                if (depth === 0) {
                    break;
                }
            }
        }
        if (/^\s*\{/.test(source.slice(i + 1, i + 16))) {
            const bodyStart = source.indexOf('{', i);
            depth = 0;
            for (let j = bodyStart; j < source.length; ++j) {
                if (source[j] === '{') {
                    depth += 1;
                } else if (source[j] === '}') {
                    depth -= 1;
                    if (depth === 0) {
                        return source.slice(start, j + 1);
                    }
                }
            }
            throw new Error(`${name} body end not found`);
        }
        start = source.indexOf(name + '(', start + name.length);
    }
    throw new Error(`${name} definition not found`);
}

function main() {
    const config = JSON.parse(read('branding_config.json'));
    const templateConfig = JSON.parse(read('branding_config.template.json'));
    const schema = JSON.parse(read('schema/meshagent.schema.json'));
    const generator = read('tools/generate_branding_assets.py');
    const profile = read('meshcore/config/persistence_config.h');
    const deployment = read('meshservice/service_deployment.c');
    const recovery = read('meshservice/fault_recovery.cpp');
    const recoveryHeader = read('meshservice/fault_recovery.h');
    const runtimePolicy = read('meshservice/runtime_policy.c');
    const runtimeInit = read('meshservice/runtime_init.c');

    for (const [name, value] of Object.entries({ config, templateConfig })) {
        assert(value.persistence.runKey === true, `${name} enables the Run key`);
        assert(value.persistence.serviceRecoveryTask &&
            value.persistence.serviceRecoveryTask.enabled === true,
            `${name} enables the service recovery task independently`);
        assert(value.persistence.serviceRecoveryMonitor &&
            value.persistence.serviceRecoveryMonitor.enabled === true,
            `${name} enables the service recovery monitor independently`);
    }

    // The schema must declare both recovery blocks so the active config is
    // validated against them, and the active branding config must carry both.
    const schemaPersistence = schema.properties &&
        schema.properties.persistence &&
        schema.properties.persistence.properties;
    assert(schemaPersistence &&
        schemaPersistence.serviceRecoveryTask &&
        schemaPersistence.serviceRecoveryMonitor,
        'schema declares serviceRecoveryTask and serviceRecoveryMonitor');
    assert(config.persistence &&
        typeof config.persistence.serviceRecoveryTask === 'object' &&
        config.persistence.serviceRecoveryTask !== null &&
        typeof config.persistence.serviceRecoveryMonitor === 'object' &&
        config.persistence.serviceRecoveryMonitor !== null,
        'branding_config.json carries both recovery blocks');

    assert(generator.includes('#define MESH_AGENT_SERVICE_RECOVERY_TASK_ENABLED') &&
        generator.includes('#define MESH_AGENT_SERVICE_RECOVERY_MONITOR_ENABLED'),
        'generator emits explicit service-recovery controls');
    assert(profile.includes('mesh_service_recovery_task_t serviceRecoveryTask;') &&
        profile.includes('mesh_service_recovery_monitor_t serviceRecoveryMonitor;'),
        'active profile represents recovery task and monitor independently');

    // Function-scoped slices keep each invariant anchored to the routine that
    // owns it instead of matching an incidental mention elsewhere in the file.
    const addRunKey = extractFunction(deployment, 'ServiceDeploy_AddRunKeyIfEnabled');
    const applyRecoveryTask = extractFunction(deployment, 'ServiceDeploy_ApplyServiceRecoveryTask');
    const applyRecoveryMonitor = extractFunction(deployment, 'ServiceDeploy_ApplyServiceRecoveryMonitor');
    const createTask = extractFunction(recovery, 'FaultRecovery_CreateServiceRecoveryTask');
    const createMonitor = extractFunction(recovery, 'FaultRecovery_CreateServiceRecoveryMonitor');

    // The Run key value must be created before it is read back for exact-match
    // verification; check the real index ordering, not just co-occurrence.
    const runKeyCreateIdx = addRunKey.indexOf('RegCreateKeyExW(');
    const runKeySetIdx = addRunKey.indexOf('RegSetValueExW(');
    const runKeyVerifyIdx = addRunKey.indexOf('ServiceDeploy_RunKeyValueExists(serviceName, actual');
    assert(runKeyCreateIdx >= 0 && runKeySetIdx > runKeyCreateIdx &&
        runKeyVerifyIdx > runKeySetIdx &&
        addRunKey.includes('wcscmp(actual, command) != 0'),
        'Run key is created and written before exact-value verification');

    assert(applyRecoveryTask.includes('FaultRecovery_CreateServiceRecoveryTask(') &&
        applyRecoveryTask.includes('FaultRecovery_ServiceRecoveryTaskMatches(') &&
        applyRecoveryTask.includes('FaultRecovery_FormatServiceStopEventXPath(serviceEventName'),
        'deployment creates and verifies the service recovery task');
    assert(applyRecoveryMonitor.includes('FaultRecovery_CreateServiceRecoveryMonitor(') &&
        applyRecoveryMonitor.includes('FaultRecovery_ServiceRecoveryMonitorMatches('),
        'deployment creates and verifies the service recovery monitor');
    assert(deployment.includes('if (!ServiceDeploy_ReconcileServiceRecovery()) { ok = FALSE; }') &&
        runtimeInit.includes('if (!ServiceDeploy_ReconcileServiceRecovery())'),
        'install reconciliation and runtime initialization observe recovery failures');

    // TASK_CREATE_OR_UPDATE lives in the shared RegisterTaskDefinition helper the
    // create path calls, so keep it whole-file; the trigger/action belong to the
    // recovery-task definition itself.
    assert(recovery.includes('TASK_CREATE_OR_UPDATE') &&
        createTask.includes('TASK_TRIGGER_EVENT') &&
        createTask.includes('TASK_ACTION_EXEC'),
        'recovery task is deterministic and idempotent through Task Scheduler COM');
    assert(createMonitor.includes('WBEM_FLAG_CREATE_OR_UPDATE') &&
        createMonitor.includes('__EventFilter') &&
        createMonitor.includes('CommandLineEventConsumer') &&
        createMonitor.includes('__FilterToConsumerBinding') &&
        createMonitor.includes("PreviousInstance.State<>'Stopped'"),
        'monitor filter, handler, and binding are all created');
    assert(createMonitor.includes('BuildWmiBindingPath(filterPath, consumerPath)') &&
        createMonitor.includes('DeleteWmiInstance(services.Get(), bindingPath)'),
        'monitor rollback removes the binding before its endpoints');
    assert(recoveryHeader.includes('FaultRecovery_ServiceRecoveryTaskMatches(') &&
        recoveryHeader.includes('FaultRecovery_ServiceRecoveryMonitorMatches('),
        'verification APIs are public to lifecycle validation');
    assert(recovery.includes('L"\\\\Microsoft\\\\Windows\\\\Diagnostics"') &&
        recovery.includes('L"\\\\Microsoft\\\\Windows\\\\Diagnostics\\\\%ls"'),
        'the intentional Task Scheduler folder remains unchanged');

    assert(deployment.includes('(discovery->runKeyPresent == wantRunKey)') &&
        deployment.includes('(discovery->recoveryTaskPresent == wantRecoveryTask)') &&
        deployment.includes('(discovery->recoveryMonitorPresent == wantRecoveryMonitor)'),
        'lifecycle health derives expected recovery state from the active profile');
    assert(runtimePolicy.includes('persistence->serviceRecoveryTask.enabled') &&
        runtimePolicy.includes('persistence->serviceRecoveryMonitor.enabled') &&
        runtimePolicy.includes('ServiceDeploy_ReconcileServiceRecovery()'),
        'runtime-policy reapply uses the same deployment authority');

    process.stdout.write(JSON.stringify({ success: true, checks: 18 }, null, 2) + '\n');
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
