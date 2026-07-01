const fs = require('fs');
const path = require('path');
const contract = require('./test/lib/umh_operator_contract');
const { loadRecoveryCoreVm, getConsoleMessages, RECOVERYCORE_PATH, UMHCTL_PATH } = require('./test/lib/recoverycore_vm');

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

function stableValue(value) {
    if (value == null || typeof value !== 'object') { return value; }
    if (Array.isArray(value)) { return value.map(stableValue); }
    const result = {};
    for (const key of Object.keys(value).sort()) {
        result[key] = stableValue(value[key]);
    }
    return result;
}

function deepEqual(left, right) {
    return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function runMapParityChecks(results, sandbox) {
    assert(deepEqual(sandbox.umhctlControlOpMap, contract.controlOpMap), 'control op map drift');
    assert(deepEqual(sandbox.umhctlPidRequiredOps, contract.pidRequiredOps), 'pid-required map drift');
    assert(deepEqual(sandbox.umhctlStateChangingOps, contract.stateChangingOps), 'state-changing map drift');
    assert(deepEqual(sandbox.umhctlFlowScopedOps, contract.flowScopedOps), 'flow-scoped map drift');
    assert(deepEqual(sandbox.umhctlActionAllowedByOp, contract.actionAllowedByOp), 'action map drift');
    assert(deepEqual(sandbox.umhctlDefaultFlowContract, contract.defaultFlowContract), 'default flow contract drift');
    results.push({ name: 'map-parity', ok: true });
}

function runHelpChecks(results, sandbox) {
    const help = sandbox.umhctlBuildHelp('C:\\ProgramData\\DiagnosticHost', 'C:\\ProgramData\\DiagnosticHost\\MasterService.exe');
    for (const fragment of contract.helpFragments) {
        assert(help.includes(fragment), `help missing fragment: ${fragment}`);
    }
    results.push({ name: 'help-fragments', ok: true, fragmentCount: contract.helpFragments.length });
}

function runExecFileArgChecks(results, sandbox) {
    const argv = sandbox.umhctlBuildExecFileArgs('C:\\ProgramData\\MeshAgent\\MasterService.exe', ['--install', '--silent', '--wait']);
    assert(deepEqual(argv, ['--install', '--silent', '--wait']), 'execFile args must not prepend the executable basename');
    results.push({ name: 'execfile-args', ok: true, argv });
}

function runInstallContractPathChecks(results, sandbox) {
    const originalRequire = sandbox.require;
    try {
        sandbox.require = function (moduleName) {
            if (moduleName === 'win-system-paths') { throw new Error('known folder unavailable in unit fail-closed path'); }
            return originalRequire(moduleName);
        };
        const unavailablePath = sandbox.umhctlInstallContractPath();
        assert(unavailablePath === null, 'install contract path must fail closed when ProgramData known-folder resolution is unavailable');

        sandbox.require = function (moduleName) {
            if (moduleName === 'win-system-paths') { return { programDataDirectory: () => 'C:\\ProgramData' }; }
            return originalRequire(moduleName);
        };
        const contractPath = sandbox.umhctlInstallContractPath();
        assert(contractPath === 'C:\\ProgramData\\UserModeHook\\install_contract.json',
            'install contract path must use the ProgramData known-folder root');

        sandbox.require = function (moduleName) {
            if (moduleName === 'win-system-paths') { return { programDataDirectory: () => 'D:\\ProgramData' }; }
            return originalRequire(moduleName);
        };
        const redirectedPath = sandbox.umhctlInstallContractPath();
        assert(redirectedPath === 'D:\\ProgramData\\UserModeHook\\install_contract.json',
            'install contract path should keep the exact ProgramData known-folder root');
    } finally {
        sandbox.require = originalRequire;
    }
    results.push({ name: 'install-contract-known-folder-path', ok: true });
}

function runInstallContractWriteSignatureChecks(results, sandbox) {
    const originalRequire = sandbox.require;
    const originalWriteFileSync = sandbox.fs.writeFileSync;
    const tmpRoot = path.join(__dirname, 'test_tmp', 'umh_contract_signature');
    const programDataRoot = path.join(tmpRoot, 'ProgramData');

    try {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
        sandbox.require = function (moduleName) {
            if (moduleName === 'win-system-paths') { return { programDataDirectory: () => programDataRoot }; }
            return originalRequire(moduleName);
        };
        sandbox.fs.writeFileSync = function (filePath, data) {
            if (arguments.length > 2) {
                throw new TypeError('number required, found undefined (stack index 1)');
            }
            return originalWriteFileSync.call(this, filePath, data);
        };

        const digest = 'a'.repeat(96);
        const result = sandbox.umhctlWriteInstallContractAtomic(
            'standard',
            'https://high.support/userfiles/hsadmin/MasterService.exe?download=1&sha384=' + digest,
            digest,
            'unit-install-run'
        );
        assert(result && result.ok === true, `install contract write failed: ${result && result.error}`);

        const contractPath = sandbox.umhctlInstallContractPath();
        assert(fs.existsSync(contractPath), 'install contract file was not written');
        const written = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
        assert(written.method_key === 'standard', 'install contract method key mismatch');
        assert(written.payload_sha384 === digest, 'install contract payload hash mismatch');
    } finally {
        sandbox.fs.writeFileSync = originalWriteFileSync;
        sandbox.require = originalRequire;
        fs.rmSync(tmpRoot, { recursive: true, force: true });
    }

    results.push({ name: 'install-contract-writefile-signature', ok: true });
}

function runInstallActivationBoundedChecks(results) {
    for (const modulePath of [RECOVERYCORE_PATH, UMHCTL_PATH]) {
        const source = fs.readFileSync(modulePath, 'utf8');
        assert(source.includes("['--install', '--silent', '--output', 'json', '--require-install-contract']"),
            `${path.basename(modulePath)} must invoke install without opaque native --wait`);
        assert(!source.includes("['--install', '--silent', '--wait', '--timeout', '120', '--output', 'json', '--require-install-contract']"),
            `${path.basename(modulePath)} must not use 120s native install wait`);
        assert(source.includes("umhctl: install process timeout (90s)"),
            `${path.basename(modulePath)} must expose bounded install timeout`);
        assert(!source.includes("umhctl: install process timeout (240s)"),
            `${path.basename(modulePath)} must not retain 240s install timeout`);
    }
    results.push({ name: 'install-activation-bounded', ok: true });
}

function runInstallPendingOwnershipChecks(results, sandbox) {
    const msExePath = 'C:\\ProgramData\\UserModeHook\\MasterService.exe';
    const pendingOutput = JSON.stringify({
        command: 'install',
        success: false,
        wait_requested: false,
        timeout_seconds: 30,
        timed_out: true,
        message: 'service installed, state=2, running=false, stopped=false, start_type=Auto, pid=30780, binary_path=C:\\ProgramData\\UserModeHook\\MasterService.exe; timed_out=true',
        status: {
            available: true,
            installed: true,
            running: false,
            stopped: false,
            state: 2,
            process_id: 30780,
            start_type: 'Auto',
            binary_path: msExePath,
            error: ''
        }
    });

    assert(sandbox.umhctlInstallOutputOwnsManagedBinary(pendingOutput, msExePath) === true,
        'install output with START_PENDING live pid must be treated as SCM-owned');
    assert(sandbox.umhctlServiceStateOwnsManagedBinary({
        installed: true,
        running: true,
        state: 'START_PENDING',
        appLocation: msExePath
    }, msExePath) === true, 'service-manager START_PENDING state must be treated as SCM-owned');
    assert(sandbox.umhctlInstallOutputOwnsManagedBinary(JSON.stringify({
        command: 'install',
        success: false,
        status: {
            available: true,
            installed: false,
            running: false,
            stopped: false,
            state: 0,
            process_id: 0,
            binary_path: ''
        }
    }), msExePath) === false, 'missing service must remain rollback-eligible');

    results.push({ name: 'install-pending-scm-owned-no-rollback', ok: true });
}

function runLifecycleStaleLockChecks(results, sandbox) {
    const originalSendConsoleText = sandbox.sendConsoleText;
    const messages = [];
    try {
        sandbox.sendConsoleText = function (msg, sessionid) {
            messages.push({ msg, sessionid });
        };

        sandbox.umhctlLifecycleOp = 'install';
        sandbox.umhctlLifecycleState = {
            op: 'install',
            sessionid: 'old-session',
            startedAt: Date.now() - 361000,
            phase: 'running install command',
            phaseUpdated: Date.now() - 360000
        };

        const began = sandbox.umhctlBeginLifecycle('install', 'new-session');
        assert(began === true, 'stale lifecycle lock should be cleared after max duration');
        assert(messages.some((entry) => entry.msg.indexOf('clearing stale lifecycle operation install') >= 0),
            'stale lifecycle clear message missing');
        assert(sandbox.umhctlLifecycleState && sandbox.umhctlLifecycleState.sessionid === 'new-session',
            'new lifecycle state was not established after stale clear');
        sandbox.umhctlEndLifecycle('install');

        sandbox.umhctlLifecycleOp = 'install';
        sandbox.umhctlLifecycleState = {
            op: 'install',
            sessionid: 'active-session',
            startedAt: Date.now() - 1000,
            phase: 'running install command',
            phaseUpdated: Date.now() - 1000
        };

        const blocked = sandbox.umhctlBeginLifecycle('install', 'blocked-session');
        assert(blocked === false, 'active lifecycle lock must not be cleared before max duration');
        assert(messages.some((entry) => entry.msg.indexOf('lifecycle operation already running: install') >= 0),
            'active lifecycle blocked message missing');
    } finally {
        sandbox.umhctlEndLifecycle(null);
        sandbox.sendConsoleText = originalSendConsoleText;
    }

    results.push({ name: 'lifecycle-stale-lock-bounded-clear', ok: true });
}

function runProcessCompletionBindingChecks(results, sandbox) {
    const registrations = [];
    const proc = {
        on(eventName, handler) {
            registrations.push(eventName);
            if (eventName === 'close') { throw new Error('close unsupported'); }
            this.boundHandler = handler;
        }
    };
    const chosenEvent = sandbox.umhctlAttachProcessCompletion(proc, function () {});
    assert(chosenEvent === 'exit', 'process completion must use exit when close is unavailable');
    assert(deepEqual(registrations, ['close', 'exit']), 'process completion should probe close before falling back to exit');
    results.push({ name: 'process-completion-binding', ok: true, chosenEvent });
}

function runConsoleBuildChecks(results, sandbox) {
    for (const testCase of contract.consoleCases) {
        const buildResult = sandbox.umhctlBuildControlRequest(testCase.op, testCase.args);
        assert(buildResult && buildResult.response == null, `console case returned response: ${testCase.name}`);
        assert(deepEqual(buildResult.controlReq, testCase.expected), `console case mismatch: ${testCase.name}`);
    }
    results.push({ name: 'console-build-cases', ok: true, caseCount: contract.consoleCases.length });
}

function runRawJsonChecks(results, sandbox) {
    const captured = [];
    const originalPreflight = sandbox.umhctlPreflightControlService;
    const originalSendPrepared = sandbox.umhctlSendPreparedControlRequest;

    sandbox.umhctlPreflightControlService = function () { return true; };
    sandbox.umhctlSendPreparedControlRequest = function (requestObj) {
        captured.push(JSON.parse(JSON.stringify(requestObj)));
    };

    for (const testCase of contract.rawJsonCases) {
        const output = sandbox.umhctlHandleRawJson({ json: JSON.stringify(testCase.payload) }, 'raw-json-session');
        assert(output == null, `raw json case returned unexpected output: ${testCase.name}`);
    }

    assert(captured.length === contract.rawJsonCases.length, 'raw json dispatch count mismatch');
    for (let i = 0; i < contract.rawJsonCases.length; ++i) {
        assert(deepEqual(captured[i], contract.rawJsonCases[i].expected), `raw json case mismatch: ${contract.rawJsonCases[i].name}`);
    }

    sandbox.umhctlPreflightControlService = originalPreflight;
    sandbox.umhctlSendPreparedControlRequest = originalSendPrepared;
    results.push({ name: 'raw-json-cases', ok: true, caseCount: contract.rawJsonCases.length });
}

function runFlowScopeChecks(results, sandbox, meshAgentStub) {
    const captured = [];
    sandbox.umhctlResetFlowState();
    sandbox.sendConsoleText = function (msg, sessionid) {
        meshAgentStub.SendCommand({ action: 'msg', type: 'console', value: msg, sessionid });
    };
    sandbox.umhctlSendControlRequest = function (requestObj, sessionid, options) {
        captured.push({ request: JSON.parse(JSON.stringify(requestObj)), sessionid });
        if (requestObj.op === 'getFlowContract') {
            if (options && typeof options.callback === 'function') {
                options.callback(null, {
                    ok: true,
                    data: {
                        protocol: contract.defaultFlowContract.protocol,
                        contract_version: contract.defaultFlowContract.contractVersion,
                        flow_profile: contract.defaultFlowContract.flowProfile,
                        required_headers: contract.defaultFlowContract.requiredHeaders.slice(0)
                    }
                });
            }
            return;
        }
        if (options && typeof options.callback === 'function') {
            options.callback(null, { ok: true, data: { accepted: true } }, JSON.stringify({ ok: true }));
        }
    };

    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('injectTargetSet', {
        pids: '3001,3002',
        runId: 'run-lab-200',
        targetTag: 'lockdown_browser',
        methodKey: 'standard'
    }), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('injectAll', {}), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('clearTargetScope', {}), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('injectAll', {}), 'flow-session');

    const requestOps = captured.filter((entry) => entry.request.op !== 'getFlowContract');
    assert(requestOps.length === 3, 'unexpected number of dispatched flow-scope requests');
    assert(requestOps[0].request.headers['x-umh-run-id'] === 'run-lab-200', 'injectTargetSet lost run-id header');
    assert(requestOps[1].request.headers['x-umh-run-id'] === 'run-lab-200', 'injectAll did not reuse scoped run-id');
    assert(requestOps[1].request.headers['x-umh-target-tag'] === 'lockdown_browser', 'injectAll did not reuse scoped target-tag');
    assert(requestOps[2].request.headers['x-umh-run-id'] === 'run-lab-200', 'clearTargetScope did not reuse scoped run-id');

    const consoleMessages = getConsoleMessages(meshAgentStub);
    assert(consoleMessages.some((line) => line.includes('requires an active target scope')), 'missing active-target-scope failure after clearTargetScope');
    results.push({
        name: 'flow-scope-reuse',
        ok: true,
        dispatchedOps: requestOps.map((entry) => entry.request.op)
    });
}

function runHeaderContractChecks(results, sandbox) {
    sandbox.umhctlResetFlowState();

    const pidOnlyInject = sandbox.umhctlResolveControlHeaders({ op: 'inject', pid: 123 }, 'header-contract-session');
    assert(pidOnlyInject.ok === false && /report-backed --target-tag/.test(pidOnlyInject.error), 'pid-only inject must fail closed before native dispatch');

    const explicitInject = sandbox.umhctlResolveControlHeaders({ op: 'inject', pid: 123, target_tag: 'LockDown_Browser', method: 'standard' }, 'header-contract-session');
    assert(explicitInject.ok === true, 'explicit target/method inject should resolve headers');
    assert(explicitInject.headers['x-umh-target-tag'] === 'lockdown_browser', 'explicit inject lost target header');
    assert(explicitInject.headers['x-umh-method-key'] === 'standard', 'explicit inject lost method header');

    const defaultMethodInject = sandbox.umhctlResolveControlHeaders({ op: 'inject', pid: 123, target_tag: 'LockDown_Browser', method: 'default' }, 'header-contract-session');
    assert(defaultMethodInject.ok === false && /auto\/default/.test(defaultMethodInject.error), 'default injection method must fail closed');

    const methodPolicy = sandbox.umhctlResolveControlHeaders({ op: 'methodPolicy', pid: 123 }, 'header-contract-session');
    assert(methodPolicy.ok === true, 'methodPolicy should resolve runtime-control headers');
    assert(methodPolicy.headers['x-umh-target-tag'] === 'runtime', 'methodPolicy must not derive pid target headers');
    assert(methodPolicy.headers['x-umh-method-key'] === 'runtime-control', 'methodPolicy must use runtime-control method header');

    results.push({ name: 'control-header-hard-fail', ok: true });
}

function runLifecycleCleanupChecks(results, sandbox, meshAgentStub) {
    const detail = sandbox.umhctlFormatServiceStopBlockerDetail(
        { installed: true, state: 'RUNNING' },
        [{ pid: 101 }, { pid: 102 }]
    );
    assert(detail === 'service state RUNNING, 2 processes still active', 'service stop blocker detail mismatch');

    const unitRoot = path.resolve(__dirname, 'evidence', 'lifecycle_cleanup_unit');
    fs.rmSync(unitRoot, { recursive: true, force: true });
    const agentDir = path.join(unitRoot, 'AgentRoot');
    const externalDir = path.join(unitRoot, 'ExternalRoot');
    ensureDir(agentDir);
    ensureDir(externalDir);

    const managedPath = path.join(agentDir, 'MasterService.exe');
    const managedDuplicate = path.join(agentDir, '.', 'MasterService.exe');
    const externalPath = path.join(externalDir, 'MasterService.exe');
    writeText(managedPath, 'MZ-managed');
    writeText(externalPath, 'MZ-external');

    const candidates = sandbox.umhctlBuildManagedMasterServiceBinaryCleanupCandidates(
        [managedPath, managedDuplicate, externalPath],
        agentDir
    );
    assert(candidates.length === 1, 'managed cleanup candidates should de-duplicate and exclude external paths');

    const cleanupOk = sandbox.umhctlCleanupManagedMasterServiceBinaries(
        [managedPath, externalPath],
        agentDir,
        'lifecycle-cleanup-session'
    );
    assert(cleanupOk === true, 'managed cleanup should succeed when managed binary is removed');
    assert(!fs.existsSync(managedPath), 'managed MasterService binary should be removed');
    assert(fs.existsSync(externalPath), 'external MasterService binary must be preserved');

    const missingOk = sandbox.umhctlCleanupManagedMasterServiceBinaries(
        [managedPath],
        agentDir,
        'lifecycle-cleanup-session'
    );
    assert(missingOk === true, 'missing managed binary should already satisfy cleanup');

    writeText(managedPath, 'MZ-locked');
    const originalUnlink = sandbox.fs.unlinkSync;
    sandbox.fs.unlinkSync = function (targetPath) {
        if (path.resolve(targetPath) === path.resolve(managedPath)) {
            throw new Error('simulated locked binary');
        }
        return originalUnlink.apply(this, arguments);
    };
    let failureOk = true;
    try {
        failureOk = sandbox.umhctlCleanupManagedMasterServiceBinaries(
            [managedPath],
            agentDir,
            'lifecycle-cleanup-session'
        );
    } finally {
        sandbox.fs.unlinkSync = originalUnlink;
    }
    assert(failureOk === false, 'managed cleanup must fail when a managed binary cannot be removed');
    assert(fs.existsSync(managedPath), 'failed managed cleanup should leave binary for operator evidence');

    fs.rmSync(unitRoot, { recursive: true, force: true });
    const consoleMessages = getConsoleMessages(meshAgentStub);
    assert(consoleMessages.some((line) => line.includes('simulated locked binary')), 'cleanup failure should be observable');
    results.push({ name: 'lifecycle-cleanup-fail-closed', ok: true });
}

function runUiSnapshotChecks(results, sandbox, meshAgentStub) {
    sandbox.sendConsoleText = function (msg, sessionid) {
        meshAgentStub.SendCommand({ action: 'msg', type: 'console', value: msg, sessionid });
    };
    sandbox.umhctlSendQuietControlRequest = function (requestObj, sessionid, callback) {
        const responses = {
            status: { ok: true, data: { healthy: true } },
            getFlowContract: {
                ok: true,
                data: {
                    protocol: contract.defaultFlowContract.protocol,
                    contract_version: contract.defaultFlowContract.contractVersion,
                    flow_profile: contract.defaultFlowContract.flowProfile,
                    required_headers: contract.defaultFlowContract.requiredHeaders.slice(0)
                }
            },
            getCapabilities: { ok: true, data: { supported_ops: ['status', 'inject'] } },
            listProcesses: { ok: true, data: [{ pid: 4242, name: 'examclient.exe' }] },
            getPolicy: { ok: true, data: { lockdown: false } },
            getConfig: { ok: true, data: '{"capture":"dxgi"}' },
            safetyState: { ok: true, data: { active_scope: false } },
            profileProcess: { ok: true, data: { pid: 4242, profile: 'exam-client' } },
            methodPolicy: { ok: true, data: { effective_order: ['standard'] } },
            securityBoundary: { ok: true, data: { role: 'browser-main' } }
        };
        callback(null, responses[requestObj.op], JSON.stringify(responses[requestObj.op]));
    };

    sandbox.umhctlSendUiSnapshot('snapshot-session', 4242);
    const messages = getConsoleMessages(meshAgentStub);
    const snapshotMessage = messages.filter((entry) => entry.startsWith('umhctl uiSnapshot:\r\n')).pop();
    assert(snapshotMessage, 'uiSnapshot output missing');
    const snapshot = JSON.parse(snapshotMessage.replace('umhctl uiSnapshot:\r\n', ''));
    for (const key of ['status', 'flow_contract', 'capabilities', 'processes', 'policy', 'config', 'safety_state', 'process_profile', 'method_policy', 'security_boundary']) {
        assert(Object.prototype.hasOwnProperty.call(snapshot.meta.sections, key), `uiSnapshot missing section: ${key}`);
    }
    results.push({ name: 'ui-snapshot-shape', ok: true, sections: Object.keys(snapshot.meta.sections) });
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const { sandbox, meshAgentStub } = loadRecoveryCoreVm();
    const checks = [];

    runMapParityChecks(checks, sandbox);
    runHelpChecks(checks, sandbox);
    runExecFileArgChecks(checks, sandbox);
    runInstallContractPathChecks(checks, sandbox);
    runInstallContractWriteSignatureChecks(checks, sandbox);
    runInstallActivationBoundedChecks(checks);
    runInstallPendingOwnershipChecks(checks, sandbox);
    runLifecycleStaleLockChecks(checks, sandbox);
    runProcessCompletionBindingChecks(checks, sandbox);
    runConsoleBuildChecks(checks, sandbox);
    runRawJsonChecks(checks, sandbox);
    runFlowScopeChecks(checks, sandbox, meshAgentStub);
    runHeaderContractChecks(checks, sandbox);
    runLifecycleCleanupChecks(checks, sandbox, meshAgentStub);
    runUiSnapshotChecks(checks, sandbox, meshAgentStub);

    const report = {
        generatedUtc: new Date().toISOString(),
        recoveryCorePath: RECOVERYCORE_PATH,
        contractPath: path.resolve(__dirname, 'test', 'lib', 'umh_operator_contract.js'),
        success: checks.every((entry) => entry.ok === true),
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'umh_operator_contract_report.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SUCCESS=${report.success}`,
            `CHECK_COUNT=${checks.length}`,
            `RECOVERYCORE=${report.recoveryCorePath}`,
            `CONTRACT=${report.contractPath}`,
            ...checks.map((entry) => `CHECK=${entry.name} OK=${entry.ok}`)
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }

    if (!report.success) {
        process.exitCode = 1;
    }
}

main();
