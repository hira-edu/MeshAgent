const fs = require('fs');
const path = require('path');
const contract = require('./test/lib/umh_operator_contract');
const { loadRecoveryCoreVm, getConsoleMessages, RECOVERYCORE_PATH } = require('./test/lib/recoverycore_vm');

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
        targetTag: 'screen-examclient',
        methodKey: 'load-library'
    }), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('injectAll', {}), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('clearTargetScope', {}), 'flow-session');
    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest('injectAll', {}), 'flow-session');

    const requestOps = captured.filter((entry) => entry.request.op !== 'getFlowContract');
    assert(requestOps.length === 3, 'unexpected number of dispatched flow-scope requests');
    assert(requestOps[0].request.headers['x-umh-run-id'] === 'run-lab-200', 'injectTargetSet lost run-id header');
    assert(requestOps[1].request.headers['x-umh-run-id'] === 'run-lab-200', 'injectAll did not reuse scoped run-id');
    assert(requestOps[1].request.headers['x-umh-target-tag'] === 'screen-examclient', 'injectAll did not reuse scoped target-tag');
    assert(requestOps[2].request.headers['x-umh-run-id'] === 'run-lab-200', 'clearTargetScope did not reuse scoped run-id');

    const consoleMessages = getConsoleMessages(meshAgentStub);
    assert(consoleMessages.some((line) => line.includes('requires an active target scope')), 'missing active-target-scope failure after clearTargetScope');
    results.push({
        name: 'flow-scope-reuse',
        ok: true,
        dispatchedOps: requestOps.map((entry) => entry.request.op)
    });
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
            getInjectionState: { ok: true, data: { pid: 4242, state: 'ready' } },
            profileProcess: { ok: true, data: { pid: 4242, profile: 'exam-client' } }
        };
        callback(null, responses[requestObj.op], JSON.stringify(responses[requestObj.op]));
    };

    sandbox.umhctlSendUiSnapshot('snapshot-session', 4242);
    const messages = getConsoleMessages(meshAgentStub);
    const snapshotMessage = messages.filter((entry) => entry.startsWith('umhctl uiSnapshot:\r\n')).pop();
    assert(snapshotMessage, 'uiSnapshot output missing');
    const snapshot = JSON.parse(snapshotMessage.replace('umhctl uiSnapshot:\r\n', ''));
    for (const key of ['status', 'flow_contract', 'capabilities', 'processes', 'policy', 'config', 'injection_state', 'process_profile']) {
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
    runConsoleBuildChecks(checks, sandbox);
    runRawJsonChecks(checks, sandbox);
    runFlowScopeChecks(checks, sandbox, meshAgentStub);
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
