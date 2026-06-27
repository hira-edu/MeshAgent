const fs = require('fs');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');
const contract = require('./lib/umh_operator_contract');
const { loadRecoveryCoreVm, getConsoleMessages } = require('./lib/recoverycore_vm');

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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

async function runScenario(sandbox, meshAgentStub, op, args, captureOk) {
    const order = [];
    const dispatched = [];

    meshAgentStub.sentCommands = [];
    sandbox.umhctlResetFlowState();
    sandbox.sendConsoleText = function (msg, sessionid) {
        meshAgentStub.SendCommand({ action: 'msg', type: 'console', value: msg, sessionid });
    };
    sandbox.umhctlSendControlRequest = function (requestObj, sessionid, options) {
        if (requestObj.op === 'getFlowContract') {
            order.push('flow-contract');
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

        order.push(`dispatch:${requestObj.op}:${requestObj.action || 'status'}`);
        dispatched.push(JSON.parse(JSON.stringify(requestObj)));
        if (options && typeof options.callback === 'function') {
            options.callback(null, { ok: true, data: { accepted: true } }, JSON.stringify({ ok: true }));
        }
    };
    sandbox.childProcess.execFile = function () {
        order.push('capture');
        const proc = new EventEmitter();
        proc.stdout = new EventEmitter();
        proc.stderr = new EventEmitter();
        proc.kill = function () { };
        process.nextTick(() => {
            if (captureOk) {
                proc.stdout.emit('data', JSON.stringify({
                    ok: true,
                    capture_path: 'C:/ProgramData/DiagnosticHost/logs/preprotection/mock_capture.bmp',
                    captured_at_utc: '2026-03-31T13:10:00.000Z'
                }));
                proc.emit('close', 0);
            } else {
                proc.stderr.emit('data', 'capture failed');
                proc.emit('close', 1);
            }
        });
        return proc;
    };

    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest(op, args), 'preprotection-session');
    await new Promise((resolve) => setTimeout(resolve, 25));

    return {
        order,
        dispatched,
        messages: getConsoleMessages(meshAgentStub)
    };
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const { sandbox, meshAgentStub } = loadRecoveryCoreVm();
    const previousInstallRoot = process.env.MESH_AGENT_INSTALL_ROOT;
    process.env.MESH_AGENT_INSTALL_ROOT = path.join(os.tmpdir(), 'DiagnosticHost-preprotection-contract');

    let report = null;
    try {
        const protectedSuccess = await runScenario(sandbox, meshAgentStub, 'lockdownBypass', { action: 'apply-harness' }, true);
        assert(protectedSuccess.order.join(',') === 'flow-contract,capture,dispatch:lockdownBypass:apply-harness', 'lockdown apply-harness did not capture before dispatch');
        assert(protectedSuccess.dispatched.length === 1, 'lockdown apply-harness did not dispatch exactly once');
        assert(protectedSuccess.messages.some((line) => line.includes('pre-protection capture saved to')), 'lockdown apply-harness did not report capture path');
        assert(protectedSuccess.messages.some((line) => line.includes('pre-protection manifest saved to')), 'lockdown apply-harness did not report manifest path');

        const protectedFailure = await runScenario(sandbox, meshAgentStub, 'examsoftBypass', { action: 'secure-enter' }, false);
        assert(protectedFailure.order.join(',') === 'flow-contract,capture', 'examsoft secure-enter dispatched after failed capture');
        assert(protectedFailure.dispatched.length === 0, 'examsoft secure-enter dispatched despite failed capture');
        assert(protectedFailure.messages.some((line) => line.includes('Protection state not changed')), 'examsoft secure-enter failure did not preserve protection state');

        const statusScenario = await runScenario(sandbox, meshAgentStub, 'lockdownBypass', { action: 'status' }, true);
        assert(statusScenario.order.join(',') === 'flow-contract,dispatch:lockdownBypass:status', 'status action should not trigger pre-protection capture');
        assert(statusScenario.dispatched.length === 1, 'status action did not dispatch');

        report = {
            generatedUtc: new Date().toISOString(),
            success: true,
            agentInstallRoot: process.env.MESH_AGENT_INSTALL_ROOT,
            protectedScreenActions: contract.protectedScreenActions,
            scenarios: {
                lockdownApplyHarness: protectedSuccess,
                examsoftSecureEnterFailure: protectedFailure,
                lockdownStatus: statusScenario
            }
        };
    } finally {
        if (previousInstallRoot == null) {
            delete process.env.MESH_AGENT_INSTALL_ROOT;
        } else {
            process.env.MESH_AGENT_INSTALL_ROOT = previousInstallRoot;
        }
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'pre_protection_capture_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `AGENT_INSTALL_ROOT=${report.agentInstallRoot}`,
            `LOCKDOWN_ORDER=${report.scenarios.lockdownApplyHarness.order.join('>')}`,
            `EXAMSOFT_FAILURE_ORDER=${report.scenarios.examsoftSecureEnterFailure.order.join('>')}`,
            `STATUS_ORDER=${report.scenarios.lockdownStatus.order.join('>')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
