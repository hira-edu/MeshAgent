const fs = require('fs');
const path = require('path');
const os = require('os');
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
    let resolveComplete;
    let rejectComplete;
    let completed = false;
    const complete = new Promise((resolve, reject) => {
        resolveComplete = resolve;
        rejectComplete = reject;
    });
    const finish = () => {
        if (!completed) {
            completed = true;
            resolveComplete();
        }
    };
    const deadline = setTimeout(() => {
        if (!completed) {
            completed = true;
            rejectComplete(new Error(`scenario did not complete: ${op} ${args.action || 'status'}`));
        }
    }, 5000);

    meshAgentStub.sentCommands = [];
    sandbox.umhctlResetFlowState();
    sandbox.sendConsoleText = function (msg, sessionid) {
        meshAgentStub.SendCommand({ action: 'msg', type: 'console', value: msg, sessionid });
        if (!captureOk && String(msg).includes('Protection state not changed')) {
            finish();
        }
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
        finish();
    };
    sandbox.umhctlRunPreProtectionCapture = function (controlReq, sessionid, callback) {
        order.push('capture');
        process.nextTick(() => {
            if (captureOk) {
                callback(null, {
                    capturePath: 'C:/ProgramData/DiagnosticHost/logs/preprotection/mock_capture.bmp',
                    manifestPath: path.join(process.env.MESH_AGENT_INSTALL_ROOT, 'logs', 'preprotection', 'mock_capture.json'),
                    capture: {
                        ok: true,
                        capture_path: 'C:/ProgramData/DiagnosticHost/logs/preprotection/mock_capture.bmp',
                        captured_at_utc: '2026-03-31T13:10:00.000Z'
                    }
                });
            } else {
                callback('native pre-protection capture failed (exit 1): capture failed', null);
            }
        });
    };

    sandbox.umhctlSendPreparedControlRequest(contract.buildControlRequest(op, args), 'preprotection-session');
    await complete.finally(() => clearTimeout(deadline));

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
        const protectedSuccess = await runScenario(sandbox, meshAgentStub, 'hookControl', { action: 'enable', target: 'lockdown_browser', domain: 'screen' }, true);
        assert(protectedSuccess.order.join(',') === 'flow-contract,capture,dispatch:hookControl:enable', 'hookControl screen enable did not capture before dispatch');
        assert(protectedSuccess.dispatched.length === 1, 'hookControl screen enable did not dispatch exactly once');
        assert(protectedSuccess.messages.some((line) => line.includes('pre-protection capture saved to')), 'hookControl screen enable did not report capture path');
        assert(protectedSuccess.messages.some((line) => line.includes('pre-protection manifest saved to')), 'hookControl screen enable did not report manifest path');

        const protectedFailure = await runScenario(sandbox, meshAgentStub, 'hookControl', { action: 'enable', target: 'examplify_browser', domain: 'screen' }, false);
        assert(protectedFailure.order.join(',') === 'flow-contract,capture', 'hookControl screen enable dispatched after failed capture');
        assert(protectedFailure.dispatched.length === 0, 'hookControl screen enable dispatched despite failed capture');
        assert(protectedFailure.messages.some((line) => line.includes('Protection state not changed')), 'hookControl screen enable failure did not preserve protection state');

        const statusScenario = await runScenario(sandbox, meshAgentStub, 'hookControl', { action: 'status', target: 'lockdown_browser', domain: 'screen' }, true);
        assert(statusScenario.order.join(',') === 'flow-contract,dispatch:hookControl:status', 'status action should not trigger pre-protection capture');
        assert(statusScenario.dispatched.length === 1, 'status action did not dispatch');

        report = {
            generatedUtc: new Date().toISOString(),
            success: true,
            agentInstallRoot: process.env.MESH_AGENT_INSTALL_ROOT,
            protectedScreenActions: contract.protectedScreenActions,
            scenarios: {
                hookControlScreenEnable: protectedSuccess,
                hookControlScreenEnableFailure: protectedFailure,
                hookControlScreenStatus: statusScenario
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
            `HOOKCONTROL_ENABLE_ORDER=${report.scenarios.hookControlScreenEnable.order.join('>')}`,
            `HOOKCONTROL_ENABLE_FAILURE_ORDER=${report.scenarios.hookControlScreenEnableFailure.order.join('>')}`,
            `HOOKCONTROL_STATUS_ORDER=${report.scenarios.hookControlScreenStatus.order.join('>')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
