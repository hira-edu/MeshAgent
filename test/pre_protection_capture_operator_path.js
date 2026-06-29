const fs = require('fs');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');
const { loadRecoveryCoreVm } = require('./lib/recoverycore_vm');

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

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForScenarioCompletion(timeline, captureOk, timeoutMs) {
    const started = Date.now();
    while ((Date.now() - started) <= timeoutMs) {
        const dispatched = timeline.some((entry) => entry.type === 'dispatch');
        const preserved = timeline.some((entry) => entry.type === 'console' && String(entry.value || '').includes('Protection state not changed'));
        if (captureOk ? dispatched : preserved) { return; }
        await sleep(25);
    }
    throw new Error(`operator pre-protection scenario did not complete (captureOk=${captureOk}) timeline=${JSON.stringify(timeline)}`);
}

function buildVmModuleStubs() {
    return {
        'win-system-paths': {
            system32Path(fileName) {
                assert(fileName === 'rundll32.exe', `unexpected system32 path lookup: ${fileName}`);
                return 'C:\\Windows\\System32\\rundll32.exe';
            }
        }
    };
}

function buildFlowContract() {
    return {
        ok: true,
        data: {
            protocol: 'umh-flow',
            contract_version: '2026-03-07',
            flow_profile: 'retained-operator-surface',
            required_headers: ['x-umh-run-id', 'x-umh-target-tag', 'x-umh-method-key']
        }
    };
}

async function runConsoleScenario(commandText, captureOk) {
    const { sandbox, meshAgentStub } = loadRecoveryCoreVm({ moduleStubs: buildVmModuleStubs() });
    const timeline = [];
    const sessionid = captureOk ? 'operator-success-session' : 'operator-failure-session';
    const commandHandler = meshAgentStub.commandHandlers[0];

    assert(typeof commandHandler === 'function', 'RecoveryCore did not register a console command handler');

    meshAgentStub.SendCommand = function (command) {
        this.sentCommands.push(command);
        if (command && command.type === 'console') {
            timeline.push({
                step: timeline.length + 1,
                type: 'console',
                value: command.value
            });
        }
    };

    sandbox.umhctlResetFlowState();
    sandbox.umhctlPreflightControlService = function () { return true; };
    sandbox.umhctlSendControlRequest = function (requestObj, requestSessionId, options) {
        if (requestObj.op === 'getFlowContract') {
            timeline.push({
                step: timeline.length + 1,
                type: 'flow-contract',
                sessionid: requestSessionId
            });
            if (options && typeof options.callback === 'function') {
                options.callback(null, buildFlowContract());
            }
            return;
        }

        timeline.push({
            step: timeline.length + 1,
            type: 'dispatch',
            sessionid: requestSessionId,
            op: requestObj.op,
            action: requestObj.action || 'status'
        });
        if (options && typeof options.callback === 'function') {
            options.callback(null, { ok: true, data: { accepted: true } }, JSON.stringify({ ok: true }));
        }
    };

    sandbox.childProcess.execFile = function (filePath, args) {
        timeline.push({
            step: timeline.length + 1,
            type: 'capture',
            filePath,
            args: Array.isArray(args) ? args.slice(0) : []
        });
        const proc = new EventEmitter();
        proc.stdout = new EventEmitter();
        proc.stderr = new EventEmitter();
        proc.kill = function () { };
        process.nextTick(() => {
            if (captureOk) {
                proc.stdout.emit('data', JSON.stringify({
                    ok: true,
                    capture_path: 'C:/ProgramData/DiagnosticHost/logs/preprotection/operator_success.bmp',
                    captured_at_utc: '2026-03-31T08:18:08.329Z',
                    width: 3440,
                    height: 1440,
                    file_size: 19814454
                }) + '\n');
                proc.emit('exit', 0, null);
                proc.emit('close', 0, null);
            } else {
                proc.stderr.emit('data', 'capture failed');
                proc.emit('exit', 1, null);
                proc.emit('close', 1, null);
            }
        });
        return proc;
    };

    commandHandler({
        action: 'msg',
        type: 'console',
        value: commandText,
        rights: 0xFFFFFFFF,
        sessionid
    });

    await waitForScenarioCompletion(timeline, captureOk, 2000);

    const dispatches = timeline.filter((entry) => entry.type === 'dispatch');
    const messages = timeline.filter((entry) => entry.type === 'console').map((entry) => entry.value);
    return {
        sessionid,
        commandText,
        captureOk,
        timeline,
        dispatches,
        messages
    };
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const previousInstallRoot = process.env.MESH_AGENT_INSTALL_ROOT;
    const previousServiceDll = process.env.MESH_AGENT_SERVICE_DLL_PATH;
    process.env.MESH_AGENT_INSTALL_ROOT = path.join(os.tmpdir(), 'DiagnosticHost-preprotection-operator-contract');
    process.env.MESH_AGENT_SERVICE_DLL_PATH = 'C:\\Program Files\\MeshAgent\\MeshService-2022.dll';

    let report = null;
    try {
        const successScenario = await runConsoleScenario('umhctl hookControl --target lockdown_browser --domain screen --action enable', true);
        const failureScenario = await runConsoleScenario('umhctl hookControl --target examplify_browser --domain screen --action enable', false);

        assert(successScenario.dispatches.length === 1, 'operator success path did not dispatch exactly once');
        assert(successScenario.dispatches[0].op === 'hookControl', 'operator success path dispatched wrong operation');
        assert(successScenario.dispatches[0].action === 'enable', 'operator success path dispatched wrong action');
        assert(successScenario.timeline.map((entry) => entry.type + (entry.type === 'dispatch' ? ':' + entry.op + ':' + entry.action : '')).join(',') === [
            'flow-contract',
            'console',
            'capture',
            'console',
            'console',
            'dispatch:hookControl:enable'
        ].join(','), 'operator success path sequence drifted');
        assert(successScenario.messages[0].includes('capturing pre-protection evidence before hookControl enable'), 'operator success path missing capture start message');
        assert(successScenario.messages[1].includes('pre-protection capture saved to'), 'operator success path missing capture saved message');
        assert(successScenario.messages[2].includes('pre-protection manifest saved to'), 'operator success path missing manifest saved message');

        assert(failureScenario.dispatches.length === 0, 'operator failure path dispatched despite failed capture');
        assert(failureScenario.timeline.map((entry) => entry.type).join(',') === 'flow-contract,console,capture,console', 'operator failure path sequence drifted');
        assert(failureScenario.messages[1].includes('Protection state not changed'), 'operator failure path missing explicit no-mutation message');

        report = {
            generatedUtc: new Date().toISOString(),
            success: true,
            agentInstallRoot: process.env.MESH_AGENT_INSTALL_ROOT,
            scenarios: {
                operatorSuccess: successScenario,
                operatorFailure: failureScenario
            }
        };
    } finally {
        if (previousInstallRoot == null) {
            delete process.env.MESH_AGENT_INSTALL_ROOT;
        } else {
            process.env.MESH_AGENT_INSTALL_ROOT = previousInstallRoot;
        }
        if (previousServiceDll == null) {
            delete process.env.MESH_AGENT_SERVICE_DLL_PATH;
        } else {
            process.env.MESH_AGENT_SERVICE_DLL_PATH = previousServiceDll;
        }
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'pre_protection_capture_operator_path.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `AGENT_INSTALL_ROOT=${report.agentInstallRoot}`,
            `SUCCESS_SEQUENCE=${report.scenarios.operatorSuccess.timeline.map((entry) => entry.type + (entry.type === 'dispatch' ? ':' + entry.op + ':' + entry.action : '')).join('>')}`,
            `FAILURE_SEQUENCE=${report.scenarios.operatorFailure.timeline.map((entry) => entry.type).join('>')}`,
            `SUCCESS_COMMAND=${report.scenarios.operatorSuccess.commandText}`,
            `FAILURE_COMMAND=${report.scenarios.operatorFailure.commandText}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
