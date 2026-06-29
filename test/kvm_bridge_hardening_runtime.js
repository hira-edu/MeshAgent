const fs = require('fs');
const path = require('path');
const net = require('net');
const childProcess = require('child_process');
const {
    resolveRundll32Path
} = require('./lib/kvm_runtime_helpers');

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

function runCommandJson(exePath, args) {
    const result = childProcess.spawnSync(exePath, args, {
        windowsHide: true,
        encoding: 'utf8'
    });
    const stdout = result.stdout || '';
    const stderr = result.stderr || '';
    let json = null;
    try {
        json = JSON.parse(stdout.trim());
    } catch (error) {
        throw new Error(`Failed to parse JSON from ${exePath} ${args.join(' ')}\nstdout:\n${stdout}\nstderr:\n${stderr}\nparse error: ${error.message}`);
    }
    return {
        status: result.status,
        stdout,
        stderr,
        json
    };
}

function processExists(pid) {
    const output = childProcess.execFileSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], {
        windowsHide: true,
        encoding: 'utf8'
    }).trim();
    if (output.length === 0) { return false; }
    if (output.startsWith('INFO:')) { return false; }
    return output.includes(`"${pid}"`);
}

async function waitForCondition(predicate, timeoutMs, intervalMs, description) {
    const start = Date.now();
    while ((Date.now() - start) < timeoutMs) {
        if (predicate()) {
            return Date.now() - start;
        }
        await sleep(intervalMs);
    }
    throw new Error(`Timed out waiting for ${description} after ${timeoutMs}ms`);
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
    const rundll32Path = resolveRundll32Path();

    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);
    assert(fs.existsSync(rundll32Path), `rundll32.exe missing at ${rundll32Path}`);

    const report = {
        generatedUtc: new Date().toISOString(),
        dllPath,
        rundll32Path,
        probe: null,
        controller: null,
        controllerConnectionMs: null,
        controllerExitCode: null,
        controllerExitSignal: null,
        childGoneWithinMs: null,
        success: false
    };
    let attachClose = null;

    const probe = runCommandJson(rundll32Path, [`${dllPath},MeshKvmProbeHostW`, '-kvm-bridge-hardening-probe-child', dllPath]);
    report.probe = probe.json;
    assert(probe.status === 0, `hardening probe exited with code ${probe.status}`);
    assert(probe.json.success === true, 'hardening probe reported failure');
    assert(probe.json.protectedProcess === true, 'bridge process was not protected');
    assert(probe.json.assignedToJobObject === true, 'bridge process was not assigned to a job object');
    assert(probe.json.bridgeConnected === true, 'bridge process did not connect to the probe pipe');
    assert(probe.json.daclProtected === true, 'probe did not observe a protected DACL');
    assert(probe.json.restrictedTerminateDenied === true, 'restricted token was able to request terminate access');
    assert(probe.json.existingHandleTerminateSucceeded === true, 'existing process handle could not terminate the bridge');

    const controlPipeName = `\\\\.\\pipe\\MeshKvmHardening_${process.pid}_${Date.now()}_in`;
    const dataPipeName = `\\\\.\\pipe\\MeshKvmHardening_${process.pid}_${Date.now()}_out`;
    let controlSocket = null;
    let dataSocket = null;
    const socketClosePromise = new Promise((resolve) => {
        const onClose = () => resolve();
        const attach = (conn) => {
            conn.once('close', onClose);
            conn.once('error', onClose);
        };
        if (dataSocket != null) {
            attach(dataSocket);
        } else {
            attachClose = attach;
        }
    });

    const controlServer = net.createServer((conn) => {
        controlSocket = conn;
        conn.on('data', () => {});
    });
    const dataServer = net.createServer((conn) => {
        dataSocket = conn;
        conn.on('data', () => {});
        if (typeof attachClose === 'function') {
            attachClose(conn);
            attachClose = null;
        }
    });

    await new Promise((resolve, reject) => {
        controlServer.once('error', reject);
        controlServer.listen(controlPipeName, resolve);
    });
    await new Promise((resolve, reject) => {
        dataServer.once('error', reject);
        dataServer.listen(dataPipeName, resolve);
    });

    const controller = childProcess.spawn(rundll32Path, [`${dllPath},MeshKvmProbeHostW`, '-kvm-bridge-job-controller', dllPath, controlPipeName, dataPipeName], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
    });

    const controllerStdout = [];
    const controllerStderr = [];
    controller.stdout.on('data', (chunk) => controllerStdout.push(chunk));
    controller.stderr.on('data', (chunk) => controllerStderr.push(chunk));

    const controllerExitPromise = new Promise((resolve, reject) => {
        controller.once('error', reject);
        controller.once('exit', (code, signal) => resolve({ code, signal }));
    });

    const connectStart = Date.now();
    await waitForCondition(() => controlSocket != null && dataSocket != null, 5000, 50, 'controller bridge connection');
    report.controllerConnectionMs = Date.now() - connectStart;

    const controllerExit = await controllerExitPromise;
    report.controllerExitCode = controllerExit.code;
    report.controllerExitSignal = controllerExit.signal;

    const controllerStdoutText = Buffer.concat(controllerStdout).toString('utf8').trim();
    const controllerStderrText = Buffer.concat(controllerStderr).toString('utf8');
    try {
        report.controller = JSON.parse(controllerStdoutText);
    } catch (error) {
        throw new Error(`Failed to parse controller JSON\nstdout:\n${controllerStdoutText}\nstderr:\n${controllerStderrText}\nparse error: ${error.message}`);
    }

    assert(controllerExit.code === 0, `controller exited with code ${controllerExit.code}`);
    assert(report.controller.success === true, 'controller reported failure');
    assert(report.controller.protectedProcess === true, 'controller did not protect the bridge');
    assert(report.controller.assignedToJobObject === true, 'controller did not assign the bridge to the job object');
    assert(report.controller.aliveAfterWarmup === true, 'bridge was not alive before controller teardown');

    const childPid = report.controller.pid;
    assert(Number.isInteger(childPid) && childPid > 0, `invalid child pid reported by controller: ${childPid}`);
    report.childGoneWithinMs = await waitForCondition(() => !processExists(childPid), 5000, 100, `child process ${childPid} exit after controller teardown`);
    await Promise.race([
        socketClosePromise,
        sleep(1000)
    ]);

    report.success = true;

    controlServer.close();
    dataServer.close();
    if (controlSocket != null) { controlSocket.destroy(); }
    if (dataSocket != null) { dataSocket.destroy(); }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_hardening_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe_stdout.json'), probe.stdout);
        writeText(path.join(evidenceDir, 'probe_stderr.txt'), probe.stderr);
        writeText(path.join(evidenceDir, 'controller_stdout.json'), controllerStdoutText + '\n');
        writeText(path.join(evidenceDir, 'controller_stderr.txt'), controllerStderrText);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `PROBE_RESTRICTED_TERMINATE_DENIED=${report.probe.restrictedTerminateDenied}`,
            `PROBE_EXISTING_HANDLE_TERMINATE=${report.probe.existingHandleTerminateSucceeded}`,
            `CONTROLLER_CHILD_PID=${report.controller.pid}`,
            `CONTROLLER_CONNECTION_MS=${report.controllerConnectionMs}`,
            `CHILD_GONE_WITHIN_MS=${report.childGoneWithinMs}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
