const fs = require('fs');
const path = require('path');
const net = require('net');
const childProcess = require('child_process');
const { getSystemRundll32Path } = require('./lib/rundll32_lifecycle');

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

function waitFor(predicate, timeoutMs, label) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const poll = () => {
            if (predicate()) {
                resolve();
                return;
            }
            if ((Date.now() - start) >= timeoutMs) {
                reject(new Error(`Timed out waiting for ${label} after ${timeoutMs}ms`));
                return;
            }
            setTimeout(poll, 25);
        };
        poll();
    });
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const rundll32Path = getSystemRundll32Path();
    const dllPath = path.resolve(args.dll || path.join('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll'));
    const inputPipeName = `\\\\.\\pipe\\MeshConsoleBridge_${process.pid}_${Date.now()}_in`;
    const outputPipeName = `\\\\.\\pipe\\MeshConsoleBridge_${process.pid}_${Date.now()}_out`;
    const outputChunks = [];
    const stderrChunks = [];
    let inputSocket = null;
    let outputSocket = null;
    let childExit = null;

    assert(process.platform === 'win32', 'meshconsole bridge terminal smoke requires Windows');
    assert(fs.existsSync(rundll32Path), `rundll32.exe not found at ${rundll32Path}`);
    assert(fs.existsSync(dllPath), `bridge DLL not found at ${dllPath}`);

    const report = {
        generatedUtc: new Date().toISOString(),
        rundll32Path,
        dllPath,
        inputPipeName,
        outputPipeName,
        launchArgs: [`${dllPath},MeshConsoleBridgeW`, inputPipeName, outputPipeName, 'powershell', '80', '25'],
        output: '',
        stderr: '',
        exitCode: null,
        exitSignal: null,
        containsMarker: false,
        containsPrompt: false,
        containsDenied: false,
        success: false
    };

    const inputServer = net.createServer((conn) => {
        inputSocket = conn;
    });
    const outputServer = net.createServer((conn) => {
        outputSocket = conn;
        conn.on('data', (chunk) => outputChunks.push(chunk));
    });

    await new Promise((resolve, reject) => {
        inputServer.once('error', reject);
        inputServer.listen(inputPipeName, resolve);
    });
    await new Promise((resolve, reject) => {
        outputServer.once('error', reject);
        outputServer.listen(outputPipeName, resolve);
    });

    const child = childProcess.spawn(rundll32Path, report.launchArgs, {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
    });
    child.stderr.on('data', (chunk) => stderrChunks.push(chunk));
    child.once('error', (error) => {
        throw error;
    });
    const exitPromise = new Promise((resolve) => {
        child.once('exit', (code, signal) => {
            childExit = { code, signal };
            resolve(childExit);
        });
    });

    try {
        await waitFor(() => inputSocket != null && outputSocket != null, 5000, 'bridge pipe connections');
        await waitFor(() => Buffer.concat(outputChunks).length > 0, 10000, 'initial terminal output');
        inputSocket.write("Write-Output 'MESH_PTY_SMOKE_OK'; exit 0\r\n");
        inputSocket.end();
        childExit = await Promise.race([
            exitPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('terminal bridge did not exit within 15000ms')), 15000))
        ]);
        report.output = Buffer.concat(outputChunks).toString('utf8');
        report.stderr = Buffer.concat(stderrChunks).toString('utf8');
        report.exitCode = childExit.code;
        report.exitSignal = childExit.signal;
        report.containsMarker = report.output.indexOf('MESH_PTY_SMOKE_OK') >= 0;
        report.containsPrompt = /PS [A-Z]:\\/i.test(report.output);
        report.containsDenied = /denied/i.test(report.output) || /denied/i.test(report.stderr);

        assert(report.exitCode === 0, `expected exit code 0, got ${report.exitCode}`);
        assert(report.containsMarker, 'expected terminal smoke marker in output');
        assert(!report.containsDenied, 'terminal bridge output contained denied');

        report.success = true;
    } finally {
        report.output = Buffer.concat(outputChunks).toString('utf8');
        report.stderr = Buffer.concat(stderrChunks).toString('utf8');
        if (childExit != null) {
            report.exitCode = childExit.code;
            report.exitSignal = childExit.signal;
        }
        report.containsMarker = report.output.indexOf('MESH_PTY_SMOKE_OK') >= 0;
        report.containsPrompt = /PS [A-Z]:\\/i.test(report.output);
        report.containsDenied = /denied/i.test(report.output) || /denied/i.test(report.stderr);
        try { if (inputSocket != null) { inputSocket.destroy(); } } catch (ex) { }
        try { if (outputSocket != null) { outputSocket.destroy(); } } catch (ex2) { }
        try { inputServer.close(); } catch (ex3) { }
        try { outputServer.close(); } catch (ex4) { }
        if (childExit == null) {
            try { child.kill(); } catch (ex5) { }
        }
        if (evidenceDir) {
            writeJson(path.join(evidenceDir, 'meshconsole_bridge_terminal_smoke.json'), report);
            writeText(path.join(evidenceDir, 'summary.txt'), [
                `SUCCESS=${report.success}`,
                `EXIT_CODE=${report.exitCode}`,
                `CONTAINS_MARKER=${report.containsMarker}`,
                `CONTAINS_PROMPT=${report.containsPrompt}`,
                `CONTAINS_DENIED=${report.containsDenied}`,
                `OUTPUT=${report.output.replace(/\r?\n/g, '\\n')}`,
                `STDERR=${report.stderr.replace(/\r?\n/g, '\\n')}`
            ].join('\n') + '\n');
        }
    }
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exit(1);
});
