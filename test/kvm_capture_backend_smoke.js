const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const childProcess = require('child_process');

const PACKET_TYPES = {
    0: 'nop',
    6: 'refresh',
    7: 'screen',
    11: 'display-list',
    27: 'jumbo',
    59: 'disconnect',
    82: 'display-info',
    88: 'mouse-cursor'
};

const SCENARIOS = {
    dxgi: {
        env: {},
        predicate: (trace) => /capture backend=dxgi reason=dxgi:/i.test(trace)
    },
    dxgi_to_wgc: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'auto',
            STEALTH_KVM_DXGI_SIMULATE_UNSUPPORTED: '1'
        },
        predicate: (trace) => /capture backend=wgc reason=wgc:/i.test(trace)
    },
    fallback: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'auto',
            STEALTH_KVM_DXGI_SIMULATE_UNSUPPORTED: '1',
            STEALTH_KVM_WGC_SIMULATE_UNAVAILABLE: '1'
        },
        predicate: (trace) => /capture backend=gdi reason=gdi:wgc-simulated-unavailable/i.test(trace)
    },
    wgc_to_dxgi: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'wgc',
            STEALTH_KVM_WGC_SIMULATE_UNAVAILABLE: '1'
        },
        predicate: (trace) => /capture backend=dxgi reason=dxgi:/i.test(trace)
    },
    access_lost: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'dxgi',
            STEALTH_KVM_DXGI_SIMULATE_ACCESS_LOST_ONCE: '1'
        },
        predicate: (trace) => /capture backend=gdi reason=gdi:dxgi-access-lost/i.test(trace)
    }
};

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

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForPredicate(predicate, timeoutMs, label) {
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
            setTimeout(poll, 50);
        };
        poll();
    });
}

function buildPacket(type, payload) {
    const body = Buffer.isBuffer(payload) ? payload : Buffer.alloc(0);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

function parsePacketStream(buffer, packets) {
    let offset = 0;
    while ((buffer.length - offset) >= 4) {
        const type = buffer.readUInt16BE(offset);
        let size = buffer.readUInt16BE(offset + 2);
        if (type === 27) {
            if ((buffer.length - offset) < 8) { break; }
            size = 8 + buffer.readUInt32BE(offset + 4);
        }
        if (size < 4) {
            throw new Error(`Invalid KVM packet length ${size} for type ${type}`);
        }
        if ((buffer.length - offset) < size) { break; }
        packets.push({
            type,
            typeName: PACKET_TYPES[type] || 'unknown',
            size
        });
        offset += size;
    }
    return buffer.slice(offset);
}

function readTextIfExists(filePath) {
    try {
        return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
    } catch (error) {
        return '';
    }
}

function collectBackendTransitions(traceText) {
    const transitions = [];
    const regex = /capture backend=([^\s\x00]+) reason=([^\x00\r\n]+)/ig;
    let match;
    while ((match = regex.exec(traceText)) !== null) {
        transitions.push({
            backend: match[1],
            reason: match[2].trim()
        });
    }
    return transitions;
}

async function main() {
    const args = parseArgs(process.argv);
    const scenarioName = String(args.scenario || 'dxgi');
    const scenario = SCENARIOS[scenarioName];
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    const rundll32Path = path.join(systemRoot, 'System32', 'rundll32.exe');
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
    const logPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'svchost-debug.log');
    const tracePath = path.join(os.tmpdir(), 'meshagent_tile_trace.log');
    const controlPipeName = `\\\\.\\pipe\\MeshKvmBackend_${process.pid}_${Date.now()}_in`;
    const dataPipeName = `\\\\.\\pipe\\MeshKvmBackend_${process.pid}_${Date.now()}_out`;
    const packets = [];
    let remainder = Buffer.alloc(0);
    let stderrText = '';
    let stdoutText = '';
    let controlSocket = null;
    let dataSocket = null;
    let childExited = false;
    let disconnectInitiatedAt = 0;

    assert(scenario, `Unknown scenario: ${scenarioName}`);
    assert(fs.existsSync(rundll32Path), `rundll32.exe not found at ${rundll32Path}`);
    assert(fs.existsSync(dllPath), `bridge DLL not found at ${dllPath}`);

    try { fs.unlinkSync(tracePath); } catch (error) { if (error.code !== 'ENOENT') { throw error; } }

    const report = {
        generatedUtc: new Date().toISOString(),
        scenario: scenarioName,
        rundll32Path,
        dllPath,
        logPath,
        tracePath,
        controlPipeName,
        dataPipeName,
        launchArgs: [`${dllPath},KvmSessionBridgeW`, controlPipeName, dataPipeName, '-kvm1'],
        env: { ...scenario.env, STEALTH_KVM_TRACE_TILE: '1' },
        packets,
        backendTransitions: [],
        aliveBeforeDisconnect: false,
        displayListPacketsAfterCommand: 0,
        exitAfterDisconnectMs: null,
        success: false
    };

    const controlServer = net.createServer((conn) => {
        controlSocket = conn;
    });
    const dataServer = net.createServer((conn) => {
        dataSocket = conn;
        conn.on('data', (chunk) => {
            remainder = parsePacketStream(Buffer.concat([remainder, chunk]), packets);
        });
    });

    const closeServers = () => {
        try { controlServer.close(); } catch (error) {}
        try { dataServer.close(); } catch (error) {}
    };

    await new Promise((resolve, reject) => {
        controlServer.once('error', reject);
        controlServer.listen(controlPipeName, resolve);
    });
    await new Promise((resolve, reject) => {
        dataServer.once('error', reject);
        dataServer.listen(dataPipeName, resolve);
    });

    const child = childProcess.spawn(rundll32Path, [`${dllPath},KvmSessionBridgeW`, controlPipeName, dataPipeName, '-kvm1'], {
        windowsHide: true,
        env: { ...process.env, STEALTH_KVM_TRACE_TILE: '1', ...scenario.env },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    const getTraceText = () => {
        return [stdoutText, stderrText, readTextIfExists(tracePath), readTextIfExists(logPath)]
            .filter((value) => value && value.length > 0)
            .join('\n');
    };

    child.stdout.on('data', (chunk) => {
        stdoutText += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
        stderrText += chunk.toString('utf8');
    });

    const exitPromise = new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, signal) => {
            childExited = true;
            resolve({ code, signal });
        });
    });

    await waitForPredicate(() => controlSocket != null && dataSocket != null, 5000, 'bridge pipe connections');
    await waitForPredicate(() => packets.some((packet) => packet.type === 82 || packet.type === 7), 8000, 'initial KVM packets');

    const displayListCountBefore = packets.filter((packet) => packet.type === 11).length;
    controlSocket.write(buildPacket(5, Buffer.from([1, 45, 0, 45, 0, 0])));
    controlSocket.write(buildPacket(8, Buffer.from([0])));
    controlSocket.write(buildPacket(87));
    controlSocket.write(buildPacket(6));
    controlSocket.write(buildPacket(11));
    await waitForPredicate(() => packets.filter((packet) => packet.type === 11).length > displayListCountBefore, 5000, 'display-list response');
    report.displayListPacketsAfterCommand = packets.filter((packet) => packet.type === 11).length - displayListCountBefore;
    await waitForPredicate(() => packets.some((packet) => packet.type === 7), 5000, 'screen packet');

    try {
        await waitForPredicate(() => scenario.predicate(getTraceText()), 12000, `scenario ${scenarioName} backend transition`);
    } catch (error) {
        throw new Error(`${error.message}; trace=${JSON.stringify(getTraceText())}`);
    }

    await sleep(500);
    assert(childExited === false, 'rundll32 bridge exited unexpectedly before transport shutdown');
    report.aliveBeforeDisconnect = true;

    disconnectInitiatedAt = Date.now();
    if (controlSocket != null) { controlSocket.destroy(); }
    if (dataSocket != null) { dataSocket.destroy(); }
    closeServers();

    const exitResult = await Promise.race([
        exitPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('rundll32 bridge did not exit within 5000ms of pipe close')), 5000))
    ]);

    report.exitAfterDisconnectMs = Date.now() - disconnectInitiatedAt;
    report.exitCode = exitResult.code;
    report.exitSignal = exitResult.signal;
    report.backendTransitions = collectBackendTransitions(getTraceText());
    report.logTail = readTextIfExists(logPath).split(/\r?\n/).filter(Boolean).slice(-40);
    report.traceTail = readTextIfExists(tracePath).split(/\r?\n/).filter(Boolean).slice(-40);

    assert(report.backendTransitions.length > 0, 'No capture backend transitions were logged');
    assert(scenario.predicate(getTraceText()), `Scenario ${scenarioName} predicate did not match final trace`);
    assert(report.exitAfterDisconnectMs <= 5000, `rundll32 bridge exit exceeded 5000ms (${report.exitAfterDisconnectMs}ms)`);
    report.success = true;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, `${scenarioName}.json`), report);
        writeText(path.join(evidenceDir, `${scenarioName}.stdout.txt`), stdoutText);
        writeText(path.join(evidenceDir, `${scenarioName}.stderr.txt`), stderrText);
        writeText(path.join(evidenceDir, `${scenarioName}.trace.txt`), getTraceText());
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SCENARIO=${scenarioName}`,
            'SUCCESS=true',
            `ALIVE_BEFORE_DISCONNECT=${report.aliveBeforeDisconnect}`,
            `DISPLAY_LIST_PACKETS_AFTER_COMMAND=${report.displayListPacketsAfterCommand}`,
            `EXIT_AFTER_DISCONNECT_MS=${report.exitAfterDisconnectMs}`,
            `BACKEND_TRANSITIONS=${report.backendTransitions.map((item) => `${item.backend}:${item.reason}`).join(',')}`,
            `PACKET_TYPES=${packets.map((packet) => `${packet.type}:${packet.typeName}`).join(',')}`,
            `COMMAND=${rundll32Path} ${dllPath},KvmSessionBridgeW ${controlPipeName} ${dataPipeName} -kvm1`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
