const fs = require('fs');
const path = require('path');
const net = require('net');
const childProcess = require('child_process');
const { getSystemRundll32Path } = require('./lib/rundll32_lifecycle');

const PACKET_TYPES = {
    0: 'nop',
    6: 'refresh',
    7: 'screen',
    27: 'jumbo',
    59: 'disconnect',
    82: 'display-info',
    88: 'mouse-cursor'
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

function waitForPacket(report, predicate, timeoutMs) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const poll = () => {
            if (predicate()) {
                resolve();
                return;
            }
            if ((Date.now() - start) >= timeoutMs) {
                reject(new Error(`Timed out waiting for expected packet after ${timeoutMs}ms`));
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
        const packet = {
            type,
            typeName: PACKET_TYPES[type] || 'unknown',
            size
        };
        if (type === 7 && size >= 8) {
            packet.width = buffer.readUInt16BE(offset + 4);
            packet.height = buffer.readUInt16BE(offset + 6);
        }
        packets.push(packet);
        offset += size;
    }
    return buffer.slice(offset);
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const rundll32Path = getSystemRundll32Path();
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
    const logPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'svchost-debug.log');
    const controlPipeName = `\\\\.\\pipe\\MeshKvm_${process.pid}_${Date.now()}_in`;
    const dataPipeName = `\\\\.\\pipe\\MeshKvm_${process.pid}_${Date.now()}_out`;
    const shutdownMode = String(args.shutdown || 'pipe-close').toLowerCase();
    const stdoutChunks = [];
    const stderrChunks = [];
    const packets = [];
    let remainder = Buffer.alloc(0);
    let controlSocket = null;
    let dataSocket = null;
    let controlConnectedAt = null;
    let dataConnectedAt = null;
    let childExited = false;
    let disconnectInitiatedAt = null;

    assert(fs.existsSync(rundll32Path), `rundll32.exe not found at ${rundll32Path}`);
    assert(fs.existsSync(dllPath), `bridge DLL not found at ${dllPath}`);

    const report = {
        generatedUtc: new Date().toISOString(),
        rundll32Path,
        dllPath,
        logPath,
        controlPipeName,
        dataPipeName,
        launchArgs: [`${dllPath},KvmSessionBridgeW`, controlPipeName, dataPipeName, '-kvm1'],
        shutdownMode,
        controlConnectedWithinMs: null,
        dataConnectedWithinMs: null,
        aliveBeforeDisconnect: false,
        displayListPacketsAfterCommand: null,
        exitAfterDisconnectMs: null,
        packets,
        success: false
    };

    const controlServer = net.createServer((conn) => {
        controlSocket = conn;
        controlConnectedAt = Date.now();
        report.controlConnectedWithinMs = controlConnectedAt - launchAt;
    });
    const dataServer = net.createServer((conn) => {
        dataSocket = conn;
        dataConnectedAt = Date.now();
        report.dataConnectedWithinMs = dataConnectedAt - launchAt;
        conn.on('data', (chunk) => {
            remainder = parsePacketStream(Buffer.concat([remainder, chunk]), packets);
        });
    });

    await new Promise((resolve, reject) => {
        controlServer.once('error', reject);
        controlServer.listen(controlPipeName, resolve);
    });
    await new Promise((resolve, reject) => {
        dataServer.once('error', reject);
        dataServer.listen(dataPipeName, resolve);
    });

    const launchAt = Date.now();
    const child = childProcess.spawn(rundll32Path, [`${dllPath},KvmSessionBridgeW`, controlPipeName, dataPipeName, '-kvm1'], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
    });

    child.stdout.on('data', (chunk) => stdoutChunks.push(chunk));
    child.stderr.on('data', (chunk) => stderrChunks.push(chunk));
    child.once('error', (error) => {
        throw error;
    });

    const exitPromise = new Promise((resolve) => {
        child.once('exit', (code, signal) => {
            childExited = true;
            resolve({ code, signal });
        });
    });

    await new Promise((resolve, reject) => {
        const start = Date.now();
        const poll = () => {
            if (controlSocket != null && dataSocket != null) {
                resolve();
                return;
            }
            if (childExited) {
                reject(new Error('rundll32 bridge exited before pipe connection'));
                return;
            }
            if ((Date.now() - start) >= 5000) {
                reject(new Error('rundll32 bridge did not connect within 5000ms'));
                return;
            }
            setTimeout(poll, 50);
        };
        poll();
    });

    assert(controlSocket != null, 'bridge stdin connection missing after connection wait');
    assert(dataSocket != null, 'bridge stdout connection missing after connection wait');
    await sleep(300);
    const displayListCountBefore = packets.filter((packet) => packet.type === 11).length;
    controlSocket.write(buildPacket(5, Buffer.from([1, 45, 0, 45, 0, 0])));
    controlSocket.write(buildPacket(8, Buffer.from([0])));
    controlSocket.write(buildPacket(87));
    controlSocket.write(buildPacket(6));
    controlSocket.write(buildPacket(11));
    await waitForPacket(report, () => packets.filter((packet) => packet.type === 11).length > displayListCountBefore, 5000);
    report.displayListPacketsAfterCommand = packets.filter((packet) => packet.type === 11).length - displayListCountBefore;
    await waitForPacket(report, () => packets.some((packet) => packet.type === 7), 5000);
    report.firstScreenPacket = packets.find((packet) => packet.type === 7) || null;

    await sleep(1000);
    report.aliveBeforeDisconnect = (child.exitCode == null);
    assert(report.aliveBeforeDisconnect, 'rundll32 bridge did not remain alive while pipe stayed connected');

    disconnectInitiatedAt = Date.now();
    switch (shutdownMode) {
        case 'disconnect-packet':
            controlSocket.write(buildPacket(59));
            break;
        case 'pipe-close':
            controlSocket.destroy();
            dataSocket.destroy();
            controlServer.close();
            dataServer.close();
            break;
        default:
            throw new Error(`Unsupported shutdown mode: ${shutdownMode}`);
    }

    const exitResult = await Promise.race([
        exitPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error(`rundll32 bridge did not exit within 5000ms of ${shutdownMode}`)), 5000))
    ]);

    report.exitAfterDisconnectMs = Date.now() - disconnectInitiatedAt;
    report.exitCode = exitResult.code;
    report.exitSignal = exitResult.signal;
    if (shutdownMode === 'disconnect-packet') {
        if (controlSocket != null) { controlSocket.destroy(); }
        if (dataSocket != null) { dataSocket.destroy(); }
        controlServer.close();
        dataServer.close();
    }
    assert(report.exitAfterDisconnectMs <= 5000, `bridge exit exceeded 5000ms (${report.exitAfterDisconnectMs}ms)`);
    assert(packets.length > 0, 'no KVM packets were received from the bridge');
    assert(report.displayListPacketsAfterCommand > 0, 'bridge did not respond to a post-connect get-displays command');
    assert(report.firstScreenPacket != null, 'bridge did not emit an initial screen packet');
    assert((report.firstScreenPacket.width >>> 0) > 0 && (report.firstScreenPacket.height >>> 0) > 0, `bridge reported invalid screen size ${report.firstScreenPacket.width}x${report.firstScreenPacket.height}`);
    if (fs.existsSync(logPath)) {
        const logLines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean);
        const startupLine = `KvmSessionBridgeW starting (input=${controlPipeName} output=${dataPipeName})`;
        const startupIndex = logLines.findIndex((line) => line.includes(startupLine));
        const runLogLines = startupIndex >= 0 ? logLines.slice(startupIndex) : logLines.slice(-200);
        report.logTail = runLogLines.slice(-80);
		assert(startupIndex >= 0, 'bridge log missing exact input/output startup line');
		assert(runLogLines.every((line) => line.includes('WaitNamedPipeW failed') === false), 'bridge log contains WaitNamedPipe failure');
		assert(runLogLines.every((line) => line.includes('KvmSessionBridgeW mainloop shutdown timed out after') === false), 'bridge log used timeout-based helper exit');
		assert(runLogLines.some((line) =>
			line.includes('KvmSessionBridgeW mainloop exited') ||
			line.includes('KvmSessionBridgeW exiting normally')),
			'bridge log missing controlled exit line');
	}
    report.success = true;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'rundll32_bridge_smoke.json'), report);
        writeText(path.join(evidenceDir, 'stdout.txt'), Buffer.concat(stdoutChunks).toString('utf8'));
        writeText(path.join(evidenceDir, 'stderr.txt'), Buffer.concat(stderrChunks).toString('utf8'));
        if (Array.isArray(report.logTail)) {
            writeText(path.join(evidenceDir, 'svchost-debug-tail.txt'), report.logTail.join('\n') + '\n');
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CONTROL_PIPE_NAME=${report.controlPipeName}`,
            `DATA_PIPE_NAME=${report.dataPipeName}`,
            `SHUTDOWN_MODE=${report.shutdownMode}`,
            `CONTROL_CONNECTED_WITHIN_MS=${report.controlConnectedWithinMs}`,
            `DATA_CONNECTED_WITHIN_MS=${report.dataConnectedWithinMs}`,
            `ALIVE_BEFORE_DISCONNECT=${report.aliveBeforeDisconnect}`,
            `DISPLAY_LIST_PACKETS_AFTER_COMMAND=${report.displayListPacketsAfterCommand}`,
            `FIRST_SCREEN=${report.firstScreenPacket ? `${report.firstScreenPacket.width}x${report.firstScreenPacket.height}` : 'missing'}`,
            `EXIT_AFTER_DISCONNECT_MS=${report.exitAfterDisconnectMs}`,
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
