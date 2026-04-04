const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const PACKET_TYPES = {
    0: 'nop',
    6: 'refresh',
    7: 'screen',
    11: 'get-displays',
    27: 'jumbo',
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

function waitForPacket(packets, predicate, timeoutMs) {
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
        packets.push({
            type,
            typeName: PACKET_TYPES[type] || 'unknown',
            size
        });
        offset += size;
    }
    return buffer.slice(offset);
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const stdoutChunks = [];
    const stderrChunks = [];
    const packets = [];
    let remainder = Buffer.alloc(0);
    let childExited = false;
    let disconnectInitiatedAt = null;

    assert(fs.existsSync(exePath), `legacy KVM executable not found at ${exePath}`);

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        launchArgs: ['-kvm1'],
        aliveBeforeDisconnect: false,
        displayListPacketsAfterCommand: null,
        exitAfterDisconnectMs: null,
        packets,
        success: false
    };

    const child = childProcess.spawn(exePath, ['-kvm1'], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe']
    });

    child.stdout.on('data', (chunk) => {
        stdoutChunks.push(chunk);
        remainder = parsePacketStream(Buffer.concat([remainder, chunk]), packets);
    });
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

    await waitForPacket(packets, () => packets.length > 0, 5000);
    await waitForPacket(packets, () => packets.some((packet) => packet.type === 82 || packet.type === 7), 5000);

    await sleep(300);
    const displayListCountBefore = packets.filter((packet) => packet.type === 11).length;
    child.stdin.write(buildPacket(11));
    await waitForPacket(packets, () => packets.filter((packet) => packet.type === 11).length > displayListCountBefore, 5000);
    report.displayListPacketsAfterCommand = packets.filter((packet) => packet.type === 11).length - displayListCountBefore;

    await sleep(1000);
    report.aliveBeforeDisconnect = (child.exitCode == null);
    assert(report.aliveBeforeDisconnect, 'legacy KVM child did not remain alive while stdio stayed connected');

    disconnectInitiatedAt = Date.now();
    child.stdin.end();

    const exitResult = await Promise.race([
        exitPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('legacy KVM child did not exit within 5000ms of stdin close')), 5000))
    ]);

    report.exitAfterDisconnectMs = Date.now() - disconnectInitiatedAt;
    report.exitCode = exitResult.code;
    report.exitSignal = exitResult.signal;
    report.childExited = childExited;
    assert(report.exitAfterDisconnectMs <= 5000, `legacy KVM exit exceeded 5000ms (${report.exitAfterDisconnectMs}ms)`);
    assert(packets.length > 0, 'no KVM packets were received from legacy stdio path');
    assert(report.displayListPacketsAfterCommand > 0, 'legacy KVM child did not respond to a post-connect get-displays command');
    report.success = true;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'legacy_kvm_stdio_smoke.json'), report);
        writeText(path.join(evidenceDir, 'stdout.txt'), Buffer.concat(stdoutChunks).toString('utf8'));
        writeText(path.join(evidenceDir, 'stderr.txt'), Buffer.concat(stderrChunks).toString('utf8'));
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `ALIVE_BEFORE_DISCONNECT=${report.aliveBeforeDisconnect}`,
            `DISPLAY_LIST_PACKETS_AFTER_COMMAND=${report.displayListPacketsAfterCommand}`,
            `EXIT_AFTER_DISCONNECT_MS=${report.exitAfterDisconnectMs}`,
            `PACKET_TYPES=${packets.map((packet) => `${packet.type}:${packet.typeName}`).join(',')}`,
            `COMMAND=${exePath} -kvm1`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
