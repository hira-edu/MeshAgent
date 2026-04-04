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

const SCENARIOS = {
    dxgi: {
        env: {},
        predicate: (stderr) => /capture backend=dxgi reason=dxgi:/i.test(stderr)
    },
    dxgi_to_wgc: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'auto',
            STEALTH_KVM_DXGI_SIMULATE_UNSUPPORTED: '1'
        },
        predicate: (stderr) => /capture backend=wgc reason=wgc:/i.test(stderr)
    },
    fallback: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'auto',
            STEALTH_KVM_DXGI_SIMULATE_UNSUPPORTED: '1',
            STEALTH_KVM_WGC_SIMULATE_UNAVAILABLE: '1'
        },
        predicate: (stderr) => /capture backend=gdi reason=gdi:wgc-simulated-unavailable/i.test(stderr)
    },
    wgc_to_dxgi: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'wgc',
            STEALTH_KVM_WGC_SIMULATE_UNAVAILABLE: '1'
        },
        predicate: (stderr) => /capture backend=dxgi reason=dxgi:/i.test(stderr)
    },
    access_lost: {
        env: {
            STEALTH_KVM_CAPTURE_BACKEND: 'dxgi',
            STEALTH_KVM_DXGI_SIMULATE_ACCESS_LOST_ONCE: '1'
        },
        predicate: (stderr) => /capture backend=gdi reason=gdi:dxgi-access-lost/i.test(stderr)
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

function collectBackendTransitions(stderr) {
    const transitions = [];
    const regex = /capture backend=([^\s\x00]+) reason=([^\x00\r\n]+)/ig;
    let match;
    while ((match = regex.exec(stderr)) !== null) {
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
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const packets = [];
    let remainder = Buffer.alloc(0);
    let stderrText = '';
    let stdoutText = '';
    let disconnectInitiatedAt = 0;

    assert(scenario, `Unknown scenario: ${scenarioName}`);
    assert(fs.existsSync(exePath), `KVM executable not found at ${exePath}`);

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        scenario: scenarioName,
        launchArgs: ['-kvm1'],
        packets,
        env: scenario.env,
        backendTransitions: [],
        aliveBeforeDisconnect: false,
        displayListPacketsAfterCommand: 0,
        exitAfterDisconnectMs: null,
        success: false
    };

    const child = childProcess.spawn(exePath, ['-kvm1'], {
        windowsHide: true,
        env: { ...process.env, ...scenario.env },
        stdio: ['pipe', 'pipe', 'pipe']
    });

    child.stdout.on('data', (chunk) => {
        stdoutText += chunk.toString('utf8');
        remainder = parsePacketStream(Buffer.concat([remainder, chunk]), packets);
    });
    child.stderr.on('data', (chunk) => {
        stderrText += chunk.toString('utf8');
    });
    child.stdin.on('error', () => {});

    const exitPromise = new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, signal) => resolve({ code, signal }));
    });

    await waitForPredicate(() => packets.some((packet) => packet.type === 82 || packet.type === 7), 8000, 'initial KVM packets');
    try {
        await waitForPredicate(() => scenario.predicate(stderrText), 12000, `scenario ${scenarioName} backend transition`);
    } catch (error) {
        throw new Error(`${error.message}; stderr=${JSON.stringify(stderrText)}`);
    }

    await sleep(500);
    report.aliveBeforeDisconnect = child.exitCode == null;
    assert(report.aliveBeforeDisconnect, 'KVM child exited unexpectedly before transport shutdown');

    disconnectInitiatedAt = Date.now();
    child.stdin.end();

    const exitResult = await Promise.race([
        exitPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('KVM child did not exit within 5000ms of stdin close')), 5000))
    ]);

    report.exitAfterDisconnectMs = Date.now() - disconnectInitiatedAt;
    report.exitCode = exitResult.code;
    report.exitSignal = exitResult.signal;
    report.backendTransitions = collectBackendTransitions(stderrText);

    assert(report.backendTransitions.length > 0, 'No capture backend transitions were logged');
    assert(report.exitAfterDisconnectMs <= 5000, `KVM child exit exceeded 5000ms (${report.exitAfterDisconnectMs}ms)`);
    report.success = true;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, `${scenarioName}.json`), report);
        writeText(path.join(evidenceDir, `${scenarioName}.stdout.txt`), stdoutText);
        writeText(path.join(evidenceDir, `${scenarioName}.stderr.txt`), stderrText);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SCENARIO=${scenarioName}`,
            'SUCCESS=true',
            `ALIVE_BEFORE_DISCONNECT=${report.aliveBeforeDisconnect}`,
            `DISPLAY_LIST_PACKETS_AFTER_COMMAND=${report.displayListPacketsAfterCommand}`,
            `EXIT_AFTER_DISCONNECT_MS=${report.exitAfterDisconnectMs}`,
            `BACKEND_TRANSITIONS=${report.backendTransitions.map((item) => `${item.backend}:${item.reason}`).join(',')}`,
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
