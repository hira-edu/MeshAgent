const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const net = require('net');

const dllPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
const rundll32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'rundll32.exe');
const reportPath = path.join(os.tmpdir(), `kvm_trace_probe_${process.pid}_${Date.now()}.json`);

if (!fs.existsSync(dllPath)) { console.error('DLL not found: ' + dllPath); process.exit(1); }

function pkt(type, payload) {
    const body = Buffer.from(payload || []);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

const pipeName = `\\\\.\\pipe\\MeshKvmTrace_${process.pid}_${Date.now()}`;
let buf = Buffer.alloc(0);
let child = null;
const timeline = [];
const counts = {};
const pictures = [];
let startTime = Date.now();
function ts() { return Date.now() - startTime; }

function note(type, size) {
    counts[type] = (counts[type] || 0) + 1;
    const entry = { t: ts(), type, size };
    timeline.push(entry);
    if (type === 3 || type === 27) pictures.push(entry);
}

function parse() {
    let off = 0;
    while ((buf.length - off) >= 4) {
        let type = buf.readUInt16BE(off);
        let size = buf.readUInt16BE(off + 2);
        if (type === 27) {
            if ((buf.length - off) < 8) break;
            size = 8 + buf.readUInt32BE(off + 4);
        }
        if (size < 4 || (buf.length - off) < size) break;
        note(type, size);
        off += size;
    }
    if (off > 0) buf = buf.slice(off);
}

let childStderr = '';
let childStdout = '';

function flush(tag) {
    try {
        fs.writeFileSync(reportPath, JSON.stringify({
            tag, counts, pictures,
            timeline: timeline.slice(-120),
            timelineLen: timeline.length,
            childStderrTail: childStderr.slice(-4000),
            elapsed: ts()
        }, null, 2));
    } catch (e) { /* ignore */ }
}

const server = net.createServer((conn) => {
    timeline.push({ t: ts(), event: 'connected' });

    conn.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        parse();
        flush('data');
    });

    // t=300ms: setup + unpause + refresh
    setTimeout(() => {
        try {
            conn.write(pkt(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));
            conn.write(pkt(8, [0]));
            conn.write(pkt(87, [2]));
            conn.write(pkt(6));
            timeline.push({ t: ts(), event: 'write1-setup+refresh' });
            flush('write1');
        } catch (e) { timeline.push({ t: ts(), event: 'write1err', msg: e.message }); }
    }, 300);

    // Subsequent refreshes at wider intervals
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write2-refresh' }); flush('write2'); } catch (e) {} }, 1500);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write3-refresh' }); flush('write3'); } catch (e) {} }, 3000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write4-refresh' }); flush('write4'); } catch (e) {} }, 5000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write5-refresh' }); flush('write5'); } catch (e) {} }, 8000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write6-refresh' }); flush('write6'); } catch (e) {} }, 11000);

    // t=15s: close
    setTimeout(() => {
        try { conn.destroy(); flush('pipe-end'); } catch (e) {}
    }, 15000);
});

server.listen(pipeName, () => {
    startTime = Date.now();
    timeline.push({ t: 0, event: 'pipe-listening' });

    const env = Object.assign({}, process.env, {
        STEALTH_KVM_TRACE_STARTUP: '1',
        STEALTH_KVM_TRACE_LOOP: '1',
        STEALTH_KVM_TRACE_TILE: '1'
    });

    child = cp.spawn(rundll32, [`${dllPath},KvmSessionBridgeW`, pipeName], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: env
    });
    timeline.push({ t: ts(), event: 'child-spawned', pid: child.pid });

    child.stdout.on('data', (chunk) => { childStdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        childStderr += text;
        for (const line of text.split(/\r?\n/)) {
            if (line.trim()) {
                timeline.push({ t: ts(), event: 'trace', line: line.trim() });
            }
        }
        flush('stderr');
    });
    child.on('exit', (code, signal) => {
        timeline.push({ t: ts(), event: 'child-exit', code, signal });
        flush('exit');
    });
    child.on('error', (err) => {
        timeline.push({ t: ts(), event: 'child-error', msg: err.message });
        flush('error');
    });
});

setTimeout(() => {
    flush('timeout');
    console.log('REPORT=' + reportPath);
    console.log(JSON.stringify({ counts, pictures, timelineLen: timeline.length, elapsed: ts() }, null, 2));
    process.exit(0);
}, 18000);
