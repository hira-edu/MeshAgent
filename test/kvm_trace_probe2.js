// Probe #2: more granular timing, tracks partial pipe reads and timestamps every data event
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const net = require('net');

const dllPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
const rundll32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'rundll32.exe');
const reportPath = path.join(os.tmpdir(), `kvm_trace_probe2_${process.pid}_${Date.now()}.json`);

if (!fs.existsSync(dllPath)) { console.error('DLL not found: ' + dllPath); process.exit(1); }

function pkt(type, payload) {
    const body = Buffer.from(payload || []);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

const pipeName = `\\\\.\\pipe\\MeshKvmTrace2_${process.pid}_${Date.now()}`;
let buf = Buffer.alloc(0);
let child = null;
const timeline = [];
const dataEvents = []; // every raw data event with size and timestamp
const packets = [];
let startTime = Date.now();
function ts() { return Date.now() - startTime; }

function parsePackets() {
    let off = 0;
    while ((buf.length - off) >= 4) {
        let type = buf.readUInt16BE(off);
        let size = buf.readUInt16BE(off + 2);
        if (type === 27) {
            if ((buf.length - off) < 8) break;
            size = 8 + buf.readUInt32BE(off + 4);
        }
        if (size < 4 || (buf.length - off) < size) break;
        packets.push({ t: ts(), type, size });
        off += size;
    }
    if (off > 0) buf = buf.slice(off);
}

let childStderr = '';

function flush(tag) {
    try {
        fs.writeFileSync(reportPath, JSON.stringify({
            tag,
            packets,
            dataEvents: dataEvents.slice(-200),
            dataEventCount: dataEvents.length,
            timeline: timeline.slice(-100),
            childStderrTail: childStderr.slice(-4000),
            elapsed: ts(),
            pendingBufLen: buf.length
        }, null, 2));
    } catch (e) { /* ignore */ }
}

const server = net.createServer((conn) => {
    timeline.push({ t: ts(), event: 'connected' });

    conn.on('data', (chunk) => {
        dataEvents.push({ t: ts(), chunkLen: chunk.length, bufBefore: buf.length });
        buf = Buffer.concat([buf, chunk]);
        parsePackets();
    });

    // t=300ms: setup + unpause + refresh
    setTimeout(() => {
        try {
            conn.write(pkt(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));
            conn.write(pkt(8, [0]));
            conn.write(pkt(87, [2]));
            conn.write(pkt(6));
            timeline.push({ t: ts(), event: 'write1-setup+refresh' });
        } catch (e) {}
    }, 300);

    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write2-refresh' }); } catch (e) {} }, 1500);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write3-refresh' }); } catch (e) {} }, 3000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write4-refresh' }); } catch (e) {} }, 5000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write5-refresh' }); } catch (e) {} }, 8000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({ t: ts(), event: 'write6-refresh' }); } catch (e) {} }, 11000);
    setTimeout(() => { try { conn.destroy(); flush('pipe-end'); } catch (e) {} }, 15000);
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

    child.stdout.on('data', (chunk) => { /* stdout goes to bridge pipe, not here */ });
    child.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        childStderr += text;
        for (const line of text.split(/\r?\n/)) {
            if (line.trim()) timeline.push({ t: ts(), event: 'trace', line: line.trim() });
        }
    });
    child.on('exit', (code, signal) => { timeline.push({ t: ts(), event: 'child-exit', code, signal }); flush('exit'); });
});

// Periodic flush
const flushInterval = setInterval(() => flush('tick'), 500);

setTimeout(() => {
    clearInterval(flushInterval);
    flush('timeout');
    // Print summary
    const picPackets = packets.filter(p => p.type === 3 || p.type === 27);
    console.log('REPORT=' + reportPath);
    console.log('Total packets: ' + packets.length);
    console.log('Total data events: ' + dataEvents.length);
    console.log('Picture packets: ' + picPackets.length);
    if (picPackets.length > 0) {
        console.log('First picture at: ' + picPackets[0].t + 'ms');
    }
    console.log('');
    console.log('=== DATA EVENTS (first 30) ===');
    for (const de of dataEvents.slice(0, 30)) {
        console.log(`  t=${de.t}ms  chunk=${de.chunkLen}  bufBefore=${de.bufBefore}`);
    }
    console.log('');
    console.log('=== PACKETS (first 30) ===');
    for (const p of packets.slice(0, 30)) {
        console.log(`  t=${p.t}ms  type=${p.type}  size=${p.size}`);
    }
    console.log('');
    console.log('=== TRACES ===');
    for (const e of timeline.filter(e => e.event === 'trace')) {
        console.log(`  t=${e.t}ms  ${e.line}`);
    }
    process.exit(0);
}, 18000);
