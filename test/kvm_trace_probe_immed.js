// Probe #5: Use setImmediate spin loop instead of timers to keep event loop polling
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const net = require('net');

const dllPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
const rundll32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'rundll32.exe');

if (!fs.existsSync(dllPath)) { console.error('DLL not found: ' + dllPath); process.exit(1); }

function pkt(type, payload) {
    const body = Buffer.from(payload || []);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

const pipeName = `\\\\.\\pipe\\MeshKvmImm_${process.pid}_${Date.now()}`;
let buf = Buffer.alloc(0);
const packets = [];
let startTime = Date.now();
let conn = null;
let done = false;
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
let writesDone = [false, false, false, false, false];

function tick() {
    if (done) return;
    const elapsed = ts();

    // Send control packets at specific times
    if (!writesDone[0] && elapsed >= 100) {
        writesDone[0] = true;
        if (conn) {
            try {
                conn.write(pkt(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));
                conn.write(pkt(8, [0]));
                conn.write(pkt(87, [2]));
                conn.write(pkt(6));
            } catch(e) {}
        }
    }
    if (!writesDone[1] && elapsed >= 2000) { writesDone[1] = true; if (conn) try { conn.write(pkt(6)); } catch(e) {} }
    if (!writesDone[2] && elapsed >= 4000) { writesDone[2] = true; if (conn) try { conn.write(pkt(6)); } catch(e) {} }
    if (!writesDone[3] && elapsed >= 6000) { writesDone[3] = true; if (conn) try { conn.write(pkt(6)); } catch(e) {} }
    if (!writesDone[4] && elapsed >= 8000) { writesDone[4] = true; if (conn) try { conn.write(pkt(6)); } catch(e) {} }

    if (elapsed >= 10000) {
        done = true;
        if (conn) try { conn.destroy(); } catch(e) {}
        return;
    }
    setImmediate(tick);
}

const server = net.createServer((c) => {
    conn = c;
    conn.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        parsePackets();
    });
});

server.listen(pipeName, () => {
    startTime = Date.now();

    const env = Object.assign({}, process.env, {
        STEALTH_KVM_TRACE_STARTUP: '1',
        STEALTH_KVM_TRACE_LOOP: '1',
        STEALTH_KVM_TRACE_TILE: '1'
    });

    const child = cp.spawn(rundll32, [`${dllPath},KvmSessionBridgeW`, pipeName], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: env
    });
    child.stderr.on('data', (chunk) => { childStderr += chunk.toString(); });
    child.on('exit', () => {});

    // Start the setImmediate spin loop
    setImmediate(tick);
});

setTimeout(() => {
    done = true;
    const pics = packets.filter(p => p.type === 3 || p.type === 27);
    console.log('Total packets: ' + packets.length);
    console.log('Picture packets: ' + pics.length);
    if (pics.length > 0) console.log('First picture at: ' + pics[0].t + 'ms');
    console.log('');
    console.log('=== ALL PACKETS ===');
    for (const p of packets) {
        const isPic = (p.type === 3 || p.type === 27) ? ' *** PICTURE ***' : '';
        console.log(`  t=${p.t}ms  type=${p.type}  size=${p.size}${isPic}`);
    }
    console.log('');
    console.log('=== TRACES ===');
    for (const line of childStderr.split(/\r?\n/)) {
        if (line.trim()) console.log('  ' + line.trim());
    }
    process.exit(0);
}, 12000);
