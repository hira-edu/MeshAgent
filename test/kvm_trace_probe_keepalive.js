// Probe #6: Frequent tiny writes to see if they unblock pipe reads
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const net = require('net');
const { getSystemRundll32Path } = require('./lib/rundll32_lifecycle');

const dllPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
const rundll32 = getSystemRundll32Path();

if (!fs.existsSync(dllPath)) { console.error('DLL not found: ' + dllPath); process.exit(1); }

function pkt(type, payload) {
    const body = Buffer.from(payload || []);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

const pipeName = `\\\\.\\pipe\\MeshKvmKA_${process.pid}_${Date.now()}`;
let buf = Buffer.alloc(0);
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

const server = net.createServer((conn) => {
    conn.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        parsePackets();
    });

    // Send setup at t=100ms
    setTimeout(() => {
        try {
            conn.write(pkt(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));
            conn.write(pkt(8, [0]));
            conn.write(pkt(87, [2]));
            conn.write(pkt(6));
        } catch (e) {}
    }, 100);

    // Send refreshes at 3s and 6s
    setTimeout(() => { try { conn.write(pkt(6)); } catch (e) {} }, 3000);
    setTimeout(() => { try { conn.write(pkt(6)); } catch (e) {} }, 6000);

    // KEEPALIVE: send tiny no-op packets every 100ms
    // Using type 255 (unknown) with 4 bytes — should be ignored by the bridge
    const keepalive = setInterval(() => {
        try { conn.write(Buffer.from([0x00, 0xFF, 0x00, 0x04])); } catch (e) {}
    }, 100);

    setTimeout(() => { clearInterval(keepalive); conn.destroy(); }, 9000);
});

server.listen(pipeName, () => {
    startTime = Date.now();

    const env = Object.assign({}, process.env, {
        STEALTH_KVM_TRACE_STARTUP: '1',
        STEALTH_KVM_TRACE_LOOP: '1'
    });

    const child = cp.spawn(rundll32, [`${dllPath},KvmSessionBridgeW`, pipeName], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: env
    });
    child.stderr.on('data', (chunk) => { childStderr += chunk.toString(); });
    child.on('exit', () => {});
});

setTimeout(() => {
    const pics = packets.filter(p => p.type === 3 || p.type === 27);
    console.log('Total packets: ' + packets.length);
    console.log('Picture packets: ' + pics.length);
    if (pics.length > 0) console.log('First picture at: ' + pics[0].t + 'ms');
    console.log('');
    console.log('=== PICTURE PACKETS ===');
    for (const p of pics) {
        console.log(`  t=${p.t}ms  type=${p.type}  size=${p.size}`);
    }
    console.log('');
    console.log('=== ALL PACKETS (non-picture) first 20 ===');
    let n = 0;
    for (const p of packets) {
        if (p.type !== 3 && p.type !== 27 && n < 20) {
            console.log(`  t=${p.t}ms  type=${p.type}  size=${p.size}`);
            n++;
        }
    }
    console.log('');
    console.log('=== TRACES ===');
    for (const line of childStderr.split(/\r?\n/)) {
        if (line.trim()) console.log('  ' + line.trim());
    }
    process.exit(0);
}, 11000);
