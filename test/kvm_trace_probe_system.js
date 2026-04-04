// Probe #3: runs the collector via PsExec as SYSTEM, same as kvm_system_picture_runtime.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const {
    resolveBridgeDllPath,
    resolvePsExecPath,
    resolveRundll32Path,
    waitForReadableFile
} = require('./lib/kvm_runtime_helpers');

const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
const dllPath = resolveBridgeDllPath(exePath);
const rundll32Path = resolveRundll32Path();
const psexecPath = resolvePsExecPath();

console.log('EXE=' + exePath);
console.log('DLL=' + dllPath);
console.log('PSEXEC=' + psexecPath);
console.log('RUNDLL32=' + rundll32Path);

// Write the collector as a standalone script
const collectorPath = path.join(os.tmpdir(), `kvm_system_trace_collector_${process.pid}.js`);
const reportPath = path.join(os.tmpdir(), `kvm_system_trace_report_${process.pid}.json`);
const launcherPath = path.join(os.tmpdir(), `kvm_system_trace_launcher_${process.pid}.cmd`);

const collectorCode = `
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const net = require('net');

const rundll32 = process.argv[2];
const dll = process.argv[3];
const reportPath = process.argv[4];

function pkt(type, payload) {
    const body = Buffer.from(payload || []);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

const pipeName = '\\\\\\\\.\\\\pipe\\\\MeshKvmSys_' + process.pid + '_' + Date.now();
let buf = Buffer.alloc(0);
let child = null;
const dataEvents = [];
const packets = [];
const timeline = [];
let startTime = Date.now();
let childStderr = '';
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

function flush(tag) {
    try {
        fs.writeFileSync(reportPath, JSON.stringify({
            tag, packets, dataEvents: dataEvents.slice(-200),
            timeline: timeline.slice(-100),
            childStderrTail: childStderr.slice(-4000),
            elapsed: ts(), pendingBufLen: buf.length,
            sessionId: os.userInfo().username,
            pid: process.pid
        }, null, 2));
    } catch(e) {}
}

const server = net.createServer((conn) => {
    timeline.push({ t: ts(), event: 'connected' });
    conn.on('data', (chunk) => {
        dataEvents.push({ t: ts(), chunkLen: chunk.length, bufBefore: buf.length });
        buf = Buffer.concat([buf, chunk]);
        parsePackets();
    });
    // Immediately send setup
    setTimeout(() => {
        try {
            conn.write(pkt(5, [1, 50, 4, 0, 0, 100]));
            conn.write(pkt(8, [0]));
            conn.write(pkt(87, [2]));
            conn.write(pkt(6));
            timeline.push({ t: ts(), event: 'write1' });
        } catch(e) { timeline.push({ t: ts(), event: 'write1err', msg: e.message }); }
    }, 300);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({t:ts(),event:'write2'}); } catch(e){} }, 1500);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({t:ts(),event:'write3'}); } catch(e){} }, 3000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({t:ts(),event:'write4'}); } catch(e){} }, 5000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({t:ts(),event:'write5'}); } catch(e){} }, 8000);
    setTimeout(() => { try { conn.write(pkt(6)); timeline.push({t:ts(),event:'write6'}); } catch(e){} }, 11000);
    setTimeout(() => { try { conn.destroy(); flush('pipe-end'); } catch(e){} }, 15000);
});

const tickInterval = setInterval(() => flush('tick'), 500);

server.listen(pipeName, () => {
    startTime = Date.now();
    timeline.push({ t: 0, event: 'pipe-listening' });
    const env = Object.assign({}, process.env, {
        STEALTH_KVM_TRACE_STARTUP: '1',
        STEALTH_KVM_TRACE_LOOP: '1',
        STEALTH_KVM_TRACE_TILE: '1'
    });
    child = cp.spawn(rundll32, [dll + ',KvmSessionBridgeW', pipeName], {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: env
    });
    timeline.push({ t: ts(), event: 'child-spawned', pid: child.pid });
    child.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        childStderr += text;
        for (const line of text.split(/\\r?\\n/)) {
            if (line.trim()) timeline.push({ t: ts(), event: 'trace', line: line.trim() });
        }
    });
    child.on('exit', (code, signal) => { timeline.push({ t: ts(), event: 'child-exit', code, signal }); flush('exit'); });
});

setTimeout(() => { clearInterval(tickInterval); flush('timeout'); process.exit(0); }, 20000);
`;

fs.writeFileSync(collectorPath, collectorCode, 'ascii');
fs.writeFileSync(launcherPath, `@echo off\r\n"${process.execPath}" "${collectorPath}" "${rundll32Path}" "${dllPath}" "${reportPath}"\r\n`, 'ascii');

console.log('COLLECTOR=' + collectorPath);
console.log('REPORT=' + reportPath);
console.log('LAUNCHER=' + launcherPath);
console.log('');

// Run via PsExec as SYSTEM
const psexec = cp.spawnSync(psexecPath, ['-accepteula', '-nobanner', '-s', launcherPath], {
    windowsHide: true,
    encoding: 'utf8',
    timeout: 30000
});

console.log('PSEXEC_STATUS=' + psexec.status);
if (psexec.stderr) console.log('PSEXEC_STDERR=' + psexec.stderr.slice(0, 500));

// Wait a moment for file to be flushed
setTimeout(async () => {
    try {
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        const pics = report.packets.filter(p => p.type === 3 || p.type === 27);
        console.log('\n=== SYSTEM PROBE RESULTS ===');
        console.log('Tag: ' + report.tag);
        console.log('Elapsed: ' + report.elapsed + 'ms');
        console.log('Total packets: ' + report.packets.length);
        console.log('Picture packets: ' + pics.length);
        if (pics.length > 0) console.log('First picture at: ' + pics[0].t + 'ms');
        console.log('\nData events (first 15):');
        for (const de of (report.dataEvents || []).slice(0, 15)) {
            console.log(`  t=${de.t}ms  chunk=${de.chunkLen}  bufBefore=${de.bufBefore}`);
        }
        console.log('\nPackets (first 15):');
        for (const p of (report.packets || []).slice(0, 15)) {
            console.log(`  t=${p.t}ms  type=${p.type}  size=${p.size}`);
        }
        console.log('\nTraces:');
        for (const e of (report.timeline || []).filter(e => e.event === 'trace')) {
            console.log(`  t=${e.t}ms  ${e.line}`);
        }
        console.log('\nTimeline events:');
        for (const e of (report.timeline || []).filter(e => e.event !== 'trace')) {
            console.log(`  t=${e.t}ms  ${e.event}` + (e.pid ? ' pid=' + e.pid : '') + (e.code !== undefined ? ' code=' + e.code : ''));
        }
    } catch (e) {
        console.log('Failed to read report: ' + e.message);
        if (fs.existsSync(reportPath)) {
            console.log('Raw: ' + fs.readFileSync(reportPath, 'utf8').slice(0, 2000));
        }
    }
    process.exit(0);
}, 2000);
