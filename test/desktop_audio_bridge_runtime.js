// Windows-only runtime probe for the native desktop-audio loopback helper (MeshAudioBridgeW).
// It launches the built service DLL through rundll32 in "local" mode, reads the framed packet
// stream from stdout, and validates the CONFIG handshake, packet header invariants, Opus AUDIO /
// SILENCE cadence, and a clean shutdown on stdin EOF. Captured audio is parsed for structure only
// and discarded; nothing is written to disk.
//
// Requires an authorized interactive Windows desktop with a default render endpoint and a built
// service DLL. On any other platform it skips cleanly (exit 0) so the suite can run on this Mac.
// Usage: node test/desktop_audio_bridge_runtime.js <ServiceDll> <evidence-dir>
'use strict';
const fs = require('fs');
const path = require('path');

if (process.platform !== 'win32') {
    process.stdout.write('SKIP desktop_audio_bridge_runtime: requires Windows\n');
    process.exit(0);
}
if (!process.argv[2] || !process.argv[3]) {
    throw new Error('Requires a built service DLL path and an evidence directory');
}

const { spawn } = require('child_process');
const serviceDll = path.resolve(process.argv[2]);
const evidence = path.resolve(process.argv[3]);
fs.mkdirSync(evidence, { recursive: true });

const HEADER = 16;
const TYPE = { 1: 'CONFIG', 2: 'AUDIO', 3: 'SILENCE', 4: 'STATUS' };
const report = { config: null, counts: { CONFIG: 0, AUDIO: 0, SILENCE: 0, STATUS: 0 }, bytes: 0, errors: [], firstDiscontinuity: false, exitCode: null };

let buffer = Buffer.alloc(0);
let lastSeq = null;

function parsePackets() {
    while (buffer.length >= HEADER) {
        const version = buffer.readUInt8(0);
        const type = buffer.readUInt8(1);
        const flags = buffer.readUInt16LE(2);
        const seq = buffer.readUInt32LE(4);
        const payloadLen = buffer.readUInt32LE(12);
        if (version !== 1) { report.errors.push('bad version ' + version); return false; }
        if (!TYPE[type]) { report.errors.push('bad type ' + type); return false; }
        if (payloadLen > 4096) { report.errors.push('payload too large ' + payloadLen); return false; }
        if (buffer.length < HEADER + payloadLen) { return true; }
        const payload = buffer.subarray(HEADER, HEADER + payloadLen);
        buffer = buffer.subarray(HEADER + payloadLen);

        report.counts[TYPE[type]]++;
        if (lastSeq !== null && seq !== ((lastSeq + 1) >>> 0)) { report.errors.push('seq gap ' + lastSeq + '->' + seq); }
        lastSeq = seq;
        if (report.counts.CONFIG + report.counts.AUDIO + report.counts.SILENCE + report.counts.STATUS === 1 && (flags & 1)) { report.firstDiscontinuity = true; }

        if (type === 1) {
            if (payloadLen !== 16) { report.errors.push('CONFIG length ' + payloadLen); }
            else {
                report.config = {
                    codec: payload.readUInt32LE(0), sampleRate: payload.readUInt32LE(4),
                    channels: payload.readUInt16LE(8), frameMs: payload.readUInt16LE(10), bitrate: payload.readUInt32LE(12)
                };
            }
        } else if (type === 4) {
            report.errors.push('STATUS code ' + payload.readUInt32LE(0) + ': ' + payload.subarray(4).toString('utf8'));
        }
    }
    return true;
}

const rundll32 = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'rundll32.exe');
const child = spawn(rundll32, [serviceDll + ',MeshAudioBridgeW', 'local'], { stdio: ['pipe', 'pipe', 'ignore'] });

child.stdout.on('data', (chunk) => { report.bytes += chunk.length; buffer = Buffer.concat([buffer, chunk]); if (!parsePackets()) { try { child.kill(); } catch (e) {} } });
child.on('error', (e) => { report.errors.push('spawn: ' + String(e)); });

// Capture ~2 seconds, then close stdin to request a clean shutdown and confirm the helper exits.
const stopTimer = setTimeout(() => { try { child.stdin.end(); } catch (e) {} }, 2000);
const killTimer = setTimeout(() => { try { child.kill(); } catch (e) {} report.errors.push('helper did not exit on stdin EOF'); }, 7000);

child.on('exit', (code) => {
    clearTimeout(stopTimer);
    clearTimeout(killTimer);
    report.exitCode = code;
    const ok = report.config !== null && report.config.codec === 1 && report.config.sampleRate === 48000 &&
        report.config.channels === 2 && report.config.frameMs === 20 && report.firstDiscontinuity &&
        report.counts.STATUS === 0 && report.errors.length === 0;
    report.success = ok;
    fs.writeFileSync(path.join(evidence, 'desktop_audio_bridge_runtime.json'), JSON.stringify(report, null, 2));
    process.stdout.write((ok ? 'PASS' : 'FAIL') + ' desktop_audio_bridge_runtime ' + JSON.stringify(report.counts) + '\n');
    process.exit(ok ? 0 : 1);
});
