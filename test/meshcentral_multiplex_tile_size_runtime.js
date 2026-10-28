// Desktop tile sizing reads only JPEG and PNG (PRD-1 / DEP-21).
// The server sizes agent-supplied tile bytes in meshdesktopmultiplex.js and recording blocks in mcrec.js.
// It must not sniff formats: the image-size ICNS, JXL and HEIF parsers have unpatched denial-of-service
// loops (GHSA-w3rx-r6r6-pgpr, GHSA-5p2g-fcmc-qvqq). This test checks that:
//   - real JPEG and PNG tiles (encoded by GDI+, the Windows agent's tile encoder) get their real sizes;
//   - ICNS, JXL and HEIF bytes, other formats, and truncated or malformed images are rejected, each
//     within a time bound, in a worker that is terminated if it hangs;
//   - the multiplexor stores a JPEG or PNG tile and drops every rejected one;
//   - mcrec.js indexes a recording that holds a rejected tile without stopping.
// No server, endpoint session, credentials, or real user input is needed.
'use strict';
const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { createRequire } = require('module');
const { Worker, isMainThread, workerData, parentPort } = require('worker_threads');
const { forkFile } = require('./lib/meshcentral_paths');

// Encoded with System.Drawing (GDI+), as the Windows agent encodes tiles (meshcore/KVM/Windows/tile.cpp).
const JPEG_64x48 = Buffer.from('/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAAwAEADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDuPBXgrRtX8M2d3d2fm3Em/c/muucOwHAYDoBXEeNdNt9I8TXlpaR+Vbx7Nqbi2MopPJJPUmsOivbyfhrMctzrE5nicynWpVeflpS5uWHNNSVrzkvdS5VaK0eltj5LMc6weNy2jgqOCjTqQ5b1FbmlaLTvaKfvN8zvJ6rruFFFFfoR8iFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFAH/9k=', 'base64');
const JPEG_16x16 = Buffer.from('/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAAQABADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDuPBXgrRtX8M2d3d2fm3Em/c/muucOwHAYDoBXEeNdNt9I8TXlpaR+Vbx7Nqbi2MopPJJPUmsOivbyfhrMctzrE5nicynWpVeflpS5uWHNNSVrzkvdS5VaK0eltj5LMc6weNy2jgqOCjTqQ5b1FbmlaLTvaKfvN8zvJ6rruf/Z', 'base64');
const PNG_32x16 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAzSURBVEhLY3Br2vJ/IDEDugC9MdwB/5cy4MXoGqmFRx0w6oDB44CBwqMOGHXAqAMG3AEAkCf9vR4DFLgAAAAASUVORK5CYII=', 'base64');
const REAL = [
    { name: 'GDI+ JPEG 64x48', data: JPEG_64x48, width: 64, height: 48 },
    { name: 'GDI+ JPEG 16x16', data: JPEG_16x16, width: 16, height: 16 },
    { name: 'GDI+ PNG 32x16', data: PNG_32x16, width: 32, height: 16 }
];

const hex = s => Buffer.from(s.replace(/\s+/g, ''), 'hex');
function repeat(unit, count) { return Buffer.concat(Array(count).fill(unit)); }

// Bytes that image-size 2.0.2 detects as ICNS, JXL or HEIF, including entries whose zero length
// is what makes the vulnerable parsers loop, and other formats a sniffing reader would accept.
const REJECTED = {
    'ICNS header': hex('69636e7300000008'),
    'ICNS zero-length entry': hex('69636e7300000018 69633038 00000000 69633038 00000000'),
    'JXL container': Buffer.concat([hex('0000000c4a584c200d0a870a'), hex('00000014667479706a786c20000000006a786c20')]),
    'JXL container with zero-size box': Buffer.concat([hex('0000000c4a584c200d0a870a'), hex('00000014667479706a786c20000000006a786c20'), hex('00000000 6a786c70 00000000')]),
    'JXL codestream': hex('ff0a00000000'),
    'HEIF ftyp': hex('00000018667479706865696300000000 6d69663168656963'),
    'HEIF with zero-size box': hex('00000018667479706865696300000000 6d69663168656963 00000000 6d657461 00000000'),
    'GIF': Buffer.from('GIF89a\x10\x00\x10\x00\x00\x00\x00', 'latin1'),
    'BMP': hex('424d 00000000 00000000 36000000 28000000 10000000 10000000 0100 1800'),
    'WebP': Buffer.concat([Buffer.from('RIFF\x24\x00\x00\x00WEBPVP8 ', 'latin1'), Buffer.alloc(24)]),
    'TIFF': hex('49492a00 08000000 0000'),
    'empty': Buffer.alloc(0),
    'JPEG SOI only': hex('ffd8'),
    'JPEG zero segment length': hex('ffd8 ffe0 0000'),
    'JPEG one byte segment length': hex('ffd8 ffe0 0001 00000000'),
    'JPEG segment past the end': hex('ffd8 ffe0 ffff 00'),
    'JPEG scan before frame': hex('ffd8 ffda 0008 0000000000 ffd9'),
    'JPEG end before frame': hex('ffd8 ffd9'),
    'JPEG truncated frame header': hex('ffd8 ffc0 0011 08 0010'),
    'JPEG zero height': hex('ffd8 ffc0 000b 08 0000 0010 01 011100'),
    'JPEG not a marker': hex('ffd8 00 ffc0 000b 08 0010 0010 01 011100'),
    'JPEG fill bytes to the end': Buffer.concat([hex('ffd8'), Buffer.alloc(1 << 20, 0xff)]),
    'JPEG many empty segments': Buffer.concat([hex('ffd8'), repeat(hex('fffe 0002'), 1 << 18)]),
    'PNG signature only': hex('89504e470d0a1a0a'),
    'PNG first chunk not IHDR': hex('89504e470d0a1a0a 0000000d 49444154 00000010 00000010 0806000000'),
    'PNG IHDR wrong length': hex('89504e470d0a1a0a 0000000c 49484452 00000010 00000010 0806000000'),
    'PNG zero width': hex('89504e470d0a1a0a 0000000d 49484452 00000000 00000010 0806000000')
};
for (const image of REAL) {
    // Every proper prefix of a real image cut before its size fields, and the image with its first byte changed.
    const sizeEnd = image.data[0] == 0x89 ? 24 : image.data.indexOf(hex('ffc0')) + 9;
    for (let n = 0; n < sizeEnd; n++) { REJECTED[image.name + ' cut to ' + n + ' bytes'] = image.data.subarray(0, n); }
    const changed = Buffer.from(image.data); changed[0] ^= 0xff;
    REJECTED[image.name + ' with a changed first byte'] = changed;
}

function loadReader(mcrecPath) {
    const mcrec = require(mcrecPath);
    assert.strictEqual(typeof mcrec.readImageSize, 'function', 'mcrec.js must export readImageSize');
    return mcrec.readImageSize;
}

// Runs in a worker so that a reader that loops can be stopped and reported.
function workerMain() {
    const readImageSize = loadReader(workerData.mcrecPath);
    const results = {};
    for (const [name, b64] of Object.entries(workerData.samples)) {
        const data = Buffer.from(b64, 'base64');
        const start = process.hrtime.bigint();
        let result, error = null;
        try { result = readImageSize(data); } catch (ex) { error = String(ex && ex.message || ex); }
        results[name] = { result, error, ms: Number(process.hrtime.bigint() - start) / 1e6 };
    }
    parentPort.postMessage(results);
}

function runInWorker(mcrecPath, samples) {
    return new Promise((resolve, reject) => {
        const encoded = {};
        for (const [name, data] of Object.entries(samples)) { encoded[name] = data.toString('base64'); }
        const worker = new Worker(__filename, { workerData: { mcrecPath, samples: encoded } });
        const timer = setTimeout(() => { worker.terminate(); reject(new Error('the reader did not return within 10 s (hang)')); }, 10000);
        worker.once('message', results => { clearTimeout(timer); worker.terminate(); resolve(results); });
        worker.once('error', error => { clearTimeout(timer); reject(error); });
    });
}

// The real multiplexor, with its own require so that './mcrec.js' is the fork's.
function loadMultiplexor(sourcePath) {
    const sandbox = { require: createRequire(sourcePath), module: { exports: {} }, Buffer, console, setTimeout, clearTimeout, setInterval, clearInterval, setImmediate };
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), sandbox, { filename: sourcePath });
    const parent = {
        trafficStats: { desktopMultiplex: { sessions: 0 } },
        parent: { debug() {}, DispatchEvent() {}, args: {} },
        db: { Get(id, cb) { cb(null, [{ meshid: 'mesh/test/group', name: 'test', icon: 1 }]); } },
        users: {}, wsagents: {}, meshes: {}
    };
    const mux = sandbox.CreateDesktopMultiplexor(parent, { id: '' }, 'node/test/device', 'test', () => {});
    const socket = { pause() {}, resume() {}, setTimeout() {}, bytesRead: 0, bytesWritten: 0 };
    const peer = browser => ({ req: { query: browser ? { browser: 1 } : {} }, user: { _id: 'user/test/v', name: 'v' },
        ws: { _socket: socket, send(data, cb) { if (cb) cb(); } }, close() {} });
    mux.addPeer(peer(true)); mux.addPeer(peer(false));
    return mux;
}

function tilePacket(x, y, image) {
    const header = Buffer.alloc(8);
    header.writeUInt16BE(3, 0); header.writeUInt16BE(8 + image.length, 2); header.writeUInt16BE(x, 4); header.writeUInt16BE(y, 6);
    return Buffer.concat([header, image]);
}
const screenPacket = (w, h) => Buffer.from([0, 7, 0, 8, w >> 8, w & 255, h >> 8, h & 255]);

function recordingBlock(type, flags, time, data) {
    const header = Buffer.alloc(16);
    header.writeInt16BE(type, 0); header.writeInt16BE(flags, 2); header.writeInt32BE(data.length, 4); header.writeIntBE(time, 10, 6);
    return Buffer.concat([header, data]);
}

async function main() {
    const mcrecPath = path.resolve(process.argv[2] || forkFile('mcrec.js'));
    const multiplexPath = path.resolve(process.argv[3] || forkFile('meshdesktopmultiplex.js'));
    loadReader(mcrecPath); // Fails here, before anything runs mcrec.js as a program, if the reader is missing.
    let failed = 0;
    const check = (name, fn) => { try { fn(); console.log('PASS ' + name); } catch (ex) { failed++; console.error('FAIL ' + name + ': ' + ex.message); } };

    const samples = Object.assign({}, REJECTED);
    for (const image of REAL) { samples[image.name] = image.data; }
    const results = await runInWorker(mcrecPath, samples);
    for (const image of REAL) {
        check('reads the size of ' + image.name, () => {
            const r = results[image.name];
            assert.strictEqual(r.error, null);
            assert.deepStrictEqual(r.result, { width: image.width, height: image.height });
        });
    }
    let slowest = 0;
    for (const name of Object.keys(REJECTED)) {
        const r = results[name];
        slowest = Math.max(slowest, r.ms);
        if ((r.error !== null) || (r.result !== null) || (r.ms > 250)) {
            failed++; console.error('FAIL rejects ' + name + ': ' + JSON.stringify(r));
        }
    }
    console.log('PASS rejects ' + Object.keys(REJECTED).length + ' non-JPEG/PNG or malformed inputs (slowest ' + slowest.toFixed(1) + ' ms)');

    check('the multiplexor stores JPEG and PNG tiles and drops rejected ones', () => {
        const mux = loadMultiplexor(multiplexPath);
        mux.processAgentData(screenPacket(64, 48));
        const before = mux.imagesCount;
        for (const name of ['ICNS zero-length entry', 'JXL container with zero-size box', 'HEIF with zero-size box', 'TIFF', 'JPEG zero segment length']) {
            mux.processAgentData(tilePacket(0, 0, REJECTED[name]));
            assert.strictEqual(mux.imagesCount, before, name + ' tile must be dropped');
        }
        mux.processAgentData(tilePacket(0, 0, JPEG_64x48));
        assert.strictEqual(mux.imagesCount, before + 1, 'JPEG tile stored');
        assert.strictEqual(mux.imagesCounters[mux.lastData], 12, 'a 64x48 tile covers 4x3 slots');
        mux.processAgentData(tilePacket(16, 16, PNG_32x16));
        assert.strictEqual(mux.imagesCounters[mux.lastData], 2, 'a 32x16 tile covers 2x1 slots');
    });

    // mcrec.js run as a program indexes a recording; a rejected tile is skipped, not fatal.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcrec-tile-size-'));
    try {
        const t0 = 1700000000000;
        const metadata = Buffer.from(JSON.stringify({ magic: 'MeshCentralRelaySession', ver: 1, protocol: 2 }));
        const blocks = [recordingBlock(1, 0, t0, metadata)];
        const screenBlock = recordingBlock(2, 1, t0, screenPacket(64, 48));
        blocks.push(screenBlock);
        const jpegPtr = blocks.reduce((n, b) => n + b.length, 0);
        blocks.push(recordingBlock(2, 1, t0 + 100, tilePacket(0, 0, JPEG_64x48)));
        const icnsPtr = blocks.reduce((n, b) => n + b.length, 0);
        blocks.push(recordingBlock(2, 1, t0 + 200, tilePacket(0, 0, REJECTED['ICNS zero-length entry'])));
        blocks.push(recordingBlock(2, 1, t0 + 11000, screenPacket(64, 48))); // Past the 10 s index interval
        blocks.push(recordingBlock(3, 0, t0 + 11000, Buffer.from('MeshCentralMCREC')));
        const file = path.join(dir, 'tiles.mcrec');
        fs.writeFileSync(file, Buffer.concat(blocks));
        const run = childProcess.spawnSync(process.execPath, [mcrecPath, file], { cwd: dir, encoding: 'utf8', timeout: 20000 });
        check('mcrec.js indexes a recording that holds a rejected tile', () => {
            assert.strictEqual(run.error, undefined, String(run.error));
            assert.strictEqual(run.status, 0, run.stderr);
            assert(/Done\./.test(run.stdout), 'indexing must finish: ' + run.stdout + run.stderr);
            const out = fs.readFileSync(file);
            assert.strictEqual(out.toString('utf8', out.length - 16), 'MeshCentralMCNDX', 'index written');
            const metaStart = out.readUIntBE(out.length - 32 + 10, 6);
            const meta = JSON.parse(out.toString('utf8', metaStart + 16, metaStart + 16 + out.readUInt32BE(metaStart + 4)));
            const basePtr = metadata.length + 16;
            assert.strictEqual(meta.indexes.length, 1);
            assert.deepStrictEqual(meta.indexes[0].slice(1), [64, 48, jpegPtr - basePtr], 'the JPEG tile covers the screen and the ICNS tile is not indexed');
            assert(icnsPtr > jpegPtr);
        });
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }

    console.log(JSON.stringify({ mcrecPath, multiplexPath, real: REAL.length, rejected: Object.keys(REJECTED).length, failed }));
    process.exitCode = failed ? 1 : 0;
}

if (isMainThread) { main().catch(error => { console.error(error.stack || error); process.exitCode = 1; }); } else { workerMain(); }
