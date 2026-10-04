'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const {Readable, Writable} = require('stream');
const source = fs.readFileSync(path.join(__dirname, '../modules/MSH_Installer.js'), 'utf8');
const helper = fs.readFileSync(path.join(__dirname, '../modules/update-helper.js'), 'utf8');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-packaging-'));
function agentFs(extra = {}) {
    return {...fs,
        openSync: (name, flag) => fs.openSync(name, flag === 'rb' ? 'r' : flag),
        createReadStream: (name, options) => fs.createReadStream(name, {...options, flags: 'r'}),
        createWriteStream: (name, options) => fs.createWriteStream(name, {...options, flags: 'w'}), ...extra};
}
function AgentPromise(executor) {
    let resolve, reject;
    const promise = new Promise((a, b) => {resolve = a; reject = b;});
    executor.call(promise, resolve, reject);
    return promise;
}
async function packageMsh(signed) {
    const input = path.join(dir, signed ? 'signed.exe' : 'unsigned.exe');
    const output = path.join(dir, signed ? 'signed-out.exe' : 'unsigned-out.exe');
    const original = Buffer.alloc(256, 0x41);
    fs.writeFileSync(input, original);
    let closed = 0;
    const sandbox = {module: {exports: {}}, Buffer, process: {execPath: output}, console: {log() {}},
        require: () => agentFs({closeSync(fd) {closed++; fs.closeSync(fd);}})};
    vm.runInNewContext(source, sandbox);
    const msh = 'MeshName=古いエージェント\n';
    await new Promise((resolve, reject) => {
        const destination = fs.createWriteStream(output);
        destination.on('error', reject); destination.on('close', resolve);
        sandbox.module.exports({platform: 'win32', sourceFileName: input, destinationStream: destination,
            msh, peinfo: {CertificateTableAddress: signed ? 128 : 0, CertificateTableSize: 128,
                certificateDwLength: 128, CertificateTableSizePos: 32}});
    });
    const result = fs.readFileSync(output), bytes = Buffer.from(msh);
    assert.equal(result.readUInt32BE(result.length - 20), bytes.length, 'trailer counts UTF-8 bytes');
    assert.equal(result.subarray(-16).toString('hex'), 'b996015880544a19b7f7e9be44914c19');
    assert(result.subarray(result.length - 20 - bytes.length, result.length - 20).equals(bytes));
    if (signed) {
        assert.equal(result.length % 8, 0, 'signed certificate table stays aligned');
        assert.equal(result.readUInt32LE(32), result.length - 128);
        assert.equal(result.readUInt32LE(128), result.length - 128);
    } else assert(result.subarray(0, original.length).equals(original));
    assert.equal(sandbox.module.exports.len(), bytes.length, 'existing trailer is recognized case-insensitively');
    assert.equal(closed, 1, 'trailer descriptor closes');
    const corrupt = Buffer.from(result); corrupt.writeUInt32BE(result.length, result.length - 20); fs.writeFileSync(output, corrupt);
    assert.throws(() => sandbox.module.exports.len(), /exceeds/);
    assert.equal(closed, 2, 'descriptor closes even for corrupt trailer');
}
async function packagingSourceFailure() {
    let ended = false;
    const destination = new Writable({write(chunk, encoding, callback) {callback();}});
    destination.on('finish', () => {ended = true;});
    const sandbox = {module: {exports: {}}, Buffer, console: {log() {}}, require: () => agentFs({
        createReadStream() {return new Readable({read() {this.destroy(Error('source lost'));}});}
    })};
    vm.runInNewContext(source, sandbox);
    const failed = new Promise(resolve => {destination.on('error', resolve);});
    sandbox.module.exports({platform: 'other', sourceFileName: 'missing', msh: 'MeshID=test', destinationStream: destination});
    assert.match(String(await failed), /source lost/);
    assert(destination.destroyed, 'source error closes destination instead of leaving packaging pending');
    assert.equal(ended, false, 'failed package never finishes successfully');
}
function updateHelper(zip, fileSystem, timers) {
    const sandbox = {module: {exports: {}}, setTimeout: (timers || {}).setTimeout || setTimeout, clearTimeout: (timers || {}).clearTimeout || clearTimeout, require(name) {
        if (name === 'promise') return AgentPromise;
        if (name === 'zip-reader') return zip;
        if (name === 'fs') return fileSystem;
        throw Error(name);
    }};
    vm.runInNewContext(helper, sandbox);
    return sandbox.module.exports;
}
async function extraction(failure) {
    const update = path.join(dir, 'agent.update.pkg');
    fs.writeFileSync(update, 'original package');
    let closed = 0;
    const payload = Buffer.from('verified executable');
    const zip = {files: failure === 'members' ? ['agent.exe', 'agent.dll'] : ['agent.exe'],
        close() {closed++;}, size: () => {if (failure === 'metadata') throw Error('metadata failed'); return payload.length + (failure === 'size' ? 1 : 0);}, crc: () => 42,
        getStream() {
            if (failure === 'stream-open') throw Error('stream open failed');
            const stream = Readable.from([payload]); stream.crc = failure === 'crc' ? 43 : 42; return stream;
        }};
    const helper = updateHelper({isZip: () => true, read: () => Promise.resolve(zip)}, agentFs());
    if (failure) await assert.rejects(helper.start(update));
    else await helper.start(update);
    // Failed opens can close the already-created destination asynchronously.
    await new Promise(resolve => setTimeout(resolve, 30));
    assert(closed >= 1, 'archive closes');
    assert(!fs.existsSync(update + '_unzipped'), 'extraction staging cleaned');
    assert.equal(fs.readFileSync(update).toString(), failure ? 'original package' : payload.toString());
}
async function stalledExtraction() {
    // The agent accepts no new update until extraction settles, so a read that never
    // finishes must time out and leave no staging behind.
    const update = path.join(dir, 'stalled.update.pkg');
    fs.writeFileSync(update, 'original package');
    fs.writeFileSync(update + '_unzipped', 'partial');
    let cleared = 0;
    const helper = updateHelper({isZip: () => true, read: () => new Promise(() => {})}, agentFs(),
        {setTimeout: fn => { setImmediate(fn); return 1; }, clearTimeout: () => { cleared++; }});
    await assert.rejects(helper.start(update), /timed out/);
    assert(!fs.existsSync(update + '_unzipped'), 'timed-out extraction staging cleaned');
    assert.equal(fs.readFileSync(update).toString(), 'original package', 'timed-out extraction leaves the package alone');
}
(async () => {
    try {
        await packageMsh(false); await packageMsh(true); await packagingSourceFailure();
        await extraction(null);
        for (const failure of ['members', 'stream-open', 'size', 'crc', 'metadata']) await extraction(failure);
        await stalledExtraction();
        const badOpen = updateHelper({isZip() {throw Error('archive inaccessible');}}, agentFs());
        await assert.rejects(badOpen.start('missing'), /inaccessible/);
        console.log('Update packaging: signed/unsigned Unicode MSH, trailer bounds, descriptor cleanup, ZIP integrity and stream failure cleanup passed');
    } finally { fs.rmSync(dir, {recursive: true, force: true}); }
})().catch(error => {console.error(error); process.exitCode = 1;});
