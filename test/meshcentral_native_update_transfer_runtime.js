// Execute production sender callbacks through all ACKs. No network or installation.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const source = fs.readFileSync(process.argv[2] || path.resolve('../MeshCentral/meshagent.js'), 'utf8');
const start = source.indexOf('parent.parent.taskLimiter.launch(function (argument, taskid, taskLimiterQueue)', source.indexOf('else if (cmdid == 12)'));
const end = source.indexOf('}, null, 1);', start);
assert(start >= 0 && end > start);
const begin = new Function('obj', 'parent', 'common', `return (${source.slice(source.indexOf('function (', start), end + 1)})(null, 42, null);`);
const ackStart = source.indexOf('if ((msg.length == 4)', source.indexOf('else if (cmdid == 14)'));
const ackEnd = source.indexOf('else if (cmdid == 15)', ackStart);
assert(ackStart >= 0 && ackEnd > ackStart);
const ackBody = source.slice(ackStart, ackEnd).trim().replace(/}\s*$/, '');
const ack = new Function('obj', 'parent', 'common', 'msg', ackBody);
const common = { ShortToStr: n => String.fromCharCode(n >> 8, n & 255), ReadShort: (s, p) => s.charCodeAt(p) * 256 + s.charCodeAt(p + 1) };
const fixtures = [7, 16384, 16385, 32768].map(size => ({ name: `boundary-${size}`, raw: Buffer.alloc(size, 65) }));
if (process.argv[3]) {
    const data = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
    for (const row of data) fixtures.push({ name: row.name, raw: fs.readFileSync(row.path), normalized: Buffer.from(row.nativeSha384, 'hex').toString('binary') });
}
let cases = 0;
const failures = [];
for (const fixture of fixtures) for (const caps of [0, 0x100, 0x200, 0x300]) for (const ram of [false, true]) for (const zipped of [false, true]) {
    const label = `${fixture.name}/caps-${caps.toString(16)}/ram-${ram}/zip-${zipped}`;
    try {
        const raw = fixture.raw;
        const zip = Buffer.alloc(16901, 90); // Opaque transport payload; decoder is tested separately.
        const rawHash = crypto.createHash('sha384').update(raw).digest('binary');
        const normalized = fixture.normalized || rawHash;
        const zipHash = crypto.createHash('sha384').update(zip).digest('binary');
        const compressed = caps === 0x300 && zipped;
        const pending = [], received = [], terminal = [];
        let completed = 0, opened = 0, closed = 0;
        const obj = { authenticated: 2, agentInfo: { capabilities: caps },
            agentExeInfo: { data: ram ? raw : null, zdata: zipped ? zip : null, size: raw.length,
                zhash: zipHash, fileHash: rawHash, hash: normalized, path: 'fixture' },
            sendBinary(value) { pending.push(Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value, 'binary')); } };
        const parent = { agentStats: { agentBinaryUpdate: 0 },
            parent: { debug() {}, agentUpdateBlockSize: 16384, taskLimiter: { completed() { completed++; } } },
            fs: { open(file, mode, done) { opened++; done(null, 7); },
                read(fd, buf, offset, length, position, done) {
                    assert.strictEqual(fd, 7, 'RAM transfer incorrectly routed to disk');
                    const n = raw.copy(buf, offset, position, Math.min(position + length, raw.length));
                    done(null, n);
                }, close(fd) { assert.strictEqual(fd, 7); closed++; } } };
        begin(obj, parent, common);
        for (let iterations = 0; pending.length; iterations++) {
            assert(iterations < 10000, 'transfer did not finish');
            const frame = pending.shift(), command = frame.readUInt16BE(0);
            if (command === 14) {
                received.push(frame.subarray(4));
                ack(obj, parent, common, '\0\x0e\0\x01');
            } else if (command === 13 && frame.length > 4) terminal.push(frame.subarray(4));
        }
        assert(Buffer.concat(received).equals(compressed ? zip : raw), 'transferred bytes differ from payload');
        assert.strictEqual(terminal.length, 1, 'expected one final hash');
        assert.strictEqual(terminal[0].toString('binary'), compressed ? zipHash : normalized, 'native receiver rejects terminal hash');
        assert.strictEqual(completed, 1);
        assert.strictEqual(closed, opened);
        assert.strictEqual(obj.agentUpdate, undefined);
        cases++;
    } catch (error) { failures.push({ label, error: error.message }); }
}
console.log(JSON.stringify({ ok: failures.length === 0, cases, failures, noNetwork: true }, null, 2));
if (failures.length) process.exitCode = 1;
