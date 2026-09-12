const fs = require('fs');
const assert = require('assert');
const path = require('path');
const source = fs.readFileSync(process.argv[2] || path.resolve('../MeshCentral/meshagent.js'), 'utf8');
const start = source.indexOf('parent.parent.taskLimiter.launch(function (argument, taskid, taskLimiterQueue)', source.indexOf('else if (cmdid == 12)'));
const end = source.indexOf('}, null, 1);', start);
assert(start >= 0 && end > start);
const callback = source.slice(source.indexOf('function (', start), end + 1);
const run = new Function('obj', 'parent', 'common', `return (${callback})(null, 42, null);`);
let count = 0;
for (const caps of [0, 0x100, 0x200, 0x300]) {
    for (const ram of [false, true]) {
        for (const zipped of [false, true]) {
            const raw = Buffer.from('raw-agent'), zip = Buffer.from('zip-agent');
            const messages = [];
            let diskReads = 0;
            const obj = { authenticated: 2, agentInfo: { capabilities: caps },
                agentExeInfo: { data: ram ? raw : null, zdata: zipped ? zip : null,
                    zhash: 'zip-hash', fileHash: 'served-raw-hash', hash: 'normalized-hash', path: 'fixture' },
                sendBinary: value => messages.push(value) };
            const parent = { agentStats: { agentBinaryUpdate: 0 },
                parent: { debug() {}, agentUpdateBlockSize: 16384, taskLimiter: { completed() {} } },
                fs: { open(file, mode, done) { diskReads++; done(null, 7); },
                    read(fd, buf, offset, length, position, done) { raw.copy(buf, offset); done(null, raw.length); }, close() {} } };
            run(obj, parent, { ShortToStr: value => String.fromCharCode(value >> 8, value & 255) });
            const compressed = caps === 0x300 && zipped;
            assert.strictEqual(diskReads, !ram && !compressed ? 1 : 0);
            assert.strictEqual(messages.length, 3);
            const expected = compressed ? zip : raw;
            assert(messages[2].subarray(4, 4 + expected.length).equals(expected));
            if (!diskReads) assert.strictEqual(obj.agentUpdate.agentUpdateHash, compressed ? 'zip-hash' : 'normalized-hash');
            count++;
        }
    }
}
console.log(JSON.stringify({ ok: true, cases: count, noNetwork: true }));
