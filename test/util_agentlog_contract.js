'use strict';
// util-agentlog (MeshAgent-owned, D22a) after the Stage 6 merge of upstream MeshCentral 1.3.1.
// Executes modules/util-agentlog.js on log text covering both sides of the merge:
//   - upstream #8082: 12 AM is hour 00, an unpadded hour still parses, and crash lines that arrive before
//     any timestamped entry are ignored instead of throwing on peek();
//   - upstream #8081: PIE crash frames (name(symbol+offset) [address]) record the file offset, external
//     .so frames are skipped, and a base= line records the ASLR base;
//   - the fork: millisecond timestamps and the [pid= tid=] [component] metadata of this agent's own log.
// The MeshCentral package serves the same bytes (meshcentral_core_module_parity_contract.js).
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'modules', 'util-agentlog.js'), 'utf8');

function parse(text) {
    const context = {
        module: { exports: {} }, Buffer, process: { execPath: '/usr/local/mesh/meshagent' },
        require(name) {
            if (name === 'MeshAgent') { return {}; }
            if (name === 'fs') {
                return { createReadStream() {
                    return { on(event, callback) { this.callback = callback; }, resume() { this.callback.call(this, Buffer.from(text)); }, removeAllListeners() {} };
                } };
            }
            throw new Error('unexpected require(' + name + ')');
        }
    };
    // The agent's Array.prototype.peek (Duktape polyfill).
    vm.runInNewContext('Array.prototype.peek = function () { return this.length ? this[this.length - 1] : null; };', context);
    vm.runInNewContext(source, context);
    return JSON.parse(JSON.stringify(context.module.exports.read(null, 'agent.log')));
}

const cases = {
    crashLinesBeforeAnyEntryAreIgnored() {
        const entries = parse('./meshagent(main+0x10) [0x7f0000001000]\n[core_dump_fedcba9876543210]\n/src/agentcore.c:42\n[a => file.c:7]\nbase=0x55aa00000000\n');
        assert.deepStrictEqual(entries, []);
    },
    twelveAmIsMidnightAndUnpaddedHoursParse() {
        const entries = parse('[2026-10-03 12:05:01 AM] [] a\n[2026-10-03 9:05:01 AM] [] b\n[2026-10-03 12:05:01 PM] [] c\n[2026-10-03 9:05:01 PM] [] d\n');
        assert.deepStrictEqual(entries.map((e) => e.t), ['00:05:01', '09:05:01', '12:05:01', '21:05:01'].map((t) => Math.floor(Date.parse('2026-10-03T' + t) / 1000)));
    },
    pieFramesBaseAndCrashId() {
        const entries = parse('[2026-10-03 07:48:55] [0123456789abcdef] crash\n' +
            'base=0x55aa00000000\n' +
            './meshagent(+0x12ab) [0x55aa000012ab]\n' +
            './meshagent(main+0x10) [0x55aa00003000]\n' +
            '/lib/x86_64-linux-gnu/libc.so.6(+0x2a1ca) [0x7f00002a1ca]\n' +
            './meshagent() [0x55aa00002000]\n' +
            '[core_dump_fedcba9876543210]\n' +
            '/src/agentcore.c:42\n');
        assert.strictEqual(entries.length, 1);
        assert.strictEqual(entries[0].h, 'fedcba9876543210');
        assert.strictEqual(entries[0].base, '0x55aa00000000');
        assert.deepStrictEqual(entries[0].sx, ['0x55aa00002000', '0x55aa00003000', '0x12ab'], 'file offset preferred, address as fallback, .so skipped');
        assert.deepStrictEqual(entries[0].s, ['/src/agentcore.c:42']);
    },
    forkMillisecondsAndMetadata() {
        const entries = parse('[2026-10-03 07:48:55.123] [pid=123 tid=456] [core] [] core.c:12 (1,2) [CONTROLCHANNEL_FAILURE] x\n');
        assert.strictEqual(entries.length, 1);
        assert.strictEqual(entries[0].t, Math.floor(Date.parse('2026-10-03T07:48:55.123') / 1000));
        assert.strictEqual(entries[0].pid, 123);
        assert.strictEqual(entries[0].tid, 456);
        assert.strictEqual(entries[0].component, 'core');
        assert.strictEqual(entries[0].f, 'core.c');
        assert.strictEqual(entries[0].l, '12');
        assert.strictEqual(entries[0].m, '[CONTROLCHANNEL_FAILURE] x');
    }
};

let failed = 0;
for (const name of Object.keys(cases)) {
    try { cases[name](); console.log('PASS ' + name); }
    catch (error) { failed += 1; console.log('FAIL ' + name + ': ' + (error && error.stack || error)); }
}
console.log('util_agentlog_contract: ' + (failed ? 'FAIL (' + failed + ' failed)' : 'PASS (' + Object.keys(cases).length + ' cases)'));
if (failed) { process.exitCode = 1; }
