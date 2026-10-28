'use strict';
// Feeds binary frames into the fork's viewer redirector (agent-redir-ws-0.1.1.js and its -min
// build) and checks what reaches the desktop module: whole frames pass through, a frame shorter
// than its 4-byte header is ignored, a frame split over several messages is reassembled into one
// command, and a jumbo frame (command 27) is unwrapped to its inner command with a 24-bit size, also
// when split. Both files must behave the same. No browser or server is used.
const assert = require('assert');
const vm = require('vm');
const { forkFile } = require('./lib/meshcentral_paths');
const { readSource, evidenceDirFromArgs, writeEvidence, runCases } = require('./lib/source_extract');

const assets = {
    standard: forkFile('public/scripts/agent-redir-ws-0.1.1.js'),
    minified: forkFile('public/scripts/agent-redir-ws-0.1.1-min.js')
};

function loadRedirect(filePath) {
    const sandbox = {
        console, Uint8Array, ArrayBuffer,
        window: { location: { protocol: 'https:', host: 'server.invalid', pathname: '/' } },
        navigator: { userAgent: 'contract' },
        setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {}
    };
    vm.createContext(sandbox);
    vm.runInContext(readSource(filePath, 'viewer redirector whose binary frame handling is driven'), sandbox, { filename: filePath });
    assert.strictEqual(typeof sandbox.CreateAgentRedirect, 'function', filePath + ' must define CreateAgentRedirect');
    return sandbox.CreateAgentRedirect;
}

function frame(cmd, payload) {
    const size = 4 + payload.length;
    assert(size <= 0xFFFF, 'frame() builds 16-bit frames only');
    return [cmd >> 8, cmd & 0xFF, size >> 8, size & 0xFF].concat(payload);
}

// Command 27 wraps a frame whose size needs 24 bits: [0,27,0,8, 0,s2,s1,s0] + inner frame.
function jumbo(cmd, payloadLength) {
    const size = 4 + payloadLength;
    const inner = [cmd >> 8, cmd & 0xFF, 0, 0];
    for (let i = 0; i < payloadLength; ++i) { inner.push(i & 0xFF); }
    return { bytes: [0, 27, 0, 8, 0, (size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF].concat(inner), inner, size };
}

function session(CreateAgentRedirect) {
    const received = [];
    const module = { protocol: 2, ProcessBinaryCommand(cmd, cmdsize, view) { received.push({ cmd, cmdsize, bytes: Array.from(view) }); } };
    const redirect = CreateAgentRedirect({}, module, null, null, null, '/');
    redirect.State = 3;
    const deliver = (bytes) => redirect.xxOnMessage({ data: new Uint8Array(bytes).buffer });
    return { received, deliver };
}

function casesFor(CreateAgentRedirect) {
    return {
        wholeFramePassesThrough() {
            const { received, deliver } = session(CreateAgentRedirect);
            const bytes = frame(3, [9, 8, 7, 6]);
            deliver(bytes);
            assert.deepStrictEqual(received, [{ cmd: 3, cmdsize: 8, bytes }]);
        },
        frameShorterThanHeaderIsIgnored() {
            const { received, deliver } = session(CreateAgentRedirect);
            deliver([0, 3, 0]);
            deliver(frame(5, [1]));
            assert.deepStrictEqual(received.map((r) => r.cmd), [5], 'the 3-byte message is dropped and the next frame still parses');
        },
        splitFrameIsReassembledOnce() {
            const { received, deliver } = session(CreateAgentRedirect);
            const bytes = frame(3, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
            deliver(bytes.slice(0, 6));
            assert.strictEqual(received.length, 0, 'nothing is dispatched before the frame is complete');
            deliver(bytes.slice(6, 12));
            deliver(bytes.slice(12));
            assert.deepStrictEqual(received, [{ cmd: 3, cmdsize: 14, bytes }]);
        },
        shortTailFragmentCompletesTheFrame() {
            const { received, deliver } = session(CreateAgentRedirect);
            const bytes = frame(4, [1, 2, 3, 4, 5, 6, 7, 8]);
            deliver(bytes.slice(0, 10));
            deliver(bytes.slice(10)); // 2 bytes: a continuation, not a frame of its own
            assert.deepStrictEqual(received, [{ cmd: 4, cmdsize: 12, bytes }]);
        },
        accumulatorResetsAfterReassembly() {
            const { received, deliver } = session(CreateAgentRedirect);
            const split = frame(3, [1, 2, 3, 4, 5, 6]);
            deliver(split.slice(0, 5));
            deliver(split.slice(5));
            deliver(frame(7, [0, 0, 1, 0, 2, 0]));
            assert.deepStrictEqual(received.map((r) => [r.cmd, r.cmdsize]), [[3, 10], [7, 10]]);
        },
        jumboFrameIsUnwrapped() {
            const { received, deliver } = session(CreateAgentRedirect);
            const big = jumbo(3, 70000);
            deliver(big.bytes);
            assert.strictEqual(received.length, 1);
            assert.strictEqual(received[0].cmd, 3, 'the inner command is dispatched, not 27');
            assert.strictEqual(received[0].cmdsize, big.size, 'the 24-bit size is used');
            assert.deepStrictEqual(received[0].bytes, big.inner, 'the 8-byte jumbo header is removed');
        },
        splitJumboFrameIsReassembled() {
            const { received, deliver } = session(CreateAgentRedirect);
            const big = jumbo(3, 70000);
            deliver(big.bytes.slice(0, 40000));
            deliver(big.bytes.slice(40000));
            assert.strictEqual(received.length, 1);
            assert.strictEqual(received[0].cmd, 3);
            assert.strictEqual(received[0].cmdsize, big.size);
            assert.deepStrictEqual(received[0].bytes, big.inner);
        }
    };
}

const report = { assets, results: {} };
let failed = 0;
for (const [name, filePath] of Object.entries(assets)) {
    const run = runCases('meshcentral_agent_redir_binary_frame_contract ' + name, casesFor(loadRedirect(filePath)));
    report.results[name] = run.results;
    failed += run.failed;
}
if (failed) { process.exitCode = 1; }

const evidenceDir = evidenceDirFromArgs(process.argv);
if (evidenceDir) {
    writeEvidence(evidenceDir, 'meshcentral_agent_redir_binary_frame_contract', report, [
        'REDIR_PATH=' + assets.standard,
        'REDIR_MIN_PATH=' + assets.minified,
        'SUCCESS=' + (failed === 0)
    ]);
}
