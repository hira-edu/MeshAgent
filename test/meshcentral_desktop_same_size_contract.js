'use strict';
// Drives the fork's remote desktop viewer (agent-desktop-0.0.2.js and its -min build) in a vm and
// checks that a screen-size command (7) for the size already shown is handled as a new stream, not
// ignored: the agent sends one when capture restarts. Every screen command must reset the draw
// queue (tiles from before it are dropped), re-send compression, unpause and the input-lock query,
// and fire onScreenSizeChange. No browser or agent is used.
const assert = require('assert');
const vm = require('vm');
const { forkFile } = require('./lib/meshcentral_paths');
const { readSource, evidenceDirFromArgs, writeEvidence, runCases } = require('./lib/source_extract');

const assets = {
    standard: forkFile('public/scripts/agent-desktop-0.0.2.js'),
    minified: forkFile('public/scripts/agent-desktop-0.0.2-min.js')
};

function loadDesktop(filePath) {
    const sandbox = {
        console, Uint8Array, ArrayBuffer, String, Object, Math, JSON,
        navigator: { platform: 'Linux x86_64', userAgent: 'contract' },
        window: {}, document: {},
        setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {},
        btoa: (text) => Buffer.from(text, 'binary').toString('base64'),
        Image: function () {}
    };
    vm.createContext(sandbox);
    vm.runInContext(readSource(filePath, 'remote desktop viewer whose screen-size handling is driven'), sandbox, { filename: filePath });
    assert.strictEqual(typeof sandbox.CreateAgentRemoteDesktop, 'function', filePath + ' must define CreateAgentRemoteDesktop');
    return sandbox.CreateAgentRemoteDesktop;
}

function viewer(CreateAgentRemoteDesktop) {
    const context = { setTransform() {}, clearRect() {}, drawImage() {}, fillRect() {}, putImageData() {} };
    const canvas = { width: 0, height: 0, style: {}, getContext: () => context };
    const desk = CreateAgentRemoteDesktop(canvas);
    const sent = [];
    const resizes = [];
    desk.parent = { State: 3, send(data) { sent.push(data); }, xxStateChange() {} };
    desk.onScreenSizeChange = (obj, width, height) => resizes.push([width, height]);
    desk.onResize = () => {};
    desk.State = 3;
    return { desk, sent, resizes };
}

// Command 7, screen size: [0,7,0,8, w>>8, w, h>>8, h].
function screen(desk, width, height) {
    const view = new Uint8Array([0, 7, 0, 8, width >> 8, width & 0xFF, height >> 8, height & 0xFF]);
    desk.ProcessBinaryCommand(7, 8, view);
}

const bytes = (text) => Array.from(text, (ch) => ch.charCodeAt(0));
const UNPAUSE = [0x00, 0x08, 0x00, 0x05, 0x00];
const INPUT_LOCK_QUERY = [0x00, 87, 0x00, 0x05, 2];

function casesFor(CreateAgentRemoteDesktop) {
    return {
        firstScreenSetsSizeAndStartsStream() {
            const { desk, sent, resizes } = viewer(CreateAgentRemoteDesktop);
            screen(desk, 1280, 720);
            assert.strictEqual(desk.ScreenWidth, 1280);
            assert.strictEqual(desk.ScreenHeight, 720);
            assert.deepStrictEqual(resizes, [[1280, 720]]);
            const packets = sent.map(bytes);
            assert(packets.some((p) => p[1] === 0x05 && p[3] === 0x0A), 'compression is sent');
            assert(packets.some((p) => p.join() === UNPAUSE.join()), 'unpause is sent');
            assert(packets.some((p) => p.join() === INPUT_LOCK_QUERY.join()), 'the input-lock state is queried');
        },
        sameSizeScreenRestartsTheStream() {
            const { desk, sent, resizes } = viewer(CreateAgentRemoteDesktop);
            screen(desk, 1280, 720);
            sent.length = 0;
            resizes.length = 0;
            desk.PendingOperations.push([5, 2, {}, 0, 0]); // a tile decoded before the restart
            desk.tilesReceived = 7;
            desk.TilesDrawn = 2;
            const generation = desk.drawGeneration;
            screen(desk, 1280, 720);
            assert.strictEqual(desk.PendingOperations.length, 0, 'tiles queued before the restart are dropped');
            assert.strictEqual(desk.tilesReceived, 0, 'the tile counter restarts');
            assert.strictEqual(desk.TilesDrawn, 0, 'the drawn counter restarts');
            assert(desk.drawGeneration > generation, 'tiles still decoding from before the restart are discarded');
            const packets = sent.map(bytes);
            assert(packets.some((p) => p[1] === 0x05 && p[3] === 0x0A), 'compression is re-sent');
            assert(packets.some((p) => p.join() === UNPAUSE.join()), 'unpause is re-sent');
            assert(packets.some((p) => p.join() === INPUT_LOCK_QUERY.join()), 'the input-lock state is queried again');
            assert.deepStrictEqual(resizes, [[1280, 720]], 'the size change is evented for the same size too');
        },
        newSizeIsApplied() {
            const { desk, resizes } = viewer(CreateAgentRemoteDesktop);
            screen(desk, 1280, 720);
            screen(desk, 1920, 1080);
            assert.strictEqual(desk.ScreenWidth, 1920);
            assert.strictEqual(desk.ScreenHeight, 1080);
            assert.strictEqual(desk.width, 1920);
            assert.strictEqual(desk.height, 1080);
            assert.deepStrictEqual(resizes, [[1280, 720], [1920, 1080]]);
        }
    };
}

const report = { assets, results: {} };
let failed = 0;
for (const [name, filePath] of Object.entries(assets)) {
    const run = runCases('meshcentral_desktop_same_size_contract ' + name, casesFor(loadDesktop(filePath)));
    report.results[name] = run.results;
    failed += run.failed;
}
if (failed) { process.exitCode = 1; }

const evidenceDir = evidenceDirFromArgs(process.argv);
if (evidenceDir) {
    writeEvidence(evidenceDir, 'meshcentral_desktop_same_size_contract', report, [
        'DESKTOP_PATH=' + assets.standard,
        'DESKTOP_MIN_PATH=' + assets.minified,
        'SUCCESS=' + (failed === 0)
    ]);
}
