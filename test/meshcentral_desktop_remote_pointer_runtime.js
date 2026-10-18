// Check the viewer's remote-pixel pointer API (SendRemotePointer, SendRemoteWheel,
// ReleaseAllPointerButtons, GetRemoteGeometry) packet by packet, on both agent-desktop assets,
// and drive it from the trackpad engine as an adapter would. No endpoint connection or OS input
// is used.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const scriptsDir = path.resolve(__dirname, '../../MeshCentral/public/scripts');

function hex(packet) { return packet.map(b => b.toString(16).padStart(2, '0')).join(''); }

function createClock() {
    const clock = { now: 1000000, timers: [], nextId: 1 };
    clock.setTimeout = (fn, ms) => { const id = clock.nextId++; clock.timers.push({ id, fn, at: clock.now + (ms || 0) }); return id; };
    clock.clearTimeout = id => { clock.timers = clock.timers.filter(t => t.id !== id); };
    clock.advance = ms => {
        const end = clock.now + ms;
        for (;;) {
            const due = clock.timers.filter(t => t.at <= end).sort((a, b) => (a.at - b.at) || (a.id - b.id))[0];
            if (!due) break;
            clock.now = due.at;
            clock.timers = clock.timers.filter(t => t !== due);
            due.fn();
        }
        clock.now = end;
    };
    return clock;
}

function scratchCanvas() {
    const c = { width: 0, height: 0 };
    c.getContext = () => ({ canvas: c, setTransform() {}, rotate() {}, drawImage() {} });
    return c;
}

// 800x600 remote shown at 400x300 CSS px.
function viewer(asset) {
    const source = fs.readFileSync(path.join(scriptsDir, asset), 'utf8');
    const canvas = { width: 800, height: 600, clientWidth: 400, clientHeight: 300, style: {}, offsetLeft: 0, offsetTop: 0 };
    canvas.getContext = () => ({ canvas, setTransform() {}, clearRect() {}, rotate() {}, fillRect() {}, drawImage() {} });
    const context = vm.createContext({ navigator: { platform: 'Win32', userAgent: 'test' }, window: {}, document: { createElement: scratchCanvas }, desktop: { State: 3 }, urlargs: {}, ShortToStr: x => String.fromCharCode(x >> 8, x & 255), console, Uint8Array, setTimeout, clearTimeout });
    vm.runInContext(source, context);
    const v = context.CreateAgentRemoteDesktop(canvas, null);
    const sink = { packets: [] };
    v.parent = { State: 2, send(p) { sink.packets.push(Array.from(p, c => c.charCodeAt(0))); }, xxStateChange(s) { this.State = s; v.xxStateChange(s); } };
    v.Start();
    v.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 800 >> 8, 800 & 255, 600 >> 8, 600 & 255]));
    return { v, canvas, record: fn => { sink.packets = []; fn(); return sink.packets.filter(p => ((p[0] << 8) | p[1]) === 2); }, all: fn => { sink.packets = []; fn(); return sink.packets; } };
}

const plain = o => JSON.parse(JSON.stringify(o));
const mouse = (button, x, y) => hex([0, 2, 0, 10, 0, button, x >> 8, x & 255, y >> 8, y & 255]);
const wheel = (x, y, d) => hex([0, 2, 0, 12, 0, 0, x >> 8, x & 255, y >> 8, y & 255, (d >> 8) & 255, d & 255]);

const cases = [];
function test(name, fn) { cases.push({ name, fn }); }

test('moves are sent once per new position', a => {
    const h = viewer(a);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 0)).map(hex), [mouse(0, 10, 20)]);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 0)).map(hex), [], 'same position, no packet');
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10.6, 20.4, 0)).map(hex), [mouse(0, 11, 20)], 'rounded to remote pixels');
});

test('button changes carry the position and need no separate move', a => {
    const h = viewer(a);
    assert.deepStrictEqual(h.record(() => { h.v.SendRemotePointer(10, 20, 1); h.v.SendRemotePointer(30, 20, 1); h.v.SendRemotePointer(30, 40, 0); }).map(hex),
        [mouse(2, 10, 20), mouse(0, 30, 20), mouse(4, 30, 40)]);
    assert.deepStrictEqual(h.record(() => { h.v.SendRemotePointer(5, 5, 2); h.v.SendRemotePointer(5, 5, 0); h.v.SendRemotePointer(6, 6, 4); h.v.SendRemotePointer(6, 6, 0); }).map(hex),
        [mouse(8, 5, 5), mouse(16, 5, 5), mouse(32, 6, 6), mouse(64, 6, 6)]);
});

test('a button swap releases first, then presses', a => {
    const h = viewer(a);
    h.v.SendRemotePointer(10, 20, 1);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 2)).map(hex), [mouse(4, 10, 20), mouse(8, 10, 20)]);
});

test('coordinates are clamped to the remote screen', a => {
    const h = viewer(a);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(-5, 9999, 0)).map(hex), [mouse(0, 0, 599)]);
});

test('every send is one command per message', a => {
    const h = viewer(a);
    const packets = h.all(() => { h.v.SendRemotePointer(1, 1, 1); h.v.SendRemotePointer(2, 2, 3); h.v.SendRemotePointer(3, 3, 0); h.v.SendRemoteWheel(3, 3, 3); });
    assert(packets.every(p => p.length === ((p[2] << 8) | p[3])), 'each message holds exactly the command its header announces');
});

test('the swap-buttons setting applies to remote pointer buttons', a => {
    const h = viewer(a);
    h.v.SwapMouse = true;
    assert.deepStrictEqual(h.record(() => { h.v.SendRemotePointer(1, 1, 1); h.v.SendRemotePointer(1, 1, 0); }).map(hex), [mouse(8, 1, 1), mouse(16, 1, 1)]);
});

test('pressed buttons are shared with the browser mouse path', a => {
    const h = viewer(a);
    h.v.SendRemotePointer(10, 20, 1);
    assert(h.v.browserPressedButtons[1], 'left is recorded as pressed');
    // A browser mouseup for that button is now a matched release.
    assert.deepStrictEqual(h.record(() => h.v.mouseup({ pageX: 5, pageY: 10, which: 1, button: 0 })).map(hex), [mouse(4, 10, 20)]);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 0)).map(hex), [], 'no second release');
});

test('the mask is the whole truth: a button another path left pressed is released', a => {
    const h = viewer(a);
    h.v.mousedown({ pageX: 5, pageY: 10, which: 3, button: 2 });
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(31, 40, 1)).map(hex), [mouse(16, 31, 40), mouse(2, 31, 40)]);
    assert.deepStrictEqual(Object.keys(h.v.browserPressedButtons), ['1']);
});

test('ReleaseAllPointerButtons releases whatever path pressed, at the last remote position', a => {
    let h = viewer(a);
    h.v.SendRemotePointer(31, 40, 1);
    h.v.mousedown({ pageX: 5, pageY: 10, which: 3, button: 2 });
    assert.deepStrictEqual(h.record(() => h.v.ReleaseAllPointerButtons()).map(hex), [mouse(4, 31, 40), mouse(16, 31, 40)]);
    assert.deepStrictEqual(Object.keys(h.v.browserPressedButtons), []);
    assert.deepStrictEqual(h.record(() => h.v.ReleaseAllPointerButtons()).map(hex), [], 'nothing left to release');
    h = viewer(a);
    h.v.mousedown({ pageX: 5, pageY: 10, which: 1, button: 0 });
    assert.deepStrictEqual(h.record(() => h.v.ReleaseAllPointerButtons()).map(hex), [mouse(4, 400, 300)], 'screen centre when no remote position is known');
});

test('view-only and disconnected viewers send nothing', a => {
    let h = viewer(a);
    h.v.stopInput = true;
    assert.deepStrictEqual(h.record(() => { h.v.SendRemotePointer(1, 1, 1); h.v.SendRemoteWheel(1, 1, 1); h.v.ReleaseAllPointerButtons(); }), []);
    h = viewer(a);
    h.v.SendRemotePointer(1, 1, 1);
    h.v.State = 2;
    assert.deepStrictEqual(h.record(() => { h.v.SendRemotePointer(2, 2, 0); h.v.SendRemoteWheel(1, 1, 1); h.v.ReleaseAllPointerButtons(); }), []);
    assert.deepStrictEqual(Object.keys(h.v.browserPressedButtons), [], 'the release is recorded even when it cannot be sent');
});

test('wheel sends one correctly signed packet per notch', a => {
    const h = viewer(a);
    assert.deepStrictEqual(h.record(() => h.v.SendRemoteWheel(10, 20, 2)).map(hex), [wheel(10, 20, 120), wheel(10, 20, 120)]);
    assert.deepStrictEqual(h.record(() => h.v.SendRemoteWheel(10, 20, -1)).map(hex), [wheel(10, 20, -120)]);
    assert.strictEqual(wheel(10, 20, -120).slice(-4), 'ff88', 'two\'s complement, not the browser path\'s ff87');
    h.v.ReverseMouseWheel = true;
    assert.deepStrictEqual(h.record(() => h.v.SendRemoteWheel(10, 20, 1)).map(hex), [wheel(10, 20, -120)]);
    h.v.ReverseMouseWheel = false;
    assert.deepStrictEqual(h.record(() => { h.v.SendRemoteWheel(10, 20, 0); h.v.SendRemoteWheel(10, 20, NaN); }), []);
    assert.strictEqual(h.record(() => h.v.SendRemoteWheel(10, 20, 1000)).length, 100, 'bounded per call');
});

test('geometry maps CSS and remote pixels both ways in every rotation', a => {
    const h = viewer(a);
    let g = h.v.GetRemoteGeometry();
    assert.deepStrictEqual([g.width, g.height, g.rotation, g.remotePerCss], [800, 600, 0, 2]);
    assert.deepStrictEqual(plain(g.cssToRemote(100, 50)), { x: 200, y: 100 });
    assert.deepStrictEqual(plain(g.remoteToCss(200, 100)), { x: 100, y: 50 });
    for (const rotation of [1, 2, 3]) {
        h.v.setRotation(rotation);
        // A rotated view swaps the canvas; the page resizes it to keep 2 remote px per CSS px.
        h.canvas.clientWidth = h.canvas.width / 2; h.canvas.clientHeight = h.canvas.height / 2;
        g = h.v.GetRemoteGeometry();
        assert.deepStrictEqual([g.width, g.height, g.rotation, g.remotePerCss], [800, 600, rotation, 2], `rotation ${rotation}: remote size and scale`);
        for (const [x, y] of [[0, 0], [123, 45], [799, 599], [400, 300]]) {
            const css = g.remoteToCss(x, y), back = g.cssToRemote(css.x, css.y);
            assert.deepStrictEqual([Math.round(back.x), Math.round(back.y)], [x, y], `rotation ${rotation}: (${x},${y}) round trip`);
        }
        // CSS (10, 20) is canvas pixel (20, 40) on the rotated canvas.
        const expected = { 1: { x: 40, y: 580 }, 2: { x: 780, y: 560 }, 3: { x: 760, y: 20 } }[rotation];
        assert.deepStrictEqual(plain(g.cssToRemote(10, 20)), expected, `rotation ${rotation}: CSS to remote`);
    }
    h.v.setRotation(0);
});

test('Stop and Start forget the last remote position', a => {
    const h = viewer(a);
    h.v.SendRemotePointer(10, 20, 0);
    h.v.Stop(); h.v.Start();
    assert.strictEqual(h.v.remotePointerLast, null);
});

test('two viewer instances keep their own buttons (WebRTC soft desktop)', a => {
    const one = viewer(a), two = viewer(a);
    one.v.SendRemotePointer(10, 10, 1);
    assert.deepStrictEqual(two.record(() => two.v.ReleaseAllPointerButtons()), []);
    assert.deepStrictEqual(one.record(() => one.v.ReleaseAllPointerButtons()).map(hex), [mouse(4, 10, 10)]);
});

test('senders report whether they sent, and refuse non-finite input', a => {
    const h = viewer(a);
    assert.strictEqual(h.v.SendRemotePointer(10, 20, 0), true);
    for (const args of [[NaN, 1, 0], [1, undefined, 0], [1, 1, NaN], ['x', 1, 0], [Infinity, 1, 0]]) {
        assert.deepStrictEqual(h.record(() => assert.strictEqual(h.v.SendRemotePointer(...args), false)), [], `pointer ${args}`);
    }
    for (const args of [[NaN, 1, 1], [1, 'y', 1], [1, 1, Infinity]]) {
        assert.deepStrictEqual(h.record(() => assert.strictEqual(h.v.SendRemoteWheel(...args), false)), [], `wheel ${args}`);
    }
    assert.deepStrictEqual(plain(h.v.remotePointerLast), { x: 10, y: 20 }, 'rejected input leaves the last position alone');
    assert.deepStrictEqual(Object.keys(h.v.browserPressedButtons), []);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 9)).map(hex), [mouse(2, 10, 20)], 'unknown mask bits are ignored');
    h.v.stopInput = true;
    assert.strictEqual(h.v.SendRemotePointer(1, 1, 0), false);
});

test('switching viewer instances mid-drag: release on the outgoing one first', a => {
    const outgoing = viewer(a), incoming = viewer(a);
    outgoing.v.SendRemotePointer(100, 100, 1);
    // The soft desktop's own bookkeeping knows nothing of the press...
    assert.deepStrictEqual(incoming.record(() => incoming.v.ReleaseAllPointerButtons()), []);
    // ...so the adapter releases on the outgoing instance, then continues on the new one.
    assert.deepStrictEqual(outgoing.record(() => outgoing.v.ReleaseAllPointerButtons()).map(hex), [mouse(4, 100, 100)]);
    assert.deepStrictEqual(incoming.record(() => incoming.v.SendRemotePointer(110, 100, 0)).map(hex), [mouse(0, 110, 100)]);
});

test('a release blocked only by view-only is kept, then sent once allowed', a => {
    const h = viewer(a);
    h.v.SendRemotePointer(10, 20, 1);
    h.v.stopInput = true;
    assert.deepStrictEqual(h.record(() => assert.strictEqual(h.v.ReleaseAllPointerButtons(), false)), []);
    assert(h.v.browserPressedButtons[1], 'still recorded');
    h.v.stopInput = false;
    assert.deepStrictEqual(h.record(() => assert.strictEqual(h.v.ReleaseAllPointerButtons(), true)).map(hex), [mouse(4, 10, 20)]);
});

test('a disconnected viewer drops the bookkeeping without sending', a => {
    const h = viewer(a);
    h.v.mousedown({ pageX: 5, pageY: 10, which: 1, button: 0 });
    h.v.State = 0;
    assert.deepStrictEqual(h.record(() => assert.strictEqual(h.v.ReleaseAllPointerButtons(), false)), []);
    assert.deepStrictEqual(Object.keys(h.v.browserPressedButtons), []);
});

test('changing SwapMouse while a button is held releases the button that was pressed', a => {
    const h = viewer(a);
    h.v.SwapMouse = true;
    h.v.SendRemotePointer(10, 20, 1);
    h.v.SwapMouse = false;
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(10, 20, 0)).map(hex), [mouse(16, 10, 20)], 'the remote right button, as pressed');
    h.v.SwapMouse = true;
    h.v.SendRemotePointer(10, 20, 1);
    h.v.SwapMouse = false;
    assert.deepStrictEqual(h.record(() => h.v.ReleaseAllPointerButtons()).map(hex), [mouse(16, 10, 20)]);
});

test('per-axis scale follows the remote axes when the canvas is stretched', a => {
    const h = viewer(a);
    h.canvas.clientWidth = 400; h.canvas.clientHeight = 600;
    let g = h.v.GetRemoteGeometry();
    assert.deepStrictEqual([g.remotePerCss, g.remotePerCssX, g.remotePerCssY], [2, 2, 1]);
    h.v.setRotation(1);
    h.canvas.clientWidth = 300; h.canvas.clientHeight = 800;
    g = h.v.GetRemoteGeometry();
    // Rotated: the canvas is 600x800; displayed X (2 px/CSS) runs along remote Y, displayed Y (1) along remote X.
    assert.deepStrictEqual([g.remotePerCss, g.remotePerCssX, g.remotePerCssY], [2, 1, 2]);
    h.v.setRotation(0);
});

test('the API works in SCREEN pixels: a smaller or reset screen clamps', a => {
    const h = viewer(a);
    h.v.SendRemotePointer(700, 500, 1);
    h.v.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 640 >> 8, 640 & 255, 480 >> 8, 480 & 255]));
    assert(h.v.browserPressedButtons[1], 'a screen reset keeps the press');
    assert.deepStrictEqual(h.record(() => h.v.ReleaseAllPointerButtons()).map(hex), [mouse(4, 639, 479)]);
    assert.deepStrictEqual(h.record(() => h.v.SendRemotePointer(5000, 5000, 0)).map(hex), [mouse(0, 639, 479)]);
    assert.deepStrictEqual(h.record(() => h.v.SendRemoteWheel(-9, 9999, 1)).map(hex), [wheel(0, 479, 120)]);
    assert.deepStrictEqual(plain(h.v.remotePointerLast), { x: 0, y: 479 }, 'a wheel updates the last position');
});

test('wheel notch rounding and the per-call bound', a => {
    const h = viewer(a);
    assert.strictEqual(h.record(() => h.v.SendRemoteWheel(1, 1, 0.4)).length, 0);
    assert.strictEqual(h.record(() => h.v.SendRemoteWheel(1, 1, 0.6)).length, 1);
    assert.strictEqual(h.record(() => h.v.SendRemoteWheel(1, 1, 100)).length, 100);
    assert.strictEqual(h.record(() => h.v.SendRemoteWheel(1, 1, -101)).length, 100);
});

test('trackpad engine gestures become the expected packets', a => {
    const h = viewer(a);
    const enginecontext = vm.createContext({ Math, Object });
    vm.runInContext(fs.readFileSync(path.join(scriptsDir, 'agent-desktop-trackpad-0.0.1.js'), 'utf8'), enginecontext);
    const clock = createClock();
    const engine = enginecontext.MeshTrackpadEngine.create({
        clock: { now: () => clock.now, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout },
        geometry: () => h.v.GetRemoteGeometry(),
        output: { pointer: (x, y, b) => h.v.SendRemotePointer(x, y, b), wheel: (x, y, n) => h.v.SendRemoteWheel(x, y, n), zoom() {}, pinchSupported: () => false }
    });
    const t = list => list.map(([id, x, y]) => ({ id, x, y }));
    const packets = h.record(() => {
        engine.setCursor(400, 300);
        engine.touchStart(t([[1, 100, 100]])); clock.advance(50); engine.touchEnd([]); clock.advance(100);
        engine.touchStart(t([[1, 100, 100]])); clock.advance(50); engine.touchEnd([]); clock.advance(1000);
        engine.touchStart(t([[1, 100, 100], [2, 140, 100]])); clock.advance(50); engine.touchEnd([]); clock.advance(1000);
        engine.touchStart(t([[1, 100, 200], [2, 140, 200]])); engine.touchMove(t([[1, 100, 140], [2, 140, 140]])); engine.touchEnd([]);
    }).map(hex);
    assert.deepStrictEqual(packets, [
        mouse(0, 400, 300),
        mouse(2, 400, 300), mouse(4, 400, 300), mouse(2, 400, 300), mouse(4, 400, 300),
        mouse(8, 400, 300), mouse(16, 400, 300),
        wheel(400, 300, -120), wheel(400, 300, -120)
    ]);
    // Teardown mid-drag through the API releases on the wire.
    engine.touchStart(t([[1, 100, 100]])); engine.touchEnd([]); clock.advance(100);
    engine.touchStart(t([[1, 100, 100]])); engine.touchMove(t([[1, 140, 100]]));
    assert(h.v.browserPressedButtons[1]);
    const released = h.record(() => { engine.reset(); h.v.ReleaseAllPointerButtons(); }).map(hex);
    assert.strictEqual(released.length, 1, 'exactly one release, from the engine; ReleaseAll finds nothing left');
    assert.strictEqual(released[0].slice(10, 12), '04');
});

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/viewer-remote-pointer/current');
    const results = [];
    for (const asset of ['agent-desktop-0.0.2.js', 'agent-desktop-0.0.2-min.js']) {
        for (const c of cases) {
            try { c.fn(asset); results.push({ asset, name: c.name, ok: true }); } catch (error) { results.push({ asset, name: c.name, ok: false, error: error.message }); }
        }
    }
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(results, null, 2));
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.asset} ${r.name}${r.ok ? '' : ': ' + r.error}`);
    if (results.some(r => !r.ok)) process.exitCode = 1;
}

main();
