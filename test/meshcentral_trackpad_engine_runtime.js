// Exercise the trackpad gesture engine (MeshCentral public/scripts/agent-desktop-trackpad-0.0.1.js)
// with a fake clock: one table test per gesture and disambiguation rule, threshold edges, finger
// transitions, cancellation in every state, and a randomized check that every press is released.
// No DOM, endpoint connection or OS input is used.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const enginePath = path.resolve(__dirname, '../../MeshCentral/public/scripts/agent-desktop-trackpad-0.0.1.js');

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

const context = vm.createContext({ Math, Object });
vm.runInContext(fs.readFileSync(enginePath, 'utf8'), context);
const Engine = context.MeshTrackpadEngine;

// 800x600 remote shown at 400x300 CSS px, so remotePerCss is 2. The cursor starts at the centre.
function harness(options) {
    options = options || {};
    const clock = createClock();
    const events = [];
    const geom = { width: 800, height: 600, remotePerCss: 2 };
    let pinch = !!options.pinch;
    let geometry = () => geom;
    const hook = options.onEvent || (() => {});
    let engine = null;
    engine = Engine.create({
        clock: { now: () => clock.now, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout },
        geometry: () => geometry(),
        output: {
            pointer: (x, y, b) => { events.push(['p', x, y, b]); hook(engine, ['p', x, y, b]); },
            wheel: (x, y, n) => { events.push(['w', x, y, n]); hook(engine, ['w', x, y, n]); },
            zoom: (r, x, y) => { events.push(['z', Math.round(r * 1000) / 1000, x, y]); hook(engine, ['z']); },
            pinchSupported: () => pinch
        },
        config: options.config
    });
    engine.setCursor(400, 300);
    events.length = 0;
    const t = list => list.map(([id, x, y]) => ({ id, x, y }));
    return {
        engine, clock, events, geom,
        start: list => engine.touchStart(t(list)),
        move: list => engine.touchMove(t(list)),
        end: list => engine.touchEnd(t(list || [])),
        advance: ms => clock.advance(ms),
        setPinch: v => { pinch = v; },
        setGeometry: fn => { geometry = fn; },
        buttons: () => events.filter(e => e[0] === 'p').map(e => e[3])
    };
}

const cases = [];
function test(name, fn) { cases.push({ name, fn }); }

// Tap = left click at the cursor; the release follows after the click-release delay.
test('tap clicks left at the cursor after the release delay', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end();
    assert.deepStrictEqual(h.events, [['p', 400, 300, 1]]);
    h.advance(249);
    assert.deepStrictEqual(h.events.length, 1, 'release must wait the full delay');
    h.advance(1);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 1], ['p', 400, 300, 0]]);
});

test('tap timing edge: 250 ms is a tap, 251 ms is not', () => {
    let h = harness(); h.start([[1, 100, 100]]); h.advance(250); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [1, 0]);
    h = harness(); h.start([[1, 100, 100]]); h.advance(251); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, []);
});

test('tap slop edge: 10 CSS px displacement is a tap, 10.8 is not, and a tap snaps back', () => {
    let h = harness(); h.start([[1, 100, 100]]); h.move([[1, 106, 108]]); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events.filter(e => e[3] !== 0 || e === h.events[h.events.length - 1]).slice(-2), [['p', 400, 300, 1], ['p', 400, 300, 0]], 'tap must click at the cursor position where the touch began');
    h = harness(); h.start([[1, 100, 100]]); h.move([[1, 106, 109]]); h.end(); h.advance(1000);
    assert(h.buttons().every(b => b === 0), 'a displacement beyond the slop must not click');
});

test('jitter below the slop does not cancel a tap (accumulated path is not used)', () => {
    const h = harness();
    h.start([[1, 100, 100]]);
    for (let i = 0; i < 10; i++) h.move([[1, 100 + (i % 2) * 3, 100]]);
    h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons().filter(b => b !== 0), [1]);
});

test('one-finger drag moves the cursor with Guacamole acceleration', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(100); h.move([[1, 110, 100]]);
    // velocity 10 px / 100 ms = 0.1, gain 1.1, remote 10 * 1.1 * 2 = 22
    assert.deepStrictEqual(h.events, [['p', 422, 300, 0]]);
    h.advance(100); h.move([[1, 110, 120]]);
    // velocity 30 / 200 = 0.15, gain 1.15, remote 20 * 1.15 * 2 = 46
    assert.deepStrictEqual(h.events[1], ['p', 422, 346, 0]);
    h.end(); h.advance(1000);
    assert.strictEqual(h.events.length, 2, 'a drag is not a click');
});

test('each axis moves by its own scale when the canvas is stretched', () => {
    const h = harness();
    h.setGeometry(() => ({ width: 800, height: 600, remotePerCss: 2, remotePerCssX: 2, remotePerCssY: 1 }));
    h.start([[1, 100, 100]]); h.advance(100); h.move([[1, 110, 110]]);
    // gain 1 + 20/100 = 1.2: x 10 * 1.2 * 2 = 24, y 10 * 1.2 * 1 = 12.
    assert.deepStrictEqual(h.events, [['p', 424, 312, 0]]);
    h.setGeometry(() => ({ width: 800, height: 600, remotePerCss: 2, remotePerCssY: 0 }));
    h.advance(100); h.move([[1, 120, 120]]);
    assert.strictEqual(h.events.length, 2, 'an unusable axis scale falls back to remotePerCss');
});

test('cursor is clamped to the remote screen', () => {
    const h = harness();
    h.engine.setCursor(798, 598); h.events.length = 0;
    h.start([[1, 100, 100]]); h.advance(100); h.move([[1, 140, 140]]);
    assert.deepStrictEqual(h.events, [['p', 799, 599, 0]]);
    h.move([[1, 160, 160]]);
    assert.strictEqual(h.events.length, 1, 'no duplicate emit at the edge');
});

test('two taps make a double click at identical coordinates', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end();
    h.advance(100);
    // The second tap jitters below the slop, which moves the cursor; the click must still land on the first.
    h.start([[1, 104, 103]]); h.advance(20); h.move([[1, 108, 103]]); h.advance(30); h.end();
    h.advance(1000);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 1], ['p', 400, 300, 0], ['p', 400, 300, 1], ['p', 400, 300, 0]], 'no drag while the first click is held');
});

test('a second tap after the release delay is a separate click', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end();
    h.advance(251);
    h.start([[1, 100, 100]]); h.advance(50); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [1, 0, 1, 0]);
    assert(h.events[1][0] === 'p' && h.events[1][3] === 0, 'the first click must be released before the second touch');
});

test('tap then touch-and-drag is one left drag', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end();
    h.advance(100);
    h.start([[1, 100, 100]]); h.advance(50); h.move([[1, 130, 100]]); h.move([[1, 160, 100]]);
    const during = h.buttons();
    assert.deepStrictEqual(during, [1, 1, 1], 'the button stays down through the drag');
    h.advance(2000);
    assert.strictEqual(h.engine.getButtons(), 1, 'the release timer must not fire while dragging');
    h.end();
    assert.deepStrictEqual(h.buttons(), [1, 1, 1, 0]);
});

test('long press then lift is a right click; a long press does not run during tap-and-a-half', () => {
    let h = harness();
    h.start([[1, 100, 100]]); h.advance(500); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 2], ['p', 400, 300, 0]]);
    h = harness();
    h.start([[1, 100, 100]]); h.advance(499); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, [], 'a 499 ms hold is neither a tap nor a long press');
    h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end(); h.advance(100);
    h.start([[1, 100, 100]]); h.advance(800); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [1, 0], 'tap then hold is one long left click, never a right click');
});

test('moving after a long press cancels the right click', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(600); h.move([[1, 130, 100]]); h.end(); h.advance(1000);
    assert(h.buttons().every(b => b === 0));
});

test('two-finger tap is a right click, even when the fingers lift separately', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.start([[1, 100, 100], [2, 140, 100]]); h.advance(60);
    h.end([[2, 140, 100]]); h.advance(20); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 2], ['p', 400, 300, 0]]);
});

test('three-finger tap is a middle click; four fingers do nothing', () => {
    let h = harness();
    h.start([[1, 100, 100], [2, 140, 100], [3, 180, 100]]); h.advance(80); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 4], ['p', 400, 300, 0]]);
    h = harness();
    h.start([[1, 100, 100], [2, 140, 100], [3, 180, 100], [4, 220, 100]]); h.advance(80); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, []);
});

test('two-finger parallel drag scrolls, carrying the remainder between steps', () => {
    const h = harness();
    h.start([[1, 100, 200], [2, 140, 200]]);
    h.move([[1, 100, 185], [2, 140, 185]]);
    h.move([[1, 100, 170], [2, 140, 170]]);
    assert.deepStrictEqual(h.events, [['w', 400, 300, -1]], 'fingers moving up 30 CSS px are one notch, signed like the upstream view');
    h.move([[1, 100, 95], [2, 140, 95]]);
    assert.deepStrictEqual(h.events[1], ['w', 400, 300, -2], 'a 75 px jump is two notches with 15 px carried, none lost');
    // 45 px down against the 15 px carried up nets 30 px: exactly one notch down.
    h.move([[1, 100, 140], [2, 140, 140]]);
    assert.deepStrictEqual(h.events[2], ['w', 400, 300, 1]);
    h.move([[1, 100, 210], [2, 140, 210]]);
    assert.deepStrictEqual(h.events[3], ['w', 400, 300, 2], 'a 70 px jump down is two notches with 10 px carried');
    h.end(); h.advance(1000);
    assert.strictEqual(h.events.filter(e => e[0] === 'p').length, 0, 'a scroll is not a click');
});

test('pinch zooms only when the adapter supports it and never moves or clicks', () => {
    let h = harness({ pinch: true });
    h.start([[1, 100, 150], [2, 200, 150]]);
    h.move([[1, 80, 150], [2, 220, 150]]);
    h.move([[1, 60, 150], [2, 240, 150]]);
    h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, [['z', 1.4, 150, 150], ['z', 1.286, 150, 150]]);
    h = harness({ pinch: false });
    h.start([[1, 100, 150], [2, 200, 150]]);
    h.move([[1, 60, 150], [2, 240, 150]]);
    h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, []);
});

test('pinch with one finger still (Chromium rule) is a pinch, not a scroll', () => {
    const h = harness({ pinch: true });
    h.start([[1, 100, 150], [2, 200, 150]]);
    h.move([[1, 100, 150], [2, 210, 150]]);
    assert.deepStrictEqual(h.events, [], 'inside 2x slop the gesture is still unknown');
    h.move([[1, 100, 150], [2, 220, 150]]);
    assert.strictEqual(h.events.length, 1);
    assert.strictEqual(h.events[0][0], 'z');
});

test('a multi-finger touch during the release window releases the left button first', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end(); h.advance(100);
    h.start([[1, 100, 100], [2, 140, 100]]);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 1], ['p', 400, 300, 0]], 'left must be released before the new gesture');
    h.advance(50); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [1, 0, 2, 0]);
});

test('a finger joining a drag releases the button at once and the gesture ends', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(50); h.end(); h.advance(100);
    h.start([[1, 100, 100]]); h.move([[1, 140, 100]]);
    h.start([[1, 140, 100], [2, 200, 100]]);
    assert.strictEqual(h.engine.getButtons(), 0);
    const count = h.events.length;
    h.move([[1, 160, 80], [2, 220, 80]]); h.end([[2, 220, 80]]); h.end(); h.advance(1000);
    assert.strictEqual(h.events.length, count, 'nothing after the release until every finger lifts');
    assert.deepStrictEqual(h.buttons().slice(-1), [0]);
});

test('1 -> 2 -> 1 fingers: the remaining finger does nothing until all lift', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(100); h.move([[1, 120, 100]]);
    const moved = h.events.length;
    h.start([[1, 120, 100], [2, 160, 100]]);
    h.end([[1, 120, 100]]);
    h.move([[1, 180, 100]]);
    h.end(); h.advance(1000);
    assert.strictEqual(h.events.length, moved);
});

test('2 -> 1 -> 2 fingers: a finger re-added after a lift is ignored', () => {
    const h = harness({ pinch: true });
    h.start([[1, 100, 100], [2, 140, 100]]); h.end([[1, 100, 100]]);
    h.start([[1, 100, 100], [3, 200, 100]]);
    h.move([[1, 100, 60], [3, 200, 60]]);
    h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, []);
});

test('cancel releases and resets from every state', () => {
    const states = {
        idle: h => {},
        oneFinger: h => { h.start([[1, 100, 100]]); },
        longPressArmed: h => { h.start([[1, 100, 100]]); h.advance(600); },
        twoFingerScroll: h => { h.start([[1, 100, 200], [2, 140, 200]]); h.move([[1, 100, 150], [2, 140, 150]]); },
        pendingRelease: h => { h.start([[1, 100, 100]]); h.end(); },
        tapAndAHalf: h => { h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); },
        dragging: h => { h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); h.move([[1, 150, 100]]); },
        lifting: h => { h.start([[1, 100, 100], [2, 140, 100]]); h.end([[2, 140, 100]]); }
    };
    for (const [name, setup] of Object.entries(states)) {
        for (const op of ['touchCancel', 'reset']) {
            const h = harness();
            setup(h);
            h.engine[op]();
            assert.strictEqual(h.engine.getButtons(), 0, `${name}/${op}: buttons must be released`);
            assert.strictEqual(h.engine.isActive(), false, `${name}/${op}: no state may remain`);
            const count = h.events.length;
            h.advance(2000); h.move([[1, 300, 300]]); h.end();
            assert.strictEqual(h.events.length, count, `${name}/${op}: no timer or stale touch may act afterwards`);
            const pointers = h.events.filter(e => e[0] === 'p');
            if (pointers.length) assert.strictEqual(pointers[pointers.length - 1][3], 0, `${name}/${op}: the last pointer state must have no buttons`);
        }
    }
});

test('setCursor sends the position (enabling trackpad moves the remote pointer)', () => {
    const h = harness();
    h.engine.setCursor(10, 20);
    assert.deepStrictEqual(h.events, [['p', 10, 20, 0]]);
});

test('windowed velocity mode uses only recent movement', () => {
    const h = harness({ config: { velocityWindowMs: 50 } });
    h.start([[1, 100, 100]]); h.advance(1000); h.move([[1, 105, 100]]);
    // velocity 5 / 50 = 0.1 (not 5 / 1000), gain 1.1, remote 5 * 1.1 * 2 = 11
    assert.deepStrictEqual(h.events, [['p', 411, 300, 0]]);
});

// Inputs an adapter really produces: lost touchends, repeated starts, ids the gesture never saw.
test('a finger whose touchend was lost does not poison the cursor', () => {
    let h = harness();
    h.start([[1, 100, 100]]); h.start([[2, 200, 200]]); h.advance(50); h.move([[2, 230, 200]]);
    assert(h.events.length === 1 && Number.isInteger(h.events[0][1]) && h.events[0][3] === 0, JSON.stringify(h.events));
    assert(Number.isFinite(h.engine.getCursor().x));
    h = harness();
    h.start([[1, 100, 100]]); h.move([[7, 150, 150]]); h.end(); h.advance(1000);
    assert(h.events.every(e => Number.isInteger(e[1]) && Number.isInteger(e[2])), JSON.stringify(h.events));
    h = harness();
    h.start([[1, 100, 100], [2, 140, 100]]); h.start([[3, 200, 200]]); h.advance(50); h.move([[3, 220, 200]]); h.end(); h.advance(1000);
    assert(h.events.every(e => Number.isInteger(e[1]) && Number.isInteger(e[2])), JSON.stringify(h.events));
    assert.strictEqual(h.engine.isActive(), false);
});

test('a lost touchend mid-drag releases the button', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.end(); h.advance(100);
    h.start([[1, 100, 100]]); h.move([[1, 140, 100]]);
    assert.strictEqual(h.engine.getButtons(), 1);
    h.move([[9, 300, 300]]);
    assert.strictEqual(h.engine.getButtons(), 0, 'a move list without the dragging finger ends the drag');
    h.advance(1000);
    assert.strictEqual(h.engine.isActive(), false);
});

test('a repeated touchstart for the same finger changes nothing', () => {
    let h = harness();
    h.start([[1, 100, 100]]); h.start([[1, 100, 100]]); h.advance(600); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [2, 0], 'the long press must survive a duplicate start');
    h = harness();
    h.start([[1, 100, 100]]); h.end(); h.advance(100);
    h.start([[1, 100, 100]]); h.move([[1, 140, 100]]); h.start([[1, 140, 100]]);
    assert.strictEqual(h.engine.getButtons(), 1, 'a duplicate start must not end a drag');
    h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons().slice(-1), [0]);
});

test('fingers added while lifting do not change the button', () => {
    const h = harness();
    h.start([[1, 100, 100], [2, 140, 100]]); h.end([[2, 140, 100]]); h.start([[2, 140, 100], [3, 180, 100], [4, 220, 100]]); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [2, 0], 'a two-finger tap stays a right click');
});

test('a two-finger tap may land staggered; a long first touch then a tap is not one', () => {
    let h = harness();
    h.start([[1, 100, 100]]); h.advance(120); h.start([[1, 100, 100], [2, 140, 100]]); h.advance(140); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [2, 0]);
    h = harness();
    h.start([[1, 100, 100]]); h.advance(400); h.start([[1, 100, 100], [2, 140, 100]]); h.advance(60); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.events, []);
});

test('three fingers landing and lifting one by one is a middle click', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.advance(30); h.start([[1, 100, 100], [2, 140, 100]]); h.advance(30);
    h.start([[1, 100, 100], [2, 140, 100], [3, 180, 100]]); h.advance(60);
    h.end([[2, 140, 100], [3, 180, 100]]); h.end([[3, 180, 100]]); h.end(); h.advance(1000);
    assert.deepStrictEqual(h.buttons(), [4, 0]);
});

test('a second finger after a cursor move turns the gesture into a scroll', () => {
    const h = harness();
    h.start([[1, 100, 200]]); h.advance(100); h.move([[1, 120, 200]]);
    const moves = h.events.length;
    h.start([[1, 120, 200], [2, 160, 200]]);
    h.move([[1, 120, 160], [2, 160, 160]]);
    assert.deepStrictEqual(h.events.slice(moves), [['w', h.events[moves - 1][1], 300, -1]]);
});

test('wheel coordinates are integers when the cursor is fractional', () => {
    const h = harness();
    h.engine.setCursor(400.4, 300.6); h.events.length = 0;
    h.start([[1, 100, 200], [2, 140, 200]]); h.move([[1, 100, 160], [2, 140, 160]]);
    assert.deepStrictEqual(h.events, [['w', 400, 301, -1]]);
});

test('callbacks may call back into the engine', () => {
    const scenarios = {
        resetOnPress: { when: e => e[0] === 'p' && e[3] === 1, run: h => { h.start([[1, 100, 100]]); h.end(); } },
        resetOnRelease: { when: e => e[0] === 'p' && e[3] === 0, run: h => { h.start([[1, 100, 100]]); h.end(); h.advance(300); } },
        cancelOnJoinRelease: { when: e => e[0] === 'p' && e[3] === 0, run: h => { h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); h.move([[1, 140, 100]]); h.start([[1, 140, 100], [2, 200, 100]]); } },
        cancelOnLiftRelease: { when: e => e[0] === 'p' && e[3] === 0, run: h => { h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); h.move([[1, 140, 100]]); h.end([[5, 1, 1]]); } },
        resetOnWheel: { when: e => e[0] === 'w', run: h => { h.start([[1, 100, 200], [2, 140, 200]]); h.move([[1, 100, 150], [2, 140, 150]]); h.move([[1, 100, 100], [2, 140, 100]]); } },
        resetOnZoom: { when: e => e[0] === 'z', pinch: true, run: h => { h.start([[1, 100, 150], [2, 200, 150]]); h.move([[1, 60, 150], [2, 240, 150]]); h.move([[1, 40, 150], [2, 260, 150]]); } }
    };
    for (const [name, sc] of Object.entries(scenarios)) {
        const h = harness({ pinch: sc.pinch, onEvent: (engine, e) => { if (sc.when(e)) engine.reset(); } });
        sc.run(h);
        h.advance(1000); h.move([[1, 300, 300]]); h.end();
        assert.strictEqual(h.engine.getButtons(), 0, name);
        assert.strictEqual(h.engine.isActive(), false, name);
    }
});

test('reset forgets the last position, so enabling again sends it', () => {
    const h = harness();
    h.engine.reset(); h.events.length = 0;
    h.engine.setCursor(400, 300);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 0]]);
});

test('setCursor is ignored while a button is held', () => {
    const h = harness();
    h.start([[1, 100, 100]]); h.end();
    assert.strictEqual(h.engine.setCursor(10, 10), false);
    assert.deepStrictEqual(h.events, [['p', 400, 300, 1]]);
});

test('unusable geometry fails closed and recovers', () => {
    for (const bad of [() => ({}), () => null, () => ({ width: 800, height: 600, remotePerCss: NaN }), () => ({ width: 800, height: 600, remotePerCss: 0 }), () => ({ width: 800, height: 600, remotePerCss: Infinity }), () => ({ width: 0, height: 600, remotePerCss: 2 })]) {
        const h = harness();
        h.setGeometry(bad);
        h.engine.reset(); h.events.length = 0;
        h.engine.setCursor(400, 300);
        h.start([[1, 100, 100]]); h.advance(50); h.move([[1, 104, 100]]); h.end(); h.advance(1000);
        h.start([[1, 100, 100], [2, 140, 100]]); h.move([[1, 100, 50], [2, 140, 50]]); h.end();
        assert.deepStrictEqual(h.events, [], `nothing may be sent without a usable screen (${JSON.stringify(bad())})`);
        h.setGeometry(() => h.geom);
        h.engine.setCursor(400, 300);
        assert.deepStrictEqual(h.events, [['p', 400, 300, 0]], 'recovers once the screen is usable');
    }
});

test('a held button is released when the screen shrinks or becomes unusable', () => {
    let h = harness();
    h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); h.move([[1, 200, 150]]);
    h.geom.width = 300; h.geom.height = 200;
    h.end();
    const last = h.events[h.events.length - 1];
    assert(last[3] === 0 && last[1] <= 299 && last[2] <= 199, JSON.stringify(last));
    h = harness();
    h.start([[1, 100, 100]]); h.end(); h.advance(100); h.start([[1, 100, 100]]); h.move([[1, 140, 100]]);
    const held = h.events[h.events.length - 1];
    h.setGeometry(() => ({}));
    h.end();
    assert.deepStrictEqual(h.events[h.events.length - 1], ['p', held[1], held[2], 0], 'the release goes out at the last position');
});

test('the first move cannot spike the gain', () => {
    for (const at of [0, 1, 5]) {
        const h = harness();
        h.start([[1, 100, 100]]); h.advance(at); h.move([[1, 110, 100]]);
        // 10 CSS px at remotePerCss 2: at most the 16 ms floor's gain, 1 + 10/16.
        assert(h.events[0][1] - 400 <= Math.round(10 * (1 + 10 / 16) * 2), `+${at} ms: ${JSON.stringify(h.events)}`);
        // 40 px in the touch's own frame: 1 + 40/16 = 3.5, capped at 3, so 40 * 3 * 2 = 240.
        const fast = harness();
        fast.start([[1, 0, 100]]); fast.move([[1, 40, 100]]);
        assert.deepStrictEqual(fast.events, [['p', 640, 300, 0]], 'gain is capped');
    }
});

test('config values are numbers or the defaults', () => {
    const h = harness({ config: { tapSlopCssPx: '20', longPressMs: NaN, maxGain: 0.5, unknown: 1 } });
    assert.strictEqual(h.engine.config.tapSlopCssPx, 20);
    assert.strictEqual(h.engine.config.longPressMs, 500);
    assert.strictEqual(h.engine.config.maxGain, 3);
    assert.strictEqual(h.engine.config.unknown, undefined);
});

// Randomized sequences: every press must be released by the end, a button changes one at a time,
// coordinates are integers on the current screen, nothing acts after a reset until the next touch,
// and none of this depends on the adapter sending well-formed touch lists. Sequences include
// repeated, stale and unknown ids, cursor moves, geometry changes and resets from inside callbacks.
function propertyCheck(runs, seed) {
    let state = seed >>> 0;
    const random = () => { state = (state * 1664525 + 1013904223) >>> 0; return state / 4294967296; };
    const pick = n => Math.floor(random() * n);
    for (let run = 0; run < runs; run++) {
        const reenter = random() < 0.1;
        let quiet = false;
        const h = harness({ pinch: random() < 0.5, onEvent: (engine, e) => {
            if (quiet) throw new Error(`run ${run}: event after reset ${JSON.stringify(e)}`);
            if (reenter && random() < 0.05) engine.reset();
        } });
        let touches = [];
        let nextId = 1;
        const steps = 2 + pick(24);
        for (let s = 0; s < steps; s++) {
            const op = pick(14);
            quiet = false;
            if (op < 3 && touches.length < 5) {
                touches = touches.concat([[nextId++, pick(400), pick(300)]]);
                const before = h.engine.getButtons();
                const knownBefore = touches.length - 1;
                h.start(touches);
                if (knownBefore > 0 && before && !reenter) assert.strictEqual(h.engine.getButtons(), 0, `run ${run}: a finger joining while a button is held must release it`);
            } else if (op < 6 && touches.length) {
                touches = touches.map(([id, x, y]) => [id, Math.max(0, Math.min(399, x + pick(61) - 30)), Math.max(0, Math.min(299, y + pick(61) - 30))]);
                h.move(touches);
            } else if (op < 8 && touches.length) {
                touches.splice(pick(touches.length), 1);
                h.end(touches);
            } else if (op === 8) {
                h.advance(pick(700));
            } else if (op === 9 && touches.length) {
                // A lost touchend: the finger vanishes from the next list without an end.
                touches.splice(pick(touches.length), 1);
            } else if (op === 10) {
                // A repeated start, or a list with an id the engine never saw start.
                if (random() < 0.5) h.start(touches); else h.move(touches.concat([[1000 + pick(5), pick(400), pick(300)]]));
            } else if (op === 11) {
                h.engine.setCursor(pick(900) - 50, pick(700) - 50);
            } else if (op === 12) {
                const r = pick(4);
                h.setGeometry(r === 0 ? () => ({}) : (r === 1 ? () => ({ width: 300, height: 200, remotePerCss: 1 }) : () => h.geom));
            } else {
                h.engine.touchCancel();
                touches = [];
                quiet = true;
                h.advance(pick(700));
                h.move([[1, 10, 10]]); h.end([]);
            }
        }
        quiet = false;
        h.setGeometry(() => h.geom);
        // Browsers end or cancel every touch eventually, including those whose end this run dropped.
        h.end([]);
        h.advance(2000);
        assert.strictEqual(h.engine.getButtons(), 0, `run ${run}: buttons must all be released after the gesture and timers end`);
        assert.strictEqual(h.engine.isActive(), false, `run ${run}: no state may remain`);
        let mask = 0;
        for (const e of h.events) {
            assert(Number.isInteger(e[1]) && Number.isInteger(e[2]) || e[0] === 'z', `run ${run}: non-integer coordinates ${e}`);
            if (e[0] === 'p') {
                assert(e[1] >= 0 && e[1] <= 799 && e[2] >= 0 && e[2] <= 599, `run ${run}: pointer off screen ${e}`);
                const changed = mask ^ e[3];
                assert((changed & (changed - 1)) === 0, `run ${run}: more than one button changed at once ${mask} -> ${e[3]}`);
                mask = e[3];
            } else if (e[0] === 'w') {
                assert(Number.isInteger(e[3]) && e[3] !== 0, `run ${run}: bad wheel ${e}`);
                assert(e[1] >= 0 && e[1] <= 799 && e[2] >= 0 && e[2] <= 599, `run ${run}: wheel off screen ${e}`);
            }
        }
        assert.strictEqual(mask, 0, `run ${run}: the last pointer state sent must have no buttons`);
    }
}

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/trackpad-engine/current');
    const runsIndex = process.argv.indexOf('--runs');
    const runs = runsIndex >= 0 ? Number(process.argv[runsIndex + 1]) : 100000;
    const results = [];
    for (const c of cases) {
        try { c.fn(); results.push({ name: c.name, ok: true }); } catch (error) { results.push({ name: c.name, ok: false, error: error.message }); }
    }
    try { propertyCheck(runs, 0x5eed); results.push({ name: `randomized sequences (${runs})`, ok: true }); } catch (error) { results.push({ name: `randomized sequences (${runs})`, ok: false, error: error.message }); }
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(results, null, 2));
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.name}${r.ok ? '' : ': ' + r.error}`);
    if (results.some(r => !r.ok)) process.exitCode = 1;
}

main();
