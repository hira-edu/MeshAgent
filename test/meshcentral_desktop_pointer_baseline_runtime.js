// Pin the mouse packets the remote desktop viewer sends today for desktop mouse input and for
// the upstream touch/trackpad handlers in the pinned MeshCentral views, so pointer changes can be
// shown not to alter them. No endpoint connection or OS input is used.
// --print writes the current traces instead of checking them (used when re-pinning after a
// reviewed MeshCentral upgrade).
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const scriptsDir = path.resolve(__dirname, '../../MeshCentral/public/scripts');
const viewsDir = path.resolve(__dirname, '../../MeshCentral/node_modules/meshcentral/views');
const PINNED_MESHCENTRAL = '1.2.5';

function hex(packet) { return packet.map(b => b.toString(16).padStart(2, '0')).join(''); }

function createClock() {
    const RealDate = Date;
    const clock = { now: 1000000, timers: [], nextId: 1 };
    function add(fn, ms, repeat) { const id = clock.nextId++; clock.timers.push({ id, fn, at: clock.now + (ms || 0), every: repeat ? Math.max(ms || 0, 1) : 0 }); return id; }
    clock.setTimeout = (fn, ms) => add(fn, ms, false);
    clock.setInterval = (fn, ms) => add(fn, ms, true);
    clock.clearTimeout = clock.clearInterval = id => { clock.timers = clock.timers.filter(t => t.id !== id); };
    clock.advance = ms => {
        const end = clock.now + ms;
        for (;;) {
            const due = clock.timers.filter(t => t.at <= end).sort((a, b) => (a.at - b.at) || (a.id - b.id))[0];
            if (!due) break;
            clock.now = due.at;
            if (due.every) { due.at += due.every; } else { clock.timers = clock.timers.filter(t => t !== due); }
            due.fn();
        }
        clock.now = end;
    };
    clock.Date = function (...args) { return args.length ? new RealDate(...args) : new RealDate(clock.now); };
    clock.Date.now = () => clock.now;
    return clock;
}

function createElement(id, rect) {
    const element = {
        id, style: {}, scrollLeft: 0, scrollTop: 0, checked: true, innerHTML: '', value: '',
        rect: Object.assign({ left: 0, top: 0, width: 0, height: 0 }, rect || {}),
        classList: { toggle() {}, contains() { return false; }, add() {}, remove() {} },
        focus() {}, blur() {}, click() {}, querySelector() { return null; },
        addEventListener() {}, removeEventListener() {},
        getBoundingClientRect() {
            // The trackpad overlay is positioned through style.left/top; everything else is static.
            const r = this.rect;
            const left = (id === 'trackpadCursor') ? (parseFloat(this.style.left) || 0) : r.left;
            const top = (id === 'trackpadCursor') ? (parseFloat(this.style.top) || 0) : r.top;
            return { left, top, width: r.width, height: r.height, right: left + r.width, bottom: top + r.height };
        }
    };
    return element;
}

// Desk is shown at 400x300 CSS px; the remote screen is 800x600, so one CSS px is two remote px.
function createCanvas() {
    const canvas = createElement('Desk', { left: 0, top: 0, width: 400, height: 300 });
    Object.assign(canvas, { width: 800, height: 600, clientWidth: 400, clientHeight: 300, offsetLeft: 0, offsetTop: 0, offsetParent: null });
    canvas.getContext = () => ({ canvas, setTransform() {}, clearRect() {}, rotate() {}, fillRect() {}, drawImage() {}, putImageData() {} });
    return canvas;
}

// setRotation copies the frame through a scratch canvas.
function createScratchCanvas() {
    const c = { width: 0, height: 0 };
    c.getContext = () => ({ canvas: c, setTransform() {}, rotate() {}, drawImage() {} });
    return c;
}

function loadViewer(asset, clock, canvas) {
    const source = fs.readFileSync(path.join(scriptsDir, asset), 'utf8');
    const context = vm.createContext({
        navigator: { platform: 'Win32', userAgent: 'Mozilla/5.0 (Linux; Android 14) Mobile' },
        window: { scrollX: 0, scrollY: 0, pageXOffset: 0, pageYOffset: 0 }, document: { createElement: createScratchCanvas }, desktop: { State: 3 }, urlargs: {},
        ShortToStr: x => String.fromCharCode(x >> 8, x & 255), console, Uint8Array,
        setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout, setInterval: clock.setInterval, clearInterval: clock.clearInterval, Date: clock.Date
    });
    vm.runInContext(source, context);
    const viewer = context.CreateAgentRemoteDesktop(canvas, null);
    const sink = { packets: [] };
    viewer.parent = {
        State: 2,
        send(packet) { sink.packets.push(Array.from(packet, c => c.charCodeAt(0))); },
        xxStateChange(state) { this.State = state; viewer.xxStateChange(state); }
    };
    viewer.Start();
    viewer.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 800 >> 8, 800 & 255, 600 >> 8, 600 & 255]));
    return { viewer, sink };
}

// Only mouse packets matter here: type 2, with the button/wheel bytes kept as sent.
function mousePackets(packets) { return packets.filter(p => ((p[0] << 8) | p[1]) === 2).map(hex); }

function record(sink, action) {
    sink.packets = [];
    action();
    return mousePackets(sink.packets);
}

function moduleScenarios(asset) {
    const clock = createClock();
    const canvas = createCanvas();
    const { viewer, sink } = loadViewer(asset, clock, canvas);
    const at = (x, y, extra) => Object.assign({ pageX: x, pageY: y, button: 0, which: 1 }, extra || {});
    const out = {};
    out.move = record(sink, () => viewer.SendMouseMsg(viewer.KeyAction.NONE, at(10, 20)));
    out.everyMoveSent = record(sink, () => { viewer.mousemove(at(10, 20)); viewer.mousemove(at(11, 20)); viewer.mousemove(at(12, 20)); });
    out.leftClick = record(sink, () => { viewer.mousedown(at(10, 20)); viewer.mouseup(at(10, 20)); });
    out.rightClick = record(sink, () => { viewer.mousedown(at(10, 20, { button: 2, which: 3 })); viewer.mouseup(at(10, 20, { button: 2, which: 3 })); });
    out.middleClick = record(sink, () => { viewer.mousedown(at(10, 20, { button: 1, which: 2 })); viewer.mouseup(at(10, 20, { button: 1, which: 2 })); });
    out.unmatchedUp = record(sink, () => viewer.mouseup(at(10, 20)));
    out.wheelUp = record(sink, () => viewer.mousewheel(at(10, 20, { wheelDelta: 40 })));
    out.wheelDown = record(sink, () => viewer.mousewheel(at(10, 20, { wheelDelta: -40 })));
    out.wheelDetail = record(sink, () => viewer.mousewheel(at(10, 20, { detail: 1 })));
    out.dblClick = record(sink, () => viewer.mousedblclick(at(10, 20)));
    out.outOfBounds = record(sink, () => { viewer.mousemove(at(401, 20)); viewer.mousedown(at(-1, 20)); viewer.mouseup(at(-1, 20)); });
    out.scrollOffset = record(sink, () => viewer.mousemove(at(10, 20, { addx: 30, addy: 40 })));
    viewer.SwapMouse = true;
    out.swapped = record(sink, () => { viewer.mousedown(at(10, 20)); viewer.mouseup(at(10, 20)); });
    viewer.SwapMouse = false;
    viewer.ReverseMouseWheel = true;
    out.reversedWheel = record(sink, () => viewer.mousewheel(at(10, 20, { wheelDelta: 40 })));
    viewer.ReverseMouseWheel = false;
    viewer.setRotation(1);
    out.rotatedMove = record(sink, () => viewer.mousemove(at(10, 20)));
    viewer.setRotation(0);
    viewer.stopInput = true;
    out.viewOnly = record(sink, () => { viewer.mousemove(at(10, 20)); viewer.mousedown(at(10, 20)); viewer.mouseup(at(10, 20)); viewer.mousewheel(at(10, 20, { wheelDelta: 40 })); });
    viewer.stopInput = false;
    return out;
}

function sliceBetween(source, startMarker, endMarker, name) {
    const start = source.indexOf(startMarker);
    assert(start >= 0, `${name}: start marker not found`);
    const end = source.indexOf(endMarker, start + startMarker.length);
    assert(end > start, `${name}: end marker not found`);
    return source.slice(start, end);
}

function touchEvent(points, changed) {
    const touch = p => ({ identifier: p[0], clientX: p[1], clientY: p[2], pageX: p[1], pageY: p[2] });
    return {
        touches: points.map(touch), targetTouches: points.map(touch), changedTouches: (changed || points).map(touch),
        defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}
    };
}

// Run a view's touch handlers against the real viewer module with a fake DOM and clock.
function createViewHarness(asset, view) {
    const clock = createClock();
    const canvas = createCanvas();
    const { viewer, sink } = loadViewer(asset, clock, canvas);
    const elements = { Desk: canvas };
    const Q = id => elements[id] || (elements[id] = createElement(id));
    elements.DeskParent = createElement('DeskParent', { left: 0, top: 0, width: 400, height: 300 });
    elements.deskarea3x = createElement('deskarea3x', { left: 0, top: 0, width: 400, height: 300 });
    elements.p10desktop = createElement('p10desktop', { left: 0, top: 0, width: 400, height: 300 });
    elements.p10 = createElement('p10', { left: 0, top: 0, width: 400, height: 300 });
    const globals = {
        Q, QV() {}, QS: id => Q(id).style, console, Math, JSON, Object, Array, String, Number, parseFloat, parseInt, isNaN,
        window: { scrollX: 0, scrollY: 0 }, document: { activeElement: null, body: { classList: { contains: c => c === 'is-mobile' } }, documentElement: { style: { getPropertyValue() { return ''; }, setProperty() {} } } },
        setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout, setInterval: clock.setInterval, clearInterval: clock.clearInterval, Date: clock.Date,
        desktop: { m: viewer, State: 3 }, webRtcDesktop: null, xxdialogMode: 0,
        setSessionActivity() {}, deskCloseMobileActions() {}, _mobileZoomMode: 'fit', _mobileKbdEnabled: false,
        fullscreen: true, fullscreenzoom: 1, features2: 0, currentNode: { agent: { id: 3 } }, GetNodeRights: () => 0xFFFFFFFF
    };
    const context = vm.createContext(globals);
    const source = fs.readFileSync(path.join(viewsDir, view), 'utf8').replace(/\r\n/g, '\n');
    if (view === 'default3.handlebars') {
        // The is-mobile coordinate and rotation overrides the page applies to desktop.m at connect.
        const overrides = sliceBetween(source, "if (document.body.classList.contains('is-mobile')) {\n                        desktop.m.GetPositionOfControl", '                    desktop.Start(desktopNode._id);', 'default3 is-mobile overrides');
        vm.runInContext(overrides, context);
        vm.runInContext(sliceBetween(source, '        // Mobile touch input for remote desktop.', '        function stopProcess(id, name) {', 'default3 touch handlers'), context);
    } else {
        vm.runInContext(sliceBetween(source, '        var trackpadMode = false;', '        //\n        // TERMINAL', 'default-mobile touch handlers'), context);
    }
    const run = (name, fn) => { sink.packets = []; fn(); return mousePackets(sink.packets); };
    const call = (fn, ...args) => context[fn](...args);
    return { context, clock, elements, viewer, run, call, sink };
}

function default3Scenarios(asset) {
    const out = {};
    const fresh = () => createViewHarness(asset, 'default3.handlebars');
    let h = fresh();
    const start = (pts) => h.call('dtouchstart', touchEvent(pts));
    const move = (pts) => h.call('dtouchmove', touchEvent(pts));
    const end = (left, changed) => h.call('dtouchend', touchEvent(left, changed));
    out.directTap = h.run('directTap', () => { start([[1, 100, 100]]); h.clock.advance(50); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.directDoubleTap = h.run('directDoubleTap', () => { start([[1, 100, 100]]); end([], [[1, 100, 100]]); h.clock.advance(100); start([[1, 102, 101]]); end([], [[1, 102, 101]]); });
    h.clock.advance(1000);
    out.directShortPanClicks = h.run('directShortPanClicks', () => { start([[1, 100, 100]]); move([[1, 120, 100]]); end([], [[1, 120, 100]]); });
    h.clock.advance(1000);
    out.directLongPan = h.run('directLongPan', () => { start([[1, 100, 100]]); move([[1, 150, 100]]); end([], [[1, 150, 100]]); });
    h.clock.advance(1000);
    out.directLongPressRight = h.run('directLongPressRight', () => { start([[1, 100, 100]]); h.clock.advance(600); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.directLongPressDrag = h.run('directLongPressDrag', () => { start([[1, 100, 100]]); h.clock.advance(600); move([[1, 110, 100]]); move([[1, 120, 100]]); end([], [[1, 120, 100]]); });
    h.clock.advance(1000);
    out.directTwoFingerScroll = h.run('directTwoFingerScroll', () => { start([[1, 100, 100], [2, 140, 100]]); move([[1, 100, 90], [2, 140, 90]]); end([[2, 140, 90]], [[1, 100, 90]]); end([], [[2, 140, 90]]); });
    h.clock.advance(1000);
    out.directSecondFingerMidDrag = h.run('directSecondFingerMidDrag', () => { start([[1, 100, 100]]); h.clock.advance(600); move([[1, 110, 100]]); start([[1, 110, 100], [2, 150, 100]]); end([[2, 150, 100]], [[1, 110, 100]]); end([], [[2, 150, 100]]); });
    h.clock.advance(1000);
    h.elements.DeskControl = Object.assign(createElement('DeskControl'), { checked: false });
    out.directInputOff = h.run('directInputOff', () => { start([[1, 100, 100]]); end([], [[1, 100, 100]]); });
    h.elements.DeskControl.checked = true;

    h = fresh();
    out.trackpadEnable = h.run('trackpadEnable', () => h.call('deskToggleTrackpad'));
    out.trackpadMove = h.run('trackpadMove', () => { start([[1, 100, 100]]); move([[1, 110, 100]]); move([[1, 120, 104]]); end([], [[1, 120, 104]]); });
    h.clock.advance(1000);
    out.trackpadTap = h.run('trackpadTap', () => { start([[1, 100, 100]]); h.clock.advance(50); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.trackpadJitterTap = h.run('trackpadJitterTap', () => { start([[1, 100, 100]]); move([[1, 102, 100]]); end([], [[1, 102, 100]]); });
    h.clock.advance(1000);
    out.trackpadSlowTap = h.run('trackpadSlowTap', () => { start([[1, 100, 100]]); h.clock.advance(300); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.trackpadLongPressRight = h.run('trackpadLongPressRight', () => { start([[1, 100, 100]]); h.clock.advance(600); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.trackpadLongPressDrag = h.run('trackpadLongPressDrag', () => { start([[1, 100, 100]]); h.clock.advance(600); move([[1, 110, 100]]); move([[1, 120, 100]]); end([], [[1, 120, 100]]); });
    h.clock.advance(1000);
    out.trackpadTwoFingerTap = h.run('trackpadTwoFingerTap', () => { start([[1, 100, 100]]); start([[1, 100, 100], [2, 140, 100]]); end([[2, 140, 100]], [[1, 100, 100]]); end([], [[2, 140, 100]]); });
    h.clock.advance(1000);
    out.trackpadTwoFingerScroll = h.run('trackpadTwoFingerScroll', () => { start([[1, 100, 100], [2, 140, 100]]); move([[1, 100, 90], [2, 140, 90]]); end([[2, 140, 90]], [[1, 100, 90]]); end([], [[2, 140, 90]]); });
    h.clock.advance(1000);
    h.elements.DeskControl = Object.assign(createElement('DeskControl'), { checked: false });
    out.trackpadInputOffMove = h.run('trackpadInputOffMove', () => { start([[1, 100, 100]]); move([[1, 110, 100]]); end([], [[1, 110, 100]]); });
    h.elements.DeskControl.checked = true;
    h.clock.advance(1000);
    h.context.xxdialogMode = 2;
    out.trackpadDialog = h.run('trackpadDialog', () => { start([[1, 100, 100]]); move([[1, 110, 100]]); end([], [[1, 110, 100]]); });
    h.context.xxdialogMode = 0;
    return out;
}

function defaultMobileScenarios(asset) {
    const out = {};
    let h = createViewHarness(asset, 'default-mobile.handlebars');
    const start = (pts) => { const e = touchEvent(pts); h.call('dtouchstart', e); return e; };
    const move = (pts) => h.call('dtouchmove', touchEvent(pts));
    const end = (left, changed) => h.call('dtouchend', touchEvent(left, changed));
    let directEvent = null;
    out.directPassesThrough = h.run('directPassesThrough', () => { directEvent = start([[1, 100, 100]]); move([[1, 110, 100]]); end([], [[1, 110, 100]]); });
    out.directDefaultPrevented = directEvent.defaultPrevented;
    out.trackpadEnable = h.run('trackpadEnable', () => h.call('deskToggleTrackpad'));
    out.trackpadMove = h.run('trackpadMove', () => { start([[1, 100, 100]]); move([[1, 110, 100]]); move([[1, 120, 104]]); end([], [[1, 120, 104]]); });
    h.clock.advance(1000);
    out.trackpadTap = h.run('trackpadTap', () => { start([[1, 100, 100]]); h.clock.advance(50); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.trackpadJitterTap = h.run('trackpadJitterTap', () => { start([[1, 100, 100]]); move([[1, 102, 100]]); end([], [[1, 102, 100]]); });
    h.clock.advance(1000);
    out.trackpadLongPress = h.run('trackpadLongPress', () => { start([[1, 100, 100]]); h.clock.advance(600); end([], [[1, 100, 100]]); });
    h.clock.advance(1000);
    out.trackpadTwoFingerUsesFirst = h.run('trackpadTwoFingerUsesFirst', () => { start([[1, 100, 100], [2, 140, 100]]); move([[1, 110, 100], [2, 150, 90]]); end([], [[1, 110, 100], [2, 150, 90]]); });
    h.clock.advance(1000);
    h.elements.p10desktop.scrollLeft = 20;
    h.elements.p10desktop.scrollTop = 10;
    out.trackpadScrolledTap = h.run('trackpadScrolledTap', () => { start([[1, 100, 100]]); end([], [[1, 100, 100]]); });
    h.elements.p10desktop.scrollLeft = 0;
    h.elements.p10desktop.scrollTop = 0;
    h.clock.advance(1000);
    h.context.xxdialogMode = 2;
    out.trackpadDialog = h.run('trackpadDialog', () => { start([[1, 100, 100]]); move([[1, 110, 100]]); end([], [[1, 110, 100]]); });
    h.context.xxdialogMode = 0;
    return out;
}

function collect() {
    const traces = {};
    for (const asset of ['agent-desktop-0.0.2.js', 'agent-desktop-0.0.2-min.js']) {
        traces[asset] = {
            module: moduleScenarios(asset),
            default3: default3Scenarios(asset),
            'default-mobile': defaultMobileScenarios(asset)
        };
    }
    return traces;
}

// Packets: 0002 000a 00 <button> <x16> <y16>, or 0002 000c 00 00 <x16> <y16> <wheel16> for wheel.
// Remote coordinates are twice the CSS coordinates (400x300 canvas showing 800x600).
// These record current behaviour, including known defects that must not change by accident:
// negative wheel deltas are one's complement (-120 is sent as ff87), every move is sent (the
// move throttle tests an unset obj.Action), rotation does not remap mouse coordinates, a
// two-finger scroll in direct mode scrolls at the previous gesture's position and clicks on lift,
// a two-finger trackpad tap left-clicks, and trackpad moves ignore the Input toggle.
const EXPECTED = {
    'module': {
        move: ['0002000a000000140028'],
        everyMoveSent: ['0002000a000000140028', '0002000a000000160028', '0002000a000000180028'],
        leftClick: ['0002000a000200140028', '0002000a000400140028'],
        rightClick: ['0002000a000800140028', '0002000a001000140028'],
        middleClick: ['0002000a002000140028', '0002000a004000140028'],
        unmatchedUp: [],
        wheelUp: ['0002000c0000001400280078'],
        wheelDown: ['0002000c000000140028ff87'],
        wheelDetail: ['0002000c000000140028ff87'],
        dblClick: ['0002000a008800140028'],
        outOfBounds: [],
        scrollOffset: ['0002000a000000320050'],
        swapped: ['0002000a000800140028', '0002000a001000140028'],
        reversedWheel: ['0002000c000000140028ff87'],
        rotatedMove: ['0002000a0000000f0035'],
        viewOnly: []
    },
    'default3': {
        directTap: ['0002000a000200c800c8', '0002000a000400c800c8'],
        directDoubleTap: ['0002000a000200c800c8', '0002000a000400c800c8', '0002000a000200c800c8', '0002000a000400c800c8'],
        directShortPanClicks: ['0002000a000000f000c8', '0002000a000200f000c8', '0002000a000400f000c8'],
        directLongPan: ['0002000a0000012c00c8'],
        directLongPressRight: ['0002000a000800c800c8', '0002000a001000c800c8'],
        directLongPressDrag: ['0002000a000200c800c8', '0002000a000000dc00c8', '0002000a000000f000c8', '0002000a000400f000c8'],
        directTwoFingerScroll: ['0002000c000000f000c8ff87', '0002000a000200c800b4', '0002000a000400c800b4'],
        directSecondFingerMidDrag: ['0002000a000200c800c8', '0002000a000000dc00c8', '0002000a000200dc00c8', '0002000a000400dc00c8'],
        directInputOff: [],
        trackpadEnable: [],
        trackpadMove: ['0002000a000001ae012c', '0002000a000001cc0138'],
        trackpadTap: ['0002000a000201cc0138', '0002000a000401cc0138'],
        trackpadJitterTap: ['0002000a000001d20138'],
        trackpadSlowTap: [],
        trackpadLongPressRight: ['0002000a000801d20138', '0002000a001001d20138'],
        trackpadLongPressDrag: ['0002000a000201d20138', '0002000a000001f00138', '0002000a0000020e0138', '0002000a0004020e0138'],
        trackpadTwoFingerTap: ['0002000a0002020e0138', '0002000a0004020e0138'],
        trackpadTwoFingerScroll: ['0002000c0000020e0138ff87'],
        trackpadInputOffMove: ['0002000a0000022c0138'],
        trackpadDialog: []
    },
    'default-mobile': {
        directPassesThrough: [],
        directDefaultPrevented: false,
        trackpadEnable: [],
        trackpadMove: ['0002000a000001ae012c', '0002000a000001cc0138'],
        trackpadTap: ['0002000a000201cc0138', '0002000a000401cc0138'],
        trackpadJitterTap: ['0002000a000001d20138'],
        trackpadLongPress: [],
        trackpadTwoFingerUsesFirst: ['0002000a000001f00138'],
        trackpadScrolledTap: ['0002000a000202040142', '0002000a000402040142'],
        trackpadDialog: []
    }
};

function main() {
    const installed = JSON.parse(fs.readFileSync(path.resolve(viewsDir, '..', 'package.json'), 'utf8')).version;
    assert.strictEqual(installed, PINNED_MESHCENTRAL, `traces are pinned to MeshCentral ${PINNED_MESHCENTRAL}; re-pin after reviewing the upgrade (installed ${installed})`);
    const traces = collect();
    if (process.argv.includes('--print')) { process.stdout.write(JSON.stringify(traces, null, 2) + '\n'); return; }
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/viewer-pointer-baseline/current');
    fs.mkdirSync(evidence, { recursive: true });
    const errors = [];
    for (const [asset, groups] of Object.entries(traces)) {
        for (const [group, scenarios] of Object.entries(groups)) {
            for (const [name, actual] of Object.entries(scenarios)) {
                try { assert.deepStrictEqual(actual, EXPECTED[group][name]); } catch (error) { errors.push(`${asset} ${group}.${name}: expected ${JSON.stringify(EXPECTED[group][name])}, got ${JSON.stringify(actual)}`); }
            }
            for (const name of Object.keys(EXPECTED[group])) { if (!(name in scenarios)) errors.push(`${asset} ${group}.${name}: scenario missing`); }
        }
    }
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify({ meshcentral: installed, traces, errors }, null, 2));
    for (const error of errors) console.log(`FAIL ${error}`);
    console.log(`${errors.length ? 'FAIL' : 'PASS'} viewer pointer baseline (${Object.keys(traces).length} assets, MeshCentral ${installed})`);
    if (errors.length) process.exitCode = 1;
}

main();
