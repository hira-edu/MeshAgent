// Run the trackpad adapters in real browsers against fixtures built from the pinned MeshCentral
// views: the views' exact canvas markup and their own touch, mouse and trackpad code (sliced from
// default3.handlebars and default-mobile.handlebars), with the real agent-desktop module recording
// the packets it would send. Chromium gets real multi-touch through CDP, so the browser's
// compatibility mouse events are part of the test; WebKit gets dispatched touch-typed events.
// No endpoint connection or OS input is used.
// Requires: npm ci --prefix test && npx --prefix test playwright install chromium webkit
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const meshcentral = path.resolve(__dirname, '../../MeshCentral');
const scripts = path.join(meshcentral, 'public/scripts');
const views = path.join(meshcentral, 'node_modules/meshcentral/views');

function view(name) { return fs.readFileSync(path.join(views, name), 'utf8').replace(/\r\n/g, '\n'); }
function slice(source, start, end, name) {
    const a = source.indexOf(start);
    assert(a >= 0, `${name}: start marker not found`);
    const b = source.indexOf(end, a + start.length);
    assert(b > a, `${name}: end marker not found`);
    return source.slice(a, b);
}

const DEFAULT3_CANVAS = '<canvas id=Desk width=640 height=480 oncontextmenu="return false"\n                                onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event)\n                                onmousewheel=dmousewheel(event)\n                                ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>';
const DEFAULT3_BLANK_CANVAS = '<canvas id=Desk oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>';
const MOBILE_CANVAS = '<canvas id=Desk width=640 height=200 style="width:100%;-ms-touch-action:none;margin-left:0px" oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event) ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>';

function fixtures() {
    const d3 = view('default3.handlebars'), dm = view('default-mobile.handlebars');
    assert(d3.includes(DEFAULT3_CANVAS) && d3.includes(DEFAULT3_BLANK_CANVAS) && dm.includes(MOBILE_CANVAS), 'fixture canvas markup must match the pinned views');
    return {
        default3: {
            adapter: 'default3', script: 'agent-desktop-trackpad-default3-0.0.1.js',
            page: `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>
body{margin:0} #deskarea3x{position:absolute;left:0;top:0;width:400px;height:300px;overflow:hidden;background:#000}
#DeskParent{width:100%;height:100%} body.native-zoom #DeskParent{position:relative;display:block;width:var(--native-desk-w,100%);height:var(--native-desk-h,100%)}
#Desk{display:block;width:100%;height:100%} #spacer{position:absolute;top:0;left:0;width:1px;height:2000px}
</style></head><body class="is-mobile"><div id=spacer></div><div id=deskarea3x><div id=DeskParent>${DEFAULT3_CANVAS}</div></div>
<svg id="trackpadCursor" style="display:none;position:fixed;width:18px;height:30px"></svg>
<input id="DeskControl" type="checkbox" checked style="position:absolute;left:520px;top:10px;width:40px;height:40px">
<button id="toggle" style="position:absolute;left:520px;top:80px;width:80px;height:40px" onclick="deskToggleTrackpad()">trackpad</button>
<script>
window.calls = []; window.packets = [];
function Q(id) { return document.getElementById(id); } function QV() {} function QS(id) { return (Q(id) || { style: {} }).style; } function QH(id, h) { var e = Q(id); if (e) e.innerHTML = h; }
var xxdialogMode = 0, _mobileZoomMode = 'fit', _mobileKbdEnabled = false, webRtcDesktop = null, desktop = null, sessionActivity = 0;
function setSessionActivity() { calls.push('setSessionActivity'); } function deskCloseMobileActions() { calls.push('deskCloseMobileActions'); }
</script><script>${slice(d3, '        var dblClickDetectArgs', '        // Mobile touch input for remote desktop.', 'default3 mouse handlers')}
${slice(d3, '        // Mobile touch input for remote desktop.', '        function stopProcess(id, name) {', 'default3 touch handlers')}</script></body></html>`,
            overrides: slice(d3, "if (document.body.classList.contains('is-mobile')) {\n                        desktop.m.GetPositionOfControl", '                    desktop.Start(desktopNode._id);', 'default3 is-mobile overrides')
        },
        mobile: {
            adapter: 'defaultMobile', script: 'agent-desktop-trackpad-mobile-0.0.1.js',
            page: `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>body{margin:0}</style></head><body>
<div id=p10 style="position:absolute;left:0;top:0;width:400px;height:355px;overflow:hidden">
<div id=p10desktop style="overflow:hidden;position:absolute;top:55px;bottom:0px;width:100%"><div id=deskarea3><div id=DeskParent style="height:100%">${MOBILE_CANVAS}</div></div></div>
<img id="trackpadCursor" style="display:none;position:absolute;pointer-events:none;z-index:999;width:24px;height:24px" /></div>
<div id="deskkeybutton6a"></div><div id="deskkeybutton6b"></div>
<button id="toggle" style="position:absolute;left:520px;top:80px;width:80px;height:40px" onclick="deskToggleTrackpad()">trackpad</button>
<button id="exitfull" style="position:absolute;left:520px;top:140px;width:80px;height:40px" onclick="fullscreen = false; if (trackpadMode) { trackpadMode = false; }">exit</button>
<script>
window.calls = []; window.packets = [];
function Q(id) { return document.getElementById(id); } function QV() {} function QS(id) { return (Q(id) || { style: {} }).style; }
var xxdialogMode = 0, desktop = null, fullscreen = true, fullscreenzoom = 1, features2 = 0, currentNode = { agent: { id: 3 } };
function GetNodeRights() { return 0xFFFFFFFF; } function setSessionActivity() { calls.push('setSessionActivity'); }
</script><script>${slice(dm, '        function dmousedown(e) {', '        //\n        // TERMINAL', 'default-mobile handlers')}</script></body></html>`,
            overrides: ''
        }
    };
}

async function openPage(browser, fixture, options) {
    const context = await browser.newContext({ hasTouch: true, isMobile: options.engine === 'chromium', viewport: { width: 640, height: 400 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.setContent(fixture.page);
    await page.addScriptTag({ path: path.join(scripts, 'agent-desktop-0.0.2.js') });
    await page.evaluate(overrides => {
        const hex = p => Array.from(p, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        desktop = { m: CreateAgentRemoteDesktop('Desk'), State: 3 };
        const m = desktop.m;
        m.parent = { State: 2, send: p => { if (((p.charCodeAt(0) << 8) | p.charCodeAt(1)) === 2) packets.push(hex(p)); }, xxStateChange: function (s) { this.State = s; m.xxStateChange(s); } };
        m.Start();
        m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 3, 32, 2, 88]));
        // The first frame would size the canvas to the 800x600 screen.
        m.Canvas.canvas.width = 800; m.Canvas.canvas.height = 600;
        if (overrides) (0, eval)(overrides);
        for (const n of ['dtouchstart', 'dtouchmove', 'dtouchend', 'dmousedown', 'dmouseup', 'dmousemove']) {
            const original = window[n];
            window[n] = function (e) { calls.push(n); return original.apply(this, arguments); };
        }
        packets.length = 0; calls.length = 0;
    }, fixture.overrides);
    if (options.controller) {
        for (const f of ['agent-desktop-trackpad-0.0.1.js', 'agent-desktop-trackpad-controller-0.0.1.js', fixture.script]) await page.addScriptTag({ path: path.join(scripts, f) });
        await page.evaluate(([adapter, flag]) => {
            window.__flag = flag;
            window.ctl = MeshTrackpadController.create({ adapter: MeshTrackpadAdapters[adapter], engine: MeshTrackpadEngine, enabled: () => window.__flag });
            if (!MeshTrackpadAdapters[adapter].detect()) throw new Error('adapter does not detect its page');
            window.ctl.install();
        }, [fixture.adapter, options.flag]);
    }
    const cdp = options.engine === 'chromium' ? await context.newCDPSession(page) : null;
    const pt = (id, x, y) => ({ x, y, id, radiusX: 1, radiusY: 1, force: 1 });
    const h = {
        page, errors, cdp,
        async touchListeners(selector) {
            const { result } = await cdp.send('Runtime.evaluate', { expression: `document.querySelector(${JSON.stringify(selector)})` });
            const { listeners } = await cdp.send('DOMDebugger.getEventListeners', { objectId: result.objectId });
            return listeners.filter(l => /^touch/.test(l.type)).length;
        },
        async touch(type, points) {
            if (cdp) { await cdp.send('Input.dispatchTouchEvent', { type, touchPoints: points.map(p => pt(...p)) }); return; }
            await page.evaluate(([type, points]) => {
                const desk = document.getElementById('Desk');
                const t = points.map(([id, x, y]) => ({ identifier: id, target: desk, clientX: x, clientY: y, pageX: x, pageY: y }));
                const map = { touchStart: 'touchstart', touchMove: 'touchmove', touchEnd: 'touchend', touchCancel: 'touchcancel' };
                const ev = new Event(map[type], { bubbles: true, cancelable: true, composed: true });
                const now = (map[type] === 'touchend' || map[type] === 'touchcancel') ? [] : t;
                for (const [k, v] of [['touches', now], ['targetTouches', now], ['changedTouches', t]]) Object.defineProperty(ev, k, { value: v });
                desk.dispatchEvent(ev);
            }, [type, points]);
        },
        // Tap, then touch again and drag: the left button is held (tap-and-a-half).
        async drag(x, y) { await h.tap(x, y); await page.waitForTimeout(60); await h.touch('touchStart', [[1, x, y]]); await h.touch('touchMove', [[1, x + 50, y]]); },
        async tap(x, y, id) { await h.touch('touchStart', [[id || 1, x, y]]); await page.waitForTimeout(40); await h.touch('touchEnd', []); },
        async click(id) { await page.click('#' + id); await page.waitForTimeout(30); },
        wait: ms => page.waitForTimeout(ms),
        state: () => page.evaluate(() => {
            const o = window.ctl && window.ctl.overlay();
            const rect = document.getElementById('Desk').getBoundingClientRect();
            const g = desktop.m.GetRemoteGeometry ? desktop.m.GetRemoteGeometry() : null;
            let overlayRemote = null;
            if (g && o && o.style.display === 'block') { const r = g.cssToRemote(parseFloat(o.style.left) - rect.left, parseFloat(o.style.top) - rect.top); overlayRemote = [Math.round(r.x), Math.round(r.y)]; }
            const cursor = document.getElementById('trackpadCursor');
            return { calls: calls.slice(), packets: packets.slice(), overlayRemote, upstreamCursor: getComputedStyle(cursor).display, pressed: Object.keys(desktop.m.browserPressedButtons), active: !!(window.ctl && window.ctl.isActive()), edgeTimer: (typeof trackpadEdgeTimer === 'undefined') ? null : trackpadEdgeTimer };
        }),
        reset: () => page.evaluate(() => { packets.length = 0; calls.length = 0; }),
        close: () => context.close()
    };
    return h;
}

const decode = p => ({ button: parseInt(p.slice(10, 12), 16), x: parseInt(p.slice(12, 16), 16), y: parseInt(p.slice(16, 20), 16) });
const buttons = packets => packets.map(p => decode(p).button).filter(b => b !== 0);
const touchCalls = calls => calls.filter(c => /^d(touch|mouse)/.test(c));

// A scripted session used to compare pages with and without the controller.
async function scripted(h) {
    await h.tap(100, 100);
    await h.wait(400);
    await h.touch('touchStart', [[1, 150, 150]]); await h.touch('touchMove', [[1, 170, 150]]); await h.touch('touchMove', [[1, 190, 160]]); await h.touch('touchEnd', []);
    await h.wait(400);
    await h.touch('touchStart', [[1, 120, 120]]); await h.wait(650); await h.touch('touchEnd', []);
    await h.wait(400);
    return h.state();
}

const results = [];
function record(engine, view, name, fn) { return fn().then(() => results.push({ engine, view, name, ok: true }), e => results.push({ engine, view, name, ok: false, error: e.message })); }

async function chromiumScenarios(browser, fx) {
    for (const [viewName, fixture] of Object.entries(fx)) {
        const enableTrackpad = async h => { await h.click('toggle'); };

        // A4: with the flag off, or with trackpad mode off, the page behaves exactly as without the controller.
        for (const trackpad of [false, true]) {
            await record('chromium', viewName, `flag off is identical to no controller (trackpad ${trackpad ? 'on' : 'off'})`, async () => {
                const base = await openPage(browser, fixture, { engine: 'chromium', controller: false });
                const off = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: false });
                try {
                    if (trackpad) { await enableTrackpad(base); await enableTrackpad(off); await base.reset(); await off.reset(); }
                    const a = await scripted(base), b = await scripted(off);
                    assert.deepStrictEqual(b.calls, a.calls, 'same page handlers ran');
                    assert.deepStrictEqual(b.packets, a.packets, 'same packets');
                    assert(touchCalls(a.calls).length > 0, 'the page handled the touches itself');
                    assert.deepStrictEqual(off.errors.concat(base.errors), []);
                } finally { await base.close(); await off.close(); }
            });
        }
        await record('chromium', viewName, 'flag on with trackpad off leaves direct touch to the page', async () => {
            const base = await openPage(browser, fixture, { engine: 'chromium', controller: false });
            const on = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
            try {
                const a = await scripted(base), b = await scripted(on);
                assert.deepStrictEqual(b.calls, a.calls); assert.deepStrictEqual(b.packets, a.packets);
                assert(touchCalls(a.calls).length > 0, 'the page handled the touches itself');
                assert.strictEqual(b.active, false);
            } finally { await base.close(); await on.close(); }
        });

        await record('chromium', viewName, 'trackpad on: the engine owns touches, no page handler or compatibility click runs', async () => {
            const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
            try {
                await enableTrackpad(h);
                let s = await h.state();
                assert.strictEqual(s.active, true);
                assert.strictEqual(s.packets.length, 1, 'enabling sends one move to the centre');
                const centre = decode(s.packets[0]);
                assert.deepStrictEqual([centre.button, centre.x, centre.y], [0, 400, 300]);
                assert.deepStrictEqual(s.overlayRemote, [400, 300], 'overlay shows the remote pointer');
                assert.strictEqual(s.upstreamCursor, 'none', 'the page\'s own trackpad cursor is hidden');
                await h.reset();
                await h.tap(50, 50); await h.wait(400);
                s = await h.state();
                assert.deepStrictEqual(touchCalls(s.calls), [], 'no dtouch* or dmouse* call');
                assert.deepStrictEqual(s.packets.map(decode).map(p => [p.button, p.x, p.y]), [[2, 400, 300], [4, 400, 300]], 'a tap clicks at the remote pointer, not the finger');
                assert(s.calls.includes('setSessionActivity'), 'the page idle timer is kept alive');
                await h.reset();
                await h.touch('touchStart', [[1, 100, 100]]); await h.wait(100); await h.touch('touchMove', [[1, 140, 120]]); await h.touch('touchMove', [[1, 180, 140]]); await h.touch('touchEnd', []);
                s = await h.state();
                const last = decode(s.packets[s.packets.length - 1]);
                assert(last.x > 400 && last.y > 300 && last.button === 0, 'a drag moves the remote pointer right and down');
                assert(Math.abs(s.overlayRemote[0] - last.x) <= 1 && Math.abs(s.overlayRemote[1] - last.y) <= 1, `overlay ${s.overlayRemote} within 1 px of ${last.x},${last.y}`);
                await h.reset();
                await h.touch('touchStart', [[1, 100, 100], [2, 140, 100]]); await h.wait(40); await h.touch('touchEnd', []); await h.wait(50);
                s = await h.state();
                assert.deepStrictEqual(buttons(s.packets), [8, 16], 'two-finger tap is a right click');
                await h.reset();
                await h.touch('touchStart', [[1, 100, 200], [2, 140, 200]]); await h.touch('touchMove', [[1, 100, 150], [2, 140, 150]]); await h.touch('touchMove', [[1, 100, 100], [2, 140, 100]]); await h.touch('touchEnd', []);
                s = await h.state();
                assert(s.packets.length >= 3 && s.packets.every(p => p.startsWith('0002000c') && p.endsWith('ff88')), `two-finger drag up scrolls one -120 packet per notch: ${s.packets}`);
                assert.deepStrictEqual(h.errors, []);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'turning trackpad off mid-drag releases the button', async () => {
            const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
            try {
                await enableTrackpad(h); await h.reset();
                await h.tap(100, 100); await h.wait(80);
                await h.touch('touchStart', [[1, 100, 100]]); await h.touch('touchMove', [[1, 150, 100]]);
                let s = await h.state();
                assert.deepStrictEqual(s.pressed, ['1'], 'dragging with the left button');
                await h.click(viewName === 'mobile' ? 'exitfull' : 'toggle');
                await h.wait(30);
                s = await h.state();
                assert.strictEqual(s.active, false);
                assert.deepStrictEqual(s.pressed, []);
                assert.strictEqual(buttons(s.packets).slice(-1)[0], 4, 'left released on the wire');
                await h.touch('touchEnd', []);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'a hidden page mid-drag releases the button', async () => {
            const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
            try {
                await enableTrackpad(h); await h.reset();
                await h.tap(100, 100); await h.wait(80);
                await h.touch('touchStart', [[1, 100, 100]]); await h.touch('touchMove', [[1, 150, 100]]);
                await h.page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true }); document.dispatchEvent(new Event('visibilitychange')); });
                const s = await h.state();
                assert.deepStrictEqual(s.pressed, []);
                assert.strictEqual(buttons(s.packets).slice(-1)[0], 4);
            } finally { await h.close(); }
        });

        if (viewName === 'default3') {
            await record('chromium', viewName, 'Input off mid-drag releases, and touches then send nothing', async () => {
                const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
                try {
                    await enableTrackpad(h); await h.reset();
                    await h.tap(100, 100); await h.wait(80);
                    await h.touch('touchStart', [[1, 100, 100]]); await h.touch('touchMove', [[1, 150, 100]]);
                    await h.click('DeskControl');
                    let s = await h.state();
                    assert.deepStrictEqual(s.pressed, []);
                    assert.strictEqual(buttons(s.packets).slice(-1)[0], 4);
                    await h.touch('touchEnd', []); await h.reset();
                    await h.tap(100, 100); await h.wait(400);
                    s = await h.state();
                    assert.deepStrictEqual(s.packets, []); assert.deepStrictEqual(touchCalls(s.calls), [], 'still owned, still no page handlers');
                } finally { await h.close(); }
            });

            await record('chromium', viewName, 'a replaced canvas is still owned', async () => {
                const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
                try {
                    await enableTrackpad(h);
                    await h.page.evaluate(html => { QH('DeskParent', html); desktop.m.CanvasId = Q('Desk'); desktop.m.Canvas = Q('Desk').getContext('2d'); desktop.m.Canvas.canvas.width = 800; desktop.m.Canvas.canvas.height = 600; }, DEFAULT3_BLANK_CANVAS);
                    await h.reset();
                    await h.tap(100, 100); await h.wait(400);
                    const s = await h.state();
                    assert.deepStrictEqual(touchCalls(s.calls), []);
                    assert.deepStrictEqual(buttons(s.packets), [2, 4]);
                } finally { await h.close(); }
            });

            await record('chromium', viewName, 'native-zoom pinch zooms locally, keeps the remote pointer, and follow scrolls', async () => {
                const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
                try {
                    await h.page.evaluate(() => { _mobileZoomMode = 'native'; document.body.classList.add('native-zoom'); document.documentElement.style.setProperty('--native-desk-w', '400px'); document.documentElement.style.setProperty('--native-desk-h', '300px'); });
                    await enableTrackpad(h); await h.reset();
                    await h.touch('touchStart', [[1, 150, 150], [2, 250, 150]]);
                    await h.touch('touchMove', [[1, 130, 150], [2, 270, 150]]);
                    await h.touch('touchMove', [[1, 100, 150], [2, 300, 150]]);
                    await h.touch('touchEnd', []);
                    let s = await h.state();
                    const width = await h.page.evaluate(() => parseFloat(document.documentElement.style.getPropertyValue('--native-desk-w')));
                    assert(width > 700, `zoomed in (${width}px)`);
                    assert.deepStrictEqual(s.packets, [], 'a pinch sends nothing');
                    assert.deepStrictEqual(s.overlayRemote, [400, 300], 'the overlay still shows the same remote pixel');
                    // Drag the pointer far right: the container scrolls to keep it in view.
                    for (let i = 0; i < 8; i++) { await h.touch('touchStart', [[1, 50, 150]]); await h.touch('touchMove', [[1, 150, 150]]); await h.touch('touchMove', [[1, 250, 150]]); await h.touch('touchEnd', []); }
                    s = await h.state();
                    const scrolled = await h.page.evaluate(() => Q('deskarea3x').scrollLeft);
                    assert(scrolled > 0, 'the container followed the pointer');
                    assert(s.overlayRemote !== null, 'the pointer stays in view');
                    const last = decode(s.packets[s.packets.length - 1]);
                    assert(Math.abs(s.overlayRemote[0] - last.x) <= 1 && Math.abs(s.overlayRemote[1] - last.y) <= 1, `overlay ${s.overlayRemote} vs ${last.x},${last.y}`);
                } finally { await h.close(); }
            });

            await record('chromium', viewName, 'a rotated view moves the remote pointer along the rotated axes', async () => {
                const h = await openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
                try {
                    await h.page.evaluate(() => { desktop.m.setRotation(1); });
                    await enableTrackpad(h); await h.reset();
                    await h.touch('touchStart', [[1, 100, 100]]); await h.wait(100); await h.touch('touchMove', [[1, 160, 100]]); await h.touch('touchEnd', []);
                    const s = await h.state();
                    const last = decode(s.packets[s.packets.length - 1]);
                    // Rotation 1: screen right is remote up.
                    assert(last.y < 300 && Math.abs(last.x - 400) <= 1, `moved along remote -y: ${last.x},${last.y}`);
                } finally { await h.close(); }
            });
        }
    }
}

// Scenarios from the Phase 4 review: paths a click observer alone would miss, and lifecycle edges.
async function reviewScenarios(browser, fx) {
    for (const [viewName, fixture] of Object.entries(fx)) {
        const open = () => openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
        const released = s => { assert.deepStrictEqual(s.pressed, [], 'nothing held'); assert.strictEqual(buttons(s.packets).slice(-1)[0], 4, 'left released on the wire'); };

        await record('chromium', viewName, 'a module without the remote-pixel API (Intel AMT) stays with the page', async () => {
            const h = await open();
            try {
                await h.page.evaluate(() => { for (const n of ['GetRemoteGeometry', 'SendRemotePointer', 'SendRemoteWheel', 'ReleaseAllPointerButtons']) delete desktop.m[n]; });
                await h.click('toggle'); await h.reset();
                await h.tap(100, 100); await h.wait(400);
                const s = await h.state();
                assert.strictEqual(s.active, false);
                assert(touchCalls(s.calls).length > 0, 'the page handles the touches');
                assert.notStrictEqual(s.upstreamCursor, 'none', 'the page\'s own cursor is not hidden');
            } finally { await h.close(); }
        });

        for (const [gate, set] of [['a dialog', 'xxdialogMode = 2'], ['trackpad mode reset (disconnect)', 'trackpadMode = false']].concat(viewName === 'default3' ? [['Input unchecked by a rights refresh', "Q('DeskControl').checked = false"]] : [])) {
            await record('chromium', viewName, `${gate} mid-drag, finger still, releases within the watchdog period`, async () => {
                const h = await open();
                try {
                    await h.click('toggle'); await h.reset();
                    await h.drag(100, 100);
                    assert.deepStrictEqual((await h.state()).pressed, ['1']);
                    await h.page.evaluate(set);
                    await h.wait(300);
                    released(await h.state());
                    await h.touch('touchEnd', []);
                } finally { await h.close(); }
            });
        }

        for (const [what, how] of [['blur', () => 'window.dispatchEvent(new Event("blur"))'], ['touchcancel', null], ['a new SCREEN', () => 'desktop.m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 4, 0, 3, 0]))'], ['the connection going down', () => 'ctl.onStateChanged(0)']]) {
            await record('chromium', viewName, `${what} mid-drag releases`, async () => {
                const h = await open();
                try {
                    await h.click('toggle'); await h.reset();
                    await h.drag(100, 100);
                    if (how) await h.page.evaluate(how());
                    else await h.page.evaluate(() => Q('Desk').dispatchEvent(new TouchEvent('touchcancel', { bubbles: true, cancelable: false, touches: [], targetTouches: [], changedTouches: [] })));
                    if (what === 'a new SCREEN') await h.touch('touchMove', [[1, 200, 120]]);
                    const s = await h.state();
                    released(s);
                    assert(s.packets.map(decode).every(p => p.x < 1024 && p.y < 768));
                    await h.touch('touchEnd', []);
                } finally { await h.close(); }
            });
        }

        await record('chromium', viewName, 'enabling before the first frame sends the remote centre, and the overlay settles there', async () => {
            const h = await open();
            try {
                await h.page.evaluate(() => { desktop.m.Canvas.canvas.width = 640; desktop.m.Canvas.canvas.height = 480; });
                await h.click('toggle');
                let s = await h.state();
                const first = decode(s.packets[0]);
                assert.deepStrictEqual([first.x, first.y], [400, 300], 'centre of the 800x600 screen, not of the stale canvas');
                await h.page.evaluate(() => { desktop.m.Canvas.canvas.width = 800; desktop.m.Canvas.canvas.height = 600; });
                await h.wait(900);
                s = await h.state();
                assert.deepStrictEqual(s.overlayRemote, [400, 300]);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'the connection coming up again places the pointer at the centre', async () => {
            const h = await open();
            try {
                await h.click('toggle');
                await h.touch('touchStart', [[1, 100, 100]]); await h.wait(100); await h.touch('touchMove', [[1, 160, 130]]); await h.touch('touchEnd', []);
                await h.reset();
                await h.page.evaluate(() => ctl.onStateChanged(3));
                const s = await h.state();
                assert.deepStrictEqual(s.packets.map(decode).map(p => [p.button, p.x, p.y]), [[0, 400, 300]]);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'uninstall restores the page, and install works again', async () => {
            const h = await open();
            try {
                await h.click('toggle');
                assert.strictEqual(await h.touchListeners('#DeskParent'), 4, 'the controller listens on the canvas parent');
                await h.page.evaluate(() => ctl.uninstall());
                assert.strictEqual(await h.touchListeners('#DeskParent'), 0, 'uninstall removes every listener it added');
                assert.strictEqual(await h.page.evaluate(() => document.documentElement.classList.contains(MeshTrackpadController.ACTIVE_CLASS)), false);
                await h.reset();
                await h.tap(100, 100); await h.wait(400);
                let s = await h.state();
                assert(touchCalls(s.calls).includes('dtouchstart'), 'the page handles touches again');
                assert.strictEqual(await h.page.evaluate(() => ctl.overlay()), null);
                await h.page.evaluate(() => ctl.install()); await h.reset();
                await h.tap(100, 100); await h.wait(400);
                s = await h.state();
                assert.deepStrictEqual(touchCalls(s.calls), []);
                assert.deepStrictEqual(buttons(s.packets), [2, 4]);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'long press right-clicks and a three-finger tap middle-clicks', async () => {
            const h = await open();
            try {
                await h.click('toggle'); await h.reset();
                await h.touch('touchStart', [[1, 100, 100]]); await h.wait(600); await h.touch('touchEnd', []);
                await h.touch('touchStart', [[1, 100, 100], [2, 140, 100], [3, 180, 100]]); await h.wait(40); await h.touch('touchEnd', []);
                const s = await h.state();
                assert.deepStrictEqual(buttons(s.packets), [8, 16, 32, 64]);
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'the connect kick during a pending tap release ends with nothing held', async () => {
            const h = await open();
            try {
                await h.click('toggle'); await h.reset();
                await h.tap(100, 100);
                // The page's mobile connect kick: a synthetic down/up straight to the module.
                await h.page.evaluate(() => { const r = desktop.m.CanvasId.getBoundingClientRect(); const ev = { pageX: r.left + window.scrollX + r.width / 2, pageY: r.top + window.scrollY + r.height / 2, button: 0, buttons: 0, which: 1 }; desktop.m.mousedown(ev); desktop.m.mouseup(ev); });
                await h.wait(400);
                const s = await h.state();
                // The kick's own down repeats the held button (a no-op on the remote); what matters is
                // that the remote ends released and nothing is left recorded as held.
                assert.deepStrictEqual(s.pressed, []);
                assert.strictEqual(buttons(s.packets).filter(b => b === 2 || b === 4).slice(-1)[0], 4, 'the last left-button packet is a release');
            } finally { await h.close(); }
        });

        if (viewName !== 'default3') continue;

        await record('chromium', viewName, 'turning trackpad on stops the page\'s edge-scroll interval from a direct-mode drag', async () => {
            const h = await open();
            try {
                // Direct mode: long press, then drag into the 60 px edge zone starts the page's interval.
                await h.touch('touchStart', [[1, 100, 150]]); await h.wait(600); await h.touch('touchMove', [[1, 200, 150]]); await h.touch('touchMove', [[1, 385, 150]]);
                assert.notStrictEqual((await h.state()).edgeTimer, null, 'the page started its interval');
                await h.click('toggle');
                await h.touch('touchEnd', []);
                await h.wait(100); await h.reset(); await h.wait(300);
                const s = await h.state();
                assert.strictEqual(s.edgeTimer, null, 'interval stopped');
                assert.deepStrictEqual(s.packets, [], 'nothing sent with no finger down');
                assert.deepStrictEqual(s.pressed, [], 'the page\'s stranded drag button was released');
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'a WebRTC module switch mid-drag releases on the old module; the new one gets later gestures', async () => {
            const h = await open();
            try {
                await h.click('toggle'); await h.reset();
                await h.drag(100, 100);
                await h.page.evaluate(() => {
                    const hex = p => Array.from(p, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                    window.packets2 = [];
                    const m2 = CreateAgentRemoteDesktop('Desk');
                    m2.parent = { State: 2, send: p => { if (((p.charCodeAt(0) << 8) | p.charCodeAt(1)) === 2) packets2.push(hex(p)); }, xxStateChange: function (s) { this.State = s; m2.xxStateChange(s); } };
                    m2.Start(); m2.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 3, 32, 2, 88]));
                    m2.Canvas.canvas.width = 800; m2.Canvas.canvas.height = 600;
                    webRtcDesktop = { softdesktop: { m: m2 } };
                });
                await h.touch('touchMove', [[1, 180, 100]]);
                let s = await h.state();
                released(s);
                await h.touch('touchEnd', []);
                await h.tap(100, 100); await h.wait(400);
                const two = await h.page.evaluate(() => packets2.slice());
                assert.deepStrictEqual(buttons(two), [2, 4], 'the soft desktop receives the next tap');
            } finally { await h.close(); }
        });

        await record('chromium', viewName, 'a pinch keeps the landing point fixed, is clamped, and works on a scrolled page', async () => {
            const h = await open();
            try {
                await h.page.evaluate(() => { _mobileZoomMode = 'native'; document.body.classList.add('native-zoom'); document.documentElement.style.setProperty('--native-desk-w', '400px'); document.documentElement.style.setProperty('--native-desk-h', '300px'); });
                await h.click('toggle');
                await h.page.evaluate(() => window.scrollTo(0, 40));
                const under = () => h.page.evaluate(() => { const r = Q('Desk').getBoundingClientRect(); const g = desktop.m.GetRemoteGeometry(); const p = g.cssToRemote(200 - r.left, 110 - r.top); return [Math.round(p.x), Math.round(p.y)]; });
                const before = await under();
                // Landing midpoint (200, 110); only the right finger moves.
                await h.touch('touchStart', [[1, 150, 110], [2, 250, 110]]);
                for (const x of [270, 290, 310]) await h.touch('touchMove', [[1, 150, 110], [2, x, 110]]);
                await h.touch('touchEnd', []);
                const after = await under();
                assert(Math.abs(after[0] - before[0]) <= 2 && Math.abs(after[1] - before[1]) <= 2, `the landing point stays put: ${before} -> ${after}`);
                for (let i = 0; i < 6; i++) { await h.touch('touchStart', [[1, 150, 110], [2, 170, 110]]); await h.touch('touchMove', [[1, 100, 110], [2, 300, 110]]); await h.touch('touchEnd', []); }
                const w = await h.page.evaluate(() => parseFloat(document.documentElement.style.getPropertyValue('--native-desk-w')));
                assert(w <= 3200, `clamped at 4x the remote width (${w})`);
            } finally { await h.close(); }
        });
    }
}

async function webkitScenarios(browser, fx) {
    for (const [viewName, fixture] of Object.entries(fx)) {
        await record('webkit', viewName, 'trackpad on: the engine owns touches (dispatched events)', async () => {
            const h = await openPage(browser, fixture, { engine: 'webkit', controller: true, flag: true });
            try {
                await h.click('toggle'); await h.reset();
                await h.tap(50, 50); await h.wait(400);
                const s = await h.state();
                assert.deepStrictEqual(touchCalls(s.calls), []);
                assert.deepStrictEqual(buttons(s.packets), [2, 4]);
                assert.deepStrictEqual(h.errors, []);
            } finally { await h.close(); }
        });
        await record('webkit', viewName, 'a real WebKit tap is owned: no page handler or compatibility click', async () => {
            const h = await openPage(browser, fixture, { engine: 'webkit', controller: true, flag: true });
            try {
                await h.click('toggle'); await h.reset();
                await h.page.touchscreen.tap(60, 60); await h.wait(400);
                const s = await h.state();
                assert.deepStrictEqual(touchCalls(s.calls), []);
                assert.deepStrictEqual(buttons(s.packets), [2, 4]);
                await h.drag(100, 100);
                await h.page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true }); document.dispatchEvent(new Event('visibilitychange')); });
                assert.deepStrictEqual((await h.state()).pressed, []);
            } finally { await h.close(); }
        });
        await record('webkit', viewName, 'flag off is identical to no controller', async () => {
            const base = await openPage(browser, fixture, { engine: 'webkit', controller: false });
            const off = await openPage(browser, fixture, { engine: 'webkit', controller: true, flag: false });
            try {
                await base.click('toggle'); await off.click('toggle'); await base.reset(); await off.reset();
                const a = await scripted(base), b = await scripted(off);
                assert.deepStrictEqual(b.calls, a.calls); assert.deepStrictEqual(b.packets, a.packets);
                assert(touchCalls(a.calls).length > 0, 'the page handled the touches itself');
            } finally { await base.close(); await off.close(); }
        });
    }
}

async function main() {
    const playwright = require(require.resolve('playwright', { paths: [__dirname] }));
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/trackpad-adapters/current');
    const fx = fixtures();
    for (const engine of ['chromium', 'webkit']) {
        const browser = await playwright[engine].launch({ headless: true });
        try { if (engine === 'chromium') { await chromiumScenarios(browser, fx); await reviewScenarios(browser, fx); } else await webkitScenarios(browser, fx); }
        finally { await browser.close(); }
    }
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(results, null, 2));
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.engine} ${r.view} ${r.name}${r.ok ? '' : ': ' + r.error}`);
    if (!results.length || results.some(r => !r.ok)) process.exitCode = 1;
}

main().catch(error => { console.error(error); process.exitCode = 1; });
