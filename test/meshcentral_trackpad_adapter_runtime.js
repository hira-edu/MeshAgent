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
const { meshcentralRoot, installedPackageDir } = require('./lib/meshcentral_paths');

const meshcentral = meshcentralRoot();
const scripts = path.join(meshcentral, 'public/scripts');
const views = path.join(installedPackageDir().dir, 'views');

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
// The guest share page's canvas has no touch handlers: the browser's compatibility mouse events drive it.
const SHARING_CANVAS = '<canvas id=Desk width=640 height=200 style="width:100%;-ms-touch-action:none;margin-left:0px" oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event)></canvas>';

// The desktop guest share page (also iPadOS's default): no touch handlers, and a blank canvas
// replaces this one when it connects.
const DESKTOP_SHARE_CANVAS = '<canvas id=Desk width=640 height=480 oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event)></canvas>';
const DESKTOP_SHARE_BLANK_CANVAS = '<canvas id=Desk oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event)></canvas>';
const DESKTOP_SHARE_INPUT = '<label><span id="DeskControlSpan" title="Toggle mouse and keyboard input"><input id="DeskControl" type="checkbox" onkeypress="return false" onkeydown="return false" onclick="toggleKvmControl()" />Input</span></label>&nbsp;';

function fixtures() {
    const d3 = view('default3.handlebars'), dm = view('default-mobile.handlebars'), sm = view('sharing-mobile.handlebars'), sd = view('sharing.handlebars');
    assert(d3.includes(DEFAULT3_CANVAS) && d3.includes(DEFAULT3_BLANK_CANVAS) && dm.includes(MOBILE_CANVAS) && sm.includes(SHARING_CANVAS), 'fixture canvas markup must match the pinned views');
    assert(sd.includes(DESKTOP_SHARE_CANVAS) && sd.includes(DESKTOP_SHARE_BLANK_CANVAS) && sd.includes(DESKTOP_SHARE_INPUT), 'desktop share fixture markup must match the pinned view');
    const line = (source, start) => slice(source, start, '\n', start.trim());
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
${slice(d3, '        function _mobileSetZoom(mode) {', '        // Watch body class for fulldesk being added/removed', 'default3 zoom mode switch')}
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
        },
        sharing: {
            // #toggle is a test shim that presses whichever trackpad button the adapter shows.
            adapter: 'sharingMobile', script: 'agent-desktop-trackpad-sharing-mobile-0.0.1.js', guest: true,
            page: `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>body{margin:0} .deskButton{position:absolute;right:10px;width:40px;height:40px;z-index:1000}</style></head><body>
<div id=p10 style="position:absolute;left:0;top:0;width:400px;height:355px;overflow:hidden">
<img id="deskkeybutton2b" class="deskButton" style="top:210px;display:none" />
<div id=p10desktop style="overflow:hidden;position:absolute;top:55px;bottom:0px;width:100%"><div id=deskarea3><div id=DeskParent style="height:100%">${SHARING_CANVAS}</div></div></div></div>
<button id="toggle" style="position:absolute;left:520px;top:80px;width:80px;height:40px" onclick="var b = ['meshTrackpadOn', 'meshTrackpadOff'].map(Q).filter(function (e) { return e && e.style.display !== 'none'; })[0]; if (b) b.click();">trackpad</button>
<button id="exitfull" style="position:absolute;left:520px;top:140px;width:80px;height:40px" onclick="fullscreen = false;">exit</button>
<script>
window.calls = []; window.packets = [];
function Q(id) { return document.getElementById(id); } function QV() {} function QS(id) { return (Q(id) || { style: {} }).style; }
var xxdialogMode = 0, desktop = null, fullscreen = true, fullscreenzoom = 1, viewOnly = 0, currentDevicePanel = 1, features2 = 0;
function setSessionActivity() { calls.push('setSessionActivity'); } function haltEvent(e) { if (e.preventDefault) e.preventDefault(); if (e.stopPropagation) e.stopPropagation(); return false; }
</script><script>${slice(sm, '        function dmousedown(e) {', '        //\n        // TERMINAL', 'sharing-mobile handlers')}</script></body></html>`,
            overrides: ''
        },
        desktopShare: {
            // #toggle is a test shim that clicks the adapter's Trackpad checkbox when it is shown.
            // The layout rules are style.css's for #deskarea3x, #DeskParent and #Desk.
            adapter: 'sharing', script: 'agent-desktop-trackpad-sharing-0.0.1.js', guest: true, blankCanvas: DESKTOP_SHARE_BLANK_CANVAS,
            page: `<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1"><style>body{margin:0}
#deskarea3x{position:absolute;left:0;top:0;width:400px;height:300px;overflow:hidden;background:#000;text-align:center}
#DeskParent{margin:0;overflow:hidden;height:100%;width:100%;position:absolute;right:0;top:0}
#Desk{overflow:hidden;width:100%;touch-action:none;position:absolute;top:0;bottom:0;left:0;right:0;margin:auto}
#deskarea4{position:absolute;left:420px;top:200px}</style></head><body>
<div id=deskarea3x><div id=DeskParent>${DESKTOP_SHARE_CANVAS}</div></div>
<div id=deskarea4><div>${DESKTOP_SHARE_INPUT}</div></div>
<button id="toggle" style="position:absolute;left:520px;top:80px;width:80px;height:40px" onclick="var l = Q('meshTrackpadLabel'); if (l && l.style.display !== 'none') Q('meshTrackpadToggle').click();">trackpad</button>
<script>
window.calls = []; window.packets = [];
function Q(id) { return document.getElementById(id); } function QV() {} function QS(id) { return (Q(id) || { style: {} }).style; } function QH(id, h) { var e = Q(id); if (e) e.innerHTML = h; }
var viewOnly = 0;
var xxdialogMode = 0, desktop = null, webRtcDesktop = null;
function setSessionActivity() { calls.push('setSessionActivity'); } function haltEvent(e) { if (e.preventDefault) e.preventDefault(); if (e.stopPropagation) e.stopPropagation(); return false; }
${line(sd, '        function isInputAllowed() {')}
${line(sd, '        function toggleKvmControl() {')}
Q('DeskControl').checked = true;
</script><script>${slice(sd, '        // Double click detection. This is important for macOS.', '        function drotate(x) {', 'sharing handlers')}</script></body></html>`,
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
            return { calls: calls.slice(), packets: packets.slice(), overlayRemote, upstreamCursor: cursor ? getComputedStyle(cursor).display : null, pressed: Object.keys(desktop.m.browserPressedButtons), active: !!(window.ctl && window.ctl.isActive()), edgeTimer: (typeof trackpadEdgeTimer === 'undefined') ? null : trackpadEdgeTimer };
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
                if (!fixture.guest) assert.strictEqual(s.upstreamCursor, 'none', 'the page\'s own trackpad cursor is hidden');
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
                await h.click((viewName === 'default3' || viewName === 'desktopShare') ? 'toggle' : 'exitfull');
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

        // The guest page has no trackpad mode of its own: leaving fullscreen (as a disconnect does) turns the adapter's off.
        // The desktop guest page's mode goes off only with the connection, which cannot carry a release.
        const modeReset = viewName === 'desktopShare' ? null : fixture.guest ? ['fullscreen left (disconnect)', 'fullscreen = false'] : ['trackpad mode reset (disconnect)', 'trackpadMode = false'];
        for (const [gate, set] of [['a dialog', 'xxdialogMode = 2'], modeReset].filter(Boolean).concat((viewName === 'default3' || viewName === 'desktopShare') ? [['Input unchecked by a rights refresh', "Q('DeskControl').checked = false"]] : [])) {
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

        await record('chromium', viewName, 'the connection going down mid-drag deactivates and leaves nothing held', async () => {
            const h = await open();
            try {
                await h.click('toggle'); await h.reset();
                await h.drag(100, 100);
                // Real order: the module reports state 0 (and stops) before the page's own handler runs.
                await h.page.evaluate(() => { desktop.m.xxStateChange(0); ctl.onStateChanged(0); });
                const s = await h.state();
                assert.deepStrictEqual(s.pressed, []);
                assert.strictEqual(s.active, false, 'a disconnected module does not count as trackpad mode');
                assert.strictEqual(await h.page.evaluate(() => ctl.engine.isActive()), false);
                await h.touch('touchEnd', []);
            } finally { await h.close(); }
        });

        for (const [what, how] of [['blur', () => 'window.dispatchEvent(new Event("blur"))'], ['touchcancel', null], ['a new SCREEN', () => 'desktop.m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 4, 0, 3, 0]))']]) {
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
                assert(touchCalls(s.calls).includes(fixture.guest ? 'dmousedown' : 'dtouchstart'), 'the page handles touches again');
                assert.strictEqual(await h.page.evaluate(() => ctl.overlay()), null);
                await h.page.evaluate(() => ctl.install());
                // Uninstalling removes the guest page's trackpad button, and with it the mode.
                if (fixture.guest) await h.click('toggle');
                await h.reset();
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

// Following the pointer in each zoomed or fullscreen layout, the arrow's size, and the guest page's
// own trackpad toggle.
async function zoomAndGuestScenarios(browser, fx) {
    const open = fixture => openPage(browser, fixture, { engine: 'chromium', controller: true, flag: true });
    // Several quick one-finger drags to the right: each moves the remote pointer further right.
    const pushRight = async (h, times, x0, y) => { for (let i = 0; i < times; i++) { await h.touch('touchStart', [[1, x0, y]]); await h.touch('touchMove', [[1, x0 + 60, y]]); await h.touch('touchMove', [[1, x0 + 120, y]]); await h.touch('touchEnd', []); } };
    const overlayClient = h => h.page.evaluate(() => { const o = ctl.overlay(); return o.style.display === 'block' ? [parseFloat(o.style.left), parseFloat(o.style.top)] : null; });
    const arrowHeight = h => h.page.evaluate(() => parseFloat(ctl.overlay().firstChild.getAttribute('height')));

    await record('chromium', 'default3', 'a pinch in fit mode switches to native zoom from the fit size, then the view follows the pointer', async () => {
        const h = await open(fx.default3);
        try {
            await h.click('toggle'); await h.reset();
            await h.touch('touchStart', [[1, 150, 150], [2, 250, 150]]);
            for (const d of [20, 50, 100]) await h.touch('touchMove', [[1, 150 - d, 150], [2, 250 + d, 150]]);
            await h.touch('touchEnd', []);
            const z = await h.page.evaluate(() => ({ mode: _mobileZoomMode, cls: document.body.classList.contains('native-zoom'), w: parseFloat(document.documentElement.style.getPropertyValue('--native-desk-w')) }));
            assert.strictEqual(z.mode, 'native'); assert.strictEqual(z.cls, true);
            // Fit size is 400 px wide; a 3x spread from there is about 1200 px, not 3x the 800 px screen.
            assert(z.w > 900 && z.w < 1500, `zoomed from the fit size (${z.w}px)`);
            assert.deepStrictEqual((await h.state()).packets, [], 'a pinch sends nothing');
            await pushRight(h, 6, 50, 150);
            assert(await h.page.evaluate(() => Q('deskarea3x').scrollLeft) > 0, 'the container followed the pointer');
            const s = await h.state(), last = decode(s.packets[s.packets.length - 1]);
            assert(s.overlayRemote && Math.abs(s.overlayRemote[0] - last.x) <= 1, `overlay ${s.overlayRemote} shows the pointer at ${last.x}`);
            assert.deepStrictEqual(h.errors, []);
        } finally { await h.close(); }
    });

    // The real mobile stylesheet centres the canvas in #DeskParent, and native zoom puts it back at
    // the scroller's origin (style-bootstrap.css, pinned through the view's own markup).
    const mobileCss = () => h => h.page.addStyleTag({ content: 'body.is-mobile #DeskParent{display:flex!important;align-items:center!important;justify-content:center!important} body.is-mobile.native-zoom #DeskParent{display:block!important} body.is-mobile.native-zoom #Desk{width:100%!important;height:100%!important}' });
    const remoteUnder = (h, x, y) => h.page.evaluate(([x, y]) => { const r = Q('Desk').getBoundingClientRect(); const p = desktop.m.GetRemoteGeometry().cssToRemote(x - r.left, y - r.top); return [Math.round(p.x), Math.round(p.y)]; }, [x, y]);
    const nativeSize = h => h.page.evaluate(() => ['--native-desk-w', '--native-desk-h'].map(v => parseFloat(document.documentElement.style.getPropertyValue(v))));
    const pinch = async (h, cx, cy, from, to) => { await h.touch('touchStart', [[1, cx - from, cy], [2, cx + from, cy]]); for (const d of [from + (to - from) / 3, from + 2 * (to - from) / 3, to]) await h.touch('touchMove', [[1, cx - d, cy], [2, cx + d, cy]]); await h.touch('touchEnd', []); };

    await record('chromium', 'default3', 'a fit-mode pinch on a letterboxed canvas keeps the picture point under the fingers', async () => {
        const h = await open(fx.default3);
        try {
            await mobileCss()(h);
            // A 400x400 area: the 4:3 fit canvas is 400x300, centred 50 px down.
            await h.page.evaluate(() => { QS('deskarea3x').height = '400px'; QS('Desk').height = '300px'; });
            await h.click('toggle'); await h.reset();
            const before = await remoteUnder(h, 200, 150);
            await pinch(h, 200, 150, 50, 150);
            const after = await remoteUnder(h, 200, 150), size = await nativeSize(h);
            assert(Math.abs(after[0] - before[0]) <= 3 && Math.abs(after[1] - before[1]) <= 3, `the point under the fingers stays put: ${before} -> ${after}`);
            assert(size[0] > 1000 && Math.abs(size[1] / size[0] - 0.75) < 0.01, `zoomed from the fit size with the screen's shape: ${size}`);
        } finally { await h.close(); }
    });

    await record('chromium', 'default3', 'a fit-mode pinch on a stretched canvas keeps the remote screen\'s shape', async () => {
        const h = await open(fx.default3);
        try {
            // Landscape fullscreen stretches the canvas to its area: here a 4:3 screen on a 400x200 one.
            await h.page.evaluate(() => { QS('deskarea3x').height = '200px'; });
            await h.click('toggle');
            await pinch(h, 200, 100, 40, 80);
            const size = await nativeSize(h);
            assert(Math.abs(size[1] / size[0] - 0.75) < 0.01, `native size follows the screen's 4:3 shape, not the stretch: ${size}`);
        } finally { await h.close(); }
    });

    await record('chromium', 'default3', 'zooming out after a fit-mode pinch stops at the fit size, and only for that screen size', async () => {
        const h = await open(fx.default3);
        try {
            // A 2000x1500 screen fits at 400 px wide, below upstream's quarter-size floor of 500.
            await h.page.evaluate(() => { desktop.m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 0x07, 0xd0, 0x05, 0xdc])); desktop.m.Canvas.canvas.width = 2000; desktop.m.Canvas.canvas.height = 1500; });
            await h.click('toggle');
            await pinch(h, 200, 150, 50, 100);
            await pinch(h, 200, 150, 150, 10);
            assert.deepStrictEqual(await nativeSize(h), [400, 300], 'back to the fit size, not clamped up to 500');
            // Another screen size: the floor taken for the old one no longer applies.
            await h.page.evaluate(() => { desktop.m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 0x07, 0xd0, 0x07, 0xd0])); desktop.m.Canvas.canvas.width = 2000; desktop.m.Canvas.canvas.height = 2000; });
            await h.click('toggle'); await h.click('toggle');
            await pinch(h, 200, 150, 150, 10);
            assert.deepStrictEqual(await nativeSize(h), [500, 500], 'upstream\'s quarter-size floor for the new screen');
        } finally { await h.close(); }
    });

    await record('chromium', 'default3', 'with the browser pinch-zoomed, the zoomed view pans to follow the pointer', async () => {
        const h = await open(fx.default3);
        try {
            await h.click('toggle'); await h.reset();
            await h.cdp.send('Emulation.setPageScaleFactor', { pageScaleFactor: 2.5 });
            await h.wait(100);
            const before = await h.page.evaluate(() => [visualViewport.scale, visualViewport.offsetLeft, visualViewport.offsetTop, document.scrollingElement.scrollHeight > innerHeight]);
            assert(before[0] > 2 && before[1] === 0 && before[2] === 0 && before[3], `zoomed at the top left of a page that can scroll: ${before}`);
            await pushRight(h, 4, 40, 60);
            for (let i = 0; i < 4; i++) { await h.touch('touchStart', [[1, 60, 20]]); await h.touch('touchMove', [[1, 60, 70]]); await h.touch('touchMove', [[1, 60, 120]]); await h.touch('touchEnd', []); }
            const vv = await h.page.evaluate(() => [visualViewport.offsetLeft, visualViewport.offsetLeft + visualViewport.width, visualViewport.offsetTop, visualViewport.offsetTop + visualViewport.height, scrollX, scrollY, Q('deskarea3x').scrollLeft, Q('deskarea3x').scrollTop]);
            const p = await overlayClient(h);
            assert(vv[0] > 0 && vv[2] > 0, `the zoomed view panned right and down: ${vv}`);
            assert(p && p[0] >= vv[0] && p[0] <= vv[1] && p[1] >= vv[2] && p[1] <= vv[3], `the pointer ${p} is in the zoomed view ${vv}`);
            assert.deepStrictEqual(vv.slice(4), [0, 0, 0, 0], 'neither the scrollable page nor the fit-mode container scrolled');
        } finally { await h.close(); }
    });

    await record('chromium', 'default3', 'the arrow is sized like the remote pointer at the current zoom, within bounds', async () => {
        const h = await open(fx.default3);
        try {
            await h.click('toggle');
            assert.strictEqual(await arrowHeight(h), 16, 'fit mode (2 remote px per CSS px): the minimum');
            const native = async w => { await h.page.evaluate(w => { _mobileZoomMode = 'native'; document.body.classList.add('native-zoom'); document.documentElement.style.setProperty('--native-desk-w', w + 'px'); document.documentElement.style.setProperty('--native-desk-h', (w * 3 / 4) + 'px'); ctl.evaluate(); }, w); return arrowHeight(h); };
            assert.strictEqual(await native(800), 20, '1:1: a Windows arrow\'s height');
            assert.strictEqual(await native(1600), 24, '2x: the maximum');
            await native(800);
            await h.cdp.send('Emulation.setPageScaleFactor', { pageScaleFactor: 2 });
            await h.wait(100); await h.page.evaluate(() => ctl.evaluate());
            assert.strictEqual(await arrowHeight(h), 12, 'browser zoom 2x at 1:1: 24 px on screen, the maximum');
        } finally { await h.close(); }
    });

    for (const viewName of ['mobile', 'sharing']) {
        await record('chromium', viewName, 'fullscreen at 1x scrolls the fullscreen view to follow the pointer', async () => {
            const h = await open(fx[viewName]);
            try {
                // What deskToggleFull sets for fullscreen at zoom 1 on an 800x600 screen.
                await h.page.evaluate(() => { QS('p10desktop').overflow = 'scroll'; QS('deskarea3').width = '800px'; QS('deskarea3').height = '600px'; });
                await h.click('toggle'); await h.reset();
                await pushRight(h, 6, 50, 120);
                assert(await h.page.evaluate(() => Q('p10desktop').scrollLeft) > 0, 'p10desktop followed the pointer');
                const s = await h.state(), last = decode(s.packets[s.packets.length - 1]);
                assert(s.overlayRemote && Math.abs(s.overlayRemote[0] - last.x) <= 1, `overlay ${s.overlayRemote} shows the pointer at ${last.x}`);
            } finally { await h.close(); }
        });
    }

    await record('chromium', 'sharing', 'the guest trackpad button shows only in fullscreen with input, and leaving fullscreen turns the mode off', async () => {
        const h = await open(fx.sharing);
        const shown = () => h.page.evaluate(() => ['meshTrackpadOn', 'meshTrackpadOff'].map(id => Q(id) && Q(id).style.display));
        try {
            assert.deepStrictEqual(await shown(), ['block', 'none'], 'offered in fullscreen');
            assert.strictEqual(await h.page.evaluate(() => Q('meshTrackpadOn').previousElementSibling.id), 'deskkeybutton2b', 'next to the page\'s fullscreen buttons');
            await h.click('meshTrackpadOn');
            let s = await h.state();
            assert.strictEqual(s.active, true);
            assert.deepStrictEqual(await shown(), ['none', 'block']);
            await h.reset(); await h.tap(100, 100); await h.wait(400);
            s = await h.state();
            assert.deepStrictEqual(buttons(s.packets), [2, 4], 'a tap clicks at the remote pointer');
            assert.deepStrictEqual(touchCalls(s.calls), [], 'no compatibility mouse event reached the page');
            await h.click('meshTrackpadOff');
            assert.strictEqual((await h.state()).active, false, 'the button turns it off');
            await h.click('meshTrackpadOn');
            await h.click('exitfull');
            assert.strictEqual((await h.state()).active, false, 'leaving fullscreen turns it off');
            assert.deepStrictEqual(await shown(), ['none', 'none']);
            await h.page.evaluate(() => { fullscreen = true; ctl.evaluate(); });
            assert.deepStrictEqual(await shown(), ['block', 'none'], 'offered again, but off');
            assert.strictEqual((await h.state()).active, false);
            await h.page.evaluate(() => ctl.uninstall());
            assert.deepStrictEqual(await shown(), [null, null], 'uninstall removes the buttons');
            assert.deepStrictEqual(h.errors, []);
        } finally { await h.close(); }
    });

    for (const viewName of ['mobile', 'sharing']) {
        await record('chromium', viewName, 'with the top menu open, a tap only closes it; the next tap clicks', async () => {
            const h = await open(fx[viewName]);
            try {
                await h.click('toggle'); await h.reset();
                await h.page.evaluate(() => { xxdialogMode = 999; window.QV = function (id, v) { calls.push('QV ' + id + ' ' + v); }; });
                await h.tap(100, 100); await h.wait(400);
                let s = await h.state();
                assert.strictEqual(await h.page.evaluate(() => xxdialogMode), 0, 'the menu is closed');
                assert(s.calls.includes('QV topMenu false'), 'through the page\'s own QV');
                assert.deepStrictEqual(s.packets, [], 'the closing tap sends nothing');
                await h.tap(100, 100); await h.wait(400);
                assert.deepStrictEqual(buttons((await h.state()).packets), [2, 4], 'the next tap clicks');
            } finally { await h.close(); }
        });
    }

    await record('chromium', 'sharing', 'a view-only share link, or the terminal panel, offers no trackpad mode', async () => {
        for (const set of ['viewOnly = 1', 'desktop.m.stopInput = true', 'currentDevicePanel = 5']) {
            const h = await open(fx.sharing);
            try {
                await h.page.evaluate(set); await h.page.evaluate(() => ctl.evaluate());
                assert.deepStrictEqual(await h.page.evaluate(() => ['meshTrackpadOn', 'meshTrackpadOff'].map(id => Q(id).style.display)), ['none', 'none'], set);
                await h.click('toggle');
                assert.strictEqual((await h.state()).active, false, set);
            } finally { await h.close(); }
        }
    });

    const shownBox = h => h.page.evaluate(() => { const l = Q('meshTrackpadLabel'); return l ? [l.style.display !== 'none', Q('meshTrackpadToggle').checked] : null; });

    await record('chromium', 'desktopShare', 'the Trackpad checkbox sits beside Input, turns the mode on and off, and owns taps', async () => {
        const base = await openPage(browser, fx.desktopShare, { engine: 'chromium', controller: false });
        const footer = p => p.evaluate(() => Q('DeskControlSpan').parentNode.parentNode.innerHTML);
        const pageFooter = await footer(base.page);
        await base.close();
        const h = await open(fx.desktopShare);
        try {
            assert.deepStrictEqual(await shownBox(h), [true, false], 'offered on a touch device');
            const order = await h.page.evaluate(() => Array.from(Q('DeskControlSpan').parentNode.parentNode.childNodes).map(n => n.nodeType === 3 ? JSON.stringify(n.nodeValue) : n.tagName + (n.id ? '#' + n.id : '') + (n.nodeName === 'SPAN' ? JSON.stringify(n.textContent) : '')));
            assert.deepStrictEqual(order, ['LABEL', 'SPAN"\u00a0"', 'LABEL#meshTrackpadLabel', '"\u00a0"'], `Input, a space, Trackpad, then the page's own space: ${order}`);
            await h.click('meshTrackpadToggle');
            let s = await h.state();
            assert.strictEqual(s.active, true);
            assert.strictEqual(s.packets.length, 1, 'enabling sends one move to the centre');
            assert.deepStrictEqual(await shownBox(h), [true, true]);
            await h.reset(); await h.tap(100, 100); await h.wait(400);
            s = await h.state();
            assert.deepStrictEqual(buttons(s.packets), [2, 4], 'a tap clicks at the remote pointer');
            assert.deepStrictEqual(touchCalls(s.calls), [], 'no compatibility mouse event reached the page');
            await h.click('meshTrackpadToggle');
            assert.strictEqual((await h.state()).active, false, 'unchecking turns it off');
            await h.reset(); await h.tap(100, 100); await h.wait(400);
            assert(touchCalls((await h.state()).calls).includes('dmousedown'), 'the page handles taps again');
            await h.click('meshTrackpadToggle');
            await h.page.evaluate(() => ctl.uninstall());
            assert.strictEqual(await shownBox(h), null, 'uninstall removes the checkbox');
            assert.strictEqual(await footer(h.page), pageFooter, 'and its spacing: the footer is the page\'s own again');
            assert.deepStrictEqual(h.errors, []);
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'no checkbox without touch, on a view-only link, with input stopped, or disconnected; disconnecting turns the mode off', async () => {
        for (const set of ['delete Window.prototype.ontouchstart; delete window.ontouchstart; Object.defineProperty(navigator, "maxTouchPoints", { value: 0 })', 'viewOnly = 1', 'desktop.m.stopInput = true', 'desktop.m.State = 0']) {
            const h = await open(fx.desktopShare);
            try {
                await h.click('toggle');
                assert.strictEqual((await h.state()).active, true, set);
                await h.page.evaluate(set); await h.page.evaluate(() => ctl.evaluate());
                assert.deepStrictEqual(await shownBox(h), [false, false], set);
                assert.strictEqual((await h.state()).active, false, set);
                assert.deepStrictEqual((await h.state()).pressed, [], set);
            } finally { await h.close(); }
        }
    });

    await record('chromium', 'desktopShare', 'enabling with Input unchecked sends nothing; checking Input lets taps through', async () => {
        const h = await open(fx.desktopShare);
        try {
            await h.page.evaluate(() => { Q('DeskControl').checked = false; });
            await h.click('meshTrackpadToggle');
            assert.strictEqual((await h.state()).active, true);
            await h.tap(100, 100); await h.wait(400);
            await h.touch('touchStart', [[1, 100, 100]]); await h.touch('touchMove', [[1, 160, 100]]); await h.touch('touchEnd', []);
            let s = await h.state();
            assert.deepStrictEqual(s.packets, [], 'not even the centring move');
            assert.strictEqual(s.overlayRemote, null, 'no arrow while input is blocked');
            await h.page.evaluate(() => { Q('DeskControl').checked = true; });
            await h.tap(100, 100); await h.wait(400);
            s = await h.state();
            assert.deepStrictEqual(buttons(s.packets), [2, 4]);
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'another panel of the page hides the arrow; coming back shows it', async () => {
        const h = await open(fx.desktopShare);
        try {
            await h.click('toggle');
            assert.notStrictEqual((await h.state()).overlayRemote, null);
            // go(12) hides the desktop panel, so the canvas has no box.
            await h.page.evaluate(() => { QS('deskarea3x').display = 'none'; ctl.evaluate(); });
            assert.strictEqual(await h.page.evaluate(() => ctl.overlay().style.display), 'none', 'no arrow over the terminal or files panel');
            await h.page.evaluate(() => { QS('deskarea3x').display = ''; ctl.evaluate(); });
            assert.deepStrictEqual((await h.state()).overlayRemote, [400, 300]);
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'Space on the focused checkbox does not toggle it; detection needs the page\'s own input rule and no trackpad mode', async () => {
        const h = await open(fx.desktopShare);
        try {
            await h.page.focus('#meshTrackpadToggle'); await h.page.keyboard.press(' ');
            assert.deepStrictEqual(await shownBox(h), [true, false], 'still off');
            assert.strictEqual((await h.state()).active, false);
            const detect = () => h.page.evaluate(() => MeshTrackpadAdapters.sharing.detect());
            assert.strictEqual(await detect(), true);
            assert.strictEqual(await h.page.evaluate(() => { window.trackpadMode = false; const d = MeshTrackpadAdapters.sharing.detect(); delete window.trackpadMode; return d; }), false, 'a page with its own trackpad mode');
            assert.strictEqual(await h.page.evaluate(() => { window._mobileZoomMode = 'fit'; const d = MeshTrackpadAdapters.sharing.detect(); delete window._mobileZoomMode; return d; }), false, 'the Modern UI');
            assert.strictEqual(await h.page.evaluate(() => { const f = window.isInputAllowed; window.isInputAllowed = undefined; const d = MeshTrackpadAdapters.sharing.detect(); window.isInputAllowed = f; return d; }), false, 'no input rule to follow');
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'the canvas the page puts in before connecting is still owned', async () => {
        const h = await open(fx.desktopShare);
        try {
            await h.click('toggle');
            await h.page.evaluate(html => { QH('DeskParent', html); desktop.m.CanvasId = Q('Desk'); desktop.m.Canvas = Q('Desk').getContext('2d'); desktop.m.Canvas.canvas.width = 800; desktop.m.Canvas.canvas.height = 600; }, fx.desktopShare.blankCanvas);
            await h.reset(); await h.tap(100, 100); await h.wait(400);
            const s = await h.state();
            assert.deepStrictEqual(touchCalls(s.calls), []);
            assert.deepStrictEqual(buttons(s.packets), [2, 4]);
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'a WebRTC soft desktop switch mid-drag releases on the old module; the new one gets later taps', async () => {
        const h = await open(fx.desktopShare);
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
            const s = await h.state();
            assert.deepStrictEqual(s.pressed, []); assert.strictEqual(buttons(s.packets).slice(-1)[0], 4, 'released on the old module');
            await h.touch('touchEnd', []);
            await h.tap(100, 100); await h.wait(400);
            assert.deepStrictEqual(buttons(await h.page.evaluate(() => packets2.slice())), [2, 4]);
        } finally { await h.close(); }
    });

    await record('chromium', 'desktopShare', 'the 1:1 view mode scrolls the canvas\'s parent to follow the pointer', async () => {
        const h = await open(fx.desktopShare);
        try {
            // What the page's deskAdjust sets for "Toggle View Mode" (deskAspectRatio 1).
            await h.page.evaluate(() => { QS('Desk')['margin-top'] = '0px'; QS('Desk').height = '600px'; QS('Desk').width = '800px'; QS('DeskParent').overflow = 'scroll'; });
            await h.click('toggle'); await h.reset();
            await pushRight(h, 6, 50, 150);
            assert(await h.page.evaluate(() => Q('DeskParent').scrollLeft) > 0, 'DeskParent followed the pointer');
            const s = await h.state(), last = decode(s.packets[s.packets.length - 1]);
            assert(s.overlayRemote && Math.abs(s.overlayRemote[0] - last.x) <= 1, `overlay ${s.overlayRemote} shows the pointer at ${last.x}`);
        } finally { await h.close(); }
    });
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
                // Dispatched touch events raise no compatibility mouse events, and the guest page has no touch handlers.
                if (!fixture.guest) assert(touchCalls(a.calls).length > 0, 'the page handled the touches itself');
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
        try { if (engine === 'chromium') { await chromiumScenarios(browser, fx); await reviewScenarios(browser, fx); await zoomAndGuestScenarios(browser, fx); } else await webkitScenarios(browser, fx); }
        finally { await browser.close(); }
    }
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(results, null, 2));
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.engine} ${r.view} ${r.name}${r.ok ? '' : ': ' + r.error}`);
    if (!results.length || results.some(r => !r.ok)) process.exitCode = 1;
}

module.exports = { fixtures };
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
