// Run the trackpad loader block of MeshCentral public/scripts/custom.js in real browsers on
// fixtures built from the pinned desktop pages, served from a routed origin so script URLs,
// localStorage and query strings behave as on the server. Checks that with the flag off nothing
// is loaded or listened to, that ?trackpadengine= sets the per-browser, per-page flag, that the
// engine, controller and the page's adapter load in order and install, and that viewer modules
// created later report their state to the controller.
// Requires: npm ci --prefix test && npx --prefix test playwright install chromium webkit
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { fixtures } = require('./meshcentral_trackpad_adapter_runtime.js');

const meshcentral = path.resolve(__dirname, '../../MeshCentral');
const scripts = path.join(meshcentral, 'public/scripts');
const ORIGIN = 'https://mesh.test';

function loaderSource() {
    const custom = fs.readFileSync(path.join(scripts, 'custom.js'), 'utf8');
    const start = custom.indexOf('/*\n * Trackpad ("mouse pointer") mode engine loader.');
    const end = custom.indexOf('/*\n * Desktop audio speaker control');
    assert(start >= 0 && end > start, 'trackpad loader block must precede the audio block in custom.js');
    return custom.slice(start, end);
}

async function openContext(browser) {
    const context = await browser.newContext({ hasTouch: true, viewport: { width: 640, height: 400 } });
    const requested = [];
    const fx = fixtures(), loader = loaderSource();
    await context.route(ORIGIN + '/**', route => {
        const url = new URL(route.request().url());
        const name = url.pathname.split('/').pop();
        if (url.pathname === '/default3' || url.pathname === '/mobile') {
            const page = fx[url.pathname.slice(1)].page.replace('<head>', '<head><script src="/scripts/custom.js"></script>');
            return route.fulfill({ status: 200, contentType: 'text/html', body: page });
        }
        if (url.pathname === '/sharing-mobile') {
            // The guest share page has p10desktop, DeskParent and fullscreenzoom, but no trackpad mode.
            const page = fx.mobile.page.replace('<head>', '<head><script src="/scripts/custom.js"></script>').replace('        var trackpadMode = false;\n', '');
            assert(!/var trackpadMode/.test(page));
            return route.fulfill({ status: 200, contentType: 'text/html', body: page });
        }
        if (url.pathname === '/scripts/custom.js') return route.fulfill({ status: 200, contentType: 'application/javascript', body: loader });
        if (url.pathname.startsWith('/scripts/')) {
            requested.push(name);
            if (context.failScript === name) return route.fulfill({ status: 404, body: '' });
            const file = path.join(scripts, name);
            return fs.existsSync(file) ? route.fulfill({ status: 200, contentType: 'application/javascript', body: fs.readFileSync(file, 'utf8') }) : route.fulfill({ status: 404, body: '' });
        }
        return route.fulfill({ status: 404, body: '' });
    });
    return { context, requested };
}

// Create the viewer module after the page has loaded, as the page does on connect.
async function connect(page) {
    await page.evaluate(() => {
        const hex = p => Array.from(p, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        desktop = { m: CreateAgentRemoteDesktop('Desk'), State: 3 };
        const m = desktop.m;
        m.parent = { State: 2, send: p => { if (((p.charCodeAt(0) << 8) | p.charCodeAt(1)) === 2) packets.push(hex(p)); }, xxStateChange: function (s) { this.State = s; m.xxStateChange(s); } };
        m.Start();
        m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 3, 32, 2, 88]));
        m.Canvas.canvas.width = 800; m.Canvas.canvas.height = 600;
        for (const n of ['dtouchstart', 'dtouchend', 'dmousedown', 'dmouseup']) { const o = window[n]; window[n] = function () { calls.push(n); return o.apply(this, arguments); }; }
        packets.length = 0; calls.length = 0;
    });
}

async function visit(ctx, pathAndQuery) {
    const page = await ctx.context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    ctx.requested.length = 0;
    await page.goto(ORIGIN + pathAndQuery);
    await page.addScriptTag({ url: ORIGIN + '/scripts/agent-desktop-0.0.2.js' });
    await page.waitForTimeout(300);
    return { page, errors };
}

const trackpadScripts = list => list.filter(n => /^agent-desktop-trackpad/.test(n));
const results = [];
async function record(engine, name, fn) { try { await fn(); results.push({ engine, name, ok: true }); } catch (e) { results.push({ engine, name, ok: false, error: e.message }); } }

async function scenarios(engine, browser) {
    await record(engine, 'flag off: nothing loaded, nothing registered, the page keeps its touches', async () => {
        const ctx = await openContext(browser);
        try {
            const { page, errors } = await visit(ctx, '/default3');
            assert.deepStrictEqual(trackpadScripts(ctx.requested), []);
            assert.deepStrictEqual(await page.evaluate(() => [typeof window.MeshTrackpad, typeof window.MeshDesktopModuleObservers, typeof window.MeshTrackpadController]), ['undefined', 'undefined', 'undefined']);
            await connect(page);
            assert.strictEqual(await page.evaluate(() => desktop.m.stateListeners.length), 0);
            await page.click('#toggle');
            await page.touchscreen.tap(60, 60); await page.waitForTimeout(300);
            assert((await page.evaluate(() => calls.slice())).includes('dtouchstart'), 'the page handled the tap');
            assert.deepStrictEqual(errors, []);
        } finally { await ctx.context.close(); }
    });

    await record(engine, '?trackpadengine=on loads engine, controller and adapter in order, persists, and installs', async () => {
        const ctx = await openContext(browser);
        try {
            let { page, errors } = await visit(ctx, '/default3?trackpadengine=on');
            assert.deepStrictEqual(trackpadScripts(ctx.requested), ['agent-desktop-trackpad-0.0.1.js', 'agent-desktop-trackpad-controller-0.0.1.js', 'agent-desktop-trackpad-default3-0.0.1.js']);
            assert.strictEqual(await page.evaluate(() => window.localStorage.getItem('meshTrackpadEngine.default3')), 'on');
            assert.strictEqual(await page.evaluate(() => window.MeshTrackpad && window.MeshTrackpad.kind), 'default3');
            await connect(page);
            assert.strictEqual(await page.evaluate(() => desktop.m.stateListeners.length), 1, 'a module created after load reports its state');
            await page.click('#toggle');
            // The controller looks again just after the click's own handlers have run.
            await page.waitForFunction(() => MeshTrackpad.controller.isActive(), null, { timeout: 2000 });
            await page.evaluate(() => packets.length = 0);
            await page.touchscreen.tap(60, 60); await page.waitForTimeout(400);
            const after = await page.evaluate(() => ({ calls: calls.filter(c => /^d(touch|mouse)/.test(c)), packets: packets.slice() }));
            assert.deepStrictEqual(after.calls, [], 'the controller owns the tap');
            assert.deepStrictEqual(after.packets.map(p => p.slice(10, 12)), ['02', '04']);
            assert.deepStrictEqual(errors, []);
            await page.close();
            ({ page, errors } = await visit(ctx, '/default3'));
            assert.strictEqual(trackpadScripts(ctx.requested).length, 3, 'the flag persists without the query');
            await page.close();
            ({ page } = await visit(ctx, '/default3?trackpadengine=off'));
            assert.deepStrictEqual(trackpadScripts(ctx.requested), []);
            assert.strictEqual(await page.evaluate(() => window.localStorage.getItem('meshTrackpadEngine.default3')), 'off');
            await page.close();
            ({ page } = await visit(ctx, '/default3?trackpadengine=default'));
            assert.deepStrictEqual(trackpadScripts(ctx.requested), [], 'default is off');
            assert.strictEqual(await page.evaluate(() => window.localStorage.getItem('meshTrackpadEngine.default3')), null);
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'each page kind has its own flag and its own adapter', async () => {
        const ctx = await openContext(browser);
        try {
            let { page } = await visit(ctx, '/default3?trackpadengine=on');
            await page.close();
            ({ page } = await visit(ctx, '/mobile'));
            assert.deepStrictEqual(trackpadScripts(ctx.requested), [], 'the Modern UI flag does not enable the classic page');
            await page.close();
            ({ page } = await visit(ctx, '/mobile?trackpadengine=on'));
            assert.deepStrictEqual(trackpadScripts(ctx.requested), ['agent-desktop-trackpad-0.0.1.js', 'agent-desktop-trackpad-controller-0.0.1.js', 'agent-desktop-trackpad-mobile-0.0.1.js']);
            assert.strictEqual(await page.evaluate(() => MeshTrackpad.kind), 'defaultMobile');
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'a module going down tears the controller down; coming up with the mode on places the pointer', async () => {
        const ctx = await openContext(browser);
        try {
            const { page } = await visit(ctx, '/default3?trackpadengine=on');
            await connect(page);
            await page.click('#toggle');
            await page.waitForFunction(() => MeshTrackpad.controller.isActive(), null, { timeout: 2000 });
            await page.touchscreen.tap(60, 60); await page.waitForTimeout(60);
            assert.notStrictEqual(await page.evaluate(() => MeshTrackpad.controller.engine.isActive()), false, 'a tap release is pending');
            await page.evaluate(() => desktop.m.xxStateChange(0));
            assert.strictEqual(await page.evaluate(() => MeshTrackpad.controller.engine.isActive()), false, 'state 0 drops the gesture');
            await page.evaluate(() => { packets.length = 0; desktop.m.Start(); desktop.m.parent.State = 2; desktop.m.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 3, 32, 2, 88])); desktop.m.Canvas.canvas.width = 800; desktop.m.Canvas.canvas.height = 600; });
            const p = await page.evaluate(() => packets.slice());
            assert.deepStrictEqual(p.map(x => [x.slice(10, 12), parseInt(x.slice(12, 16), 16), parseInt(x.slice(16, 20), 16)]), [['00', 400, 300]], 'state 3 with the mode on sends the centre');
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'a real disconnect deactivates and hides the overlay', async () => {
        const ctx = await openContext(browser);
        try {
            const { page } = await visit(ctx, '/default3?trackpadengine=on');
            await connect(page);
            await page.click('#toggle');
            await page.waitForFunction(() => MeshTrackpad.controller.isActive(), null, { timeout: 2000 });
            // Real order: the module reports state 0, then the page's handler drops the desktop and the mode.
            await page.evaluate(() => { desktop.m.parent.xxStateChange(0); desktop = null; trackpadMode = false; });
            const s = await page.evaluate(() => ({ active: MeshTrackpad.controller.isActive(), overlay: MeshTrackpad.controller.overlay().style.display, cls: document.documentElement.classList.contains(MeshTrackpadController.ACTIVE_CLASS) }));
            assert.deepStrictEqual(s, { active: false, overlay: 'none', cls: false });
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'a WebRTC soft desktop coming up mid-drag releases on the old module and places once it knows its screen', async () => {
        const ctx = await openContext(browser);
        try {
            const { page } = await visit(ctx, '/default3?trackpadengine=on');
            await connect(page);
            await page.click('#toggle');
            await page.waitForFunction(() => MeshTrackpad.controller.isActive(), null, { timeout: 2000 });
            await page.touchscreen.tap(60, 60); await page.waitForTimeout(60);
            assert.deepStrictEqual(await page.evaluate(() => Object.keys(desktop.m.browserPressedButtons)), ['1'], 'the tap holds left (pending release)');
            await page.evaluate(() => {
                const hex = p => Array.from(p, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                window.softPackets = [];
                const m2 = CreateAgentRemoteDesktop('Desk');
                // Like CreateKvmDataChannel: the soft module reaches state 3 in Start(), before any SCREEN.
                m2.parent = { State: 0, send: p => { if (((p.charCodeAt(0) << 8) | p.charCodeAt(1)) === 2) softPackets.push(hex(p)); }, xxStateChange: function (s) { if (this.State == s) return; this.State = s; m2.xxStateChange(s); } };
                webRtcDesktop = { softdesktop: m2.parent };
                m2.parent.m = m2;
                packets.length = 0;
                m2.parent.xxStateChange(3);
            });
            let s = await page.evaluate(() => ({ hw: packets.slice(), hwPressed: Object.keys(desktop.m.browserPressedButtons), soft: softPackets.slice() }));
            assert.deepStrictEqual(s.hw.map(p => p.slice(10, 12)), ['04'], 'the old module released the left button');
            assert.deepStrictEqual(s.hwPressed, []);
            assert.deepStrictEqual(s.soft, [], 'nothing from the soft desktop before it knows its screen');
            await page.evaluate(() => { const m2 = webRtcDesktop.softdesktop.m; m2.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, 3, 32, 2, 88])); });
            await page.waitForTimeout(500);
            s = await page.evaluate(() => softPackets.slice());
            assert.deepStrictEqual(s.map(p => [p.slice(10, 12), parseInt(p.slice(12, 16), 16), parseInt(p.slice(16, 20), 16)]), [['00', 400, 300]], 'placed at the centre once the soft desktop knows the screen');
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'another desktop module\'s state changes do not reach the controller', async () => {
        const ctx = await openContext(browser);
        try {
            const { page } = await visit(ctx, '/default3?trackpadengine=on');
            await connect(page);
            await page.click('#toggle');
            await page.waitForFunction(() => MeshTrackpad.controller.isActive(), null, { timeout: 2000 });
            // Move the pointer off the centre, so a stray re-placement would show as a packet.
            await page.evaluate(() => { MeshTrackpad.controller.engine.setCursor(123, 45); });
            await page.evaluate(() => {
                const c = document.createElement('canvas'); c.id = 'kvmid_x'; c.width = 100; c.height = 100; document.body.appendChild(c);
                const m3 = CreateAgentRemoteDesktop('kvmid_x');
                m3.parent = { State: 0, send: () => {}, xxStateChange: function (s) { this.State = s; m3.xxStateChange(s); } };
                packets.length = 0;
                m3.xxStateChange(3); m3.xxStateChange(0);
            });
            await page.waitForTimeout(100);
            assert.deepStrictEqual(await page.evaluate(() => ({ active: MeshTrackpad.controller.isActive(), packets: packets.slice() })), { active: true, packets: [] });
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'the guest share page, without a trackpad mode, loads nothing', async () => {
        const ctx = await openContext(browser);
        try {
            const { page, errors } = await visit(ctx, '/sharing-mobile?trackpadengine=on');
            assert.deepStrictEqual(trackpadScripts(ctx.requested), []);
            assert.strictEqual(await page.evaluate(() => window.localStorage.getItem('meshTrackpadEngine.defaultMobile')), null, 'a share link cannot set the flag');
            assert.deepStrictEqual(errors, []);
        } finally { await ctx.context.close(); }
    });

    await record(engine, 'a script that fails to load leaves trackpad mode to the page', async () => {
        const ctx = await openContext(browser);
        ctx.context.failScript = 'agent-desktop-trackpad-controller-0.0.1.js';
        try {
            const { page, errors } = await visit(ctx, '/default3?trackpadengine=on');
            assert.deepStrictEqual(trackpadScripts(ctx.requested), ['agent-desktop-trackpad-0.0.1.js', 'agent-desktop-trackpad-controller-0.0.1.js'], 'loading stops at the failure');
            assert.strictEqual(await page.evaluate(() => typeof window.MeshTrackpad), 'undefined');
            assert.strictEqual(await page.evaluate(() => (window.MeshDesktopModuleObservers || []).length), 0, 'no longer observing new modules');
            await connect(page);
            assert.strictEqual(await page.evaluate(() => desktop.m.stateListeners.length), 0);
            await page.click('#toggle');
            await page.touchscreen.tap(60, 60); await page.waitForTimeout(300);
            assert((await page.evaluate(() => calls.slice())).includes('dtouchstart'));
            assert.deepStrictEqual(errors, []);
        } finally { await ctx.context.close(); }
    });
}

async function main() {
    const playwright = require(require.resolve('playwright', { paths: [__dirname] }));
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/trackpad-loader/current');
    for (const engine of ['chromium', 'webkit']) {
        const browser = await playwright[engine].launch({ headless: true });
        try { await scenarios(engine, browser); } finally { await browser.close(); }
    }
    fs.mkdirSync(evidence, { recursive: true });
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(results, null, 2));
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.engine} ${r.name}${r.ok ? '' : ': ' + r.error}`);
    if (!results.length || results.some(r => !r.ok)) process.exitCode = 1;
}

main().catch(error => { console.error(error); process.exitCode = 1; });
