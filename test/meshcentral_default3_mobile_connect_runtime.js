// Prove that the Modern UI page (default3) sends no mouse button when a desktop session connects on a
// phone, that it wakes streaming with unpause and refresh instead, and that its one fallback pointer
// move happens only when no frame arrives (upstream #8104, fork commit 1e378b0b7).
//
// The real page runs whole in a mobile-emulated browser: the served view file rendered with neutral
// template values (min = '-min' for the minified page, as webserver.js renders it), the fork's own
// public/ scripts, and commander.ashx as public/commander.htm. Only the two server sockets are fake:
// control.ashx serves one online device, and meshrelay.ashx plays the agent end of the desktop relay
// (relay 'c', then a screen-size command, then optionally one frame). The test opens the device's
// Desktop tab, taps Connect with real touch input and records every packet the viewer sends.
// customJSTags renders empty: custom.js is out of scope here (SSOT rule 8); the duplicate-server check
// covers the page as production serves it.
//
// Variants: the fork's English page and its -min (views/default3.handlebars, views/default3-min.handlebars).
// Options:
//   --view <file>      run this page file instead (repeatable), for example production's override, to
//                      compare; it is held to the same expectations
//   --browser <name>   chromium (Pixel 7) or webkit (iPhone 15); default both
//   --evidence <dir>   write report.json and one Playwright trace per run
// Requires: npm ci --prefix test && npx --prefix test playwright install chromium webkit
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { meshcentralRoot } = require('./lib/meshcentral_paths');

const root = meshcentralRoot();
const ENGINES = { chromium: 'Pixel 7', webkit: 'iPhone 15' };
const OBSERVE_MS = 5000;          // after the screen-size command; the fallback runs at 3500 ms
const FALLBACK_EARLIEST_MS = 3300;
const USER = 'user//s2mobile', MESH = 'mesh//s2mobile', NODE = 'node//s2mobile';
const MIME = { '.htm': 'text/html', '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.ico': 'image/x-icon', '.json': 'application/json',
    '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };
// A 1x1 JPEG for the frame scenario (the latch fires on ProcessPictureMsg, whatever the image).
const JPEG = Buffer.from('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=', 'base64');

function required(file, purpose) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch (error) {
        if (error.code === 'ENOENT') { throw new Error('required input missing: ' + file + ' (' + purpose + ')', { cause: error }); }
        throw error;
    }
    if (!text.trim()) { throw new Error('required input is empty: ' + file + ' (' + purpose + ')'); }
    return text;
}

// The template values this page reads as JSON or numbers need valid text; everything else renders empty.
function render(template, min) {
    const values = { min, domainurl: '/', logoutControls: '%7B%7D', pluginHandler: 'null', debuglevel: '0', features: '0', features2: '0',
        features3: '0', sessiontime: '60', webRelayPort: '0', serverfeatures: '0', hide: '0', lang: 'en', extitle: 'MeshCentral',
        title: 'MeshCentral', titlehtml: 'MeshCentral' };
    return template.replace(/\{\{\{?(\w+)\}?\}\}/g, (match, key) => (Object.prototype.hasOwnProperty.call(values, key) ? values[key] : ''));
}

function startServer(page, log) {
    const publicDir = path.join(root, 'public');
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost');
        if (url.pathname === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page); return; }
        const rel = (url.pathname === '/commander.ashx') ? 'commander.htm' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
        const file = path.resolve(publicDir, rel);
        if (file.startsWith(publicDir + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile()) {
            res.writeHead(200, { 'content-type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
            res.end(fs.readFileSync(file));
            return;
        }
        log.push('404 ' + url.pathname);
        res.writeHead(404); res.end();
    });
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// Viewer -> agent packets, as [type, ...bytes]: mouse is type 2 with the button byte at offset 5.
function classify(packets) {
    const isType = (p, t) => p.bytes.length >= 4 && ((p.bytes[0] << 8) | p.bytes[1]) === t;
    const mouse = packets.filter(p => isType(p, 2));
    return {
        mouseButtons: mouse.filter(p => p.bytes[5] !== 0),
        mouseMoves: mouse.filter(p => p.bytes[5] === 0),
        unpause: packets.filter(p => isType(p, 8) && p.bytes.length === 5 && p.bytes[4] === 0),
        refresh: packets.filter(p => isType(p, 6) && p.bytes.length === 4)
    };
}

async function runOne(playwright, engine, variant, scenario, evidence) {
    const log = [];
    const server = await startServer(render(variant.text, variant.min), log);
    const port = server.address().port;
    const browser = await playwright[engine].launch({ headless: true });
    const context = await browser.newContext(Object.assign({}, playwright.devices[ENGINES[engine]]));
    if (evidence) { await context.tracing.start({ screenshots: true, snapshots: true }); }
    const packets = [];
    let screenAt = null, relayUrl = null;
    try {
        const page = await context.newPage();
        page.on('pageerror', error => log.push('pageerror ' + error.message));
        await page.routeWebSocket(/\/control\.ashx/, ws => {
            const send = o => ws.send(JSON.stringify(o));
            send({ action: 'serverinfo', serverinfo: { name: '127.0.0.1', mpsname: '127.0.0.1', mpsport: 0, port, emailcheck: false, domainauth: false, tlshash: '00', https: false, features: 0 } });
            send({ action: 'userinfo', userinfo: { _id: USER, name: 's2mobile', siteadmin: 0xFFFFFFFF, links: { [MESH]: { rights: 0xFFFFFFFF } } } });
            ws.onMessage(message => {
                let o; try { o = JSON.parse(message); } catch (error) { log.push('control non-JSON ' + String(message).slice(0, 60)); return; }
                if (o.action === 'meshes') { send({ action: 'meshes', meshes: [{ _id: MESH, name: 'S2 group', mtype: 2, desc: '', links: { [USER]: { rights: 0xFFFFFFFF } } }] }); }
                if (o.action === 'nodes') { send({ action: 'nodes', nodes: { [MESH]: [{ _id: NODE, name: 's2-device', meshid: MESH, host: '127.0.0.1', icon: 1, conn: 1, pwr: 1, mtype: 2, agent: { id: 6, caps: 15, ver: 0 }, osdesc: 'Linux' }] } }); }
            });
        });
        await page.routeWebSocket(/\/meshrelay\.ashx/, ws => {
            relayUrl = ws.url();
            ws.onMessage(message => {
                if (typeof message === 'string') { return; } // relay control text (options, rtt)
                packets.push({ t: screenAt == null ? null : Date.now() - screenAt, bytes: Array.from(Buffer.from(message)) });
            });
            // The relay connects ('c'); the agent end then reports its screen, as an agent does on a new session.
            setTimeout(() => ws.send('c'), 50);
            setTimeout(() => {
                screenAt = Date.now();
                ws.send(Buffer.from([0x00, 0x07, 0x00, 0x08, 0x03, 0x20, 0x02, 0x58])); // 800 x 600
                if (scenario === 'frame') {
                    setTimeout(() => {
                        const head = Buffer.from([0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        head.writeUInt16BE(8 + JPEG.length, 2);
                        ws.send(Buffer.concat([head, JPEG]));
                    }, 150);
                }
            }, 300);
        });
        await page.goto('http://127.0.0.1:' + port + '/');
        await page.waitForFunction(() => (typeof gotoDevice === 'function') && (typeof getNodeFromId === 'function') && (getNodeFromId('node//s2mobile') != null), null, { timeout: 30000 });
        const mobile = await page.evaluate(() => document.body.classList.contains('is-mobile'));
        // The device list's own navigation to the device's Desktop tab.
        await page.evaluate(() => gotoDevice('node//s2mobile', 11));
        await page.tap('#connectbutton1', { timeout: 10000 });
        await page.waitForFunction(() => (typeof desktop !== 'undefined') && desktop && desktop.State === 3, null, { timeout: 10000 });
        await page.waitForTimeout(OBSERVE_MS + 200);
        const state = await page.evaluate(() => ({ desktopState: desktop ? desktop.State : null }));
        return { mobile, relayUrl, state, packets, log };
    } finally {
        if (evidence) { await context.tracing.stop({ path: path.join(evidence, [engine, variant.name, scenario].join('-') + '.zip') }); }
        await context.close();
        await browser.close();
        server.close();
    }
}

function validate(scenario, result) {
    const errors = [];
    const check = (name, fn) => { try { fn(); } catch (error) { errors.push(name + ': ' + error.message.split('\n')[0]); } };
    const after = result.packets.filter(p => p.t != null && p.t <= OBSERVE_MS);
    const c = classify(after);
    check('mobile', () => assert.strictEqual(result.mobile, true, 'body.is-mobile must be set in mobile emulation'));
    check('connected', () => assert.strictEqual(result.state.desktopState, 3, 'the session must reach state 3'));
    check('noMouseButton', () => assert.strictEqual(c.mouseButtons.length, 0, 'no mouse button may be sent on connect; sent ' + c.mouseButtons.map(p => 'button 0x' + p.bytes[5].toString(16) + ' at ' + p.t + ' ms').join(', ')));
    check('noMouseBeforeConnect', () => assert.deepStrictEqual(result.packets.filter(p => p.t == null && p.bytes[1] === 2), [], 'no mouse packet before the screen'));
    // ProcessScreenMsg sends one unpause; the page's wake adds unpause plus refresh at 300/800/1600/2600 ms.
    check('unpause', () => assert(c.unpause.length >= 5, 'expected the screen unpause plus 4 wake retries, got ' + c.unpause.length));
    check('refresh', () => assert(c.refresh.length >= 4, 'expected 4 wake refreshes, got ' + c.refresh.length));
    check('refreshTimes', () => assert(c.refresh.filter(p => p.t >= 250).length >= 4, 'refreshes must come from the timed wake'));
    if (scenario === 'no-frame') {
        check('fallbackMove', () => {
            assert.strictEqual(c.mouseMoves.length, 1, 'exactly one fallback pointer move when no frame arrives, got ' + c.mouseMoves.length);
            assert(c.mouseMoves[0].t >= FALLBACK_EARLIEST_MS, 'the fallback move must wait for the retries (sent at ' + c.mouseMoves[0].t + ' ms)');
        });
    } else {
        check('noFallbackMove', () => assert.deepStrictEqual(c.mouseMoves.map(p => p.t), [], 'no pointer move once a frame has arrived'));
    }
    return { errors, counts: { mouseButtons: c.mouseButtons.length, mouseMoves: c.mouseMoves.map(p => p.t), unpause: c.unpause.length, refresh: c.refresh.map(p => p.t) } };
}

async function main() {
    const argv = process.argv.slice(2);
    const evidenceIndex = argv.indexOf('--evidence');
    const evidence = evidenceIndex >= 0 ? path.resolve(argv[evidenceIndex + 1]) : null;
    if (evidence) { fs.mkdirSync(evidence, { recursive: true }); }
    const browserIndex = argv.indexOf('--browser');
    const engines = browserIndex >= 0 ? [argv[browserIndex + 1]] : Object.keys(ENGINES);
    for (const engine of engines) { assert(ENGINES[engine], 'unsupported browser ' + engine); }
    const views = [];
    argv.forEach((arg, i) => { if (arg === '--view') { views.push(path.resolve(argv[i + 1])); } });
    const variants = views.length
        ? views.map(file => ({ name: path.basename(file), file, min: /-min[._]/.test(path.basename(file)) ? '-min' : '' }))
        : [{ name: 'default3', file: path.join(root, 'views', 'default3.handlebars'), min: '' },
            { name: 'default3-min', file: path.join(root, 'views', 'default3-min.handlebars'), min: '-min' }];
    for (const variant of variants) { variant.text = required(variant.file, 'served Modern UI page under test'); }
    const playwright = require('playwright');
    const report = [];
    for (const engine of engines) {
        for (const variant of variants) {
            for (const scenario of ['no-frame', 'frame']) {
                let entry;
                try {
                    const result = await runOne(playwright, engine, variant, scenario, evidence);
                    const checked = validate(scenario, result);
                    entry = { engine, device: ENGINES[engine], view: variant.file, scenario, errors: checked.errors, counts: checked.counts, relayUrl: result.relayUrl, log: result.log, packets: result.packets };
                } catch (error) {
                    entry = { engine, device: ENGINES[engine], view: variant.file, scenario, errors: ['run: ' + error.message.split('\n')[0]] };
                }
                report.push(entry);
                console.log((entry.errors.length ? 'FAIL' : 'PASS') + ' ' + engine + ' (' + ENGINES[engine] + ') ' + variant.name + ' ' + scenario +
                    (entry.counts ? ' buttons=' + entry.counts.mouseButtons + ' moves=[' + entry.counts.mouseMoves.join(',') + '] unpause=' + entry.counts.unpause + ' refresh=[' + entry.counts.refresh.join(',') + ']' : '') +
                    (entry.errors.length ? ': ' + entry.errors.join('; ') : ''));
            }
        }
    }
    if (evidence) { fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(report, null, 2)); }
    const failed = report.filter(entry => entry.errors.length).length;
    console.log((failed ? 'FAIL' : 'PASS') + ' default3 mobile connect (' + report.length + ' runs, ' + failed + ' failed)');
    if (failed) { process.exitCode = 1; }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
