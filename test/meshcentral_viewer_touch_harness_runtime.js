// Prove the browser mechanics the trackpad adapters rely on, in real engines: a capture-phase
// listener on the canvas's parent sees touches before the canvas's inline ontouch* handlers,
// stopPropagation there keeps those handlers from running, and preventDefault there keeps the
// browser from turning a tap into compatibility mouse events (which the views' inline onmouse*
// handlers would send as an absolute click). The control run, with no capture listener, must show
// the inline handlers and the compatibility click, so the harness can detect a leak at all.
// Chromium gets real multi-touch through CDP; WebKit can only receive dispatched touch-typed
// events, which exercise DOM dispatch but not WebKit's own tap-to-mouse conversion.
// Requires: npm ci --prefix test && npx --prefix test playwright install chromium webkit
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PAGE = `<!doctype html><html><body style="margin:0">
<div id=DeskParent style="position:absolute;left:0;top:0;width:400px;height:300px">
<canvas id=Desk width=800 height=600 style="width:400px;height:300px;touch-action:none"
 onmousedown="log('inline:mousedown')" onmouseup="log('inline:mouseup')" onclick="log('inline:click')"
 ontouchstart="log('inline:touchstart:' + event.touches.length)" ontouchmove="log('inline:touchmove:' + event.touches.length)"
 ontouchend="log('inline:touchend:' + event.touches.length)"></canvas></div>
<script>
window.events = [];
function log(e) { window.events.push(e); }
window.installOwner = function () {
  var parent = document.getElementById('DeskParent');
  ['touchstart', 'touchmove', 'touchend', 'touchcancel'].forEach(function (type) {
    parent.addEventListener(type, function (e) {
      if (e.target.id !== 'Desk') return;
      log('owner:' + type + ':' + e.touches.length);
      if (type !== 'touchcancel') e.preventDefault();
      e.stopPropagation();
    }, { capture: true, passive: false });
  });
};
</script></body></html>`;

async function chromiumTouches(page, owned) {
    const cdp = await page.context().newCDPSession(page);
    const pt = (id, x, y) => ({ x, y, id, radiusX: 1, radiusY: 1, force: 1 });
    const send = (type, touchPoints) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints });
    // A one-finger tap, then a two-finger touch that moves and lifts.
    await send('touchStart', [pt(1, 100, 100)]);
    await send('touchEnd', []);
    await page.waitForTimeout(400);
    await send('touchStart', [pt(1, 100, 100), pt(2, 150, 100)]);
    await send('touchMove', [pt(1, 100, 90), pt(2, 150, 90)]);
    await send('touchEnd', []);
    await page.waitForTimeout(400);
    return page.evaluate(() => window.events);
}

// Desktop WebKit does not expose the Touch constructor, so touch-typed events carry their touch
// lists as properties. Dispatch order, stopPropagation and the inline handlers are what is tested.
async function webkitTouches(page) {
    return page.evaluate(() => {
        const desk = document.getElementById('Desk');
        const touch = (id, x, y) => ({ identifier: id, target: desk, clientX: x, clientY: y, pageX: x, pageY: y });
        const fire = (type, touches, changed) => {
            const event = new Event(type, { bubbles: true, cancelable: true, composed: true });
            for (const [name, value] of [['touches', touches], ['targetTouches', touches], ['changedTouches', changed]]) Object.defineProperty(event, name, { value });
            return desk.dispatchEvent(event);
        };
        const a = touch(1, 100, 100), b = touch(2, 150, 100);
        fire('touchstart', [a], [a]);
        fire('touchend', [], [a]);
        fire('touchstart', [a, b], [a, b]);
        fire('touchmove', [a, b], [a, b]);
        fire('touchend', [], [a, b]);
        return window.events;
    });
}

function validate(engine, owned, events) {
    const errors = [];
    const check = (name, fn) => { try { fn(); } catch (error) { errors.push(`${name}: ${error.message}`); } };
    const inline = events.filter(e => e.startsWith('inline:touch'));
    const mouse = events.filter(e => /^inline:(mousedown|mouseup|click)$/.test(e));
    if (owned) {
        check('ownerSeesTwoFingers', () => assert(events.includes('owner:touchstart:2'), 'capture listener must see the two-finger touchstart'));
        check('ownerRunsFirst', () => assert(events[0].startsWith('owner:'), 'capture listener must run before any inline handler'));
        check('inlineTouchBlocked', () => assert.deepStrictEqual(inline, [], 'stopPropagation must keep the inline ontouch* handlers from running'));
        check('noCompatMouse', () => assert.deepStrictEqual(mouse, [], 'preventDefault must suppress compatibility mouse events'));
    } else {
        check('inlineTouchRuns', () => assert(inline.includes('inline:touchstart:1') && inline.includes('inline:touchstart:2'), 'without the owner the inline handlers must run'));
        if (engine === 'chromium') {
            check('compatMouseVisible', () => assert(mouse.includes('inline:mousedown'), 'without preventDefault a tap must produce compatibility mouse events, or the harness cannot detect a leak'));
        }
    }
    return errors;
}

async function main() {
    const playwright = require(require.resolve('playwright', { paths: [__dirname] }));
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/viewer-touch-harness/current');
    fs.mkdirSync(evidence, { recursive: true });
    const report = [];
    for (const engine of ['chromium', 'webkit']) {
        const browser = await playwright[engine].launch({ headless: true });
        try {
            for (const owned of [false, true]) {
                const context = await browser.newContext({ hasTouch: true, isMobile: engine === 'chromium', viewport: { width: 400, height: 300 } });
                try {
                    const page = await context.newPage();
                    await page.setContent(PAGE);
                    if (owned) await page.evaluate(() => window.installOwner());
                    const events = engine === 'chromium' ? await chromiumTouches(page, owned) : await webkitTouches(page);
                    report.push({ engine, owned, events, errors: validate(engine, owned, events) });
                } finally { await context.close(); }
            }
        } finally { await browser.close(); }
    }
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(report, null, 2));
    for (const r of report) console.log(`${r.errors.length ? 'FAIL' : 'PASS'} ${r.engine} ${r.owned ? 'owned' : 'control'}: ${r.errors.join('; ')}`);
    if (report.some(r => r.errors.length)) process.exitCode = 1;
}

main().catch(error => { console.error(error); process.exitCode = 1; });
