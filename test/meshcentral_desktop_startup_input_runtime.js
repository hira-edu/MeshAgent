// Exercise real viewer packet dispatch. No endpoint connection or OS input is used.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

async function exerciseViewer(createViewer, canvas) {
    const viewer = createViewer(canvas, null);
    let packets = [];
    const phases = {};
    viewer.parent = {
        State: 2,
        send(packet) { packets.push(Array.from(packet, c => c.charCodeAt(0))); },
        xxStateChange(state) { this.State = state; viewer.xxStateChange(state); }
    };
    function screen(width = 800, height = 600) {
        viewer.ProcessBinaryCommand(7, 8, new Uint8Array([0, 7, 0, 8, width >> 8, width & 255, height >> 8, height & 255]));
    }
    function capture(name, action) {
        packets = [];
        action();
        phases[name] = packets.slice();
    }
    viewer.Start();
    capture('connect', () => screen());
    capture('unmatchedBrowserReleases', () => {
        for (const [key, code, keyCode] of [['Shift', 'ShiftLeft', 16], ['Control', 'ControlLeft', 17], ['Alt', 'AltLeft', 18], ['Meta', 'MetaLeft', 91], ['Meta', 'MetaRight', 92], ['a', 'KeyA', 65]]) {
            viewer.handleKeyUp({ key, code, keyCode });
        }
        viewer.xxMouseUp({ pageX: 20, pageY: 20, button: 0 });
    });
    phases.inputEnabledAfterUnmatchedReleases = !viewer.stopInput;
    capture('sameSize', () => screen());
    capture('resize', () => screen(1024, 768));
    capture('userKeys', () => {
        viewer.SendKeyMsgKC(viewer.KeyAction.DOWN, 65);
        viewer.SendKeyMsgKC(viewer.KeyAction.UP, 65);
    });
    viewer.SendKeyMsgKC(viewer.KeyAction.DOWN, 17);
    viewer.SendKeyMsgKC(viewer.KeyAction.DOWN, 16);
    capture('heldKeysResize', () => screen());
    capture('afterRelease', () => screen());
    capture('userMouse', () => {
        viewer.SendMouseMsg(viewer.KeyAction.DOWN, { pageX: 20, pageY: 20, button: 0 });
        viewer.SendMouseMsg(viewer.KeyAction.UP, { pageX: 20, pageY: 20, button: 0 });
    });
    capture('browserKeys', () => {
        const e = { key: 'ArrowLeft', code: 'ArrowLeft', keyCode: 37 };
        viewer.xxKeyDown(e);
        viewer.xxKeyUp(e);
    });
    capture('browserUnicode', () => {
        const e = { key: 'a', code: 'KeyA', keyCode: 65 };
        viewer.xxKeyDown(e);
        viewer.xxKeyPress(e);
        viewer.xxKeyUp(e);
    });
    capture('browserMouse', () => {
        const e = { pageX: 20, pageY: 20, button: 0 };
        viewer.xxMouseDown(e);
        viewer.xxMouseUp(e);
        viewer.xxMouseUp(e);
    });
    const unicode = { key: 'A', code: 'KeyA', keyCode: 65 };
    viewer.xxKeyDown(unicode);
    viewer.xxKeyPress(unicode);
    capture('unicodeBlur', () => viewer.handleReleaseKeys());
    capture('unicodeAfterBlur', () => viewer.xxKeyUp(unicode));
    const ctrl = { key: 'Control', code: 'ControlLeft', keyCode: 17, timeStamp: 100 };
    packets = [];
    viewer.xxKeyDown(ctrl);
    await new Promise(resolve => setTimeout(resolve, 130));
    viewer.xxKeyUp(ctrl);
    phases.browserCtrl = packets.slice();
    capture('browserAltGr', () => {
        const alt = { key: 'AltGraph', code: 'AltRight', keyCode: 18, timeStamp: 120 };
        viewer.xxKeyDown(ctrl);
        viewer.xxKeyDown(alt);
        viewer.xxKeyUp(ctrl);
        viewer.xxKeyUp(alt);
    });
    viewer.xxKeyDown(ctrl);
    capture('pendingCtrlReset', () => screen());
    packets = [];
    await new Promise(resolve => setTimeout(resolve, 130));
    phases.afterPendingCtrlReset = packets.slice();
    viewer.xxKeyDown(ctrl);
    viewer.handleReleaseKeys();
    packets = [];
    await new Promise(resolve => setTimeout(resolve, 130));
    phases.afterPendingCtrlBlur = packets.slice();
    viewer.xxMouseDown({ pageX: 20, pageY: 20, button: 0 });
    viewer.xxKeyDown(ctrl);
    viewer.xxStateChange(0);
    viewer.Start();
    viewer.parent.State = 2;
    capture('reconnect', () => screen());
    packets = [];
    await new Promise(resolve => setTimeout(resolve, 130));
    viewer.xxKeyUp(ctrl);
    viewer.xxMouseUp({ pageX: 20, pageY: 20, button: 0 });
    phases.afterReconnectReleases = packets.slice();
    // The page marks view-only sessions once, before the first screen packet.
    viewer.xxStateChange(0);
    viewer.Start();
    viewer.parent.State = 2;
    viewer.stopInput = true;
    capture('viewOnlyConnect', () => screen());
    capture('viewOnlyResize', () => screen(1024, 768));
    phases.viewOnlyKept = viewer.stopInput === true;
    capture('viewOnlyInput', () => {
        viewer.mousedown({ pageX: 20, pageY: 20, button: 0 });
        viewer.mouseup({ pageX: 20, pageY: 20, button: 0 });
        viewer.handleKeyDown({ key: 'Alt', code: 'AltLeft', keyCode: 18 });
        viewer.handleKeyUp({ key: 'Alt', code: 'AltLeft', keyCode: 18 });
    });
    return phases;
}

function validate(phases) {
    const errors = [];
    function check(name, fn) { try { fn(); } catch (error) { errors.push(`${name}: ${error.message}`); } }
    const input = packets => packets.filter(p => [1, 2, 15, 85].includes((p[0] << 8) | p[1]));
    for (const phase of ['connect', 'sameSize', 'resize', 'afterRelease', 'reconnect', 'pendingCtrlReset', 'viewOnlyConnect', 'viewOnlyResize']) {
        check(phase, () => {
            assert.deepStrictEqual(input(phases[phase]), [], 'screen metadata must not synthesize input');
            assert.deepStrictEqual(phases[phase].map(p => p[1]), [5, 8, 87, 14], 'keep compression, resume, lock query and touch handshake');
        });
    }
    check('userKeys', () => assert.deepStrictEqual(input(phases.userKeys), [[0, 1, 0, 6, 0, 65], [0, 1, 0, 6, 1, 65]]));
    check('heldKeysResize', () => {
        assert.deepStrictEqual(input(phases.heldKeysResize), [[0, 1, 0, 6, 1, 16], [0, 1, 0, 6, 1, 17]], 'release only keys pressed by this viewer before resetting its state');
        assert.deepStrictEqual(phases.heldKeysResize.slice(0, 2).map(p => p[1]), [1, 1]);
    });
    check('userMouse', () => assert.deepStrictEqual(input(phases.userMouse).map(p => [p[1], p[5]]), [[2, 2], [2, 4]]));
    check('unmatchedBrowserReleases', () => assert.deepStrictEqual(input(phases.unmatchedBrowserReleases), [], 'browser releases without a viewer press must not reach the endpoint'));
    check('inputEnabledAfterUnmatchedReleases', () => assert.strictEqual(phases.inputEnabledAfterUnmatchedReleases, true));
    check('browserKeys', () => assert.deepStrictEqual(input(phases.browserKeys), [[0, 1, 0, 6, 4, 37], [0, 1, 0, 6, 3, 37]]));
    check('browserUnicode', () => assert.deepStrictEqual(input(phases.browserUnicode), [[0, 85, 0, 7, 0, 0, 97], [0, 85, 0, 7, 1, 0, 97]]));
    check('browserMouse', () => assert.deepStrictEqual(input(phases.browserMouse).map(p => [p[1], p[5]]), [[2, 2], [2, 4]]));
    check('unicodeBlur', () => assert.deepStrictEqual(input(phases.unicodeBlur), [[0, 85, 0, 7, 1, 0, 65]]));
    check('browserCtrl', () => assert.deepStrictEqual(input(phases.browserCtrl), [[0, 1, 0, 6, 0, 17], [0, 1, 0, 6, 1, 17]]));
    check('browserAltGr', () => assert.deepStrictEqual(input(phases.browserAltGr), [[0, 1, 0, 6, 0, 225], [0, 1, 0, 6, 1, 17], [0, 1, 0, 6, 1, 225]]));
    for (const phase of ['unicodeAfterBlur', 'afterPendingCtrlReset', 'afterPendingCtrlBlur', 'afterReconnectReleases']) {
        check(phase, () => assert.deepStrictEqual(input(phases[phase]), [], 'reset/blur/reconnect must not leak stale browser input'));
    }
    check('viewOnlyKept', () => assert.strictEqual(phases.viewOnlyKept, true, 'screen packets must not clear page-imposed view-only'));
    check('viewOnlyInput', () => assert.deepStrictEqual(input(phases.viewOnlyInput), [], 'view-only viewer must not send input'));
    return errors;
}

async function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = path.resolve(evidenceIndex >= 0 ? process.argv[evidenceIndex + 1] : 'artifacts/validation/kvm-startup-input/current');
    fs.mkdirSync(evidence, { recursive: true });
    const assets = ['agent-desktop-0.0.2.js', 'agent-desktop-0.0.2-min.js'];
    const report = [];
    for (const asset of assets) {
        const source = fs.readFileSync(path.resolve(__dirname, '../../MeshCentral/public/scripts', asset), 'utf8');
        const canvas = { width: 800, height: 600, clientWidth: 800, clientHeight: 600, style: {}, offsetLeft: 0, offsetTop: 0 };
        canvas.getContext = () => ({ canvas, setTransform() {}, clearRect() {}, rotate() {}, fillRect() {} });
        const context = vm.createContext({ navigator: { platform: 'Win32' }, window: {}, document: {}, desktop: { State: 3 }, urlargs: {}, ShortToStr: x => String.fromCharCode(x >> 8, x & 255), console, Uint8Array, setTimeout, clearTimeout });
        vm.runInContext(source, context);
        const phases = await exerciseViewer(context.CreateAgentRemoteDesktop, canvas);
        report.push({ engine: 'node-vm', asset, phases, errors: validate(phases) });
    }
    if (process.argv.includes('--browsers')) {
        const playwright = require('playwright');
        const browserIndex = process.argv.indexOf('--browser');
        const engines = browserIndex < 0 ? ['chromium', 'firefox', 'webkit'] : [process.argv[browserIndex + 1]];
        for (const engine of engines) {
            assert(['chromium', 'firefox', 'webkit'].includes(engine), 'unsupported browser');
            const browser = await playwright[engine].launch({ headless: true });
            try {
                for (const asset of assets) {
                    const context = await browser.newContext();
                    await context.tracing.start({ screenshots: true, snapshots: true });
                    try {
                        const page = await context.newPage();
                        const pageErrors = [];
                        page.on('pageerror', error => pageErrors.push(error.message));
                        await page.setContent('<canvas width="800" height="600" style="display:block;position:absolute;left:0;top:0"></canvas>');
                        await page.evaluate(() => {
                            Object.defineProperty(navigator, 'platform', { value: 'Win32' });
                            window.urlargs = {};
                            window.desktop = { State: 3 };
                            window.ShortToStr = x => String.fromCharCode(x >> 8, x & 255);
                        });
                        await page.addScriptTag({ path: path.resolve(__dirname, '../../MeshCentral/public/scripts', asset) });
                        const phases = await page.evaluate(`(${exerciseViewer.toString()})(CreateAgentRemoteDesktop, document.querySelector('canvas'))`);
                        report.push({ engine, asset, phases, errors: validate(phases).concat(pageErrors) });
                    } finally {
                        await context.tracing.stop({ path: path.join(evidence, `${engine}-${asset}.zip`) });
                        await context.close();
                    }
                }
            } finally { await browser.close(); }
        }
    }
    fs.writeFileSync(path.join(evidence, 'report.json'), JSON.stringify(report, null, 2));
    for (const result of report) {
        console.log(`${result.errors.length ? 'FAIL' : 'PASS'} ${result.engine} ${result.asset}: ${result.errors.join('; ')}`);
    }
    if (report.some(result => result.errors.length)) process.exitCode = 1;
}

main().catch(error => { console.error(error); process.exitCode = 1; });
