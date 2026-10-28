const fs = require('fs');
const path = require('path');
const { forkFile } = require('./lib/meshcentral_paths');
const vm = require('vm');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function createHarness() {
    const canvasContext = {
        canvas: { width: 0, height: 0 },
        clearRect() {},
        setTransform() {},
        fillRect() {},
        rotate() {},
        drawImage() {}
    };
    const canvasElement = {
        clientWidth: 1280,
        clientHeight: 720,
        style: {},
        getContext() { return canvasContext; }
    };
    const context = {
        console,
        navigator: { platform: 'Win32', userAgent: 'Mozilla/5.0' },
        window: {},
        document: {},
        urlargs: {},
        Q: () => null,
        Canvas: canvasContext,
        Image: function ImageMock() {
            this.onload = null;
            this.error = null;
            Object.defineProperty(this, 'src', {
                set: () => {
                    if (typeof this.onload === 'function') { this.onload(); }
                }
            });
        },
        Uint8Array,
        ArrayBuffer,
        btoa: (text) => Buffer.from(text, 'binary').toString('base64'),
        Blob: function BlobMock() {},
        FileReader: function FileReaderMock() {}
    };
    return { context, canvasElement };
}

function mutateDesktopState(desktop) {
    desktop.PendingOperations = [[7, 2]];
    desktop.tilesReceived = 9;
    desktop.TilesDrawn = 8;
    desktop.FirstDraw = true;
    desktop.stopInput = true;
    desktop.pressedKeys = [65, 66];
    desktop.RemoteInputLock = true;
    desktop.KeyboardState = 4;
    desktop.displays = { 1: 'Display 1' };
    desktop.selectedDisplay = 1;
}

function captureDesktopState(desktop) {
    return {
        pendingOperations: desktop.PendingOperations.length,
        tilesReceived: desktop.tilesReceived,
        tilesDrawn: desktop.TilesDrawn,
        firstDraw: desktop.FirstDraw,
        stopInput: desktop.stopInput,
        pressedKeysLength: desktop.pressedKeys.length,
        remoteInputLock: desktop.RemoteInputLock,
        keyboardState: desktop.KeyboardState,
        displays: desktop.displays,
        selectedDisplay: desktop.selectedDisplay
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const desktopPath = forkFile('public/scripts/agent-desktop-0.0.2.js');
    const source = fs.readFileSync(desktopPath, 'utf8');
    const { context, canvasElement } = createHarness();
    vm.createContext(context);
    vm.runInContext(source, context);

    const desktop = context.CreateAgentRemoteDesktop(canvasElement, null);
    const sentPackets = [];
    const parentStateTransitions = [];
    desktop.parent = {
        State: 2,
        send: (packet) => sentPackets.push(packet),
        xxStateChange(nextState) {
            this.State = nextState;
            parentStateTransitions.push(nextState);
        },
        // What agent-redir-ws's connected() does: the module declares the connection on its first SCREEN.
        connected() { if (this.State == 2) { this.xxStateChange(3); } }
    };

    desktop.ProcessScreenMsg(800, 600);
    const firstHandshakeCount = sentPackets.length;
    const parentStateAfterFirstScreen = desktop.parent.State;
    mutateDesktopState(desktop);
    desktop.ProcessScreenMsg(800, 600);
    const secondHandshakeCount = sentPackets.length;
    const afterSameSizeReset = captureDesktopState(desktop);
    const parentStateAfterSameSizeReset = desktop.parent.State;

    // Native touch (touchenabled 2): a contact the remote already saw go down must be released
    // when a SCREEN resets the stream, or it stays down on the remote. A contact that was only
    // queued (f 1, its down not sent yet) is dropped without sending anything.
    const touchPackets = [];
    let clearedTimer = null;
    context.clearInterval = (id) => { clearedTimer = id; };
    desktop.touchenabled = 2;
    desktop.State = 3;
    desktop.TouchArray = { 7: { x: 100, y: 200, f: 3 }, 9: { x: 5, y: 6, f: 1 } };
    desktop.touchtimer = 'touch-timer';
    const beforeTouchReset = sentPackets.length;
    desktop.ProcessScreenMsg(800, 600);
    for (const packet of sentPackets.slice(beforeTouchReset)) { if (packet.charCodeAt(1) === desktop.InputType.TOUCH) { touchPackets.push(packet); } }
    const touchRelease = {
        packets: touchPackets.length,
        messageType: touchPackets.length ? touchPackets[0].charCodeAt(4) : null,
        id: touchPackets.length ? touchPackets[0].charCodeAt(5) : null,
        flags: touchPackets.length ? ((touchPackets[0].charCodeAt(6) << 24) | (touchPackets[0].charCodeAt(7) << 16) | (touchPackets[0].charCodeAt(8) << 8) | touchPackets[0].charCodeAt(9)) >>> 0 : null,
        length: touchPackets.length ? touchPackets[0].length : null,
        remainingContacts: Object.keys(desktop.TouchArray).length,
        touchtimer: desktop.touchtimer,
        clearedTimer
    };
    desktop.State = 0;

    // WEB-2 / WEB-5: no second debug switch and no dead draw or key state.
    const deadState = {
        trace: typeof desktop.trace,
        killDraw: typeof desktop.KillDraw,
        firstUpKeys: typeof desktop.firstUpKeys,
        sourceMentions: ['KVMTRACE', 'kvmtrace', 'KillDraw', 'xcount', 'firstUpKeys'].filter((word) => source.includes(word))
    };
    // Tiles still drain in order and the counters wrap to zero once every received tile is drawn.
    const drawn = [];
    context.Canvas.drawImage = (tile, x, y) => drawn.push([x, y]);
    desktop.Canvas = context.Canvas;
    desktop.State = 3;
    const tiles = [];
    context.Image = function TileMock() { tiles.push(this); };
    desktop.resetDrawState();
    desktop.ProcessPictureMsg(new Uint8Array(8), 0, 0);
    desktop.ProcessPictureMsg(new Uint8Array(8), 16, 0);
    for (const tile of tiles) { tile.onload(); }
    const tileDrain = { drawn: drawn.length, tilesReceived: desktop.tilesReceived, tilesDrawn: desktop.TilesDrawn, pending: desktop.PendingOperations.length };
    desktop.State = 0;

    mutateDesktopState(desktop);
    desktop.Stop();
    const afterStop = captureDesktopState(desktop);

    mutateDesktopState(desktop);
    desktop.Start();
    const afterStart = captureDesktopState(desktop);

    const report = {
        desktopPath,
        firstHandshakeCount,
        secondHandshakeCount,
        sameSizeHandshakeDelta: secondHandshakeCount - firstHandshakeCount,
        parentStateTransitions,
        parentStateAfterFirstScreen,
        parentStateAfterSameSizeReset,
        afterSameSizeReset,
        touchRelease,
        deadState,
        tileDrain,
        afterStop,
        afterStart
    };

    assert(deadState.trace === 'undefined' && deadState.killDraw === 'undefined' && deadState.firstUpKeys === 'undefined', `expected no trace(), KillDraw or firstUpKeys on the module, got ${JSON.stringify(deadState)}`);
    assert(deadState.sourceMentions.length === 0, `expected the viewer source to drop ${deadState.sourceMentions.join(', ')}`);
    assert(tileDrain.drawn === 2 && tileDrain.tilesReceived === 0 && tileDrain.tilesDrawn === 0 && tileDrain.pending === 0, `expected two tiles drawn and the counters wrapped, got ${JSON.stringify(tileDrain)}`);
    assert(touchRelease.packets === 1, `expected one touch packet releasing the held contact on SCREEN, got ${touchRelease.packets}`);
    assert(touchRelease.messageType === 2 && touchRelease.id === 7, `expected a type-2 touch packet carrying contact 7, got ${JSON.stringify(touchRelease)}`);
    assert(touchRelease.flags === 0x00040000, `expected POINTER_FLAG_UP for the held contact, got 0x${(touchRelease.flags || 0).toString(16)}`);
    assert(touchRelease.length === 4 + 1 + 9, `expected exactly one contact in the release packet (queued contact 9 dropped), got length ${touchRelease.length}`);
    assert(touchRelease.remainingContacts === 0, `expected no touch contact left after SCREEN, got ${touchRelease.remainingContacts}`);
    assert(touchRelease.touchtimer === null && touchRelease.clearedTimer === 'touch-timer', `expected the touch timer to be cleared, got ${JSON.stringify(touchRelease)}`);

    assert(report.firstHandshakeCount === 3, `expected first screen reset handshake to send 3 packets, got ${report.firstHandshakeCount}`);
    assert(report.sameSizeHandshakeDelta === 3, `expected same-size screen reset handshake delta to be 3, got ${report.sameSizeHandshakeDelta}`);
    assert(report.parentStateAfterFirstScreen === 3, `expected first screen packet to promote parent state to 3, got ${report.parentStateAfterFirstScreen}`);
    assert(report.parentStateAfterSameSizeReset === 3, `expected same-size reset to keep parent state at 3, got ${report.parentStateAfterSameSizeReset}`);
    assert(report.parentStateTransitions.length === 1 && report.parentStateTransitions[0] === 3, `expected one parent state transition to 3, got ${JSON.stringify(report.parentStateTransitions)}`);
    assert(afterSameSizeReset.pendingOperations === 0, `afterSameSizeReset.pendingOperations was not reset (${afterSameSizeReset.pendingOperations})`);
    assert(afterSameSizeReset.tilesReceived === 0, `afterSameSizeReset.tilesReceived was not reset (${afterSameSizeReset.tilesReceived})`);
    assert(afterSameSizeReset.tilesDrawn === 0, `afterSameSizeReset.tilesDrawn was not reset (${afterSameSizeReset.tilesDrawn})`);
    assert(afterSameSizeReset.firstDraw === true, 'afterSameSizeReset.firstDraw was not armed for the new stream');
    // stopInput is the page's view-only flag, not per-stream state.
    assert(afterSameSizeReset.stopInput === true, 'afterSameSizeReset cleared the page view-only stopInput');
    assert(afterSameSizeReset.pressedKeysLength === 0, `afterSameSizeReset.pressedKeys was not reset (${afterSameSizeReset.pressedKeysLength})`);
    assert(afterSameSizeReset.remoteInputLock === null, `afterSameSizeReset.remoteInputLock was not reset (${afterSameSizeReset.remoteInputLock})`);
    assert(afterSameSizeReset.keyboardState === 0, `afterSameSizeReset.keyboardState was not reset (${afterSameSizeReset.keyboardState})`);
    assert(afterSameSizeReset.displays === null, 'afterSameSizeReset.displays was not reset');
    assert(afterSameSizeReset.selectedDisplay === null, `afterSameSizeReset.selectedDisplay was not reset (${afterSameSizeReset.selectedDisplay})`);

    for (const [phaseName, state] of Object.entries({ afterStop, afterStart })) {
        assert(state.pendingOperations === 0, `${phaseName}.pendingOperations was not reset (${state.pendingOperations})`);
        assert(state.tilesReceived === 0, `${phaseName}.tilesReceived was not reset (${state.tilesReceived})`);
        assert(state.tilesDrawn === 0, `${phaseName}.tilesDrawn was not reset (${state.tilesDrawn})`);
        assert(state.firstDraw === false, `${phaseName}.firstDraw was not reset`);
        assert(state.stopInput === true, `${phaseName} cleared the page view-only stopInput`);
        assert(state.pressedKeysLength === 0, `${phaseName}.pressedKeys was not reset (${state.pressedKeysLength})`);
        assert(state.remoteInputLock === null, `${phaseName}.remoteInputLock was not reset (${state.remoteInputLock})`);
        assert(state.keyboardState === 0, `${phaseName}.keyboardState was not reset (${state.keyboardState})`);
        assert(state.displays === null, `${phaseName}.displays was not reset`);
        assert(state.selectedDisplay === null, `${phaseName}.selectedDisplay was not reset (${state.selectedDisplay})`);
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_desktop_reconnect_runtime.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `DESKTOP_PATH=${desktopPath}`,
            `FIRST_HANDSHAKE_COUNT=${report.firstHandshakeCount}`,
            `SAME_SIZE_HANDSHAKE_DELTA=${report.sameSizeHandshakeDelta}`,
            `PARENT_STATE_TRANSITIONS=${JSON.stringify(report.parentStateTransitions)}`,
            `PARENT_STATE_AFTER_FIRST_SCREEN=${report.parentStateAfterFirstScreen}`,
            `PARENT_STATE_AFTER_SAME_SIZE_RESET=${report.parentStateAfterSameSizeReset}`,
            `AFTER_SAME_SIZE_RESET=${JSON.stringify(afterSameSizeReset)}`,
            `AFTER_STOP=${JSON.stringify(afterStop)}`,
            `AFTER_START=${JSON.stringify(afterStart)}`,
            'SUCCESS=true'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
