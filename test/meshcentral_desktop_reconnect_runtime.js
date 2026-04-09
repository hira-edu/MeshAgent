const fs = require('fs');
const path = require('path');
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
        Blob: function BlobMock() {},
        FileReader: function FileReaderMock() {}
    };
    return { context, canvasElement };
}

function mutateDesktopState(desktop) {
    desktop.PendingOperations = [[7, 2]];
    desktop.tilesReceived = 9;
    desktop.TilesDrawn = 8;
    desktop.KillDraw = 3;
    desktop.FirstDraw = true;
    desktop.stopInput = true;
    desktop.firstUpKeys = [16, 17, 18];
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
        killDraw: desktop.KillDraw,
        firstDraw: desktop.FirstDraw,
        stopInput: desktop.stopInput,
        firstUpKeysLength: desktop.firstUpKeys.length,
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
    const desktopPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-desktop-0.0.2.js');
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
        }
    };

    desktop.ProcessScreenMsg(800, 600);
    const firstHandshakeCount = sentPackets.length;
    const parentStateAfterFirstScreen = desktop.parent.State;
    mutateDesktopState(desktop);
    desktop.ProcessScreenMsg(800, 600);
    const secondHandshakeCount = sentPackets.length;
    const afterSameSizeReset = captureDesktopState(desktop);
    const parentStateAfterSameSizeReset = desktop.parent.State;

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
        afterStop,
        afterStart
    };

    assert(report.firstHandshakeCount === 3, `expected first screen reset handshake to send 3 packets, got ${report.firstHandshakeCount}`);
    assert(report.sameSizeHandshakeDelta === 3, `expected same-size screen reset handshake delta to be 3, got ${report.sameSizeHandshakeDelta}`);
    assert(report.parentStateAfterFirstScreen === 3, `expected first screen packet to promote parent state to 3, got ${report.parentStateAfterFirstScreen}`);
    assert(report.parentStateAfterSameSizeReset === 3, `expected same-size reset to keep parent state at 3, got ${report.parentStateAfterSameSizeReset}`);
    assert(report.parentStateTransitions.length === 1 && report.parentStateTransitions[0] === 3, `expected one parent state transition to 3, got ${JSON.stringify(report.parentStateTransitions)}`);
    assert(afterSameSizeReset.pendingOperations === 0, `afterSameSizeReset.pendingOperations was not reset (${afterSameSizeReset.pendingOperations})`);
    assert(afterSameSizeReset.tilesReceived === 0, `afterSameSizeReset.tilesReceived was not reset (${afterSameSizeReset.tilesReceived})`);
    assert(afterSameSizeReset.tilesDrawn === 0, `afterSameSizeReset.tilesDrawn was not reset (${afterSameSizeReset.tilesDrawn})`);
    assert(afterSameSizeReset.killDraw === 0, `afterSameSizeReset.killDraw was not reset (${afterSameSizeReset.killDraw})`);
    assert(afterSameSizeReset.firstDraw === true, 'afterSameSizeReset.firstDraw was not armed for the new stream');
    assert(afterSameSizeReset.stopInput === false, 'afterSameSizeReset.stopInput was not cleared');
    assert(afterSameSizeReset.firstUpKeysLength === 0, `afterSameSizeReset.firstUpKeys was not reset (${afterSameSizeReset.firstUpKeysLength})`);
    assert(afterSameSizeReset.pressedKeysLength === 0, `afterSameSizeReset.pressedKeys was not reset (${afterSameSizeReset.pressedKeysLength})`);
    assert(afterSameSizeReset.remoteInputLock === null, `afterSameSizeReset.remoteInputLock was not reset (${afterSameSizeReset.remoteInputLock})`);
    assert(afterSameSizeReset.keyboardState === 0, `afterSameSizeReset.keyboardState was not reset (${afterSameSizeReset.keyboardState})`);
    assert(afterSameSizeReset.displays === null, 'afterSameSizeReset.displays was not reset');
    assert(afterSameSizeReset.selectedDisplay === null, `afterSameSizeReset.selectedDisplay was not reset (${afterSameSizeReset.selectedDisplay})`);

    for (const [phaseName, state] of Object.entries({ afterStop, afterStart })) {
        assert(state.pendingOperations === 0, `${phaseName}.pendingOperations was not reset (${state.pendingOperations})`);
        assert(state.tilesReceived === 0, `${phaseName}.tilesReceived was not reset (${state.tilesReceived})`);
        assert(state.tilesDrawn === 0, `${phaseName}.tilesDrawn was not reset (${state.tilesDrawn})`);
        assert(state.killDraw === 0, `${phaseName}.killDraw was not reset (${state.killDraw})`);
        assert(state.firstDraw === false, `${phaseName}.firstDraw was not reset`);
        assert(state.stopInput === false, `${phaseName}.stopInput was not reset`);
        assert(state.firstUpKeysLength === 0, `${phaseName}.firstUpKeys was not reset (${state.firstUpKeysLength})`);
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
