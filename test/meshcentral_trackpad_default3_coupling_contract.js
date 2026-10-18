// Pin every part of the upstream Modern UI view (default3) that the fork's trackpad adapter reads,
// calls or listens beneath, so a MeshCentral upgrade that moves any of them fails here instead of
// letting the adapter and the view both process the same touches.
const fs = require('fs');
const path = require('path');

const PINNED_MESHCENTRAL = '1.2.5';
const moduleRoot = path.resolve(__dirname, '../../MeshCentral/node_modules/meshcentral');
const scriptsDir = path.resolve(__dirname, '../../MeshCentral/public/scripts');

function read(file) { return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n'); }
function count(text, needle) { return text.split(needle).length - 1; }
function declaresVar(text, name) { return new RegExp('\\n\\s*var ' + name.replace(/\$/g, '\\$') + '\\s*(=|;)').test(text); }
function declaresFunction(text, name) { return text.includes('function ' + name + '('); }
// Calls only: definitions are "GrabMouseInput = function", references are "GrabMouseInput;".
function grabMouseInputCalls(text) { return (text.match(/(?<!Un)GrabMouseInput\s*\(/g) || []).length; }

function checks() {
    const view = read(path.join(moduleRoot, 'views', 'default3.handlebars'));
    const mobileView = read(path.join(moduleRoot, 'views', 'default-mobile.handlebars'));
    const version = JSON.parse(read(path.join(moduleRoot, 'package.json'))).version;
    const fork = ['agent-desktop-0.0.2.js', 'agent-redir-ws-0.1.1.js'].map(f => read(path.join(scriptsDir, f)));
    const upstream = ['agent-redir-ws-0.1.1.js', 'agent-redir-rtc-0.1.0.js'].map(f => path.join(moduleRoot, 'public', 'scripts', f)).filter(fs.existsSync).map(read);
    const staticCanvas = '<canvas id=Desk width=640 height=480 oncontextmenu="return false"\n                                onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event)\n                                onmousewheel=dmousewheel(event)\n                                ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>';
    const blankCanvas = "QH('DeskParent', '<canvas id=Desk oncontextmenu=\"return false\" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>');";
    const replacementCanvas = "QH('DeskParent', '<canvas id=\"Desk\" oncontextmenu=\"return false\" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event)></canvas>');";
    return {
        pinnedVersion: version === PINNED_MESHCENTRAL,
        // State the adapter reads.
        declaresTrackpadMode: declaresVar(view, 'trackpadMode'),
        declaresDesktop: declaresVar(view, 'desktop'),
        declaresWebRtcDesktop: declaresVar(view, 'webRtcDesktop'),
        declaresDialogMode: declaresVar(view, 'xxdialogMode'),
        declaresMobileZoomMode: declaresVar(view, '_mobileZoomMode'),
        zoomModesAreFitAndNative: view.includes("_mobileZoomMode === 'native'") && view.includes("_mobileZoomMode = 'fit'"),
        softDesktopModuleResolution: view.includes('return (webRtcDesktop && webRtcDesktop.softdesktop) ? webRtcDesktop.softdesktop.m : (desktop ? desktop.m : null);'),
        inputToggleIsDeskControl: view.includes('id="DeskControl"') && view.includes("Q('DeskControl').checked"),
        isMobileBodyClass: view.includes("document.body.classList.contains('is-mobile')"),
        // Side duties the adapter performs in place of dtouchstart.
        sessionActivityFunction: declaresFunction(view, 'setSessionActivity'),
        closeMobileActionsFunction: declaresFunction(view, 'deskCloseMobileActions'),
        dtouchstartDuties: view.includes('function dtouchstart(e) {\n            setSessionActivity();\n            deskCloseMobileActions();'),
        // Native zoom is applied through these CSS variables.
        nativeZoomCssVariables: view.includes("setProperty('--native-desk-w'") && view.includes("setProperty('--native-desk-h'"),
        // Elements.
        deskParentDeclaredOnce: count(view, 'id=DeskParent') === 1 && !view.includes("QH('deskarea3x'"),
        deskArea3xScroller: view.includes('id=deskarea3x>'),
        upstreamOverlay: view.includes('<svg id="trackpadCursor"'),
        // Every markup the page uses for #Desk, all inside #DeskParent.
        staticCanvasMarkup: view.includes(staticCanvas),
        blankCanvasMarkup: view.includes(blankCanvas),
        replacementCanvasMarkup: view.includes(replacementCanvas),
        noOtherCanvasMarkup: count(view, 'canvas id=Desk ') + count(view, 'canvas id="Desk" ') === 3,
        // The adapter assumes the view binds no cancel or pointer handlers of its own.
        noTouchCancel: !view.includes('touchcancel'),
        // (The device map's OpenLayers 'pointermove' is not a DOM listener and is unrelated.)
        noPointerEvents: !/addEventListener\(\s*['"]pointer|onpointer(down|move|up|cancel)/i.test(view),
        // Lifecycle: nothing calls GrabMouseInput, so the adapter must not depend on it.
        grabMouseInputUncalled: [view].concat(fork, upstream).every(text => grabMouseInputCalls(text) === 0),
        // Mode toggle and its disconnect reset stay upstream's.
        trackpadToggle: declaresFunction(view, 'deskToggleTrackpad'),
        disconnectResetsTrackpad: view.includes("if (typeof trackpadMode !== 'undefined') {\n                        trackpadMode = false;"),
        // Adapter detection: these markers identify this view and are absent from the classic one.
        detectionMarkers: view.includes('id=deskarea3x>') && view.includes('_mobileZoomMode') && !mobileView.includes('id=deskarea3x') && !mobileView.includes('_mobileZoomMode'),
        customJsLoaded: view.includes('{{{customJSTags}}}'),
        // Intel AMT desktops share the canvas without the remote-pixel API: the controller leaves them to the page.
        amtDesktopSharesCanvas: view.includes("CreateAmtRemoteDesktop('Desk')"),
        // The page's edge-scroll interval outlives a gesture the controller takes over; only
        // dtouchstart (and trackpadStopEdgeScroll, which the adapter calls) stops it.
        edgeScrollStop: declaresFunction(view, 'trackpadStopEdgeScroll'),
        edgeScrollGating: view.includes('if ((!trackpadMode && !dtouchDragActive) || (trackpadEdgeDX === 0 && trackpadEdgeDY === 0)) { trackpadStopEdgeScroll(); return; }'),
        dtouchstartStopsEdgeScroll: view.includes('dtouchLongPressed = false; dtouchDragActive = false; trackpadStopEdgeScroll();'),
        // trackpadMode changes only in its declaration, the toggle and the disconnect reset; the last
        // has no click, which is why the controller also watches while a button is held.
        trackpadModeAssignments: (view.match(/\btrackpadMode\s*=(?!=)/g) || []).length === 3,
        // Input can be unchecked without a click (rights refresh): same reason.
        inputUncheckedWithoutClick: view.includes("Q('DeskControl').checked = false;"),
        // No other capture-phase touch listener that could run before the controller's.
        noCaptureTouchListeners: !/addEventListener\(\s*['"]touch\w+['"][^)]*(true|capture)/.test(view),
        // deskarea3x is the native-zoom scroller the adapter follows and pans.
        nativeZoomScroller: view.includes("var sc = Q('deskarea3x');") && view.includes('sc.scrollLeft -= dx'),
        // The WebRTC soft desktop is a new viewer module on the same canvas that reaches state 3 in
        // Start(), before its first SCREEN: the controller releases on the old module and waits
        // for the new one's screen.
        softDesktopIsNewModule: view.includes("webRtcDesktop.softdesktop = CreateKvmDataChannel(webRtcDesktop.webchannel, CreateAgentRemoteDesktop('Desk', Q('id_mainarea')), desktop.m);") && view.includes('webRtcDesktop.softdesktop.Start();'),
        softDesktopConnectsOnStart: read(path.join(moduleRoot, 'public', 'scripts', 'agent-redir-rtc-0.1.0.js')).includes("obj.Start = function () {\n        if (obj.debugmode == 1) { console.log('start'); }\n        obj.xxStateChange(3);")
    };
}

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const results = checks();
    const failed = Object.entries(results).filter(([, ok]) => !ok).map(([name]) => name);
    if (evidenceIndex >= 0) {
        const dir = path.resolve(process.argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_trackpad_default3_coupling_contract.json'), JSON.stringify({ pinned: PINNED_MESHCENTRAL, results }, null, 2));
    }
    for (const name of failed) console.log(`FAIL ${name}`);
    console.log(`${failed.length ? 'FAIL' : 'PASS'} default3 trackpad coupling (${Object.keys(results).length} checks, MeshCentral ${PINNED_MESHCENTRAL})`);
    if (failed.length) process.exitCode = 1;
}

main();
