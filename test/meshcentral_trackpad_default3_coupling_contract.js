// Pin every part of the Modern UI view (default3) that the fork's trackpad adapter reads,
// calls or listens beneath, so a MeshCentral upgrade that moves any of them fails here instead of
// letting the adapter and the view both process the same touches.
const fs = require('fs');
const path = require('path');
const { meshcentralRoot } = require('./lib/meshcentral_paths');

const PINNED_MESHCENTRAL = '1.2.5';
// The fork's own package source: since Stage 2 the fork serves its own views (the production
// overrides are retired, D16, and #8104 is a fork commit). How these files differ from the pinned
// upstream package is checked separately, hunk by hunk, by meshcentral_upstream_base_contract.js,
// so an upstream change stays visible there.
const moduleRoot = meshcentralRoot();
const scriptsDir = path.join(moduleRoot, 'public', 'scripts');

// Every input is required: a missing or empty file fails the contract and says what it was for.
function read(file) {
    const purpose = file.startsWith(scriptsDir + path.sep) ? 'fork script checked against the fork page'
        : file.startsWith(moduleRoot + path.sep) ? `fork package file this contract pins (MeshCentral ${PINNED_MESHCENTRAL} base)` : 'coupling contract input';
    let text;
    try {
        text = fs.readFileSync(file, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') throw new Error(`required input missing: ${file} (${purpose})`, { cause: error });
        throw error;
    }
    if (text.trim().length === 0) throw new Error(`required input is empty: ${file} (${purpose})`);
    return text.replace(/\r\n/g, '\n');
}
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
    // Both redirect scripts the page can load are required, so neither can drop out of the
    // GrabMouseInput check below.
    const upstream = ['agent-redir-ws-0.1.1.js', 'agent-redir-rtc-0.1.0.js'].map(f => read(path.join(moduleRoot, 'public', 'scripts', f)));
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
        // A pinch in fit mode calls the page's own switch into native zoom, then overrides the
        // size it sets with the fit size. The switch sets the mode first and the variables directly.
        mobileSetZoomSwitch: view.includes("function _mobileSetZoom(mode) {\n            _mobileZoomMode = mode;") &&
            view.includes("document.documentElement.style.setProperty('--native-desk-w', w + 'px');\n                document.documentElement.style.setProperty('--native-desk-h', h + 'px');\n                document.body.classList.add('native-zoom');"),
        // The mobile stylesheet centres the fit canvas in #DeskParent, and native zoom makes
        // #DeskParent a block at the scroller's origin: the pinch anchor is taken before the switch.
        mobileCanvasCentred: (() => { const css = read(path.join(moduleRoot, 'public', 'styles', 'style-bootstrap.css')); return css.includes('body.is-mobile #DeskParent {\n    display: flex !important;\n    align-items: center !important;\n    justify-content: center !important;') && css.includes('body.is-mobile.native-zoom #DeskParent {\n    position: relative !important;\n    display: block !important;') && css.includes('body.is-mobile.native-zoom #Desk {\n    width: 100% !important;\n    height: 100% !important;'); })(),
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
