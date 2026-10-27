// Pin every part of the upstream classic mobile view (default-mobile) that the fork's trackpad
// adapter reads, calls or listens beneath, so a MeshCentral upgrade that moves any of them fails
// here instead of letting the adapter and the view both process the same touches.
const fs = require('fs');
const path = require('path');
const { meshcentralRoot, installedPackageDir } = require('./lib/meshcentral_paths');

const PINNED_MESHCENTRAL = '1.2.5';
const moduleRoot = installedPackageDir().dir;
const scriptsDir = path.join(meshcentralRoot(), 'public', 'scripts');

// Every input is required: a missing or empty file fails the contract and says what it was for.
function read(file) {
    const purpose = file.startsWith(moduleRoot + path.sep) ? `installed MeshCentral package file this contract pins to ${PINNED_MESHCENTRAL}`
        : file.startsWith(scriptsDir + path.sep) ? 'fork script checked against the pinned upstream page' : 'coupling contract input';
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
function declaresVar(text, name) { return new RegExp('\\n\\s*var ' + name + '\\s*(=|;)').test(text); }
function declaresFunction(text, name) { return text.includes('function ' + name + '('); }
// Calls only: definitions are "GrabMouseInput = function", references are "GrabMouseInput;".
function grabMouseInputCalls(text) { return (text.match(/(?<!Un)GrabMouseInput\s*\(/g) || []).length; }

function checks() {
    const view = read(path.join(moduleRoot, 'views', 'default-mobile.handlebars'));
    const modernView = read(path.join(moduleRoot, 'views', 'default3.handlebars'));
    const version = JSON.parse(read(path.join(moduleRoot, 'package.json'))).version;
    const fork = ['agent-desktop-0.0.2.js', 'agent-redir-ws-0.1.1.js'].map(f => read(path.join(scriptsDir, f)));
    const canvas = '<canvas id=Desk width=640 height=200 style="width:100%;-ms-touch-action:none;margin-left:0px" oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event) ontouchstart=dtouchstart(event) ontouchmove=dtouchmove(event) ontouchend=dtouchend(event)></canvas>';
    return {
        pinnedVersion: version === PINNED_MESHCENTRAL,
        // State the adapter reads.
        declaresTrackpadMode: declaresVar(view, 'trackpadMode'),
        declaresFullscreen: declaresVar(view, 'fullscreen'),
        declaresFullscreenZoom: declaresVar(view, 'fullscreenzoom'),
        fullscreenZoomIsOneOrHalf: view.includes('if (fullscreenzoom == 1) { fullscreenzoom = 0.5; } else { fullscreenzoom = 1; }'),
        declaresDesktop: declaresVar(view, 'desktop'),
        declaresDialogMode: declaresVar(view, 'xxdialogMode'),
        // The adapter targets desktop.m directly: this view has no WebRTC soft desktop.
        noSoftDesktop: !view.includes('softdesktop') && !view.includes('webRtcDesktop'),
        viewOnlyIsStopInput: view.includes('if ((features2 & 0x2000) != 0) desktop.m.stopInput = true;'),
        // Side duty the adapter performs in place of dtouchstart.
        sessionActivityFunction: declaresFunction(view, 'setSessionActivity'),
        dtouchstartDuty: view.includes('function dtouchstart(e) {\n            setSessionActivity();'),
        // Elements.
        deskParentDeclaredOnce: count(view, 'id=DeskParent') === 1,
        canvasInsideDeskParent: view.includes('<div id=DeskParent style="height:100%">\n                                ' + canvas),
        // The only other canvas markup is a commented-out replacement, so the canvas is never recreated.
        noLiveCanvasReplacement: count(view, 'canvas id=Desk') === 2 && view.includes("                //QH('DeskParent', '<canvas id=Desk"),
        fullscreenScroller: view.includes('<div id=p10desktop style="overflow:hidden;'),
        overlayOffsetParent: view.includes('<div id=p10 ') && view.includes("var p10Rect = Q('p10').getBoundingClientRect();"),
        upstreamOverlay: view.includes('<img id="trackpadCursor" src="images/mobile-pointer.png"'),
        trackpadToggleButtons: view.includes('id="deskkeybutton6a"') && view.includes('id="deskkeybutton6b"'),
        // The adapter assumes the view binds no cancel or pointer handlers of its own.
        noTouchCancel: !view.includes('touchcancel'),
        noPointerEvents: !/addEventListener\(\s*['"]pointer|onpointer(down|move|up|cancel)/i.test(view),
        // Lifecycle: the desktop is created through the factory custom.js already hooks, and the
        // page's state handler is assigned afterwards (the hook's setter chain captures it).
        desktopFactoryCall: view.includes("desktop = CreateAgentRedirect(meshserver, CreateAgentRemoteDesktop('Desk'), serverPublicNamePort, authCookie, authRelayCookie, domainUrl);"),
        stateHandlerAssigned: view.includes('desktop.onStateChanged = onDesktopStateChange;'),
        grabMouseInputUncalled: [view].concat(fork).every(text => grabMouseInputCalls(text) === 0),
        // Mode toggle, fullscreen-only availability and the fullscreen-exit reset stay upstream's.
        trackpadToggle: declaresFunction(view, 'deskToggleTrackpad'),
        trackpadOnlyInFullscreen: view.includes("QV('deskkeybutton6a', fullscreen && inputAllowed && !trackpadMode);"),
        fullscreenExitResetsTrackpad: view.includes('if (!fullscreen && trackpadMode) {\n                    trackpadMode = false;'),
        // Adapter detection: these markers identify this view and are absent from the modern one.
        detectionMarkers: view.includes('id=p10desktop') && view.includes('var fullscreenzoom') && !modernView.includes('id=p10desktop') && !modernView.includes('fullscreenzoom'),
        customJsLoaded: view.includes('{{{customJSTags}}}'),
        // Intel AMT desktops share the canvas without the remote-pixel API: the controller leaves them to the page.
        amtDesktopSharesCanvas: view.includes("CreateAmtRemoteDesktop('Desk')"),
        edgeScrollStop: declaresFunction(view, 'trackpadStopEdgeScroll'),
        // The top menu is dialog mode 999, closed by a document click the controller suppresses;
        // the adapter closes it the same way.
        topMenuClosedByClick: view.includes("document.onclick = function (e) { if ((xxdialogMode == 999) && (e.target.id != 'topMenuIcon')) { QV('topMenu', false); xxdialogMode = 0; } }"),
        edgeScrollGating: view.includes('if (!trackpadMode || (trackpadEdgeDX === 0 && trackpadEdgeDY === 0)) { trackpadStopEdgeScroll(); return; }'),
        // trackpadMode changes only in its declaration, the toggle and the fullscreen-exit reset, and
        // fullscreen only in its declaration and deskToggleFull: the activation the adapter reads.
        trackpadModeAssignments: (view.match(/\btrackpadMode\s*=(?!=)/g) || []).length === 3,
        fullscreenAssignments: (view.match(/\bfullscreen\s*=(?!=)/g) || []).length === 2,
        noCaptureTouchListeners: !/addEventListener\(\s*['"]touch\w+['"][^)]*(true|capture)/.test(view),
        // p10desktop scrolls in fullscreen: the adapter's follow target.
        fullscreenScrolls: view.includes("QS('p10desktop').overflow = 'scroll';"),
        // The guest share page has this page's markers but no trackpad mode, which is why detection
        // also requires trackpadMode.
        sharePageHasNoTrackpadMode: (() => { const share = read(path.join(moduleRoot, 'views', 'sharing-mobile.handlebars')); return /id="?p10desktop/.test(share) && share.includes('fullscreenzoom') && !/var trackpadMode/.test(share); })()
    };
}

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const results = checks();
    const failed = Object.entries(results).filter(([, ok]) => !ok).map(([name]) => name);
    if (evidenceIndex >= 0) {
        const dir = path.resolve(process.argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_trackpad_default_mobile_coupling_contract.json'), JSON.stringify({ pinned: PINNED_MESHCENTRAL, results }, null, 2));
    }
    for (const name of failed) console.log(`FAIL ${name}`);
    console.log(`${failed.length ? 'FAIL' : 'PASS'} default-mobile trackpad coupling (${Object.keys(results).length} checks, MeshCentral ${PINNED_MESHCENTRAL})`);
    if (failed.length) process.exitCode = 1;
}

main();
