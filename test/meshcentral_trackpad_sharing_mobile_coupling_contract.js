// Pin every part of the upstream guest share page for phones (sharing-mobile) that the fork's
// trackpad adapter reads, calls, adds to or listens beneath, so a MeshCentral upgrade that moves any
// of them fails here instead of letting the adapter and the page both process the same touches.
const fs = require('fs');
const path = require('path');
const { meshcentralRoot, upstreamPackageDir } = require('./lib/meshcentral_paths');

const PINNED_MESHCENTRAL = '1.2.5';
// Stock upstream, not the installed package: since Stage 1 the installed package is the fork.
const moduleRoot = upstreamPackageDir();
const scriptsDir = path.join(meshcentralRoot(), 'public', 'scripts');

// Every input is required: a missing or empty file fails the contract and says what it was for.
function read(file) {
    const purpose = file.startsWith(moduleRoot + path.sep) ? `pinned upstream MeshCentral package file this contract pins to ${PINNED_MESHCENTRAL}`
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

function checks() {
    const view = read(path.join(moduleRoot, 'views', 'sharing-mobile.handlebars'));
    const classic = read(path.join(moduleRoot, 'views', 'default-mobile.handlebars'));
    const desktopShare = read(path.join(moduleRoot, 'views', 'sharing.handlebars'));
    const version = JSON.parse(read(path.join(moduleRoot, 'package.json'))).version;
    const adapter = read(path.join(scriptsDir, 'agent-desktop-trackpad-sharing-mobile-0.0.1.js'));
    const canvas = '<canvas id=Desk width=640 height=200 style="width:100%;-ms-touch-action:none;margin-left:0px" oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event)></canvas>';
    return {
        pinnedVersion: version === PINNED_MESHCENTRAL,
        // State the adapter reads.
        declaresFullscreen: declaresVar(view, 'fullscreen'),
        declaresFullscreenZoom: declaresVar(view, 'fullscreenzoom'),
        declaresDesktop: declaresVar(view, 'desktop'),
        declaresDialogMode: declaresVar(view, 'xxdialogMode'),
        // viewOnly is a number (parseInt), compared with === 1.
        viewOnlyIsParsedNumber: view.includes("var viewOnly = parseInt('{{{viewOnly}}}');"),
        currentDevicePanelIsNumber: view.includes('var currentDevicePanel = 0;') && view.includes('if (features & 2) { currentDevicePanel = 1; }'),
        viewOnlyIsStopInput: count(view, 'desktop.m.stopInput = (viewOnly == 1);') === 2 && view.includes('if ((features2 & 0x2000) != 0) desktop.m.stopInput = true;'),
        noSoftDesktop: !view.includes('softdesktop') && !view.includes('webRtcDesktop'),
        sessionActivityFunction: declaresFunction(view, 'setSessionActivity'),
        // The top menu is dialog mode 999, closed by a document click the controller suppresses;
        // the adapter closes it the same way.
        topMenuClosedByClick: view.includes("document.onclick = function (e) { if ((xxdialogMode == 999) && (e.target.id != 'topMenuIcon')) { QV('topMenu', false); xxdialogMode = 0; } }"),
        // No trackpad mode of its own: the adapter keeps it, and detection relies on that.
        noTrackpadMode: !/trackpad/i.test(view),
        // No touch handlers at all: with trackpad mode off, taps reach the page as compatibility
        // mouse events, which the controller's capture listener suppresses while it is on.
        noTouchHandlers: !/touch(start|move|end|cancel)/.test(view),
        noPointerEvents: !/addEventListener\(\s*['"]pointer|onpointer(down|move|up|cancel)/i.test(view),
        // Elements.
        deskParentDeclaredOnce: count(view, 'id=DeskParent') === 1,
        canvasInsideDeskParent: view.includes('<div id=DeskParent style="height:100%">\n                                ' + canvas),
        noLiveCanvasReplacement: count(view, 'canvas id=Desk') === 2 && view.includes("                //QH('DeskParent', '<canvas id=Desk"),
        fullscreenScroller: view.includes('<div id=p10desktop style="overflow:hidden;'),
        fullscreenScrolls: view.includes("QS('p10desktop').overflow = 'scroll';"),
        // The adapter's toggle goes after the keyboard button, in the slot the classic page uses for
        // its trackpad toggle, with the page's own button class and images.
        buttonAnchor: view.includes('<img id="deskkeybutton2b" src="images/mobile-desk-keyboard-close.png" class="deskButton" style="top:210px;display:none" onclick="toggleKeyboard()" />'),
        buttonSlotFree: !view.includes('top:260px'),
        buttonClass: view.includes('.deskButton {\n            box-shadow: 0px 0px 10px #000;') && /\.deskButton \{[^}]*position:absolute;[^}]*z-index:1000;/.test(view),
        classicSlotAndImages: classic.includes('<img id="deskkeybutton6a" src="images/mobile-touch.png" class="deskButton" style="top:260px;display:none"') && classic.includes('<img id="deskkeybutton6b" src="images/mobile-desk-mouse.png" class="deskButton" style="top:260px;display:none"'),
        imagesShipped: ['mobile-touch.png', 'mobile-desk-mouse.png'].every(f => fs.existsSync(path.join(moduleRoot, 'public', 'images', f))),
        // Lifecycle: fullscreen changes only in its declaration and deskToggleFull, which a click or
        // the disconnect handler calls; the adapter turns its mode off when fullscreen ends.
        fullscreenAssignments: (view.match(/\bfullscreen\s*=(?!=)/g) || []).length === 2,
        fullscreenToggle: view.includes('function deskToggleFull() {\n            fullscreen = !fullscreen;'),
        disconnectLeavesFullscreen: view.includes('desktopNode = desktop = null;\n                    QV(\'DeskScreens\', false);\n                    if (fullscreen == true) { deskToggleFull(); }'),
        desktopFactoryCall: view.includes("desktop = CreateAgentRedirect(null, CreateAgentRemoteDesktop('Desk'), serverPublicNamePort, authCookie, null, domainUrl);"),
        stateHandlerAssigned: count(view, 'desktop.onStateChanged = onDesktopStateChange;') === 2,
        // Intel AMT desktops share the canvas without the remote-pixel API: the controller leaves them to the page.
        amtDesktopSharesCanvas: view.includes("CreateAmtRemoteDesktop('Desk')"),
        customJsLoaded: view.includes('{{{customJSTags}}}'),
        noCaptureTouchListeners: !/addEventListener\(\s*['"]touch\w+['"][^)]*(true|capture)/.test(view),
        // Detection: this page has the classic page's markers plus viewOnly, the classic page has its
        // own trackpad mode, and the desktop guest page has neither p10desktop nor fullscreenzoom.
        detectionMarkers: view.includes('id=p10desktop') && view.includes('var fullscreenzoom') && /\n\s*var trackpadMode\s*=/.test(classic) && !/var viewOnly/.test(classic) && !desktopShare.includes('p10desktop') && !desktopShare.includes('fullscreenzoom') && !/var trackpadMode/.test(desktopShare),
        adapterReadsThese: ['window.fullscreen', 'window.currentDevicePanel', 'window.viewOnly', 'window.xxdialogMode', 'window.setSessionActivity', "el('deskkeybutton2b')", "el('p10desktop')"].every(s => adapter.includes(s))
    };
}

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const results = checks();
    const failed = Object.entries(results).filter(([, ok]) => !ok).map(([name]) => name);
    if (evidenceIndex >= 0) {
        const dir = path.resolve(process.argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_trackpad_sharing_mobile_coupling_contract.json'), JSON.stringify({ pinned: PINNED_MESHCENTRAL, results }, null, 2));
    }
    for (const name of failed) console.log(`FAIL ${name}`);
    console.log(`${failed.length ? 'FAIL' : 'PASS'} sharing-mobile trackpad coupling (${Object.keys(results).length} checks, MeshCentral ${PINNED_MESHCENTRAL})`);
    if (failed.length) process.exitCode = 1;
}

main();
