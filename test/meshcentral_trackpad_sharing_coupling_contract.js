// Pin every part of the upstream guest desktop share page for desktop browsers (sharing, also what
// iPadOS gets by default) that the fork's trackpad adapter reads, calls, adds to or listens beneath,
// so a MeshCentral upgrade that moves any of them fails here instead of letting the adapter and the
// page both process the same touches.
const fs = require('fs');
const path = require('path');

const PINNED_MESHCENTRAL = '1.2.5';
const moduleRoot = path.resolve(__dirname, '../../MeshCentral/node_modules/meshcentral');
const scriptsDir = path.resolve(__dirname, '../../MeshCentral/public/scripts');

function read(file) { return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n'); }
function count(text, needle) { return text.split(needle).length - 1; }

function checks() {
    const view = read(path.join(moduleRoot, 'views', 'sharing.handlebars'));
    const mainUi = read(path.join(moduleRoot, 'views', 'default.handlebars'));
    const css = read(path.join(moduleRoot, 'public', 'styles', 'style.css'));
    const sharingCss = read(path.join(moduleRoot, 'public', 'styles', 'style-sharing.css'));
    const version = JSON.parse(read(path.join(moduleRoot, 'package.json'))).version;
    const adapter = read(path.join(scriptsDir, 'agent-desktop-trackpad-sharing-0.0.1.js'));
    const canvas = '<canvas id=Desk width=640 height=480 oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event) onmousewheel=dmousewheel(event)></canvas>';
    const blankCanvas = '<canvas id=Desk oncontextmenu="return false" onmousedown=dmousedown(event) onmouseup=dmouseup(event) onmousemove=dmousemove(event)></canvas>';
    return {
        pinnedVersion: version === PINNED_MESHCENTRAL,
        // State the adapter reads. viewOnly is a number (parseInt), compared with === 1.
        viewOnlyIsParsedNumber: view.includes("var viewOnly = parseInt('{{{viewOnly}}}');"),
        declaresDesktop: view.includes('\n        var desktop = null;'),
        declaresWebRtcDesktop: view.includes('\n        var webRtcDesktop = null;'),
        declaresDialogMode: view.includes('\n        var xxdialogMode;'),
        sessionActivityFunction: view.includes('function setSessionActivity() {'),
        // The adapter's input rule is the page's own.
        inputRule: view.includes("function isInputAllowed() { return (viewOnly != 1) && (Q('DeskControl').checked == true); }"),
        viewOnlyIsStopInput: count(view, 'desktop.m.stopInput = (viewOnly == 1);') === 2,
        // The WebRTC soft desktop is a second viewer module on the same canvas, which the page's own
        // mouse handlers prefer: so does the adapter.
        softDesktopIsNewModule: view.includes("webRtcDesktop.softdesktop = CreateKvmDataChannel(webRtcDesktop.webchannel, CreateAgentRemoteDesktop('Desk', Q('id_mainarea')), desktop.m);") && view.includes('webRtcDesktop.softdesktop.Start();'),
        handlersPreferSoftDesktop: count(view, 'if ((webRtcDesktop != null) && (webRtcDesktop.softdesktop != null)) { webRtcDesktop.softdesktop.m.mouse') === 5,
        // No trackpad mode, zoom state or touch handling of its own: detection and ownership rely on it.
        noTrackpadMode: !/trackpad/i.test(view),
        noMobileZoomState: !view.includes('_mobileZoomMode') && !view.includes('fullscreenzoom'),
        noTouchHandlers: !/touch(start|move|end|cancel)/.test(view),
        noPointerEvents: !/addEventListener\(\s*['"]pointer|onpointer(down|move|up|cancel)/i.test(view),
        noCaptureTouchListeners: !/addEventListener\(\s*['"]touch\w+['"][^)]*(true|capture)/.test(view),
        // Elements: the canvas, the blank canvas it is replaced with on connect, both in #DeskParent.
        deskParentDeclaredOnce: count(view, 'id=DeskParent') === 1,
        canvasInsideDeskParent: view.includes('<div id=DeskParent>\n                    ' + canvas),
        canvasReplacedInDeskParent: view.includes("QH('DeskParent', '" + blankCanvas + "');") && count(view, 'canvas id=Desk') === 2,
        // The adapter's checkbox goes after the page's Input checkbox label.
        inputCheckbox: view.includes('<label><span id="DeskControlSpan" title="Toggle mouse and keyboard input"><input id="DeskControl" type="checkbox" onkeypress="return false" onkeydown="return false" onclick="toggleKvmControl()" />Input</span></label>&nbsp;'),
        noOtherTrackpadIds: !view.includes('meshTrackpad'),
        // #DeskParent is the scroller: the 1:1 view mode scrolls it, and the page's own mouse
        // handlers add its scroll. The stylesheets fit the canvas inside it and do not centre it.
        oneToOneViewScrollsDeskParent: view.includes("QS('Desk').width = deskW + 'px';\n                QS('DeskParent').overflow = 'scroll';"),
        handlersAddDeskParentScroll: count(view, "e.addx = Q('DeskParent').scrollLeft; e.addy = Q('DeskParent').scrollTop;") === 4,
        deskParentCss: css.includes('#DeskParent {\n    margin: 0;\n    overflow: hidden;\n    height: 100%;\n    width: 100%;\n    position: absolute;'),
        deskCss: css.includes('#Desk {\n    overflow: hidden;\n    width: 100%;\n    -ms-touch-action: none;\n    touch-action: none;\n    position: absolute;'),
        noMobileCss: !css.includes('is-mobile') && !sharingCss.includes('is-mobile') && !sharingCss.includes('#DeskParent') && !sharingCss.includes('#Desk '),
        stylesheets: view.includes('href="styles/style.css"') && view.includes('href="styles/style-sharing.css"') && !view.includes('style-bootstrap.css'),
        // Lifecycle: a disconnect drops the desktop, which the adapter reads as the end of the mode.
        disconnectDropsDesktop: view.includes("                    desktop.Stop();\n                    desktop = null;\n                    QV('DeskFocus', false);"),
        // Intel AMT desktops share the canvas without the remote-pixel API: the controller leaves them to the page.
        amtDesktopSharesCanvas: view.includes("CreateAmtRemoteDesktop('Desk')"),
        customJsLoaded: view.includes('{{{customJSTags}}}'),
        // Detection: viewOnly separates this page from the main desktop UI, which has the same
        // scroller and Input checkbox.
        detectionMarkers: view.includes('id=deskarea3x') && view.includes('id="DeskControlSpan"') && mainUi.includes('id=deskarea3x') && mainUi.includes('id="DeskControlSpan"') && !/var viewOnly/.test(mainUi) && !/var trackpadMode/.test(mainUi),
        adapterReadsThese: ['window.viewOnly', 'window.isInputAllowed', 'window.xxdialogMode', 'window.webRtcDesktop', 'window.setSessionActivity', "el('DeskControlSpan')", "el('DeskParent')"].every(s => adapter.includes(s))
    };
}

function main() {
    const evidenceIndex = process.argv.indexOf('--evidence');
    const results = checks();
    const failed = Object.entries(results).filter(([, ok]) => !ok).map(([name]) => name);
    if (evidenceIndex >= 0) {
        const dir = path.resolve(process.argv[evidenceIndex + 1]);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'meshcentral_trackpad_sharing_coupling_contract.json'), JSON.stringify({ pinned: PINNED_MESHCENTRAL, results }, null, 2));
    }
    for (const name of failed) console.log(`FAIL ${name}`);
    console.log(`${failed.length ? 'FAIL' : 'PASS'} sharing trackpad coupling (${Object.keys(results).length} checks, MeshCentral ${PINNED_MESHCENTRAL})`);
    if (failed.length) process.exitCode = 1;
}

main();
