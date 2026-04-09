const fs = require('fs');
const path = require('path');

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

function evaluateStandardAsset(source) {
    const startMarker = 'obj.ProcessScreenMsg = function (width, height) {';
    const endMarker = 'obj.ProcessBinaryCommand = function (cmd, cmdsize, view) {';
    const start = source.indexOf(startMarker);
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    const functionSource = start >= 0 && end > start ? source.slice(start, end) : '';
    return {
        functionLocated: functionSource.length > 0,
        acceptsSameSizeScreenPackets: !functionSource.includes('if ((obj.ScreenWidth == width) && (obj.ScreenHeight == height)) return;'),
        updatesScreenDimensions: functionSource.includes('obj.ScreenWidth = obj.width = width;') &&
            functionSource.includes('obj.ScreenHeight = obj.height = height;'),
        resetsPendingDrawQueue: functionSource.includes("obj.resetStreamState('screen:") ||
            functionSource.includes("obj.resetDrawState('screen:") ||
            (functionSource.includes('obj.KillDraw = obj.tilesReceived;') &&
                functionSource.includes('while (obj.PendingOperations.length > 0) { obj.PendingOperations.shift(); }')),
        refreshesCompressionHandshakeOnResize: functionSource.includes('obj.SendCompressionLevel(obj.ImageType);'),
        sendsUnpauseOnResize: functionSource.includes('obj.SendUnPause();'),
        sendsInputLockQueryOnResize: functionSource.includes('obj.SendRemoteInputLock(2);'),
        firesResizeEventForAcceptedResize: functionSource.includes('if (obj.onScreenSizeChange != null) { obj.onScreenSizeChange(obj, obj.ScreenWidth, obj.ScreenHeight, obj.CanvasId); }')
    };
}

function evaluateMinifiedAsset(source) {
    return {
        functionLocated: source.includes('n.ProcessScreenMsg=function(e,t){'),
        acceptsSameSizeScreenPackets: !source.includes('n.ScreenWidth!=e||n.ScreenHeight!=t'),
        updatesScreenDimensions: source.includes('n.ScreenWidth=n.width=e,n.ScreenHeight=n.height=t'),
        resetsPendingDrawQueue: source.includes('n.resetStreamState("screen:') ||
            source.includes('n.resetDrawState("screen:') ||
            (source.includes('n.KillDraw=n.tilesReceived') &&
                source.includes('n.PendingOperations.length>0;)n.PendingOperations.shift()')),
        refreshesCompressionHandshakeOnResize: source.includes('n.SendCompressionLevel(n.ImageType),n.SendUnPause(),n.SendRemoteInputLock(2)'),
        sendsInputLockQueryOnResize: source.includes('n.SendRemoteInputLock(2)'),
        firesResizeEventForAcceptedResize: source.includes('null!=n.onScreenSizeChange&&n.onScreenSizeChange(n,n.ScreenWidth,n.ScreenHeight,n.CanvasId)')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const desktopPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-desktop-0.0.2.js');
    const desktopMinPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-desktop-0.0.2-min.js');
    const checks = {
        standard: evaluateStandardAsset(fs.readFileSync(desktopPath, 'utf8')),
        minified: evaluateMinifiedAsset(fs.readFileSync(desktopMinPath, 'utf8'))
    };

    for (const [assetName, assetChecks] of Object.entries(checks)) {
        for (const [name, passed] of Object.entries(assetChecks)) {
            assert(passed, `${assetName}.${name} failed`);
        }
    }

    const report = {
        desktopPath,
        desktopMinPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_desktop_same_size_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `DESKTOP_PATH=${desktopPath}`,
            `DESKTOP_MIN_PATH=${desktopMinPath}`,
            'SUCCESS=true',
            `STANDARD_CHECKS=${Object.entries(checks.standard).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `MINIFIED_CHECKS=${Object.entries(checks.minified).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
