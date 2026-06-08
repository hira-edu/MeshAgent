const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const modulePath = path.resolve('modules', 'win-deskutils.js');
    const polyfillsPath = path.resolve('microscript', 'ILibDuktape_Polyfills.c');
    const meshcorePath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.js');

    const moduleSource = fs.readFileSync(modulePath, 'utf8');
    const polyfillsSource = fs.readFileSync(polyfillsPath, 'utf8');
    const meshcoreSource = fs.existsSync(meshcorePath) ? fs.readFileSync(meshcorePath, 'utf8') : '';
    const embeddedMatch = polyfillsSource.match(/addCompressedModule\('win-deskutils', Buffer\.from\('([^']+)', 'base64'\)\);/);
    const embeddedSource = embeddedMatch ? zlib.inflateSync(Buffer.from(embeddedMatch[1], 'base64')).toString('utf8') : '';

    const checks = {
        meshcoreRequestsIdleApi:
            meshcoreSource.includes("require('win-deskutils').idle.getSecondsAllSessions().then(function (seconds)"),
        moduleExportsIdleApi:
            moduleSource.includes('module.exports.idle = { getSeconds: idle_getSeconds, getSecondsAllSessions: idle_getSecondsAllSessions };'),
        idleUsesDocumentedWindowsApi:
            moduleSource.includes("user32.CreateMethod('GetLastInputInfo')") &&
            moduleSource.includes('user32.GetLastInputInfo(lastInputInfo)') &&
            moduleSource.includes("wtsapi32.CreateMethod('WTSQuerySessionInformationW')") &&
            moduleSource.includes("wtsapi32.CreateMethod('WTSFreeMemory')") &&
            moduleSource.includes('var WTSIdleTime = 17;'),
        idleUsesTickDeltaWithWrapHandling:
            moduleSource.includes("kernel32.CreateMethod('GetTickCount')") &&
            moduleSource.includes('now >= then ? (now - then) : ((0x100000000 - then) + now)'),
        allSessionsReturnsPromise:
            moduleSource.includes("var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });") &&
            moduleSource.includes('return (resolvedPromise(seconds));'),
        allSessionsUsesServiceSafeWtsQuery:
            moduleSource.includes("idle_getSeconds(sessions[i].SessionId)") &&
            moduleSource.includes('idle_getWtsSessionSeconds(tsid)') &&
            !moduleSource.includes("sessionDispatch(tsid, 'idle', 'getSeconds', [])"),
        allSessionsDoesNotThrowStatusTelemetry:
            moduleSource.includes("try { sessionSeconds = idle_getSeconds(sessions[i].SessionId); } catch (ex3) { continue; }") &&
            moduleSource.includes("if (seconds < 0) { try { seconds = idle_getCurrentSessionSeconds(); } catch (ex4) { } }"),
        sessionDispatchDoesNotPolluteStdout:
            !moduleSource.includes("console.log('stype: ' + stype);"),
        sessionDispatchEmbedsWinDeskutilsForChild:
            moduleSource.includes("childEnv.win_deskutils = getJSModule('win-deskutils');") &&
            moduleSource.includes("addModule('win-deskutils', process.env['win_deskutils'])"),
        nativeRuntimeEmbedsWinDeskutils:
            polyfillsSource.includes("addCompressedModule('win-deskutils'"),
        embeddedWinDeskutilsMatchesSource:
            embeddedSource === moduleSource
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({
        modulePath,
        polyfillsPath,
        meshcorePath,
        checks
    }, null, 2) + '\n');
}

main();
