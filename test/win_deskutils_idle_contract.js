const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

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

function readSource(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const modulePath = path.resolve('modules', 'win-deskutils.js');
    const polyfillsPath = path.resolve('microscript', 'ILibDuktape_Polyfills.c');
    const meshcorePath = path.resolve('..', 'MeshCentral', 'agents', 'meshcore.js');

    const moduleSource = readSource(modulePath);
    const polyfillsSource = readSource(polyfillsPath);
    const meshcoreSource = fs.existsSync(meshcorePath) ? readSource(meshcorePath) : '';
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
        sessionDispatchDeniesChildProcessBridge:
            moduleSource.includes('Windows desktop utility session dispatch is disabled until an approved rundll32 contract export exists.') &&
            !moduleSource.includes("childEnv.win_deskutils = getJSModule('win-deskutils');") &&
            !moduleSource.includes("addModule('win-deskutils', process.env['win_deskutils'])") &&
            !moduleSource.includes("'-b64exec'"),
        nativeRuntimeEmbedsWinDeskutils:
            polyfillsSource.includes("addCompressedModule('win-deskutils'"),
        embeddedWinDeskutilsMatchesSource:
            embeddedSource === moduleSource
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        modulePath,
        polyfillsPath,
        meshcorePath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'win_deskutils_idle_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
