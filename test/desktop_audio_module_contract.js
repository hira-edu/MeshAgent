'use strict';
// Static contract for modules/desktop-audio.js: the helper launch matches the native
// MeshAudioBridgeW grammar and process policy, the source stays within the Duktape
// idiom, the embedded copy and the MeshCentral core copies match it, and the
// datastore kill switch is documented.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { meshcentralRoot } = require('./lib/meshcentral_paths');

const root = path.resolve(__dirname, '..');
const meshcentral = meshcentralRoot();

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}
function read(file) {
    return fs.readFileSync(file, 'utf8').replace(/\r\n?/g, '\n');
}
function count(haystack, needle) {
    return haystack.split(needle).length - 1;
}

function main() {
    const source = read(path.join(root, 'modules', 'desktop-audio.js'));
    const checks = {};

    // Launch: same rundll32 path, DLL resolution, per-session key and backoff as clipboard.js.
    checks.launchesServiceDllBridge =
        source.includes("execFile(paths.system32Path('rundll32.exe'), [dll + ',MeshAudioBridgeW', state.key])") &&
        source.includes("installedServiceRuntimeDll('' + serviceName)") &&
        source.includes("desktopAudioAcquire('tsid=' + tsid)") &&
        count(source, 'execFile(') === 1;
    checks.boundsAndBackoff =
        source.includes('var DESKTOP_AUDIO_HELPER_LIMIT = 4;') &&
        source.includes('var DESKTOP_AUDIO_RETRY_MS = 30000;') &&
        source.includes('state.retryAt = failed ? Date.now() + DESKTOP_AUDIO_RETRY_MS : 0;') &&
        source.includes("'Desktop audio helper is still terminating.'");
    checks.packetValidation =
        source.includes('var DESKTOP_AUDIO_VERSION = 1;') &&
        source.includes('var DESKTOP_AUDIO_HEADER_BYTES = 16;') &&
        source.includes('var DESKTOP_AUDIO_MAX_PAYLOAD = 4096;') &&
        source.includes('var DESKTOP_AUDIO_MAX_REASON = 256;') &&
        source.includes("if (length > DESKTOP_AUDIO_MAX_PAYLOAD) { desktopAudioInvalid('length'); }") &&
        source.includes("'Invalid desktop audio packet: configuration must come first.'");
    checks.supportAndKillSwitch =
        source.includes("if (process.platform != 'win32') { return false; }") &&
        source.includes("require('MeshAgent').isService !== true") &&
        source.includes("CreateVariable('MeshAudioBridgeW')") &&
        source.includes("require('SimpleDataStore').Shared().Get('desktopAudio')") &&
        source.includes("catch (datastoreError) { return true; }") &&
        source.includes("else if (desktopAudioDisabled())");
    // Duktape: createEvent('close') installs an accessor that shadows a prototype close().
    checks.closeIsInstanceMethod =
        source.includes(".addMethod('close', function close() { desktopAudioRelease(this); });") &&
        !source.includes('prototype.close');
    checks.exportsOnlySpecApi = /module\.exports =\n\{\n    supported: desktopAudioSupported,\n    disabled: desktopAudioDisabled,\n    open: function open\(tsid\) \{ return \(new DesktopAudioStream\(tsid\)\); \}\n\};\n$/.test(source);
    // No audio content (or anything else) is logged, stored or written by the module.
    checks.noLoggingOrStorage =
        !/console\.|rawLog|require\('fs'\)|writeFile|appendFile|\.Put\(/.test(source);
    // Duktape-compatible ES5 idiom; Duktape's Buffer.from() does not accept arrays.
    checks.duktapeSyntax =
        !/=>|`|\blet\s|\bconst\s|\bclass\s|\.\.\.|Buffer\.from\(\[/.test(source);

    // The embedded copy is what ships; it must match the source and be Windows-only.
    const polyfills = read(path.join(root, 'microscript', 'ILibDuktape_Polyfills.c'));
    const embed = /addCompressedModule\('desktop-audio', Buffer\.from\('([^']+)', 'base64'\), '([^']+)'\)/.exec(polyfills);
    checks.embeddedOnce = embed != null && count(polyfills, "addCompressedModule('desktop-audio'") === 1;
    checks.embeddedMatchesSource = embed != null &&
        zlib.inflateSync(Buffer.from(embed[1], 'base64')).toString('utf8').replace(/\r\n?/g, '\n') === source;
    if (embed != null) {
        const before = polyfills.slice(0, embed.index);
        checks.embeddedWindowsOnly = before.lastIndexOf('#ifdef WIN32') > before.lastIndexOf('#endif');
    } else {
        checks.embeddedWindowsOnly = false;
    }

    // Native side: the helper accepts exactly the form the module launches.
    const bridge = read(path.join(root, 'meshservice', 'audio_bridge.h'));
    const processPipe = read(path.join(root, 'microstack', 'ILibProcessPipe.c'));
    checks.nativeGrammarMatches =
        bridge.includes('MeshAudioBridgeW tsid=<sessionId>') &&
        bridge.includes('wcsncmp(mode, L"tsid=", 5) == 0') &&
        processPipe.includes('ILibProcessPipe_IsApprovedAudioBridgeLaunchA(target, parameters)');

    // MeshCentral core modules: identical copies, as for the other published core modules.
    const copies = [
        path.join(meshcentral, 'agents', 'modules_meshcore', 'desktop-audio.js')
    ];
    checks.meshcentralCopiesMatch = copies.every((file) => fs.existsSync(file) && read(file) === source);

    const configuration = read(path.join(root, 'docs', 'CONFIGURATION.md'));
    checks.killSwitchDocumented = configuration.includes('`desktopAudio`') && configuration.includes('MeshAudioBridgeW');

    const failed = Object.keys(checks).filter((name) => !checks[name]);
    process.stdout.write(JSON.stringify({ success: failed.length === 0, checks }, null, 2) + '\n');
    assert(failed.length === 0, 'Desktop audio module contract failed: ' + failed.join(', '));
}

main();
