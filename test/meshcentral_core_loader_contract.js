'use strict';
// The agent cores and MeshCmd that MeshCentral builds from the fork package's agents/ tree.
// The fork's own obj.updateMeshCore and obj.updateMeshCmd (meshcentral.js) are executed against the
// fork's agents/ directory, with minifycore off (the default and production setting) and on.
//
// CORE-46: the Windows recovery cores carry every served module that their own modules require.
//   win-terminal requires win-system-paths; agents built before win-system-paths was embedded
//   (MeshAgent 25401cb2, 2026-10-18) have no copy, so recovery terminals and run commands threw there.
//   Modules the agent embeds and the server does not serve (win-registry, win-message-pump) are the
//   agent's own and are not checked here.
// SRV-53 (D24): the package ships no minified MeshCmd (agents/meshcmd.min.js,
//   agents/modules_meshcmd_min/). With minifycore on or off MeshCmd is built from meshcmd.js and
//   modules_meshcmd.
// SRV-18 (D24): with no minified modules there is no .js/.min.js twin to choose between, so the
//   loader has no twin selector, and minifycore does not change any served core.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const zlib = require('zlib');
const { meshcentralRoot, forkFile } = require('./lib/meshcentral_paths');

const root = meshcentralRoot();
const agents = path.join(root, 'agents');
const source = fs.readFileSync(forkFile('meshcentral.js'), 'utf8').replace(/\r\n?/g, '\n');

function extractBraced(signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `meshcentral.js is missing: ${signature}`);
    const bodyStart = source.indexOf('{', start + signature.length - 1);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1) + ';';
    }
    throw new Error(`unterminated: ${signature}`);
}
const versionStart = source.indexOf('    const moduleVersionPattern = ');
const versionEnd = source.indexOf('    // Update the default mesh core', versionStart);
assert(versionStart >= 0 && versionEnd > versionStart, 'module version helpers precede updateMeshCore');
const loader = [
    source.slice(versionStart, versionEnd),
    extractBraced('obj.escapeCodeString = function (str, keepUtf8) {'),
    extractBraced('obj.updateMeshCore = function (func, dumpToFile) {'),
    extractBraced('obj.updateMeshCmd = function (func) {')
].join('\n');

// The pack step writes agents/module-versions.json; a checkout has none, so the manifest is
// synthesised with one date per served module file. Every other read goes to the real tree.
const manifestPath = path.join(agents, 'module-versions.json');
const manifest = { modules: {} };
for (const dir of ['modules_meshcore', 'modules_meshcore_min']) {
    if (!fs.existsSync(path.join(agents, dir))) continue;
    for (const name of fs.readdirSync(path.join(agents, dir))) manifest.modules[dir + '/' + name] = '2026-10-01T00:00:00.000Z';
}
const sandboxFs = Object.assign({}, fs, {
    readFileSync(file, ...rest) {
        if (path.resolve(String(file)) === manifestPath) return JSON.stringify(manifest);
        return fs.readFileSync(file, ...rest);
    }
});

const datapath = fs.mkdtempSync(path.join(os.tmpdir(), 'meshcentral-core-loader-'));
function build(minifycore) {
    const obj = {
        fs: sandboxFs, path, crypto, args: { minifycore }, datapath, debug() {},
        common: { IntToStr: v => String.fromCharCode((v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255) },
        defaultMeshCores: {}, defaultMeshCoresHash: {}, defaultMeshCoresDeflate: {}
    };
    const context = { obj, __dirname: root, Buffer, require: name => (name === 'zlib' ? zlib : require(name)), getCurrentVersion: () => '1.2.5',
        console: { log() {}, error: message => { throw new Error(message); } },
        process: { exit(code) { throw new Error('updateMeshCore exited with ' + code); } } };
    vm.runInNewContext(loader, context);
    let coreDone = null, cmdDone = null;
    obj.updateMeshCore(ok => { coreDone = ok; });
    obj.updateMeshCmd(ok => { cmdDone = ok; });
    assert.strictEqual(coreDone, true, 'updateMeshCore completes');
    assert.strictEqual(cmdDone, true, 'updateMeshCmd completes');
    const cores = {};
    for (const [name, buffer] of Object.entries(obj.defaultMeshCores)) cores[name] = buffer.toString('utf8');
    return { cores, meshcmd: obj.defaultMeshCmd };
}
const modulesIn = text => [...text.matchAll(/try \{ addModule\("([^"]+)"/g)].map(m => m[1]);

try {
    const off = build(false);
    const on = build(true);

    // CORE-46: recovery cores are closed over the served modules their modules require, except
    // served modules every supported agent embeds with the API the recovery modules use.
    // Each entry names the served module that calls it and the calls it makes.
    const agentEmbedded = {
        // Embedded since 2020 (MeshAgent 39a4f997); QueryKey with typed values (_type) since 2019.
        // Later changes touched only QueryKeyLastModified, which win-system-paths does not call.
        'win-registry': { usedBy: 'win-system-paths', apis: ['QueryKey'] },
        // Embedded since 2020 (MeshAgent 39a4f997) with consoleUid() (2019) and Current().Active;
        // recoverycore.js itself already calls the embedded consoleUid().
        'user-sessions': { usedBy: 'win-terminal', apis: ['Current', 'consoleUid'] }
    };
    const polyfills = fs.readFileSync(path.join(__dirname, '..', 'microscript', 'ILibDuktape_Polyfills.c'), 'utf8');
    for (const [name, { usedBy, apis }] of Object.entries(agentEmbedded)) {
        assert(polyfills.includes("addCompressedModule('" + name + "'"), name + ' must be embedded by the agent');
        const userText = fs.readFileSync(path.join(agents, 'modules_meshcore', usedBy + '.js'), 'utf8');
        assert(userText.includes("require('" + name + "')"), usedBy + ' requires ' + name);
        for (const api of apis) assert(userText.includes('.' + api + '('), usedBy + ' uses ' + name + '.' + api);
    }
    const served = new Set(fs.readdirSync(path.join(agents, 'modules_meshcore')).filter(n => n.endsWith('.js')).map(n => n.slice(0, -3)).filter(n => !agentEmbedded[n]));
    for (const core of ['windows-recovery', 'windows-agentrecovery']) {
        assert(off.cores[core], core + ' is built');
        const carried = new Set(modulesIn(off.cores[core]));
        assert(carried.has('win-terminal') && carried.has('win-system-paths'), core + ' carries win-terminal and the win-system-paths it requires');
        for (const name of carried) {
            const text = fs.readFileSync(path.join(agents, 'modules_meshcore', name + '.js'), 'utf8');
            for (const [, dependency] of text.matchAll(/require\('([^']+)'\)/g)) {
                if (served.has(dependency)) assert(carried.has(dependency), `${core}: ${name} requires the served module ${dependency}, which the core must carry`);
            }
        }
    }
    assert(modulesIn(off.cores['windows-amt']).includes('win-system-paths'), 'the normal Windows core still carries win-system-paths');
    for (const core of ['linux-recovery', 'linux-agentrecovery']) {
        assert(!modulesIn(off.cores[core]).some(name => name.startsWith('win-')), core + ' carries no Windows modules');
    }

    // SRV-53: no minified MeshCmd is shipped; MeshCmd comes from meshcmd.js and modules_meshcmd.
    for (const removed of ['meshcmd.min.js', 'modules_meshcmd_min']) {
        assert(!fs.existsSync(path.join(agents, removed)), `agents/${removed} must not be shipped (D24)`);
    }
    const meshcmdSource = fs.readFileSync(path.join(agents, 'meshcmd.js'), 'utf8').replace("'***Mesh*Cmd*Version***'", "'1.2.5'");
    const meshcmdModules = fs.readdirSync(path.join(agents, 'modules_meshcmd')).filter(n => n.endsWith('.js')).map(n => n.slice(0, -3));
    for (const [label, built] of [['minifycore off', off], ['minifycore on', on]]) {
        assert(built.meshcmd.endsWith(meshcmdSource), label + ': MeshCmd is built from agents/meshcmd.js');
        assert.deepStrictEqual(modulesIn(built.meshcmd), meshcmdModules, label + ': MeshCmd carries agents/modules_meshcmd');
    }

    // SRV-18: no minified core modules exist, so minifycore changes no core and no selector remains.
    assert(!fs.readdirSync(path.join(agents, 'modules_meshcore')).some(n => n.endsWith('.min.js')), 'modules_meshcore holds no .min.js twins');
    assert.deepStrictEqual(Object.keys(on.cores).sort(), Object.keys(off.cores).sort(), 'the same cores are built');
    for (const core of Object.keys(off.cores)) assert.strictEqual(on.cores[core], off.cores[core], core + ' does not depend on minifycore');
    assert(!/preferredModule/.test(extractBraced('obj.updateMeshCore = function (func, dumpToFile) {')), 'the .js/.min.js twin selector is gone');
} finally {
    fs.rmSync(datapath, { recursive: true, force: true });
}

console.log('meshcentral_core_loader_contract: PASS (recovery cores carry their served dependencies; MeshCmd and cores come from unminified sources)');
