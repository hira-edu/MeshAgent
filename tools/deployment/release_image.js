'use strict';
// Release image build steps (tools/deployment/Dockerfile). Runs inside the Linux build stage.
//
//   node release_image.js verify-pack --meshcentral <checkout> --pack-record <file>
//       T21/D4: the tarball this Linux pack produced is the one deploy/package-lock.json pins. Run
//       after `node deploy/scripts/pack.js --agents <dir> --json > <file>` and before `npm ci`.
//   node release_image.js manifest --meshcentral <checkout> --pack-record <file> --install <root> --out <file>
//       Checks the installed tree (the pinned tarball, no image-size, the D6 daemon marker, every pinned
//       agent binary) and writes the schema-2 release manifest that release_manager.py and
//       smoke_checks.py read.
//
// Every value in the manifest is computed from the pack record, the installed package and the
// tracked fork files; nothing is taken on trust from the build environment.
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const zlib = require('node:zlib');

const MANIFEST_SCHEMA = 2;
const PACKAGE_DIR = 'node_modules/meshcentral';
// Fork files delivered beside the package, so the release allows exactly their tracked bytes in the
// governed data and web folders: custom.js, the one meshcentral-web/public file (D11), and the
// nativeruntime plugin, which MeshCentral loads only from meshcentral-data/plugins (PRD-12, SRV-54).
const SHADOW_FILES = [['deploy/meshcentral-web/public/scripts/custom.js', 'meshcentral-web/public/scripts/custom.js']];
const SHADOW_FOLDERS = [['plugins/nativeruntime', 'meshcentral-data/plugins/nativeruntime']];

function fail(message) {
    console.error('release_image: ' + message);
    process.exit(1);
}

function options(names) {
    const values = {};
    for (let i = 3; i < process.argv.length; i += 2) {
        const name = process.argv[i];
        if (!name.startsWith('--') || !names.includes(name.slice(2)) || (process.argv[i + 1] == null)) { fail('unexpected argument ' + name); }
        values[name.slice(2)] = path.resolve(process.argv[i + 1]);
    }
    for (const name of names) { if (values[name] == null) { fail('--' + name + ' is required'); } }
    return values;
}

function readJson(file) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (ex) { fail('cannot read ' + file + ': ' + ex.message); }
}

function digest(algorithm, file, encoding) {
    return crypto.createHash(algorithm).update(fs.readFileSync(file)).digest(encoding);
}

// pack.js --json prints its summary lines, then the record as indented JSON starting on its own line.
function packRecord(file) {
    const text = fs.readFileSync(file, 'utf8');
    const start = text.search(/^\{$/m);
    if (start < 0) { fail(file + ' holds no pack.js --json record'); }
    let record;
    try { record = JSON.parse(text.slice(start)); } catch (ex) { fail(file + ': the pack record is not JSON: ' + ex.message); }
    for (const key of ['tarball', 'version', 'commit', 'integrity', 'packagedCommit', 'agentBuild', 'agents', 'platform']) {
        if (record[key] == null) { fail('the pack record has no ' + key); }
    }
    if (!/^[0-9a-f]{40}$/.test(record.commit) || !/^[0-9a-f]{40}$/.test(record.packagedCommit)) { fail('the pack record commits are not full git shas'); }
    if (record.platform !== 'linux') { fail('the release pack ran on ' + record.platform + '; release packs run on Linux (D4)'); }
    if (!Array.isArray(record.agents) || (record.agents.length === 0)) { fail('the pack record pins no agent binary; the release serves only pinned fork agents'); }
    return record;
}

function lockedTarball(meshcentral, record) {
    const deployPackage = readJson(path.join(meshcentral, 'deploy', 'package.json'));
    const lock = readJson(path.join(meshcentral, 'deploy', 'package-lock.json'));
    const expected = 'file:dist/meshcentral-' + record.version + '.tgz';
    if (record.tarball !== 'deploy/dist/meshcentral-' + record.version + '.tgz') { fail('unexpected pack output ' + record.tarball); }
    if (deployPackage.dependencies.meshcentral !== expected) { fail('deploy/package.json installs ' + deployPackage.dependencies.meshcentral + ', not ' + expected); }
    const entry = (lock.packages || {})['node_modules/meshcentral'] || {};
    if ((entry.version !== record.version) || (entry.resolved !== expected)) { fail('deploy/package-lock.json does not lock ' + expected); }
    return entry.integrity;
}

function verifyPack() {
    const args = options(['meshcentral', 'pack-record']);
    const record = packRecord(args['pack-record']);
    const tarball = path.join(args.meshcentral, record.tarball);
    const actual = 'sha512-' + digest('sha512', tarball, 'base64');
    if (actual !== record.integrity) { fail(record.tarball + ' is ' + actual + ', but pack.js recorded ' + record.integrity); }
    const locked = lockedTarball(args.meshcentral, record);
    if (locked !== actual) {
        fail('T21: the Linux pack of MeshCentral ' + record.commit + ' gives ' + actual + ', but deploy/package-lock.json pins ' +
            locked + '. The lock was not made from this pack; re-lock from a Linux pack of this commit (D4).');
    }
    console.log('Linux pack of ' + record.commit + ' matches the locked tarball ' + actual);
}

// The cores the package itself builds, as /meshagents?cores=1 reports them for a server with no data-folder
// cores and no plugin modules: the package's own updateMeshCore, run in a sandbox against its own agents/.
function packageCoreHashes(packageRoot) {
    const source = fs.readFileSync(path.join(packageRoot, 'meshcentral.js'), 'utf8').replace(/\r\n?/g, '\n');
    function extractBraced(signature) {
        const start = source.indexOf(signature);
        if (start < 0) { fail('meshcentral.js has no ' + signature); }
        const bodyStart = source.indexOf('{', start + signature.length - 1);
        let depth = 0;
        for (let i = bodyStart; i < source.length; ++i) {
            if (source[i] === '{') { depth++; }
            if ((source[i] === '}') && (--depth === 0)) { return source.slice(start, i + 1) + ';'; }
        }
        fail('meshcentral.js: unterminated ' + signature);
    }
    const versionStart = source.indexOf('    const moduleVersionPattern = ');
    const versionEnd = source.indexOf('    // Update the default mesh core', versionStart);
    if ((versionStart < 0) || (versionEnd < versionStart)) { fail('meshcentral.js: the module version helpers were not found'); }
    const loader = [source.slice(versionStart, versionEnd), extractBraced('obj.escapeCodeString = function (str, keepUtf8) {'),
        extractBraced('obj.updateMeshCore = function (func, dumpToFile) {')].join('\n');
    const datapath = fs.mkdtempSync(path.join(os.tmpdir(), 'release-image-cores-'));
    try {
        const obj = { fs, path, crypto, args: {}, datapath, debug() { }, common: require(path.join(packageRoot, 'common.js')),
            defaultMeshCores: {}, defaultMeshCoresHash: {}, defaultMeshCoresDeflate: {} };
        const context = { obj, __dirname: packageRoot, Buffer, require: name => (name === 'zlib' ? zlib : require(name)),
            console: { log() { }, error: message => fail('updateMeshCore: ' + message) },
            process: { exit(code) { fail('updateMeshCore exited with ' + code); } } };
        vm.runInNewContext(loader, context);
        let done = null;
        obj.updateMeshCore(ok => { done = ok; });
        if (done !== true) { fail('updateMeshCore did not build the package cores'); }
        const hashes = {};
        for (const name of Object.keys(obj.defaultMeshCoresHash).sort()) { hashes[name] = Buffer.from(obj.defaultMeshCoresHash[name], 'binary').toString('hex'); }
        if (Object.keys(hashes).length === 0) { fail('the package builds no agent core'); }
        return hashes;
    } finally { fs.rmSync(datapath, { recursive: true, force: true }); }
}

function shadowAllowlist(meshcentral) {
    const entries = [];
    const add = (source, target) => {
        const stat = fs.lstatSync(source);
        if (!stat.isFile()) { fail(source + ' is not a regular file'); }
        entries.push({ path: target, sha256: digest('sha256', source, 'hex') });
    };
    for (const [source, target] of SHADOW_FILES) { add(path.join(meshcentral, source), target); }
    for (const [folder, target] of SHADOW_FOLDERS) {
        for (const name of fs.readdirSync(path.join(meshcentral, folder)).sort()) { add(path.join(meshcentral, folder, name), target + '/' + name); }
    }
    return entries;
}

async function manifest() {
    const args = options(['meshcentral', 'pack-record', 'install', 'out']);
    const record = packRecord(args['pack-record']);
    const install = args.install;
    const packageRoot = path.join(install, PACKAGE_DIR);
    const problems = [];
    const installedLock = readJson(path.join(install, 'node_modules', '.package-lock.json'));
    const installed = (installedLock.packages || {})[PACKAGE_DIR] || {};
    if ((installed.version !== record.version) || (installed.integrity !== record.integrity)) {
        problems.push('the installed meshcentral is ' + installed.version + ' ' + installed.integrity + ', not the packed ' + record.version + ' ' + record.integrity);
    }
    if (readJson(path.join(packageRoot, 'package.json')).version !== record.version) { problems.push('the installed package.json is not version ' + record.version); }
    if (readJson(path.join(packageRoot, 'agents', 'module-versions.json')).commit !== record.packagedCommit) { problems.push('the installed module versions are not dated by ' + record.packagedCommit); }
    for (const relative of ['node_modules/image-size', PACKAGE_DIR + '/node_modules/image-size']) {
        if (fs.existsSync(path.join(install, relative))) { problems.push(relative + ' is installed; the fork package tree must not contain image-size'); }
    }
    if (!fs.lstatSync(path.join(packageRoot, 'daemon'), { throwIfNoEntry: false })?.isFile()) { problems.push(PACKAGE_DIR + '/daemon is missing (D6: self-update stays off)'); }

    // Agent binaries: the package's own parser and verifier (agentbuilds.js) on the installed files.
    const agentbuilds = require(path.join(packageRoot, 'agentbuilds.js'));
    const types = require(path.join(packageRoot, 'agenttypes.js'))();
    const pins = agentbuilds.parseManifest(readJson(path.join(packageRoot, 'agents', agentbuilds.MANIFEST_NAME)), agentbuilds.agentNames(types));
    if (JSON.stringify(pins.build) !== JSON.stringify(record.agentBuild)) { problems.push('the installed agent pins name build ' + JSON.stringify(pins.build) + ', the pack ' + JSON.stringify(record.agentBuild)); }
    for (const pin of pins.files.values()) {
        const why = await agentbuilds.verifyFile(path.join(packageRoot, 'agents', pin.filename), pin);
        if (why) { problems.push('installed agent ' + pin.filename + ': ' + why); }
    }
    const agentBinaries = {};
    for (const id of Object.keys(types).sort((a, b) => a - b)) {
        const pin = pins.files.get(types[id].localname);
        if (pin == null) { continue; }
        agentBinaries[id] = { localname: pin.filename, unsigned: types[id].unsigned === true, path: PACKAGE_DIR + '/agents/' + pin.filename, size: pin.size, sha384: pin.sha384 };
    }
    if (Object.keys(agentBinaries).length === 0) { problems.push('no agent architecture serves a pinned binary'); }
    if (problems.length) { fail(problems.length + ' problem(s) in the installed release:\n  ' + problems.join('\n  ')); }

    const release = {
        schema: MANIFEST_SCHEMA,
        meshcentral_version: record.version,
        reviewedUpstreamVersion: record.version,
        forkRevision: record.commit,
        package: { tarball: path.basename(record.tarball), integrity: record.integrity, packagedCommit: record.packagedCommit },
        agentBuild: pins.build,
        agentBinaries,
        agentCoreHashes: packageCoreHashes(packageRoot),
        shadowAllowlist: shadowAllowlist(args.meshcentral)
    };
    fs.mkdirSync(path.dirname(args.out), { recursive: true });
    fs.writeFileSync(args.out, JSON.stringify(release, null, 2) + '\n', { flag: 'wx' });
    console.log('Release manifest ' + args.out + ': MeshCentral ' + record.version + ', fork ' + record.commit + ', ' +
        Object.keys(agentBinaries).length + ' agent architectures, ' + Object.keys(release.agentCoreHashes).length + ' cores');
}

const command = process.argv[2];
if (command === 'verify-pack') { verifyPack(); }
else if (command === 'manifest') { manifest().catch(ex => fail(ex.stack || String(ex))); }
else { fail('usage: release_image.js verify-pack|manifest ...'); }
