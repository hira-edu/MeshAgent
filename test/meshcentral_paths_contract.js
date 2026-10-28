'use strict';
// Unit tests for test/lib/meshcentral_paths.js on temporary layouts. They never read the real
// MeshCentral checkout, so they pass with or without MESHCENTRAL_ROOT.
// test/meshcentral_paths_contract.py runs the same cases against the Python helper.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const paths = require('./lib/meshcentral_paths');

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'meshcentral-paths-'));
let counter = 0;

function makeFork(dir) {
    fs.mkdirSync(path.join(dir, 'agents'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'meshagent.js'), '// fixture\n');
    return dir;
}

function installPackage(root, rel, name) {
    const dir = path.join(root, rel);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: name || 'meshcentral', version: '1.2.5' }));
    return dir;
}

// A fresh <parent>/MeshAgent with an optional <parent>/MeshCentral sibling.
function workspace(withSibling) {
    const parent = path.join(temp, 'ws' + (counter++));
    const meshagentRoot = path.join(parent, 'MeshAgent');
    fs.mkdirSync(meshagentRoot, { recursive: true });
    const sibling = path.join(parent, 'MeshCentral');
    if (withSibling) { makeFork(sibling); }
    return { meshagentRoot, sibling };
}

function throwsWith(fn, fragments) {
    assert.throws(fn, (error) => {
        assert(error instanceof paths.MeshCentralPathError, 'expected MeshCentralPathError, got ' + error);
        for (const fragment of fragments) {
            assert(error.message.includes(fragment), 'expected ' + JSON.stringify(fragment) + ' in: ' + error.message);
        }
        return true;
    });
}

const cases = {
    envSetIsUsed() {
        const ws = workspace(true);
        const other = makeFork(path.join(temp, 'elsewhere' + (counter++), 'MeshCentral'));
        assert.strictEqual(paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: other }, meshagentRoot: ws.meshagentRoot }), other);
    },
    envRelativeIsResolved() {
        const ws = workspace(false);
        const other = makeFork(path.join(temp, 'relative' + (counter++)));
        const relative = path.relative(process.cwd(), other);
        assert.strictEqual(paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: relative }, meshagentRoot: ws.meshagentRoot }), other);
    },
    envMissingThrows() {
        const ws = workspace(true);
        const missing = path.join(temp, 'no-such-dir');
        throwsWith(() => paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: missing }, meshagentRoot: ws.meshagentRoot }),
            ['not found', missing, 'from MESHCENTRAL_ROOT', 'Set MESHCENTRAL_ROOT']);
    },
    envNotADirectoryThrows() {
        const ws = workspace(false);
        const file = path.join(temp, 'a-file' + (counter++));
        fs.writeFileSync(file, 'x');
        throwsWith(() => paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: file }, meshagentRoot: ws.meshagentRoot }), ['is not a directory', file]);
    },
    envWithoutMarkersThrows() {
        const ws = workspace(true);
        const notFork = path.join(temp, 'not-fork' + (counter++));
        fs.mkdirSync(notFork);
        throwsWith(() => paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: notFork }, meshagentRoot: ws.meshagentRoot }),
            ['does not look like the MeshCentral fork', 'meshagent.js (file)', 'agents (directory)']);
    },
    emptyEnvFallsBackToSibling() {
        const ws = workspace(true);
        assert.strictEqual(paths.meshcentralRoot({ env: { MESHCENTRAL_ROOT: '' }, meshagentRoot: ws.meshagentRoot }), ws.sibling);
    },
    siblingPresentIsUsed() {
        const ws = workspace(true);
        assert.strictEqual(paths.meshcentralRoot({ env: {}, meshagentRoot: ws.meshagentRoot }), ws.sibling);
    },
    siblingAbsentThrows() {
        const ws = workspace(false);
        throwsWith(() => paths.meshcentralRoot({ env: {}, meshagentRoot: ws.meshagentRoot }),
            ['not found', ws.sibling, 'MESHCENTRAL_ROOT is not set', 'Set MESHCENTRAL_ROOT']);
    },
    defaultMeshagentRootIsTwoLevelsUp() {
        assert.strictEqual(paths.MESHAGENT_ROOT, path.resolve(__dirname, '..'));
        assert(fs.existsSync(path.join(paths.MESHAGENT_ROOT, 'AGENTS.md')), 'MESHAGENT_ROOT must be the MeshAgent checkout');
    },
    deployPackage() {
        const ws = workspace(true);
        const dir = installPackage(ws.sibling, paths.PACKAGE_DIR);
        assert.deepStrictEqual(paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), { dir });
        assert.strictEqual(dir, path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'));
    },
    staleRootInstallIsRefusedWithoutEnv() {
        // The local case: no MESHCENTRAL_ROOT, and the sibling checkout still has a pre-Stage-1 root install.
        const ws = workspace(true);
        installPackage(ws.sibling, paths.PACKAGE_DIR);
        const stale = installPackage(ws.sibling, paths.STALE_ROOT_PACKAGE_DIR);
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }),
            ['Stale pre-Stage-1', stale, 'MESHCENTRAL_ROOT is not set', path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'), 'Set MESHCENTRAL_ROOT']);
    },
    staleRootInstallIsRefusedWithEnv() {
        const ws = workspace(false);
        const other = makeFork(path.join(temp, 'stale' + (counter++), 'MeshCentral'));
        const stale = installPackage(other, paths.STALE_ROOT_PACKAGE_DIR);
        throwsWith(() => paths.installedPackageDir({ env: { MESHCENTRAL_ROOT: other }, meshagentRoot: ws.meshagentRoot }),
            ['Stale pre-Stage-1', stale, 'MESHCENTRAL_ROOT points at ' + other]);
    },
    rootInstallIsNeverUsed() {
        // A root install alone is not a fallback: it is refused, not returned.
        const ws = workspace(true);
        installPackage(ws.sibling, paths.STALE_ROOT_PACKAGE_DIR);
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['Stale pre-Stage-1']);
    },
    noPackageThrows() {
        const ws = workspace(true);
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }),
            ['not found', path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'), 'npm ci']);
    },
    packageWithoutManifestThrows() {
        const ws = workspace(true);
        fs.mkdirSync(path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'), { recursive: true });
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['no readable package.json']);
    },
    packageWithOtherNameThrows() {
        const ws = workspace(true);
        installPackage(ws.sibling, paths.PACKAGE_DIR, 'not-meshcentral');
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['"not-meshcentral"', 'not "meshcentral"']);
    },
    installedPackageNeedsRoot() {
        const ws = workspace(false);
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['Set MESHCENTRAL_ROOT']);
    },
    forkFileIsUnderRoot() {
        const ws = workspace(true);
        const options = { env: {}, meshagentRoot: ws.meshagentRoot };
        assert.strictEqual(paths.forkFile('meshagent.js', options), path.join(ws.sibling, 'meshagent.js'));
        assert.strictEqual(paths.forkFile('agents/meshcore.js', options), path.join(ws.sibling, 'agents', 'meshcore.js'));
    },
    forkFileRejectsEscapes() {
        const ws = workspace(true);
        const options = { env: {}, meshagentRoot: ws.meshagentRoot };
        throwsWith(() => paths.forkFile('../MeshAgent/x.js', options), ['leaves the MeshCentral checkout']);
        throwsWith(() => paths.forkFile('agents/../..', options), ['leaves the MeshCentral checkout']);
        throwsWith(() => paths.forkFile('.', options), ['leaves the MeshCentral checkout']);
        throwsWith(() => paths.forkFile(path.join(ws.sibling, 'meshagent.js'), options), ['needs a relative path']);
        throwsWith(() => paths.forkFile('', options), ['needs a relative path']);
    },
    forkFileNeedsRoot() {
        const ws = workspace(false);
        throwsWith(() => paths.forkFile('meshagent.js', { env: {}, meshagentRoot: ws.meshagentRoot }), ['Set MESHCENTRAL_ROOT']);
    },
    wrapperFileIsUnderDeploy() {
        const ws = workspace(true);
        writeWrapper(ws.sibling, 'meshcentral-deploy');
        const options = { env: {}, meshagentRoot: ws.meshagentRoot };
        assert.strictEqual(paths.wrapperDir(options), path.join(ws.sibling, 'deploy'));
        assert.strictEqual(paths.wrapperFile('meshcentral-web/public/scripts/custom.js', options),
            path.join(ws.sibling, 'deploy', 'meshcentral-web', 'public', 'scripts', 'custom.js'));
        throwsWith(() => paths.wrapperFile('../meshagent.js', options), ['leaves the deployment wrapper']);
        throwsWith(() => paths.wrapperFile('', options), ['needs a relative path']);
    },
    wrapperMissingNamesStage1() {
        const ws = workspace(true);
        // The old layout: the wrapper package.json at the root is not accepted.
        fs.writeFileSync(path.join(ws.sibling, 'package.json'), JSON.stringify({ name: 'meshcentral-deploy' }));
        throwsWith(() => paths.wrapperDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['deployment wrapper not found', 'Stage 1']);
    },
    wrapperWithOtherNameThrows() {
        const ws = workspace(true);
        writeWrapper(ws.sibling, 'meshcentral');
        throwsWith(() => paths.wrapperFile('x', { env: {}, meshagentRoot: ws.meshagentRoot }), ['is named "meshcentral"']);
    },
    treeDigestMatchesPythonFixture() {
        // The same tree and digest are checked in meshcentral_paths_contract.py, so both helpers
        // compute one value. "Z/" sorts before "a/" by UTF-8 bytes.
        const tree = tinyTree(path.join(temp, 'digest' + (counter++)));
        assert.deepStrictEqual(paths.treeDigest(tree), { digest: TINY_DIGEST, fileCount: 3 });
    },
    upstreamDefaultCacheIsUnderArtifacts() {
        const ws = workspace(false);
        assert.strictEqual(paths.upstreamCacheRoot({ env: {}, meshagentRoot: ws.meshagentRoot }),
            path.join(ws.meshagentRoot, 'artifacts', 'meshcentral-upstream'));
    },
    upstreamVerifiedReferenceIsReturned() {
        const fixture = upstreamFixture();
        assert.strictEqual(paths.upstreamPackageDir(fixture.options), fixture.pkg);
    },
    upstreamMissingNamesTheCommand() {
        const fixture = upstreamFixture({ populate: false });
        throwsWith(() => paths.upstreamPackageDir(fixture.options), ['is missing', paths.FETCH_COMMAND, 'MESHCENTRAL_UPSTREAM_CACHE']);
    },
    upstreamChangedFileFailsIntegrity() {
        const fixture = upstreamFixture();
        fs.writeFileSync(path.join(fixture.pkg, 'a', 'b.txt'), 'hellO\n');
        throwsWith(() => paths.upstreamPackageDir(fixture.options), ['fails its integrity check', paths.FETCH_COMMAND]);
    },
    upstreamExtraFileFailsIntegrity() {
        const fixture = upstreamFixture();
        fs.writeFileSync(path.join(fixture.pkg, 'extra.js'), '');
        throwsWith(() => paths.upstreamPackageDir(fixture.options), ['fails its integrity check', 'with 4 files']);
    },
    upstreamOtherPinFails() {
        const fixture = upstreamFixture({ marker: { treeDigest: 'sha256:00' } });
        throwsWith(() => paths.upstreamPackageDir(fixture.options), ['made from another pin', paths.FETCH_COMMAND]);
    },
    upstreamMissingMarkerFails() {
        const fixture = upstreamFixture();
        fs.rmSync(path.join(fixture.refDir, 'reference.json'));
        throwsWith(() => paths.upstreamPackageDir(fixture.options), ['no readable reference.json']);
    },
    upstreamPinIsComplete() {
        const pin = paths.loadReferencePin();
        assert.strictEqual(pin.name, 'meshcentral');
        assert.strictEqual(pin.version, '1.3.1');
        assert(/^sha512-[A-Za-z0-9+/]{86}==$/.test(pin.integrity), 'pinned integrity is a sha512: ' + pin.integrity);
        assert(/^sha256:[0-9a-f]{64}$/.test(pin.treeDigest), 'pinned tree digest is a sha256: ' + pin.treeDigest);
        assert(Number.isInteger(pin.fileCount) && pin.fileCount > 0);
    }
};

function writeWrapper(root, name) {
    fs.mkdirSync(path.join(root, 'deploy'), { recursive: true });
    fs.writeFileSync(path.join(root, 'deploy', 'package.json'), JSON.stringify({ name }));
}

const TINY_DIGEST ='sha256:63dc7f5b4d9481f89b76e3cc2b6367567dd8b24b803cf747542ff6d80d19ce65';

function tinyTree(dir) {
    fs.mkdirSync(path.join(dir, 'a'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'Z'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"meshcentral","version":"9.9.9"}');
    fs.writeFileSync(path.join(dir, 'a', 'b.txt'), 'hello\n');
    fs.writeFileSync(path.join(dir, 'Z', 'c.txt'), 'x');
    return dir;
}

// A cache under MESHCENTRAL_UPSTREAM_CACHE holding the tiny tree, with a pin file describing it.
function upstreamFixture(settings) {
    const opts = Object.assign({ populate: true, marker: {} }, settings);
    const base = path.join(temp, 'upstream' + (counter++));
    const cache = path.join(base, 'cache');
    const pin = { name: 'meshcentral', version: '9.9.9', tarball: 'https://example.invalid/m.tgz', integrity: 'sha512-AA==', treeDigest: TINY_DIGEST, fileCount: 3 };
    fs.mkdirSync(base, { recursive: true });
    const pinPath = path.join(base, 'pin.json');
    fs.writeFileSync(pinPath, JSON.stringify(pin));
    const refDir = path.join(cache, 'meshcentral-9.9.9');
    const pkg = path.join(refDir, 'package');
    if (opts.populate) {
        tinyTree(pkg);
        fs.writeFileSync(path.join(refDir, 'reference.json'), JSON.stringify(Object.assign({}, pin, opts.marker)));
    }
    return { options: { env: { MESHCENTRAL_UPSTREAM_CACHE: cache }, pinPath }, refDir, pkg };
}

const failures = [];
try {
    for (const [name, run] of Object.entries(cases)) {
        try { run(); } catch (error) { failures.push(name + ': ' + error.message); }
    }
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
if (failures.length) {
    console.error(failures.join('\n'));
    console.log('FAIL meshcentral paths helper (' + failures.length + '/' + Object.keys(cases).length + ' failed)');
    process.exit(1);
}
console.log('PASS meshcentral paths helper (' + Object.keys(cases).length + ' cases)');
