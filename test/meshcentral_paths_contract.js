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

function installPackage(root, layoutName, name) {
    const layout = paths.PACKAGE_LAYOUTS.find((entry) => entry.name === layoutName);
    const dir = path.join(root, layout.rel);
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
    wrapperRootLayout() {
        const ws = workspace(true);
        const dir = installPackage(ws.sibling, 'wrapper-root');
        assert.deepStrictEqual(paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), { layout: 'wrapper-root', dir });
        assert.strictEqual(dir, path.join(ws.sibling, 'node_modules', 'meshcentral'));
    },
    deployLayout() {
        const ws = workspace(true);
        const dir = installPackage(ws.sibling, 'deploy');
        assert.deepStrictEqual(paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), { layout: 'deploy', dir });
        assert.strictEqual(dir, path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'));
    },
    bothLayoutsThrow() {
        const ws = workspace(true);
        const a = installPackage(ws.sibling, 'wrapper-root');
        const b = installPackage(ws.sibling, 'deploy');
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['ambiguous', 'wrapper-root', a, 'deploy', b]);
    },
    noLayoutThrows() {
        const ws = workspace(true);
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }),
            ['not found', 'wrapper-root', path.join(ws.sibling, 'node_modules', 'meshcentral'), 'deploy', path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral')]);
    },
    layoutWithoutManifestThrows() {
        const ws = workspace(true);
        fs.mkdirSync(path.join(ws.sibling, 'deploy', 'node_modules', 'meshcentral'), { recursive: true });
        throwsWith(() => paths.installedPackageDir({ env: {}, meshagentRoot: ws.meshagentRoot }), ['layout deploy', 'package.json']);
    },
    layoutWithOtherPackageThrows() {
        const ws = workspace(true);
        installPackage(ws.sibling, 'wrapper-root', 'not-meshcentral');
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
    }
};

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
