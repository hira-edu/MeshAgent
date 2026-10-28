'use strict';
// The one way MeshAgent tests locate the MeshCentral fork checkout and its installed npm package.
// test/lib/meshcentral_paths.py implements the same rules for the Python tests; keep them in step.
//
// MeshCentral root:  MESHCENTRAL_ROOT when set (it must exist and look like the fork), otherwise
//                    the sibling <MeshAgent root>/../MeshCentral, where the MeshAgent root is two
//                    levels above this file. Worktrees under MeshAgent/.claude/worktrees have no
//                    sibling, so they must set MESHCENTRAL_ROOT. Nothing missing is ever returned.
// Installed package: <root>/deploy/node_modules/meshcentral, installed by the deployment wrapper
//                    (Stage 1). A package at <root>/node_modules/meshcentral is a stale install from
//                    before Stage 1 and is refused, because Node would resolve it first from the root.
// Fork files:        files of the fork package at the repo root, such as meshagent.js.
// Upstream package:  the stock npm package pinned in meshcentral_upstream_reference.json, extracted
//                    into a git-ignored cache by test/lib/fetch_upstream_reference.py and verified
//                    against the pinned tree digest on first use. Tests that compare the fork with
//                    stock upstream read it here; since Stage 1 the installed package is the fork.
//
// Every function takes an optional { env, meshagentRoot } so the helper's own tests can point it
// at temporary layouts; tests should call them without arguments.
const fs = require('fs');
const path = require('path');

const MESHAGENT_ROOT = path.resolve(__dirname, '..', '..');

// Files every MeshCentral fork checkout has at its root, before and after the Stage 1 restructure.
const ROOT_MARKERS = Object.freeze([
    Object.freeze({ rel: 'meshagent.js', kind: 'file' }),
    Object.freeze({ rel: 'agents', kind: 'directory' })
]);

// The installed package, relative to the MeshCentral root (Stage 1 layout).
const PACKAGE_DIR = path.join('deploy', 'node_modules', 'meshcentral');
// The pre-Stage-1 location. It is never used: its presence is an error (see installedPackageDir).
const STALE_ROOT_PACKAGE_DIR = path.join('node_modules', 'meshcentral');

class MeshCentralPathError extends Error {
    constructor(message) {
        super(message);
        this.name = 'MeshCentralPathError';
    }
}

function statOrNull(target) {
    try {
        return fs.statSync(target);
    } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') { return null; }
        throw new MeshCentralPathError('Cannot inspect ' + target + ': ' + error.message);
    }
}

function checkRoot(root, source) {
    const stat = statOrNull(root);
    if (!stat) {
        throw new MeshCentralPathError('MeshCentral checkout not found at ' + root + ' (' + source + '). ' +
            'Set MESHCENTRAL_ROOT to the MeshCentral fork checkout.');
    }
    if (!stat.isDirectory()) {
        throw new MeshCentralPathError('MeshCentral path ' + root + ' (' + source + ') is not a directory. ' +
            'Set MESHCENTRAL_ROOT to the MeshCentral fork checkout.');
    }
    const missing = ROOT_MARKERS.filter((marker) => {
        const markerStat = statOrNull(path.join(root, marker.rel));
        return !markerStat || (marker.kind === 'file' ? !markerStat.isFile() : !markerStat.isDirectory());
    });
    if (missing.length) {
        throw new MeshCentralPathError('MeshCentral path ' + root + ' (' + source + ') does not look like the MeshCentral fork: missing ' +
            missing.map((marker) => marker.rel + ' (' + marker.kind + ')').join(', ') + '. Set MESHCENTRAL_ROOT to the MeshCentral fork checkout.');
    }
    return root;
}

// Returns the absolute MeshCentral checkout root, or throws MeshCentralPathError.
function meshcentralRoot(options) {
    const env = (options && options.env) || process.env;
    const meshagentRoot = path.resolve((options && options.meshagentRoot) || MESHAGENT_ROOT);
    const fromEnv = env.MESHCENTRAL_ROOT;
    if (fromEnv !== undefined && fromEnv !== '') {
        return checkRoot(path.resolve(fromEnv), 'from MESHCENTRAL_ROOT');
    }
    return checkRoot(path.resolve(meshagentRoot, '..', 'MeshCentral'), 'sibling of the MeshAgent root ' + meshagentRoot + '; MESHCENTRAL_ROOT is not set');
}

// Returns { dir } for the installed meshcentral npm package, or throws MeshCentralPathError when it
// is missing, is not the meshcentral package, or a stale pre-Stage-1 install sits at the root.
function installedPackageDir(options) {
    const env = (options && options.env) || process.env;
    const root = meshcentralRoot(options);
    const stale = path.join(root, STALE_ROOT_PACKAGE_DIR);
    if (statOrNull(stale) !== null) {
        const how = (env.MESHCENTRAL_ROOT !== undefined && env.MESHCENTRAL_ROOT !== '')
            ? 'MESHCENTRAL_ROOT points at ' + root
            : 'MESHCENTRAL_ROOT is not set, so the sibling checkout ' + root + ' is used';
        throw new MeshCentralPathError('Stale pre-Stage-1 meshcentral install at ' + stale + ' (' + how + '). Since Stage 1 the package is installed only at ' +
            path.join(root, PACKAGE_DIR) + '. Set MESHCENTRAL_ROOT to a MeshCentral checkout or worktree without a root node_modules, or remove ' + path.join(root, 'node_modules') + '.');
    }
    const dir = path.join(root, PACKAGE_DIR);
    const stat = statOrNull(dir);
    if (stat === null) {
        throw new MeshCentralPathError('Installed meshcentral package not found at ' + dir + '. Install the wrapper dependencies (npm ci in ' + path.join(root, WRAPPER_DIR) + ').');
    }
    if (!stat.isDirectory()) {
        throw new MeshCentralPathError('Installed meshcentral package path ' + dir + ' is not a directory.');
    }
    const manifestPath = path.join(dir, 'package.json');
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('Installed meshcentral package has no readable package.json at ' + manifestPath + ': ' + error.message);
    }
    if (manifest.name !== 'meshcentral') {
        throw new MeshCentralPathError('Installed package at ' + dir + ' is named ' + JSON.stringify(manifest.name) + ', not "meshcentral".');
    }
    return { dir };
}

// Returns the absolute path of a fork package file at the MeshCentral repo root. The root is
// validated; whether the file itself must exist is the caller's check, because some inputs are optional.
function forkFile(rel, options) {
    if (typeof rel !== 'string' || rel === '' || path.isAbsolute(rel)) {
        throw new MeshCentralPathError('forkFile needs a relative path inside the MeshCentral checkout, got ' + JSON.stringify(rel));
    }
    const root = meshcentralRoot(options);
    const target = path.resolve(root, rel);
    const relative = path.relative(root, target);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new MeshCentralPathError('forkFile path ' + JSON.stringify(rel) + ' leaves the MeshCentral checkout ' + root);
    }
    return target;
}

// The deployment wrapper (Stage 1 layout): <root>/deploy, whose package.json is named
// meshcentral-deploy. It holds the wrapper package.json and lockfile, deploy/node_modules,
// meshcentral-web (custom.js), scripts/ and the config template. Before Stage 1 these sat at the
// repo root, where no wrapper is accepted: tests that read wrapper files need the Stage 1 layout.
const WRAPPER_DIR = 'deploy';
const WRAPPER_PACKAGE_NAME = 'meshcentral-deploy';

function wrapperDir(options) {
    const root = meshcentralRoot(options);
    const dir = path.join(root, WRAPPER_DIR);
    const manifestPath = path.join(dir, 'package.json');
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('MeshCentral deployment wrapper not found: ' + manifestPath + ' is not a readable package.json (' + error.message +
            '). These files moved under deploy/ in Stage 1; point MESHCENTRAL_ROOT at a checkout with the Stage 1 layout.');
    }
    if (manifest.name !== WRAPPER_PACKAGE_NAME) {
        throw new MeshCentralPathError('MeshCentral deployment wrapper ' + manifestPath + ' is named ' + JSON.stringify(manifest.name) + ', not "' + WRAPPER_PACKAGE_NAME + '".');
    }
    return dir;
}

// Returns the absolute path of a file inside the deployment wrapper. Like forkFile, whether the
// file exists is the caller's check.
function wrapperFile(rel, options) {
    if (typeof rel !== 'string' || rel === '' || path.isAbsolute(rel)) {
        throw new MeshCentralPathError('wrapperFile needs a relative path inside the deployment wrapper, got ' + JSON.stringify(rel));
    }
    const dir = wrapperDir(options);
    const target = path.resolve(dir, rel);
    const relative = path.relative(dir, target);
    if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new MeshCentralPathError('wrapperFile path ' + JSON.stringify(rel) + ' leaves the deployment wrapper ' + dir);
    }
    return target;
}

// Pinned stock upstream package. The pin lives in meshcentral_upstream_reference.json, shared with
// the Python helper and test/lib/fetch_upstream_reference.py, which is the only writer of the cache.
const REFERENCE_PIN_PATH = path.join(__dirname, 'meshcentral_upstream_reference.json');
const UPSTREAM_CACHE_ENV = 'MESHCENTRAL_UPSTREAM_CACHE';
const FETCH_COMMAND = 'python test/lib/fetch_upstream_reference.py';
const REFERENCE_MARKER = 'reference.json';

function loadReferencePin(pinPath) {
    const file = pinPath || REFERENCE_PIN_PATH;
    let pin;
    try {
        pin = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('Cannot read the upstream reference pin ' + file + ': ' + error.message);
    }
    for (const key of ['name', 'version', 'tarball', 'integrity', 'treeDigest', 'fileCount']) {
        if (!pin[key]) { throw new MeshCentralPathError('Upstream reference pin ' + file + ' has no ' + key); }
    }
    if (!String(pin.integrity).startsWith('sha512-') || !String(pin.treeDigest).startsWith('sha256:')) {
        throw new MeshCentralPathError('Upstream reference pin ' + file + ' needs a sha512- integrity and a sha256: treeDigest');
    }
    return pin;
}

// MESHCENTRAL_UPSTREAM_CACHE, or <MeshAgent root>/artifacts/meshcentral-upstream (git-ignored).
function upstreamCacheRoot(options) {
    const env = (options && options.env) || process.env;
    const fromEnv = env[UPSTREAM_CACHE_ENV];
    if (fromEnv !== undefined && fromEnv !== '') { return path.resolve(fromEnv); }
    return path.resolve((options && options.meshagentRoot) || MESHAGENT_ROOT, 'artifacts', 'meshcentral-upstream');
}

function referenceDir(pin, options) {
    return path.join(upstreamCacheRoot(options), pin.name + '-' + pin.version);
}

function walkTree(root) {
    const files = [];
    const stack = [root];
    while (stack.length) {
        const current = stack.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isSymbolicLink()) { throw new MeshCentralPathError('Upstream reference holds a link, which a package never has: ' + full); }
            if (entry.isDirectory()) { stack.push(full); }
            else if (entry.isFile()) { files.push(path.relative(root, full).split(path.sep).join('/')); }
            else { throw new MeshCentralPathError('Upstream reference holds a non-regular file: ' + full); }
        }
    }
    return files;
}

// sha256 over one line per regular file, "<sha256 hex> <size> <posix path>\n", sorted by the
// UTF-8 bytes of the path. meshcentral_paths.py tree_digest computes the same value.
function treeDigest(root) {
    const crypto = require('crypto');
    const files = walkTree(root).sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
    const outer = crypto.createHash('sha256');
    for (const rel of files) {
        const data = fs.readFileSync(path.join(root, rel));
        outer.update(crypto.createHash('sha256').update(data).digest('hex') + ' ' + data.length + ' ' + rel + '\n', 'utf8');
    }
    return { digest: 'sha256:' + outer.digest('hex'), fileCount: files.length };
}

const verifiedUpstream = new Set();

// Returns the absolute folder of the extracted, verified stock upstream package (the pin above).
// Never uses the network: when the cache is missing, made from another pin, or its tree does not
// match the pinned digest, it throws MeshCentralPathError naming the command that populates it.
function upstreamPackageDir(options) {
    const pin = loadReferencePin(options && options.pinPath);
    const refDir = referenceDir(pin, options);
    const pkg = path.join(refDir, 'package');
    const label = 'pinned upstream ' + pin.name + ' ' + pin.version + ' reference';
    const env = (options && options.env) || process.env;
    const hint = 'Populate it with: ' + FETCH_COMMAND + (env[UPSTREAM_CACHE_ENV] ? ' (with the same ' + UPSTREAM_CACHE_ENV + ')' : '');
    const key = pkg + '\0' + pin.treeDigest;
    if (verifiedUpstream.has(key)) { return pkg; }
    const stat = statOrNull(pkg);
    if (!stat || !stat.isDirectory()) {
        throw new MeshCentralPathError('The ' + label + ' is missing: ' + pkg + ' does not exist. ' + hint);
    }
    let marker;
    try {
        marker = JSON.parse(fs.readFileSync(path.join(refDir, REFERENCE_MARKER), 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('The ' + label + ' at ' + refDir + ' has no readable ' + REFERENCE_MARKER + ': ' + error.message + '. ' + hint);
    }
    for (const field of ['name', 'version', 'integrity', 'treeDigest']) {
        if (marker[field] !== pin[field]) {
            throw new MeshCentralPathError('The ' + label + ' at ' + refDir + ' was made from another pin (' + field + ' ' +
                JSON.stringify(marker[field]) + ', pinned ' + JSON.stringify(pin[field]) + '). ' + hint);
        }
    }
    const tree = treeDigest(pkg);
    if (tree.digest !== pin.treeDigest || tree.fileCount !== pin.fileCount) {
        throw new MeshCentralPathError('The ' + label + ' at ' + pkg + ' fails its integrity check: tree ' + tree.digest + ' with ' +
            tree.fileCount + ' files, pinned ' + pin.treeDigest + ' with ' + pin.fileCount + ' files. ' + hint);
    }
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('The ' + label + ' has no readable package.json: ' + error.message + '. ' + hint);
    }
    if (manifest.name !== pin.name || manifest.version !== pin.version) {
        throw new MeshCentralPathError('The ' + label + ' package.json is ' + manifest.name + '@' + manifest.version + '. ' + hint);
    }
    verifiedUpstream.add(key);
    return pkg;
}

module.exports = {
    MESHAGENT_ROOT,
    PACKAGE_DIR,
    STALE_ROOT_PACKAGE_DIR,
    ROOT_MARKERS,
    REFERENCE_PIN_PATH,
    UPSTREAM_CACHE_ENV,
    FETCH_COMMAND,
    MeshCentralPathError,
    meshcentralRoot,
    installedPackageDir,
    forkFile,
    wrapperDir,
    wrapperFile,
    loadReferencePin,
    upstreamCacheRoot,
    upstreamPackageDir,
    treeDigest
};
