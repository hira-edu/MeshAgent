'use strict';
// The one way MeshAgent tests locate the MeshCentral fork checkout and its installed npm package.
// test/lib/meshcentral_paths.py implements the same rules for the Python tests; keep them in step.
//
// MeshCentral root:  MESHCENTRAL_ROOT when set (it must exist and look like the fork), otherwise
//                    the sibling <MeshAgent root>/../MeshCentral, where the MeshAgent root is two
//                    levels above this file. Worktrees under MeshAgent/.claude/worktrees have no
//                    sibling, so they must set MESHCENTRAL_ROOT. Nothing missing is ever returned.
// Installed package: one of the named layouts below. Exactly one must exist.
// Fork files:        files of the fork package at the repo root, such as meshagent.js.
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

const PACKAGE_LAYOUTS = Object.freeze([
    // The wrapper's package.json and node_modules at the repo root (before Stage 1).
    Object.freeze({ name: 'wrapper-root', rel: path.join('node_modules', 'meshcentral') }),
    // The wrapper moved under deploy/ (Stage 1).
    Object.freeze({ name: 'deploy', rel: path.join('deploy', 'node_modules', 'meshcentral') })
]);

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

// Returns { layout, dir } for the installed meshcentral npm package, or throws MeshCentralPathError
// when neither layout or both layouts are present.
function installedPackageDir(options) {
    const root = meshcentralRoot(options);
    const candidates = PACKAGE_LAYOUTS.map((layout) => ({ layout: layout.name, dir: path.join(root, layout.rel) }));
    const describe = candidates.map((candidate) => candidate.layout + ' (' + candidate.dir + ')').join(' and ');
    const present = candidates.filter((candidate) => statOrNull(candidate.dir) !== null);
    if (present.length === 0) {
        throw new MeshCentralPathError('Installed meshcentral package not found: neither ' + describe + ' exists. Install the wrapper dependencies.');
    }
    if (present.length > 1) {
        throw new MeshCentralPathError('Installed meshcentral package is ambiguous: both ' + describe + ' exist. Remove the stale layout.');
    }
    const found = present[0];
    if (!statOrNull(found.dir).isDirectory()) {
        throw new MeshCentralPathError('Installed meshcentral package path ' + found.dir + ' (layout ' + found.layout + ') is not a directory.');
    }
    const manifestPath = path.join(found.dir, 'package.json');
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (error) {
        throw new MeshCentralPathError('Installed meshcentral package (layout ' + found.layout + ') has no readable package.json at ' + manifestPath + ': ' + error.message);
    }
    if (manifest.name !== 'meshcentral') {
        throw new MeshCentralPathError('Installed package at ' + found.dir + ' (layout ' + found.layout + ') is named ' + JSON.stringify(manifest.name) + ', not "meshcentral".');
    }
    return { layout: found.layout, dir: found.dir };
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

module.exports = {
    MESHAGENT_ROOT,
    PACKAGE_LAYOUTS,
    ROOT_MARKERS,
    MeshCentralPathError,
    meshcentralRoot,
    installedPackageDir,
    forkFile
};
