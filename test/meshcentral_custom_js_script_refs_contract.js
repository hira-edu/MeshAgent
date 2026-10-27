'use strict';
// public/scripts/custom.js is carried byte for byte and is out of review scope (operator
// decision), but the scripts it loads must ship with it. This reads only the string
// literals in custom.js that name a .js, .css or .wasm file and asserts each one resolves
// to a tracked file in the MeshCentral repo. custom.js is served from <domain>/scripts/,
// so the reference forms map as follows:
//   name.js, ./name.js, scripts/name.js, /scripts/name.js  -> public/scripts/name.js
//   ../plugin/<p>/<f>, /plugin/<p>/<f>, plugin/<p>/<f>      -> plugins/<p>/<f>, and a file in
//                                                              plugins/<p>/ must register the
//                                                              'plugin/<p>/<f>' route
//   plugins/<p>/<f>                                         -> plugins/<p>/<f>
// A query string (?v=...) is ignored. Any other form fails, and finding no reference at
// all fails, so a format change cannot pass silently.
//
// MeshCentral is read from MESHCENTRAL_ROOT, or the sibling ../MeshCentral checkout.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const CUSTOM = 'public/scripts/custom.js';
const LITERAL = /(['"`])([^'"`\s]*?\.(?:js|css|wasm)(?:\?[^'"`\s]*)?)\1/g;

function meshcentralRoot() {
    const root = path.resolve(process.env.MESHCENTRAL_ROOT || path.join(__dirname, '..', '..', 'MeshCentral'));
    let stat;
    try { stat = fs.statSync(root); } catch (error) {
        throw new Error('MeshCentral checkout not found at ' + root + ' (set MESHCENTRAL_ROOT): ' + error.message);
    }
    assert(stat.isDirectory(), 'MeshCentral path is not a directory: ' + root);
    return root;
}

function trackedFiles(root) {
    const result = spawnSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true });
    if (result.error) { throw new Error('git ls-files could not run: ' + result.error.message); }
    assert(result.status === 0, 'git ls-files failed in ' + root + ': ' + String(result.stderr).trim());
    return new Set(result.stdout.split('\0').filter(Boolean));
}

// Maps one reference to the repo file it loads, or returns an error string.
function resolveReference(reference) {
    const url = reference.split('?')[0];
    if (url.includes('${') || /^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) { return { error: 'unsupported reference form' }; }
    let match = /^(?:\.\/|\/?scripts\/)?([^/]+)$/.exec(url);
    if (match) { return { file: 'public/scripts/' + match[1] }; }
    match = /^(?:\.\.\/|\/)?plugin\/([^/]+)\/(.+)$/.exec(url);
    if (match) { return { file: 'plugins/' + match[1] + '/' + match[2], plugin: match[1], route: 'plugin/' + match[1] + '/' + match[2] }; }
    match = /^\/?plugins\/([^/]+)\/(.+)$/.exec(url);
    if (match) { return { file: 'plugins/' + match[1] + '/' + match[2] }; }
    return { error: 'unsupported reference form' };
}

function main() {
    const root = meshcentralRoot();
    const tracked = trackedFiles(root);
    assert(tracked.has(CUSTOM), CUSTOM + ' is not tracked in ' + root);
    const text = fs.readFileSync(path.join(root, CUSTOM), 'utf8');
    const references = [...new Set(Array.from(text.matchAll(LITERAL), (match) => match[2]))].sort();
    const failures = [];
    if (references.length === 0) { failures.push('no script reference found in ' + CUSTOM + '; its loading format changed'); }

    for (const reference of references) {
        const resolved = resolveReference(reference);
        if (resolved.error) { failures.push(reference + ': ' + resolved.error); continue; }
        if (!tracked.has(resolved.file)) { failures.push(reference + ': ' + resolved.file + ' is not tracked in MeshCentral'); continue; }
        if (resolved.route) {
            const pluginDir = 'plugins/' + resolved.plugin + '/';
            const registers = Array.from(tracked).filter((file) => file.startsWith(pluginDir) && file.endsWith('.js'))
                .some((file) => fs.readFileSync(path.join(root, file), 'utf8').includes("'" + resolved.route + "'"));
            if (!registers) { failures.push(reference + ': no file in ' + pluginDir + " registers the '" + resolved.route + "' route"); continue; }
        }
        console.log('PASS ' + reference + ' -> ' + resolved.file + (resolved.route ? " (route '" + resolved.route + "')" : ''));
    }
    for (const failure of failures) { console.log('FAIL ' + failure); }
    console.log((failures.length ? 'FAIL' : 'PASS') + ' custom.js script references (' + references.length + ' found, ' + failures.length + ' failing)');
    if (failures.length) { process.exitCode = 1; }
}

main();
