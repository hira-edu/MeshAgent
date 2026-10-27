/*
 * harden-image-size.js — preload shim for MeshCentral.
 *
 * WHY THIS EXISTS
 * ---------------
 * image-size has two unpatched high-severity advisories with no fixed release
 * upstream (latest published is 2.0.2, which is what we run):
 *
 *   GHSA-w3rx-r6r6-pgpr  ICNS parser  — denial of service via infinite loop
 *   GHSA-5p2g-fcmc-qvqq  JXL/HEIF parsers — denial of service via infinite loops
 *
 * MeshCentral calls image-size on attacker-influenceable bytes:
 *
 *   meshdesktopmultiplex.js:700  imageSize(data.slice(8))   // desktop tile from an agent
 *   mcrec.js:125                 imageSize(block.data.slice(8))  // recording file block
 *
 * imageSize() sniffs the format from the buffer, so any authenticated agent can
 * send a tile whose bytes are detected as ICNS/JXL/HEIF and hang the server's
 * event loop. `desktopmultiplex` is enabled here, so that path is live.
 *
 * MeshCentral's desktop tiles and recording blocks are JPEG (with PNG in some
 * paths); the ICNS/JXL/HEIF decoders are never legitimately needed. Disabling
 * them removes the vulnerable code paths entirely while leaving normal
 * operation untouched.
 *
 * HOW IT IS LOADED
 * ----------------
 * NODE_OPTIONS=--require=<this file>, so it runs before meshcentral.js loads:
 * the host service through the systemd drop-in 30-harden-image-size.conf, and
 * release containers through release_manager.start. Both files are tracked in
 * MeshAgent tools/deployment and installed by install_controller.py.
 *
 * image-size is resolved the way MeshCentral resolves it: from the directory of
 * the script Node is running (node_modules/meshcentral/meshcentral.js, so the
 * same node_modules lookup and the same module instance MeshCentral uses), then
 * from the working directory. No install path is assumed.
 *
 * FAIL CLOSED
 * -----------
 * If image-size cannot be found, has no disableTypes(), no longer lists one of
 * the parsers below, or still runs one of them after disabling, this shim stops
 * the process with an error. MeshCentral never starts with the parsers enabled.
 * The line "harden-image-size: disabled unpatched parsers: ..." is printed only
 * after every parser was proven disabled; the release smoke test requires it.
 *
 * REMOVE THIS once image-size ships a release that fixes both advisories:
 * delete the drop-in and the release preload, and re-run `npm audit`.
 */

'use strict';

var fs = require('fs');
var path = require('path');

var DISABLE = ['icns', 'jxl', 'jxl-stream', 'heif'];

// The smallest input image-size 2.0.2 detects as each type. Each one is refused before its
// parser runs when the type is disabled; even if a parser did run, every length field here
// ends inside the buffer, so the probe itself cannot loop.
var PROBES = {
    'icns': Buffer.from('69636e7300000008', 'hex'),
    'jxl': Buffer.concat([Buffer.from('0000000c4a584c200d0a870a', 'hex'),
                          Buffer.from('00000014667479706a786c20000000006a786c20', 'hex')]),
    'jxl-stream': Buffer.from('ff0a00000000', 'hex'),
    'heif': Buffer.from('00000018667479706865696300000000' + '6d69663168656963', 'hex')
};

function refuse(reason) {
    throw new Error('harden-image-size: refusing to start MeshCentral with the unpatched image-size parsers enabled: ' +
                    reason);
}

function searchPaths() {
    var paths = [];
    if (process.argv[1]) {
        var script = path.resolve(process.argv[1]);
        try {
            script = fs.realpathSync(script); // Node resolves the main script's symlinks the same way.
        } catch (ex) {
            refuse('cannot locate the script being started (' + script + '): ' + ex.message);
        }
        paths.push(path.dirname(script));
    }
    paths.push(process.cwd());
    return paths;
}

function harden() {
    var paths = searchPaths();
    var location;
    try {
        location = require.resolve('image-size', { paths: paths });
    } catch (ex) {
        refuse('image-size cannot be resolved from ' + paths.join(', ') + ': ' + ex.message);
    }
    var imageSize = require(location);
    if (typeof imageSize.disableTypes !== 'function' || typeof imageSize.imageSize !== 'function' ||
            !Array.isArray(imageSize.types)) {
        refuse(location + ' does not provide disableTypes(), imageSize() and types; review this mitigation');
    }
    var missing = DISABLE.filter(function (type) { return imageSize.types.indexOf(type) < 0; });
    if (missing.length > 0) {
        refuse(location + ' no longer lists the parser(s) ' + missing.join(', ') + '; review this mitigation');
    }
    imageSize.disableTypes(DISABLE.slice());
    DISABLE.forEach(function (type) {
        var result;
        try {
            result = imageSize.imageSize(PROBES[type]);
        } catch (ex) {
            if (ex && ex.message === 'disabled file type: ' + type) { return; }
            refuse('the ' + type + ' probe was not refused as disabled (' + (ex && ex.message) + ')');
        }
        refuse('the ' + type + ' probe was parsed (' + JSON.stringify(result) + ')');
    });
    console.log('harden-image-size: disabled unpatched parsers: ' + DISABLE.join(', '));
}

harden();
