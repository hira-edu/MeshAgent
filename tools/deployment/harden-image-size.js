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
 * This lives in /opt/meshcentral/bin (outside node_modules) so that it survives
 * `npm install` / MeshCentral upgrades. It is wired in via the systemd drop-in
 * /etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf using
 * NODE_OPTIONS=--require, so it runs before meshcentral.js loads.
 *
 * REMOVE THIS once image-size ships a release that fixes both advisories:
 * delete the drop-in, run `systemctl daemon-reload`, and re-run `npm audit`.
 */

'use strict';

var DISABLE = ['icns', 'jxl', 'jxl-stream', 'heif'];

try {
    var imageSize = require('/opt/meshcentral/node_modules/image-size');
    if (typeof imageSize.disableTypes === 'function') {
        imageSize.disableTypes(DISABLE);
        console.log('harden-image-size: disabled unpatched parsers: ' + DISABLE.join(', '));
    } else {
        console.log('harden-image-size: WARNING - image-size has no disableTypes(); parsers NOT disabled');
    }
} catch (ex) {
    // Never block server startup because of this shim.
    console.log('harden-image-size: WARNING - could not harden image-size: ' + ex.message);
}
