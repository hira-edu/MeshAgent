// The trackpad engine is derived from Apache Guacamole (Apache-2.0) and Chromium (BSD-3). Keep the
// attribution those licences require in the served file and in the repository notices.
const fs = require('fs');
const path = require('path');
const { meshcentralRoot } = require('./lib/meshcentral_paths');

// Every input is required: a missing or empty file fails the contract and says what it was for.
function readRequired(file, purpose) {
    let text;
    try {
        text = fs.readFileSync(file, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') throw new Error(`required input missing: ${file} (${purpose})`, { cause: error });
        throw error;
    }
    if (text.trim().length === 0) throw new Error(`required input is empty: ${file} (${purpose})`);
    return text;
}

const meshcentral = meshcentralRoot();
const engine = readRequired(path.join(meshcentral, 'public/scripts/agent-desktop-trackpad-0.0.1.js'), 'trackpad engine whose licence header is checked');
// Since Stage 1 the notices sit at their publish path inside the fork package, next to the engine.
const notices = readRequired(path.join(meshcentral, 'public/scripts/THIRD_PARTY_NOTICES.txt'), 'repository notices that must carry the trackpad engine attribution');
const header = engine.startsWith('/*!') ? engine.slice(0, engine.indexOf('*/') + 2).replace(/^\s*\* ?/gm, '') : '';
const flat = text => text.replace(/\s+/g, ' ');

const bsd = [
    'Copyright 2015 The Chromium Authors. All rights reserved.',
    'Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.',
    'Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.',
    'Neither the name of Google Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.',
    'IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES'
];
const checks = {
    // A /*! header survives minifiers that keep licence comments.
    engineHeaderPreserved: header.length > 0 && engine.startsWith('/*! @license'),
    engineApacheHeader: flat(header).includes('Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements.') && flat(header).includes('http://www.apache.org/licenses/LICENSE-2.0'),
    engineGuacamoleNotice: flat(header).includes('Apache Guacamole Copyright 2020 The Apache Software Foundation'),
    engineModificationNotice: flat(header).includes('Modified:'),
    engineSourcePinned: header.includes('31d2a6f6accc5ed4fecd491c30fc51728db940eb') && header.includes('90.0.4430.0'),
    engineChromiumFileNotice: flat(header).includes('Copyright 2013 The Chromium Authors. All rights reserved.'),
    // uglify-js drops the header unless told to keep it, so the engine ships unminified: any
    // minified copy must still carry the full header.
    noMinifiedWithoutHeader: fs.readdirSync(path.join(meshcentral, 'public/scripts')).filter(f => /^agent-desktop-trackpad-.*-min\.js$/.test(f)).every(f => flat(readRequired(path.join(meshcentral, 'public/scripts', f), 'minified trackpad engine copy')).includes(flat(header).slice(0, 200))),
    engineBsdText: bsd.every(line => flat(header).includes(line)),
    noticesListEngine: notices.includes('public/scripts/agent-desktop-trackpad-0.0.1.js'),
    noticesGuacamole: flat(notices).includes('Apache Guacamole Copyright 2020 The Apache Software Foundation'),
    noticesBsdText: bsd.every(line => flat(notices.replace(/^\/\/ ?/gm, '')).includes(line)),
    noticesChromiumFileNotice: flat(notices).includes('Copyright 2013 The Chromium Authors. All rights reserved.'),
    noticesApacheLicence: notices.includes('Apache License') && notices.includes('Version 2.0, January 2004') && notices.includes('END OF TERMS AND CONDITIONS'),
    // The notices are published next to the engine they cover.
    noticesPublished: (() => { const d = readRequired(path.join(__dirname, '..', 'deploy.py'), 'deploy mapping that must publish the notices next to the engine'); return d.includes('"local_path": "../MeshCentral/public/scripts/THIRD_PARTY_NOTICES.txt"') && d.includes('"remote_relative_path": "scripts/THIRD_PARTY_NOTICES.txt"') && d.includes('"remote_relative_path": "scripts/agent-desktop-trackpad-0.0.1.js"'); })()
};
const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([name]) => name);
for (const name of failed) console.log(`FAIL ${name}`);
console.log(`${failed.length ? 'FAIL' : 'PASS'} trackpad licence attribution (${Object.keys(checks).length} checks)`);
if (failed.length) process.exitCode = 1;
