'use strict';
// The fork server's agent architecture table (meshAgentsArchitectureNumbers), which the Windows and
// service agent helpers in meshagent.js derive from (SRV-10). Since MeshCentral 1.3.1 (60cea8731)
// meshcentral.js loads it from agenttypes.js; this checks that wiring and returns a fresh table from
// the fork's agenttypes.js, which is a pure data module.
const assert = require('assert');
const fs = require('fs');
const { forkFile } = require('./meshcentral_paths');

const LOADER = "obj.meshAgentsArchitectureNumbers = require('./agenttypes')();";

function readArchitectureTable() {
    const loader = fs.readFileSync(forkFile('meshcentral.js'), 'utf8');
    assert(loader.includes(LOADER), 'meshcentral.js must load meshAgentsArchitectureNumbers from agenttypes.js');
    const source = fs.readFileSync(forkFile('agenttypes.js'), 'utf8');
    const module = { exports: {} };
    new Function('module', 'exports', 'require', source)(module, module.exports, (name) => {
        throw new Error('agenttypes.js must not require modules, it asked for ' + name);
    });
    assert.strictEqual(typeof module.exports, 'function', 'agenttypes.js must export a table factory');
    const table = module.exports();
    assert(table != null && typeof table == 'object' && Object.keys(table).length > 0, 'agenttypes.js must return the architecture table');
    return table;
}

module.exports = { readArchitectureTable };
