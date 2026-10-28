'use strict';
// SRV-10 (S10): meshagent.js decides which agents are Windows agents, and which of those are service
// agents, from MeshCentral's architecture table (meshAgentsArchitectureNumbers in meshcentral.js), not
// from a second hand-kept id list. Windows agents are the win32 entries; service agents are the
// MeshService binaries among them. Id 34 is the MeshCentral Assistant (platform 'assistant'), not a
// Windows agent. The update gate, the native update route and agentupdate requests use these sets.
// The fork's helpers are executed against the real table.
const assert = require('assert');
const fs = require('fs');
const { forkFile } = require('./lib/meshcentral_paths');

function read(filePath) { return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n'); }

function extractBraced(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing: ${signature}`);
    const bodyStart = source.indexOf('{', start + signature.length - 1);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated: ${signature}`);
}

const server = read(forkFile('meshagent.js'));
const architectures = new Function('return ' + extractBraced(read(forkFile('meshcentral.js')), 'obj.meshAgentsArchitectureNumbers = {').replace('obj.meshAgentsArchitectureNumbers = ', '') + ';')();
const helpers = new Function('parent', [
    extractBraced(server, 'function isWindowsServiceAgentArchitecture(agentId)'),
    extractBraced(server, 'function isWindowsAgentArchitecture(agentId)'),
    'return { isWindowsServiceAgentArchitecture, isWindowsAgentArchitecture };'
].join('\n'))({ parent: { meshAgentsArchitectureNumbers: architectures } });

const ids = Object.keys(architectures).map(Number).sort((a, b) => a - b);
const windows = ids.filter(id => helpers.isWindowsAgentArchitecture(id));
const services = ids.filter(id => helpers.isWindowsServiceAgentArchitecture(id));
const agentIds = id => id < 10000; // ids an agent reports; 10000+ are download variants and tools

// The sets the update code has always used for agents, without the Assistant (34).
assert.deepStrictEqual(services.filter(agentIds), [3, 4, 22, 43], 'Windows service agents');
assert.deepStrictEqual(windows.filter(agentIds), [1, 2, 3, 4, 21, 22, 42, 43], 'Windows agents');
assert.strictEqual(architectures[34].platform, 'assistant', 'id 34 is the MeshCentral Assistant');
assert(!helpers.isWindowsAgentArchitecture(34), 'the Assistant is not a Windows agent');
// The table's other win32 entries classify the same way: the unsigned service builds are services,
// the Assistant executable and MeshCmd are Windows but not services.
assert.deepStrictEqual(services.filter(id => !agentIds(id)), [10003, 10004]);
assert.deepStrictEqual(windows.filter(id => !agentIds(id)), [10003, 10004, 10006, 11000, 11001, 11002]);
// Every classification follows the table, so a new table entry needs no second list.
for (const id of ids) {
    const entry = architectures[id];
    assert.strictEqual(helpers.isWindowsAgentArchitecture(id), entry.platform === 'win32', `id ${id}: Windows follows platform`);
    assert.strictEqual(helpers.isWindowsServiceAgentArchitecture(id), entry.platform === 'win32' && /service/i.test(entry.desc), `id ${id}: service follows the table`);
}
for (const id of [-1, 31, 44, 99, 12345, undefined, null, 'x']) {
    assert.strictEqual(helpers.isWindowsAgentArchitecture(id), false, `unknown id ${id} is not Windows`);
    assert.strictEqual(helpers.isWindowsServiceAgentArchitecture(id), false, `unknown id ${id} is not a service`);
}

// No second hand-kept id list remains in meshagent.js.
for (const name of ['isWindowsServiceAgentArchitecture', 'isWindowsAgentArchitecture']) {
    assert(!/agentId == \d/.test(extractBraced(server, 'function ' + name + '(agentId)')), name + ' must not compare literal ids');
}

console.log('meshcentral_windows_architecture_contract: PASS (Windows and service agent ids derive from meshAgentsArchitectureNumbers)');
