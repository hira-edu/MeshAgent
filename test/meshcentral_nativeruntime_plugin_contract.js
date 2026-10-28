'use strict';
// The fork's nativeruntime MeshCentral plugin (plugins/nativeruntime), loaded from the fork checkout.
// SRV-44: runtime status is read only from the shape the agent emits (meshcore/runtime_control_binding.c
//   MeshRuntimeBinding_PutEndpoint): controllers.x86 and controllers.x64, each with the fixed numeric
//   fields and flags bit 0 set while that runtime is active. Any other shape is not a status.
// SRV-45: the plugin exports no close(); pluginHandler.js never calls one.
// SRV-49: hook keys are plain property names, as pluginHandler.callHook looks them up.
// SRV-48: metadata and docs name the fork's MeshCentral version, not 1.2.1.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { meshcentralRoot } = require('./lib/meshcentral_paths');

const root = meshcentralRoot();
const pluginDir = path.join(root, 'plugins', 'nativeruntime');
const pluginSource = fs.readFileSync(path.join(pluginDir, 'nativeruntime.js'), 'utf8');
const { nativeruntime, createController, sanitizeStatus } = require(path.join(pluginDir, 'nativeruntime.js'));

// The agent's endpoint record.
const binding = fs.readFileSync(path.join(__dirname, '..', 'meshcore', 'runtime_control_binding.c'), 'utf8');
const endpointFields = [...binding.slice(binding.indexOf('static void MeshRuntimeBinding_PutEndpoint'), binding.indexOf('duk_ret_t MeshRuntimeBinding_Execute'))
    .matchAll(/"([A-Za-z]+)"/g)].map(m => m[1]);
assert.deepStrictEqual(endpointFields, ['transportSuccess', 'transportError', 'result', 'flags', 'matchedTargetCount', 'residentTargetCount',
    'activeTargetCount', 'inactiveTargetCount', 'failedTargetCount', 'lastError'], 'the agent endpoint record this test models');
assert(/MeshRuntimeBinding_PutEndpoint\(ctx, &results\[0\]\); duk_put_prop_string\(ctx, -2, "x86"\);/.test(binding) &&
    /MeshRuntimeBinding_PutEndpoint\(ctx, &results\[1\]\); duk_put_prop_string\(ctx, -2, "x64"\);/.test(binding) &&
    binding.includes('duk_put_prop_string(ctx, -2, "controllers");'), 'the agent always sends controllers.x86 and controllers.x64');
function endpoint(active, transportError = 0, transportSuccess = true) {
    return { transportSuccess, transportError, result: 0, flags: active ? 1 : 0, matchedTargetCount: 0, residentTargetCount: 0,
        activeTargetCount: active ? 1 : 0, inactiveTargetCount: active ? 0 : 1, failedTargetCount: 0, lastError: transportError };
}
const agentResult = (x86, x64, extra = {}) => ({ action: 'nativeRuntimeResult', version: 1, operation: 'getStatus', ok: true, controllers: { x86, x64 }, ...extra });

// SRV-44: the agent shape.
for (const [x86, x64, running] of [[false, false, false], [true, false, true], [false, true, true], [true, true, true]]) {
    const status = sanitizeStatus(agentResult(endpoint(x86), endpoint(x64)));
    assert.deepStrictEqual([status.state, status.running, status.loadEnabled], ['ready', running, running], `flags ${+x86}/${+x64}`);
    assert.deepStrictEqual(Object.keys(status).sort(), ['controllers', 'loadEnabled', 'running', 'state']);
}
assert.strictEqual(sanitizeStatus(agentResult(endpoint(false), endpoint(false, 1067))).state, 'degraded', 'a crashed launch is degraded');
assert.strictEqual(sanitizeStatus(agentResult(endpoint(false), endpoint(false, 2, false))).state, 'degraded', 'one unreachable controller is degraded');
assert.strictEqual(sanitizeStatus(agentResult(endpoint(false, 2, false), endpoint(false, 2, false))).state, 'unavailable');
assert.strictEqual(sanitizeStatus(agentResult(endpoint(false), endpoint(false), { state: 'degraded', running: true })).state, 'ready', 'agent-supplied state and running are ignored');
assert.strictEqual(sanitizeStatus(agentResult(endpoint(false), endpoint(false), { running: true })).running, false, 'running comes from the flags only');
const stripped = sanitizeStatus(agentResult({ ...endpoint(true), secret: 'C:\\private' }, endpoint(false)));
assert.deepStrictEqual(stripped.controllers.x86, { ...endpoint(true) }, 'only the fixed endpoint fields are forwarded');

// SRV-44: shapes no agent emits are not a status.
const notStatus = [
    { action: 'nativeRuntimeResult', running: true },
    { action: 'nativeRuntimeResult', loadEnabled: true },
    agentResult(undefined, undefined, { controllers: { running: true } }),
    agentResult(undefined, undefined, { controllers: { loadEnabled: true } }),
    agentResult({ running: true }, { running: false }),
    agentResult({ loadEnabled: true }, { loadEnabled: true }),
    agentResult({ active: true, transportSuccess: true }, endpoint(false)),
    agentResult(endpoint(true), undefined),
    agentResult(undefined, endpoint(true)),
    agentResult({ ...endpoint(true), flags: -1 }, endpoint(false)),
    agentResult(endpoint(true), endpoint(false), { controllers: [endpoint(true), endpoint(false)] }),
    null, [], 'running'
];
for (const message of notStatus) assert.strictEqual(sanitizeStatus(message), null, 'not a status: ' + JSON.stringify(message));

// A result in another shape does not settle a pending request; it ends as an unknown outcome.
(async () => {
    const sent = [];
    const agent = { dbNodeKey: 'node//A', send(value) { sent.push(JSON.parse(value)); } };
    const controller = createController({ getAgent: () => agent, timeoutMs: 50,
        authorize: async () => ({ principal: 'user//a', nodeid: 'node//A', canControl: true }) });
    const requestId = '6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b';
    const pending = controller.request({ action: 'nativeRuntime', version: 1, operation: 'getStatus', requestId }, {});
    await new Promise(setImmediate);
    assert.strictEqual(sent.length, 1, 'the request reached the agent');
    controller.receive({ action: 'nativeRuntimeResult', version: 1, operation: 'getStatus', requestId: sent[0].requestId, ok: true, running: true, loadEnabled: true }, agent);
    const response = await pending;
    assert.strictEqual(response.error && response.error.code, 'outcome-unknown', 'a top-level running result is not accepted');

    // SRV-45, SRV-49: the plugin object pluginHandler sees.
    const server = { config: { domains: { '': { id: '', url: '/' } }, settings: { plugins: { enabled: true, list: ['nativeruntime'] } } },
        db: { Get(id, cb) { cb(null, []); } }, decodeCookie() { return null; } };
    const plugin = nativeruntime({ parent: server });
    assert.deepStrictEqual(Object.keys(plugin).sort(), ['exports', 'hook_processAgentData', 'hook_setupHttpHandlers'], 'plugin members');
    assert(!/'hook_'\s*\+/.test(pluginSource), 'hook keys are not built by concatenation');
    const handler = fs.readFileSync(path.join(root, 'pluginHandler.js'), 'utf8');
    assert(!/\.close\s*\(/.test(handler.replace(/file\.close\(/g, '')), 'pluginHandler.js calls no plugin close()');

    // SRV-48: the fork's MeshCentral version, and no 1.2.1 left in the plugin.
    const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
    const config = JSON.parse(fs.readFileSync(path.join(pluginDir, 'config.json'), 'utf8'));
    assert.strictEqual(config.meshCentralCompat, version, 'config.json meshCentralCompat is the fork package version');
    for (const name of fs.readdirSync(pluginDir)) {
        assert(!fs.readFileSync(path.join(pluginDir, name), 'utf8').includes('1.2.1'), name + ' must not name MeshCentral 1.2.1');
    }
    const readme = fs.readFileSync(path.join(pluginDir, 'README.md'), 'utf8');
    for (const [, ref] of readme.matchAll(/`((?:deploy|plugins|views)\/[^`\s]+)`/g)) {
        assert(fs.existsSync(path.join(root, ref)), 'README path exists: ' + ref);
    }
    console.log('meshcentral_nativeruntime_plugin_contract: PASS (agent status shape only, plain hooks, no close, fork version)');
})().catch(error => { console.error(error); process.exitCode = 1; });
