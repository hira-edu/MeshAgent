'use strict';
// Module policy for the agent core modules the MeshCentral fork package serves (D22, G7).
//
// MeshCentral sends every file in agents/modules_meshcore inside the agent core as
// addModule(name, source, releaseDate). An agent replaces its own copy of a module when the server's
// date is newer, so the package decides which code agents run.
// D24: the package has no minified core. agents/modules_meshcore_min and agents/meshcore.min.js must
// not exist; with minifycore on, MeshCentral would serve them instead of the files checked here.
// Every package module file falls in exactly one class:
//   - MeshAgent-owned (D22): modules both projects carry, shipped as MeshAgent's own copy. The
//     package bytes equal MeshAgent's modules/<name>.js as git stores it (LF), byte for byte.
//   - fork: modules upstream does not ship, or that the fork replaces. They equal MeshAgent's
//     modules/<name>.js apart from line endings (the package keeps production's CRLF bytes), with no
//     exceptions: clipboard is MeshAgent's copy too (CORE-56, operator 2026-10-28).
//   - upstream: everything else equals the pinned upstream package (test/lib/meshcentral_upstream_
//     reference.json) byte for byte, and every upstream module is present.
// A file that fits none of these is unknown and fails.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { forkFile, upstreamPackageDir } = require('./lib/meshcentral_paths');

const root = path.resolve(__dirname, '..');
const FOLDER = 'modules_meshcore';
// D24: removed from the package; each must be absent.
const ABSENT = ['modules_meshcore_min', 'meshcore.min.js'];

// D22 (option b, operator 2026-10-28): modules upstream also ships that the package carries as
// MeshAgent's copy: the four the agent embeds, and wifi-scanner (deliberate fork change). The other
// overlapping modules (amt-lme, amt-mei, smbios, wifi-scanner-windows, win-securitycenter, win-volumes)
// are not embedded and stay upstream's, so the upstream rule covers them.
const MESHAGENT_OWNED = ['monitor-border', 'util-agentlog', 'win-console', 'win-deskutils', 'wifi-scanner'];
// Upstream ships these, and the fork replaces them with MeshAgent's copy.
const FORK_REPLACES_UPSTREAM = ['win-terminal', 'win-virtual-terminal'];

const lf = (buffer) => buffer.toString('latin1').replace(/\r\n?/g, '\n');
const moduleName = (file) => file.replace(/\.min\.js$/, '.js').replace(/\.(js|json)$/, '');
const listModules = (directory) => fs.readdirSync(directory).filter((entry) => /\.(js|json)$/.test(entry)).sort();
// true when the path exists; false only for ENOENT, so any other error stops the contract.
function exists(target) {
    try { fs.lstatSync(target); return true; } catch (error) { if (error.code === 'ENOENT') { return false; } throw error; }
}

function main() {
    const agents = forkFile('agents');
    const upstreamAgents = path.join(upstreamPackageDir(), 'agents');
    const result = { owned: [], fork: [], upstream: [], drifted: [], unknown: [], missingUpstream: [], missingOwned: [], present: [] };
    assert(fs.statSync(agents).isDirectory(), 'MeshCentral package folder missing: ' + agents);
    for (const name of ABSENT) {
        if (exists(path.join(agents, name))) { result.present.push('agents/' + name); }
    }

    {
        const folder = FOLDER;
        const directory = path.join(agents, folder);
        const upstreamDirectory = path.join(upstreamAgents, folder);
        assert(fs.statSync(directory).isDirectory(), 'MeshCentral package folder missing: ' + directory);
        assert(fs.statSync(upstreamDirectory).isDirectory(), 'upstream reference folder missing: ' + upstreamDirectory);
        const names = listModules(directory);
        for (const name of listModules(upstreamDirectory)) {
            if (!names.includes(name)) { result.missingUpstream.push(folder + '/' + name); }
        }
        for (const name of names) {
            const relative = folder + '/' + name;
            const module = moduleName(name);
            const bytes = fs.readFileSync(path.join(directory, name));
            const source = path.join(root, 'modules', module + '.js');
            const hasSource = fs.existsSync(source);
            const upstreamFile = path.join(upstreamDirectory, name);
            const inUpstream = fs.existsSync(upstreamFile);
            if (MESHAGENT_OWNED.includes(module)) {
                result.owned.push(relative);
                if (!hasSource || !bytes.equals(Buffer.from(lf(fs.readFileSync(source)), 'latin1'))) {
                    result.drifted.push(relative + ' (MeshAgent-owned: must equal modules/' + module + '.js)');
                }
            } else if (!inUpstream || FORK_REPLACES_UPSTREAM.includes(module)) {
                if (!hasSource) { result.unknown.push(relative); continue; }
                result.fork.push(relative);
                if (lf(bytes) !== lf(fs.readFileSync(source))) { result.drifted.push(relative + ' (fork: must equal modules/' + module + '.js)'); }
            } else {
                result.upstream.push(relative);
                if (!bytes.equals(fs.readFileSync(upstreamFile))) { result.drifted.push(relative + ' (must equal upstream)'); }
            }
        }
    }
    for (const module of MESHAGENT_OWNED) {
        if (!result.owned.includes('modules_meshcore/' + module + '.js')) { result.missingOwned.push('modules_meshcore/' + module + '.js'); }
    }

    const checks = {
        // Guards against a vacuous pass if the layout changes.
        everyClassPopulated: result.owned.length === MESHAGENT_OWNED.length && result.fork.length >= 10 && result.upstream.length >= 15,
        everyMeshAgentOwnedModulePresent: result.missingOwned.length === 0,
        everyUpstreamModulePresent: result.missingUpstream.length === 0,
        noUnknownModule: result.unknown.length === 0,
        everyCopyMatchesItsSource: result.drifted.length === 0,
        // D24: no minified core in the package (served instead of the files above with minifycore on).
        noMinifiedCore: result.present.length === 0
    };
    const failed = Object.keys(checks).filter((name) => !checks[name]);
    const counts = { owned: result.owned.length, fork: result.fork.length, upstream: result.upstream.length };
    process.stdout.write(JSON.stringify({ success: failed.length === 0, counts, drifted: result.drifted, present: result.present,
        unknown: result.unknown, missingUpstream: result.missingUpstream, missingOwned: result.missingOwned, checks }, null, 2) + '\n');
    assert(failed.length === 0, 'MeshCentral core module policy failed: ' + failed.join(', '));
}

main();
