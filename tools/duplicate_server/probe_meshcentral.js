// Read what a layout serves through MeshCentral's own server object and functions.
//
// node probe_meshcentral.js <layoutRoot>
//
// The layout's node_modules/meshcentral/meshcentral.js is compiled in memory with one extra line
// that exports CreateMeshCentralServer and getConfig (the file on disk is not touched). The probe
// then runs MeshCentral's own getConfig, CreateMeshCentralServer, pluginHandler, updateMeshCore,
// GetMeshServerCertificate and updateMeshAgentsTable, and reports:
//   - the module names and versions MeshCentral puts into each core (obj.defaultMeshCores),
//   - the on-disk agent binary MeshCentral selects per architecture (obj.meshAgentBinaries),
//   - selfUpdate and the loaded plugins as MeshCentral sees them.
// Only the start-up glue that lives inline in Start/StartEx is mirrored, each line cited.
// Run it after the layout's server has started once, so certificates and signed agents exist.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

function fail(message) { console.error('probe: ' + message); process.exit(1); }

const layoutRoot = path.resolve(process.argv[2] || '');
const packageDir = path.join(layoutRoot, 'node_modules', 'meshcentral');
const mcPath = path.join(packageDir, 'meshcentral.js');
if (!fs.existsSync(mcPath)) { fail('no MeshCentral at ' + mcPath); }

// mainStart() runs from the wrapper root with no arguments under systemd (meshcentral.js:4313).
process.chdir(layoutRoot);
process.argv = [process.argv[0], mcPath];

const source = fs.readFileSync(mcPath, 'utf8');
const loaded = new Module(mcPath, module);
loaded.filename = mcPath;
loaded.paths = Module._nodeModulePaths(packageDir);
loaded._compile(source + '\nmodule.exports.__dupProbe = { CreateMeshCentralServer: CreateMeshCentralServer, getConfig: getConfig };\n', mcPath);
const probe = loaded.exports.__dupProbe;
if (!probe) { fail('could not expose CreateMeshCentralServer from ' + mcPath); }
const req = Module.createRequire(mcPath);

const config = probe.getConfig(false);
if (config == null) { fail('MeshCentral getConfig returned null'); }
const args = req('minimist')([]);
const obj = probe.CreateMeshCentralServer(config, args);

// obj.Start: "Place all settings into arguments" (meshcentral.js:185).
for (const i in obj.config.settings) { obj.args[i] = obj.config.settings[i]; }
// obj.StartEx: minifycore default (meshcentral.js:1675).
if (obj.args.minifycore == null) { obj.args.minifycore = false; }
// obj.StartEx domain setup: url and id (meshcentral.js:1520-1521).
for (const i in obj.config.domains) {
    if (obj.config.domains[i].dns == null) { obj.config.domains[i].url = (i == '') ? '/' : ('/' + i + '/'); } else { obj.config.domains[i].url = '/'; }
    obj.config.domains[i].id = i;
}

const report = {
    layout: layoutRoot,
    meshcentralVersion: JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8')).version,
    node: process.version,
    datapath: obj.datapath,
    webViewsOverridePath: obj.webViewsOverridePath || null,
    webPublicOverridePath: obj.webPublicOverridePath || null,
    args: { selfupdate: obj.args.selfupdate, minifycore: obj.args.minifycore, minify: obj.config.domains[''].minify, plugins: obj.args.plugins || null },
};

function decodeCore(buffer) {
    // A core is IntToStr(0) + 'var addedModules = [];' + one addModule line per module + the core text
    // (meshcentral.js updateMeshCore). Read the addModule calls MeshCentral wrote.
    // Each generated entry is one physical line: escapeCodeString escapes CR and LF inside the module.
    const text = buffer.slice(4).toString('utf8');
    const header = 'var addedModules = [];\r\n';
    if (!text.startsWith(header)) { fail('core does not start with the addedModules header'); }
    const jsLine = /^try \{ addModule\("([^"]+)", "((?:[^"\\]|\\.)*)"(?:, "([^"]*)")?\); addedModules\.push\("([^"]+)"\); \} catch \((?:ex|e)\) \{ \}$/;
    const jsonLine = /^var ([A-Za-z0-9_$-]+) = JSON\.parse\('((?:[^'\\]|\\.)*)'\);$/;
    const modules = [];
    let offset = header.length;
    while (true) {
        const end = text.indexOf('\r\n', offset);
        if (end < 0) { break; }
        const line = text.slice(offset, end);
        let match = jsLine.exec(line), entry = null;
        if (match) {
            if (match[1] !== match[4]) { fail('addModule/addedModules name mismatch in core: ' + match[1]); }
            entry = { name: match[1], kind: 'js', version: match[3] === undefined ? null : match[3], escaped: match[2] };
        } else if ((match = jsonLine.exec(line))) {
            entry = { name: match[1], kind: 'json', version: null, escaped: match[2] };
        } else {
            break; // first line that is not a module entry: the core text starts here
        }
        modules.push({ name: entry.name, kind: entry.kind, version: entry.version, escapedLength: entry.escaped.length,
            sha256OfEscaped: crypto.createHash('sha256').update(entry.escaped).digest('hex') });
        offset = end + 2;
    }
    const coreText = text.slice(offset);
    return { bytes: buffer.length, sha384: crypto.createHash('sha384').update(buffer).digest('hex'), modules,
        coreTextSha256: crypto.createHash('sha256').update(coreText).digest('hex') };
}

function sha256File(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

function requireFile(file, why) { if (!fs.existsSync(file)) { fail(file + ' is missing (' + why + '); start the layout once before probing'); } }

// obj.StartEx connects the database before creating the plugin handler (meshcentral.js:1001-1002);
// the plugin handler reads plugin records from it. SetupDatabase is not run: the server already did.
req('./db.js').CreateDB(obj, function (db) {
    obj.db = db;
    // Plugins: obj.StartEx creates the handler under this exact condition (meshcentral.js:1769-1771).
    if ((obj.config) && (obj.config.settings) && (obj.config.settings.plugins != null) && (obj.config.settings.plugins != false) && ((typeof obj.config.settings.plugins != 'object') || (obj.config.settings.plugins.enabled != false))) {
        obj.pluginHandler = req('./pluginHandler.js').pluginHandler(obj);
    }
    report.plugins = {
        configured: (obj.config.settings.plugins && obj.config.settings.plugins.list) || [],
        loaded: obj.pluginHandler ? Object.keys(obj.pluginHandler.plugins).sort() : [],
        pluginPath: obj.pluginHandler ? obj.pluginHandler.pluginPath : null,
    };

    obj.updateMeshCore(function (ok) {
        if (ok !== true) { fail('updateMeshCore reported failure (no meshcore.js found)'); }
        // Where the core came from: the same existsSync test MeshCentral used (meshcentral.js:2932-2938).
        report.coreSource = fs.existsSync(path.join(obj.datapath, 'meshcore.js')) ? obj.datapath : path.join(packageDir, 'agents');
        report.cores = {};
        for (const name of Object.keys(obj.defaultMeshCores).sort()) { report.cores[name] = decodeCore(obj.defaultMeshCores[name]); }

        requireFile(path.join(obj.datapath, 'root-cert-public.crt'), 'server certificates');
        requireFile(path.join(obj.datapath, 'codesign-cert-public.crt'), 'agent code-signing certificate');
        obj.certificateOperations = req('./certoperations.js').CertificateOperations(obj);
        obj.certificateOperations.GetMeshServerCertificate(obj.args, obj.config, function (certs) {
            obj.certificates = certs;
            report.codeSigning = { present: certs.codesign != null };
            const domain = obj.config.domains[''];
            let reported = false;
            const done = function () {
                if (reported) { return; } reported = true;
                report.agentBinaries = {};
                for (const archid of [3, 4, 43]) {
                    const bin = obj.meshAgentBinaries[archid];
                    const arch = obj.meshAgentsArchitectureNumbers[archid];
                    if (bin == null) { report.agentBinaries[archid] = { selected: null, localname: arch.localname }; continue; }
                    report.agentBinaries[archid] = {
                        localname: arch.localname, core: arch.core, unsigned: arch.unsigned === true,
                        path: bin.path, relativePath: path.relative(layoutRoot, bin.path).split(path.sep).join('/'),
                        size: fs.statSync(bin.path).size, sha256: sha256File(bin.path),
                    };
                }
                process.stdout.write(JSON.stringify(report, null, 2) + '\n');
                process.exit(0);
            };
            // updateMeshAgentsTable calls back once every binary is loaded (meshcentral.js:3598).
            obj.updateMeshAgentsTable(domain, done);
            setTimeout(function () { if (!reported) { fail('updateMeshAgentsTable did not finish within 120s'); } }, 120000).unref();
        });
    });
});
