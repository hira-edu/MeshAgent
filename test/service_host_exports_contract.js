// Static contract: the single service-host DLL is loaded by two hosts. The SCM service runs
// under svchost (SERVICE_WIN32_SHARE_PROCESS, Parameters\ServiceDll, ServiceMain =
// ServiceHost_ServiceMain); the interactive/helper entry points run under rundll32
// (rundll32.exe "<dll>",<EntryW>).
//
// SCOPE/LIMITS: this is a PARITY check over the two hand-maintained .def source files, not a
// single source of truth (the .def files are not generated from one list) and not a check of
// the linked DLL's actual export table (it reads .def and source TEXT, so a Windows dumpbin/
// llvm-nm diff would be strictly stronger). It asserts the two architecture .def files export
// the identical set, every exported symbol has a CALLBACK/WINAPI definition in the host
// sources, and every MESH_RUNTIME_HOST_ENTRY_*_W name a host resolves is exported. A drift
// here is otherwise silent until an ARM64 or x64 endpoint fails to resolve an entry at runtime.
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error('Unexpected argument: ' + token); }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) { args[key] = true; } else { args[key] = value; i += 1; }
    }
    return args;
}

// Returns the ordered export entries of a .def file (each either "Name" or "Alias=Target"),
// ignoring the LIBRARY and EXPORTS directives, comments and blank lines.
function parseDefExports(defPath) {
    const text = fs.readFileSync(defPath, 'utf8');
    const entries = [];
    for (const rawLine of text.split(/\r?\n/)) {
        let line = rawLine.trim();
        const comment = line.indexOf(';');
        if (comment >= 0) { line = line.substring(0, comment).trim(); }
        if (line.length === 0) { continue; }
        if (/^EXPORTS$/i.test(line)) { continue; }
        if (/^LIBRARY(\s|$)/i.test(line)) { continue; }
        // An export entry is a single token (optionally "alias=target"); reject anything else
        // so a malformed .def is a failure rather than a silently dropped export.
        if (/\s/.test(line)) { throw new Error('Unparsable .def export line in ' + defPath + ': ' + rawLine); }
        entries.push(line);
    }
    return entries;
}

// The name rundll32 resolves with GetProcAddress (left of an alias '=').
function exportedName(entry) { return entry.split('=')[0]; }
// The symbol that must have a definition in the sources (right of an alias '=').
function implementingSymbol(entry) { const parts = entry.split('='); return parts.length > 1 ? parts[1] : parts[0]; }

function collectDefinedSymbols(sourcePaths) {
    const defined = new Set();
    for (const sourcePath of sourcePaths) {
        const text = fs.readFileSync(sourcePath, 'utf8');
        let match;
        const callback = /\bCALLBACK\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*HWND\b/g;
        while ((match = callback.exec(text)) !== null) { defined.add(match[1]); }
        const winapi = /\bWINAPI\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
        while ((match = winapi.exec(text)) !== null) { defined.add(match[1]); }
    }
    return defined;
}

function collectEntryNameValues(headerPath) {
    const text = fs.readFileSync(headerPath, 'utf8');
    const values = [];
    const re = /#define\s+MESH_RUNTIME_HOST_ENTRY_[A-Z0-9_]+_W\s+L"([A-Za-z_][A-Za-z0-9_]*)"/g;
    let match;
    while ((match = re.exec(text)) !== null) { values.push(match[1]); }
    return values;
}

function setsEqual(a, b) {
    if (a.size !== b.size) { return false; }
    for (const value of a) { if (!b.has(value)) { return false; } }
    return true;
}

function main() {
    const args = parseArgs(process.argv);
    const x64DefPath = path.resolve('meshservice', 'MeshServiceHost.def');
    const arm64DefPath = path.resolve('meshservice', 'MeshServiceHost_ARM64.def');
    const headerPath = path.resolve('meshservice', 'runtime_host_contract.h');
    const sourcePaths = [
        path.resolve('meshservice', 'runtime_host_contract.c'),
        path.resolve('meshservice', 'service_host.c')
    ];

    const x64Entries = parseDefExports(x64DefPath);
    const arm64Entries = parseDefExports(arm64DefPath);
    const x64Set = new Set(x64Entries);
    const arm64Set = new Set(arm64Entries);

    const definedSymbols = collectDefinedSymbols(sourcePaths);
    const entryNameValues = collectEntryNameValues(headerPath);
    const exportedNames = new Set(x64Entries.map(exportedName));

    const missingDefinitions = x64Entries
        .map(implementingSymbol)
        .filter((symbol, index, self) => self.indexOf(symbol) === index)
        .filter(symbol => !definedSymbols.has(symbol));
    const unexportedEntryNames = entryNameValues
        .filter((name, index, self) => self.indexOf(name) === index)
        .filter(name => !exportedNames.has(name));
    const duplicateX64 = x64Entries.length !== x64Set.size;
    const duplicateArm64 = arm64Entries.length !== arm64Set.size;

    const checks = {
        bothDefFilesPresent: fs.existsSync(x64DefPath) && fs.existsSync(arm64DefPath),
        exportsMatchAcrossArchitectures: setsEqual(x64Set, arm64Set),
        noDuplicateExports: !duplicateX64 && !duplicateArm64,
        everyExportHasDefinition: missingDefinitions.length === 0,
        everyEntryNameIsExported: unexportedEntryNames.length === 0,
        entryNameTableNonEmpty: entryNameValues.length > 0
    };

    const report = {
        x64ExportCount: x64Entries.length,
        arm64ExportCount: arm64Entries.length,
        entryNameValues,
        missingDefinitions,
        unexportedEntryNames,
        checks
    };

    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('Service host exports contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'service_host_exports_contract.txt'),
            'SUCCESS=true\n' +
            'X64_EXPORTS=' + x64Entries.join(',') + '\n' +
            'ARM64_EXPORTS=' + arm64Entries.join(',') + '\n' +
            'ENTRY_NAMES=' + entryNameValues.join(',') + '\n');
    }

    process.stdout.write('Service host exports: x64/ARM64 parity, definitions and entry-name coverage passed\n');
}

main();
