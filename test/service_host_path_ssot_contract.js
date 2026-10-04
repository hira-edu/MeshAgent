// Static contract: there is ONE definition of "where is the system host binary" and "is this
// path exactly that host binary". The service DLL is hosted by svchost (the SCM service) and
// rundll32 (interactive/helper entries); every consumer that resolves or validates such a path
// must go through meshservice/runtime_host_contract.c, never a private "%System32%\<binary>"
// construction. This guard prevents a new local copy (and the validation drift it brings, e.g.
// a resolver that accepts a directory named rundll32.exe) from reappearing.
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

function read(relPath) { return fs.readFileSync(path.resolve(relPath), 'utf8'); }

// Returns the brace-matched body of the first function whose signature contains `marker`.
function functionBody(source, marker) {
    const at = source.indexOf(marker);
    if (at < 0) { return null; }
    let i = source.indexOf('{', at);
    if (i < 0) { return null; }
    let depth = 0;
    const start = i;
    for (; i < source.length; ++i) {
        if (source[i] === '{') { depth++; }
        else if (source[i] === '}') { depth--; if (depth === 0) { return source.substring(start, i + 1); } }
    }
    return null;
}

// Files that are allowed to construct a system host path, each a documented, distinct concern.
const ALLOWLIST = new Set([
    'meshservice/runtime_host_contract.c',   // the single source of truth (the resolver itself)
    'meshservice/runtime_host_contract.h',   // the binary-name constants
    'microstack/ILibProcessPipe.c',          // the sanctioned ASCII launch gate (reference behavior)
    'meshservice/service_binding_transaction.h', // legacy ImagePath / svchost -k netsvcs detection
    'meshservice/service_deployment.c'       // legacy install-dir svchost cleanup + process-name compare
]);

// Native sources to scan.
function listSources() {
    const roots = ['meshservice', 'microstack', 'microscript', 'meshcore'];
    const exts = new Set(['.c', '.cpp', '.h']);
    const skip = /(^|\/)(x64|Win32|obj|bin)(\/|$)/;
    const out = [];
    function walk(dir) {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            const rel = path.relative('.', full).split(path.sep).join('/');
            if (skip.test(rel)) { continue; }
            if (entry.isDirectory()) { walk(full); }
            else if (exts.has(path.extname(entry.name))) { out.push(rel); }
        }
    }
    for (const root of roots) { if (fs.existsSync(root)) { walk(root); } }
    return out;
}

function main() {
    const args = parseArgs(process.argv);

    const runtimeC = read('meshservice/runtime_host_contract.c');
    const kvmC = read('meshcore/KVM/Windows/kvm.c');
    const watchdogC = read('meshservice/service_watchdog.c');

    // A file "constructs a system host path" if it pairs a GetSystemDirectory call with a host
    // binary reference (literal name or the shared constant).
    const binaryRef = /rundll32\.exe|svchost\.exe|MESH_RUNTIME_HOST_BINARY_/;
    const offenders = [];
    for (const rel of listSources()) {
        if (ALLOWLIST.has(rel)) { continue; }
        const text = read(rel);
        if (/GetSystemDirectory[AW]?\s*\(/.test(text) && binaryRef.test(text)) { offenders.push(rel); }
    }

    const isExactBody = functionBody(runtimeC, 'MeshRuntimeHost_IsExactSystemBinaryPathW(const wchar_t* binaryName');
    const sysHostBody = functionBody(runtimeC, 'MeshRuntimeHost_GetSystemHostPathW(wchar_t* runtimeHostPath');
    const svcHostBody = functionBody(runtimeC, 'MeshRuntimeHost_GetServiceHostPathW(wchar_t* serviceHostPath');
    const kvmResolverBody = functionBody(kvmC, 'kvm_relay_resolve_runtime_host_pathW(WCHAR* output');
    const watchdogPredicateBody = functionBody(watchdogC, 'Helper_IsExactSystemRuntimeHostPathW(const WCHAR* value');

    const checks = {
        noUnsanctionedHostPathConstruction: offenders.length === 0,
        builderExists: runtimeC.includes('MeshRuntimeHost_BuildSystemBinaryPathW(const wchar_t* binaryName'),
        // The predicate must derive from the builder, so the two cannot diverge.
        predicateDerivesFromBuilder: isExactBody != null && isExactBody.includes('MeshRuntimeHost_BuildSystemBinaryPathW('),
        // The resolver must enforce an existing file (reject a directory) via requireExistingFile.
        builderRejectsDirectory: functionBody(runtimeC, 'MeshRuntimeHost_BuildSystemBinaryPathW(const wchar_t* binaryName') != null &&
            functionBody(runtimeC, 'MeshRuntimeHost_BuildSystemBinaryPathW(const wchar_t* binaryName').includes('MeshRuntimeHost_FileExistsW'),
        resolversAreThinWrappers: sysHostBody != null && sysHostBody.includes('MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_RUNDLL32_W') &&
            svcHostBody != null && svcHostBody.includes('MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_SVCHOST_W'),
        kvmDelegatesToSsot: kvmResolverBody != null && kvmResolverBody.includes('MeshRuntimeHost_GetSystemHostPathW(') &&
            !/GetSystemDirectory/.test(kvmResolverBody),
        watchdogDelegatesToSsot: watchdogPredicateBody != null && watchdogPredicateBody.includes('MeshRuntimeHost_IsExactSystemBinaryPathW(') &&
            !/GetSystemDirectory/.test(watchdogPredicateBody)
    };

    const report = { offenders, checks };
    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('Service host path SSOT contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'service_host_path_ssot_contract.txt'),
            'SUCCESS=true\nALLOWLIST=' + [...ALLOWLIST].join(',') + '\nOFFENDERS=' + offenders.join(',') + '\n');
    }

    process.stdout.write('Service host path SSOT: one resolver/predicate, wrappers thin, kvm+watchdog delegate, no unsanctioned construction\n');
}

main();
