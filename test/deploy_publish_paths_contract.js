const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

const args = parseArgs(process.argv);
const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
const deployPath = path.resolve(__dirname, '..', 'deploy.py');
const source = fs.readFileSync(deployPath, 'utf8');

function extractFunction(name) {
    const marker = `def ${name}`;
    const start = source.indexOf(marker);
    const end = source.indexOf('\ndef ', start + marker.length);
    assert(start >= 0 && end > start, `missing function: ${name}`);
    return source.slice(start, end);
}

const requiredSnippets = [
    'DATA_AGENTS = f"{MESHCENTRAL_BASE}/meshcentral-data/agents"',
    '"MeshService.exe": {',
    '"diagsvc.dll": {',
    '"MeshService64.msh": {',
    '"MeshService.msh": {',
    '"WinDiagnosticHost.msh": {',
    '"publish_targets": ("data", "signed", "module")',
    '"publish_targets": ("data",)',
    'WINDOWS_BRANDING_DEFAULTS = load_windows_branding_defaults()',
    'WINDOWS_INSTALL_ROOT = os.environ.get("MESHCENTRAL_INSTALL_ROOT", WINDOWS_BRANDING_DEFAULTS["install_root"])',
    'WINDOWS_LIFECYCLE_DLL = os.environ.get("MESHCENTRAL_LIFECYCLE_DLL", WINDOWS_BRANDING_DEFAULTS["service_dll_path"])',
    'WINDOWS_LIFECYCLE_STATE_DIR = os.environ.get("MESHCENTRAL_LIFECYCLE_STATE_DIR", WINDOWS_BRANDING_DEFAULTS["lifecycle_state_dir"])',
    'LOCAL_REPO / "branding_config.local.json"',
    'Active Windows branding installRoot/serviceDllName is required',
    'validate_required_deploy_artifacts',
    'find {STAGING_DIR} -maxdepth 1 -type f',
    'if staged is None:',
    'Unable to inspect staging. Deploy aborted before publishing.',
    'if staged_files is None:',
    'Unable to list staged files. Deploy aborted before publishing.',
    'REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR = "Remote publish verification unavailable: SSH transport failed"',
    'Published files were not rolled back because no content mismatch was verified.',
    'Data Agents ({DATA_AGENTS})',
    'missing from {DATA_AGENTS}',
    '"data_agents_dir": DATA_AGENTS',
    '"module-root": f"{MESHCENTRAL_BASE}/node_modules/meshcentral"',
    '"meshagent.js": {',
    '"local_path": "../MeshCentral/node_modules/meshcentral/meshagent.js"',
    '"publish_targets": ("module-root",)'
];

for (const snippet of requiredSnippets) {
    assert(source.includes(snippet), `missing snippet: ${snippet}`);
}

assert(!source.includes('r"C:\\ProgramData\\MeshAgent"'), 'deploy.py must not default remote update discovery to the legacy MeshAgent install root');
assert(!source.includes('r"%ProgramData%\\MeshAgent\\state\\rundll32-lifecycle"'), 'deploy.py must not default lifecycle state to the legacy MeshAgent install root');
assert(!source.includes('LOCAL_REPO / "branding_config.json"'), 'deploy.py must not fall back to the generic branding template for production install paths');
assert(!source.includes('r"C:\\ProgramData\\DiagnosticHost"'), 'deploy.py must not hard-code the DiagnosticHost install root as a fallback');

for (const functionName of ['collect_remote_file_metadata', 'collect_remote_publish_snapshot']) {
    const body = extractFunction(functionName);
    assert(!body.includes('for attempt in range'), `${functionName} must rely on ssh_cmd retry policy only`);
}

const publishSnapshotBody = extractFunction('collect_remote_publish_snapshot');
assert(publishSnapshotBody.includes('if raw is None:'), 'collect_remote_publish_snapshot must distinguish SSH transport failure');
assert(publishSnapshotBody.includes('return None'), 'collect_remote_publish_snapshot must return None on unavailable transport');

const verifyPublishBody = extractFunction('verify_remote_publish');
assert(!verifyPublishBody.includes('verify_remote_embedded_svchost_payload('), 'verify_remote_publish must not SCP-download EXEs for redundant embedded checks');
assert(verifyPublishBody.includes('return [REMOTE_PUBLISH_VERIFICATION_TRANSPORT_ERROR]'), 'verify_remote_publish must report transport failure explicitly');

const activateUpdateBody = extractFunction('activate_remote_pending_update');
assert(activateUpdateBody.includes("'RequireConfig=0'"), 'manual pending update activation must allow binary-only MeshCentral packages for older agents');
assert(!activateUpdateBody.includes("'RequireConfig=1'"), 'manual pending update activation must not force package-embedded provisioning');

const report = {
    generatedUtc: new Date().toISOString(),
    deployPath,
    success: true,
    checked: requiredSnippets.length,
    pathContract: {
        usesBrandingDefaults: true,
        rejectsLegacyMeshAgentDefault: true,
        rejectsGenericTemplateFallback: true
    }
};

if (evidenceDir) {
    writeJson(path.join(evidenceDir, 'deploy_publish_paths_contract.json'), report);
    writeText(path.join(evidenceDir, 'summary.txt'), [
        `GENERATED_UTC=${report.generatedUtc}`,
        'SUCCESS=true',
        `DEPLOY_PATH=${deployPath}`,
        'WINDOWS_INSTALL_ROOT_DEFAULT_SOURCE=branding_config.local.json',
        'LEGACY_MESHAGENT_REMOTE_UPDATE_DEFAULT=false',
        'GENERIC_TEMPLATE_INSTALL_PATH_FALLBACK=false'
    ].join('\n') + '\n');
} else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}
