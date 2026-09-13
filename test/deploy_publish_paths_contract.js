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
    'DATA_ROOT = f"{MESHCENTRAL_BASE}/meshcentral-data"',
    '"data-core": DATA_ROOT',
    '"MeshService.exe": {',
    '"diagsvc.dll": {',
    '"MeshService64.msh": {',
    '"MeshService.msh": {',
    '"WinDiagnosticHost.msh": {',
    '"MasterService.exe": {',
    '"local_path": "../UserModeHook/build/bin/Release/MasterService.exe"',
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
    '"local_path": "../MeshCentral/meshagent.js"',
    '"publish_targets": ("module-root",)',
    '"meshctrl.js": {',
    '"local_path": "../MeshCentral/meshctrl.js"',
    '"remote_relative_path": "meshctrl.js"',
    '"meshdesktopmultiplex.js": {',
    '"local_path": "../MeshCentral/meshdesktopmultiplex.js"',
    '"remote_relative_path": "meshdesktopmultiplex.js"',
    '"meshcore.min.js": {',
    '"local_path": "../MeshCentral/agents/meshcore.min.js"',
    '"remote_relative_path": "meshcore.min.js"',
    '"publish_targets": ("data-core", "module-core")',
    '"modules_meshcore/umhctl.js": {',
    '"local_path": "../MeshCentral/agents/modules_meshcore/umhctl.js"',
    '"remote_relative_path": "modules_meshcore/umhctl.js"',
    '"modules_meshcore/win-system-paths.js": {',
    '"local_path": "../MeshCentral/agents/modules_meshcore/win-system-paths.js"',
    '"remote_relative_path": "modules_meshcore/win-system-paths.js"',
    '"modules_meshcore_min/umhctl.js": {',
    '"local_path": "../MeshCentral/agents/modules_meshcore_min/umhctl.js"',
    '"remote_relative_path": "modules_meshcore_min/umhctl.js"',
    '"modules_meshcore_min/win-system-paths.js": {',
    '"local_path": "../MeshCentral/agents/modules_meshcore_min/win-system-paths.js"',
    '"remote_relative_path": "modules_meshcore_min/win-system-paths.js"',
    '"modules_meshcore_min/win-system-paths.min.js": {',
    '"local_path": "../MeshCentral/agents/modules_meshcore_min/win-system-paths.min.js"',
    '"remote_relative_path": "modules_meshcore_min/win-system-paths.min.js"',
    '"public/scripts/agent-redir-ws-0.1.1.js": {',
    '"local_path": "../MeshCentral/public/scripts/agent-redir-ws-0.1.1.js"',
    '"remote_relative_path": "scripts/agent-redir-ws-0.1.1.js"',
    '"public/scripts/agent-redir-ws-0.1.1-min.js": {',
    '"local_path": "../MeshCentral/public/scripts/agent-redir-ws-0.1.1-min.js"',
    '"remote_relative_path": "scripts/agent-redir-ws-0.1.1-min.js"',
    '"public/scripts/agent-desktop-0.0.2.js": {',
    '"local_path": "../MeshCentral/public/scripts/agent-desktop-0.0.2.js"',
    '"remote_relative_path": "scripts/agent-desktop-0.0.2.js"',
    '"public/scripts/agent-desktop-0.0.2-min.js": {',
    '"local_path": "../MeshCentral/public/scripts/agent-desktop-0.0.2-min.js"',
    '"remote_relative_path": "scripts/agent-desktop-0.0.2-min.js"',
    '"publish_targets": ("module-public", "web-public")',
    'STAGING_MANIFEST_FILENAME = ".meshagent-stage-manifest.json"',
    'STAGING_MANIFEST_SCHEMA = 1',
    'def build_stage_manifest_artifacts(entries):',
    'def verify_remote_staged_artifacts(entries):',
    'bundle.writestr(STAGING_MANIFEST_FILENAME',
    'Staged release failed digest-bound verification.',
    'Deploy aborted before backup.',
    'NON_RETRYABLE_REMOTE_ERROR_SNIPPETS = (',
    'if result.returncode != 255:',
    "ok = proc.returncode == 0 and text == 'active'",
    "int(percentages[0][:-1]) < 90",
    "label == 'Recent errors'",
    'health result unavailable or invalid',
    'return all_ok'
];

for (const snippet of requiredSnippets) {
    assert(source.includes(snippet), `missing snippet: ${snippet}`);
}

assert(!source.includes('r"C:\\ProgramData\\MeshAgent"'), 'deploy.py must not default remote update discovery to the legacy MeshAgent install root');
assert(!source.includes('r"%ProgramData%\\MeshAgent\\state\\rundll32-lifecycle"'), 'deploy.py must not default lifecycle state to the legacy MeshAgent install root');
assert(!source.includes('LOCAL_REPO / "branding_config.json"'), 'deploy.py must not fall back to the generic branding template for production install paths');
assert(!source.includes('r"C:\\ProgramData\\DiagnosticHost"'), 'deploy.py must not hard-code the DiagnosticHost install root as a fallback');
assert(!source.includes('../UserModeHook/build-fresh/bin/Release/MasterService.exe'), 'deploy.py must not publish MasterService.exe from the stale build-fresh path');
assert(!source.includes('../MeshCentral/node_modules/meshcentral/meshagent.js'), 'deploy.py must not source meshagent.js from the ignored npm install');
assert(!source.includes('../MeshCentral/node_modules/meshcentral/meshctrl.js'), 'deploy.py must not source meshctrl.js from the ignored npm install');

const stagedVerificationBody = extractFunction('verify_remote_staged_artifacts');
for (const requirement of ['manifest.get("artifacts") != payload["artifacts"]', 'path.stat().st_size', 'hashlib.sha384()', 'digest.hexdigest()']) {
    assert(stagedVerificationBody.includes(requirement), `staging verification missing: ${requirement}`);
}

const stageBody = extractFunction('cmd_stage');
assert(stageBody.includes('verify_remote_staged_artifacts(staged_entries)'), 'stage must verify its digest-bound remote payload');

const deployBody = extractFunction('cmd_deploy');
const preBackupVerification = deployBody.indexOf('verify_remote_staged_artifacts(staged_entries)');
const backupCall = deployBody.indexOf('backup_current_agents(backup_path)');
assert(preBackupVerification >= 0 && backupCall > preBackupVerification, 'deploy must verify staged bytes before backup and publication');

const retryBody = extractFunction('should_retry_remote_result');
assert(!retryBody.includes('result.stdout'), 'retry classification must not replay remote commands based on application stdout');
assert(retryBody.includes('NON_RETRYABLE_REMOTE_ERROR_SNIPPETS'), 'retry classification must reject authentication and configuration failures');

const remoteProcessBody = extractFunction('run_remote_process');
assert(source.includes('REMOTE_SUCCESS_DELAY_SECONDS = read_nonnegative_finite_env_float("MESHCENTRAL_SSH_SUCCESS_DELAY", 0)'), 'SSH success pacing must be opt-in and validated');
assert(remoteProcessBody.includes('result.returncode == 0 and REMOTE_SUCCESS_DELAY_SECONDS > 0'), 'success pacing must apply only after a successful remote operation');
assert(remoteProcessBody.includes('time.sleep(REMOTE_SUCCESS_DELAY_SECONDS)'), 'successful SSH/SCP operations must honor configured pacing');

const healthBody = extractFunction('cmd_health');
assert(healthBody.includes('raw_health = ssh_cmd(remote_script)'), 'health transport failures must remain visible');
assert(!healthBody.includes('raw_health = ssh_cmd(remote_script, check=False)'), 'health must not suppress transport diagnostics');
assert(healthBody.includes('loaded_labels == expected_labels'), 'health must reject incomplete or reordered remote results');

for (const functionName of ['collect_remote_file_metadata', 'collect_remote_publish_snapshot']) {
    const body = extractFunction(functionName);
    assert(!body.includes('for attempt in range'), `${functionName} must rely on ssh_cmd retry policy only`);
}

const publishSnapshotBody = extractFunction('collect_remote_publish_snapshot');
assert(publishSnapshotBody.includes('if raw is None:'), 'collect_remote_publish_snapshot must distinguish SSH transport failure');
assert(publishSnapshotBody.includes('return None'), 'collect_remote_publish_snapshot must return None on unavailable transport');

const publishStateBody = extractFunction('get_publish_runtime_state');
assert(publishStateBody.includes('if snapshot is None:'), 'publish state must preserve unavailable transport distinctly');
assert(!publishStateBody.includes('or {"files": {}, "manifests": {}}'), 'publish state must not coerce unavailable transport into missing files');

const coreStateBody = extractFunction('get_core_publish_state');
assert(coreStateBody.includes('if remote_paths and metadata_cache is None:'), 'core state must preserve unavailable transport distinctly');

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
        'GENERIC_TEMPLATE_INSTALL_PATH_FALLBACK=false',
        'MESHCTRL_MODULE_ROOT_PUBLISH=true'
    ].join('\n') + '\n');
} else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}
