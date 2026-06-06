const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

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
    '"data_agents_dir": DATA_AGENTS'
];

for (const snippet of requiredSnippets) {
    assert(source.includes(snippet), `missing snippet: ${snippet}`);
}

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

process.stdout.write(JSON.stringify({
    deployPath,
    checked: requiredSnippets.length
}, null, 2) + '\n');
