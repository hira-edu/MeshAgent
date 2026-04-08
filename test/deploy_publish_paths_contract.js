const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

const deployPath = path.resolve(__dirname, '..', 'deploy.py');
const source = fs.readFileSync(deployPath, 'utf8');

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
    'Data Agents ({DATA_AGENTS})',
    'missing from {DATA_AGENTS}',
    '"data_agents_dir": DATA_AGENTS'
];

for (const snippet of requiredSnippets) {
    assert(source.includes(snippet), `missing snippet: ${snippet}`);
}

process.stdout.write(JSON.stringify({
    deployPath,
    checked: requiredSnippets.length
}, null, 2) + '\n');
