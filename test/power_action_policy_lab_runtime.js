// Lab-state half of the host power action policy check. It needs files that are not tracked:
// branding_config.local.json (local identities, never committed) and the generated
// meshcore/generated/meshagent_branding.h (gitignored, written by the branding generator).
// The tracked-source half is test/power_action_policy_contract.js, which passes on a clean clone.
// Run from the MeshAgent root of a configured lab checkout.
const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

// Every input is required: a missing or empty file fails the test and says what it was for.
function readRepoFile(repoRoot, relativePath, purpose) {
    const fullPath = path.join(repoRoot, relativePath);
    let text;
    try {
        text = fs.readFileSync(fullPath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`required lab input missing: ${fullPath} (${purpose})`, { cause: error });
        }
        throw error;
    }
    assert(text.trim().length > 0, `required lab input is empty: ${fullPath} (${purpose})`);
    return text;
}

function main() {
    const repoRoot = process.cwd();
    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidenceDir = evidenceIndex >= 0 ? path.resolve(process.argv[evidenceIndex + 1]) : null;

    const generatedBranding = readRepoFile(repoRoot, path.join('meshcore', 'generated', 'meshagent_branding.h'),
        'generated branding header for the current lab build; run tools/generate_branding_assets.py or build first');
    const localConfig = JSON.parse(readRepoFile(repoRoot, 'branding_config.local.json',
        'current lab branding configuration; local file, never committed'));

    const checks = {
        generatedBrandingCarriesCurrentPolicy:
            /#define\s+MESH_AGENT_ALLOW_HOST_POWER_ACTIONS\s+1/.test(generatedBranding),
        currentLabConfigAllowsHostPowerActions:
            localConfig.advanced.allowHostPowerActions === true
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `power action policy lab runtime failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            generatedBranding: path.join(repoRoot, 'meshcore', 'generated', 'meshagent_branding.h'),
            localConfig: path.join(repoRoot, 'branding_config.local.json')
        },
        checks
    };

    if (evidenceDir) {
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'power_action_policy_lab_runtime.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'power_action_policy_lab_runtime_summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            'CURRENT_ALLOW_HOST_POWER_ACTIONS=true',
            'HOST_POWER_ACTIONS=enabled_by_branding'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
