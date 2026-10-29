// Contract: the `preview` build channel differs from `production` in every
// machine-wide identity and labels itself visibly, while `production` output is
// byte-identical to the channel-less (default) generator invocation.
//
// Fails before the channel work (the generator rejects --channel); passes after.
// Hermetic: drives tools/generate_branding_assets.py against the committed
// branding_config.json template. See evidence/stage6/preview-agent-map.md.

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

function assert(condition, message) {
    if (!condition) { throw new Error(message); }
}

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error(`Unexpected argument: ${token}`); }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) { args[key] = true; }
        else { args[key] = value; i += 1; }
    }
    return args;
}

function findPython(repoRoot) {
    for (const candidate of ['python3', 'python']) {
        const result = childProcess.spawnSync(candidate, ['--version'], { cwd: repoRoot, encoding: 'utf8' });
        if (result.status === 0) { return candidate; }
    }
    throw new Error('python3 or python is required to generate branding assets for this contract');
}

function generate(repoRoot, python, configPath, outputHeader, channel) {
    const argv = [
        path.join(repoRoot, 'tools', 'generate_branding_assets.py'),
        '--repo-root', repoRoot,
        '--config', configPath,
        '--output-header', outputHeader
    ];
    if (channel != null) { argv.push('--channel', channel); }
    // The generator falls back to MESHAGENT_CHANNEL when no --channel is given, and a preview CI build sets it.
    // Each case here names its channel explicitly or means "unset", so the inherited variable is removed.
    const env = Object.assign({}, process.env);
    delete env.MESHAGENT_CHANNEL;
    return childProcess.spawnSync(python, argv, { cwd: repoRoot, encoding: 'utf8', env });
}

function generateOrThrow(repoRoot, python, configPath, outputHeader, channel) {
    const result = generate(repoRoot, python, configPath, outputHeader, channel);
    assert(result.status === 0,
        `branding generator (channel=${channel || 'default'}) failed: status=${result.status} stderr=${result.stderr || ''}`);
    assert(fs.existsSync(outputHeader), `generator did not write ${outputHeader}`);
    return fs.readFileSync(outputHeader, 'utf8');
}

// A generated #define's value, i.e. everything after the macro name on its line.
function defineValue(header, macro) {
    const re = new RegExp('^#define\\s+' + macro + '\\s+(.*)$', 'm');
    const match = header.match(re);
    assert(match, `generated header is missing #define ${macro}`);
    return match[1].trim();
}

// The string literal inside TEXT("...") or "...".
function stringValue(header, macro) {
    const raw = defineValue(header, macro);
    const textMatch = raw.match(/^TEXT\("(.*)"\)$/);
    if (textMatch) { return textMatch[1]; }
    const quoteMatch = raw.match(/^"(.*)"$/);
    assert(quoteMatch, `#define ${macro} is not a string literal: ${raw}`);
    return quoteMatch[1];
}

function stripTimestamp(header) {
    return header.split(/\r?\n/).filter((line) => !line.startsWith('/* Generated on:')).join('\n');
}

// Every machine-wide identity the map enumerates, as a generated branding macro.
const IDENTITY_MACROS = [
    'MESH_AGENT_SERVICE_FILE',          // SCM service key (and pipe/mutex/registry/firewall derive from it)
    'MESH_AGENT_SERVICE_NAME',          // service display name (visible)
    'MESH_AGENT_FILE_DESCRIPTION',      // service description (visible)
    'MESH_AGENT_PRODUCT_NAME',          // version resource / uninstall display (visible)
    'MESH_AGENT_INTERNAL_NAME',
    'MESH_AGENT_ORIGINAL_FILENAME',
    'MESH_AGENT_INSTALL_ROOT',
    'MESH_AGENT_LOG_DIRECTORY',
    'MESH_AGENT_BINARY_NAME',
    'MESH_AGENT_SERVICE_HOST_DLL',
    'MESH_AGENT_ARTIFACT_DB',
    'MESH_AGENT_ARTIFACT_CONFIG',
    'MESH_AGENT_ARTIFACT_LOG',
    'MESH_AGENT_PERSIST_TASK_NAME',
    'MESH_AGENT_SERVICE_RECOVERY_TASK_NAME'
];

// Macros whose value must visibly announce the preview agent.
const VISIBLE_MACROS = [
    'MESH_AGENT_SERVICE_NAME',
    'MESH_AGENT_FILE_DESCRIPTION',
    'MESH_AGENT_PRODUCT_NAME'
];

function main() {
    const args = parseArgs(process.argv);
    const repoRoot = path.resolve(__dirname, '..');
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const configPath = path.join(repoRoot, 'branding_config.json');
    const python = findPython(repoRoot);

    const outDir = evidenceDir
        ? (fs.mkdirSync(evidenceDir, { recursive: true }), evidenceDir)
        : fs.mkdtempSync(path.join(os.tmpdir(), 'preview-channel-'));

    const defaultHeaderPath = path.join(outDir, 'default.h');
    const prodHeaderPath = path.join(outDir, 'production.h');
    const previewHeaderPath = path.join(outDir, 'preview.h');

    const defaultHeader = generateOrThrow(repoRoot, python, configPath, defaultHeaderPath, null);
    const prodHeader = generateOrThrow(repoRoot, python, configPath, prodHeaderPath, 'production');
    const previewHeader = generateOrThrow(repoRoot, python, configPath, previewHeaderPath, 'preview');

    // 1. Production output is byte-identical whether the channel is omitted or
    //    stated explicitly (proves channel=production is the untouched code path).
    assert(stripTimestamp(defaultHeader) === stripTimestamp(prodHeader),
        'production output must be byte-identical with and without an explicit --channel production');

    // 2. Every mapped machine-wide identity differs between the channels.
    for (const macro of IDENTITY_MACROS) {
        const prod = stringValue(prodHeader, macro);
        const preview = stringValue(previewHeader, macro);
        assert(prod !== preview,
            `preview must differ from production in ${macro} (both are "${prod}")`);
    }

    // 3. Identity (non-visible) names carry the "2" suffix; production carries none.
    assert(stringValue(previewHeader, 'MESH_AGENT_SERVICE_FILE')
            === stringValue(prodHeader, 'MESH_AGENT_SERVICE_FILE') + '2',
        'preview SCM service key must be the production key plus the "2" suffix');
    assert(stringValue(previewHeader, 'MESH_AGENT_INSTALL_ROOT')
            === stringValue(prodHeader, 'MESH_AGENT_INSTALL_ROOT') + '2',
        'preview install root must be the production root plus the "2" suffix');
    assert(stringValue(previewHeader, 'MESH_AGENT_LOG_DIRECTORY')
            === stringValue(prodHeader, 'MESH_AGENT_INSTALL_ROOT') + '2/logs',
        'preview log directory must live under the suffixed install root');

    const stemSuffixMacros = {
        MESH_AGENT_BINARY_NAME: ['meshagent.exe', 'meshagent2.exe'],
        MESH_AGENT_SERVICE_HOST_DLL: ['meshsvc.dll', 'meshsvc2.dll'],
        MESH_AGENT_ARTIFACT_DB: ['meshagent.db', 'meshagent2.db'],
        MESH_AGENT_ARTIFACT_CONFIG: ['meshagent.conf', 'meshagent2.conf'],
        MESH_AGENT_ARTIFACT_LOG: ['meshagent.log', 'meshagent2.log']
    };
    for (const macro of Object.keys(stemSuffixMacros)) {
        const [expectedProd, expectedPreview] = stemSuffixMacros[macro];
        assert(stringValue(prodHeader, macro) === expectedProd,
            `production ${macro} must be "${expectedProd}" (got "${stringValue(prodHeader, macro)}")`);
        assert(stringValue(previewHeader, macro) === expectedPreview,
            `preview ${macro} must insert "2" before the extension (expected "${expectedPreview}")`);
    }

    // 4. Visible names announce the preview agent; production names never do.
    for (const macro of VISIBLE_MACROS) {
        const prod = stringValue(prodHeader, macro);
        const preview = stringValue(previewHeader, macro);
        assert(!/preview/i.test(prod), `production ${macro} must not be labelled preview (got "${prod}")`);
        assert(/preview/i.test(preview), `preview ${macro} must visibly say it is the preview agent (got "${preview}")`);
    }

    // 5. Nothing in the production header carries the identity or preview label
    //    (guards against the transform leaking into production).
    for (const macro of IDENTITY_MACROS) {
        const prod = stringValue(prodHeader, macro);
        assert(!/preview/i.test(prod), `production ${macro} must not contain "preview" (got "${prod}")`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        productionByteIdentical: true,
        identityMacrosChecked: IDENTITY_MACROS.length,
        sample: {
            production: {
                serviceKey: stringValue(prodHeader, 'MESH_AGENT_SERVICE_FILE'),
                installRoot: stringValue(prodHeader, 'MESH_AGENT_INSTALL_ROOT'),
                displayName: stringValue(prodHeader, 'MESH_AGENT_SERVICE_NAME')
            },
            preview: {
                serviceKey: stringValue(previewHeader, 'MESH_AGENT_SERVICE_FILE'),
                installRoot: stringValue(previewHeader, 'MESH_AGENT_INSTALL_ROOT'),
                displayName: stringValue(previewHeader, 'MESH_AGENT_SERVICE_NAME')
            }
        }
    };

    if (evidenceDir) {
        fs.writeFileSync(path.join(evidenceDir, 'preview_channel_identity_contract.json'),
            JSON.stringify(report, null, 2) + '\n');
    }
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

main();
