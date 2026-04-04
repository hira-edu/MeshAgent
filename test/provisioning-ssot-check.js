const fs = require('fs');
const path = require('path');
const {
    parseKvText,
    extractEmbeddedMsh,
    buildIdentityFromKv,
    buildIdentityFromBranding,
    compareIdentity
} = require('./lib/provisioning_identity');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; i += 2) {
        const key = argv[i];
        const value = argv[i + 1];
        if (!key || !key.startsWith('--') || value == null) {
            throw new Error('Expected --key value pairs.');
        }
        args[key.substring(2)] = value;
    }
    return args;
}

function requireArg(args, key) {
    const value = args[key];
    if (!value) {
        throw new Error(`Missing --${key}`);
    }
    return path.resolve(value);
}

function optionalArg(args, key) {
    return args[key] ? path.resolve(args[key]) : null;
}

function readUtf8(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = requireArg(args, 'evidence');
    ensureDir(evidenceDir);

    const brandingPath = requireArg(args, 'branding-json');
    const meshcentralMshPath = requireArg(args, 'meshcentral-msh');
    const packageExePath = optionalArg(args, 'package-exe');
    const packageMshPath = optionalArg(args, 'package-msh');

    const sources = [];
    const comparisons = [];

    const brandingConfig = JSON.parse(readUtf8(brandingPath));
    const brandingIdentity = buildIdentityFromBranding('branding_json', brandingConfig);
    sources.push({ type: 'branding_json', path: brandingPath, identity: brandingIdentity });

    const meshcentralIdentity = buildIdentityFromKv('meshcentral_msh', parseKvText(readUtf8(meshcentralMshPath)));
    sources.push({ type: 'meshcentral_msh', path: meshcentralMshPath, identity: meshcentralIdentity });
    comparisons.push(compareIdentity(brandingIdentity, meshcentralIdentity));

    if (packageMshPath && fs.existsSync(packageMshPath)) {
        const packageMshIdentity = buildIdentityFromKv('package_sidecar_msh', parseKvText(readUtf8(packageMshPath)));
        sources.push({ type: 'package_sidecar_msh', path: packageMshPath, identity: packageMshIdentity });
        comparisons.push(compareIdentity(meshcentralIdentity, packageMshIdentity));
        comparisons.push(compareIdentity(brandingIdentity, packageMshIdentity));
    }

    if (packageExePath && fs.existsSync(packageExePath)) {
        try {
            const embeddedText = extractEmbeddedMsh(packageExePath);
            const embeddedIdentity = buildIdentityFromKv('package_embedded_msh', parseKvText(embeddedText));
            const embeddedArtifact = path.join(evidenceDir, 'package_embedded_msh.txt');
            fs.writeFileSync(embeddedArtifact, embeddedText);
            sources.push({ type: 'package_embedded_msh', path: packageExePath, extractedPath: embeddedArtifact, identity: embeddedIdentity });
            comparisons.push(compareIdentity(meshcentralIdentity, embeddedIdentity));
            comparisons.push(compareIdentity(brandingIdentity, embeddedIdentity));
        } catch (error) {
            sources.push({
                type: 'package_embedded_msh',
                path: packageExePath,
                error: error instanceof Error ? error.message : String(error)
            });
        }
    }

    const success = comparisons.every((comparison) => comparison.match);
    const report = {
        generatedUtc: new Date().toISOString(),
        success,
        sources,
        comparisons
    };

    fs.writeFileSync(path.join(evidenceDir, 'provisioning_ssot_report.json'), JSON.stringify(report, null, 2));

    const summaryLines = [
        `GENERATED_UTC=${report.generatedUtc}`,
        `SUCCESS=${success}`,
        `BRANDING_JSON=${brandingPath}`,
        `MESHCENTRAL_MSH=${meshcentralMshPath}`
    ];
    if (packageExePath) { summaryLines.push(`PACKAGE_EXE=${packageExePath}`); }
    if (packageMshPath) { summaryLines.push(`PACKAGE_MSH=${packageMshPath}`); }
    for (const comparison of comparisons) {
        summaryLines.push(`COMPARE=${comparison.left}=>${comparison.right} MATCH=${comparison.match}`);
        for (const mismatch of comparison.mismatches) {
            summaryLines.push(`MISMATCH=${comparison.left}=>${comparison.right} FIELD=${mismatch.field} LEFT=${JSON.stringify(mismatch.left)} RIGHT=${JSON.stringify(mismatch.right)}`);
        }
    }
    fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), summaryLines.join('\n') + '\n');

    if (!success) {
        process.exitCode = 1;
    }
}

main();
