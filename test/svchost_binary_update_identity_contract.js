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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunction(source, signature, nextSignature) {
    let start = -1;
    let cursor = 0;
    while (cursor < source.length) {
        const candidate = source.indexOf(signature, cursor);
        if (candidate < 0) { break; }
        const afterSignature = source.slice(candidate + signature.length, candidate + signature.length + 16);
        if (/^\s*\{/.test(afterSignature)) {
            start = candidate;
            break;
        }
        cursor = candidate + signature.length;
    }
    const end = start >= 0 ? source.indexOf(nextSignature, start + signature.length) : -1;
    return (start >= 0 && end > start) ? source.slice(start, end) : '';
}

function normalize(source) {
    return source.replace(/\s+/g, ' ');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const installerPath = path.resolve('meshservice', 'stealth_installer.c');
    const source = fs.readFileSync(installerPath, 'utf8');

    const installedProvisioningBlock = extractFunction(
        source,
        'static BOOL Stealth_InstalledProvisioningHealthy(const StealthInstallPaths* paths, wchar_t* liveMshPath, size_t liveMshPathCch)',
        '\nstatic BOOL Stealth_BuildSiblingPathWithExtension');
    const prepareBlock = extractFunction(
        source,
        'static BOOL Stealth_PrepareUpdateTransaction(const StealthInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, StealthUpdateTransaction* tx)',
        '\nstatic BOOL Stealth_BackupUpdateTransaction');
    const convergedBlock = extractFunction(
        source,
        'static BOOL Stealth_IsPrimaryLifecycleConverged(const StealthLifecycleDiscovery* discovery, BOOL requirePendingClear)',
        '\nstatic BOOL Stealth_IsPrimaryLifecycleHealthy');
    const discoveryBlock = extractFunction(
        source,
        'static BOOL Stealth_DiscoverCurrentState(StealthLifecycleDiscovery* discovery)',
        '\nstatic BOOL Stealth_RunLifecycleOperation');
    const runBlock = extractFunction(
        source,
        'static BOOL Stealth_RunLifecycleOperation(StealthLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig)',
        '\nBOOL Stealth_PerformCompleteInstallation');

    assert(installedProvisioningBlock.length > 0, 'unable to isolate Stealth_InstalledProvisioningHealthy');
    assert(prepareBlock.length > 0, 'unable to isolate Stealth_PrepareUpdateTransaction');
    assert(convergedBlock.length > 0, 'unable to isolate Stealth_IsPrimaryLifecycleConverged');
    assert(discoveryBlock.length > 0, 'unable to isolate Stealth_DiscoverCurrentState');
    assert(runBlock.length > 0, 'unable to isolate Stealth_RunLifecycleOperation');

    const normalizedConverged = normalize(convergedBlock);
    const normalizedDiscovery = normalize(discoveryBlock);
    const normalizedRun = normalize(runBlock);

    const checks = {
        installedProvisioningFallsBackToDatastoreNodeId:
            installedProvisioningBlock.includes('configHealthy && mshHealthy') &&
            installedProvisioningBlock.includes('Stealth_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL)'),
        prepareRecordsInstalledDatastoreIdentity:
            prepareBlock.includes('installedDbIdentityPresent = Stealth_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL);'),
        prepareAllowsMissingConfWithDatastoreIdentity:
            prepareBlock.includes('Binary-only update retaining datastore identity without installed provisioning .conf') &&
            prepareBlock.includes('if (!installedDbIdentityPresent)') &&
            prepareBlock.includes('Binary-only update rejected because installed provisioning .conf is unavailable or invalid'),
        prepareAllowsMissingMshWithDatastoreIdentity:
            prepareBlock.includes('Binary-only update retaining datastore identity without installed provisioning .msh') &&
            prepareBlock.includes('Binary-only update rejected because installed provisioning .msh is unavailable or invalid'),
        convergenceUsesConfigOrDatastoreIdentity:
            convergedBlock.includes('const BOOL identityHealthy = (discovery->configKeysValid ||') &&
            convergedBlock.includes('(discovery->dbExists && discovery->nodeIdPresent))') &&
            normalizedConverged.includes('discovery->dllDaclValid && identityHealthy'),
        convergenceDoesNotRequireConfFile:
            !normalizedConverged.includes('discovery->confExists &&'),
        discoveryClassifiesDatastoreIdentityAsHealthy:
            discoveryBlock.includes('const BOOL identityHealthy = (discovery->configKeysValid ||') &&
            discoveryBlock.includes('(discovery->dbExists && discovery->nodeIdPresent))') &&
            normalizedDiscovery.includes('discovery->exeDaclValid && identityHealthy'),
        discoveryDoesNotRequireConfFileForHealthyState:
            !normalizedDiscovery.includes('discovery->confExists && discovery->installRootDaclValid'),
        lifecycleKeepsBinaryOnlyUpdateAsUpdate:
            normalizedRun.includes('request == STEALTH_LIFECYCLE_REQUEST_UPDATE && !requireConfig && plan.action == STEALTH_LIFECYCLE_ACTION_REPAIR && discovery.dbExists && discovery.nodeIdPresent') &&
            runBlock.includes('Binary-only update preserving datastore identity') &&
            normalizedRun.includes('plan.action = STEALTH_LIFECYCLE_ACTION_UPDATE;'),
        updateActionStillUsesUpdateFlow:
            normalizedRun.includes('ok = Stealth_ApplyUpdateFlow(sourceExePath, sourceDllPath, TRUE, requireConfig);')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        installerPath,
        checks
    };

    if (evidenceDir) {
        ensureDir(evidenceDir);
        fs.writeFileSync(path.join(evidenceDir, 'svchost_binary_update_identity_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
