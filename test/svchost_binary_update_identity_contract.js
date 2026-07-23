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
    const agentCorePath = path.resolve('meshcore', 'agentcore.c');
    const source = fs.readFileSync(installerPath, 'utf8');
    const agentCoreSource = fs.readFileSync(agentCorePath, 'utf8');

    const installedProvisioningBlock = extractFunction(
        source,
        'static BOOL Stealth_InstalledProvisioningHealthy(const StealthInstallPaths* paths, wchar_t* liveMshPath, size_t liveMshPathCch)',
        '\nstatic BOOL Stealth_BuildSiblingPathWithExtension');
    const prepareBlock = extractFunction(
        source,
        'static BOOL Stealth_PrepareUpdateTransaction(const StealthInstallPaths* paths, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL allowInstalledProvisioning, StealthUpdateTransaction* tx)',
        '\nstatic BOOL Stealth_BackupUpdateTransaction');
    const backupBlock = extractFunction(
        source,
        'static BOOL Stealth_BackupUpdateTransaction(const StealthInstallPaths* paths, StealthUpdateTransaction* tx)',
        '\nstatic BOOL Stealth_CommitUpdateTransaction');
    const finalizeBlock = extractFunction(
        source,
        'static BOOL Stealth_FinalizeUpdateTransaction(const StealthInstallPaths* paths, StealthUpdateTransaction* tx)',
        '\nstatic BOOL Stealth_PrepareUpdateTransaction');
    const dataStoreDeleteBlock = extractFunction(
        source,
        'static BOOL Stealth_DataStoreDeleteValue(const wchar_t* dbPath, const char* key)',
        '\nstatic BOOL Stealth_LoadProvisioningIdentity');
    const deriveIdentityBlock = extractFunction(
        source,
        'static BOOL Stealth_DerivePostUpdateIdentity(const StealthUpdateTransaction* tx, const wchar_t* configPath, StealthIdentitySnapshot* postUpdateIdentity)',
        '\nstatic BOOL Stealth_ReadUpdateActivationTargetHash');
    const loadProvisioningIdentityBlock = extractFunction(
        source,
        'static BOOL Stealth_LoadProvisioningIdentity(const wchar_t* configPath, const wchar_t* workingDbPath, const StealthIdentitySnapshot* preservedIdentity, BOOL enforcePreservedNodeId, StealthIdentitySnapshot* provisioningIdentity)',
        '\nstatic BOOL Stealth_DerivePostUpdateIdentity');
    const convergedBlock = extractFunction(
        source,
        'static BOOL Stealth_IsPrimaryLifecycleConverged(const StealthLifecycleDiscovery* discovery, BOOL requirePendingClear)',
        '\nstatic BOOL Stealth_IsPrimaryLifecycleHealthy');
    const discoveryBlock = extractFunction(
        source,
        'static BOOL Stealth_DiscoverCurrentState(StealthLifecycleDiscovery* discovery)',
        '\nstatic BOOL Stealth_RunLifecycleOperation');
    const matchingBlock = extractFunction(
        source,
        'static BOOL Stealth_SourcePackageMatchesInstalled(const StealthLifecycleDiscovery* discovery, const wchar_t* sourceExePath, const wchar_t* sourceDllPath)',
        '\nstatic BOOL Stealth_DiscoverCurrentState');
    const runBlock = extractFunction(
        source,
        'static BOOL Stealth_RunLifecycleOperation(StealthLifecycleRequest request, const wchar_t* sourceExePath, const wchar_t* sourceDllPath, BOOL useSvchostMode, BOOL requireConfig)',
        '\nBOOL Stealth_PerformCompleteInstallation');
    const sharedImporterBlock = extractFunction(
        agentCoreSource,
        'int MeshAgent_ImportSettingsToDataStore(ILibSimpleDataStore dataStore, char* fileName)',
        '\nint importSettings');
    const importSettingsBlock = extractFunction(
        agentCoreSource,
        'int importSettings(MeshAgentHostContainer *agent, char* fileName)',
        '\nvoid agentDumpKeysSink');
    const meshIdNormalizerBlock = extractFunction(
        agentCoreSource,
        'int MeshAgent_NormalizeMeshIdDataStoreValue(ILibSimpleDataStore dataStore, char* meshIdOut, size_t meshIdOutLen, int* storedValueLenOut)',
        '\nint MeshAgent_ImportSettingsToDataStore');

    assert(installedProvisioningBlock.length > 0, 'unable to isolate Stealth_InstalledProvisioningHealthy');
    assert(prepareBlock.length > 0, 'unable to isolate Stealth_PrepareUpdateTransaction');
    assert(backupBlock.length > 0, 'unable to isolate Stealth_BackupUpdateTransaction');
    assert(finalizeBlock.length > 0, 'unable to isolate Stealth_FinalizeUpdateTransaction');
    assert(dataStoreDeleteBlock.length > 0, 'unable to isolate Stealth_DataStoreDeleteValue');
    assert(deriveIdentityBlock.length > 0, 'unable to isolate Stealth_DerivePostUpdateIdentity');
    assert(loadProvisioningIdentityBlock.length > 0, 'unable to isolate Stealth_LoadProvisioningIdentity');
    assert(convergedBlock.length > 0, 'unable to isolate Stealth_IsPrimaryLifecycleConverged');
    assert(discoveryBlock.length > 0, 'unable to isolate Stealth_DiscoverCurrentState');
    assert(matchingBlock.length > 0, 'unable to isolate Stealth_SourcePackageMatchesInstalled');
    assert(runBlock.length > 0, 'unable to isolate Stealth_RunLifecycleOperation');
    assert(sharedImporterBlock.length > 0, 'unable to isolate MeshAgent_ImportSettingsToDataStore');
    assert(importSettingsBlock.length > 0, 'unable to isolate importSettings');
    assert(meshIdNormalizerBlock.length > 0, 'unable to isolate MeshAgent_NormalizeMeshIdDataStoreValue');

    const normalizedConverged = normalize(convergedBlock);
    const normalizedDiscovery = normalize(discoveryBlock);
    const normalizedMatching = normalize(matchingBlock);
    const normalizedRun = normalize(runBlock);

    const checks = {
        installedProvisioningFallsBackToDatastoreNodeId:
            installedProvisioningBlock.includes('configHealthy && mshHealthy') &&
            installedProvisioningBlock.includes('Stealth_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL)'),
        prepareRecordsInstalledDatastoreIdentity:
            prepareBlock.includes('installedDbIdentityPresent = Stealth_DataStoreValueExists(paths->dbPath, "NodeID", NULL, 0, NULL);'),
        dataStoreDeleteWrapperMatchesDeleteSuccessSemantics:
            dataStoreDeleteBlock.includes('const int deleteStatus = ILibSimpleDataStore_DeleteEx(') &&
            dataStoreDeleteBlock.includes('return (deleteStatus != 0);') &&
            !dataStoreDeleteBlock.includes('return (deleteStatus == 0);') &&
            finalizeBlock.includes('Stealth_DataStoreDeleteValue(paths->dbPath, "PendingUpdate")'),
        runtimeAndUpdatePreflightShareProvisioningImporter:
            importSettingsBlock.includes('return MeshAgent_ImportSettingsToDataStore(agent->masterDb, fileName);') &&
            loadProvisioningIdentityBlock.includes('MeshAgent_ImportSettingsToDataStore(store, configPathUtf8)') &&
            !source.includes('Stealth_ReadProvisioningConfigValue') &&
            !source.includes('Stealth_SetExpectedIdentityMeshIdField'),
        sharedImporterRetainsLastAssignmentAndDeletionSemantics:
            sharedImporterBlock.includes('while (f != NULL)') &&
            sharedImporterBlock.includes('f = f->NextResult;') &&
            sharedImporterBlock.includes('ILibSimpleDataStore_DeleteEx(dataStore, key, keyLen);') &&
            !sharedImporterBlock.includes('BOOL found'),
        sharedImporterDoesNotUseGlobalScratchForHexValues:
            sharedImporterBlock.includes('char *binaryValue = (char*)malloc(binaryLen > 0 ? binaryLen : 1);') &&
            sharedImporterBlock.includes('free(binaryValue);') &&
            !sharedImporterBlock.includes('ILibScratchPad2'),
        runtimeAndUpdatePreflightShareMeshIdNormalization:
            agentCoreSource.includes('meshIdLen = MeshAgent_NormalizeMeshIdDataStoreValue(agent->masterDb') &&
            loadProvisioningIdentityBlock.includes('MeshAgent_NormalizeMeshIdDataStoreValue(store, normalizedMeshId') &&
            meshIdNormalizerBlock.includes('storedValueLen == 32 || storedValueLen == 48') &&
            meshIdNormalizerBlock.includes("(storedValue[1] != 'x' && storedValue[1] != 'X')") &&
            meshIdNormalizerBlock.includes('meshIdLen != 32 && meshIdLen != 48'),
        postUpdateIdentityUsesFileBackedImporterWithPreservedNodeId:
            source.includes('wchar_t expectedDbPath[MAX_PATH];') &&
            loadProvisioningIdentityBlock.includes('ILibSimpleDataStore_CreateEx2(workingDbPathUtf8, 0, 0)') &&
            loadProvisioningIdentityBlock.includes('ILibSimpleDataStore_PutEx(') &&
            loadProvisioningIdentityBlock.includes('Stealth_CaptureIdentitySnapshotFromDataStore(store, provisioningIdentity)') &&
            deriveIdentityBlock.includes('&tx->rollbackIdentity'),
        rollbackAndPostUpdateSnapshotsStaySeparate:
            source.includes('StealthIdentitySnapshot rollbackIdentity;') &&
            source.includes('StealthIdentitySnapshot postUpdateIdentity;') &&
            backupBlock.includes('Stealth_CaptureIdentitySnapshot(paths->dbPath, &tx->rollbackIdentity)') &&
            source.includes('Stealth_WaitForExpectedIdentity(paths.dbPath, &tx.postUpdateIdentity, 30000)') &&
            source.includes('Stealth_WaitForExpectedIdentity(paths.dbPath, &tx.rollbackIdentity, 30000)') &&
            !source.includes('StealthIdentitySnapshot expectedIdentity;'),
        stagedProvisioningCannotReplaceNodeId:
            loadProvisioningIdentityBlock.includes('preservedIdentity->nodeIdPresent != provisioningIdentity->nodeIdPresent') &&
            loadProvisioningIdentityBlock.includes('Staged provisioning rejected because it changes the installed NodeID'),
        requiredKeyValidationUsesEffectiveImportedValues:
            source.includes('valid = Stealth_LoadProvisioningIdentity(') &&
            !source.includes('strstr(buf, "MeshServer=")') &&
            !source.includes('strstr(buf, "ServerID=")') &&
            !source.includes('strstr(buf, "MeshID=")'),
        printableIdentityComparisonAllowsTrailingNulOnly:
            source.includes('static BOOL Stealth_IdentityFieldBytesMatch(') &&
            source.includes('Stealth_IsPrintableIdentityValue(expectedValue, expectedValueLen)') &&
            source.includes("expectedValue[normalizedExpectedLen - 1] == '\\0'") &&
            source.includes("actualValue[normalizedActualLen - 1] == '\\0'"),
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
        installNoopsWhenHealthyPackageAlreadyMatches:
            source.includes('static BOOL Stealth_FileSha256MatchesW(const wchar_t* leftPath, const wchar_t* rightPath)') &&
            normalizedMatching.includes('discovery == NULL || discovery->stateKind != STEALTH_LIFECYCLE_STATE_HEALTHY') &&
            normalizedMatching.includes('if (!Stealth_FileSha256MatchesW(sourceExePath, discovery->paths.exePath)) { return FALSE; }') &&
            normalizedMatching.includes('if (!Stealth_FileSha256MatchesW(sourceDllPath, discovery->paths.dllPath)) { return FALSE; }') &&
            normalizedMatching.includes('return compared;') &&
            normalizedRun.includes('request == STEALTH_LIFECYCLE_REQUEST_INSTALL && plan.action == STEALTH_LIFECYCLE_ACTION_REPAIR && Stealth_SourcePackageMatchesInstalled(&discovery, sourceExePath, sourceDllPath)') &&
            runBlock.includes('Install request already matches healthy installed package; using noop action') &&
            normalizedRun.includes('plan.action = STEALTH_LIFECYCLE_ACTION_NONE;') &&
            normalizedRun.includes('plan.requiresQuiesce = FALSE;') &&
            normalizedRun.includes('plan.requiresStage = FALSE;') &&
            normalizedRun.includes('plan.requiresServiceStart = FALSE;'),
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
        agentCorePath,
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
