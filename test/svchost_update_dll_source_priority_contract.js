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

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const installerPath = path.resolve('meshservice', 'stealth_installer.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const source = fs.readFileSync(installerPath, 'utf8');
    const serviceMain = fs.readFileSync(serviceMainPath, 'utf8');
    const start = source.indexOf('static BOOL Stealth_EnsureSvchostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath)');
    const end = start >= 0 ? source.indexOf('\nstatic BOOL Stealth_EnsureConfigFile', start) : -1;
    const block = (start >= 0 && end > start) ? source.slice(start, end) : '';
    const updateDeclarationStart = source.indexOf('static BOOL Stealth_PrepareUpdateTransaction(');
    const updateStart = updateDeclarationStart >= 0 ? source.indexOf('static BOOL Stealth_PrepareUpdateTransaction(', updateDeclarationStart + 1) : -1;
    const updateEnd = updateStart >= 0 ? source.indexOf('\nstatic BOOL Stealth_BackupUpdateTransaction', updateStart) : -1;
    const updateBlock = (updateStart >= 0 && updateEnd > updateStart) ? source.slice(updateStart, updateEnd) : '';
    const ingressStart = serviceMain.indexOf('static int MeshService_RunSelfUpdateIngress(');
    const ingressEnd = ingressStart >= 0 ? serviceMain.indexOf('\nstatic int MeshService_IsUnsupportedLifecycleSwitch', ingressStart) : -1;
    const ingressBlock = (ingressStart >= 0 && ingressEnd > ingressStart) ? serviceMain.slice(ingressStart, ingressEnd) : '';

    assert(block.length > 0, 'unable to isolate Stealth_EnsureSvchostDllFile');
    assert(updateBlock.length > 0, 'unable to isolate Stealth_PrepareUpdateTransaction');
    assert(ingressBlock.length > 0, 'unable to isolate MeshService_RunSelfUpdateIngress');

    const explicitIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(sourceDllPath, destPath, L"explicit package DLL")');
    const sameBasenameIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package same-basename DLL")');
    const embeddedIndex = block.indexOf('Stealth_ExtractEmbeddedSvchostDllFromExe(sourceExePath, destPath)');
    const brandedIndex = Math.max(
        block.indexOf('Stealth_TryStageAndValidateSvchostDll(brandedCandidatePath, destPath, L"package sibling branded DLL")'),
        block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package sibling branded DLL")')
    );
    const fallbackIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package sibling fallback DLL")');

    assert(explicitIndex >= 0, 'missing explicit package DLL stage');
    assert(sameBasenameIndex >= 0, 'missing same-basename DLL stage');
    assert(embeddedIndex >= 0, 'missing embedded DLL extraction stage');
    assert(brandedIndex >= 0, 'missing branded sibling DLL stage');
    assert(fallbackIndex >= 0, 'missing fallback sibling DLL stage');
    assert(block.includes('Stealth_BuildSiblingPathWithFileName(sourceExePath, brandedDllName, brandedCandidatePath'), 'branded sibling DLL path must be built from branded DLL name');
    assert(block.includes('_wcsicmp(candidatePath, brandedCandidatePath) != 0'), 'fallback sibling DLL must not duplicate branded sibling path');
    assert(explicitIndex < sameBasenameIndex, 'explicit DLL stage must remain first');
    assert(sameBasenameIndex < embeddedIndex, 'same-basename DLL must be checked before embedded extraction');
    assert(embeddedIndex < brandedIndex, 'embedded extraction must outrank branded sibling DLL fallback');
    assert(brandedIndex < fallbackIndex, 'branded sibling fallback must outrank generic fallback DLL');
    const normalizedUpdateBlock = updateBlock.replace(/\s+/g, ' ');
    assert(normalizedUpdateBlock.includes('Stealth_EnsureSvchostDllFile(sourceExePath, sourceDllPath, tx->stagedDllPath)'), 'update transaction must preserve explicit lifecycle sourceDllPath');
    assert(!updateBlock.includes('UNREFERENCED_PARAMETER(sourceDllPath)'), 'update transaction must not ignore sourceDllPath');
    assert(ingressBlock.includes('MeshService_PathsReferToSameFileW(sourceExePath, installedPaths.exePath)'), 'self-update ingress must compare source package against installed executable');
    assert(ingressBlock.includes('Refusing installed executable as update package source'), 'self-update ingress must reject installed executable as package source');

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        installerPath,
        serviceMainPath,
        checks: {
            explicitBeforeSameBasename: explicitIndex < sameBasenameIndex,
            sameBasenameBeforeEmbedded: sameBasenameIndex < embeddedIndex,
            embeddedBeforeBrandedSibling: embeddedIndex < brandedIndex,
            brandedBeforeFallbackSibling: brandedIndex < fallbackIndex,
            brandedUsesDedicatedPath: block.includes('Stealth_BuildSiblingPathWithFileName(sourceExePath, brandedDllName, brandedCandidatePath'),
            fallbackSkipsBrandedPath: block.includes('_wcsicmp(candidatePath, brandedCandidatePath) != 0'),
            updateUsesExplicitSourceDll: normalizedUpdateBlock.includes('Stealth_EnsureSvchostDllFile(sourceExePath, sourceDllPath, tx->stagedDllPath)'),
            updateDoesNotIgnoreSourceDll: !updateBlock.includes('UNREFERENCED_PARAMETER(sourceDllPath)'),
            selfUpdateRejectsInstalledSource: ingressBlock.includes('MeshService_PathsReferToSameFileW(sourceExePath, installedPaths.exePath)') &&
                ingressBlock.includes('Refusing installed executable as update package source')
        }
    };

    if (evidenceDir) {
        ensureDir(evidenceDir);
        fs.writeFileSync(path.join(evidenceDir, 'svchost_update_dll_source_priority_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(report.checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
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
