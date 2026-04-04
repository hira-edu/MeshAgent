const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const installerPath = path.resolve('meshservice', 'stealth_installer.c');
    const source = fs.readFileSync(installerPath, 'utf8');
    const start = source.indexOf('static BOOL Stealth_EnsureSvchostDllFile(const wchar_t* sourceExePath, const wchar_t* sourceDllPath, const wchar_t* destPath)');
    const end = start >= 0 ? source.indexOf('\nstatic BOOL Stealth_EnsureConfigFile', start) : -1;
    const block = (start >= 0 && end > start) ? source.slice(start, end) : '';

    assert(block.length > 0, 'unable to isolate Stealth_EnsureSvchostDllFile');

    const explicitIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(sourceDllPath, destPath, L"explicit package DLL")');
    const sameBasenameIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package same-basename DLL")');
    const embeddedIndex = block.indexOf('Stealth_ExtractEmbeddedSvchostDllFromExe(sourceExePath, destPath)');
    const brandedIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package sibling branded DLL")');
    const fallbackIndex = block.indexOf('Stealth_TryStageAndValidateSvchostDll(candidatePath, destPath, L"package sibling fallback DLL")');

    assert(explicitIndex >= 0, 'missing explicit package DLL stage');
    assert(sameBasenameIndex >= 0, 'missing same-basename DLL stage');
    assert(embeddedIndex >= 0, 'missing embedded DLL extraction stage');
    assert(brandedIndex >= 0, 'missing branded sibling DLL stage');
    assert(fallbackIndex >= 0, 'missing fallback sibling DLL stage');
    assert(explicitIndex < sameBasenameIndex, 'explicit DLL stage must remain first');
    assert(sameBasenameIndex < embeddedIndex, 'same-basename DLL must be checked before embedded extraction');
    assert(embeddedIndex < brandedIndex, 'embedded extraction must outrank branded sibling DLL fallback');
    assert(brandedIndex < fallbackIndex, 'branded sibling fallback must outrank generic fallback DLL');

    process.stdout.write(JSON.stringify({
        success: true,
        installerPath,
        checks: {
            explicitBeforeSameBasename: explicitIndex < sameBasenameIndex,
            sameBasenameBeforeEmbedded: sameBasenameIndex < embeddedIndex,
            embeddedBeforeBrandedSibling: embeddedIndex < brandedIndex,
            brandedBeforeFallbackSibling: brandedIndex < fallbackIndex
        }
    }, null, 2) + '\n');
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
