const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const source = fs.readFileSync(serviceMainPath, 'utf8');

    const noUiMatches = source.match(/SEE_MASK_NOCLOSEPROCESS\s*\|\s*SEE_MASK_FLAG_NO_UI/g) || [];
    const uacConsentTriggerStart = source.indexOf('static int MeshService_RunKvmUacConsentTriggerCommand');
    const uacConsentTriggerEnd = source.indexOf('static int MeshService_RunKvmSecureDesktopProbeCommand');
    const uacConsentTriggerSection =
        uacConsentTriggerStart >= 0 && uacConsentTriggerEnd > uacConsentTriggerStart
            ? source.slice(uacConsentTriggerStart, uacConsentTriggerEnd)
            : '';
    const report = {
        serviceMainPath,
        checks: {
            retriesInvalidFunctionShellLaunch: source.includes('launchErr == ERROR_INVALID_FUNCTION'),
            suppressesShellUiOnRunAsPaths: noUiMatches.length >= 4,
            suppressesShellUiOnUacConsentTrigger: uacConsentTriggerSection.includes('SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI'),
            closesRunAsProcessHandle: source.includes('if (sei.hProcess != NULL) { CloseHandle(sei.hProcess); }')
        },
        noUiOccurrenceCount: noUiMatches.length
    };

    for (const [name, passed] of Object.entries(report.checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

main();
