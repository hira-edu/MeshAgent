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

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const source = fs.readFileSync(serviceMainPath, 'utf8');

    const uacConsentTriggerStart = source.indexOf('static int MeshService_RunKvmUacConsentTriggerCommand');
    const uacConsentTriggerEnd = source.indexOf('static int MeshService_RunKvmSecureDesktopProbeCommand');
    const uacConsentTriggerSection =
        uacConsentTriggerStart >= 0 && uacConsentTriggerEnd > uacConsentTriggerStart
            ? source.slice(uacConsentTriggerStart, uacConsentTriggerEnd)
            : '';
    const shellExecuteMatches = [...source.matchAll(/ShellExecuteExW\s*\(/g)].map((match) => match.index);
    const report = {
        serviceMainPath,
        checks: {
            guiRunAsShellFallbackRemoved:
                !source.includes('MeshService_RunSelfCommandAndWait') &&
                !source.includes('RunAsAdmin(') &&
                !source.includes('shell-runas-') &&
                !source.includes('shell-open-fallback') &&
                !source.includes('MeshService_StageElevatedLaunchImage'),
            noGuiShellLaunchRetryHeuristic:
                !source.includes('launchErr == ERROR_INVALID_FUNCTION') &&
                !source.includes('MeshService_IsRecoverableLaunchError'),
            shellExecuteOnlyInUacConsentTrigger:
                shellExecuteMatches.length === 1 &&
                shellExecuteMatches[0] >= uacConsentTriggerStart &&
                shellExecuteMatches[0] < uacConsentTriggerEnd,
            suppressesShellUiOnUacConsentTrigger: uacConsentTriggerSection.includes('SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI'),
            closesUacConsentTriggerProcessHandle: uacConsentTriggerSection.includes('if (ok && executeInfo.hProcess != NULL)') &&
                uacConsentTriggerSection.includes('CloseHandle(executeInfo.hProcess);')
        },
        shellExecuteOccurrenceCount: shellExecuteMatches.length
    };

    for (const [name, passed] of Object.entries(report.checks)) {
        assert(passed, `${name} failed`);
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'gui_shell_launch_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${new Date().toISOString()}`,
            'SUCCESS=true',
            `SHELL_EXECUTE_OCCURRENCES=${report.shellExecuteOccurrenceCount}`,
            `CHECKS=${Object.entries(report.checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
