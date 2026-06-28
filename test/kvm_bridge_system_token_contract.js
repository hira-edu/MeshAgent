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
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const processPipeSource = fs.readFileSync(processPipePath, 'utf8');

    const checks = {
        opensServiceTokenForDuplication: processPipeSource.includes('OpenProcessToken(procHandle, TOKEN_DUPLICATE | TOKEN_QUERY, &token)'),
        duplicatesPrimaryTokenWithExplicitRights:
            processPipeSource.includes('DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT'),
        rewritesTokenSessionId: processPipeSource.includes('SetTokenInformation(userToken, (TOKEN_INFORMATION_CLASS)TokenSessionId'),
        usesSpecifiedSessionId: processPipeSource.includes('if (spawnType == ILibProcessPipe_SpawnTypes_SPECIFIED_USER) { sessionId = (DWORD)(uint64_t)sid; }'),
        desktopBridgeKeepsServiceToken:
            processPipeSource.includes('useLoggedOnUserToken = 0;') &&
            !processPipeSource.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA(target, parameters)') &&
            !processPipeSource.includes('useLoggedOnUserToken = (spawnType != ILibProcessPipe_SpawnTypes_WINLOGON'),
        assignsDesktopBySpawnType: processPipeSource.includes('info.lpDesktop = (spawnType == ILibProcessPipe_SpawnTypes_WINLOGON) ? L"Winsta0\\\\Winlogon" : L"winsta0\\\\default";'),
        loadsUserenvDynamically: processPipeSource.includes('LoadLibraryExW(L"userenv.dll"'),
        createsTokenEnvironmentBlock: processPipeSource.includes('ILibProcessPipe_TryCreateEnvironmentBlock(userToken, &tokenEnvironment'),
        mergesOverrideEnvironment: processPipeSource.includes('ILibProcessPipe_MergeWideEnvBlocks((WCHAR*)processEnvironment, overrideEnvironment)'),
        createProcessUsesSharedEnvironment: processPipeSource.includes('CreateProcessAsUserW(userToken') && processPipeSource.includes('creationFlags, processEnvironment, NULL, &info, &processInfo)'),
        creationFlagsIncludeUnicodeAndNoWindow: processPipeSource.includes('CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `system-token contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            processPipePath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_system_token_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
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
