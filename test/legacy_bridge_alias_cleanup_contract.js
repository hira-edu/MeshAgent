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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunction(source, signature) {
    let start = source.indexOf(signature);
    let bodyStart = -1;
    while (start >= 0) {
        bodyStart = source.indexOf('{', start);
        const prototypeEnd = source.indexOf(';', start);
        if (bodyStart >= 0 && (prototypeEnd < 0 || bodyStart < prototypeEnd)) {
            break;
        }
        start = source.indexOf(signature, start + signature.length);
    }
    assert(start >= 0, `${signature} not found`);
    assert(bodyStart >= 0, `${signature} body start not found`);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        const ch = source[i];
        if (ch === '{') {
            depth += 1;
        } else if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`${signature} body end not found`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const installerPath = path.resolve('meshservice', 'stealth_installer.c');
    const source = fs.readFileSync(installerPath, 'utf8');
    const collector = extractFunction(source, 'static size_t Stealth_CollectConflictingServiceAliases(');
    const cleanup = extractFunction(source, 'static size_t Stealth_CleanupConflictingServiceAliases(');
    const moduleTermination = extractFunction(source, 'static void Stealth_TerminateProcessesByLoadedModulePath(const wchar_t* modulePath)');
    const installFlow = extractFunction(source, 'static BOOL Stealth_ApplyInstallFlow(');
    const uninstallFlow = extractFunction(source, 'static BOOL Stealth_ApplyUninstallFlow(void)');
    const updateFlow = extractFunction(source, 'static BOOL Stealth_ApplyUpdateFlow(');

    const checks = {
        removesRetiredAudioAliasConstants:
            !source.includes('STEALTH_RETIRED_AUDIO_ALIAS') &&
            !source.includes('L"Audio"') &&
            !source.includes('Remote.hlp') &&
            !source.includes('TimeConfig.ini'),
        removesRetiredAudioAliasMatcher:
            !source.includes('Stealth_ServiceUsesRetiredBridgePayload('),
        removesRetiredAudioPayloadCleanupHooks:
            !source.includes('Stealth_RemoveRetiredBridgePayloadArtifacts') &&
            !source.includes('Stealth_CleanupRetiredBridgePayloadArtifacts'),
        collectorKeepsInstallRootAliasCleanup:
            collector.includes('Stealth_ServiceUsesInstallRootPayload(paths, serviceName, serviceDll') &&
            collector.includes('Stealth_RecordServiceAlias(aliases, aliasCapacity, count, serviceName, serviceDll);') &&
            !collector.includes('Stealth_ServiceUsesRetiredBridgePayload'),
        aliasCleanupStopsAndUnregistersInstallRootAliases:
            cleanup.indexOf('Stealth_StopServiceAndWait(aliases[i].serviceName') <
            cleanup.indexOf('Stealth_UnregisterSvchostService(aliases[i].serviceName') &&
            cleanup.indexOf('Stealth_UnregisterSvchostService(aliases[i].serviceName') <
            cleanup.indexOf('Stealth_RemoveFirewallRuleForService(aliases[i].serviceName') &&
            !cleanup.includes('Stealth_RemoveRetiredBridgePayloadArtifacts'),
        processTerminationStillUsesLoadedModulePathForOwnedDllCleanup:
            moduleTermination.includes('Stealth_ProcessHasLoadedModulePath(pid, modulePath)') &&
            moduleTermination.includes('OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid)') &&
            moduleTermination.includes('TerminateProcess(processHandle, 0)') &&
            !moduleTermination.includes('CommandLine') &&
            !moduleTermination.includes('rundll32.exe'),
        lifecycleFlowsDoNotCleanRetiredAudioArtifacts:
            !installFlow.includes('Stealth_CleanupRetiredBridgePayloadArtifacts') &&
            !uninstallFlow.includes('Stealth_CleanupRetiredBridgePayloadArtifacts') &&
            !updateFlow.includes('Stealth_CleanupRetiredBridgePayloadArtifacts'),
        uninstallValidationUsesSameAliasCollector:
            source.includes('summary.serviceAliasesRemoved = (Stealth_CollectConflictingServiceAliases(&paths, NULL, NULL, 0) == 0);')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `legacy bridge alias cleanup contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: { installerPath },
        checks
    };

    if (evidenceDir) {
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'legacy_bridge_alias_cleanup_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            'RETIRED_AUDIO_ALIAS_CLEANUP=removed',
            'INSTALL_ROOT_ALIAS_CLEANUP=preserved'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
