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

function readSource(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;

    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const watchdogPath = path.resolve('meshservice', 'stealth_watchdog.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const resourcePath = path.resolve('meshservice', 'resource.h');
    const integrationPath = path.resolve('meshservice', 'stealth_integration.c');
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const agentcoreHeaderPath = path.resolve('meshcore', 'agentcore.h');
    const proxyHelperPath = path.resolve('modules', 'proxy-helper.js');
    const wgetPath = path.resolve('modules', 'wget.js');
    const configGuidePath = path.resolve('docs', 'CONFIGURATION.md');

    const processPipeSource = readSource(processPipePath);
    const watchdogSource = readSource(watchdogPath);
    const serviceMainSource = readSource(serviceMainPath);
    const resourceSource = readSource(resourcePath);
    const integrationSource = readSource(integrationPath);
    const agentcoreSource = readSource(agentcorePath);
    const agentcoreHeaderSource = readSource(agentcoreHeaderPath);
    const proxyHelperSource = readSource(proxyHelperPath);
    const wgetSource = readSource(wgetPath);
    const configGuideSource = readSource(configGuidePath);

    const forbiddenAgentcoreTokens = [
        'MeshServer=local',
        'swarm.meshcentral.com',
        'MeshAgentDoH',
        'WinHttpGetProxyForUrl',
        'MeshAgent_CacheResolvedAddress',
        'MeshAgent_AdvanceBrandedEndpoint',
        'MeshServer_ConnectEx_AutoProxy',
        'MeshServer_ConnectEx_Enumerate_Contexts',
        'g_meshNetworkProfile.',
        'autoproxy_setup',
        'usingBrandedEndpoint'
    ];

    const forbiddenAgentcoreHits = forbiddenAgentcoreTokens.filter((token) => agentcoreSource.includes(token));
    const forbiddenProxyDiscoveryTokens = [
        'WinHttpGetProxyForUrl',
        'netsh winhttp import proxy source=ie',
        'ProxyEnable',
        'ProxyServer',
        'ProxyOverride',
        'HKEY_USERS',
        'win-registry',
        'wpad',
        'WPAD',
        'autoproxy',
        'gsettings',
        '/etc/environment',
        '/etc/yum.conf',
        '/etc/apt',
        '/etc/sysconfig',
        'default gateway'
    ];
    const proxyDiscoverySurface = [
        agentcoreSource,
        agentcoreHeaderSource,
        proxyHelperSource,
        wgetSource,
        serviceMainSource,
        resourceSource
    ].join('\n');
    const forbiddenProxyDiscoveryHits = forbiddenProxyDiscoveryTokens.filter((token) => proxyDiscoverySurface.includes(token));

    const checks = {
        processPipeRemovesLegacySessionKvmException:
            !processPipeSource.includes('ILibProcessPipe_LogPolicyDecisionA("allow-kvm"') &&
            !processPipeSource.includes('ILibProcessPipe_HasKvmSwitchA('),
        processPipeBlocksStandaloneAgentSelfSpawnInUserSessions:
            !processPipeSource.includes('allow-agent-self') &&
            !processPipeSource.includes('ILibProcessPipe_IsApprovedAgentSelfSpawnLaunchA') &&
            !processPipeSource.includes('MESHAGENT_SELF_SPAWN_PATH'),
        processPipeRestrictsBridgeToRundll32Export: processPipeSource.includes('ILibProcessPipe_IsApprovedDesktopBridgeLaunchA') &&
            processPipeSource.includes('allow-kvm-bridge') &&
            processPipeSource.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A'),
        processPipeDeniesInternalHelperReentry:
            !processPipeSource.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA') &&
            !processPipeSource.includes('allow-helper-reentry') &&
            !processPipeSource.includes('ILibProcessPipe_HasExactParameterA(parameters, "--slave")') &&
            !processPipeSource.includes('ILibProcessPipe_HasExactParameterA(parameters, "-b64exec")') &&
            processPipeSource.includes('blocked-windows-spawn') &&
            processPipeSource.includes('ILibProcessPipe_IsWindowsSpawnAllowed(spawnType, target, parameters)'),
        processPipeDoesNotAllowGenericUserSessionByEnv:
            !processPipeSource.includes('ILibProcessPipe_LogPolicyDecisionA("allow", "generic"') &&
            !processPipeSource.includes('strictServiceOnly == 0 || allowDesktopBridge != 0'),
        helperMonitorRequiresApprovedBridgeCommand: watchdogSource.includes('HelperMonitor_IsApprovedDesktopBridgeCommand') &&
            watchdogSource.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W') &&
            watchdogSource.includes('\\rundll32.exe') &&
            watchdogSource.includes('CommandLineToArgvW(arguments, &argumentCount)') &&
            watchdogSource.includes('Helper_IsApprovedBridgeModuleArgumentW(argumentVector[0])') &&
            watchdogSource.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[1], L"_in")') &&
            watchdogSource.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[2], L"_out")') &&
            watchdogSource.includes('Helper_IsApprovedBridgeModeW(argumentVector[3])') &&
            watchdogSource.includes('Helper_IsApprovedBridgeOptionalFlagW(argumentVector[i])') &&
            !watchdogSource.includes('Helper_CommandLineContainsInsensitiveW'),
        helperMonitorLaunchFailsClosed: watchdogSource.includes('Watchdog helper user-session launch blocked by rundll32-only helper policy') &&
            watchdogSource.includes('Helper monitor start blocked by rundll32-only helper policy') &&
            watchdogSource.includes('SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY)') &&
            watchdogSource.includes('Helper_IsApprovedBridgeModuleArgumentW(argumentVector[0])') &&
            watchdogSource.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[1], L"_in")') &&
            watchdogSource.includes('CommandLineToArgvW(arguments, &argumentCount)') &&
            !watchdogSource.includes('Helper_LogPolicyDecision'),
        serviceMainDisablesImplicitHelperFallback: serviceMainSource.includes('Helper monitor is not a retained production launch path') &&
            serviceMainSource.includes('config->enableHelperMonitor = FALSE;') &&
            !serviceMainSource.includes('STEALTH_HELPER_EXE') &&
            !serviceMainSource.includes('STEALTH_HELPER_ARGS') &&
            !serviceMainSource.includes('STEALTH_HELPER_PERSISTENT') &&
            !serviceMainSource.includes('STEALTH_HELPER_WATCHDOG') &&
            !serviceMainSource.includes('HelperMonitor_IsApprovedDesktopBridgeCommand(config->helperExePath, config->helperArguments)'),
        serviceMainRejectsDirectKvmExeModes: serviceMainSource.includes('direct KVM slave execution is disabled') &&
            serviceMainSource.includes('MeshService_IsRunningUnderRundll32()') &&
            serviceMainSource.includes('kvm_server_mainloop((void*)parm);'),
        serviceMainRejectsDirectHelperReentry: serviceMainSource.includes('MeshService_HasUnsupportedDirectScriptSwitch(argc, argv)') &&
            serviceMainSource.includes('direct -exec/-b64exec/--slave helper re-entry is disabled') &&
            serviceMainSource.includes('Use an approved rundll32 contract export') &&
            !serviceMainSource.includes('ILibBase64Decode((unsigned char *)argv[2]') &&
            !serviceMainSource.includes('ILibString_Copy(argv[2], 0)'),
        integrationRejectsOutOfContractHelperMonitor: integrationSource.includes('Helper monitor activation blocked by rundll32-only helper policy') &&
            !integrationSource.includes('HelperMonitor_Start(&helperConfig') &&
            !integrationSource.includes('HelperMonitor_RequestSpawn((DWORD)-1)') &&
            !integrationSource.includes('Watchdog_RegisterHelper(&helperConfig)'),
        agentcoreDoesNotPublishAuthorizedSelfSpawnPath: !agentcoreSource.includes('MESHAGENT_SELF_SPAWN_PATH'),
        agentcoreUsesDirectHeadersOnly: agentcoreSource.includes('MeshAgent_AddHostHeader(req, NULL, host, port, useDefaultPort2);') &&
            agentcoreSource.includes('MeshAgent_AddUserAgentHeader(req, NULL);'),
        agentcoreUsesDirectTlsOnly: agentcoreSource.includes('ILibWebClient_Request_SetSNI(reqToken, host,') &&
            agentcoreSource.includes('ILibWebClient_Request_SetALPN(reqToken, NULL);'),
        agentcoreRemovedRejectedDriftTokens: forbiddenAgentcoreHits.length === 0,
        proxyPolicyRejectsAmbientDiscovery: forbiddenProxyDiscoveryHits.length === 0,
        proxyHelperRequiresExplicitWebProxy: proxyHelperSource.includes("getMshValue('WebProxy')") &&
            proxyHelperSource.includes("throw ('No explicit proxy')") &&
            proxyHelperSource.includes("Explicit WebProxy must include a port") &&
            proxyHelperSource.includes('return false;'),
        wgetDoesNotReadUserProxyRegistry: !wgetSource.includes('Internet Settings') &&
            !wgetSource.includes('global-tunnel') &&
            !wgetSource.includes('win-registry'),
        agentcoreReadsOnlyExplicitProxy: agentcoreSource.includes('ILibSimpleDataStore_GetEx(agent->masterDb, "WebProxy", 8, inBuffer') &&
            !agentcoreSource.includes("require('proxy-helper').getProxy();") &&
            !agentcoreHeaderSource.includes('proxyCandidate') &&
            !agentcoreHeaderSource.includes('proxyFallback') &&
            !agentcoreHeaderSource.includes('usingBrandedEndpoint'),
        guiRemovesRetiredAutoProxyControl: !serviceMainSource.includes('IDC_AUTOPROXY') &&
            !serviceMainSource.includes('autoproxy') &&
            !resourceSource.includes('IDC_AUTOPROXY') &&
            !resourceSource.includes('Auto Proxy'),
        activeDocsRejectProxyFallback: configGuideSource.includes('Ambient proxy discovery is not used') &&
            configGuideSource.includes('explicit') &&
            configGuideSource.includes('WebProxy') &&
            !configGuideSource.includes('auto-helper') &&
            !configGuideSource.includes('autoproxy=1')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `Drift reduction contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            processPipePath,
            watchdogPath,
            serviceMainPath,
            resourcePath,
            integrationPath,
            agentcorePath,
            agentcoreHeaderPath,
            proxyHelperPath,
            wgetPath,
            configGuidePath
        },
        forbiddenAgentcoreTokens,
        forbiddenAgentcoreHits,
        forbiddenProxyDiscoveryTokens,
        forbiddenProxyDiscoveryHits,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'drift_reduction_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `FORBIDDEN_AGENTCORE_HITS=${forbiddenAgentcoreHits.join(',') || '(none)'}`,
            `FORBIDDEN_PROXY_DISCOVERY_HITS=${forbiddenProxyDiscoveryHits.join(',') || '(none)'}`
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
