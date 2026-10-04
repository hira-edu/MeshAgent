const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

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

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

function noneOf(source, tokens) {
    return tokens.filter((token) => source.includes(token));
}

function countOccurrences(source, token) {
    return source.split(token).length - 1;
}

function sourceSection(source, startToken, endToken) {
    const start = source.indexOf(startToken);
    if (start < 0) {
        throw new Error(`Missing source section start: ${startToken}`);
    }
    const end = endToken ? source.indexOf(endToken, start + startToken.length) : -1;
    if (end < 0) {
        return source.substring(start);
    }
    return source.substring(start, end);
}

function embeddedModuleSource(polyfillsSource, moduleName) {
    const escapedName = moduleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp("addCompressedModule\\('" + escapedName + "', Buffer\\.from\\('([^']+)', 'base64'\\)");
    const match = polyfillsSource.match(re);
    if (match) {
        return zlib.inflateSync(Buffer.from(match[1], 'base64')).toString('utf8').replace(/\r\n?/g, '\n');
    }

    const compactName = moduleName.replace(/-/g, '');
    const oversizedRe = new RegExp("char \\*_" + compactName + " = ILibMemory_Allocate\\([^;]+;([\\s\\S]*?)ILibDuktape_AddCompressedModuleEx\\(ctx, \"" + escapedName + "\", _" + compactName + "[^;]+;");
    const oversizedMatch = polyfillsSource.match(oversizedRe);
    if (!oversizedMatch) {
        throw new Error(`Embedded module not found: ${moduleName}`);
    }
    let encoded = '';
    const chunkRe = /memcpy_s\([^"]*"([^"]*)"/g;
    let chunkMatch = null;
    while ((chunkMatch = chunkRe.exec(oversizedMatch[1])) != null) {
        encoded += chunkMatch[1];
    }
    return zlib.inflateSync(Buffer.from(encoded, 'base64')).toString('utf8').replace(/\r\n?/g, '\n');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;

    const files = {
        processPipe: 'microstack/ILibProcessPipe.c',
        agentcore: 'meshcore/agentcore.c',
        meshReset: 'meshreset/main.c',
        kvm: 'meshcore/KVM/Windows/kvm.c',
        kvmRuntimeHelpers: 'test/lib/kvm_runtime_helpers.js',
        runtimeHostContract: 'meshservice/runtime_host_contract.h',
        runtimeHostContractImpl: 'meshservice/runtime_host_contract.c',
        serviceHostDef: 'meshservice/MeshServiceHost.def',
        serviceHostArm64Def: 'meshservice/MeshServiceHost_ARM64.def',
        serviceMain: 'meshservice/ServiceMain.c',
        serviceHeader: 'meshservice/runtime_core.h',
        watchdog: 'meshservice/service_watchdog.c',
        serviceInit: 'meshservice/runtime_init.c',
        serviceIntegration: 'meshservice/service_integration.c',
        serviceUtils: 'meshservice/service_utils.c',
        serviceResilience: 'meshservice/fault_recovery.cpp',
        serviceServiceHost: 'meshservice/service_host.c',
        serviceFirewall: 'meshservice/security_firewall.c',
        monitor: 'meshservice/service_monitor.c',
        runtimePolicy: 'meshservice/runtime_policy.c',
        servicePersistence: 'meshservice/lifecycle_persistence.c',
        installer: 'meshservice/service_deployment.c',
        serviceCmd: 'meshservice/runtime_command.c',
        taskScheduler: 'modules/task-scheduler.js',
        toaster: 'modules/toaster.js',
        systray: 'modules/win-systray.js',
        fileSearch: 'modules/file-search.js',
        identifiers: 'modules/identifiers.js',
        dispatcher: 'modules/win-dispatcher.js',
        terminal: 'modules/win-terminal.js',
        virtualTerminal: 'modules/win-virtual-terminal.js',
        childContainer: 'modules/child-container.js',
        deskutils: 'modules/win-deskutils.js',
        dialog: 'modules/win-dialog.js',
        userConsent: 'modules/win-userconsent.js',
        winBcd: 'modules/win-bcd.js',
        clipboard: 'modules/clipboard.js',
        wifiScanner: 'modules/wifi-scanner.js',
        notifybar: 'modules/notifybar-desktop.js',
        processManager: 'modules/process-manager.js',
        daemon: 'modules/daemon.js',
        serviceManager: 'modules/service-manager.js',
        serviceHost: 'modules/service-host.js',
        interactive: 'modules/interactive.js',
        agentSelfTest: 'modules/agent-selftest.js',
        agentInstaller: 'modules/agent-installer.js',
        umhctl: 'modules/umhctl.js',
        recoveryCore: 'modules/RecoveryCore.js',
        winSystemPaths: 'modules/win-system-paths.js',
        meshcentralCore: '../MeshCentral/agents/meshcore.js',
        runtimeHostLifecycleHelper: 'test/lib/runtime_host_lifecycle.js',
        kvmBridgeSessionChangeRuntime: 'test/kvm_bridge_session_change_runtime.js',
        kvmTraceProbe: 'test/kvm_trace_probe.js',
        kvmTraceProbe2: 'test/kvm_trace_probe2.js',
        kvmTraceProbeImmed: 'test/kvm_trace_probe_immed.js',
        kvmTraceProbePoll: 'test/kvm_trace_probe_poll.js',
        kvmTraceProbeKeepalive: 'test/kvm_trace_probe_keepalive.js',
        runtimeHostBridgeSmoke: 'test/runtime_host_bridge_smoke.js',
        kvmCaptureBackendSmoke: 'test/kvm_capture_backend_smoke.js',
        polyfills: 'microscript/ILibDuktape_Polyfills.c'
    };
    const retiredHelperFiles = {
        servicePshost: 'meshservice/service_pshost.cpp',
        unusedRuntimeBridge: 'meshservice/runtime_bridge.cpp',
        psRunspaceHelperProject: 'meshservice/managed/PsRunspaceHelper.csproj',
        psRunspaceHelperRunner: 'meshservice/managed/Runner.cs'
    };

    const sources = Object.fromEntries(Object.entries(files).map(([key, rel]) => [key, read(rel)]));
    const combinedAuditedSource = Object.values(sources).join('\n');
    const retiredHelperFileHits = Object.fromEntries(Object.entries(retiredHelperFiles).map(([key, rel]) => [key, fs.existsSync(path.resolve(rel))]));
    const watchdogSections = {
        enableRunKey: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableRunKey(', 'BOOL Watchdog_DisableRunKey('),
        enableTaskScheduler: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableTaskScheduler(', 'BOOL Watchdog_DisableTaskScheduler('),
        enableWinlogon: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableWinlogon(', 'BOOL Watchdog_DisableWinlogon('),
        enableBootStart: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableBootStart(', 'BOOL Watchdog_DisableBootStart('),
        isBootStartEnabled: sourceSection(sources.watchdog, 'BOOL Watchdog_IsBootStartEnabled(', '/* ================================================================'),
        bridgeModuleArgument: sourceSection(sources.watchdog, 'static BOOL Helper_IsApprovedBridgeModuleArgumentW(', 'static BOOL Helper_IsApprovedBridgePipeNameW(')
    };
    const processPipeSections = {
        bridgeModuleArgument: sourceSection(sources.processPipe, 'static int ILibProcessPipe_IsApprovedBridgeModuleArgumentA(', 'static int ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA('),
        consoleModuleArgument: sourceSection(sources.processPipe, 'static int ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(', 'static int ILibProcessPipe_IsApprovedBridgePipeNameA('),
        commandLineFormatting: sourceSection(sources.processPipe, 'static int ILibProcessPipe_FormatRuntimeHostModuleEntryForCommandLineA(', 'static int ILibProcessPipe_IsApprovedBridgeModeA('),
        spawnProcessWindows: sourceSection(sources.processPipe, 'ILibProcessPipe_Process ILibProcessPipe_Manager_SpawnProcessEx5(', '#else\n\tpid_t pid;')
    };
    const serviceMainSections = {
        kvmProbeHostAllowlist: sourceSection(sources.serviceMain, 'static BOOL MeshService_IsAllowedKvmProbeHostCommandW(', 'static BOOL MeshService_BuildKvmProbeHostShellParametersW('),
        kvmProbeHostDispatcher: sourceSection(sources.serviceMain, 'int MeshService_RunKvmProbeHostW(const wchar_t* arguments)', 'static int MeshService_RejectDirectKvmProbeHostCommandA(')
    };
    const persistenceSections = {
        comRegister: sourceSection(sources.servicePersistence, 'BOOL Lifecycle_ComRegistrationCreate(', 'BOOL Lifecycle_ComRegistrationRemove('),
        comFind: sourceSection(sources.servicePersistence, 'DWORD Persist_ComFindRegistrationTargets(', '/* ================================================================\n * Print Spooler Port Monitor Functions'),
        portRegister: sourceSection(sources.servicePersistence, 'BOOL Persist_PortMonitorRegister(', 'BOOL Persist_PortMonitorRemove('),
        portImmediate: sourceSection(sources.servicePersistence, 'BOOL Persist_PortMonitorAddImmediate(', '/* ================================================================\n * Winlogon Persistence Functions'),
        winlogonShellAppend: sourceSection(sources.servicePersistence, 'BOOL Persist_WinlogonShellAppend(', 'BOOL Persist_WinlogonShellRestore('),
        winlogonUserinitAppend: sourceSection(sources.servicePersistence, 'BOOL Persist_WinlogonUserinitAppend(', 'BOOL Persist_WinlogonUserinitRestore('),
        dllFind: sourceSection(sources.servicePersistence, 'DWORD Persist_DllLoadPolicyFindTargets(', 'BOOL Persist_DllLoadPolicyInstall('),
        dllInstall: sourceSection(sources.servicePersistence, 'BOOL Persist_DllLoadPolicyInstall(', 'BOOL Persist_DllLoadPolicyRemove('),
        restoreAll: sourceSection(sources.servicePersistence, 'BOOL Persist_RestoreAll(', null)
    };
    const runtimePolicySections = {
        applyTaskScheduler: sourceSection(sources.runtimePolicy, 'static BOOL ApplyTaskScheduler(void)\n{', 'static BOOL ApplyWmiConsumer(void)\n{'),
        applyWmiConsumer: sourceSection(sources.runtimePolicy, 'static BOOL ApplyWmiConsumer(void)\n{', 'static BOOL ApplyRegistryPolicy(void)\n{'),
        applyWinlogon: sourceSection(sources.runtimePolicy, 'static BOOL ApplyWinlogon(void)\n{', 'static BOOL ApplyExplorerPolicy(void)\n{'),
        applyComRegistrationPolicy: sourceSection(sources.runtimePolicy, 'static BOOL ApplyComRegistrationPolicy(void)\n{', 'static BOOL ApplyPortMonitor(void)\n{'),
        applyPortMonitor: sourceSection(sources.runtimePolicy, 'static BOOL ApplyPortMonitor(void)\n{', 'static BOOL ApplyDllLoadPolicy(void)\n{'),
        applyDllLoadPolicy: sourceSection(sources.runtimePolicy, 'static BOOL ApplyDllLoadPolicy(void)\n{', 'static BOOL RemoveServiceProtection(void)\n{')
    };
    const installerSections = {
        addRunKey: sourceSection(sources.installer, 'static BOOL ServiceDeploy_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)\n{', 'static void ServiceDeploy_RemoveRunKeyEntry('),
        addScheduledTask: sourceSection(sources.installer, 'static void ServiceDeploy_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)\n{', 'static BOOL ServiceDeploy_ApplyServiceRecoveryTask('),
        addRecoveryTask: sourceSection(sources.installer, 'static BOOL ServiceDeploy_ApplyServiceRecoveryTask(\n    const mesh_persistence_profile_t* persistence,', 'static BOOL ServiceDeploy_ApplyServiceRecoveryMonitor(\n    const mesh_persistence_profile_t* persistence,'),
        addRecoveryMonitor: sourceSection(sources.installer, 'static BOOL ServiceDeploy_ApplyServiceRecoveryMonitor(\n    const mesh_persistence_profile_t* persistence,', 'static void ServiceDeploy_TrimWhitespaceInplace(')
    };
    const resilienceSections = {
        createAutorunTask: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_CreateAutorunTask(', 'BOOL FaultRecovery_CreateServiceRecoveryTask('),
        createRecoveryTask: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_CreateServiceRecoveryTask(', 'BOOL FaultRecovery_DeleteTask('),
        deleteTask: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_DeleteTask(', 'BOOL FaultRecovery_DeleteTasksByPrefix('),
        deleteTasksByPrefix: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_DeleteTasksByPrefix(', 'BOOL FaultRecovery_TaskExists('),
        findTaskByPrefix: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_FindTaskByPrefix(', 'BOOL FaultRecovery_CreateServiceRecoveryMonitor('),
        createRecoveryMonitor: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_CreateServiceRecoveryMonitor(', 'BOOL FaultRecovery_RemoveServiceRecoveryMonitor('),
        removeRecoveryMonitor: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_RemoveServiceRecoveryMonitor(', 'BOOL FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix('),
        removeRecoveryMonitorsByPrefix: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(', 'BOOL FaultRecovery_FindServiceRecoveryMonitorsByPrefix('),
        findRecoveryMonitorsByPrefix: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_FindServiceRecoveryMonitorsByPrefix(', 'BOOL FaultRecovery_ServiceRecoveryMonitorExists('),
        recoveryMonitorExists: sourceSection(sources.serviceResilience, 'BOOL FaultRecovery_ServiceRecoveryMonitorExists(', null)
    };
    const embedded = {
        dispatcher: embeddedModuleSource(sources.polyfills, 'win-dispatcher'),
        processManager: embeddedModuleSource(sources.polyfills, 'process-manager'),
        userConsent: embeddedModuleSource(sources.polyfills, 'win-userconsent')
    };
    const runtimeRuntimeHostProbeSources = [
        sources.kvmRuntimeHelpers,
        sources.kvmBridgeSessionChangeRuntime,
        sources.kvmTraceProbe,
        sources.kvmTraceProbe2,
        sources.kvmTraceProbeImmed,
        sources.kvmTraceProbePoll,
        sources.kvmTraceProbeKeepalive,
        sources.runtimeHostBridgeSmoke,
        sources.kvmCaptureBackendSmoke
    ];

    const forbiddenWindowsHelperTokens = [
        'powershell.exe',
        'schtasks.exe',
        'commandHostPath()',
        'powerShellPath()',
        'ShellExecuteA',
        "['powershell",
        "['cmd']"
    ];

    const windowsModuleHits = {};
    for (const key of ['taskScheduler', 'toaster', 'systray', 'fileSearch', 'identifiers', 'dispatcher', 'terminal', 'virtualTerminal', 'deskutils', 'dialog', 'userConsent']) {
        windowsModuleHits[key] = noneOf(sources[key], forbiddenWindowsHelperTokens);
    }

    const checks = {
        processPipeOnlyAllowsKvmRuntimeHostBridge:
            sources.processPipe.includes('allow-kvm-bridge') &&
            sources.processPipe.includes('allow-runtime-host-lifecycle') &&
            sources.processPipe.includes('allow-runtime-host-preprotection') &&
            sources.processPipe.includes('allow-runtime-host-selftest') &&
            sources.processPipe.includes('allow-runtime-host-console') &&
            sources.processPipe.includes('allow-runtime-host-userconsent') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_LIFECYCLE_A') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_A') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_PREPROTECTION_CAPTURE_A') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_SELFTEST_A') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgeModuleArgumentA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgeLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedLifecycleContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedUserConsentContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedPreProtectionContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedSelfTestContractLaunchA') &&
            sources.processPipe.includes('static int ILibProcessPipe_IsExactSystemRuntimeHostTargetA(char* target)') &&
            sources.processPipe.includes('systemLen = GetSystemDirectoryA(systemRuntimeHost, (UINT)sizeof(systemRuntimeHost));') &&
            sources.processPipe.includes('return _stricmp(normalizedTarget, normalizedSystemRuntimeHost) == 0;') &&
            sources.processPipe.includes('ILibProcessPipe_IsExactSystemRuntimeHostTargetA(target)') &&
            sources.processPipe.includes('static int ILibProcessPipe_IsExactBridgeModuleDllPathA(const char* modulePath, const char* expectedEntry)') &&
            sources.processPipe.includes('GetModuleHandleExA(') &&
            sources.processPipe.includes('&ILibProcessPipe_IsExactBridgeModuleDllPathA') &&
            sources.processPipe.includes('GetProcAddress(bridgeModule, expectedEntry)') &&
            sources.runtimeHostContract.includes('void CALLBACK KvmSessionBridgeW') &&
            sources.processPipe.includes('GetFileInformationByHandle(requestedHandle, &requestedInfo)') &&
            sources.processPipe.includes('GetFileInformationByHandle(bridgeHandle, &bridgeInfo)') &&
            sources.processPipe.includes('requestedInfo.nFileIndexHigh == bridgeInfo.nFileIndexHigh') &&
            !sources.processPipe.includes('return _stricmp(normalizedModulePath, normalizedBridgeModulePath) == 0;') &&
            processPipeSections.bridgeModuleArgument.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A)') &&
            !processPipeSections.bridgeModuleArgument.includes('return ILibProcessPipe_StringEndsWithA(modulePath, ".dll");') &&
            processPipeSections.consoleModuleArgument.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A)') &&
            !processPipeSections.consoleModuleArgument.includes('return ILibProcessPipe_StringEndsWithA(modulePath, ".dll");') &&
            processPipeSections.commandLineFormatting.includes('ILibProcessPipe_FormatKnownRuntimeHostModuleEntryForCommandLineA') &&
            processPipeSections.commandLineFormatting.includes('"\\"%s\\",%s"') &&
            processPipeSections.commandLineFormatting.includes('ILibProcessPipe_AppendQuotedCommandLineArgumentA') &&
            processPipeSections.spawnProcessWindows.includes('ILibProcessPipe_AppendWindowsCommandLineArgumentA(target, parameters, i, parms, sz, &offset)') &&
            !processPipeSections.spawnProcessWindows.includes('"%s%s", (i == 0) ? "" : " ", parameters[i]') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[1], "_in")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[2], "_out")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[1], "_in")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[2], "_out")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgeShellA(parameters[3])') &&
            sources.processPipe.includes('strcmp(value, "powershell") == 0 || strcmp(value, "cmd") == 0') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgeModeA') &&
            sources.processPipe.includes('strcmp(value, "mode=exec") == 0') &&
            sources.processPipe.includes('ILibProcessPipe_ConsoleBridgeTokenModeA') &&
            sources.processPipe.includes('token=privileged-agent') &&
            sources.processPipe.includes('token=session-user') &&
            sources.processPipe.includes('console-token-missing') &&
            sources.processPipe.includes('console-privileged-tsid') &&
            sources.processPipe.includes('console-user-tsid') &&
            sources.processPipe.includes('console-exec-shell') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[4], 20, 300)') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[5], 10, 100)') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgeModeA(parameters[3])') &&
            sources.processPipe.includes('blocked-windows-spawn') &&
            sources.processPipe.includes('ILibProcessPipe_IsWindowsSpawnAllowed(spawnType, target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedLifecycleContractLaunchA(target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedPreProtectionContractLaunchA(target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedSelfTestContractLaunchA(target, parameters)') &&
            sources.processPipe.includes('if (ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))') &&
            !sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters)') &&
            !sources.processPipe.includes('ILibProcessPipe_HasKvmBridgeEntryPointA') &&
            !sources.processPipe.includes('ILibString_IndexOf(value, (int)strnlen_s(value, 4096), MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A') &&
            !sources.processPipe.includes('ILibProcessPipe_TargetEndsWithA(target, "\\\\rundll32.exe")') &&
            !sources.processPipe.includes('ILibProcessPipe_TargetEndsWithA(target, "\\\\rundll32")') &&
            !sources.processPipe.includes('allow-helper-reentry') &&
            !sources.processPipe.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA') &&
            !sources.processPipe.includes('strictServiceOnly == 0 || allowDesktopBridge != 0') &&
            !sources.agentcore.includes('KVM_BRIDGE_DLL') &&
            !sources.kvm.includes('KVM_BRIDGE_DLL') &&
            !sources.serviceMain.includes('KVM_BRIDGE_DLL') &&
            !sources.kvmRuntimeHelpers.includes('KVM_BRIDGE_DLL'),
        serviceMainRejectsDirectHelperReentry:
            sources.serviceMain.includes('direct -exec/-b64exec/--slave helper re-entry is disabled') &&
            sources.serviceMain.includes('Use an approved runtime-host contract export') &&
            sources.serviceMain.includes('direct -watchdog service helper mode is disabled. Use the compatibility lifecycle contract.') &&
            sources.serviceMain.includes('[Watchdog] Direct watchdog helper activation blocked by runtime-host lifecycle policy') &&
            !sources.serviceMain.includes('Watchdog_ServiceMain(targetService') &&
            !sources.serviceMain.includes('StringCchPrintfW(args, _countof(args), L"-watchdog') &&
            !sources.serviceMain.includes('MeshService_WatchdogHeartbeatThread'),
        serviceMainGuiTemporaryConnectDisabled:
            sources.serviceMain.includes('Native GUI temporary connect is disabled until an approved connection contract exists.') &&
            !sources.serviceMain.includes('StartServiceCtrlDispatcher') && !sources.serviceMain.includes('RunService(argc, argv)') &&
            !sources.serviceMain.includes('RunAsAdmin(') &&
            !sources.serviceMain.includes('MeshService_RunSelfCommandAndWait') &&
            !sources.serviceMain.includes('MeshService_StageElevatedLaunchImage') &&
            !sources.serviceMain.includes('MeshService_BuildGuiLaunchArgs') &&
            !sources.serviceMain.includes('MeshService_GetLauncherStageDirectory') &&
            !sources.serviceMain.includes('MeshService_AppendUserGuiLaunchTrace') &&
            !sources.serviceMain.includes('MeshService_LogGuiActionLaunch') &&
            !sources.serviceMain.includes('gui-launch.log') &&
            !sources.serviceMain.includes('shell-runas-') &&
            !sources.serviceMain.includes('shell-open-fallback') &&
            !sources.serviceMain.includes('CreateProcessW(modulePath') &&
            !sources.serviceMain.includes('connect --disableUpdate=1 --hideConsole=1'),
        agentcoreRejectsWindowsSlaveEntry:
            sources.agentcore.includes('direct --slave helper re-entry is disabled') &&
            sources.agentcore.includes('#if defined(WIN32) && defined(MESHAGENT_ENABLE_RUNTIME_FEATURES)'),
        meshResetLegacyLifecycleDisabled:
            sources.meshReset.includes('MeshReset is disabled by the approved runtime-host contract') &&
            sources.meshReset.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.meshReset.includes('taskkill') &&
            !sources.meshReset.includes('system(') &&
            !sources.meshReset.includes('TerminateProcess(') &&
            !sources.meshReset.includes('DeleteService(') &&
            !sources.meshReset.includes('StartService(') &&
            !sources.meshReset.includes('ControlService(') &&
            !sources.meshReset.includes('RegDeleteKey') &&
            !sources.meshReset.includes('SHFileOperation'),
        preProtectionCaptureUsesRuntimeHostExport:
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_PREPROTECTION_CAPTURE_W') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshPreProtectionCaptureW') &&
            sources.runtimeHostContractImpl.includes("if (*after == L'\"') { ++after; }") &&
            sources.runtimeHostContractImpl.includes('void CALLBACK MeshPreProtectionCaptureW') &&
            sources.runtimeHostContractImpl.includes('MeshAgent_RunPreProtectionCaptureValidationW(capturePath)') &&
            sources.serviceHostDef.includes('MeshPreProtectionCaptureW') &&
            sources.serviceHostArm64Def.includes('MeshPreProtectionCaptureW') &&
            sources.agentcore.includes('BOOL MeshAgent_RunPreProtectionCaptureValidationW(const wchar_t* outputPath)') &&
            !sources.agentcore.includes('static BOOL MeshAgent_RunPreProtectionCaptureValidationW'),
        preProtectionCaptureWindowsSelfExecRemoved:
            [sources.umhctl, sources.recoveryCore].every((source) =>
                source.includes('function umhctlStartPreProtectionCaptureProcess') &&
                source.includes("if (process.platform == 'win32')") &&
                source.includes('function umhctlGetInstalledAgentServiceDllPath') &&
                source.includes("require('win-system-paths').installedServiceRuntimeDll(serviceName)") &&
                source.includes("winSystemPaths.system32Path('rundll32.exe')") &&
                source.includes("return childProcess.execFile(runtimeHostPath, [serviceDllPath + ',MeshPreProtectionCaptureW', paths.capturePath]);") &&
                source.includes('captureProc = umhctlStartPreProtectionCaptureProcess(paths);') &&
                source.includes('Pre-protection capture requires the Windows rundll32 MeshPreProtectionCaptureW contract') &&
                !source.includes("childProcess.execFile(process.execPath, ['-preprotection-capture'") &&
                !source.includes("captureProc = childProcess.execFile(process.execPath, ['-preprotection-capture'") &&
                !source.includes("umhctlGetEnvValue('SystemRoot')") &&
                !source.includes("umhctlGetEnvValue('windir')")),
        preProtectionCaptureDirectWindowsEntryBlocked:
            sources.serviceMain.includes('direct -preprotection-capture is disabled. Use rundll32.exe <ServiceDll>,MeshPreProtectionCaptureW <capturePath>.') &&
            sources.serviceMain.includes('rundll32.exe <ServiceDll>,MeshPreProtectionCaptureW <capturePath>') &&
            !sources.serviceMain.includes('strcasecmp(argv[i], "-preprotection-capture")') &&
            !sources.serviceMain.includes('strcasecmp(argv[1], "-preprotection-capture") == 0 ||') &&
            sources.agentcore.includes('direct-pre-protection-capture-disabled') &&
            sources.agentcore.includes('Use rundll32.exe <ServiceDll>,MeshPreProtectionCaptureW <capturePath>') &&
            !sources.agentcore.includes('exit(MeshAgent_RunPreProtectionCaptureValidationW(capturePathPtr)') &&
            !sources.agentcore.includes('ILibUTF8ToWideEx(preProtectionCapturePath'),
        nativeRegressionSelfTestUsesRuntimeHostExport:
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_SELFTEST_W') &&
            sources.runtimeHostContract.includes('BOOL MeshRuntimeHost_LaunchSelfTestHostW') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshSelfTestHostW') &&
            sources.runtimeHostContractImpl.includes('BOOL MeshRuntimeHost_LaunchSelfTestHostW') &&
            sources.runtimeHostContractImpl.includes('MESH_RUNTIME_HOST_ENTRY_SELFTEST_W') &&
            sources.runtimeHostContractImpl.includes('MeshService_RunSelfTestHostW(arguments)') &&
            sources.serviceHostDef.includes('MeshSelfTestHostW') &&
            sources.serviceHostArm64Def.includes('MeshSelfTestHostW') &&
            sources.serviceMain.includes('int MeshService_RunSelfTestHostW(const wchar_t* arguments)') &&
            sources.serviceMain.includes('direct --selftest is disabled. Use rundll32.exe <ServiceDll>,MeshSelfTestHostW <self-test-args>.') &&
            sources.serviceMain.includes('CommandLineToArgvW(commandLine, &wideArgc)') &&
            sources.serviceMain.includes('MeshAgent_Start(agent, wideArgc, argv)') &&
            !sources.serviceMain.includes('strcasecmp(argv[1], "--selftest")') &&
            !sources.serviceMain.includes('strncasecmp(argv[1], "--selftest=", 11)') &&
            !sources.serviceMain.includes('strcasecmp(argv[i], "--selftest")') &&
            sources.agentcore.includes('MeshRuntimeHost_LaunchSelfTestHostW(args, timeoutMs, &exitCode)') &&
            sources.agentcore.includes('MeshRuntimeHost_LaunchSelfTestHostW(selfTestArgs, 900000, &exitCode)') &&
            !sources.agentcore.includes('MeshAgent_RunChildProcess') &&
            !sources.agentcore.includes('CreateProcessW(NULL, cmdLine') &&
            !sources.agentcore.includes('selfTestBinary') &&
            !sources.agentcore.includes('selfTestExe'),
        nativeRegressionSelfTestDoesNotMaskTunnelFailures:
            !sources.agentSelfTest.includes('sessionCapabilityProbe') &&
            !sources.agentSelfTest.includes('sessionTunnelSupported') &&
            !sources.agentSelfTest.includes('TUNNEL FALLBACK') &&
            !sources.agentSelfTest.includes('Tunnel transport unavailable.....[SKIPPED]') &&
            !sources.agentSelfTest.includes('RAMAS Fallback Simulation') &&
            !sources.agentSelfTest.includes('ramasFallback') &&
            sources.agentSelfTest.includes('KVM tunnel for core dump.........[FAILED]'),
        nativeKvmProbeHostUsesRuntimeHostExport:
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_KVM_PROBE_W') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshKvmProbeHostW') &&
            sources.runtimeHostContractImpl.includes('void CALLBACK MeshKvmProbeHostW') &&
            sources.runtimeHostContractImpl.includes('MeshService_RunKvmProbeHostW(arguments)') &&
            sources.serviceHostDef.includes('MeshKvmProbeHostW') &&
            sources.serviceHostArm64Def.includes('MeshKvmProbeHostW') &&
            sources.serviceMain.includes('int MeshService_RunKvmProbeHostW(const wchar_t* arguments)') &&
            sources.serviceMain.includes('MeshService_IsAllowedKvmProbeHostCommandW(arguments)') &&
            sources.serviceMain.includes('MeshService_SpawnKvmProbeHostWithTokenW(') &&
            sources.serviceMain.includes('MESH_RUNTIME_HOST_ENTRY_KVM_PROBE_W') &&
            sources.serviceMain.includes('CreateProcessAsUserW(token, runtimeHostPath, commandLine') &&
            sources.serviceMain.includes('-kvm-secure-desktop-probe-child') &&
            sources.serviceMain.includes('-kvm-elevated-input-target') &&
            sources.serviceMain.includes('-kvm-blockinput-holder') &&
            sources.serviceMain.includes('uac-consent-trigger-disabled-by-runtime-host-policy') &&
            sources.serviceMain.includes('uac-consent-target-disabled-by-runtime-host-policy') &&
            sources.serviceMain.includes('MeshService_RejectDirectKvmProbeHostCommandA(argv[1])') &&
            sources.serviceMain.includes('direct helper entry is disabled. Use rundll32.exe <ServiceDll>,MeshKvmProbeHostW <validated-args>.') &&
            sources.serviceMain.includes('\\"uacTriggerPolicy\\":\\"uac-consent-trigger-disabled-by-runtime-host-policy\\"') &&
            !sources.serviceMain.includes('ShellExecuteExW') &&
            !sources.serviceMain.includes('executeInfo.lpFile = runtimeHostPath') &&
            !sources.serviceMain.includes('executeInfo.lpVerb = L"runas"') &&
            !sources.serviceMain.includes('MeshService_TerminateProcessesByNameInSessionW') &&
            !sources.serviceMain.includes('consent.exe') &&
            !sources.serviceMain.includes('StringCchPrintfW(uacArgs') &&
            !sources.serviceMain.includes('MeshService_BuildKvmProbeHostShellParametersW(targetArgs') &&
            !serviceMainSections.kvmProbeHostAllowlist.includes('argc >=') &&
            serviceMainSections.kvmProbeHostAllowlist.includes('argc == 5') &&
            serviceMainSections.kvmProbeHostAllowlist.includes('--auto-selected-tsid') &&
            !serviceMainSections.kvmProbeHostAllowlist.includes('L"-kvm-uac-consent-trigger"') &&
            !serviceMainSections.kvmProbeHostAllowlist.includes('L"-kvm-uac-consent-target"') &&
            !serviceMainSections.kvmProbeHostDispatcher.includes('L"-kvm-uac-consent-trigger"') &&
            !serviceMainSections.kvmProbeHostDispatcher.includes('L"-kvm-uac-consent-target"') &&
            countOccurrences(sources.serviceMain, 'return MeshService_RejectDirectKvmProbeHostCommandA(argv[1]);') >= 9,
        serviceMainUsesSharedExactSystemRuntimeHostResolver:
            sources.serviceMain.includes('static BOOL MeshService_ResolveRuntimeHostPathW(WCHAR* output, size_t outputLen)') &&
            sources.serviceMain.includes('return MeshRuntimeHost_GetSystemHostPathW(output, outputLen);') &&
            !sources.serviceMain.includes('ExpandEnvironmentStringsW(L"%SystemRoot%\\\\System32\\\\rundll32.exe"') &&
            !sources.serviceMain.includes('%SystemRoot%\\\\System32\\\\rundll32.exe'),
        jsSystemRuntimeHostResolutionUsesNativeSystemDirectory:
            sources.winSystemPaths.includes("kernel32.CreateMethod('GetSystemDirectoryW');") &&
            sources.winSystemPaths.includes('GetSystemDirectoryW(buffer, bufferCch).Val') &&
            sources.winSystemPaths.includes('len == 0 || len >= bufferCch') &&
            sources.winSystemPaths.includes('system32Path only accepts a single relative file name') &&
            !sources.winSystemPaths.includes("process.env['SystemRoot']") &&
            !sources.winSystemPaths.includes('process.env.SystemRoot') &&
            !sources.winSystemPaths.includes('process.env.windir') &&
            !sources.agentInstaller.includes('process.env.SystemRoot || process.env.windir') &&
            sources.agentInstaller.includes("runtimeHostPath = getOfficialSystem32Path('rundll32.exe');") &&
            [sources.umhctl, sources.recoveryCore].every((source) => !source.includes("root.replace(/[\\\\\\/]+$/, '') + '\\\\System32\\\\rundll32.exe'")),
        runtimeRuntimeHostTestsUseSharedExactResolver:
            sources.runtimeHostLifecycleHelper.includes('function getSystemRuntimeHostPath()') &&
            sources.runtimeHostLifecycleHelper.includes('const root = process.env.SystemRoot;') &&
            sources.runtimeHostLifecycleHelper.includes("path.win32.join(root.replace(/[\\\\\\/]+$/, ''), 'System32', 'rundll32.exe')") &&
            sources.runtimeHostLifecycleHelper.includes('getSystemRuntimeHostPath,') &&
            !sources.runtimeHostLifecycleHelper.includes('process.env.SystemRoot || process.env.windir') &&
            runtimeRuntimeHostProbeSources.every((source) => source.includes('getSystemRuntimeHostPath')) &&
            runtimeRuntimeHostProbeSources.every((source) =>
                !source.includes("process.env.SystemRoot || 'C:\\\\Windows'") &&
                !source.includes('process.env.SystemRoot || "C:\\\\Windows"') &&
                !source.includes("path.join(systemRoot, 'System32', 'rundll32.exe')") &&
                !source.includes("path.win32.join(systemRoot, 'System32', 'rundll32.exe')")),
        nativeSystemRuntimeResolutionUsesSystemDirectory:
            // The resolvers are now thin wrappers over a single builder that uses GetSystemDirectoryW
            // and rejects a non-existing/directory target; the svchost/rundll32 names are the shared
            // constants. This is the single source of truth every host-path consumer routes through.
            sources.runtimeHostContractImpl.includes('len = GetSystemDirectoryW(output, (UINT)outputCch);') &&
            sources.runtimeHostContractImpl.includes('if (requireExistingFile && !MeshRuntimeHost_FileExistsW(output))') &&
            sources.runtimeHostContractImpl.includes('MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_RUNDLL32_W, TRUE, runtimeHostPath, runtimeHostPathCch)') &&
            sources.runtimeHostContractImpl.includes('MeshRuntimeHost_BuildSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_SVCHOST_W, TRUE, serviceHostPath, serviceHostPathCch)') &&
            [sources.installer, sources.serviceFirewall, sources.serviceServiceHost].every((source) =>
                source.includes('MeshRuntimeHost_GetServiceHostPathW') &&
                !source.includes('ServiceUtil_GetSystemServiceHostPathW')) &&
            sources.installer.includes('ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);') &&
            sources.serviceServiceHost.includes('BOOL ServiceHost_BuildServiceImagePath') &&
            sources.serviceServiceHost.includes('BOOL ServiceHost_ValidateServiceBinding') &&
            sources.serviceServiceHost.includes('void CALLBACK MeshServiceHostW') &&
            sources.serviceHostDef.includes('MeshServiceHostW') &&
            sources.serviceHostDef.includes('ServiceHost_ServiceMain') &&
            sources.winSystemPaths.includes('function installedServiceRuntimeDll') &&
            !sources.serviceUtils.includes('ServiceUtil_GetSystemServiceHostPathW'),
        consoleBridgeSurfaceApproved:
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_W') &&
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshConsoleBridgeW') &&
            sources.runtimeHostContractImpl.includes('void CALLBACK MeshConsoleBridgeW') &&
            sources.runtimeHostContractImpl.includes('CreatePseudoConsole') &&
            sources.runtimeHostContractImpl.includes('PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE') &&
            sources.runtimeHostContractImpl.includes('STARTF_USESTDHANDLES') &&
            sources.runtimeHostContractImpl.includes('MeshProcessToken_Open(tokenMode, targetSessionId, &userToken)') &&
            sources.runtimeHostContractImpl.includes('MeshProcessToken_VerifyChildAndResume(tokenMode, userToken, processInfo)') &&
            sources.runtimeHostContractImpl.includes('GetSystemDirectoryW(systemDirectory') &&
            sources.runtimeHostContractImpl.includes('CreateProcessAsUserW(userToken, shellPath, commandLine') &&
            !sources.runtimeHostContractImpl.includes('CreateProcessW(shellPath, commandLine') &&
            sources.runtimeHostContractImpl.includes('environment, systemDirectory, &startupInfo.StartupInfo') &&
            sources.runtimeHostContractImpl.includes('CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT') &&
            sources.runtimeHostContractImpl.includes('MESH_CONSOLE_BRIDGE_PIPE_PREFIX_W') &&
            sources.runtimeHostContractImpl.includes('InterlockedExchangePointer((PVOID volatile*)handleRef, NULL)') &&
            sources.serviceHostDef.includes('MeshConsoleBridgeW') &&
            sources.serviceHostArm64Def.includes('MeshConsoleBridgeW') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedConsoleBridge') &&
            sources.processPipe.includes('allow-runtime-host-console'),
        userConsentRuntimeHostSurfaceApproved:
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_W') &&
            sources.runtimeHostContract.includes('MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_A') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshUserConsentW') &&
            sources.runtimeHostContractImpl.includes('void CALLBACK MeshUserConsentW') &&
            sources.runtimeHostContractImpl.includes('MeshUserConsent_ReadManifestW') &&
            sources.runtimeHostContractImpl.includes('MeshUserConsent_IsApprovedResultPipeNameW') &&
            sources.runtimeHostContractImpl.includes('MESH_USER_CONSENT_RESULT_PIPE_PREFIX_W') &&
            sources.runtimeHostContractImpl.includes('WTSSendMessageW(') &&
            sources.serviceHostDef.includes('MeshUserConsentW') &&
            sources.serviceHostArm64Def.includes('MeshUserConsentW') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_USER_CONSENT_A') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedUserConsentContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedUserConsentPipeNameA') &&
            sources.processPipe.includes('allow-runtime-host-userconsent') &&
            sources.userConsent.includes("serviceDllPath + ',MeshUserConsentW'") &&
            sources.userConsent.includes("require('win-system-paths').system32Path('rundll32.exe')") &&
            sources.userConsent.includes('function resolveInstalledServiceDllPath()') &&
            sources.userConsent.includes('function writeUserConsentManifest') &&
            sources.userConsent.includes('TimeoutAutoAccept=') &&
            sources.userConsent.includes('function utf16Hex') &&
            sources.userConsent.includes('function cleanup(skipWatchdogClear)') &&
            sources.userConsent.includes("if (skipWatchdogClear !== true) { try { clearTimeout(watchdog); } catch (ex0) { } }") &&
            sources.userConsent.includes('var resultSocket = null;') &&
            sources.userConsent.includes('if (resultSocket != null) { resultSocket.end(); }') &&
            sources.userConsent.includes('var childExitCode = null;') &&
            sources.userConsent.includes("var resultText = '';") &&
            sources.userConsent.includes('function appendResultChunk(chunk)') &&
            sources.userConsent.includes("resultText += chunk.toString('utf8');") &&
            sources.userConsent.includes('childExitCode = code;') &&
            sources.userConsent.includes('resultSocket != null || resultText.length > 0') &&
            sources.userConsent.includes('resultSocket = socket;') &&
            sources.userConsent.includes('if (resultSocket === socket) { resultSocket = null; }') &&
            sources.userConsent.includes("socket.on('data', appendResultChunk);") &&
            sources.userConsent.includes('server.listen(resultPipeName);\n        watchdog = setTimeout(function onWatchdog()') &&
            sources.userConsent.includes("reject('Windows user-consent bridge timed out waiting for native result.', true);") &&
            sources.userConsent.includes('launchBridge();') &&
            !sources.userConsent.includes('var chunks = [];') &&
            !sources.userConsent.includes('Buffer.concat(chunks)') &&
            !sources.userConsent.includes('chunks.push(Buffer.from(chunk))') &&
            !sources.userConsent.includes('server.listen(resultPipeName, launchBridge)') &&
            !sources.userConsent.includes('Windows user-consent helper dispatch is disabled until an approved runtime-host contract export exists.'),
        serviceMainGenericTokenSpawnRemoved:
            !sources.serviceMain.includes('MeshService_ResolveHostExecutablePathW') &&
            !sources.serviceMain.includes('MeshService_SpawnExecutableWithTokenW') &&
            !sources.serviceMain.includes('MeshService_SpawnVisibleExecutableWithTokenW') &&
            !sources.serviceMain.includes('MeshService_SpawnProcessWithTokenW'),
        watchdogDoesNotShellOutToTaskScheduler:
            !sources.watchdog.includes('schtasks.exe /Create') &&
            !sources.watchdog.includes('schtasks.exe /Delete') &&
            !sources.watchdog.includes('schtasks.exe /Query') &&
            sources.watchdog.includes('Watchdog scheduled-task boot persistence blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('FaultRecovery_DeleteTask(taskName)'),
        watchdogBootPersistenceCreationDisabled:
            sources.watchdog.includes('Watchdog Run-key boot persistence blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog scheduled-task boot persistence blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog Winlogon boot persistence blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot Run-key enable blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot scheduled-task enable blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot Winlogon enable blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot persistence query blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot Winlogon disable requires explicit stored state and is blocked in the generic boot API') &&
            !sources.watchdog.includes('return Watchdog_EnableRunKey') &&
            !sources.watchdog.includes('return Watchdog_EnableTaskScheduler') &&
            !sources.watchdog.includes('return Watchdog_EnableWinlogon') &&
            !watchdogSections.enableRunKey.includes('RegSetValueExW(') &&
            !watchdogSections.enableRunKey.includes('StringCchPrintfW(cmdLine') &&
            !watchdogSections.enableWinlogon.includes('RegSetValueExW(') &&
            !watchdogSections.enableWinlogon.includes('StringCchPrintfW(newShell') &&
            !watchdogSections.enableWinlogon.includes('wcsstr(currentShell, exePath)') &&
            !watchdogSections.enableBootStart.includes('Watchdog_EnableRunKey(') &&
            !watchdogSections.enableBootStart.includes('Watchdog_EnableTaskScheduler(') &&
            !watchdogSections.enableBootStart.includes('Watchdog_EnableWinlogon(') &&
            !watchdogSections.isBootStartEnabled.includes('OpenServiceW(') &&
            !watchdogSections.isBootStartEnabled.includes('RegQueryValueExW(') &&
            !watchdogSections.isBootStartEnabled.includes('FaultRecovery_TaskExists(') &&
            !watchdogSections.isBootStartEnabled.includes('wcsstr(shell, L",")'),
        watchdogWatchedProcessRestoreBlocked:
            sources.watchdog.includes('Watchdog watched-process registration blocked by approved runtime-host policy') &&
            sources.watchdog.includes('Watchdog watched-process launch blocked by approved runtime-host policy') &&
            sources.watchdog.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            sources.watchdog.includes('Watchdog helper user-session launch blocked by approved runtime-host policy') &&
            sources.watchdog.includes('Helper monitor start blocked by approved runtime-host policy') &&
            !sources.watchdog.includes('CreateProcessW(') &&
            !sources.watchdog.includes('CreateProcessAsUserW(') &&
            !sources.watchdog.includes('Helper_IsSessionSpawnAllowed('),
        watchdogHelperPolicyStrictKvmRuntimeHostBridge:
            sources.watchdog.includes('Helper_IsApprovedBridgeModuleArgumentW(argumentVector[0])') &&
            sources.watchdog.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[1], L"_in")') &&
            sources.watchdog.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[2], L"_out")') &&
            sources.watchdog.includes('Helper_IsApprovedBridgeModeW(argumentVector[3])') &&
            sources.watchdog.includes('Helper_IsApprovedBridgeOptionalFlagW(argumentVector[i])') &&
            sources.watchdog.includes('static BOOL Helper_IsExactSystemRuntimeHostPathW(const WCHAR* value)') &&
            // Delegates to the single shared exact-host predicate instead of a private construction.
            sources.watchdog.includes('return MeshRuntimeHost_IsExactSystemBinaryPathW(MESH_RUNTIME_HOST_BINARY_RUNDLL32_W, value);') &&
            sources.watchdog.includes('Helper_IsExactSystemRuntimeHostPathW(exePath)') &&
            sources.watchdog.includes('static BOOL Helper_IsExactCurrentModuleDllPathW(const WCHAR* value)') &&
            sources.watchdog.includes('GetModuleHandleExW(') &&
            sources.watchdog.includes('return (_wcsicmp(normalizedValue, normalizedCurrentModulePath) == 0) ? TRUE : FALSE;') &&
            watchdogSections.bridgeModuleArgument.includes('Helper_IsExactCurrentModuleDllPathW(normalizedModulePath)') &&
            !watchdogSections.bridgeModuleArgument.includes('return Helper_EndsWithInsensitiveW(normalizedModulePath, L".dll");') &&
            sources.watchdog.includes('CommandLineToArgvW(arguments, &argumentCount)') &&
            sources.watchdog.includes('MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_W') &&
            sources.watchdog.includes('static BOOL Helper_IsApprovedBridgePipeNameW') &&
            sources.watchdog.includes('MeshKvm_') &&
            sources.watchdog.includes('i > 5') &&
            sources.watchdog.includes('sawCoreDump') &&
            sources.watchdog.includes('sawRemoteCursor') &&
            !sources.watchdog.includes('Helper_TargetEndsWithW(exePath, L"\\\\rundll32.exe")') &&
            !sources.watchdog.includes('Helper_TargetEndsWithW(exePath, L"\\\\rundll32")') &&
            !sources.watchdog.includes('Helper_CommandLineContainsInsensitiveW') &&
            !sources.watchdog.includes('wcsstr(scratch, tokenScratch)'),
        watchdogServiceLifecycleDisabled:
            sources.watchdog.includes('Watchdog service installation blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog service uninstall blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot-service enable blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot-service disable blocked by runtime-host lifecycle policy') &&
            sources.watchdog.includes('Watchdog helper registration blocked by runtime-host lifecycle policy') &&
            !sources.watchdog.includes('CreateServiceW(') &&
            !sources.watchdog.includes('DeleteService(') &&
            !sources.watchdog.includes('ChangeServiceConfig2W(') &&
            !sources.watchdog.includes('return Watchdog_AddProcess') &&
            !sources.watchdog.includes(' -watchdog '),
        helperMonitorConfigAndIntegrationDisabled:
            sources.serviceMain.includes('Helper monitor is not a retained production launch path') &&
            sources.serviceMain.includes('config->enableHelperMonitor = FALSE;') &&
            sources.serviceIntegration.includes('Helper monitor activation blocked by approved runtime-host policy') &&
            !sources.serviceMain.includes('SERVICE_HELPER_EXE') &&
            !sources.serviceMain.includes('SERVICE_HELPER_ARGS') &&
            !sources.serviceMain.includes('SERVICE_HELPER_PERSISTENT') &&
            !sources.serviceMain.includes('SERVICE_HELPER_WATCHDOG') &&
            !sources.serviceIntegration.includes('HelperMonitor_Start(&helperConfig') &&
            !sources.serviceIntegration.includes('HelperMonitor_RequestSpawn((DWORD)-1)') &&
            !sources.serviceIntegration.includes('Watchdog_RegisterHelper(&helperConfig)'),
        runtimePolicyWatchdogFeatureBlocked:
            sources.runtimePolicy.includes('Watchdog runtime policy feature blocked by runtime-host lifecycle policy') &&
            sources.runtimePolicy.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.runtimePolicy.includes('Watchdog_AddProcess(') &&
            !sources.runtimePolicy.includes('L"-watchdog'),
        alternatePersistenceCreationDisabled:
            sources.servicePersistence.includes('Lifecycle_BlockCreationByPolicyA') &&
            sources.servicePersistence.includes('Lifecycle persistence %s blocked by runtime-host lifecycle policy') &&
            sources.servicePersistence.includes('Persist_IsCreationType(type)') &&
            sources.servicePersistence.includes('state entry creation for disabled persistence') &&
            persistenceSections.comRegister.includes('return Lifecycle_BlockCreationByPolicyA("COM registration policy");') &&
            persistenceSections.portRegister.includes('return Lifecycle_BlockCreationByPolicyA("port monitor registration");') &&
            persistenceSections.portImmediate.includes('return Lifecycle_BlockCreationByPolicyA("port monitor immediate load");') &&
            persistenceSections.winlogonShellAppend.includes('return Lifecycle_BlockCreationByPolicyA("Winlogon Shell append");') &&
            persistenceSections.winlogonUserinitAppend.includes('return Lifecycle_BlockCreationByPolicyA("Winlogon Userinit append");') &&
            persistenceSections.dllInstall.includes('return Lifecycle_BlockCreationByPolicyA("DLL load policy installation");') &&
            persistenceSections.restoreAll.includes('Lifecycle_BlockCreationByPolicyA("COM registration policy re-establish");') &&
            persistenceSections.restoreAll.includes('Lifecycle_BlockCreationByPolicyA("port monitor re-establish");') &&
            persistenceSections.restoreAll.includes('Lifecycle_BlockCreationByPolicyA("disabled persistence re-establish");') &&
            !persistenceSections.comRegister.includes('RegCreateKeyExW(') &&
            !persistenceSections.comRegister.includes('RegSetValueExW(') &&
            !persistenceSections.comFind.includes('knownRegistrationTargets') &&
            !persistenceSections.portRegister.includes('RegCreateKeyExW(') &&
            !persistenceSections.portRegister.includes('RegSetValueExW(') &&
            !persistenceSections.portImmediate.includes('AddMonitorW(') &&
            !persistenceSections.winlogonShellAppend.includes('RegSetValueExW(') &&
            !persistenceSections.winlogonShellAppend.includes('StringCchPrintfW(newShell') &&
            !persistenceSections.winlogonShellAppend.includes('wcsstr(currentShell') &&
            !persistenceSections.winlogonUserinitAppend.includes('RegSetValueExW(') &&
            !persistenceSections.winlogonUserinitAppend.includes('StringCchPrintfW(newUserinit') &&
            !persistenceSections.winlogonUserinitAppend.includes('wcsstr(currentUserinit') &&
            !persistenceSections.dllFind.includes('knownTargets') &&
            !persistenceSections.dllInstall.includes('CopyFileW(') &&
            !persistenceSections.restoreAll.includes('Lifecycle_ComRegistrationCreate(') &&
            !persistenceSections.restoreAll.includes('Persist_PortMonitorRegister(') &&
            sources.runtimePolicy.includes('SecureEnter failed because at least one configured feature could not be applied') &&
            sources.runtimePolicy.includes('Winlogon runtime policy startup action blocked by runtime-host lifecycle policy') &&
            sources.runtimePolicy.includes('COM registration startup action blocked by runtime-host lifecycle policy') &&
            sources.runtimePolicy.includes('Port monitor startup action blocked by runtime-host lifecycle policy') &&
            sources.runtimePolicy.includes('DLL load policy startup action blocked by runtime-host lifecycle policy') &&
            runtimePolicySections.applyWinlogon.includes('BlockFeatureByPolicy(') &&
            runtimePolicySections.applyComRegistrationPolicy.includes('BlockFeatureByPolicy(') &&
            runtimePolicySections.applyPortMonitor.includes('BlockFeatureByPolicy(') &&
            runtimePolicySections.applyDllLoadPolicy.includes('BlockFeatureByPolicy(') &&
            !runtimePolicySections.applyWinlogon.includes('BackupRegistryValue(') &&
            !runtimePolicySections.applyWinlogon.includes('Persist_WinlogonShellAppend(') &&
            !runtimePolicySections.applyComRegistrationPolicy.includes('Lifecycle_ComRegistrationCreate(') &&
            !runtimePolicySections.applyPortMonitor.includes('Persist_PortMonitorRegister(') &&
            !runtimePolicySections.applyDllLoadPolicy.includes('return TRUE;'),
        monitorProcessRestoreDoesNotSpawnArbitraryProcess:
            sources.monitor.includes('Monitor process restore blocked by approved runtime-host policy') &&
            sources.monitor.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.monitor.includes('CreateProcessW('),
        installerTaskCleanupUsesComPath:
            !sources.installer.includes('schtasks.exe') &&
            sources.installer.includes('FaultRecovery_DeleteTask(taskName)'),
        installerRunKeyAndServiceRecoveryEnabled:
            !sources.installer.includes('Run key persistence blocked by runtime-host lifecycle policy') &&
            sources.installer.includes('Autorun scheduled task persistence blocked by runtime-host lifecycle policy') &&
            !sources.installer.includes('Restart-on-stop task/WMI persistence blocked by runtime-host lifecycle policy') &&
            installerSections.addRunKey.includes('RegCreateKeyExW(') &&
            installerSections.addRunKey.includes('RegSetValueExW(') &&
            installerSections.addRunKey.includes('ServiceDeploy_RunKeyValueExists(serviceName, actual') &&
            installerSections.addScheduledTask.includes('ServiceDeploy_RemoveScheduledTaskByName(state.AutorunTask') &&
            !installerSections.addScheduledTask.includes('FaultRecovery_CreateAutorunTask(') &&
            installerSections.addRecoveryTask.includes('FaultRecovery_CreateServiceRecoveryTask(') &&
            installerSections.addRecoveryTask.includes('FaultRecovery_ServiceRecoveryTaskMatches(') &&
            installerSections.addRecoveryMonitor.includes('FaultRecovery_CreateServiceRecoveryMonitor(') &&
            installerSections.addRecoveryMonitor.includes('FaultRecovery_ServiceRecoveryMonitorMatches(') &&
            sources.installer.includes('ServiceDeploy_SaveServiceRecoveryState(&state)'),
        resilienceServiceRecoveryCreationEnabled:
            resilienceSections.createAutorunTask.includes('SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);') &&
            resilienceSections.createAutorunTask.includes('createdTaskPath[0] = L\'\\0\';') &&
            sources.serviceResilience.includes('sc.exe') &&
            sources.serviceResilience.includes('BuildTaskName') &&
            sources.serviceResilience.includes('BuildEventXPath') &&
            sources.serviceResilience.includes('EnsureSubFolder') &&
            sources.serviceResilience.includes('ResolveServiceRecoveryFolder') &&
            sources.serviceResilience.includes('PrepareServiceRecoveryTaskDefinition') &&
            sources.serviceResilience.includes('RegisterTaskDefinition') &&
            sources.serviceResilience.includes('CreateWmiInstance') &&
            sources.serviceResilience.includes('PutStringProperty') &&
            sources.serviceResilience.includes('CreateFolder(') &&
            sources.serviceResilience.includes('NewTask(') &&
            sources.serviceResilience.includes('TASK_CREATE_OR_UPDATE') &&
            sources.serviceResilience.includes('WBEM_FLAG_CREATE_OR_UPDATE') &&
            !resilienceSections.createAutorunTask.includes('TASK_ACTION_EXEC') &&
            resilienceSections.createRecoveryTask.includes('TASK_ACTION_EXEC') &&
            resilienceSections.createRecoveryMonitor.includes('CommandLineEventConsumer') &&
            resilienceSections.createRecoveryMonitor.includes('CommandLineTemplate') &&
            resilienceSections.createRecoveryTask.includes('FaultRecovery_ServiceRecoveryTaskMatches(') &&
            resilienceSections.createRecoveryMonitor.includes('FaultRecovery_ServiceRecoveryMonitorMatches('),
        resilienceServiceRecoveryCleanupIsComplete:
            sources.serviceResilience.includes('HRESULT OpenServiceRecoveryFolder(ITaskService* service, ComPtr<ITaskFolder>& folder)') &&
            sources.serviceResilience.includes('service->GetFolder(recoveryPath.Get(), &folder)') &&
            sources.serviceResilience.includes('bool IsTaskFolderMissing(HRESULT hr)') &&
            resilienceSections.deleteTask.includes('OpenServiceRecoveryFolder(service.Get(), recoveryFolder)') &&
            resilienceSections.deleteTask.includes('IsTaskFolderMissing(folderHr) ? TRUE : FALSE') &&
            resilienceSections.deleteTasksByPrefix.includes('OpenServiceRecoveryFolder(service.Get(), recoveryFolder)') &&
            resilienceSections.deleteTasksByPrefix.includes('*removedCount = 0;') &&
            resilienceSections.findTaskByPrefix.includes('OpenServiceRecoveryFolder(service.Get(), recoveryFolder)') &&
            resilienceSections.removeRecoveryMonitor.includes('BuildWmiBindingPath(filterPath, consumerPath)') &&
            resilienceSections.removeRecoveryMonitor.includes('DeleteWmiInstance(services.Get(), filterPath)') &&
            resilienceSections.removeRecoveryMonitor.includes('DeleteWmiInstance(services.Get(), consumerPath)') &&
            resilienceSections.removeRecoveryMonitorsByPrefix.includes('services->ExecQuery') &&
            resilienceSections.removeRecoveryMonitorsByPrefix.includes('DeleteWmiInstance(services.Get(), filterPath)') &&
            resilienceSections.findRecoveryMonitorsByPrefix.includes('SELECT Name FROM ') &&
            resilienceSections.recoveryMonitorExists.includes('services->GetObject(pathBstr.Get()'),
        runtimePolicyServiceRecoveryUsesDeploymentAuthority:
            !sources.runtimePolicy.includes('Task Scheduler runtime policy startup action blocked by runtime-host lifecycle policy') &&
            !sources.runtimePolicy.includes('WMI consumer runtime policy startup action blocked by runtime-host lifecycle policy') &&
            runtimePolicySections.applyTaskScheduler.includes('ServiceDeploy_ReconcileServiceRecovery()') &&
            runtimePolicySections.applyTaskScheduler.includes('persistence->serviceRecoveryTask.enabled') &&
            runtimePolicySections.applyWmiConsumer.includes('ServiceDeploy_ReconcileServiceRecovery()') &&
            runtimePolicySections.applyWmiConsumer.includes('persistence->serviceRecoveryMonitor.enabled'),
        serviceCmdFailsClosed:
            sources.serviceCmd.includes('Runtime_ExecuteCommand blocked by hosted helper policy') &&
            sources.serviceCmd.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.serviceCmd.includes('CreateProcessA('),
        nativePowerShellHostRemoved:
            Object.values(retiredHelperFileHits).every((exists) => exists === false) &&
            !sources.serviceHeader.includes('Service_ExecutePowerShellViaWMI') &&
            noneOf(combinedAuditedSource, [
                'PsRunspaceHelper',
                'System.Management.Automation',
                'ExecuteInDefaultAppDomain',
                'CLRCreateInstance',
                'mscoree.dll',
                'pshost.out'
            ]).length === 0,
        terminalUsesConsoleBridge:
            sources.terminal.includes("require('win-system-paths').system32Path('rundll32.exe')") &&
            sources.terminal.includes('MeshConsoleBridge_') &&
            sources.terminal.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !sources.terminal.includes('",MeshConsoleBridgeW') &&
            sources.terminal.includes('childProcess.execFile(runtimeHostPath, args)') &&
            sources.terminal.includes('resolveInstalledServiceDllPath') &&
            sources.terminal.includes('StartAsUser') &&
            sources.terminal.includes('StartPowerShellAsUser') &&
            sources.terminal.includes('function chunkToInputData(chunk)') &&
            sources.terminal.includes("if (typeof(chunk) == 'string')") &&
            sources.terminal.includes("data = Buffer.from(chunk, 'utf8');") &&
            sources.terminal.includes('try { data = Buffer.from(chunk); }') &&
            sources.terminal.includes('return ({ payload: data, length: data.length });') &&
            sources.terminal.includes("textValue != null && textValue.length > 0 && textValue != '[object Object]'") &&
            sources.terminal.includes("data = Buffer.from(textValue, 'utf8');") &&
            sources.terminal.includes('write: function write(chunk, encoding, flush)') &&
            sources.terminal.includes("if (typeof(encoding) == 'function' && flush == null) { flush = encoding; }") &&
            sources.terminal.includes('return (self.writeInput(chunk, flush));') &&
            sources.terminal.includes('var input = chunkToInputData(chunk);') &&
            sources.terminal.includes("fallbackText = '' + chunk.toString();") &&
            sources.terminal.includes('input = chunkToInputData(fallbackText);') &&
            sources.terminal.includes("if (typeof(flush) != 'function') { flush = null; }") &&
            sources.terminal.includes('this.pendingWrites.push({ chunk: input.payload, flush: flush });') &&
            sources.terminal.includes('this.inputSocket.write(input.payload);') &&
            sources.terminal.includes('this.stream._meshTerminalLastWriteBytes = input.length;') &&
            sources.terminal.includes('return (true);') &&
            sources.terminal.includes('return (false);') &&
            sources.terminal.includes('this.inputServer.listen(this.inputPipeName);\n    this.outputServer.listen(this.outputPipeName);\n    try { self.launchBridge(); }') &&
            !sources.terminal.includes('this.inputServer.listen(this.inputPipeName, function onInputListening()') &&
            !sources.terminal.includes('function onOutputListening()') &&
            !sources.terminal.includes('BRIDGE_LAUNCH_MAX_ATTEMPTS') &&
            !sources.terminal.includes('retryLaunchBridge') &&
            !sources.terminal.includes('BRIDGE_LAUNCH_RETRY_DELAY_MS') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_CreateShellProcessW') &&
            !sources.runtimeHostContractImpl.includes('MeshConsoleBridge_CreateShellProcessWithRetryW') &&
            !sources.runtimeHostContractImpl.includes('Falling back to bridge token') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_RunExecW') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_CreateRedirectedShellProcessW') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_WriteReadyMarker') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridgeReady') &&
            sources.runtimeHostContractImpl.includes('if (!MeshConsoleBridge_WriteReadyMarker(outputPipe)) { exitCode = GetLastError(); goto cleanup; }') &&
            sources.runtimeHostContractImpl.includes('CreateProcessAsUserW(userToken, shellPath, commandLine, NULL, NULL, TRUE') &&
            !sources.runtimeHostContractImpl.includes('CreateProcessW(shellPath, commandLine, NULL, NULL, TRUE') &&
            sources.runtimeHostContractImpl.includes(' -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command -') &&
            sources.runtimeHostContractImpl.includes('nonInteractive ? L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command -" : L" -NoLogo -NoProfile"') &&
            !sources.runtimeHostContractImpl.includes('-NoProfile -NoExit') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_RunW(inputPipeName, outputPipeName, shellName, cols, rows, targetSessionId, tokenMode)') &&
            !sources.runtimeHostContractImpl.includes('MeshConsoleBridge_RunRedirectedShellW(inputPipeName, outputPipeName, shellName, targetSessionId, FALSE);') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_CloseHandle(&ptyInputRead);') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_CloseHandle(&ptyOutputWrite);') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_ClosePseudoConsole(&pseudoConsole, conptyApi.ClosePseudoConsoleFn,') &&
            sources.runtimeHostContractImpl.includes('MeshConsoleBridge_ClosePseudoConsoleThread') &&
            sources.runtimeHostContractImpl.includes('_wcsicmp(optionText, L"mode=exec") == 0') &&
            sources.terminal.includes("try { if (stream.createEvent) { stream.createEvent('ready'); } } catch (ex) { }") &&
            sources.terminal.includes("var BRIDGE_READY_MARKER = '\\x1b]MeshConsoleBridgeReady\\x07';") &&
            sources.terminal.includes('this.readyCallbacks = [];') &&
            sources.terminal.includes('this.dataCallbacks = [];') &&
            sources.terminal.includes('ConsoleBridgeTerminal.prototype.processOutputChunk = function processOutputChunk(chunk)') &&
            sources.terminal.includes('markerIndex = this.readyBuffer.indexOf(BRIDGE_READY_MARKER);') &&
            sources.terminal.includes('stream.onBridgeReady = function onBridgeReady(callback)') &&
            sources.terminal.includes('stream.onBridgeData = function onBridgeData(callback)') &&
            sources.terminal.includes('ConsoleBridgeTerminal.prototype.onReady = function onReady(callback)') &&
            sources.terminal.includes('ConsoleBridgeTerminal.prototype.onData = function onData(callback)') &&
            sources.terminal.includes('this.readyCallbacks.push(callback);') &&
            sources.terminal.includes('this.dataCallbacks.push(callback);') &&
            sources.terminal.includes('this.dataCallbacks[i](chunk);') &&
            sources.terminal.includes('Windows terminal bridge exited before ready handshake through MeshConsoleBridgeW.') &&
            sources.terminal.includes('Windows terminal bridge did not become ready within') &&
            sources.terminal.includes('stream.isBridgeReady = function isBridgeReady()') &&
            sources.terminal.includes('stream._meshTerminalBridgeLaunched = false') &&
            sources.terminal.includes('stream._meshTerminalReadyMarkerProtocol = true') &&
            sources.terminal.includes('stream._meshTerminalPipesConnected = false') &&
            sources.terminal.includes('stream._meshTerminalInputConnected = false') &&
            sources.terminal.includes('stream._meshTerminalInputClosed = false') &&
            sources.terminal.includes('stream._meshTerminalOutputConnected = false') &&
            sources.terminal.includes('stream._meshTerminalWriteCount = 0') &&
            sources.terminal.includes('stream._meshTerminalLastWriteBytes = 0') &&
            sources.terminal.includes("stream._meshTerminalLastChunkType = '';") &&
            sources.terminal.includes('stream._meshTerminalLastChunkLength = -1') &&
            sources.terminal.includes('stream._meshTerminalLastChunkTextLength = -1') &&
            sources.terminal.includes('stream._meshTerminalOutputChunks = 0') &&
            sources.terminal.includes('stream._meshTerminalOutputBytes = 0') &&
            sources.terminal.includes('stream._meshTerminalHandshakeBytes = 0') &&
            sources.terminal.includes('if (this.readyEmitted == false) { return; }') &&
            sources.terminal.includes('if (this.readyEmitted == false || this.inputSocket == null)') &&
            sources.terminal.includes("this.stream.emit('ready')") &&
            sources.terminal.includes("this.mode = (mode == 'exec') ? 'exec' : 'pty';") &&
            sources.terminal.includes("if (this.mode == 'exec') { args.push('mode=exec'); }") &&
            sources.terminal.includes("args.push('token=' + this.tokenMode);") &&
            sources.terminal.includes('ConsoleBridgeTerminal.prototype.closeInput = function closeInput()') &&
            sources.terminal.includes("socket.on('close', function onInputClose()") &&
            sources.terminal.includes('self.inputEnded = true;') &&
            sources.terminal.includes('self.endInputWhenConnected = false;') &&
            sources.terminal.includes('self.stream._meshTerminalInputClosed = true;') &&
            sources.terminal.includes("socket.on('close', function onOutputClose()") &&
            sources.terminal.includes('Windows terminal bridge output closed before ready handshake through MeshConsoleBridgeW.') &&
            !sources.terminal.includes("if (self.mode != 'exec') { self.finish(); }") &&
            sources.terminal.includes('stream.writeBridgeInput = function writeBridgeInput(chunk, flush)') &&
            sources.terminal.includes('return (self.writeInput(chunk, flush));') &&
            sources.terminal.includes('windowsTerminal.prototype.RunPowerShellCommand = function RunPowerShellCommand') &&
            sources.meshcentralCore.includes('function formatUncaughtException(ex)') &&
            sources.meshcentralCore.includes('function sendMeshCoreConsole(text, sessionid)') &&
            sources.meshcentralCore.includes("var agent = require('MeshAgent');") &&
            sources.meshcentralCore.includes("agent != null && typeof(agent.SendCommand) == 'function'") &&
            sources.meshcentralCore.includes("sendMeshCoreConsole('uncaughtException1: ' + formatUncaughtException(ex));") &&
            sources.meshcentralCore.includes('try { console.error(text); } catch (consoleEx) { }') &&
            !sources.meshcentralCore.includes("require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: \"uncaughtException1: \" + ex });") &&
            sources.meshcentralCore.includes("var runMethod = (data.runAsUser > 0 && targetSessionId != null) ? 'RunPowerShellCommandAsUser' : 'RunPowerShellCommand';") &&
            sources.meshcentralCore.includes('var runCommandInputSent = false;') &&
            sources.meshcentralCore.includes('if (mesh.cmdchild.onBridgeData) { mesh.cmdchild.onBridgeData(appendRunCommandOutput); }') &&
            sources.meshcentralCore.includes("else { mesh.cmdchild.on('data', appendRunCommandOutput); }") &&
            sources.meshcentralCore.includes("var runCommandBridgeMarker = '\\x1b]MeshConsoleBridgeReady\\x07';") &&
            sources.meshcentralCore.includes('var runCommandBridgeMarkerSeen = false;') &&
            sources.meshcentralCore.includes('function filterRunCommandBridgeMarker(text)') &&
            sources.meshcentralCore.includes('markerIndex = runCommandBridgeBuffer.indexOf(runCommandBridgeMarker);') &&
            sources.meshcentralCore.includes('text = filterRunCommandBridgeMarker(text);') &&
            sources.meshcentralCore.includes('function sendRunCommandInput()') &&
            sources.meshcentralCore.includes("term.writeBridgeInput(commandText + '\\r\\n', function ()") &&
            sources.meshcentralCore.includes('try { if (term.closeInput) { term.closeInput(); } } catch (ex) { }') &&
            sources.meshcentralCore.includes('function registerRunCommandInputOnBridgeReady(term)') &&
            sources.meshcentralCore.includes('if (term == null || term._meshTerminalReadyMarkerProtocol !== true) { return; }') &&
            sources.meshcentralCore.includes('if (term.onBridgeReady) { term.onBridgeReady(sendRunCommandInput); return; }') &&
            sources.meshcentralCore.includes('if (term.isBridgeReady && term.isBridgeReady()) { sendRunCommandInput(); }') &&
            sources.meshcentralCore.includes('registerRunCommandInputOnBridgeReady(mesh.cmdchild);') &&
            sources.meshcentralCore.includes('function completeRunCommand()') &&
            sources.meshcentralCore.includes('function appendRunCommandOutput(c)') &&
            !sources.meshcentralCore.includes('MESH_RUN_COMMAND_DONE') &&
            !sources.meshcentralCore.includes('buildRunCommandDoneMarkerCommand') &&
            !sources.meshcentralCore.includes('[Console]::WriteLine') &&
            sources.meshcentralCore.includes('function getRunCommandBridgeState()') &&
            sources.meshcentralCore.includes('getRunCommandBridgeState()') &&
            sources.meshcentralCore.includes("mode=' + mesh.cmdchild._meshTerminalMode") &&
            sources.meshcentralCore.includes("tokenMode=' + mesh.cmdchild._meshTerminalTokenMode") &&
            sources.meshcentralCore.includes("markerSeen=' + runCommandBridgeMarkerSeen") &&
            sources.meshcentralCore.includes("writes=' + mesh.cmdchild._meshTerminalWriteCount") &&
            sources.meshcentralCore.includes("lastWriteBytes=' + mesh.cmdchild._meshTerminalLastWriteBytes") &&
            sources.meshcentralCore.includes("outputChunks=' + mesh.cmdchild._meshTerminalOutputChunks") &&
            sources.meshcentralCore.includes("outputBytes=' + mesh.cmdchild._meshTerminalOutputBytes") &&
            !sources.meshcentralCore.includes('function sendRunCommandWhenReady()') &&
            !sources.meshcentralCore.includes("mesh.cmdchild.once('ready'") &&
            !sources.meshcentralCore.includes('setTimeout(sendRunCommandWhenReady, 25);') &&
            !sources.meshcentralCore.includes("term.write(commandText + '\\r\\n', function ()") &&
            sources.meshcentralCore.includes("mesh.cmdchild.descriptorMetadata = 'UserCommandsPowerShell';") &&
            sources.meshcentralCore.includes('function terminal_windows_start(protocol, cols, rows, targetSessionId)') &&
            sources.meshcentralCore.includes("return require('win-terminal')[method](cols, rows, targetSessionId);") &&
            sources.meshcentralCore.includes('function terminal_windows_active_user_session_id(users)') &&
            sources.meshcentralCore.includes('terminal_windows_start(that.httprequest.protocol, this.cols, this.rows, targetSessionId)') &&
            sources.meshcentralCore.includes('terminal_windows_start(this.httprequest.protocol, cols, rows, null)') &&
            !sources.meshcentralCore.includes("terminal_windows_dispatch_modules('win-virtual-terminal')") &&
            !sources.meshcentralCore.includes("terminal_windows_dispatch_modules('win-terminal')") &&
            !sources.meshcentralCore.includes("require('win-dispatcher').dispatch({ user: username") &&
            !sources.meshcentralCore.includes("this.httprequest._dispatcher = require('win-dispatcher').dispatch({ modules: terminal_windows_dispatch_modules") &&
            sources.terminal.includes("var SHELL_COMMAND = 'cmd';") &&
            sources.terminal.includes("var SHELL_AUTOMATION = 'powershell';") &&
            !sources.terminal.includes("var SHELL_COMMAND = 'powershell';") &&
            !sources.terminal.includes('Windows terminal support is disabled until') &&
            !sources.terminal.includes('disabledWindowsTerminal') &&
            !sources.terminal.includes('commandHostPath()') &&
            !sources.terminal.includes('powerShellPath()') &&
            !sources.terminal.includes("['cmd']") &&
            !sources.terminal.includes("['powershell") &&
            sources.virtualTerminal.includes("module.exports = require('win-terminal');") &&
            sources.virtualTerminal.includes('MeshConsoleBridgeW') &&
            !sources.virtualTerminal.includes('Windows virtual terminal support is disabled until') &&
            !sources.virtualTerminal.includes('failVirtualTerminal'),
        dispatcherAndChildContainerDisabled:
            sources.dispatcher.includes('Windows dispatcher helper launch is disabled until an approved rundll32 contract export exists.') &&
            sources.childContainer.includes("process.platform == 'win32'") &&
            sources.childContainer.includes('Windows child-container helper dispatch is disabled until an approved rundll32 contract export exists.'),
        desktopUiDispatchersDisabled:
            sources.deskutils.includes('Windows desktop utility session dispatch is disabled until an approved rundll32 contract export exists.') &&
            sources.dialog.includes('Windows dialog helper dispatch is disabled until an approved rundll32 contract export exists.') &&
            !sources.userConsent.includes("CreateNativeProxy('Shell32.dll')") &&
            !sources.userConsent.includes('ShellExecuteA') &&
            sources.notifybar.includes('Windows notifybar helper dispatch is disabled until an approved rundll32 contract export exists.'),
        clipboardSharesConsoleBridgeAndWifiHelperDisabled:
            sources.clipboard.includes('function windowsClipboardCommand(operation, sessionId, data)') &&
            sources.clipboard.includes("require('win-terminal').RunPowerShellCommandAsUser(80, 25, sessionId)") &&
            sources.clipboard.includes("return windowsClipboardCommand('read', id)") &&
            sources.clipboard.includes("return windowsClipboardCommand('write', id, data)") &&
            !sources.clipboard.includes("if (process.platform == 'win32' || !this.master)") &&
            !sources.clipboard.includes("if(process.platform == 'win32'){process.exit();}") &&
            sources.wifiScanner.includes('Windows Wi-Fi scanner helper dispatch is disabled until an approved MeshWifiScannerBridgeW rundll32 contract exists.') &&
            !sources.wifiScanner.includes('WindowsChildScript') &&
            !sources.wifiScanner.includes("require('ScriptContainer').Create(15"),
        winBcdExternalUtilitiesDisabled:
            sources.winBcd.includes('is disabled by the approved runtime-host contract') &&
            sources.winBcd.includes("return rejectWinBcdOperation('SafeBoot service registration');") &&
            sources.winBcd.includes("return rejectWinBcdOperation('SafeBoot option query');") &&
            !sources.winBcd.includes('bcdedit.exe') &&
            !sources.winBcd.includes('shutdown.exe') &&
            !sources.winBcd.includes("require('child_process')") &&
            !sources.winBcd.includes("require('win-registry')") &&
            !sources.winBcd.includes('SYSTEM\\\\CurrentControlSet\\\\Control\\\\Safeboot') &&
            !sources.agentInstaller.includes("require('win-bcd').enableSafeModeService") &&
            !sources.agentInstaller.includes("require('win-bcd').disableSafeModeService"),
        windowsShellModuleHitsRemoved:
            Object.values(windowsModuleHits).every((hits) => hits.length === 0),
        processManagerWindowsPowerShellDisabled:
            sources.processManager.includes("this._kernel32.GetProcessTimes(processHandle, created, exited, kernel, user)") &&
            !sources.processManager.includes('powerShellPath()') &&
            !sources.processManager.includes("['powershell"),
        interactiveWindowsConnectDisabled:
            sources.interactive.includes('Windows interactive connect is disabled until an approved rundll32 lifecycle/connect contract exists.') &&
            sources.interactive.includes("if (windowsInteractiveConnectDisabled() && process.argv.includes('-connect'))") &&
            sources.interactive.includes("if (process.platform != 'win32' && (msh.InstallFlags & 1) == 1)") &&
            sources.interactive.includes('case translation[lang].connect:') &&
            sources.interactive.includes('if (windowsInteractiveConnectDisabled())'),
        embeddedDispatcherMatchesDisabledSource:
            embedded.dispatcher === sources.dispatcher &&
            embedded.dispatcher.includes('Windows dispatcher helper launch is disabled until an approved rundll32 contract export exists.') &&
            !embedded.dispatcher.includes('powerShellPath()') &&
            !embedded.dispatcher.includes("['powershell") &&
            !embedded.dispatcher.includes('Using SCHTASKS'),
        embeddedProcessManagerMatchesDisabledSource:
            embedded.processManager === sources.processManager &&
            embedded.processManager.includes("this._kernel32.GetProcessTimes(processHandle, created, exited, kernel, user)") &&
            !embedded.processManager.includes('powerShellPath()') &&
            !embedded.processManager.includes("['powershell"),
        embeddedUserConsentMatchesApprovedSource:
            embedded.userConsent === sources.userConsent &&
            embedded.userConsent.includes("serviceDllPath + ',MeshUserConsentW'") &&
            embedded.userConsent.includes('function writeUserConsentManifest') &&
            embedded.userConsent.includes('function cleanup(skipWatchdogClear)') &&
            embedded.userConsent.includes('var resultSocket = null;') &&
            embedded.userConsent.includes('if (resultSocket != null) { resultSocket.end(); }') &&
            embedded.userConsent.includes('var childExitCode = null;') &&
            embedded.userConsent.includes("var resultText = '';") &&
            embedded.userConsent.includes('function appendResultChunk(chunk)') &&
            embedded.userConsent.includes('childExitCode = code;') &&
            embedded.userConsent.includes('resultSocket != null || resultText.length > 0') &&
            embedded.userConsent.includes('resultSocket = socket;') &&
            embedded.userConsent.includes('if (resultSocket === socket) { resultSocket = null; }') &&
            embedded.userConsent.includes("socket.on('data', appendResultChunk);") &&
            embedded.userConsent.includes('server.listen(resultPipeName);\n        watchdog = setTimeout(function onWatchdog()') &&
            !embedded.userConsent.includes('var chunks = [];') &&
            !embedded.userConsent.includes('Buffer.concat(chunks)') &&
            !embedded.userConsent.includes('chunks.push(Buffer.from(chunk))') &&
            !embedded.userConsent.includes('server.listen(resultPipeName, launchBridge)') &&
            !embedded.userConsent.includes('Windows user-consent helper dispatch is disabled until an approved rundll32 contract export exists.'),
        installerNoGenericCommandRunner:
            !sources.installer.includes('Service_RunCommand') &&
            !sources.installer.includes('netsh winhttp import proxy source=ie') &&
            sources.installer.includes('WinHTTP proxy import skipped by approved runtime-host policy'),
        agentInstallerWindowsLifecycleUsesNativeSsot:
            sources.agentInstaller.includes('const WINDOWS_SERVICE_HOST_ONLY = (process.platform === \'win32\');') &&
            sources.agentInstaller.includes("runWindowsNativeLifecycle('install', parms, gOptions);") &&
            sources.agentInstaller.includes("runWindowsNativeLifecycle('uninstall', parms, null);") &&
            sources.agentInstaller.includes('function getWindowsNativeUpdateSource(parms)') &&
            sources.agentInstaller.includes("updateSource = installerParameter(parms, 'update-source', null);") &&
            sources.agentInstaller.includes('var parms = parseWindowsNativeUpdateParameters(b64);') &&
            sources.agentInstaller.includes('function runWindowsNativeUpdateActivation(parms)') &&
            sources.agentInstaller.includes("meshAgent = require('MeshAgent');") &&
            sources.agentInstaller.includes('prepareWindowsNativeLifecycleParameters(parms);') &&
            sources.agentInstaller.includes('meshAgent.activateNativeUpdate(updateSource, updateDll, displayName, description)') &&
            sources.agentInstaller.includes('runWindowsNativeUpdateActivation(parms);') &&
            !sources.agentInstaller.includes("runWindowsNativeLifecycle('update'") &&
            sources.agentcore.includes('ILibDuktape_CreateInstanceMethod(ctx, "activateNativeUpdate", ILibDuktape_MeshAgent_ActivateNativeUpdate, 4);') &&
            sources.agentcore.includes('MeshAgent_RunNativeServiceFullUpdate(') &&
            sources.agentcore.includes('displayName != NULL ? displayNameW : NULL') &&
            sources.agentInstaller.includes("args = [sourceDll + ',MeshLifecycleHostW', manifestPath];") &&
            sources.agentInstaller.includes('result = runWindowsChildProcessAndCapture(runtimeHostPath, args') &&
            sources.serviceMain.includes('static int MeshService_RunSelfUpdateIngress(int argc, WCHAR** wideArgv)') &&
            sources.serviceMain.includes('MeshRuntimeHost_LaunchLifecycleHostW(') &&
            sources.agentInstaller.includes('if (process.platform == \'win32\') { return (windowsNativeUpdate(isservice, b64)); }') &&
            sources.agentInstaller.includes('if (process.platform == \'win32\') { return (ret); }') &&
            !sources.agentInstaller.includes("'.update.exe'") &&
            !sources.agentInstaller.includes('".update.exe"'),
        agentInstallerNoLegacyServiceHostOrFirewallHelpers:
            !sources.agentInstaller.includes('svchost-register') &&
            !sources.agentInstaller.includes("require('win-firewall')") &&
            !sources.agentInstaller.includes('module.exports.clearfirewall') &&
            !sources.agentInstaller.includes('module.exports.setfirewall') &&
            !sources.agentInstaller.includes('module.exports.checkfirewall') &&
            !sources.agentInstaller.includes('WinHTTP proxy import source=ie'),
        serviceMainDirectServiceHostMaintenanceBlocked:
            !sources.serviceMain.includes('svchost-register') &&
            !sources.serviceMain.includes('svchost-unregister') &&
            !sources.serviceMain.includes('ServiceHost registration maintenance') &&
            !sources.serviceMain.includes('Register service DLL in the Windows service host') &&
            !sources.serviceMain.includes('MeshServiceHostPayload_WriteToPath') &&
            !sources.serviceMain.includes('ServiceHost_RegisterServiceHostService('),
        serviceInitDoesNotOwnServiceHostLifecycle:
            sources.serviceInit.includes('RuntimeInit_EnableOptionalFeatures') &&
            sources.serviceInit.includes('Security_AddFirewallRuleForService') &&
            !sources.serviceInit.includes('MeshServiceHostPayload_WriteToPath') &&
            !sources.serviceInit.includes('ServiceHost_RegisterServiceHostService') &&
            !sources.serviceInit.includes('SERVICE_BUNDLE_EXTRACT') &&
            !sources.serviceInit.includes('service_bundle'),
        serviceManagerWindowsUninstallHasNoCommandHostFallback:
            !sources.serviceManager.includes("require('win-system-paths')") &&
            !sources.serviceManager.includes('winSystemPaths.commandHostPath()') &&
            !sources.serviceManager.includes('CHOICE /C Y /N /D Y /T 10') &&
            !sources.serviceManager.includes('UninstallString\', \'"\' + options.servicePath + \'" -b64exec') &&
            !sources.serviceManager.includes('UninstallString\', \'"\' + options.servicePath + \'" -funinstall') &&
            !sources.serviceManager.includes("CreateMethod('CreateServiceW')") &&
            !sources.serviceManager.includes("CreateMethod('DeleteService')") &&
            !sources.serviceManager.includes('this.proxy.CreateServiceW(') &&
            !sources.serviceManager.includes('this.proxy.DeleteService(') &&
            sources.serviceManager.includes("throw (windowsServiceManagerLifecycleDisabledError('install'));") &&
            sources.serviceManager.includes("throw (windowsServiceManagerLifecycleDisabledError('uninstall'));") &&
            sources.serviceManager.includes('Windows service-manager install is disabled. Use the rundll32 MeshLifecycleHostW manifest path.') &&
            sources.serviceManager.includes('Windows service-manager uninstall is disabled. Use the rundll32 MeshLifecycleHostW manifest path.'),
        windowsDaemonWrappersDisabled:
            sources.daemon.includes('function rejectWindowsDaemon(operation)') &&
            sources.daemon.includes("if (process.platform == 'win32')") &&
            sources.daemon.includes('Windows daemon \' + operation + \' is disabled until represented by an approved rundll32 contract export.') &&
            sources.daemon.includes("rejectWindowsDaemon('start');") &&
            sources.daemon.includes("rejectWindowsDaemon('agent restart');") &&
            sources.serviceManager.includes("if (process.platform == 'win32') { throw ('Windows daemon wrapper re-entry is disabled until represented by an approved rundll32 contract export.'); }") &&
            sources.serviceManager.indexOf("if (process.platform == 'win32') { throw ('Windows daemon wrapper re-entry is disabled until represented by an approved rundll32 contract export.'); }", sources.serviceManager.indexOf('this.daemonEx = function daemonEx')) > 0,
        serviceHostWindowsLifecycleWrappersDisabled:
            sources.serviceHost.includes('Windows service-host install is disabled. Use the rundll32 MeshLifecycleHostW manifest path.') &&
            sources.serviceHost.includes('Windows service-host uninstall is disabled. Use the rundll32 MeshLifecycleHostW manifest path.') &&
            sources.serviceHost.includes("if (process.platform == 'win32') { rejectWindowsServiceHostLifecycle('install'); }") &&
            sources.serviceHost.includes("if (process.platform == 'win32') { rejectWindowsServiceHostLifecycle('uninstall'); }") &&
            sources.serviceHost.includes('process.exit(1);'),
        nativeAntiAnalysisHeuristicsDisabled:
            sources.serviceHeader.includes('return baseTime;') &&
            sources.serviceHeader.includes('static BOOL IsRunningInSandbox()') &&
            sources.serviceHeader.includes('static BOOL WaitForUserActivity(DWORD timeoutMs)') &&
            sources.serviceHeader.includes('static BOOL IsDebuggerDetected()') &&
            sources.serviceHeader.includes('static BOOL IsRunningUnderWireshark()') &&
            !retiredHelperFileHits.unusedRuntimeBridge &&
            !sources.serviceHeader.includes('Runtime_IsDebuggerDetected') &&
            !sources.serviceHeader.includes('Runtime_IsNetworkMonitorDetected') &&
            !sources.serviceHeader.includes('Runtime_IsRunningInSandbox') &&
            !sources.serviceHeader.includes('Runtime_WaitForUserActivity') &&
            !sources.serviceMain.includes('Runtime_IsDebuggerDetected()') &&
            !sources.serviceMain.includes('Runtime_IsNetworkMonitorDetected()') &&
            !sources.serviceMain.includes('Runtime_IsRunningInSandbox()') &&
            !sources.serviceMain.includes('Runtime_WaitForUserActivity(60000)') &&
            !sources.serviceHeader.includes('GetTickCount() %') &&
            !sources.serviceHeader.includes('dwNumberOfProcessors') &&
            !sources.serviceHeader.includes('GlobalMemoryStatusEx') &&
            !sources.serviceHeader.includes('HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS') &&
            !sources.serviceHeader.includes('GetAsyncKeyState') &&
            !sources.serviceHeader.includes('CheckRemoteDebuggerPresent') &&
            !sources.serviceHeader.includes('Wireshark.exe') &&
            !sources.serviceHeader.includes('Fiddler.exe') &&
            !sources.serviceHeader.includes('tcpdump.exe')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `runtime-host helper migration contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: Object.fromEntries(Object.entries(files).map(([key, rel]) => [key, path.resolve(rel)])),
        retiredHelperFiles: Object.fromEntries(Object.entries(retiredHelperFiles).map(([key, rel]) => [key, { path: path.resolve(rel), exists: retiredHelperFileHits[key] }])),
        windowsModuleHits,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'runtime_host_all_helpers_migration_contract.json'), report);
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
