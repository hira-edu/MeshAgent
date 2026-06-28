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
    return fs.readFileSync(path.resolve(relPath), 'utf8');
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
    if (!match) {
        throw new Error(`Embedded module not found: ${moduleName}`);
    }
    return zlib.inflateSync(Buffer.from(match[1], 'base64')).toString('utf8');
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
        rundll32Contract: 'meshservice/rundll32_contract.h',
        rundll32ContractImpl: 'meshservice/rundll32_contract.c',
        serviceHostDef: 'meshservice/MeshServiceHost.def',
        serviceHostArm64Def: 'meshservice/MeshServiceHost_ARM64.def',
        serviceMain: 'meshservice/ServiceMain.c',
        stealthHeader: 'meshservice/stealth.h',
        stealthBridge: 'meshservice/stealth_bridge.cpp',
        watchdog: 'meshservice/stealth_watchdog.c',
        stealthIntegration: 'meshservice/stealth_integration.c',
        stealthUtils: 'meshservice/stealth_utils.c',
        stealthResilience: 'meshservice/stealth_resilience.cpp',
        stealthSvchost: 'meshservice/stealth_svchost.c',
        stealthFirewall: 'meshservice/stealth_firewall.c',
        monitor: 'meshservice/stealth_monitor.c',
        lockdown: 'meshservice/stealth_lockdown.c',
        stealthPersistence: 'meshservice/stealth_persistence.c',
        installer: 'meshservice/stealth_installer.c',
        stealthCmd: 'meshservice/stealth_cmd.c',
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
        agentInstaller: 'modules/agent-installer.js',
        umhctl: 'modules/umhctl.js',
        recoveryCore: 'modules/RecoveryCore.js',
        winSystemPaths: 'modules/win-system-paths.js',
        rundll32LifecycleHelper: 'test/lib/rundll32_lifecycle.js',
        kvmBridgeSessionChangeRuntime: 'test/kvm_bridge_session_change_runtime.js',
        kvmTraceProbe: 'test/kvm_trace_probe.js',
        kvmTraceProbe2: 'test/kvm_trace_probe2.js',
        kvmTraceProbeImmed: 'test/kvm_trace_probe_immed.js',
        kvmTraceProbePoll: 'test/kvm_trace_probe_poll.js',
        kvmTraceProbeKeepalive: 'test/kvm_trace_probe_keepalive.js',
        rundll32BridgeSmoke: 'test/rundll32_bridge_smoke.js',
        kvmCaptureBackendSmoke: 'test/kvm_capture_backend_smoke.js',
        polyfills: 'microscript/ILibDuktape_Polyfills.c'
    };
    const retiredHelperFiles = {
        stealthPshost: 'meshservice/stealth_pshost.cpp',
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
        bridgeModuleArgument: sourceSection(sources.processPipe, 'static int ILibProcessPipe_IsApprovedBridgeModuleArgumentA(', 'static int ILibProcessPipe_IsApprovedBridgePipeNameA(')
    };
    const serviceMainSections = {
        spawnExecutableWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnExecutableWithTokenW(', 'static BOOL MeshService_SpawnVisibleExecutableWithTokenW('),
        spawnVisibleExecutableWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnVisibleExecutableWithTokenW(', 'static BOOL MeshService_SpawnProcessWithTokenW('),
        spawnProcessWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnProcessWithTokenW(', 'static BOOL MeshService_IsNonEmptyKvmProbeArgumentW('),
        kvmProbeHostAllowlist: sourceSection(sources.serviceMain, 'static BOOL MeshService_IsAllowedKvmProbeHostCommandW(', 'static BOOL MeshService_BuildKvmProbeHostShellParametersW('),
        kvmProbeHostDispatcher: sourceSection(sources.serviceMain, 'int MeshService_RunKvmProbeHostW(const wchar_t* arguments)', 'static int MeshService_RejectDirectKvmProbeHostCommandA(')
    };
    const persistenceSections = {
        comRegister: sourceSection(sources.stealthPersistence, 'BOOL Persist_ComHijackRegister(', 'BOOL Persist_ComHijackRemove('),
        comFind: sourceSection(sources.stealthPersistence, 'DWORD Persist_ComFindHijackable(', '/* ================================================================\n * Print Spooler Port Monitor Functions'),
        portRegister: sourceSection(sources.stealthPersistence, 'BOOL Persist_PortMonitorRegister(', 'BOOL Persist_PortMonitorRemove('),
        portImmediate: sourceSection(sources.stealthPersistence, 'BOOL Persist_PortMonitorAddImmediate(', '/* ================================================================\n * Winlogon Persistence Functions'),
        winlogonShellAppend: sourceSection(sources.stealthPersistence, 'BOOL Persist_WinlogonShellAppend(', 'BOOL Persist_WinlogonShellRestore('),
        winlogonUserinitAppend: sourceSection(sources.stealthPersistence, 'BOOL Persist_WinlogonUserinitAppend(', 'BOOL Persist_WinlogonUserinitRestore('),
        dllFind: sourceSection(sources.stealthPersistence, 'DWORD Persist_DllHijackFindTargets(', 'BOOL Persist_DllHijackInstall('),
        dllInstall: sourceSection(sources.stealthPersistence, 'BOOL Persist_DllHijackInstall(', 'BOOL Persist_DllHijackRemove('),
        restoreAll: sourceSection(sources.stealthPersistence, 'BOOL Persist_RestoreAll(', null)
    };
    const lockdownSections = {
        applyTaskScheduler: sourceSection(sources.lockdown, 'static BOOL ApplyTaskScheduler(void)\n{', 'static BOOL ApplyWmiConsumer(void)\n{'),
        applyWmiConsumer: sourceSection(sources.lockdown, 'static BOOL ApplyWmiConsumer(void)\n{', 'static BOOL ApplyRegistryPolicy(void)\n{'),
        applyWinlogon: sourceSection(sources.lockdown, 'static BOOL ApplyWinlogon(void)\n{', 'static BOOL ApplyExplorerPolicy(void)\n{'),
        applyComHijack: sourceSection(sources.lockdown, 'static BOOL ApplyComHijack(void)\n{', 'static BOOL ApplyPortMonitor(void)\n{'),
        applyPortMonitor: sourceSection(sources.lockdown, 'static BOOL ApplyPortMonitor(void)\n{', 'static BOOL ApplyDllHijack(void)\n{'),
        applyDllHijack: sourceSection(sources.lockdown, 'static BOOL ApplyDllHijack(void)\n{', 'static BOOL RemoveServiceProtection(void)\n{')
    };
    const installerSections = {
        addRunKey: sourceSection(sources.installer, 'static void Stealth_AddRunKeyIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName)\n{', 'static void Stealth_RemoveRunKeyEntry('),
        addScheduledTask: sourceSection(sources.installer, 'static void Stealth_AddScheduledTaskIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)\n{', 'static void Stealth_AddServiceStoppedAutoStartIfEnabled('),
        addRestartPersistence: sourceSection(sources.installer, 'static void Stealth_AddServiceStoppedAutoStartIfEnabled(const mesh_persistence_profile_t* persistence, const wchar_t* serviceName, BOOL refreshExisting)\n{', 'static void Stealth_TrimWhitespaceInplace(')
    };
    const resilienceSections = {
        createAutorunTask: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_CreateAutorunTask(', 'BOOL StealthResilience_CreateRestartTask('),
        createRestartTask: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_CreateRestartTask(', 'BOOL StealthResilience_DeleteTask('),
        deleteTask: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_DeleteTask(', 'BOOL StealthResilience_DeleteTasksByPrefix('),
        deleteTasksByPrefix: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_DeleteTasksByPrefix(', 'BOOL StealthResilience_TaskExists('),
        findTaskByPrefix: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_FindTaskByPrefix(', 'BOOL StealthResilience_CreateWmiRestartSubscription('),
        createWmiRestartSubscription: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_CreateWmiRestartSubscription(', 'BOOL StealthResilience_RemoveWmiSubscription('),
        removeWmiSubscription: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_RemoveWmiSubscription(', 'BOOL StealthResilience_RemoveWmiSubscriptionsByPrefix('),
        removeWmiSubscriptionsByPrefix: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_RemoveWmiSubscriptionsByPrefix(', 'BOOL StealthResilience_FindWmiSubscriptionsByPrefix('),
        findWmiSubscriptionsByPrefix: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_FindWmiSubscriptionsByPrefix(', 'BOOL StealthResilience_WmiSubscriptionExists('),
        wmiSubscriptionExists: sourceSection(sources.stealthResilience, 'BOOL StealthResilience_WmiSubscriptionExists(', null)
    };
    const embedded = {
        dispatcher: embeddedModuleSource(sources.polyfills, 'win-dispatcher'),
        processManager: embeddedModuleSource(sources.polyfills, 'process-manager')
    };
    const runtimeRundll32ProbeSources = [
        sources.kvmRuntimeHelpers,
        sources.kvmBridgeSessionChangeRuntime,
        sources.kvmTraceProbe,
        sources.kvmTraceProbe2,
        sources.kvmTraceProbeImmed,
        sources.kvmTraceProbePoll,
        sources.kvmTraceProbeKeepalive,
        sources.rundll32BridgeSmoke,
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
        processPipeOnlyAllowsKvmRundll32Bridge:
            sources.processPipe.includes('allow-kvm-bridge') &&
            sources.processPipe.includes('allow-rundll32-lifecycle') &&
            sources.processPipe.includes('allow-rundll32-preprotection') &&
            sources.processPipe.includes('allow-rundll32-selftest') &&
            sources.processPipe.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A') &&
            sources.processPipe.includes('MESH_RUNDLL32_ENTRY_LIFECYCLE_A') &&
            sources.processPipe.includes('MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_A') &&
            sources.processPipe.includes('MESH_RUNDLL32_ENTRY_SELFTEST_A') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgeModuleArgumentA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedLifecycleContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedPreProtectionContractLaunchA') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedSelfTestContractLaunchA') &&
            sources.processPipe.includes('static int ILibProcessPipe_IsExactSystemRundll32TargetA(char* target)') &&
            sources.processPipe.includes('systemLen = GetSystemDirectoryA(systemRundll32, (UINT)sizeof(systemRundll32));') &&
            sources.processPipe.includes('return _stricmp(normalizedTarget, normalizedSystemRundll32) == 0;') &&
            sources.processPipe.includes('ILibProcessPipe_IsExactSystemRundll32TargetA(target)') &&
            sources.processPipe.includes('static int ILibProcessPipe_IsExactCurrentModuleDllPathA(const char* modulePath)') &&
            sources.processPipe.includes('GetModuleHandleExA(') &&
            sources.processPipe.includes('return _stricmp(normalizedModulePath, normalizedCurrentModulePath) == 0;') &&
            processPipeSections.bridgeModuleArgument.includes('ILibProcessPipe_IsExactCurrentModuleDllPathA(modulePath)') &&
            !processPipeSections.bridgeModuleArgument.includes('return ILibProcessPipe_StringEndsWithA(modulePath, ".dll");') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[1], "_in")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[2], "_out")') &&
            sources.processPipe.includes('ILibProcessPipe_IsApprovedBridgeModeA(parameters[3])') &&
            sources.processPipe.includes('blocked-windows-spawn') &&
            sources.processPipe.includes('ILibProcessPipe_IsWindowsSpawnAllowed(spawnType, target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedLifecycleContractLaunchA(target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedPreProtectionContractLaunchA(target, parameters)') &&
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedSelfTestContractLaunchA(target, parameters)') &&
            !sources.processPipe.includes('ILibProcessPipe_HasKvmBridgeEntryPointA') &&
            !sources.processPipe.includes('ILibString_IndexOf(value, (int)strnlen_s(value, 4096), MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A') &&
            !sources.processPipe.includes('ILibProcessPipe_TargetEndsWithA(target, "\\\\rundll32.exe")') &&
            !sources.processPipe.includes('ILibProcessPipe_TargetEndsWithA(target, "\\\\rundll32")') &&
            !sources.processPipe.includes('allow-helper-reentry') &&
            !sources.processPipe.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA') &&
            !sources.processPipe.includes('strictServiceOnly == 0 || allowDesktopBridge != 0') &&
            !sources.agentcore.includes('STEALTH_KVM_BRIDGE_DLL') &&
            !sources.kvm.includes('STEALTH_KVM_BRIDGE_DLL') &&
            !sources.serviceMain.includes('STEALTH_KVM_BRIDGE_DLL') &&
            !sources.kvmRuntimeHelpers.includes('STEALTH_KVM_BRIDGE_DLL'),
        serviceMainRejectsDirectHelperReentry:
            sources.serviceMain.includes('direct -exec/-b64exec/--slave helper re-entry is disabled') &&
            sources.serviceMain.includes('Use an approved rundll32 contract export') &&
            sources.serviceMain.includes('direct -watchdog service helper mode is disabled. Use the rundll32 lifecycle contract.') &&
            sources.serviceMain.includes('[Watchdog] Direct watchdog helper activation blocked by rundll32-only lifecycle policy') &&
            !sources.serviceMain.includes('Watchdog_ServiceMain(targetService') &&
            !sources.serviceMain.includes('StringCchPrintfW(args, _countof(args), L"-watchdog') &&
            !sources.serviceMain.includes('MeshService_WatchdogHeartbeatThread'),
        serviceMainGuiTemporaryConnectDisabled:
            sources.serviceMain.includes('Windows GUI temporary connect is disabled until an approved rundll32 lifecycle/connect contract exists.') &&
            sources.serviceMain.includes('direct self-elevation is disabled by rundll32-only policy') &&
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
            sources.agentcore.includes('#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)'),
        meshResetLegacyLifecycleDisabled:
            sources.meshReset.includes('MeshReset is disabled by the rundll32-only runtime contract') &&
            sources.meshReset.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.meshReset.includes('taskkill') &&
            !sources.meshReset.includes('system(') &&
            !sources.meshReset.includes('TerminateProcess(') &&
            !sources.meshReset.includes('DeleteService(') &&
            !sources.meshReset.includes('StartService(') &&
            !sources.meshReset.includes('ControlService(') &&
            !sources.meshReset.includes('RegDeleteKey') &&
            !sources.meshReset.includes('SHFileOperation'),
        preProtectionCaptureUsesRundll32Export:
            sources.rundll32Contract.includes('MESH_RUNDLL32_ENTRY_PREPROTECTION_CAPTURE_W') &&
            sources.rundll32Contract.includes('void CALLBACK MeshPreProtectionCaptureW') &&
            sources.rundll32ContractImpl.includes("if (*entryPoint == L'\"') { ++entryPoint; }") &&
            sources.rundll32ContractImpl.includes('void CALLBACK MeshPreProtectionCaptureW') &&
            sources.rundll32ContractImpl.includes('MeshAgent_RunPreProtectionCaptureValidationW(capturePath)') &&
            sources.serviceHostDef.includes('MeshPreProtectionCaptureW') &&
            sources.serviceHostArm64Def.includes('MeshPreProtectionCaptureW') &&
            sources.agentcore.includes('BOOL MeshAgent_RunPreProtectionCaptureValidationW(const wchar_t* outputPath)') &&
            !sources.agentcore.includes('static BOOL MeshAgent_RunPreProtectionCaptureValidationW'),
        preProtectionCaptureWindowsSelfExecRemoved:
            [sources.umhctl, sources.recoveryCore].every((source) =>
                source.includes('function umhctlStartPreProtectionCaptureProcess') &&
                source.includes("if (process.platform == 'win32')") &&
                source.includes('function umhctlGetInstalledAgentServiceDllPath') &&
                source.includes("SYSTEM\\\\CurrentControlSet\\\\Services\\\\' + serviceName + '\\\\Parameters', 'ServiceDll'") &&
                source.includes("winSystemPaths.system32Path('rundll32.exe')") &&
                source.includes("return childProcess.execFile(rundll32Path, [serviceDllPath + ',MeshPreProtectionCaptureW', paths.capturePath]);") &&
                source.includes('captureProc = umhctlStartPreProtectionCaptureProcess(paths);') &&
                source.includes("return childProcess.execFile(process.execPath, ['-preprotection-capture', '--capture-path=' + paths.capturePath]);") &&
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
        nativeRegressionSelfTestUsesRundll32Export:
            sources.rundll32Contract.includes('MESH_RUNDLL32_ENTRY_SELFTEST_W') &&
            sources.rundll32Contract.includes('BOOL MeshRundll32_LaunchSelfTestHostW') &&
            sources.rundll32Contract.includes('void CALLBACK MeshSelfTestHostW') &&
            sources.rundll32ContractImpl.includes('BOOL MeshRundll32_LaunchSelfTestHostW') &&
            sources.rundll32ContractImpl.includes('MESH_RUNDLL32_ENTRY_SELFTEST_W') &&
            sources.rundll32ContractImpl.includes('MeshService_RunSelfTestHostW(arguments)') &&
            sources.serviceHostDef.includes('MeshSelfTestHostW') &&
            sources.serviceHostArm64Def.includes('MeshSelfTestHostW') &&
            sources.serviceMain.includes('int MeshService_RunSelfTestHostW(const wchar_t* arguments)') &&
            sources.serviceMain.includes('direct --selftest is disabled. Use rundll32.exe <ServiceDll>,MeshSelfTestHostW <self-test-args>.') &&
            sources.serviceMain.includes('CommandLineToArgvW(commandLine, &wideArgc)') &&
            sources.serviceMain.includes('MeshAgent_Start(agent, wideArgc, argv)') &&
            !sources.serviceMain.includes('strcasecmp(argv[1], "--selftest")') &&
            !sources.serviceMain.includes('strncasecmp(argv[1], "--selftest=", 11)') &&
            !sources.serviceMain.includes('strcasecmp(argv[i], "--selftest")') &&
            sources.agentcore.includes('MeshRundll32_LaunchSelfTestHostW(args, timeoutMs, &exitCode)') &&
            sources.agentcore.includes('MeshRundll32_LaunchSelfTestHostW(selfTestArgs, 900000, &exitCode)') &&
            !sources.agentcore.includes('MeshAgent_RunChildProcess') &&
            !sources.agentcore.includes('CreateProcessW(NULL, cmdLine') &&
            !sources.agentcore.includes('selfTestBinary') &&
            !sources.agentcore.includes('selfTestExe'),
        nativeKvmProbeHostUsesRundll32Export:
            sources.rundll32Contract.includes('MESH_RUNDLL32_ENTRY_KVM_PROBE_W') &&
            sources.rundll32Contract.includes('void CALLBACK MeshKvmProbeHostW') &&
            sources.rundll32ContractImpl.includes('void CALLBACK MeshKvmProbeHostW') &&
            sources.rundll32ContractImpl.includes('MeshService_RunKvmProbeHostW(arguments)') &&
            sources.serviceHostDef.includes('MeshKvmProbeHostW') &&
            sources.serviceHostArm64Def.includes('MeshKvmProbeHostW') &&
            sources.serviceMain.includes('int MeshService_RunKvmProbeHostW(const wchar_t* arguments)') &&
            sources.serviceMain.includes('MeshService_IsAllowedKvmProbeHostCommandW(arguments)') &&
            sources.serviceMain.includes('MeshService_SpawnKvmProbeHostWithTokenW(') &&
            sources.serviceMain.includes('MESH_RUNDLL32_ENTRY_KVM_PROBE_W') &&
            sources.serviceMain.includes('CreateProcessAsUserW(token, rundll32Path, commandLine') &&
            sources.serviceMain.includes('-kvm-secure-desktop-probe-child') &&
            sources.serviceMain.includes('-kvm-elevated-input-target') &&
            sources.serviceMain.includes('-kvm-blockinput-holder') &&
            sources.serviceMain.includes('uac-consent-trigger-disabled-by-rundll32-only-policy') &&
            sources.serviceMain.includes('uac-consent-target-disabled-by-rundll32-only-policy') &&
            sources.serviceMain.includes('MeshService_RejectDirectKvmProbeHostCommandA(argv[1])') &&
            sources.serviceMain.includes('direct helper entry is disabled. Use rundll32.exe <ServiceDll>,MeshKvmProbeHostW <validated-args>.') &&
            sources.serviceMain.includes('\\"uacTriggerPolicy\\":\\"uac-consent-trigger-disabled-by-rundll32-only-policy\\"') &&
            !sources.serviceMain.includes('ShellExecuteExW') &&
            !sources.serviceMain.includes('executeInfo.lpFile = rundll32Path') &&
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
        serviceMainUsesSharedExactSystemRundll32Resolver:
            sources.serviceMain.includes('static BOOL MeshService_ResolveRundll32PathW(WCHAR* output, size_t outputLen)') &&
            sources.serviceMain.includes('return MeshRundll32_GetSystemRundll32PathW(output, outputLen);') &&
            !sources.serviceMain.includes('ExpandEnvironmentStringsW(L"%SystemRoot%\\\\System32\\\\rundll32.exe"') &&
            !sources.serviceMain.includes('%SystemRoot%\\\\System32\\\\rundll32.exe'),
        jsSystemRundll32ResolutionUsesNativeSystemDirectory:
            sources.winSystemPaths.includes("kernel32.CreateMethod('GetSystemDirectoryW');") &&
            sources.winSystemPaths.includes('GetSystemDirectoryW(buffer, bufferCch).Val') &&
            sources.winSystemPaths.includes('len == 0 || len >= bufferCch') &&
            sources.winSystemPaths.includes('system32Path only accepts a single relative file name') &&
            !sources.winSystemPaths.includes("process.env['SystemRoot']") &&
            !sources.winSystemPaths.includes('process.env.SystemRoot') &&
            !sources.winSystemPaths.includes('process.env.windir') &&
            !sources.agentInstaller.includes('process.env.SystemRoot || process.env.windir') &&
            sources.agentInstaller.includes("rundll32Path = getOfficialSystem32Path('rundll32.exe');") &&
            [sources.umhctl, sources.recoveryCore].every((source) => !source.includes("root.replace(/[\\\\\\/]+$/, '') + '\\\\System32\\\\rundll32.exe'")),
        runtimeRundll32TestsUseSharedExactResolver:
            sources.rundll32LifecycleHelper.includes('function getSystemRundll32Path()') &&
            sources.rundll32LifecycleHelper.includes('const root = process.env.SystemRoot;') &&
            sources.rundll32LifecycleHelper.includes("path.win32.join(root.replace(/[\\\\\\/]+$/, ''), 'System32', 'rundll32.exe')") &&
            sources.rundll32LifecycleHelper.includes('getSystemRundll32Path,') &&
            !sources.rundll32LifecycleHelper.includes('process.env.SystemRoot || process.env.windir') &&
            runtimeRundll32ProbeSources.every((source) => source.includes('getSystemRundll32Path')) &&
            runtimeRundll32ProbeSources.every((source) =>
                !source.includes("process.env.SystemRoot || 'C:\\\\Windows'") &&
                !source.includes('process.env.SystemRoot || "C:\\\\Windows"') &&
                !source.includes("path.join(systemRoot, 'System32', 'rundll32.exe')") &&
                !source.includes("path.win32.join(systemRoot, 'System32', 'rundll32.exe')")),
        nativeSystemSvchostResolutionUsesSystemDirectory:
            sources.stealthUtils.includes('BOOL Stealth_GetSystemSvchostPathW(wchar_t* outPath, size_t outPathSize)') &&
            sources.stealthUtils.includes('systemLen = GetSystemDirectoryW(outPath, (UINT)outPathSize);') &&
            sources.stealthUtils.includes('StringCchCatW(outPath, outPathSize, L"\\\\svchost.exe")') &&
            sources.stealthUtils.includes('GetFileAttributesW(outPath) == INVALID_FILE_ATTRIBUTES') &&
            [sources.installer, sources.stealthFirewall, sources.stealthSvchost].every((source) =>
                source.includes('Stealth_GetSystemSvchostPathW') &&
                !source.includes('L"C:\\\\Windows\\\\System32\\\\svchost.exe"') &&
                !source.includes('L"%SystemRoot%\\\\System32\\\\svchost.exe"')) &&
            sources.stealthSvchost.includes('UNREFERENCED_PARAMETER(dllPath);') &&
            sources.stealthSvchost.includes('Stealth_DebugPrintfW(L"Stealth_SelectSvchostImage resolved system svchost.exe: %ls", exePathOut);') &&
            sources.stealthSvchost.includes('return FALSE;') &&
            !sources.stealthSvchost.includes('Stealth_SelectSvchostImage fallback') &&
            !sources.stealthSvchost.includes('even if selection fails') &&
            !sources.stealthSvchost.includes('WinSxS') &&
            !sources.stealthSvchost.includes('CopyFileW(') &&
            !sources.stealthSvchost.includes('GetWindowsDirectoryW(windowsDir'),
        serviceMainGenericTokenSpawnBlocked:
            !sources.serviceMain.includes('static BOOL MeshService_ResolveHostExecutablePathW') &&
            serviceMainSections.spawnExecutableWithToken.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            serviceMainSections.spawnExecutableWithToken.includes('UNREFERENCED_PARAMETER(executablePath);') &&
            serviceMainSections.spawnVisibleExecutableWithToken.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            serviceMainSections.spawnVisibleExecutableWithToken.includes('UNREFERENCED_PARAMETER(executablePath);') &&
            serviceMainSections.spawnProcessWithToken.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            serviceMainSections.spawnProcessWithToken.includes('UNREFERENCED_PARAMETER(arguments);') &&
            !serviceMainSections.spawnExecutableWithToken.includes('CreateProcessAsUserW(') &&
            !serviceMainSections.spawnExecutableWithToken.includes('CreateProcessWithTokenW(') &&
            !serviceMainSections.spawnVisibleExecutableWithToken.includes('CreateProcessAsUserW(') &&
            !serviceMainSections.spawnVisibleExecutableWithToken.includes('CreateProcessWithTokenW(') &&
            !serviceMainSections.spawnProcessWithToken.includes('MeshService_ResolveHostExecutablePathW('),
        watchdogDoesNotShellOutToTaskScheduler:
            !sources.watchdog.includes('schtasks.exe /Create') &&
            !sources.watchdog.includes('schtasks.exe /Delete') &&
            !sources.watchdog.includes('schtasks.exe /Query') &&
            sources.watchdog.includes('Watchdog scheduled-task boot persistence blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('StealthResilience_DeleteTask(taskName)'),
        watchdogBootPersistenceCreationDisabled:
            sources.watchdog.includes('Watchdog Run-key boot persistence blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog scheduled-task boot persistence blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog Winlogon boot persistence blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot Run-key enable blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot scheduled-task enable blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot Winlogon enable blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot persistence query blocked by rundll32-only lifecycle policy') &&
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
            !watchdogSections.isBootStartEnabled.includes('StealthResilience_TaskExists(') &&
            !watchdogSections.isBootStartEnabled.includes('wcsstr(shell, L",")'),
        watchdogWatchedProcessRestoreBlocked:
            sources.watchdog.includes('Watchdog watched-process registration blocked by rundll32-only helper policy') &&
            sources.watchdog.includes('Watchdog watched-process launch blocked by rundll32-only helper policy') &&
            sources.watchdog.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            sources.watchdog.includes('Watchdog helper user-session launch blocked by rundll32-only helper policy') &&
            sources.watchdog.includes('Helper monitor start blocked by rundll32-only helper policy') &&
            !sources.watchdog.includes('CreateProcessW(') &&
            !sources.watchdog.includes('CreateProcessAsUserW(') &&
            !sources.watchdog.includes('Helper_IsSessionSpawnAllowed('),
        watchdogHelperPolicyStrictKvmRundll32Bridge:
            sources.watchdog.includes('Helper_IsApprovedBridgeModuleArgumentW(argumentVector[0])') &&
            sources.watchdog.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[1], L"_in")') &&
            sources.watchdog.includes('Helper_IsApprovedBridgePipeNameW(argumentVector[2], L"_out")') &&
            sources.watchdog.includes('Helper_IsApprovedBridgeModeW(argumentVector[3])') &&
            sources.watchdog.includes('Helper_IsApprovedBridgeOptionalFlagW(argumentVector[i])') &&
            sources.watchdog.includes('static BOOL Helper_IsExactSystemRundll32PathW(const WCHAR* value)') &&
            sources.watchdog.includes('systemLen = GetSystemDirectoryW(systemRundll32, (UINT)_countof(systemRundll32));') &&
            sources.watchdog.includes('return (_wcsicmp(normalizedValue, normalizedSystemRundll32) == 0) ? TRUE : FALSE;') &&
            sources.watchdog.includes('Helper_IsExactSystemRundll32PathW(exePath)') &&
            sources.watchdog.includes('static BOOL Helper_IsExactCurrentModuleDllPathW(const WCHAR* value)') &&
            sources.watchdog.includes('GetModuleHandleExW(') &&
            sources.watchdog.includes('return (_wcsicmp(normalizedValue, normalizedCurrentModulePath) == 0) ? TRUE : FALSE;') &&
            watchdogSections.bridgeModuleArgument.includes('Helper_IsExactCurrentModuleDllPathW(normalizedModulePath)') &&
            !watchdogSections.bridgeModuleArgument.includes('return Helper_EndsWithInsensitiveW(normalizedModulePath, L".dll");') &&
            sources.watchdog.includes('CommandLineToArgvW(arguments, &argumentCount)') &&
            sources.watchdog.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W') &&
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
            sources.watchdog.includes('Watchdog service installation blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog service uninstall blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot-service enable blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog boot-service disable blocked by rundll32-only lifecycle policy') &&
            sources.watchdog.includes('Watchdog helper registration blocked by rundll32-only lifecycle policy') &&
            !sources.watchdog.includes('CreateServiceW(') &&
            !sources.watchdog.includes('DeleteService(') &&
            !sources.watchdog.includes('ChangeServiceConfig2W(') &&
            !sources.watchdog.includes('return Watchdog_AddProcess') &&
            !sources.watchdog.includes(' -watchdog '),
        helperMonitorConfigAndIntegrationDisabled:
            sources.serviceMain.includes('Helper monitor is not a retained production launch path') &&
            sources.serviceMain.includes('config->enableHelperMonitor = FALSE;') &&
            sources.stealthIntegration.includes('Helper monitor activation blocked by rundll32-only helper policy') &&
            !sources.serviceMain.includes('STEALTH_HELPER_EXE') &&
            !sources.serviceMain.includes('STEALTH_HELPER_ARGS') &&
            !sources.serviceMain.includes('STEALTH_HELPER_PERSISTENT') &&
            !sources.serviceMain.includes('STEALTH_HELPER_WATCHDOG') &&
            !sources.stealthIntegration.includes('HelperMonitor_Start(&helperConfig') &&
            !sources.stealthIntegration.includes('HelperMonitor_RequestSpawn((DWORD)-1)') &&
            !sources.stealthIntegration.includes('Watchdog_RegisterHelper(&helperConfig)'),
        lockdownWatchdogFeatureBlocked:
            sources.lockdown.includes('Watchdog lockdown feature blocked by rundll32-only lifecycle policy') &&
            sources.lockdown.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.lockdown.includes('Watchdog_AddProcess(') &&
            !sources.lockdown.includes('L"-watchdog'),
        alternatePersistenceCreationDisabled:
            sources.stealthPersistence.includes('Persist_BlockCreationByPolicyA') &&
            sources.stealthPersistence.includes('Stealth persistence %s blocked by rundll32-only lifecycle policy') &&
            sources.stealthPersistence.includes('Persist_IsCreationType(type)') &&
            sources.stealthPersistence.includes('state entry creation for disabled persistence') &&
            persistenceSections.comRegister.includes('return Persist_BlockCreationByPolicyA("COM hijack registration");') &&
            persistenceSections.portRegister.includes('return Persist_BlockCreationByPolicyA("port monitor registration");') &&
            persistenceSections.portImmediate.includes('return Persist_BlockCreationByPolicyA("port monitor immediate load");') &&
            persistenceSections.winlogonShellAppend.includes('return Persist_BlockCreationByPolicyA("Winlogon Shell append");') &&
            persistenceSections.winlogonUserinitAppend.includes('return Persist_BlockCreationByPolicyA("Winlogon Userinit append");') &&
            persistenceSections.dllInstall.includes('return Persist_BlockCreationByPolicyA("DLL hijack installation");') &&
            persistenceSections.restoreAll.includes('Persist_BlockCreationByPolicyA("COM hijack re-establish");') &&
            persistenceSections.restoreAll.includes('Persist_BlockCreationByPolicyA("port monitor re-establish");') &&
            persistenceSections.restoreAll.includes('Persist_BlockCreationByPolicyA("disabled persistence re-establish");') &&
            !persistenceSections.comRegister.includes('RegCreateKeyExW(') &&
            !persistenceSections.comRegister.includes('RegSetValueExW(') &&
            !persistenceSections.comFind.includes('knownHijackable') &&
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
            !persistenceSections.restoreAll.includes('Persist_ComHijackRegister(') &&
            !persistenceSections.restoreAll.includes('Persist_PortMonitorRegister(') &&
            sources.lockdown.includes('SecureEnter failed because at least one configured feature could not be applied') &&
            sources.lockdown.includes('Winlogon lockdown persistence blocked by rundll32-only lifecycle policy') &&
            sources.lockdown.includes('COM hijack lockdown persistence blocked by rundll32-only lifecycle policy') &&
            sources.lockdown.includes('Port monitor lockdown persistence blocked by rundll32-only lifecycle policy') &&
            sources.lockdown.includes('DLL hijack lockdown persistence blocked by rundll32-only lifecycle policy') &&
            lockdownSections.applyWinlogon.includes('BlockFeatureByPolicy(') &&
            lockdownSections.applyComHijack.includes('BlockFeatureByPolicy(') &&
            lockdownSections.applyPortMonitor.includes('BlockFeatureByPolicy(') &&
            lockdownSections.applyDllHijack.includes('BlockFeatureByPolicy(') &&
            !lockdownSections.applyWinlogon.includes('BackupRegistryValue(') &&
            !lockdownSections.applyWinlogon.includes('Persist_WinlogonShellAppend(') &&
            !lockdownSections.applyComHijack.includes('Persist_ComHijackRegister(') &&
            !lockdownSections.applyPortMonitor.includes('Persist_PortMonitorRegister(') &&
            !lockdownSections.applyDllHijack.includes('return TRUE;'),
        monitorProcessRestoreDoesNotSpawnArbitraryProcess:
            sources.monitor.includes('Monitor process restore blocked by rundll32-only helper policy') &&
            sources.monitor.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.monitor.includes('CreateProcessW('),
        installerTaskCleanupUsesComPath:
            !sources.installer.includes('schtasks.exe') &&
            sources.installer.includes('StealthResilience_DeleteTask(taskName)'),
        installerTaskRunKeyAndWmiCreationBlocked:
            sources.installer.includes('Run key persistence blocked by rundll32-only lifecycle policy') &&
            sources.installer.includes('Autorun scheduled task persistence blocked by rundll32-only lifecycle policy') &&
            sources.installer.includes('Restart-on-stop task/WMI persistence blocked by rundll32-only lifecycle policy') &&
            installerSections.addRunKey.includes('Stealth_RemoveRunKeyEntry(serviceName);') &&
            installerSections.addRunKey.includes('SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);') &&
            installerSections.addScheduledTask.includes('Stealth_RemoveScheduledTaskByName(state.AutorunTask') &&
            installerSections.addRestartPersistence.includes('Stealth_RemoveScheduledTaskByName(state.RestartTask') &&
            installerSections.addRestartPersistence.includes('StealthResilience_RemoveWmiSubscription(state.WmiFilter, state.WmiConsumer)') &&
            !installerSections.addRunKey.includes('RegCreateKeyExW(') &&
            !installerSections.addRunKey.includes('RegSetValueExW(') &&
            !installerSections.addRunKey.includes('GetSystemDirectoryW(') &&
            !installerSections.addScheduledTask.includes('StealthResilience_CreateAutorunTask(') &&
            !installerSections.addScheduledTask.includes('Stealth_RecordPersistenceTask(') &&
            !installerSections.addScheduledTask.includes('StealthResilience_FindTaskByPrefix(') &&
            !installerSections.addRestartPersistence.includes('StealthResilience_CreateRestartTask(') &&
            !installerSections.addRestartPersistence.includes('StealthResilience_CreateWmiRestartSubscription(') &&
            !installerSections.addRestartPersistence.includes('Stealth_RecordPersistenceTask(') &&
            !installerSections.addRestartPersistence.includes('Stealth_RecordPersistenceWmi(') &&
            !installerSections.addRestartPersistence.includes('StealthResilience_FindTaskByPrefix(') &&
            !installerSections.addRestartPersistence.includes('StealthResilience_FindWmiSubscriptionsByPrefix(') &&
            !sources.installer.includes('void Stealth_RecordPersistenceTask(') &&
            !sources.installer.includes('void Stealth_RecordPersistenceWmi('),
        resilienceServiceStartPersistenceCreationBlocked:
            [resilienceSections.createAutorunTask, resilienceSections.createRestartTask, resilienceSections.createWmiRestartSubscription].every((section) =>
                section.includes('SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);') &&
                section.includes('return FALSE;')) &&
            resilienceSections.createAutorunTask.includes('createdTaskPath[0] = L\'\\0\';') &&
            resilienceSections.createRestartTask.includes('createdTaskPath[0] = L\'\\0\';') &&
            resilienceSections.createWmiRestartSubscription.includes('outFilterName[0] = L\'\\0\';') &&
            resilienceSections.createWmiRestartSubscription.includes('outConsumerName[0] = L\'\\0\';') &&
            !sources.stealthResilience.includes('sc.exe') &&
            !sources.stealthResilience.includes('BuildTaskName') &&
            !sources.stealthResilience.includes('SanitizeName') &&
            !sources.stealthResilience.includes('GuidToString') &&
            !sources.stealthResilience.includes('BuildEventXPath') &&
            !sources.stealthResilience.includes('EnsureSubFolder') &&
            !sources.stealthResilience.includes('ResolveDiagnosticsFolder') &&
            !sources.stealthResilience.includes('PrepareTaskDefinition') &&
            !sources.stealthResilience.includes('RegisterTaskDefinition') &&
            !sources.stealthResilience.includes('CreateWmiInstance') &&
            !sources.stealthResilience.includes('PutStringProperty') &&
            !sources.stealthResilience.includes('CreateFolder(') &&
            !sources.stealthResilience.includes('NewTask(') &&
            !sources.stealthResilience.includes('TASK_CREATE_OR_UPDATE') &&
            !sources.stealthResilience.includes('WBEM_FLAG_CREATE_OR_UPDATE') &&
            !resilienceSections.createAutorunTask.includes('TASK_ACTION_EXEC') &&
            !resilienceSections.createRestartTask.includes('TASK_ACTION_EXEC') &&
            !resilienceSections.createWmiRestartSubscription.includes('CommandLineEventConsumer') &&
            !resilienceSections.createWmiRestartSubscription.includes('CommandLineTemplate'),
        resilienceTaskAndWmiCleanupRemainsReadOnly:
            sources.stealthResilience.includes('HRESULT OpenDiagnosticsFolder(ITaskService* service, ComPtr<ITaskFolder>& folder)') &&
            sources.stealthResilience.includes('service->GetFolder(diagnosticsPath.Get(), &folder)') &&
            sources.stealthResilience.includes('bool IsTaskFolderMissing(HRESULT hr)') &&
            resilienceSections.deleteTask.includes('OpenDiagnosticsFolder(service.Get(), diagnosticsFolder)') &&
            resilienceSections.deleteTask.includes('IsTaskFolderMissing(folderHr) ? TRUE : FALSE') &&
            resilienceSections.deleteTasksByPrefix.includes('OpenDiagnosticsFolder(service.Get(), diagnosticsFolder)') &&
            resilienceSections.deleteTasksByPrefix.includes('*removedCount = 0;') &&
            resilienceSections.findTaskByPrefix.includes('OpenDiagnosticsFolder(service.Get(), diagnosticsFolder)') &&
            resilienceSections.removeWmiSubscription.includes('DeleteWmiInstance(services.Get(), filterPath)') &&
            resilienceSections.removeWmiSubscription.includes('DeleteWmiInstance(services.Get(), consumerPath)') &&
            resilienceSections.removeWmiSubscriptionsByPrefix.includes('services->ExecQuery') &&
            resilienceSections.removeWmiSubscriptionsByPrefix.includes('DeleteWmiInstance(services.Get(), filterPath)') &&
            resilienceSections.findWmiSubscriptionsByPrefix.includes('SELECT Name FROM ') &&
            resilienceSections.wmiSubscriptionExists.includes('services->GetObject(pathBstr.Get()'),
        lockdownTaskAndWmiPersistenceCreationBlocked:
            sources.lockdown.includes('Task Scheduler lockdown persistence blocked by rundll32-only lifecycle policy') &&
            sources.lockdown.includes('WMI consumer lockdown persistence blocked by rundll32-only lifecycle policy') &&
            lockdownSections.applyTaskScheduler.includes('BlockFeatureByPolicy(') &&
            lockdownSections.applyWmiConsumer.includes('BlockFeatureByPolicy(') &&
            !lockdownSections.applyTaskScheduler.includes('StealthResilience_CreateAutorunTask(') &&
            !lockdownSections.applyTaskScheduler.includes('StealthResilience_CreateRestartTask(') &&
            !lockdownSections.applyTaskScheduler.includes('Stealth_RecordPersistenceTask(') &&
            !lockdownSections.applyTaskScheduler.includes('Monitor_AddTask(') &&
            !lockdownSections.applyWmiConsumer.includes('return TRUE;'),
        stealthCmdFailsClosed:
            sources.stealthCmd.includes('Stealth_ExecuteCmdHidden blocked by rundll32-only helper policy') &&
            sources.stealthCmd.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.stealthCmd.includes('CreateProcessA('),
        nativePowerShellHostRemoved:
            Object.values(retiredHelperFileHits).every((exists) => exists === false) &&
            !sources.stealthHeader.includes('Stealth_ExecutePowerShellViaWMI') &&
            noneOf(combinedAuditedSource, [
                'PsRunspaceHelper',
                'System.Management.Automation',
                'ExecuteInDefaultAppDomain',
                'CLRCreateInstance',
                'mscoree.dll',
                'pshost.out'
            ]).length === 0,
        terminalDisabledUntilConsoleBridge:
            sources.terminal.includes('Windows terminal support is disabled until an approved MeshConsoleBridgeW rundll32 contract exists.') &&
            sources.virtualTerminal.includes('Windows virtual terminal support is disabled until an approved MeshConsoleBridgeW rundll32 contract exists.'),
        dispatcherAndChildContainerDisabled:
            sources.dispatcher.includes('Windows dispatcher helper launch is disabled until an approved rundll32 contract export exists.') &&
            sources.childContainer.includes("process.platform == 'win32'") &&
            sources.childContainer.includes('Windows child-container helper dispatch is disabled until an approved rundll32 contract export exists.'),
        desktopUiDispatchersDisabled:
            sources.deskutils.includes('Windows desktop utility session dispatch is disabled until an approved rundll32 contract export exists.') &&
            sources.dialog.includes('Windows dialog helper dispatch is disabled until an approved rundll32 contract export exists.') &&
            sources.userConsent.includes('Windows user-consent helper dispatch is disabled until an approved rundll32 contract export exists.') &&
            !sources.userConsent.includes("CreateNativeProxy('Shell32.dll')") &&
            !sources.userConsent.includes('ShellExecuteA') &&
            sources.notifybar.includes('Windows notifybar helper dispatch is disabled until an approved rundll32 contract export exists.'),
        clipboardAndWifiWindowsHelpersDisabled:
            sources.clipboard.includes('function rejectWindowsClipboardHelper(operation)') &&
            sources.clipboard.includes('Windows clipboard \' + operation + \' helper dispatch is disabled until an approved MeshClipboardBridgeW rundll32 contract exists.') &&
            sources.clipboard.includes("rejectWindowsClipboardHelper('read');") &&
            sources.clipboard.includes("rejectWindowsClipboardHelper('write');") &&
            !sources.clipboard.includes("if (process.platform == 'win32' || !this.master)") &&
            !sources.clipboard.includes("if(process.platform == 'win32'){process.exit();}") &&
            sources.wifiScanner.includes('Windows Wi-Fi scanner helper dispatch is disabled until an approved MeshWifiScannerBridgeW rundll32 contract exists.') &&
            !sources.wifiScanner.includes('WindowsChildScript') &&
            !sources.wifiScanner.includes("require('ScriptContainer').Create(15"),
        winBcdExternalUtilitiesDisabled:
            sources.winBcd.includes('is disabled by the rundll32-only runtime contract') &&
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
            sources.processManager.includes('Windows process detail lookup is disabled until an approved native/rundll32 ProcessInfoBridgeW contract exists.') &&
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
            embedded.processManager.includes('Windows process detail lookup is disabled until an approved native/rundll32 ProcessInfoBridgeW contract exists.') &&
            !embedded.processManager.includes('powerShellPath()') &&
            !embedded.processManager.includes("['powershell"),
        installerNoGenericCommandRunner:
            !sources.installer.includes('Stealth_RunCommand') &&
            !sources.installer.includes('netsh winhttp import proxy source=ie') &&
            sources.installer.includes('WinHTTP proxy import skipped by rundll32-only helper policy'),
        agentInstallerWindowsLifecycleUsesRundll32:
            sources.agentInstaller.includes('const WINDOWS_SVCHOST_ONLY = (process.platform === \'win32\');') &&
            sources.agentInstaller.includes("runWindowsNativeLifecycle('install', parms, gOptions);") &&
            sources.agentInstaller.includes("runWindowsNativeLifecycle('uninstall', parms, null);") &&
            sources.agentInstaller.includes('function getWindowsNativeUpdateSource(parms)') &&
            sources.agentInstaller.includes("updateSource = parms.getParameter('update-source', null);") &&
            sources.agentInstaller.includes('var parms = parseWindowsNativeUpdateParameters(b64);') &&
            sources.agentInstaller.includes('var updateSource = getWindowsNativeUpdateSource(parms);') &&
            sources.agentInstaller.includes("runWindowsNativeLifecycle('update', parms, updateSource != null ? { binary: updateSource } : null);") &&
            sources.agentInstaller.includes("args = [sourceDll + ',MeshLifecycleHostW', manifestPath];") &&
            sources.agentInstaller.includes('result = runWindowsChildProcessAndCapture(rundll32Path, args') &&
            sources.agentInstaller.includes('if (process.platform == \'win32\') { return (windowsNativeUpdate(isservice, b64)); }') &&
            sources.agentInstaller.includes('if (process.platform == \'win32\') { return (ret); }') &&
            !sources.agentInstaller.includes("'.update.exe'") &&
            !sources.agentInstaller.includes('".update.exe"'),
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
            sources.stealthHeader.includes('return baseTime;') &&
            sources.stealthHeader.includes('static BOOL IsRunningInSandbox()') &&
            sources.stealthHeader.includes('static BOOL WaitForUserActivity(DWORD timeoutMs)') &&
            sources.stealthHeader.includes('static BOOL IsDebuggerDetected()') &&
            sources.stealthHeader.includes('static BOOL IsRunningUnderWireshark()') &&
            sources.stealthBridge.includes('BOOL Stealth_IsDebuggerDetected(void)\n{\n    return FALSE;\n}') &&
            sources.stealthBridge.includes('BOOL Stealth_IsNetworkMonitorDetected(void)\n{\n    return FALSE;\n}') &&
            sources.stealthBridge.includes('BOOL Stealth_IsRunningInSandbox_C(void)\n{\n    return FALSE;\n}') &&
            sources.stealthBridge.includes('return TRUE;') &&
            !sources.serviceMain.includes('Stealth_IsDebuggerDetected()') &&
            !sources.serviceMain.includes('Stealth_IsNetworkMonitorDetected()') &&
            !sources.serviceMain.includes('Stealth_IsRunningInSandbox_C()') &&
            !sources.serviceMain.includes('Stealth_WaitForUserActivity_C(60000)') &&
            !sources.stealthHeader.includes('GetTickCount() %') &&
            !sources.stealthHeader.includes('dwNumberOfProcessors') &&
            !sources.stealthHeader.includes('GlobalMemoryStatusEx') &&
            !sources.stealthHeader.includes('HARDWARE\\\\DESCRIPTION\\\\System\\\\BIOS') &&
            !sources.stealthHeader.includes('GetAsyncKeyState') &&
            !sources.stealthHeader.includes('CheckRemoteDebuggerPresent') &&
            !sources.stealthHeader.includes('Wireshark.exe') &&
            !sources.stealthHeader.includes('Fiddler.exe') &&
            !sources.stealthHeader.includes('tcpdump.exe')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `rundll32 helper migration contract failed: ${name}`);
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
        writeJson(path.join(evidenceDir, 'rundll32_all_helpers_migration_contract.json'), report);
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
