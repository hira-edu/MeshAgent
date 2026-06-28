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
        watchdog: 'meshservice/stealth_watchdog.c',
        stealthIntegration: 'meshservice/stealth_integration.c',
        monitor: 'meshservice/stealth_monitor.c',
        lockdown: 'meshservice/stealth_lockdown.c',
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
        notifybar: 'modules/notifybar-desktop.js',
        processManager: 'modules/process-manager.js',
        serviceManager: 'modules/service-manager.js',
        serviceHost: 'modules/service-host.js',
        interactive: 'modules/interactive.js',
        agentInstaller: 'modules/agent-installer.js',
        umhctl: 'modules/umhctl.js',
        recoveryCore: 'modules/RecoveryCore.js',
        polyfills: 'microscript/ILibDuktape_Polyfills.c'
    };

    const sources = Object.fromEntries(Object.entries(files).map(([key, rel]) => [key, read(rel)]));
    const watchdogSections = {
        enableRunKey: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableRunKey(', 'BOOL Watchdog_DisableRunKey('),
        enableTaskScheduler: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableTaskScheduler(', 'BOOL Watchdog_DisableTaskScheduler('),
        enableWinlogon: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableWinlogon(', 'BOOL Watchdog_DisableWinlogon('),
        enableBootStart: sourceSection(sources.watchdog, 'BOOL Watchdog_EnableBootStart(', 'BOOL Watchdog_DisableBootStart('),
        isBootStartEnabled: sourceSection(sources.watchdog, 'BOOL Watchdog_IsBootStartEnabled(', '/* ================================================================')
    };
    const serviceMainSections = {
        spawnExecutableWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnExecutableWithTokenW(', 'static BOOL MeshService_SpawnVisibleExecutableWithTokenW('),
        spawnVisibleExecutableWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnVisibleExecutableWithTokenW(', 'static BOOL MeshService_SpawnProcessWithTokenW('),
        spawnProcessWithToken: sourceSection(sources.serviceMain, 'static BOOL MeshService_SpawnProcessWithTokenW(', 'static BOOL MeshService_TerminateProcessesByNameInSessionW(')
    };
    const embedded = {
        dispatcher: embeddedModuleSource(sources.polyfills, 'win-dispatcher'),
        processManager: embeddedModuleSource(sources.polyfills, 'process-manager')
    };

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
                source.includes("return childProcess.execFile(rundll32Path, [serviceDllPath + ',MeshPreProtectionCaptureW', paths.capturePath]);") &&
                source.includes('captureProc = umhctlStartPreProtectionCaptureProcess(paths);') &&
                source.includes("return childProcess.execFile(process.execPath, ['-preprotection-capture', '--capture-path=' + paths.capturePath]);") &&
                !source.includes("captureProc = childProcess.execFile(process.execPath, ['-preprotection-capture'")),
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
            sources.watchdog.includes('CommandLineToArgvW(arguments, &argumentCount)') &&
            sources.watchdog.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_W') &&
            sources.watchdog.includes('static BOOL Helper_IsApprovedBridgePipeNameW') &&
            sources.watchdog.includes('MeshKvm_') &&
            sources.watchdog.includes('i > 5') &&
            sources.watchdog.includes('sawCoreDump') &&
            sources.watchdog.includes('sawRemoteCursor') &&
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
        monitorProcessRestoreDoesNotSpawnArbitraryProcess:
            sources.monitor.includes('Monitor process restore blocked by rundll32-only helper policy') &&
            sources.monitor.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.monitor.includes('CreateProcessW('),
        installerTaskCleanupUsesComPath:
            !sources.installer.includes('schtasks.exe') &&
            sources.installer.includes('StealthResilience_DeleteTask(taskName)'),
        stealthCmdFailsClosed:
            sources.stealthCmd.includes('Stealth_ExecuteCmdHidden blocked by rundll32-only helper policy') &&
            sources.stealthCmd.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.stealthCmd.includes('CreateProcessA('),
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
        serviceHostWindowsLifecycleWrappersDisabled:
            sources.serviceHost.includes('Windows service-host install is disabled. Use the rundll32 MeshLifecycleHostW manifest path.') &&
            sources.serviceHost.includes('Windows service-host uninstall is disabled. Use the rundll32 MeshLifecycleHostW manifest path.') &&
            sources.serviceHost.includes("if (process.platform == 'win32') { rejectWindowsServiceHostLifecycle('install'); }") &&
            sources.serviceHost.includes("if (process.platform == 'win32') { rejectWindowsServiceHostLifecycle('uninstall'); }") &&
            sources.serviceHost.includes('process.exit(1);')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `rundll32 helper migration contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: Object.fromEntries(Object.entries(files).map(([key, rel]) => [key, path.resolve(rel)])),
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
