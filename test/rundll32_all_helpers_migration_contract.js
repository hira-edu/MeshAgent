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
        serviceMain: 'meshservice/ServiceMain.c',
        watchdog: 'meshservice/stealth_watchdog.c',
        monitor: 'meshservice/stealth_monitor.c',
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
        notifybar: 'modules/notifybar-desktop.js',
        processManager: 'modules/process-manager.js',
        serviceManager: 'modules/service-manager.js',
        serviceHost: 'modules/service-host.js',
        interactive: 'modules/interactive.js',
        agentInstaller: 'modules/agent-installer.js',
        polyfills: 'microscript/ILibDuktape_Polyfills.c'
    };

    const sources = Object.fromEntries(Object.entries(files).map(([key, rel]) => [key, read(rel)]));
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
            sources.processPipe.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A') &&
            sources.processPipe.includes('blocked-user-session') &&
            !sources.processPipe.includes('allow-helper-reentry') &&
            !sources.processPipe.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA') &&
            !sources.processPipe.includes('strictServiceOnly == 0 || allowDesktopBridge != 0'),
        serviceMainRejectsDirectHelperReentry:
            sources.serviceMain.includes('direct -exec/-b64exec/--slave helper re-entry is disabled') &&
            sources.serviceMain.includes('Use an approved rundll32 contract export'),
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
        watchdogDoesNotShellOutToTaskScheduler:
            !sources.watchdog.includes('schtasks.exe /Create') &&
            !sources.watchdog.includes('schtasks.exe /Delete') &&
            !sources.watchdog.includes('schtasks.exe /Query') &&
            sources.watchdog.includes('StealthResilience_TaskExists(config->bootName)'),
        watchdogWatchedProcessRestoreBlocked:
            sources.watchdog.includes('Watchdog watched-process registration blocked by rundll32-only helper policy') &&
            sources.watchdog.includes('Watchdog watched-process launch blocked by rundll32-only helper policy') &&
            sources.watchdog.includes('ERROR_ACCESS_DISABLED_BY_POLICY') &&
            !sources.watchdog.includes('CreateProcessW('),
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
