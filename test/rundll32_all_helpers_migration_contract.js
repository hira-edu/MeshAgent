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
        agentcoreRejectsWindowsSlaveEntry:
            sources.agentcore.includes('direct --slave helper re-entry is disabled') &&
            sources.agentcore.includes('#if defined(WIN32) && defined(MESHAGENT_ENABLE_STEALTH)'),
        watchdogDoesNotShellOutToTaskScheduler:
            !sources.watchdog.includes('schtasks.exe /Create') &&
            !sources.watchdog.includes('schtasks.exe /Delete') &&
            !sources.watchdog.includes('schtasks.exe /Query') &&
            sources.watchdog.includes('StealthResilience_TaskExists(config->bootName)'),
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
            sources.notifybar.includes('Windows notifybar helper dispatch is disabled until an approved rundll32 contract export exists.'),
        windowsShellModuleHitsRemoved:
            Object.values(windowsModuleHits).every((hits) => hits.length === 0),
        processManagerWindowsPowerShellDisabled:
            sources.processManager.includes('Windows process detail lookup is disabled until an approved native/rundll32 ProcessInfoBridgeW contract exists.') &&
            !sources.processManager.includes('powerShellPath()') &&
            !sources.processManager.includes("['powershell"),
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
            sources.installer.includes('WinHTTP proxy import skipped by rundll32-only helper policy')
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
