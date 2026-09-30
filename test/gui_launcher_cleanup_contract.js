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
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const contractPath = path.resolve('meshservice', 'runtime_host_contract.c');
    const headerPath = path.resolve('meshservice', 'runtime_host_contract.h');
    const defPath = path.resolve('meshservice', 'MeshServiceHost.def');
    const installerPath = path.resolve('meshservice', 'service_deployment.c');
    const guiHarnessPath = path.resolve('test', 'gui_button_race_harness', 'Program.cs');
    const serviceMain = readSource(serviceMainPath);
    const contract = readSource(contractPath);
    const header = readSource(headerPath);
    const def = readSource(defPath);
    const installer = readSource(installerPath);
    const guiHarness = readSource(guiHarnessPath);
    const launcherCleanupStart = contract.indexOf('BOOL MeshRuntimeHost_LaunchLauncherCleanupW');
    const launcherCleanupEnd = contract.indexOf('BOOL MeshRuntimeHost_LaunchSelfTestHostW', launcherCleanupStart);
    const launcherCleanupSection =
        launcherCleanupStart >= 0 && launcherCleanupEnd > launcherCleanupStart
            ? contract.slice(launcherCleanupStart, launcherCleanupEnd)
            : '';

    const checks = {
        exportsCleanupEntrypoint:
            header.includes('MESH_RUNTIME_HOST_ENTRY_LAUNCHER_CLEANUP_W') &&
            header.includes('void CALLBACK MeshLauncherCleanupW') &&
            def.includes('MeshLauncherCleanupW'),
        cleanupUsesRuntimeHostNoShell:
            launcherCleanupSection.includes('BOOL MeshRuntimeHost_LaunchLauncherCleanupW') &&
            launcherCleanupSection.includes('CreateProcessW(runtimeHostPath, commandLine') &&
            !launcherCleanupSection.includes('cmd.exe /c') &&
            !launcherCleanupSection.includes('powershell'),
        cleanupWaitsForParentThenDeletes:
            contract.includes('OpenProcess(SYNCHRONIZE, FALSE, parentPid)') &&
            contract.includes('WaitForSingleObject(parentProcess, timeoutMs)') &&
            contract.includes('DeleteFileW(targetPath)') &&
            contract.includes('MoveFileExW(targetPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)'),
        guiSchedulesCleanupOnlyAfterSuccessfulInstall:
            serviceMain.includes('LOWORD(wParam) == IDC_INSTALLBUTTON && MeshService_ShouldCleanupLauncherAfterLifecycle(modulePath)') &&
            serviceMain.includes('MeshRuntimeHost_LaunchLauncherCleanupW(modulePath, GetCurrentProcessId(), 60000)') &&
            serviceMain.indexOf('MeshRuntimeHost_LaunchLauncherCleanupW(modulePath, GetCurrentProcessId(), 60000)') <
                serviceMain.indexOf('EndDialog(hDlg, LOWORD(wParam));', serviceMain.indexOf('if (result)')),
        guiInstallButtonSelectsUpdateWhenInstalled:
            serviceMain.includes('static MeshRuntimeHostLifecycleAction MeshService_GetGuiInstallButtonLifecycleAction(void)') &&
            serviceMain.includes('int serviceState = GetServiceState(MeshService_GetDialogServiceNameA());') &&
            serviceMain.includes('return (serviceState == 100) ?') &&
            !serviceMain.includes('return (serviceState == 0 || serviceState == 100) ?') &&
            serviceMain.includes('MESH_RUNTIME_HOST_LIFECYCLE_ACTION_INSTALL :\n\t\tMESH_RUNTIME_HOST_LIFECYCLE_ACTION_UPDATE') &&
            serviceMain.includes('lifecycleAction = MeshService_GetGuiInstallButtonLifecycleAction();'),
        guiLifecycleUsesDialogServiceName:
            serviceMain.includes('static char g_dialogServiceName[256] = { 0 };') &&
            serviceMain.includes('StringCchCopyA(g_dialogServiceName, _countof(g_dialogServiceName), meshServiceName)') &&
            serviceMain.includes('int r = GetServiceState(MeshService_GetDialogServiceNameA());'),
        guiServiceStateDoesNotAliasQueryFailureToMissing:
            serviceMain.includes('if (openError == ERROR_SERVICE_DOES_NOT_EXIST)') &&
            serviceMain.includes('SetLastError(openError);') &&
            !serviceMain.includes('case 0:\n\t\tcase 100: // Not installed') &&
            !serviceMain.includes('case 0:\n\t\t\t\tcase 100: // Not installed'),
        obsoleteSharedHostStatusCommandRemoved:
            !serviceMain.includes('MeshService_PrintServiceHostStatusJson'),
        installedPayloadGuard:
            serviceMain.includes('static BOOL MeshService_ShouldCleanupLauncherAfterLifecycle') &&
            serviceMain.includes('_wcsicmp(modulePath, paths.exePath) == 0') &&
            serviceMain.includes('MeshService_PathIsUnderDirectoryW(modulePath, paths.installDir)'),
        lifecycleStatePathDoesNotAliasCombineOutput:
            !contract.includes('MeshRuntimeHost_CombinePathW(lifecycleDir, _countof(lifecycleDir), lifecycleDir, L"runtime-host-lifecycle")') &&
            contract.includes('wchar_t stateRoot[MAX_PATH * 4] = {0};') &&
            contract.includes('MeshRuntimeHost_CombinePathW(lifecycleDir, _countof(lifecycleDir), stateRoot, L"runtime-host-lifecycle")'),
        installerLogPathDoesNotAliasCombineOutput:
            !installer.includes('MeshInstaller_CombinePath(logDir, _countof(logDir), logDir, L"logs")') &&
            installer.includes('wchar_t defaultRoot[MAX_PATH] = {0};') &&
            installer.includes('MeshInstaller_CombinePath(logDir, _countof(logDir), defaultRoot, L"logs")'),
        uninstallValidationUsesTempHostArtifacts:
            contract.includes('MeshRuntimeHost_PrepareTempManifestPathW') &&
            contract.includes('MeshAgent-runtime-host-lifecycle') &&
            contract.includes('ServiceDeploy_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log")'),
        uninstallLifecycleDoesNotLoadInstalledDll:
            contract.includes('action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL') &&
            contract.includes('MeshRuntimeHost_PrepareTempHostDllPathW(hostDllPath, hostDllPathCch)') &&
            contract.includes('ServiceDeploy_StageServiceHostDllForLifecycleHost(sourceExePath, uninstallSourceDll, hostDllPath)') &&
            !contract.includes('action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_UNINSTALL ||\n         action == MESH_RUNTIME_HOST_LIFECYCLE_ACTION_VALIDATE_INSTALL'),
        uninstallRemovesOrphanedInstallDirectories:
            installer.includes('discovery->stateKind == SERVICE_LIFECYCLE_STATE_CLEAN &&') &&
            installer.includes('!discovery->installRootExists &&') &&
            installer.includes('!discovery->logsDirExists') &&
            installer.includes('SERVICE_LIFECYCLE_ACTION_UNINSTALL'),
        provisioningAcceptsValidatedSidecarMsh:
            installer.includes('sourceSidecarConfigPresent') &&
            installer.includes('ServiceDeploy_BuildSiblingPathWithExtension(sourceExePath, L".msh"') &&
            installer.includes('ServiceDeploy_CopyFileOverwrite(sidecarPath, destPath)') &&
            installer.includes('target->configAvailable = (target->sourceEmbeddedConfigPresent || target->sourceSidecarConfigPresent)'),
        updateStagesPackageProvisioningThroughSidecarFallback:
            installer.includes('ServiceDeploy_EnsureConfigFile(sourceExePath, tx->stagedConfPath)') &&
            installer.includes('ServiceDeploy_EnsureMshFile(sourceExePath, tx->stagedMshPath)') &&
            installer.includes('[UPDATE] Unable to stage a valid provisioning .conf file from package payload') &&
            installer.includes('[UPDATE] Unable to stage a valid provisioning .msh file from package payload') &&
            !installer.includes('[UPDATE] Unable to stage a valid provisioning .conf file from embedded package payload') &&
            !installer.includes('[UPDATE] Unable to stage a valid provisioning .msh file from embedded package payload'),
        runtimeHarnessRequiresLauncherRemoval:
            guiHarness.includes('var launcherRemoved = WaitForLauncherRemoval(guiExe, TimeSpan.FromMinutes(1));') &&
            guiHarness.includes('launcherRemoved &&'),
        runtimeHarnessUsesUpdateValidation:
            guiHarness.includes('RunCliUntilSuccess(cliRunnerExe, "-validate-update", 180000, 4, 2000)') &&
            guiHarness.includes('post-update-validate-update-attempts=') &&
            !guiHarness.includes('post-update-validate-install-attempts='),
        runtimeHarnessRequiresObservedLifecycleAudit:
            guiHarness.includes('var audit = AnalyzeGuiActionDelta(delta, "install");') &&
            guiHarness.includes('var audit = AnalyzeGuiActionDelta(delta, "update");') &&
            guiHarness.includes('var audit = AnalyzeGuiActionDelta(delta, "uninstall");') &&
            guiHarness.includes('return audit.SuccessCount > 0 && audit.FailureCount == 0;') &&
            guiHarness.includes('LineMatchesGuiLifecycleAction(line, token)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `GUI launcher cleanup contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            serviceMainPath,
            contractPath,
            headerPath,
            defPath,
            installerPath,
            guiHarnessPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'gui_launcher_cleanup_contract.json'), report);
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
