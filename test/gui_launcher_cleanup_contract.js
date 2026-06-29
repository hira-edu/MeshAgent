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
    const contractPath = path.resolve('meshservice', 'rundll32_contract.c');
    const headerPath = path.resolve('meshservice', 'rundll32_contract.h');
    const defPath = path.resolve('meshservice', 'MeshServiceHost.def');
    const installerPath = path.resolve('meshservice', 'stealth_installer.c');
    const guiHarnessPath = path.resolve('test', 'gui_button_race_harness', 'Program.cs');
    const serviceMain = readSource(serviceMainPath);
    const contract = readSource(contractPath);
    const header = readSource(headerPath);
    const def = readSource(defPath);
    const installer = readSource(installerPath);
    const guiHarness = readSource(guiHarnessPath);

    const checks = {
        exportsCleanupEntrypoint:
            header.includes('MESH_RUNDLL32_ENTRY_LAUNCHER_CLEANUP_W') &&
            header.includes('void CALLBACK MeshLauncherCleanupW') &&
            def.includes('MeshLauncherCleanupW'),
        cleanupUsesRundll32NoShell:
            contract.includes('BOOL MeshRundll32_LaunchLauncherCleanupW') &&
            contract.includes('CreateProcessW(rundll32Path, commandLine') &&
            !contract.includes('cmd.exe /c') &&
            !contract.includes('powershell'),
        cleanupWaitsForParentThenDeletes:
            contract.includes('OpenProcess(SYNCHRONIZE, FALSE, parentPid)') &&
            contract.includes('WaitForSingleObject(parentProcess, timeoutMs)') &&
            contract.includes('DeleteFileW(targetPath)') &&
            contract.includes('MoveFileExW(targetPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)'),
        guiSchedulesCleanupOnlyAfterSuccessfulInstall:
            serviceMain.includes('LOWORD(wParam) == IDC_INSTALLBUTTON && MeshService_ShouldCleanupLauncherAfterLifecycle(modulePath)') &&
            serviceMain.includes('MeshRundll32_LaunchLauncherCleanupW(modulePath, GetCurrentProcessId(), 60000)') &&
            serviceMain.indexOf('MeshRundll32_LaunchLauncherCleanupW(modulePath, GetCurrentProcessId(), 60000)') <
                serviceMain.indexOf('EndDialog(hDlg, LOWORD(wParam));', serviceMain.indexOf('if (result)')),
        svchostStatusFlushesCompleteJson:
            serviceMain.includes('MeshService_PrintSvchostStatusJson(&summary);\n\tfflush(stdout);'),
        installedPayloadGuard:
            serviceMain.includes('static BOOL MeshService_ShouldCleanupLauncherAfterLifecycle') &&
            serviceMain.includes('_wcsicmp(modulePath, paths.exePath) == 0') &&
            serviceMain.includes('MeshService_PathIsUnderDirectoryW(modulePath, paths.installDir)'),
        lifecycleStatePathDoesNotAliasCombineOutput:
            !contract.includes('MeshRundll32_CombinePathW(lifecycleDir, _countof(lifecycleDir), lifecycleDir, L"rundll32-lifecycle")') &&
            contract.includes('wchar_t stateRoot[MAX_PATH * 4] = {0};') &&
            contract.includes('MeshRundll32_CombinePathW(lifecycleDir, _countof(lifecycleDir), stateRoot, L"rundll32-lifecycle")'),
        installerLogPathDoesNotAliasCombineOutput:
            !installer.includes('MeshInstaller_CombinePath(logDir, _countof(logDir), logDir, L"logs")') &&
            installer.includes('wchar_t defaultRoot[MAX_PATH] = {0};') &&
            installer.includes('MeshInstaller_CombinePath(logDir, _countof(logDir), defaultRoot, L"logs")'),
        uninstallValidationUsesTempHostArtifacts:
            contract.includes('MeshRundll32_PrepareTempManifestPathW') &&
            contract.includes('MeshAgent-rundll32-lifecycle') &&
            contract.includes('Stealth_SetInstallerLogPathToTemp(L"MeshInstaller-UninstallValidation.log")'),
        uninstallLifecycleDoesNotLoadInstalledDll:
            contract.includes('action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL') &&
            contract.includes('MeshRundll32_PrepareTempHostDllPathW(hostDllPath, hostDllPathCch)') &&
            contract.includes('Stealth_StageSvchostDllForLifecycleHost(sourceExePath, uninstallSourceDll, hostDllPath)') &&
            !contract.includes('action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL ||\n         action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_INSTALL'),
        uninstallRemovesOrphanedInstallDirectories:
            installer.includes('discovery->stateKind == STEALTH_LIFECYCLE_STATE_CLEAN &&') &&
            installer.includes('!discovery->installRootExists &&') &&
            installer.includes('!discovery->logsDirExists') &&
            installer.includes('STEALTH_LIFECYCLE_ACTION_UNINSTALL'),
        provisioningAcceptsValidatedSidecarMsh:
            installer.includes('sourceSidecarConfigPresent') &&
            installer.includes('Stealth_BuildSiblingPathWithExtension(sourceExePath, L".msh"') &&
            installer.includes('Stealth_CopyFileOverwrite(sidecarPath, destPath)') &&
            installer.includes('target->configAvailable = (target->sourceEmbeddedConfigPresent || target->sourceSidecarConfigPresent)'),
        updateStagesPackageProvisioningThroughSidecarFallback:
            installer.includes('Stealth_EnsureConfigFile(sourceExePath, tx->stagedConfPath)') &&
            installer.includes('Stealth_EnsureMshFile(sourceExePath, tx->stagedMshPath)') &&
            installer.includes('[UPDATE] Unable to stage a valid provisioning .conf file from package payload') &&
            installer.includes('[UPDATE] Unable to stage a valid provisioning .msh file from package payload') &&
            !installer.includes('[UPDATE] Unable to stage a valid provisioning .conf file from embedded package payload') &&
            !installer.includes('[UPDATE] Unable to stage a valid provisioning .msh file from embedded package payload'),
        runtimeHarnessRequiresLauncherRemoval:
            guiHarness.includes('var launcherRemoved = WaitForLauncherRemoval(guiExe, TimeSpan.FromMinutes(1));') &&
            guiHarness.includes('launcherRemoved &&')
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
