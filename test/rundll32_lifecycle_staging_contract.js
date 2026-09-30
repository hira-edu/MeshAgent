const fs = require('fs');
const path = require('path');

// Static contract for the rundll32 lifecycle, UMH and consent hosts: private
// uninstall staging, unique and swept staged artifacts, timed-out host
// handling, the anchored MasterService.exe path, and fail-closed job setup.

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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunction(source, name) {
    // The definition is the occurrence whose parameter list is followed by the
    // opening brace; prototypes and call sites are skipped.
    let start = source.indexOf(name + '(');
    while (start >= 0) {
        let depth = 0;
        let i = start + name.length;
        for (; i < source.length; ++i) {
            if (source[i] === '(') {
                depth += 1;
            } else if (source[i] === ')') {
                depth -= 1;
                if (depth === 0) {
                    break;
                }
            }
        }
        if (/^\s*\{/.test(source.slice(i + 1, i + 16))) {
            const bodyStart = source.indexOf('{', i);
            depth = 0;
            for (let j = bodyStart; j < source.length; ++j) {
                if (source[j] === '{') {
                    depth += 1;
                } else if (source[j] === '}') {
                    depth -= 1;
                    if (depth === 0) {
                        return source.slice(start, j + 1);
                    }
                }
            }
            throw new Error(`${name} body end not found`);
        }
        start = source.indexOf(name + '(', start + name.length);
    }
    throw new Error(`${name} definition not found`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const contractPath = path.resolve('meshservice', 'rundll32_contract.c');
    const consentModulePath = path.resolve('modules', 'win-userconsent.js');
    const source = fs.readFileSync(contractPath, 'utf8');
    const consentModule = fs.readFileSync(consentModulePath, 'utf8');

    const tempDir = extractFunction(source, 'MeshRundll32_PrepareTempLifecycleDirectoryW');
    const stateDir = extractFunction(source, 'MeshRundll32_PrepareLifecycleStateDirectoryW');
    const sweep = extractFunction(source, 'MeshRundll32_SweepStaleLifecycleArtifactsW');
    const hostDll = extractFunction(source, 'MeshRundll32_PrepareLifecycleHostDllW');
    const launch = extractFunction(source, 'MeshRundll32_LaunchLifecycleHostW');
    const lifecycleHost = extractFunction(source, 'MeshLifecycleHostW');
    const selfTest = extractFunction(source, 'MeshRundll32_LaunchSelfTestHostW');
    const approvedPath = extractFunction(source, 'MeshUmhHost_IsApprovedMasterServicePathW');
    const managedLocation = extractFunction(source, 'MeshUmhHost_IsManagedMasterServiceLocationW');
    const readManifest = extractFunction(source, 'MeshUmhHost_ReadManifestW');
    const runManifest = extractFunction(source, 'MeshUmhHost_RunManifestCommandW');
    const argEquals = extractFunction(source, 'MeshUmhHost_ArgEquals');
    const resultPipe = extractFunction(source, 'MeshUserConsent_OpenResultPipeW');
    const execShell = extractFunction(source, 'MeshConsoleBridge_RunRedirectedShellW');

    const onWatchdogStart = consentModule.indexOf('function onWatchdog');
    const onWatchdog = onWatchdogStart >= 0 ? consentModule.slice(onWatchdogStart, consentModule.indexOf('\n    }', onWatchdogStart)) : '';

    const checks = {
        uninstallStagingUsesPrivateSystemTempDirectory:
            !tempDir.includes('GetTempPathW(') &&
            tempDir.includes('GetSystemWindowsDirectoryW(') &&
            tempDir.includes('MESH_RUNDLL32_TEMP_STAGING_SDDL') &&
            tempDir.includes('CreateDirectoryW(tempDir, &securityAttributes)') &&
            !tempDir.includes('CreateDirectoryIfMissingW(') &&
            /#define MESH_RUNDLL32_TEMP_STAGING_SDDL L"D:P\(/.test(source),
        validateUninstallStagesOutsideInstallRoot:
            hostDll.includes('action == MESH_RUNDLL32_LIFECYCLE_ACTION_UNINSTALL || action == MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_UNINSTALL'),
        launcherRemovesEmptyStagingDirectory:
            launch.includes('RemoveDirectoryW(MeshRundll32_TempLifecycleDir)'),
        stagedArtifactNamesAreUniquePerCall:
            source.includes('L"host-%lu-%llu-%ld.dll"') &&
            source.includes('L"manifest-%lu-%llu-%ld.ini"') &&
            !source.includes('L"host-%lu-%llu.dll"') &&
            !source.includes('L"manifest-%lu-%llu.ini"'),
        staleArtifactsAreSweptOnlyForExitedLaunchers:
            stateDir.includes('MeshRundll32_SweepStaleLifecycleArtifactsW(lifecycleDir);') &&
            sweep.includes('MESH_RUNDLL32_STALE_ARTIFACT_AGE_MS') &&
            sweep.includes('MeshRundll32_ProcessIsRunning((DWORD)pid)') &&
            sweep.includes('pid == GetCurrentProcessId()'),
        lifecycleHostConsumesManifestOnce:
            lifecycleHost.indexOf('(void)DeleteFileW(manifestPath);') > lifecycleHost.indexOf('Failed to read manifest'),
        timedOutMutatingHostIsNotKilled:
            launch.includes('MESH_RUNDLL32_LIFECYCLE_ACTION_VALIDATE_PACKAGE))') &&
            launch.includes('to finish its own transaction') &&
            launch.includes('childExited = (WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0);') &&
            launch.includes('(pi.hProcess == NULL || childExited) && manifestPath') &&
            launch.includes('(pi.hProcess == NULL || childExited) && deleteHostDllOnExit'),
        selfTestReportsTimeoutNotStillActive:
            selfTest.includes('exitCode = (waitError != ERROR_SUCCESS) ? waitError : ERROR_GEN_FAILURE;') &&
            selfTest.includes('else if (!GetExitCodeProcess(pi.hProcess, &exitCode))'),
        masterServicePathIsCanonicalAndAnchored:
            approvedPath.includes('GetFullPathNameW(') &&
            approvedPath.includes('MeshUmhHost_IsManagedMasterServiceLocationW(fullPath)') &&
            managedLocation.includes('FOLDERID_ProgramData') &&
            managedLocation.includes('L"%ls\\\\UserModeHook"') &&
            readManifest.includes('StringCchCopyW(manifestOut->exePath, _countof(manifestOut->exePath), approvedExePath)'),
        manifestRejectsTruncatedValues:
            readManifest.includes('read >= (DWORD)_countof(manifestOut->exePath) - 1') &&
            readManifest.includes('read >= (DWORD)_countof(manifestOut->args[i]) - 1'),
        manifestArgsMatchCaseSensitively:
            argEquals.includes('wcscmp(manifest->args[index], expected)') &&
            !argEquals.includes('_wcsicmp('),
        masterServiceJobFailsClosed:
            runManifest.includes('L"job object unavailable"') &&
            runManifest.includes('L"job object configuration failed"') &&
            runManifest.includes('L"job assignment failed for MasterService.exe"') &&
            !runManifest.includes('if (job != NULL && !AssignProcessToJobObject'),
        consentResultPipeWaitsOnlyWhileBusy:
            resultPipe.includes('if (lastError != ERROR_PIPE_BUSY)') &&
            resultPipe.includes('WaitNamedPipeW(pipeName, (DWORD)(deadline - now))') &&
            !resultPipe.includes('Sleep('),
        consentWatchdogStopsDialogHost:
            onWatchdog.includes('child.kill();'),
        execDrainIsBoundedAfterShellExit:
            execShell.includes('processCompleted ? MESH_CONSOLE_BRIDGE_EXEC_OUTPUT_DRAIN_MS : INFINITE') &&
            execShell.includes('MeshConsoleBridge_StopCopyThread(outputThread, 2000);'),
        bridgeStdHandlesAreNotInherited:
            source.includes('SetHandleInformation(stdHandle, HANDLE_FLAG_INHERIT, 0);')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `rundll32 lifecycle staging contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: { contractPath, consentModulePath },
        checks
    };

    if (evidenceDir) {
        ensureDir(evidenceDir);
        fs.writeFileSync(path.join(evidenceDir, 'rundll32_lifecycle_staging_contract.json'), JSON.stringify(report, null, 2));
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
