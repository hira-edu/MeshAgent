const fs = require('fs');
const path = require('path');
const { loadRecoveryCoreVm } = require('./lib/recoverycore_vm');

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

function readText(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function hasAll(source, tokens) {
    return tokens.every((token) => source.includes(token));
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function signature: ${signature}`);
    const open = source.indexOf('{', start);
    assert(open >= 0, `missing function body: ${signature}`);
    let depth = 0;
    for (let i = open; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.substring(start, i + 1);
            }
        }
    }
    throw new Error(`unterminated function body: ${signature}`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const recoveryCorePath = path.resolve('modules', 'RecoveryCore.js');
    const umhctlPath = path.resolve('modules', 'umhctl.js');
    const operatorContractPath = path.resolve('test', 'lib', 'umh_operator_contract.js');
    const rundll32ContractPath = path.resolve('meshservice', 'rundll32_contract.c');
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const rundll32HeaderPath = path.resolve('meshservice', 'rundll32_contract.h');
    const defPath = path.resolve('meshservice', 'MeshServiceHost.def');
    const recoveryCore = readText(recoveryCorePath);
    const umhctl = readText(umhctlPath);
    const operatorContract = readText(operatorContractPath);
    const rundll32Contract = readText(rundll32ContractPath);
    const processPipe = readText(processPipePath);
    const rundll32Header = readText(rundll32HeaderPath);
    const defSource = readText(defPath);
    const { sandbox } = loadRecoveryCoreVm();

    const sharedTokens = [
        "var umhctlAllowedInstallMethodKeys = { standard: 1, setwindowshookex: 1, manualmap: 1, reflective: 1 };",
        'function umhctlMasterServiceCommandSucceeded(exitCode, outputText)',
        'function umhctlMasterServiceCommandFailureDetail(outputText)',
        "sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', native uninstall unavailable; removing service registration only.', sessionid);",
        "sendConsoleText('umhctl: native uninstall cleanup was not proven; reporting uninstall incomplete.', sessionid);",
        'var nativeUninstallOk = umhctlMasterServiceCommandSucceeded(code, out);',
        "sendConsoleText('umhctl: native uninstall failed; clean uninstall is not proven (' + umhctlMasterServiceCommandFailureDetail(out) + ').', sessionid);",
        "completeUninstall(finalCleanSuccess);"
    ];

    const checks = {
        recoveryCoreHasSharedTokens: hasAll(recoveryCore, sharedTokens),
        umhctlHasSharedTokens: hasAll(umhctl, sharedTokens),
        recoveryCoreDoesNotReportForcedRemovalAsClean: !recoveryCore.includes("sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', removing service registration via fallback.', sessionid);") &&
            !recoveryCore.includes('completeUninstall(true);\n        });\n    };'),
        umhctlDoesNotReportForcedRemovalAsClean: !umhctl.includes("sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', removing service registration via fallback.', sessionid);") &&
            !umhctl.includes('completeUninstall(true);\n        });\n    };'),
        recoveryCoreOmitsRetiredHookControl: !recoveryCore.toLowerCase().includes('hookcontrol') &&
            !recoveryCore.toLowerCase().includes('hook-control'),
        umhctlOmitsRetiredHookControl: !umhctl.toLowerCase().includes('hookcontrol') &&
            !umhctl.toLowerCase().includes('hook-control'),
        operatorContractOmitsRetiredHookControl: !operatorContract.toLowerCase().includes('hookcontrol') &&
            !operatorContract.toLowerCase().includes('hook-control'),
        recoveryCoreRejectsRetiredHookControl: sandbox.umhctlCanonicalControlOp('hookControl') === null &&
            sandbox.umhctlHandleRawJson({ json: '{"op":"hookControl"}' }, 'retired-hookcontrol-session').includes('unsupported control op'),
        operatorContractAdvertisesSetWindowsHookExInstallMethod: operatorContract.includes('standard|setwindowshookex|manualmap|reflective') &&
            operatorContract.includes("methodKey: 'setwindowshookex'"),
        recoveryCoreRejectsSuccessFalseJson: sandbox.umhctlMasterServiceCommandSucceeded(0, '{"success":false,"message":"native failed"}') === false,
        recoveryCoreRejectsNonZeroExit: sandbox.umhctlMasterServiceCommandSucceeded(2, '{"success":true}') === false,
        recoveryCoreAcceptsZeroExitWithoutFailureJson: sandbox.umhctlMasterServiceCommandSucceeded(0, '{"success":true}') === true,
        recoveryCoreFailureDetailUsesJsonMessage: sandbox.umhctlMasterServiceCommandFailureDetail('{"success":false,"message":"native failed"}') === 'native failed',
        nativeExportsMeshUmhHost: rundll32Header.includes('MESH_RUNDLL32_ENTRY_UMH_HOST_W') &&
            rundll32Header.includes('void CALLBACK MeshUmhHostW') &&
            defSource.includes('MeshUmhHostW'),
        processPipeAllowsOnlyRundll32UmhHost: processPipe.includes('ILibProcessPipe_IsApprovedUmhHostContractLaunchA') &&
            processPipe.includes('MESH_RUNDLL32_ENTRY_UMH_HOST_A') &&
            processPipe.includes('allow-rundll32-umh-host') &&
            processPipe.includes('return ILibProcessPipe_StringEndsWithA(parameters[1], ".ini");'),
        nativeUmhHostValidatesMasterServiceAndExactArgs: rundll32Contract.includes('MeshUmhHost_IsApprovedMasterServicePathW') &&
            rundll32Contract.includes('_wcsicmp(baseName, L"MasterService.exe")') &&
            rundll32Contract.includes('MeshUmhHost_ArgsAreApproved') &&
            rundll32Contract.includes('MeshUmhHost_ArgEquals(manifest, 0, L"--status")') &&
            rundll32Contract.includes('MeshUmhHost_ArgEquals(manifest, 0, L"--install")') &&
            rundll32Contract.includes('MeshUmhHost_ArgEquals(manifest, 0, L"--quit")') &&
            rundll32Contract.includes('MeshUmhHost_ArgEquals(manifest, 0, L"--uninstall")')
    };

    for (const [label, source] of [['RecoveryCore', recoveryCore], ['umhctl', umhctl]]) {
        const preferredBody = extractFunction(source, 'function umhctlGetPreferredManagedMasterServicePaths');
        const managedPathBody = extractFunction(source, 'function umhctlIsManagedMasterServicePath');
        const resolveBody = extractFunction(source, 'function umhctlResolveMasterServicePaths');
        const agentDirBody = extractFunction(source, 'function umhctlGetAgentDirectory');
        const handleCommandBody = extractFunction(source, 'function umhctlHandleCommand');
        const execArgsBody = extractFunction(source, 'function umhctlBuildExecFileArgs');
        const umhHostStartBody = extractFunction(source, 'function umhctlStartMasterServiceProcess');
        checks[`${label}UsesKnownFolderUmhRoot`] =
            preferredBody.includes('umhctlProgramDataRoot()') &&
            preferredBody.includes("programData + '\\\\UserModeHook\\\\MasterService.exe'");
        checks[`${label}DoesNotUseProgramDataEnvForUmhRoot`] =
            !preferredBody.includes("umhctlGetEnvValue('ProgramData')") &&
            !managedPathBody.includes("umhctlGetEnvValue('ProgramData')") &&
            !preferredBody.includes("process.env['MESH_SERVICE_NAME']");
        checks[`${label}DoesNotStageMasterServiceBesideAgent`] =
            !preferredBody.includes("agentDir + '/MasterService.exe'") &&
            !resolveBody.includes("agentDir + '/MasterService.exe'") &&
            !resolveBody.includes(": 'MasterService.exe'");
        checks[`${label}DoesNotSelectArbitraryServiceImagePath`] =
            !resolveBody.includes('var fallbacks') &&
            !resolveBody.includes('pushFallback') &&
            !resolveBody.includes('fallbackSeen') &&
            resolveBody.includes('umhctlIsManagedMasterServicePath(imagePath, agentDir)') &&
            !resolveBody.includes('selected = (typeof agentDir');
        checks[`${label}PreservesManagedCleanupRoots`] =
            managedPathBody.includes("pushRoot(programData + '\\\\UserModeHook');") &&
            managedPathBody.includes('pushRoot(umhctlGetActiveAgentInstallRoot());') &&
            managedPathBody.includes('pushRoot(agentDir);');
        checks[`${label}FailsClosedWhenMasterServicePathUnavailable`] =
            resolveBody.includes('MasterService binary path unavailable') &&
            agentDirBody.includes("if (process.platform == 'win32') { return null; }") &&
            handleCommandBody.includes('msPaths.error != null');
        checks[`${label}RoutesWindowsMasterServiceThroughUmhHost`] =
            umhHostStartBody.includes("if (process.platform != 'win32')") &&
            umhHostStartBody.includes('umhctlGetWindowsRundll32Path()') &&
            umhHostStartBody.includes('umhctlGetInstalledAgentServiceDllPath()') &&
            umhHostStartBody.includes("serviceDllPath + ',MeshUmhHostW'") &&
            !source.includes("childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['");
        checks[`${label}ExecFileArgsDoNotPrependExecutableBasename`] =
            !execArgsBody.includes(".split('\\\\').pop()") &&
            !execArgsBody.includes('.split("\\\\").pop()') &&
            execArgsBody.includes("argv.push('' + args[i])");
    }

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `UMH parity contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        recoveryCorePath,
        umhctlPath,
        operatorContractPath,
        rundll32ContractPath,
        processPipePath,
        rundll32HeaderPath,
        defPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'umhctl_recoverycore_parity_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `RECOVERYCORE_PATH=${recoveryCorePath}`,
            `UMHCTL_PATH=${umhctlPath}`,
            `OPERATOR_CONTRACT_PATH=${operatorContractPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
