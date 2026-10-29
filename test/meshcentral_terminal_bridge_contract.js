const fs = require('fs');
const path = require('path');
const { forkFile, installedPackageDir, wrapperFile } = require('./lib/meshcentral_paths');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

// A missing or empty input fails the contract and says what it was for.
function read(relPath, purpose) {
    const fullPath = path.resolve(relPath);
    let text;
    try {
        text = fs.readFileSync(fullPath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`required input missing: ${fullPath} (${purpose})`, { cause: error });
        }
        throw error;
    }
    assert(text.trim().length > 0, `required input is empty: ${fullPath} (${purpose})`);
    return text.replace(/\r\n?/g, '\n');
}

// Each input group lists the copies it checks: tracked sources (this repository, the MeshCentral
// repository) and the installed MeshCentral package. Each one must exist. Untracked shadow copies in a
// server's data folder are refused by the G4 start-time check, not read here.
function declaredInputs(group, purpose, required) {
    assert(required.length > 0, `${group}: declares no input (${purpose})`);
    const missing = required.filter((relPath) => !fs.existsSync(path.resolve(relPath)));
    assert(missing.length === 0,
        `${group}: required input missing: ${missing.map((relPath) => path.resolve(relPath)).join(', ')} (${purpose})`);
    return { purpose, paths: required };
}

function sourceBetween(source, startNeedle, endNeedle) {
    const start = source.indexOf(startNeedle);
    if (start < 0) { return ''; }
    const end = source.indexOf(endNeedle, start + startNeedle.length);
    return end > start ? source.slice(start, end) : source.slice(start);
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

function checkTerminalModule(source) {
    // Structure only. The bridge's behaviour (ready handshake, input, output, failures, the
    // agent log, run commands) is executed by test/windows_terminal_failure_runtime.js and by
    // MeshCentral deploy/tests/runcommands-terminal-output.test.js.
    // The sister repository can retain a different local variable name while
    // using the same system-only executable and callback command contract.
    const hostAssignment = source.match(/var\s+(\w+)\s*=\s*require\('win-system-paths'\)\.system32Path\('rundll32\.exe'\)/);
    return {
        resolvesCanonicalInstalledDll:
            source.includes("require('win-system-paths').installedServiceRuntimeDll(resolveServiceName())") &&
            !source.includes("\\\\Parameters', 'ServiceDll'"),
        failsWithoutServiceIdentity:
            source.includes('the agent service identity is unavailable') &&
            !source.includes("name = 'meshagent'"),
        usesRuntimeHostConsoleBridge:
            source.includes("require('win-system-paths').system32Path('rundll32.exe')") &&
            source.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !source.includes('",MeshConsoleBridgeW') &&
            hostAssignment != null && source.includes(`childProcess.execFile(${hostAssignment[1]}, args)`),
        defaultsRegularTerminalToCmd:
            source.includes("var SHELL_COMMAND = 'cmd';") &&
            source.includes("var SHELL_AUTOMATION = 'powershell';") &&
            !source.includes("var SHELL_COMMAND = 'powershell';"),
        boundedBridgeConnect:
            source.includes('BRIDGE_CONNECT_TIMEOUT_MS = 15000') &&
            source.includes('Windows terminal bridge did not become ready within'),
        reportsPolicyDeny:
            source.includes('Windows terminal bridge launch was denied by process policy.'),
        retryStaysInsideNativeRuntimeHostBridge:
            source.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !source.includes('BRIDGE_LAUNCH_MAX_ATTEMPTS') &&
            !source.includes('retryLaunchBridge') &&
            !source.includes('BRIDGE_LAUNCH_RETRY_DELAY_MS') &&
            !source.includes('commandHostPath()') &&
            !source.includes('powerShellPath()'),
        launchesBridgeAfterPipeHandlesAreCreated:
            source.includes('this.inputServer.listen(this.inputPipeName);\n    this.outputServer.listen(this.outputPipeName);\n    try { self.launchBridge(); }') &&
            !source.includes('this.inputServer.listen(this.inputPipeName, function onInputListening()') &&
            !source.includes('function onOutputListening()'),
        sessionAndTokenRulesStayExplicit:
            source.includes("this.tokenMode != 'privileged-agent' && this.tokenMode != 'session-user'") &&
            source.includes("this.tokenMode == 'privileged-agent' && this.targetSessionId != null") &&
            source.includes("this.tokenMode == 'session-user' && (this.targetSessionId == null || this.targetSessionId == 0)") &&
            source.includes("args.push('token=' + this.tokenMode);") &&
            source.includes("if (this.mode == 'exec') { args.push('mode=exec'); }"),
        runCommandsUseOneHelper:
            source.includes('windowsTerminal.prototype.RunCommand = function RunCommand(script, options, callback)') &&
            !source.includes('RunPowerShellCommand'),
        noBridgeDebugState:
            !source.includes('_meshTerminal') &&
            !source.includes('console.rawLog'),
        // Production regression 2026-10-29: the agent's Duktape stream.Duplex has explicit events and no
        // createEvent, so emitting an undeclared event throws ("Event 'ready' not found"); the bridge failed
        // every terminal at the ready handshake ("Denied"). Readiness goes through onReady() only, and the
        // module emits only events a Duktape stream.Duplex declares (behaviour: MeshCentral
        // deploy/tests/agent-core-terminal-ready-handshake.test.js).
        emitsOnlyDuktapeDuplexEvents:
            !/createEvent\(/.test(source) &&
            [...source.matchAll(/\.emit\(/g)].length === [...source.matchAll(/\.emit\('([a-zA-Z]+)'/g)].length &&
            [...source.matchAll(/\.emit\('([a-zA-Z]+)'/g)].every((match) =>
                ['close', 'data', 'drain', 'end', 'error', 'finish', 'pipe', 'unpipe'].includes(match[1]))
    };
}

function checkVirtualTerminalModule(source) {
    return {
        virtualTerminalWrapsConsoleBridge:
            source.includes("module.exports = require('win-terminal');") &&
            source.includes('MeshConsoleBridgeW') &&
            !source.includes('CreatePseudoConsole') &&
            !source.includes('CreateProcessW') &&
            !source.includes('OFFICIAL_CMD_EXE') &&
            !source.includes('OFFICIAL_POWERSHELL_EXE')
    };
}

function checkDispatcherModule(source) {
    return {
        dispatcherDisabledOnWindows:
            source.includes('Windows dispatcher helper launch is disabled until an approved rundll32 contract export exists.') &&
            source.includes('dispatch: disabled') &&
            source.includes('connect: disabled') &&
            !source.includes('MeshUserTask') &&
            !source.includes('-b64exec') &&
            !source.includes('win-tasks') &&
            !source.includes('schtasks.exe')
    };
}

function checkMeshCore(source) {
    const terminalConsentSection = sourceBetween(source, "currentTranslation['terminalConsent']", 'terminal_promise_connection_rejected');
    const fileConsentSection = sourceBetween(source, "currentTranslation['fileConsent']", 'files_consentpromise_resolved');

    return {
        uncaughtExceptionHandlerIsFailClosed:
            source.includes('function formatUncaughtException(ex)') &&
            source.includes('function sendMeshCoreConsole(text, sessionid)') &&
            source.includes("var agent = require('MeshAgent');") &&
            source.includes("agent != null && typeof(agent.SendCommand) == 'function'") &&
            source.includes("sendMeshCoreConsole('uncaughtException1: ' + formatUncaughtException(ex));") &&
            // Behaviour: MeshCentral deploy/tests/agent-core-uncaught-exception.test.js.
            !source.includes('catch (consoleEx) { }') &&
            !source.includes('catch (sendEx) { }') &&
            !source.includes("require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: \"uncaughtException1: \" + ex });"),
        busyRuncommandReplies:
            source.includes("var busyReply = \"Run commands can't execute, already busy.\";") &&
            source.includes('if (data.reply) { sendRunCommandResult(busyReply); }'),
        // The run-command behaviour is executed by MeshCentral deploy/tests/runcommands-terminal-output.test.js.
        windowsRuncommandUsesSharedHelper:
            source.includes("mesh.cmdchild = require('win-terminal').RunCommand(commandText, {") &&
            /^var RUN_COMMANDS_TIMEOUT_MS = \d+;$/m.test(source) &&
            source.includes('timeoutMs: RUN_COMMANDS_TIMEOUT_MS') &&
            source.includes("mesh.cmdchild.descriptorMetadata = 'UserCommandsPowerShell';") &&
            !source.includes('MeshConsoleBridgeReady') &&
            !source.includes('_meshTerminal') &&
            !source.includes('MESH_RUN_COMMAND_DONE') &&
            !source.includes('[Console]::WriteLine') &&
            !source.includes("mesh.cmdchild.once('ready'"),
        windowsTerminalAvoidsDispatcher:
            source.includes('function terminal_windows_start(protocol, cols, rows, targetSessionId)') &&
            source.includes("return require('win-terminal')[method](cols, rows, targetSessionId);") &&
            source.includes("terminal_windows_start(this.httprequest.protocol, cols, rows, require('win-terminal').SelectUserSession(this.that.tsid))") &&
            !source.includes('users.Active[0].SessionId') &&
            source.includes('terminal_windows_start(this.httprequest.protocol, cols, rows, null)') &&
            !source.includes("terminal_windows_dispatch_modules('win-virtual-terminal')") &&
            !source.includes("terminal_windows_dispatch_modules('win-terminal')") &&
            !source.includes("require('win-dispatcher').dispatch({ user: username") &&
            !source.includes("this.httprequest._dispatcher = require('win-dispatcher').dispatch({ modules: terminal_windows_dispatch_modules"),
        windowsEnhancedConsentCarriesTunnelSession:
            terminalConsentSection.includes('ipr.tsid =') &&
            terminalConsentSection.includes('uid: this.tsid') &&
            fileConsentSection.includes('ipr.tsid =') &&
            fileConsentSection.includes('uid: this.tsid'),
        windowsSelfUpdateFailsClosedBeforeLegacyExecutablePath:
            source.includes('Windows JavaScript self-update is disabled; native binary update is handled by the agent control channel.') &&
            source.includes("if (process.platform == 'win32')") &&
            source.includes("process.platform != 'freebsd' && process.platform != 'linux'") &&
            source.includes('Self Update disabled for this platform; native service lifecycle is required.') &&
            !source.includes('.update.exe') &&
            !source.includes('_wexecve') &&
            !source.includes('-fullupdate') &&
            !source.includes("wmic service \"' + name + '\" call stopservice")
    };
}

function checkMeshCtrl(source) {
    return {
        // Type 0 lets the server pick each agent's shell (cmd on Windows, sh elsewhere); type 1 is rejected for non-Windows agents.
        runCommandDefaultUsesAgentShellType:
            source.includes("type: ((args.powershell) ? 2 : 0)") &&
            !source.includes("type: ((args.powershell) ? 2 : 1)")
    };
}

function checkProcessPipePolicy(source) {
    return {
        consoleBridgeAllowedForAnySpawnType:
            source.includes('if (ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))') &&
            !source.includes('if (!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))'),
        consoleBridgeStillExactRuntimeHostContract:
            source.includes('static int ILibProcessPipe_IsApprovedConsoleBridgeLaunchA') &&
            source.includes('ILibProcessPipe_IsExactSystemRuntimeHostTargetA(target)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(parameters[0])') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[1], "_in")') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[2], "_out")') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeShellA(parameters[3])') &&
            source.includes('strcmp(value, "powershell") == 0 || strcmp(value, "cmd") == 0') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[4], 20, 300)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[5], 10, 100)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeModeA') &&
            source.includes('strcmp(value, "mode=exec") == 0') &&
            source.includes('ILibProcessPipe_ConsoleBridgeTokenModeA') &&
            source.includes('token=privileged-agent') &&
            source.includes('token=session-user') &&
            source.includes('console-token-missing') &&
            source.includes('console-privileged-tsid') &&
            source.includes('console-user-tsid') &&
            source.includes('console-exec-shell') &&
            source.includes('console-duplicate-mode')
    };
}

function checkNativeSelfUpdateIngress(source) {
    const start = source.indexOf('static int MeshService_RunSelfUpdateIngress');
    const end = source.indexOf('static int MeshService_IsUnsupportedLifecycleSwitch', start);
    const section = start >= 0 && end > start ? source.slice(start, end) : '';

    return {
        selfUpdateWaitsForLifecycleHost:
            section.includes('MeshRuntimeHost_LaunchLifecycleHostW') &&
            section.includes('TRUE,\n\t\t600000,\n\t\t&lifecycleExitCode') &&
            section.includes('if (lifecycleExitCode != ERROR_SUCCESS)') &&
            section.includes('RuntimeHost lifecycle update host completed'),
        selfUpdateDoesNotFireAndForgetLifecycleHost:
            !section.includes('FALSE,\n\t\t0,\n\t\t&lifecycleExitCode') &&
            !section.includes('RuntimeHost lifecycle update host launched')
    };
}

function checkNativeConsoleBridge(source) {
    const dispatchStart = source.indexOf('void CALLBACK MeshConsoleBridgeW');
    const dispatchSection = dispatchStart >= 0 ? source.slice(dispatchStart) : '';
    const ptyStart = source.indexOf('static DWORD MeshConsoleBridge_RunW');
    const ptyEnd = source.indexOf('cleanup:', ptyStart);
    const ptySection = ptyStart >= 0 && ptyEnd > ptyStart ? source.slice(ptyStart, ptyEnd) : '';
    const cleanupSection = ptyEnd >= 0 ? source.slice(ptyEnd, source.indexOf('void CALLBACK MeshUmhHostW', ptyEnd)) : '';

    return {
        interactiveTerminalsUseConpty:
            dispatchSection.includes('MeshConsoleBridge_RunExecW(inputPipeName, outputPipeName, shellName, targetSessionId, tokenMode)') &&
            dispatchSection.includes('MeshConsoleBridge_RunW(inputPipeName, outputPipeName, shellName, cols, rows, targetSessionId, tokenMode)') &&
            !dispatchSection.includes('MeshConsoleBridge_RunRedirectedShellW(inputPipeName, outputPipeName, shellName, targetSessionId, FALSE);'),
        interactiveTerminalsDoNotForceNoExit:
            source.includes('nonInteractive ? L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command -" : L" -NoLogo -NoProfile"') &&
            source.includes('_wcsicmp(shellName, L"cmd") == 0 && !nonInteractive') &&
            source.includes('shellSuffix = L"\\\\cmd.exe";') &&
            !source.includes('-NoProfile -NoExit'),
        conptyHostClosesPtySideHandlesAfterProcessStart:
            ptySection.includes('conptyApi.CreatePseudoConsoleFn(consoleSize, ptyInputRead, ptyOutputWrite, 0, &pseudoConsole)') &&
            ptySection.includes('MeshConsoleBridge_CreateShellProcessW(pseudoConsole, shellPath, commandLine, targetSessionId, tokenMode, &processInfo)') &&
            ptySection.includes('MeshConsoleBridge_CloseHandle(&ptyInputRead);') &&
            ptySection.includes('MeshConsoleBridge_CloseHandle(&ptyOutputWrite);'),
        conptyCloseDrainsFinalOutputBeforePipeTeardown:
            cleanupSection.includes('MeshConsoleBridge_ClosePseudoConsole(&pseudoConsole, conptyApi.ClosePseudoConsoleFn,') &&
            cleanupSection.indexOf('InterlockedExchange(&outputStopFlag, 1);') > cleanupSection.indexOf('MeshConsoleBridge_ClosePseudoConsole(') &&
            source.includes('MeshConsoleBridge_ClosePseudoConsoleThread'),
        conptyCleanupJoinsWorkersBeforeClosingTheirReadOrWriteHandles:
            cleanupSection.indexOf('MeshConsoleBridge_StopCopyThread(inputThread, 2000);') >= 0 &&
            cleanupSection.indexOf('MeshConsoleBridge_StopCopyThread(inputThread, 2000);') < cleanupSection.indexOf('MeshConsoleBridge_CloseHandle(&ptyInputWrite);') &&
            cleanupSection.indexOf('MeshConsoleBridge_StopCopyThread(inputThread, 2000);') < cleanupSection.indexOf('MeshConsoleBridge_CloseHandle(&inputPipe);') &&
            cleanupSection.indexOf('MeshConsoleBridge_StopCopyThread(outputThread, 2000);') < cleanupSection.indexOf('MeshConsoleBridge_CloseHandle(&outputPipe);') &&
            cleanupSection.indexOf('MeshConsoleBridge_StopCopyThread(outputThread, 2000);') < cleanupSection.indexOf('MeshConsoleBridge_CloseHandle(&ptyOutputRead);') &&
            source.includes('CancelSynchronousIo(thread);')
    };
}

function checkCustomRunCommandOverlay(source) {
    return {
        downloadCommandUsesPowerShellNativeTempPath:
            source.includes("function psq(v) { return \"'\" + String(v).replace(/'/g, \"''\") + \"'\"; }") &&
            source.includes("$umhDir=Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'UMH'") &&
            source.includes('$target=Join-Path -Path $umhDir -ChildPath ') &&
            !source.includes("'%TEMP%\\\\UMH'") &&
            !source.includes("'%TEMP%\\\\UMH\\\\"),
        downloadCommandRunsNonInteractivePowerShell:
            source.includes('powershell -NoLogo -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy RemoteSigned -EncodedCommand ') &&
            source.includes('function utf16leBase64') &&
            !source.includes('powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command '),
        downloadCommandDisposesWebClient:
            source.includes('$wc=New-Object System.Net.WebClient') &&
            source.includes('finally { if ($wc) { $wc.Dispose() } }')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const terminalInputs = declaredInputs('terminalModules', 'win-terminal copies whose system-only executable and callback contract is checked', [
        'modules/win-terminal.js',
        forkFile('agents/modules_meshcore/win-terminal.js')
    ]);
    const systemPathInputs = declaredInputs('systemPathModules', 'win-system-paths copies whose service runtime DLL resolution is checked', [
        'modules/win-system-paths.js',
        forkFile('agents/modules_meshcore/win-system-paths.js')
    ]);
    const virtualTerminalInputs = declaredInputs('virtualTerminalModules', 'win-virtual-terminal copies whose terminal contract is checked', [
        'modules/win-virtual-terminal.js',
        forkFile('agents/modules_meshcore/win-virtual-terminal.js')
    ]);
    // MeshAgent's embedded copy only: D9 deleted the three fork copies under
    // agents/modules_meshcore*/, so MeshCentral no longer carries win-dispatcher.
    const dispatcherInputs = declaredInputs('dispatcherModules', 'win-dispatcher copy whose disabled-connect contract is checked', [
        'modules/win-dispatcher.js'
    ]);
    const coreInputs = declaredInputs('meshCores', 'MeshCentral agent core whose run-command and consent handling is checked', [
        forkFile('agents/meshcore.js')
    ]);
    const meshCtrlInputs = declaredInputs('meshCtrl', 'meshctrl copies whose run-command options are checked', [
        forkFile('meshctrl.js'),
        path.join(installedPackageDir().dir, 'meshctrl.js')
    ]);
    const customOverlayInputs = declaredInputs('customRunCommandOverlays', 'custom.js run-command overlay whose download command is checked', [
        // The package copy is npm's empty stub since Stage 1; the served file is the wrapper's.
        wrapperFile('meshcentral-web/public/scripts/custom.js')
    ]);
    const terminalPaths = terminalInputs.paths;
    const corePaths = coreInputs.paths;
    const customOverlayPaths = customOverlayInputs.paths;

    const report = {
        terminalModules: {},
        systemPathModules: {},
        virtualTerminalModules: {},
        dispatcherModules: {},
        meshCores: {},
        meshCtrl: {},
        customRunCommandOverlays: {},
        processPipePolicy: {},
        nativeSelfUpdateIngress: {},
        nativeConsoleBridge: {}
    };

    for (const terminalPath of terminalPaths) {
        const checks = checkTerminalModule(read(terminalPath, terminalInputs.purpose));
        report.terminalModules[terminalPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${terminalPath}: ${name} failed`);
        }
    }
    for (const modulePath of systemPathInputs.paths) {
        const source = read(modulePath, systemPathInputs.purpose);
        const checks = {
            resolvesCanonicalServiceBinding:
                /function\s+installedServiceRuntimeDll\s*\(/.test(source) &&
                source.includes('SYSTEM\\\\CurrentControlSet\\\\Services\\\\') &&
                source.includes('serviceRuntimeDllFromCommand(command)') &&
                source.includes('MeshServiceHostW')
        };
        report.systemPathModules[modulePath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${modulePath}: ${name} failed`);
        }
    }

    for (const virtualTerminalPath of virtualTerminalInputs.paths) {
        const checks = checkVirtualTerminalModule(read(virtualTerminalPath, virtualTerminalInputs.purpose));
        report.virtualTerminalModules[virtualTerminalPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${virtualTerminalPath}: ${name} failed`);
        }
    }

    for (const dispatcherPath of dispatcherInputs.paths) {
        const checks = checkDispatcherModule(read(dispatcherPath, dispatcherInputs.purpose));
        report.dispatcherModules[dispatcherPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${dispatcherPath}: ${name} failed`);
        }
    }

    for (const corePath of corePaths) {
        const checks = checkMeshCore(read(corePath, coreInputs.purpose));
        report.meshCores[corePath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${corePath}: ${name} failed`);
        }
    }

    for (const meshCtrlPath of meshCtrlInputs.paths) {
        const checks = checkMeshCtrl(read(meshCtrlPath, meshCtrlInputs.purpose));
        report.meshCtrl[meshCtrlPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${meshCtrlPath}: ${name} failed`);
        }
    }

    for (const customOverlayPath of customOverlayPaths) {
        const checks = checkCustomRunCommandOverlay(read(customOverlayPath, customOverlayInputs.purpose));
        report.customRunCommandOverlays[customOverlayPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${customOverlayPath}: ${name} failed`);
        }
    }

    report.processPipePolicy = checkProcessPipePolicy(read('microstack/ILibProcessPipe.c', 'native process pipe source whose spawn policy is checked'));
    for (const [name, passed] of Object.entries(report.processPipePolicy)) {
        assert(passed, `microstack/ILibProcessPipe.c: ${name} failed`);
    }

    report.nativeSelfUpdateIngress = checkNativeSelfUpdateIngress(read('meshservice/ServiceMain.c', 'service entry source whose self-update ingress is checked'));
    for (const [name, passed] of Object.entries(report.nativeSelfUpdateIngress)) {
        assert(passed, `meshservice/ServiceMain.c: ${name} failed`);
    }

    report.nativeConsoleBridge = checkNativeConsoleBridge(read('meshservice/runtime_host_contract.c', 'runtime host source whose console bridge is checked'));
    for (const [name, passed] of Object.entries(report.nativeConsoleBridge)) {
        assert(passed, `meshservice/runtime_host_contract.c: ${name} failed`);
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_terminal_bridge_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            'SUCCESS=true',
            `TERMINAL_MODULES=${terminalPaths.length}`,
            `MESHCORES=${corePaths.length}`,
            `CUSTOM_RUNCOMMAND_OVERLAYS=${customOverlayPaths.length}`,
            `PROCESS_PIPE_POLICY=${Object.entries(report.processPipePolicy).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `NATIVE_SELF_UPDATE_INGRESS=${Object.entries(report.nativeSelfUpdateIngress).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `NATIVE_CONSOLE_BRIDGE=${Object.entries(report.nativeConsoleBridge).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
