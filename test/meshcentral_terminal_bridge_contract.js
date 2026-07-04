const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

function existingPaths(paths) {
    return paths.filter((relPath) => fs.existsSync(path.resolve(relPath)));
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
    return {
        usesRundll32ConsoleBridge:
            source.includes("require('win-system-paths').system32Path('rundll32.exe')") &&
            source.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !source.includes('",MeshConsoleBridgeW') &&
            source.includes('childProcess.execFile(rundll32Path, args)'),
        defaultsRegularTerminalToCmd:
            source.includes("var SHELL_COMMAND = 'cmd';") &&
            source.includes("var SHELL_AUTOMATION = 'powershell';") &&
            !source.includes("var SHELL_COMMAND = 'powershell';"),
        boundedBridgeConnect:
            source.includes('BRIDGE_CONNECT_TIMEOUT_MS = 15000') &&
            source.includes('Windows terminal bridge did not become ready within'),
        reportsPolicyDeny:
            source.includes('Windows terminal bridge launch was denied by process policy.'),
        retryStaysInsideNativeRundll32Bridge:
            source.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !source.includes('BRIDGE_LAUNCH_MAX_ATTEMPTS') &&
            !source.includes('retryLaunchBridge') &&
            !source.includes('BRIDGE_LAUNCH_RETRY_DELAY_MS') &&
            !source.includes('commandHostPath()') &&
            !source.includes('powerShellPath()'),
        usesDuktapeDuplexWriteContract:
            source.includes('function chunkToInputData(chunk)') &&
            source.includes("if (typeof(chunk) == 'string')") &&
            source.includes("data = Buffer.from(chunk, 'utf8');") &&
            source.includes('try { data = Buffer.from(chunk); }') &&
            source.includes('return ({ payload: data, length: data.length });') &&
            source.includes("textValue != null && textValue.length > 0 && textValue != '[object Object]'") &&
            source.includes("data = Buffer.from(textValue, 'utf8');") &&
            source.includes('write: function write(chunk, encoding, flush)') &&
            source.includes("if (typeof(encoding) == 'function' && flush == null) { flush = encoding; }") &&
            source.includes('return (self.writeInput(chunk, flush));') &&
            source.includes('var input = chunkToInputData(chunk);') &&
            source.includes("fallbackText = '' + chunk.toString();") &&
            source.includes("input = chunkToInputData(fallbackText);") &&
            source.includes("if (typeof(flush) != 'function') { flush = null; }") &&
            source.includes('var flushCalled = false;') &&
            source.includes('function completeFlush()') &&
            source.includes('this.pendingWrites.push({ chunk: input.payload, flush: flush });') &&
            source.includes('if (flush) { this.inputSocket.write(input.payload, completeFlush); }') &&
            source.includes('else { this.inputSocket.write(input.payload); }') &&
            source.includes('if (!flush) { completeFlush(); }') &&
            source.includes('this.stream._meshTerminalLastWriteBytes = input.length;') &&
            source.includes('return (true);') &&
            source.includes('return (false);'),
        launchesBridgeAfterPipeHandlesAreCreated:
            source.includes('this.inputServer.listen(this.inputPipeName);\n    this.outputServer.listen(this.outputPipeName);\n    try { self.launchBridge(); }') &&
            !source.includes('this.inputServer.listen(this.inputPipeName, function onInputListening()') &&
            !source.includes('function onOutputListening()'),
        exposesReadyState:
            source.includes("try { if (stream.createEvent) { stream.createEvent('ready'); } } catch (ex) { }") &&
            source.includes("var BRIDGE_READY_MARKER = '\\x1b]MeshConsoleBridgeReady\\x07';") &&
            source.includes('this.readyCallbacks = [];') &&
            source.includes('this.dataCallbacks = [];') &&
            source.includes('ConsoleBridgeTerminal.prototype.processOutputChunk = function processOutputChunk(chunk)') &&
            source.includes('markerIndex = this.readyBuffer.indexOf(BRIDGE_READY_MARKER);') &&
            source.includes('this.emitReadyOnce();') &&
            source.includes('stream.onBridgeReady = function onBridgeReady(callback)') &&
            source.includes('stream.onBridgeData = function onBridgeData(callback)') &&
            source.includes('ConsoleBridgeTerminal.prototype.onReady = function onReady(callback)') &&
            source.includes('ConsoleBridgeTerminal.prototype.onData = function onData(callback)') &&
            source.includes('this.readyCallbacks.push(callback);') &&
            source.includes('this.dataCallbacks.push(callback);') &&
            source.includes('this.dataCallbacks[i](chunk);') &&
            source.includes("Windows terminal bridge did not become ready within") &&
            source.includes('Windows terminal bridge exited before ready handshake through MeshConsoleBridgeW.') &&
            source.includes('stream.isBridgeReady = function isBridgeReady()') &&
            source.includes('stream._meshTerminalReady = false') &&
            source.includes('stream._meshTerminalBridgeLaunched = false') &&
            source.includes('stream._meshTerminalReadyMarkerProtocol = true') &&
            source.includes('stream._meshTerminalPipesConnected = false') &&
            source.includes('stream._meshTerminalInputConnected = false') &&
            source.includes('stream._meshTerminalInputClosed = false') &&
            source.includes('stream._meshTerminalOutputConnected = false') &&
            source.includes('stream._meshTerminalChildPid = 0') &&
            source.includes('stream._meshTerminalBridgeExited = false') &&
            source.includes('stream._meshTerminalWriteCount = 0') &&
            source.includes('stream._meshTerminalLastWriteBytes = 0') &&
            source.includes("stream._meshTerminalLastChunkType = '';") &&
            source.includes('stream._meshTerminalLastChunkLength = -1') &&
            source.includes('stream._meshTerminalLastChunkTextLength = -1') &&
            source.includes('stream._meshTerminalOutputChunks = 0') &&
            source.includes('stream._meshTerminalOutputBytes = 0') &&
            source.includes('stream._meshTerminalHandshakeBytes = 0') &&
            source.includes('if (this.readyEmitted == false) { return; }') &&
            source.includes('if (this.readyEmitted == false || this.inputSocket == null)') &&
            source.includes("this.stream.emit('ready')"),
        exposesClosedState:
            source.includes('stream.isBridgeClosed = function isBridgeClosed()') &&
            source.includes('stream._meshTerminalClosed = false') &&
            source.includes('emitCloseOnce'),
        inputPipeCloseDoesNotCloseTerminal:
            source.includes("socket.on('close', function onInputClose()") &&
            source.includes('self.inputSocket = null;') &&
            source.includes('self.inputEnded = true;') &&
            source.includes('self.endInputWhenConnected = false;') &&
            source.includes('self.stream._meshTerminalInputClosed = true;') &&
            source.includes("socket.on('close', function onOutputClose() { self.finish(); });") &&
            !source.includes("if (self.mode != 'exec') { self.finish(); }"),
        supportsNonInteractiveRunCommandMode:
            source.includes("this.mode = (mode == 'exec') ? 'exec' : 'pty';") &&
            source.includes("if (this.mode == 'exec') { args.push('mode=exec'); }") &&
            source.includes('ConsoleBridgeTerminal.prototype.closeInput = function closeInput()') &&
            source.includes('stream.closeInput = function closeInput()') &&
            source.includes('stream.writeBridgeInput = function writeBridgeInput(chunk, flush)') &&
            source.includes('return (self.writeInput(chunk, flush));') &&
            source.includes("if (self.mode == 'exec') { self.closeInput(); }") &&
            source.includes('self.stream._meshTerminalBridgeExited = true;') &&
            source.includes("if (self.mode == 'exec' && self.outputSocket != null)") &&
            source.includes('read: function read(size)') &&
            source.includes('windowsTerminal.prototype.RunPowerShellCommand = function RunPowerShellCommand') &&
            source.includes("return (new ConsoleBridgeTerminal(SHELL_AUTOMATION, cols, rows, targetSessionId, 'exec'));")
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
            source.includes('try { console.error(text); } catch (consoleEx) { }') &&
            !source.includes("require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: \"uncaughtException1: \" + ex });"),
        staleBusyStateIsClosed:
            source.includes('if (terminal_is_closed(mesh.cmdchild))') &&
            source.includes('terminal_close_stream(mesh.cmdchild);') &&
            source.includes('delete mesh.cmdchild;'),
        busyRuncommandReplies:
            source.includes("var busyReply = \"Run commands can't execute, already busy.\";") &&
            source.includes('if (data.reply) { sendRunCommandResult(busyReply); }'),
        windowsRuncommandUsesConsoleBridge:
            source.includes("var runMethod = (data.runAsUser > 0) ? 'RunPowerShellCommandAsUser' : 'RunPowerShellCommand';") &&
            source.includes("mesh.cmdchild = require('win-terminal')[runMethod](80, 25, targetSessionId);") &&
            source.includes("mesh.cmdchild.descriptorMetadata = 'UserCommandsPowerShell';") &&
            source.includes("mesh.cmdchild.on('close', completeRunCommand);") &&
            source.includes('if (mesh.cmdchild.onBridgeData) { mesh.cmdchild.onBridgeData(appendRunCommandOutput); }') &&
            source.includes("else { mesh.cmdchild.on('data', appendRunCommandOutput); }"),
        windowsRuncommandUsesNonInteractiveExecStream:
            source.includes("var commandText = Array.isArray(data.cmds) ? data.cmds.join('\\r\\n')") &&
            source.includes('var runCommandInputSent = false;') &&
            source.includes("var runCommandBridgeMarker = '\\x1b]MeshConsoleBridgeReady\\x07';") &&
            source.includes('var runCommandBridgeMarkerSeen = false;') &&
            source.includes('function filterRunCommandBridgeMarker(text)') &&
            source.includes('markerIndex = runCommandBridgeBuffer.indexOf(runCommandBridgeMarker);') &&
            source.includes('text = filterRunCommandBridgeMarker(text);') &&
            source.includes('function sendRunCommandInput()') &&
            source.includes("term.writeBridgeInput(commandText + '\\r\\n', function ()") &&
            source.includes('try { if (term.closeInput) { term.closeInput(); } } catch (ex) { }') &&
            source.includes('function registerRunCommandInputOnBridgeReady(term)') &&
            source.includes('if (term == null || term._meshTerminalReadyMarkerProtocol !== true) { return; }') &&
            source.includes('if (term.onBridgeReady) { term.onBridgeReady(sendRunCommandInput); return; }') &&
            source.includes('if (term.isBridgeReady && term.isBridgeReady()) { sendRunCommandInput(); }') &&
            source.includes('registerRunCommandInputOnBridgeReady(mesh.cmdchild);') &&
            source.includes('function completeRunCommand()') &&
            source.includes('function appendRunCommandOutput(c)') &&
            !source.includes('MESH_RUN_COMMAND_DONE') &&
            !source.includes('buildRunCommandDoneMarkerCommand') &&
            !source.includes('[Console]::WriteLine') &&
            !source.includes("mesh.cmdchild.write(data.cmds + '\\r\\n'") &&
            source.includes('function getRunCommandBridgeState()') &&
            source.includes('getRunCommandBridgeState()') &&
            source.includes("mode=' + mesh.cmdchild._meshTerminalMode") &&
            source.includes("markerSeen=' + runCommandBridgeMarkerSeen") &&
            source.includes("writes=' + mesh.cmdchild._meshTerminalWriteCount") &&
            source.includes("lastWriteBytes=' + mesh.cmdchild._meshTerminalLastWriteBytes") &&
            source.includes("outputChunks=' + mesh.cmdchild._meshTerminalOutputChunks") &&
            source.includes("outputBytes=' + mesh.cmdchild._meshTerminalOutputBytes") &&
            !source.includes('function sendRunCommandWhenReady()') &&
            !source.includes("mesh.cmdchild.once('ready'") &&
            !source.includes('setTimeout(sendRunCommandWhenReady, 25);') &&
            !source.includes("term.write(commandText + '\\r\\n', function ()") &&
            !source.includes("mesh.cmdchild.write(data.cmds + '\\r\\nexit\\r\\n');\n                        } catch") &&
            !source.includes("runCommandDoneMarker"),
        windowsRuncommandHasCallerBoundedTimeout:
            source.includes('Windows run commands timed out through MeshConsoleBridgeW.') &&
            source.includes("replydata += 'Windows run commands timed out through MeshConsoleBridgeW.' + getRunCommandBridgeState();") &&
            source.includes('}, 300000);'),
        windowsTerminalAvoidsDispatcher:
            source.includes('function terminal_windows_start(protocol, cols, rows, targetSessionId)') &&
            source.includes("return require('win-terminal')[method](cols, rows, targetSessionId);") &&
            source.includes('function terminal_windows_active_user_session_id(users)') &&
            source.includes('terminal_windows_start(that.httprequest.protocol, this.cols, this.rows, targetSessionId)') &&
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
        hasTerminalCloseHelpers:
            source.includes('function terminal_is_closed(term)') &&
            source.includes('function terminal_close_stream(term)'),
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
        runCommandDefaultUsesShellType:
            source.includes("type: ((args.powershell) ? 2 : 1)") &&
            !source.includes("type: ((args.powershell) ? 2 : 0)")
    };
}

function checkProcessPipePolicy(source) {
    return {
        consoleBridgeAllowedForAnySpawnType:
            source.includes('if (ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))') &&
            !source.includes('if (!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedConsoleBridgeLaunchA(target, parameters))'),
        consoleBridgeStillExactRundll32Contract:
            source.includes('static int ILibProcessPipe_IsApprovedConsoleBridgeLaunchA') &&
            source.includes('ILibProcessPipe_IsExactSystemRundll32TargetA(target)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(parameters[0])') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[1], "_in")') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgePipeNameA(parameters[2], "_out")') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeShellA(parameters[3])') &&
            source.includes('strcmp(value, "powershell") == 0 || strcmp(value, "cmd") == 0') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[4], 20, 300)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[5], 10, 100)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeModeA') &&
            source.includes('strcmp(value, "mode=exec") == 0') &&
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
            section.includes('MeshRundll32_LaunchLifecycleHostW') &&
            section.includes('TRUE,\n\t\t600000,\n\t\t&lifecycleExitCode') &&
            section.includes('if (lifecycleExitCode != ERROR_SUCCESS)') &&
            section.includes('Rundll32 lifecycle update host completed'),
        selfUpdateDoesNotFireAndForgetLifecycleHost:
            !section.includes('FALSE,\n\t\t0,\n\t\t&lifecycleExitCode') &&
            !section.includes('Rundll32 lifecycle update host launched')
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
            dispatchSection.includes('MeshConsoleBridge_RunExecW(inputPipeName, outputPipeName, shellName, targetSessionId)') &&
            dispatchSection.includes('MeshConsoleBridge_RunW(inputPipeName, outputPipeName, shellName, cols, rows, targetSessionId)') &&
            !dispatchSection.includes('MeshConsoleBridge_RunRedirectedShellW(inputPipeName, outputPipeName, shellName, targetSessionId, FALSE);'),
        interactiveTerminalsDoNotForceNoExit:
            source.includes('nonInteractive ? L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" : L" -NoLogo -NoProfile"') &&
            source.includes('_wcsicmp(shellName, L"cmd") == 0 && !nonInteractive') &&
            source.includes('shellSuffix = L"\\\\cmd.exe";') &&
            !source.includes('-NoProfile -NoExit'),
        conptyHostClosesPtySideHandlesAfterProcessStart:
            ptySection.includes('conptyApi.CreatePseudoConsoleFn(consoleSize, ptyInputRead, ptyOutputWrite, 0, &pseudoConsole)') &&
            ptySection.includes('MeshConsoleBridge_CreateShellProcessWithRetryW(pseudoConsole, shellPath, commandLine, targetSessionId, &processInfo)') &&
            ptySection.includes('MeshConsoleBridge_CloseHandle(&ptyInputRead);') &&
            ptySection.includes('MeshConsoleBridge_CloseHandle(&ptyOutputWrite);'),
        conptyCloseDrainsFinalOutputBeforePipeTeardown:
            ptySection.includes('conptyApi.ClosePseudoConsoleFn(pseudoConsole);') &&
            cleanupSection.indexOf('conptyApi.ClosePseudoConsoleFn(pseudoConsole);') >= 0 &&
            cleanupSection.indexOf('MeshConsoleBridge_CloseHandle(&ptyOutputRead);') > cleanupSection.indexOf('conptyApi.ClosePseudoConsoleFn(pseudoConsole);')
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
            source.includes('powershell -NoLogo -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand ') &&
            source.includes('function utf16leBase64') &&
            !source.includes('powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command '),
        downloadCommandDisposesWebClient:
            source.includes('$wc=New-Object System.Net.WebClient') &&
            source.includes('finally { if ($wc) { $wc.Dispose() } }')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const terminalPaths = existingPaths([
        'modules/win-terminal.js',
        '../MeshCentral/meshcentral-data/modules_meshcore/win-terminal.js',
        '../MeshCentral/meshcentral-data/modules_meshcore_min/win-terminal.js',
        '../MeshCentral/meshcentral-data/modules_meshcore_min/win-terminal.min.js',
        '../MeshCentral/agents/modules_meshcore/win-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-terminal.min.js'
    ]);
    const virtualTerminalPaths = existingPaths([
        'modules/win-virtual-terminal.js',
        '../MeshCentral/agents/modules_meshcore/win-virtual-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-virtual-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-virtual-terminal.min.js'
    ]);
    const dispatcherPaths = existingPaths([
        'modules/win-dispatcher.js',
        '../MeshCentral/agents/modules_meshcore/win-dispatcher.js',
        '../MeshCentral/agents/modules_meshcore_min/win-dispatcher.js',
        '../MeshCentral/agents/modules_meshcore_min/win-dispatcher.min.js'
    ]);
    const corePaths = existingPaths([
        '../MeshCentral/meshcentral-data/meshcore.js',
        '../MeshCentral/meshcore.js',
        '../MeshCentral/meshcore.min.js',
        '../MeshCentral/agents/meshcore.js',
        '../MeshCentral/agents/meshcore.min.js'
    ]);

    const report = {
        terminalModules: {},
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
        const checks = checkTerminalModule(read(terminalPath));
        report.terminalModules[terminalPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${terminalPath}: ${name} failed`);
        }
    }

    for (const virtualTerminalPath of virtualTerminalPaths) {
        const checks = checkVirtualTerminalModule(read(virtualTerminalPath));
        report.virtualTerminalModules[virtualTerminalPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${virtualTerminalPath}: ${name} failed`);
        }
    }

    for (const dispatcherPath of dispatcherPaths) {
        const checks = checkDispatcherModule(read(dispatcherPath));
        report.dispatcherModules[dispatcherPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${dispatcherPath}: ${name} failed`);
        }
    }

    for (const corePath of corePaths) {
        const checks = checkMeshCore(read(corePath));
        report.meshCores[corePath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${corePath}: ${name} failed`);
        }
    }

    const meshCtrlPaths = existingPaths([
        '../MeshCentral/meshctrl.js',
        '../MeshCentral/node_modules/meshcentral/meshctrl.js'
    ]);
    for (const meshCtrlPath of meshCtrlPaths) {
        const checks = checkMeshCtrl(read(meshCtrlPath));
        report.meshCtrl[meshCtrlPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${meshCtrlPath}: ${name} failed`);
        }
    }

    const customOverlayPaths = existingPaths([
        '../MeshCentral/public/scripts/custom.js'
    ]);
    for (const customOverlayPath of customOverlayPaths) {
        const checks = checkCustomRunCommandOverlay(read(customOverlayPath));
        report.customRunCommandOverlays[customOverlayPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${customOverlayPath}: ${name} failed`);
        }
    }

    report.processPipePolicy = checkProcessPipePolicy(read('microstack/ILibProcessPipe.c'));
    for (const [name, passed] of Object.entries(report.processPipePolicy)) {
        assert(passed, `microstack/ILibProcessPipe.c: ${name} failed`);
    }

    report.nativeSelfUpdateIngress = checkNativeSelfUpdateIngress(read('meshservice/ServiceMain.c'));
    for (const [name, passed] of Object.entries(report.nativeSelfUpdateIngress)) {
        assert(passed, `meshservice/ServiceMain.c: ${name} failed`);
    }

    report.nativeConsoleBridge = checkNativeConsoleBridge(read('meshservice/rundll32_contract.c'));
    for (const [name, passed] of Object.entries(report.nativeConsoleBridge)) {
        assert(passed, `meshservice/rundll32_contract.c: ${name} failed`);
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
