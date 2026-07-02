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
        defaultsToPowerShell:
            source.includes("var SHELL_COMMAND = 'powershell';") &&
            source.includes("var SHELL_AUTOMATION = 'powershell';") &&
            !source.includes("var SHELL_COMMAND = 'cmd';"),
        boundedBridgeConnect:
            source.includes('BRIDGE_CONNECT_TIMEOUT_MS = 15000') &&
            source.includes('Windows terminal bridge did not connect within'),
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
            source.includes("if (typeof(chunk) == 'string') { return ({ payload: chunk, length: chunk.length }); }") &&
            source.includes('try { data = Buffer.from(chunk); }') &&
            source.includes('return ({ payload: data, length: data.length });') &&
            source.includes("textValue != null && textValue.length > 0 && textValue != '[object Object]'") &&
            source.includes('return ({ payload: textValue, length: textValue.length });') &&
            source.includes('write: function write(chunk, flush)') &&
            source.includes('return (self.writeInput(chunk, flush));') &&
            source.includes('var input = chunkToInputData(chunk);') &&
            source.includes("fallbackText = '' + chunk.toString();") &&
            source.includes('input = { payload: fallbackText, length: fallbackText.length };') &&
            source.includes('this.pendingWrites.push({ chunk: input.payload, flush: flush });') &&
            source.includes('this.inputSocket.write(input.payload);') &&
            source.includes('this.stream._meshTerminalLastWriteBytes = input.length;') &&
            source.includes('return (true);') &&
            source.includes('return (false);') &&
            !source.includes('write: function write(chunk, encoding, flush)'),
        launchesBridgeAfterPipeHandlesAreCreated:
            source.includes('this.inputServer.listen(this.inputPipeName);\n    this.outputServer.listen(this.outputPipeName);\n    try { self.launchBridge(); }') &&
            !source.includes('this.inputServer.listen(this.inputPipeName, function onInputListening()') &&
            !source.includes('function onOutputListening()'),
        exposesReadyState:
            source.includes("if (stream.createEvent) { stream.createEvent('ready'); }") &&
            source.includes('stream.isBridgeReady = function isBridgeReady()') &&
            source.includes('stream._meshTerminalReady = false') &&
            source.includes('stream._meshTerminalBridgeLaunched = false') &&
            source.includes('stream._meshTerminalInputConnected = false') &&
            source.includes('stream._meshTerminalOutputConnected = false') &&
            source.includes('stream._meshTerminalChildPid = 0') &&
            source.includes('stream._meshTerminalWriteCount = 0') &&
            source.includes('stream._meshTerminalLastWriteBytes = 0') &&
            source.includes("stream._meshTerminalLastChunkType = '';") &&
            source.includes('stream._meshTerminalLastChunkLength = -1') &&
            source.includes('stream._meshTerminalLastChunkTextLength = -1') &&
            source.includes('stream._meshTerminalOutputChunks = 0') &&
            source.includes('stream._meshTerminalOutputBytes = 0') &&
            source.includes("this.stream.emit('ready')"),
        exposesClosedState:
            source.includes('stream.isBridgeClosed = function isBridgeClosed()') &&
            source.includes('stream._meshTerminalClosed = false') &&
            source.includes('emitCloseOnce'),
        supportsNonInteractiveRunCommandMode:
            source.includes("this.mode = (mode == 'exec') ? 'exec' : 'pty';") &&
            source.includes("if (this.mode == 'exec') { args.push('mode=exec'); }") &&
            source.includes('ConsoleBridgeTerminal.prototype.closeInput = function closeInput()') &&
            source.includes('stream.closeInput = function closeInput()') &&
            source.includes("if (self.mode == 'exec') { self.closeInput(); }") &&
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
    return {
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
            source.includes("mesh.cmdchild.on('close', completeRunCommand);"),
        windowsRuncommandUsesNonInteractiveExecStream:
            source.includes("var commandText = Array.isArray(data.cmds) ? data.cmds.join('\\r\\n')") &&
            source.includes("mesh.cmdchild.write(commandText + '\\r\\n');") &&
            source.includes('if (mesh.cmdchild.closeInput) { mesh.cmdchild.closeInput(); }') &&
            source.includes('function completeRunCommand()') &&
            source.includes('function appendRunCommandOutput(c)') &&
            !source.includes('MESH_RUN_COMMAND_DONE') &&
            !source.includes('buildRunCommandDoneMarkerCommand') &&
            !source.includes('[Console]::WriteLine') &&
            !source.includes("mesh.cmdchild.write(data.cmds + '\\r\\n'") &&
            source.includes('function getRunCommandBridgeState()') &&
            source.includes('getRunCommandBridgeState()') &&
            source.includes("mode=' + mesh.cmdchild._meshTerminalMode") &&
            source.includes("writes=' + mesh.cmdchild._meshTerminalWriteCount") &&
            source.includes("lastWriteBytes=' + mesh.cmdchild._meshTerminalLastWriteBytes") &&
            source.includes("outputChunks=' + mesh.cmdchild._meshTerminalOutputChunks") &&
            source.includes("outputBytes=' + mesh.cmdchild._meshTerminalOutputBytes") &&
            !source.includes('function sendRunCommandWhenReady()') &&
            !source.includes('setTimeout(sendRunCommandWhenReady, 25);') &&
            !source.includes("mesh.cmdchild.once('ready'") &&
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
        hasTerminalCloseHelpers:
            source.includes('function terminal_is_closed(term)') &&
            source.includes('function terminal_close_stream(term)')
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
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[4], 20, 300)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeSizeA(parameters[5], 10, 100)') &&
            source.includes('ILibProcessPipe_IsApprovedConsoleBridgeModeA') &&
            source.includes('strcmp(value, "mode=exec") == 0') &&
            source.includes('console-duplicate-mode')
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
        processPipePolicy: {}
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

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_terminal_bridge_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            'SUCCESS=true',
            `TERMINAL_MODULES=${terminalPaths.length}`,
            `MESHCORES=${corePaths.length}`,
            `CUSTOM_RUNCOMMAND_OVERLAYS=${customOverlayPaths.length}`,
            `PROCESS_PIPE_POLICY=${Object.entries(report.processPipePolicy).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
