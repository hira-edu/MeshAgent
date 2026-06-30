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
        retryUsesSameRundll32Bridge:
            source.includes('BRIDGE_LAUNCH_MAX_ATTEMPTS = 2') &&
            source.includes('setTimeout(function retryLaunchBridge() { self.launchBridge(); }, BRIDGE_LAUNCH_RETRY_DELAY_MS)') &&
            source.includes("serviceDllPath + ',MeshConsoleBridgeW'") &&
            !source.includes('commandHostPath()') &&
            !source.includes('powerShellPath()'),
        usesDuktapeDuplexWriteContract:
            source.includes('function chunkToInputData(chunk)') &&
            source.includes("if (typeof(chunk) == 'string') { return ({ payload: chunk, length: chunk.length }); }") &&
            source.includes('try { data = Buffer.from(chunk); }') &&
            source.includes('return ({ payload: data, length: data.length });') &&
            source.includes("text != null && text.length > 0 && text != '[object Object]'") &&
            source.includes('return ({ payload: text, length: text.length });') &&
            source.includes('write: function write(chunk, flush)') &&
            source.includes('return (self.writeInput(chunk, flush));') &&
            source.includes('var input = chunkToInputData(chunk);') &&
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
            source.includes('emitCloseOnce')
    };
}

function checkMeshCore(source) {
    return {
        staleBusyStateIsClosed:
            source.includes('if (terminal_is_closed(mesh.cmdchild))') &&
            source.includes('terminal_close_stream(mesh.cmdchild);') &&
            source.includes('delete mesh.cmdchild;'),
        busyRuncommandReplies:
            source.includes("replydata = \"Run commands can't execute, already busy.\";") &&
            source.includes("mesh.SendCommand({ action: 'msg', type: 'runcommands', result: replydata"),
        windowsRuncommandUsesConsoleBridge:
            source.includes("var runMethod = 'StartPowerShell';") &&
            source.includes("mesh.cmdchild = require('win-terminal')[runMethod](80, 25, targetSessionId);") &&
            source.includes("mesh.cmdchild.descriptorMetadata = 'UserCommandsPowerShell';") &&
            source.includes("mesh.cmdchild.on('close', function ()"),
        windowsRuncommandQueuesThroughTerminalStream:
            source.includes('function sendRunCommandToTerminal()') &&
            source.includes('var runCommandSent = false') &&
            source.includes('mesh.cmdchild._meshRunCommandSent = true') &&
            source.includes('function getRunCommandBridgeState()') &&
            source.includes('getRunCommandBridgeState()') &&
            source.includes("writes=' + mesh.cmdchild._meshTerminalWriteCount") &&
            source.includes("lastWriteBytes=' + mesh.cmdchild._meshTerminalLastWriteBytes") &&
            source.includes("lastChunkType=' + mesh.cmdchild._meshTerminalLastChunkType") &&
            source.includes("lastChunkLength=' + mesh.cmdchild._meshTerminalLastChunkLength") &&
            source.includes("lastChunkTextLength=' + mesh.cmdchild._meshTerminalLastChunkTextLength") &&
            source.includes("outputChunks=' + mesh.cmdchild._meshTerminalOutputChunks") &&
            source.includes("outputBytes=' + mesh.cmdchild._meshTerminalOutputBytes") &&
            source.includes('sendRunCommandToTerminal();') &&
            !source.includes('function sendRunCommandWhenReady()') &&
            !source.includes('setTimeout(sendRunCommandWhenReady, 25);') &&
            !source.includes("mesh.cmdchild.once('ready'") &&
            !source.includes("mesh.cmdchild.write(data.cmds + '\\r\\nexit\\r\\n');\n                        } catch"),
        windowsRuncommandHasCallerBoundedTimeout:
            source.includes('Windows run commands timed out through MeshConsoleBridgeW.') &&
            source.includes('Windows run commands timed out through MeshConsoleBridgeW." + getRunCommandBridgeState()') &&
            source.includes('}, 90000);'),
        hasTerminalCloseHelpers:
            source.includes('function terminal_is_closed(term)') &&
            source.includes('function terminal_close_stream(term)')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const terminalPaths = [
        'modules/win-terminal.js',
        '../MeshCentral/agents/modules_meshcore/win-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-terminal.js',
        '../MeshCentral/agents/modules_meshcore_min/win-terminal.min.js'
    ];
    const corePaths = [
        '../MeshCentral/agents/meshcore.js',
        '../MeshCentral/agents/meshcore.min.js'
    ];

    const report = {
        terminalModules: {},
        meshCores: {}
    };

    for (const terminalPath of terminalPaths) {
        const checks = checkTerminalModule(read(terminalPath));
        report.terminalModules[terminalPath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${terminalPath}: ${name} failed`);
        }
    }

    for (const corePath of corePaths) {
        const checks = checkMeshCore(read(corePath));
        report.meshCores[corePath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${corePath}: ${name} failed`);
        }
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_terminal_bridge_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            'SUCCESS=true',
            `TERMINAL_MODULES=${terminalPaths.length}`,
            `MESHCORES=${corePaths.length}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
