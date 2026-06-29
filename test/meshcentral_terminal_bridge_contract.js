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
        boundedBridgeConnect:
            source.includes('BRIDGE_CONNECT_TIMEOUT_MS = 15000') &&
            source.includes('Windows terminal bridge did not connect within'),
        reportsPolicyDeny:
            source.includes('Windows terminal bridge launch was denied by process policy.'),
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
            source.includes("mesh.cmdchild = require('win-terminal')[runMethod](80, 25, targetSessionId);") &&
            source.includes("mesh.cmdchild.on('close', function ()"),
        windowsRuncommandHasCallerBoundedTimeout:
            source.includes('Windows run commands timed out through MeshConsoleBridgeW.') &&
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
