const fs = require('fs');
const path = require('path');
const Module = require('module');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error(`Unexpected argument: ${token}`); }
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
    if (!condition) { throw new Error(message); }
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const dllPath = path.resolve(args.dll || path.join('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll'));
    const wrapperPath = path.resolve(args.wrapper || path.join('modules', 'win-terminal.js'));
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    const originalLoad = Module._load;

    assert(process.platform === 'win32', 'win-terminal wrapper smoke requires Windows');
    assert(fs.existsSync(dllPath), `bridge DLL not found at ${dllPath}`);
    assert(fs.existsSync(wrapperPath), `win-terminal wrapper not found at ${wrapperPath}`);

    Module._load = function patchedLoad(request, parent, isMain) {
        if (request === 'win-registry') {
            return {
                HKEY: { LocalMachine: 0 },
                QueryKey: function QueryKey() { return dllPath; }
            };
        }
        if (request === 'win-system-paths') {
            return { system32Path: function system32Path(fileName) { return path.join(systemRoot, 'System32', fileName); } };
        }
        return originalLoad.apply(this, arguments);
    };

    const report = {
        generatedUtc: new Date().toISOString(),
        dllPath,
        wrapperPath,
        output: '',
        chunks: 0,
        closed: false,
        success: false
    };

    try {
        delete require.cache[wrapperPath];
        const terminal = require(wrapperPath).RunPowerShellCommand(80, 25, null);
        assert(typeof(terminal.writeBridgeInput) === 'function', 'expected win-terminal exec stream to expose writeBridgeInput');
        const closePromise = new Promise((resolve, reject) => {
            terminal.on('data', (chunk) => {
                report.chunks++;
                report.output += chunk.toString();
            });
            terminal.on('error', reject);
            terminal.on('close', () => {
                report.closed = true;
                resolve();
            });
        });
        terminal.writeBridgeInput("Write-Output 'MESH_WRAPPER_EXEC_OK'; [Environment]::MachineName\r\n", function noop() {});
        terminal.closeInput();
        await Promise.race([
            closePromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('wrapper exec stream did not close within 15000ms')), 15000))
        ]);
        assert(report.output.indexOf('MESH_WRAPPER_EXEC_OK') >= 0, 'expected wrapper exec marker in output');
        assert(report.chunks > 0, 'expected at least one data chunk');
        report.success = true;
    } finally {
        Module._load = originalLoad;
        if (evidenceDir) {
            writeJson(path.join(evidenceDir, 'win_terminal_wrapper_exec_smoke.json'), report);
            writeText(path.join(evidenceDir, 'summary.txt'), [
                `SUCCESS=${report.success}`,
                `CHUNKS=${report.chunks}`,
                `CLOSED=${report.closed}`,
                `OUTPUT=${report.output.replace(/\r?\n/g, '\\n')}`
            ].join('\n') + '\n');
        }
    }
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exit(1);
});
