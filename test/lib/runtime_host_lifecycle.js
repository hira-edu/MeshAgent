const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ENTRYPOINT = 'MeshLifecycleHostW';

const SWITCH_TO_ACTION = new Map([
    ['-fullinstall', 'install'],
    ['-fullupdate', 'update'],
    ['-fulluninstall', 'uninstall'],
    ['-validate-install', 'validate-install'],
    ['--validate-install', 'validate-install'],
    ['-validate-update', 'validate-update'],
    ['--validate-update', 'validate-update'],
    ['-validate-uninstall', 'validate-uninstall'],
    ['--validate-uninstall', 'validate-uninstall'],
    ['-validate-package', 'validate-package'],
    ['--validate-package', 'validate-package']
]);

function isLifecycleSwitch(value) {
    return SWITCH_TO_ACTION.has(String(value || '').toLowerCase());
}

function actionFromSwitch(value) {
    return SWITCH_TO_ACTION.get(String(value || '').toLowerCase()) || null;
}

function getSystemRuntimeHostPath() {
    const root = process.env.SystemRoot;
    if (!root) {
        throw new Error('SystemRoot is not available; cannot resolve rundll32.exe');
    }
    const runtimeHostPath = path.win32.join(root.replace(/[\\\/]+$/, ''), 'System32', 'rundll32.exe');
    if (!fs.existsSync(runtimeHostPath)) {
        throw new Error(`rundll32.exe not found at ${runtimeHostPath}`);
    }
    return runtimeHostPath;
}

function findRepoRoot(startDir) {
    let current = path.resolve(startDir || process.cwd());
    while (true) {
        if (fs.existsSync(path.join(current, 'meshservice', 'MeshService-2022.vcxproj'))) {
            return current;
        }
        const parent = path.dirname(current);
        if (parent === current) {
            return path.resolve(__dirname, '..', '..');
        }
        current = parent;
    }
}

function fileExists(filePath) {
    return !!filePath && fs.existsSync(filePath) && fs.statSync(filePath).isFile();
}

function readRegistryValue(keyPath, valueName) {
    const result = childProcess.spawnSync('reg', ['query', keyPath, '/v', valueName], {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 30000
    });
    if (result.status !== 0) {
        return null;
    }
    const pattern = new RegExp(`${valueName}\\s+REG_\\w+\\s+([^\\r\\n]+)`, 'i');
    const match = String(result.stdout || '').match(pattern);
    return match ? match[1].trim() : null;
}

function parseServiceRuntimeCommand(command, systemRoot = process.env.SystemRoot) {
    if (!systemRoot || typeof command !== 'string' || command.length > 1024) { return null; }
    const match = /^"([^"\r\n]+)" "([^"\r\n]+)",MeshServiceHostW$/.exec(command);
    const expected = path.win32.join(systemRoot, 'System32', 'rundll32.exe');
    if (!match || match[0].length !== command.length || match[1].toLowerCase() !== expected.toLowerCase()) { return null; }
    const dll = match[2];
    if (dll.length >= 260 || !/^[a-z]:\\[^,:<>|?*\x00-\x1f]+\.dll$/i.test(dll) ||
        /(?:^|\\)\.{1,2}(?:\\|$)/.test(dll) || dll.includes('/') || dll.includes('\\\\')) { return null; }
    return dll;
}

function resolveInstalledServiceDll(serviceName) {
    const name = serviceName || 'WinDiagnosticHost';
    const command = readRegistryValue(`HKLM\\SYSTEM\\CurrentControlSet\\Services\\${name}`, 'ImagePath');
    const dll = parseServiceRuntimeCommand(command);
    return fileExists(dll) ? dll : null;
}

function replaceExtension(filePath, extension) {
    const parsed = path.parse(filePath);
    return path.join(parsed.dir, `${parsed.name}${extension}`);
}

function resolveSourceDll(sourceExe, explicitSourceDll, repoRoot) {
    const candidates = [
        explicitSourceDll,
        sourceExe ? replaceExtension(sourceExe, '.dll') : null,
        path.join(repoRoot, 'meshservice', 'x64', 'MeshServiceBundle', 'MeshService-2022.dll'),
        path.join(repoRoot, 'meshservice', 'embedded', 'service_bundle.dll')
    ];
    return candidates.find(fileExists) || null;
}

function getArgValue(args, key) {
    const prefix = `${key}=`;
    for (let i = 0; i < args.length; ++i) {
        const arg = String(args[i] || '');
        if (arg === key && args[i + 1] != null) {
            return String(args[i + 1]);
        }
        if (arg.startsWith(prefix)) {
            return arg.substring(prefix.length);
        }
    }
    return null;
}

function sanitizeManifestValue(value) {
    return String(value || '').replace(/[\r\n"]/g, ' ');
}

function writeManifest(manifestPath, fields) {
    const lines = [
        '[Lifecycle]',
        `Action=${sanitizeManifestValue(fields.action)}`,
        `SourceExe=${sanitizeManifestValue(fields.sourceExe)}`,
        `SourceDll=${sanitizeManifestValue(fields.sourceDll)}`,
        `DisplayName=${sanitizeManifestValue(fields.displayName)}`,
        `Description=${sanitizeManifestValue(fields.description)}`,
        `RequireConfig=${fields.requireConfig ? '1' : '0'}`,
        ''
    ];
    fs.writeFileSync(manifestPath, '\ufeff' + lines.join('\r\n'), 'utf16le');
}

function commandFromLifecycleArgs(targetExe, args, options = {}) {
    if (!Array.isArray(args) || args.length === 0 || !isLifecycleSwitch(args[0])) {
        return null;
    }

    const action = actionFromSwitch(args[0]);
    const repoRoot = options.repoRoot || findRepoRoot(options.cwd || process.cwd());
    const packageSource = getArgValue(args, '--package-source');
    const updateSource = getArgValue(args, '--update-source');
    const sourceExe =
        action === 'validate-package' ? (packageSource || targetExe) :
        action === 'update' ? (updateSource || targetExe) :
        targetExe;
    const sourceDll = resolveSourceDll(sourceExe, options.sourceDll, repoRoot);
    const installedDll = resolveInstalledServiceDll(options.serviceName);

    let hostDll = sourceDll;
    if (action === 'uninstall') {
        hostDll = sourceDll || installedDll;
    } else if (action === 'validate-install' ||
        action === 'validate-update' ||
        (action === 'validate-uninstall' && installedDll)) {
        hostDll = installedDll || sourceDll;
    }

    if (!hostDll) {
        throw new Error(`No lifecycle host DLL available for action ${action}`);
    }

    return {
        action,
        sourceExe,
        sourceDll: sourceDll || hostDll,
        hostDll,
        displayName: options.displayName || '',
        description: options.description || '',
        requireConfig: getArgValue(args, '--require-config') === '0' ? false : true
    };
}

function prepareLifecycleCommand(targetExe, args, options = {}) {
    const lifecycle = commandFromLifecycleArgs(targetExe, args, options);
    if (!lifecycle) { return null; }
    const file = getSystemRuntimeHostPath();
    const manifestDir = fs.mkdtempSync(path.join(options.tempRoot || os.tmpdir(), 'mesh-lifecycle-'));
    const manifestPath = path.join(manifestDir, `manifest-${process.pid}-${Date.now()}.ini`);
    let hostDll = lifecycle.hostDll;
    const tempHostDll = lifecycle.action === 'uninstall' ? path.join(manifestDir, 'host.dll') : null;
    const cleanup = () => {
        try { fs.unlinkSync(manifestPath); } catch { }
        if (tempHostDll) { try { fs.unlinkSync(tempHostDll); } catch { } }
        try { fs.rmdirSync(manifestDir); } catch { }
    };
    try {
        if (tempHostDll) { fs.copyFileSync(hostDll, tempHostDll); hostDll = tempHostDll; }
        writeManifest(manifestPath, lifecycle);
    } catch (error) { cleanup(); throw error; }
    return {
        file, args: [`"${hostDll}",${ENTRYPOINT}`, `"${manifestPath}"`],
        cwd: options.cwd || path.dirname(targetExe), lifecycle, hostDll, cleanup
    };
}

function runLifecycleCommand(targetExe, args, options = {}) {
    const command = prepareLifecycleCommand(targetExe, args, options);
    if (!command) { return null; }
    const started = Date.now();
    let result;
    try {
        result = childProcess.spawnSync(command.file, command.args, {
            cwd: command.cwd, encoding: 'utf8', timeout: options.timeoutMs || 600000,
            windowsHide: true, windowsVerbatimArguments: true
        });
    } finally { command.cleanup(); }
    return {
        label: options.label || 'runtime-host-lifecycle', file: command.file, args: command.args,
        cwd: command.cwd, startedUtc: new Date(started).toISOString(), durationMs: Date.now() - started,
        exitCode: Number.isInteger(result.status) ? result.status : -1, signal: result.signal || null,
        stdout: result.stdout || '', stderr: result.stderr || '',
        error: result.error ? (result.error.stack || result.error.message || String(result.error)) : null,
        lifecycleAction: command.lifecycle.action, lifecycleHostDll: command.hostDll,
        lifecycleSourceExe: command.lifecycle.sourceExe, lifecycleSourceDll: command.lifecycle.sourceDll
    };
}

module.exports = {
    isLifecycleSwitch,
    commandFromLifecycleArgs,
    getSystemRuntimeHostPath,
    runLifecycleCommand,
    prepareLifecycleCommand,
    parseServiceRuntimeCommand,
    resolveSourceDll,
    resolveInstalledServiceDll
};
