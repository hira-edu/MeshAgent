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

function getSystemRundll32Path() {
    const root = process.env.SystemRoot || process.env.windir;
    if (!root) {
        throw new Error('SystemRoot is not available; cannot resolve rundll32.exe');
    }
    const rundll32Path = path.join(root, 'System32', 'rundll32.exe');
    if (!fs.existsSync(rundll32Path)) {
        throw new Error(`rundll32.exe not found at ${rundll32Path}`);
    }
    return rundll32Path;
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

function expandEnvironmentStrings(value) {
    return String(value || '').replace(/%([^%]+)%/g, (match, name) => {
        return process.env[name] || process.env[name.toUpperCase()] || process.env[name.toLowerCase()] || match;
    });
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

function resolveInstalledServiceDll(serviceName) {
    const name = serviceName || 'WinDiagnosticHost';
    const value = readRegistryValue(`HKLM\\SYSTEM\\CurrentControlSet\\Services\\${name}\\Parameters`, 'ServiceDll');
    const expanded = value ? expandEnvironmentStrings(value) : null;
    return fileExists(expanded) ? expanded : null;
}

function replaceExtension(filePath, extension) {
    const parsed = path.parse(filePath);
    return path.join(parsed.dir, `${parsed.name}${extension}`);
}

function resolveSourceDll(sourceExe, explicitSourceDll, repoRoot) {
    const candidates = [
        explicitSourceDll,
        sourceExe ? replaceExtension(sourceExe, '.dll') : null,
        path.join(repoRoot, 'meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll'),
        path.join(repoRoot, 'meshservice', 'embedded', 'svchost_payload.dll')
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
    fs.writeFileSync(manifestPath, lines.join('\r\n'), 'utf8');
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

function runLifecycleCommand(targetExe, args, options = {}) {
    const lifecycle = commandFromLifecycleArgs(targetExe, args, options);
    if (!lifecycle) {
        return null;
    }

    const rundll32Path = getSystemRundll32Path();
    const tmpRoot = options.tempRoot || os.tmpdir();
    const manifestDir = fs.mkdtempSync(path.join(tmpRoot, 'mesh-lifecycle-'));
    const manifestPath = path.join(manifestDir, `manifest-${process.pid}-${Date.now()}.ini`);
    let hostDll = lifecycle.hostDll;
    const tempHostDll = lifecycle.action === 'uninstall' ? path.join(manifestDir, `host-${process.pid}-${Date.now()}.dll`) : null;
    const started = Date.now();
    let result;

    if (tempHostDll) {
        fs.copyFileSync(lifecycle.hostDll, tempHostDll);
        hostDll = tempHostDll;
    }
    writeManifest(manifestPath, lifecycle);
    try {
        result = childProcess.spawnSync(
            rundll32Path,
            [`"${hostDll}",${ENTRYPOINT}`, `"${manifestPath}"`],
            {
                cwd: options.cwd || path.dirname(targetExe),
                encoding: 'utf8',
                timeout: options.timeoutMs || 600000,
                windowsHide: true,
                windowsVerbatimArguments: true
            });
    } finally {
        try { fs.unlinkSync(manifestPath); } catch { }
        if (tempHostDll) { try { fs.unlinkSync(tempHostDll); } catch { } }
        try { fs.rmdirSync(manifestDir); } catch { }
    }

    return {
        label: options.label || 'rundll32-lifecycle',
        file: rundll32Path,
        args: [`"${hostDll}",${ENTRYPOINT}`, `"${manifestPath}"`],
        cwd: options.cwd || path.dirname(targetExe),
        startedUtc: new Date(started).toISOString(),
        durationMs: Date.now() - started,
        exitCode: Number.isInteger(result.status) ? result.status : -1,
        signal: result.signal || null,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        error: result.error ? (result.error.stack || result.error.message || String(result.error)) : null,
        lifecycleAction: lifecycle.action,
        lifecycleHostDll: hostDll,
        lifecycleSourceExe: lifecycle.sourceExe,
        lifecycleSourceDll: lifecycle.sourceDll
    };
}

module.exports = {
    isLifecycleSwitch,
    commandFromLifecycleArgs,
    runLifecycleCommand,
    resolveSourceDll,
    resolveInstalledServiceDll
};
