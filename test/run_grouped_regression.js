const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
    loadIdentityFromEmbeddedExe,
    loadIdentityFromKvFile,
    compareIdentity
} = require('./lib/provisioning_identity');
const lifecycleRunner = require('./lib/rundll32_lifecycle');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_SOURCE_EXE = path.join(REPO_ROOT, 'meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
const DEFAULT_SOURCE_DLL = path.join(REPO_ROOT, 'meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
const HARNESS_PROJECT = path.join(REPO_ROOT, 'test', 'gui_button_race_harness', 'GuiButtonRaceHarness.csproj');
const HARNESS_DLL = path.join(REPO_ROOT, 'test', 'gui_button_race_harness', 'bin', 'Release', 'net10.0-windows', 'GuiButtonRaceHarness.dll');
const DEFAULT_GUI_LOG = path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'DiagnosticHost', 'gui-launch.log');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const key = argv[i];
        if (!key.startsWith('--')) {
            throw new Error(`Unexpected argument: ${key}`);
        }

        const name = key.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            throw new Error(`Missing value for --${name}`);
        }

        args[name] = value;
        i += 1;
    }
    return args;
}

function getArg(args, key, fallback) {
    return args[key] != null ? path.resolve(args[key]) : fallback;
}

function timestampUtc() {
    const now = new Date();
    const pad = (value) => String(value).padStart(2, '0');
    return `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function hashFile(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonIfPresent(filePath) {
    return fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf8')) : null;
}

function trimText(value) {
    const text = String(value || '').replace(/\r/g, ' ').replace(/\n/g, ' ').trim();
    if (!text) { return '(empty)'; }
    return text.length <= 600 ? text : `${text.substring(0, 600)}...`;
}

function ensureFile(filePath, label) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`${label} missing: ${filePath}`);
    }
}

function defaultSidecar(sourceExe, extension) {
    const candidate = path.join(path.dirname(sourceExe), `${path.basename(sourceExe, path.extname(sourceExe))}${extension}`);
    return fs.existsSync(candidate) ? candidate : null;
}

function resolveSourceSet(args) {
    const exe = getArg(args, 'source-exe', DEFAULT_SOURCE_EXE);
    ensureFile(exe, 'source exe');

    const explicitDb = args['source-db'] ? path.resolve(args['source-db']) : null;
    const explicitMsh = args['source-msh'] ? path.resolve(args['source-msh']) : null;
    const explicitConf = args['source-conf'] ? path.resolve(args['source-conf']) : null;
    const explicitDll = args['source-dll'] ? path.resolve(args['source-dll']) : null;
    const dll = explicitDll || defaultSidecar(exe, '.dll') || (fs.existsSync(DEFAULT_SOURCE_DLL) ? DEFAULT_SOURCE_DLL : null);
    if (dll != null) { ensureFile(dll, 'source dll'); }

    return {
        exe,
        db: explicitDb || defaultSidecar(exe, '.db'),
        msh: explicitMsh || defaultSidecar(exe, '.msh'),
        conf: explicitConf || defaultSidecar(exe, '.conf'),
        dll
    };
}

function copyIfPresent(sourcePath, destinationPath) {
    if (!sourcePath) { return null; }
    ensureDir(path.dirname(destinationPath));
    fs.copyFileSync(sourcePath, destinationPath);
    return destinationPath;
}

function stageExecutable(sourceSet, destinationExe, options = {}) {
    const includeDb = options.includeDb !== false;
    const includeMsh = options.includeMsh !== false;
    const includeConf = options.includeConf === true;
    const includeDll = options.includeDll !== false;

    ensureDir(path.dirname(destinationExe));
    fs.copyFileSync(sourceSet.exe, destinationExe);

    const staged = {
        exe: destinationExe,
        db: includeDb ? copyIfPresent(sourceSet.db, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.db`)) : null,
        msh: includeMsh ? copyIfPresent(sourceSet.msh, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.msh`)) : null,
        conf: includeConf ? copyIfPresent(sourceSet.conf, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.conf`)) : null,
        dll: includeDll ? copyIfPresent(sourceSet.dll, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.dll`)) : null
    };
    staged.sha256 = hashFile(destinationExe);
    return staged;
}

function cacheSourceSet(sourceSet, cacheDir) {
    ensureDir(cacheDir);

    const cachedExe = path.join(cacheDir, path.basename(sourceSet.exe));
    fs.copyFileSync(sourceSet.exe, cachedExe);

    return {
        exe: cachedExe,
        db: copyIfPresent(sourceSet.db, path.join(cacheDir, path.basename(sourceSet.db || ''))),
        msh: copyIfPresent(sourceSet.msh, path.join(cacheDir, path.basename(sourceSet.msh || ''))),
        conf: copyIfPresent(sourceSet.conf, path.join(cacheDir, path.basename(sourceSet.conf || ''))),
        dll: copyIfPresent(sourceSet.dll, path.join(cacheDir, path.basename(sourceSet.dll || '')))
    };
}

function createCommandRunner(commandsPath, commandRecords, context = {}) {
    return function runCommand(label, file, args, options = {}) {
        const start = Date.now();
        const cwd = options.cwd || REPO_ROOT;
        let record;
        if (process.platform === 'win32' && args && args.length > 0 && lifecycleRunner.isLifecycleSwitch(args[0])) {
            record = lifecycleRunner.runLifecycleCommand(file, args, {
                label,
                cwd,
                timeoutMs: options.timeoutMs || 120000,
                repoRoot: REPO_ROOT,
                serviceName: context.serviceName || 'WinDiagnosticHost',
                sourceDll: context.sourceDll || null
            });
        } else {
            const result = spawnSync(file, args, {
                cwd,
                encoding: 'utf8',
                timeout: options.timeoutMs || 120000,
                windowsHide: true
            });
            record = {
                label,
                file,
                args,
                cwd,
                startedUtc: new Date(start).toISOString(),
                durationMs: Date.now() - start,
                exitCode: Number.isInteger(result.status) ? result.status : -1,
                signal: result.signal || null,
                stdout: result.stdout || '',
                stderr: result.stderr || '',
                error: result.error ? (result.error.stack || result.error.message || String(result.error)) : null
            };
        }
        commandRecords.push(record);
        fs.appendFileSync(commandsPath, JSON.stringify({
            label: record.label,
            file: record.file,
            args: record.args,
            cwd: record.cwd,
            exitCode: record.exitCode,
            durationMs: record.durationMs,
            startedUtc: record.startedUtc,
            lifecycleAction: record.lifecycleAction || null,
            lifecycleHostDll: record.lifecycleHostDll || null,
            lifecycleSourceExe: record.lifecycleSourceExe || null,
            lifecycleSourceDll: record.lifecycleSourceDll || null
        }) + '\n');
        return record;
    };
}

function writeCommandArtifacts(dir, name, record) {
    writeJson(path.join(dir, `${name}.json`), record);
    writeText(path.join(dir, `${name}.stdout.txt`), record.stdout || '');
    writeText(path.join(dir, `${name}.stderr.txt`), record.stderr || '');
}

function ensureSuccess(record, message) {
    if (record.error) {
        throw new Error(`${message}: ${record.error}`);
    }
    if (record.exitCode !== 0) {
        throw new Error(`${message}: exit=${record.exitCode} stdout=${trimText(record.stdout)} stderr=${trimText(record.stderr)}`);
    }
}

function ensureFailure(record, message) {
    if (record.error) { return; }
    if (record.exitCode === 0) {
        throw new Error(`${message}: unexpectedly succeeded`);
    }
}

function parseValidationJson(record) {
    try {
        return JSON.parse(record.stdout);
    } catch {
        return null;
    }
}

function getElevationState(runCommand) {
    const result = runCommand('session-elevation', 'whoami', ['/groups'], { timeoutMs: 30000, cwd: REPO_ROOT });
    const stdout = result.stdout || '';
    const elevated = stdout.includes('High Mandatory Level') || stdout.includes('System Mandatory Level');
    return {
        platform: process.platform,
        elevated,
        exitCode: result.exitCode,
        stdout,
        stderr: result.stderr || ''
    };
}

function queryServiceName(runCommand, runnerExe) {
    const record = runCommand('query-service-name', runnerExe, ['-name'], {
        cwd: path.dirname(runnerExe),
        timeoutMs: 60000
    });
    ensureSuccess(record, 'query service name');
    return record.stdout.trim() || 'WinDiagnosticHost';
}

function queryNodeId(runCommand, serviceName, label = 'query-nodeid') {
    const record = runCommand(label, 'reg', ['query', `HKLM\\SOFTWARE\\Open Source\\${serviceName}`, '/v', 'NodeId'], {
        cwd: REPO_ROOT,
        timeoutMs: 30000
    });
    if (record.exitCode !== 0) { return ''; }

    const match = record.stdout.match(/NodeId\s+REG_\w+\s+([^\r\n]+)/i);
    return match ? match[1].trim() : '';
}

function hexNodeIdToRegistryValue(hexValue) {
    const normalized = String(hexValue || '').trim();
    if (!normalized || normalized.length % 2 !== 0 || /[^0-9a-f]/i.test(normalized)) {
        return '';
    }

    return Buffer.from(normalized, 'hex')
        .toString('base64')
        .replace(/\+/g, '@')
        .replace(/\//g, '$')
        .replace(/=+$/g, '');
}

function queryExecutableNodeId(runCommand, executablePath, label = 'query-installed-nodeid') {
    const record = runCommand(label, executablePath, ['-nodeid'], {
        cwd: path.dirname(executablePath),
        timeoutMs: 60000
    });
    if (record.exitCode !== 0) { return ''; }
    return String(record.stdout || '').trim();
}

function resolveInstalledAgentExe(statusRecord) {
    const payload = parseValidationJson(statusRecord);
    const serviceDll = payload && payload.values
        ? (payload.values.expectedServiceDll || payload.values.serviceDllExpanded || '')
        : '';
    if (!serviceDll) {
        throw new Error('svchost status did not provide an installed service DLL path');
    }

    const installDir = path.dirname(serviceDll);
    if (!fs.existsSync(installDir)) {
        throw new Error(`Installed service directory missing: ${installDir}`);
    }

    const preferred = path.join(installDir, 'diaghost.exe');
    if (fs.existsSync(preferred)) {
        return preferred;
    }

    const candidates = fs.readdirSync(installDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.exe'))
        .map((entry) => entry.name)
        .filter((name) => name.toLowerCase() !== 'svchost.exe' && name.toLowerCase() !== 'masterservice.exe')
        .sort((left, right) => left.localeCompare(right, 'en', { sensitivity: 'base' }));

    if (candidates.length === 1) {
        return path.join(installDir, candidates[0]);
    }

    throw new Error(`Unable to resolve installed agent executable from ${installDir}`);
}

function sleepMs(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function isSuccessfulValidationRecord(record) {
    const payload = parseValidationJson(record);
    if (record && record.lifecycleAction && record.exitCode === 0) {
        return {
            payload: {
                success: true,
                phase: record.lifecycleAction,
                checks: { lifecycleHostExit: true },
                values: {
                    lifecycleHostDll: record.lifecycleHostDll || '',
                    lifecycleSourceExe: record.lifecycleSourceExe || '',
                    lifecycleSourceDll: record.lifecycleSourceDll || ''
                }
            },
            success: true
        };
    }
    return {
        payload,
        success: !record.error && record.exitCode === 0 && payload != null && payload.success === true
    };
}

function runValidationWithRetries(runCommand, runnerExe, phaseDir, artifactStem, args, message, options = {}) {
    const attempts = options.attempts || 5;
    const delayMs = options.delayMs || 2000;
    const timeoutMs = options.timeoutMs || 180000;
    const cwd = options.cwd || path.dirname(runnerExe);
    let lastRecord = null;
    let lastValidation = { payload: null, success: false };

    for (let attempt = 1; attempt <= attempts; ++attempt) {
        const record = runCommand(`${artifactStem}-attempt-${attempt}`, runnerExe, args, {
            cwd,
            timeoutMs
        });
        writeCommandArtifacts(phaseDir, `${artifactStem}-attempt-${attempt}`, record);
        lastRecord = record;
        lastValidation = isSuccessfulValidationRecord(record);

        if (lastValidation.success) {
            writeCommandArtifacts(phaseDir, artifactStem, record);
            return {
                attempts: attempt,
                payload: lastValidation.payload,
                record
            };
        }

        if (attempt < attempts) {
            sleepMs(delayMs);
        }
    }

    writeCommandArtifacts(phaseDir, artifactStem, lastRecord);
    if (lastRecord && lastRecord.error) {
        throw new Error(`${message}: ${lastRecord.error}`);
    }
    throw new Error(
        `${message}: exit=${lastRecord ? lastRecord.exitCode : -1} stdout=${trimText(lastRecord ? lastRecord.stdout : '')} stderr=${trimText(lastRecord ? lastRecord.stderr : '')}`
    );
}

function waitForNodeIdConvergence(runCommand, serviceName, installedExe, labelPrefix, timeoutMs = 60000) {
    const deadline = Date.now() + timeoutMs;
    let registryNodeId = '';
    let executableNodeId = '';

    while (Date.now() <= deadline) {
        registryNodeId = queryNodeId(runCommand, serviceName, `${labelPrefix}-registry`);
        executableNodeId = queryExecutableNodeId(runCommand, installedExe, `${labelPrefix}-exe`);

        if (registryNodeId && executableNodeId && registryNodeId === hexNodeIdToRegistryValue(executableNodeId)) {
            return {
                registryNodeId,
                executableNodeId
            };
        }

        sleepMs(500);
    }

    throw new Error(
        `NodeId did not converge for ${installedExe}: registry=${registryNodeId || '(missing)'} executable=${executableNodeId || '(missing)'}`
    );
}

function summarizePhase(phaseDir, lines) {
    writeText(path.join(phaseDir, 'summary.txt'), `${lines.join('\n')}\n`);
}

function runPackagePreflight(runCommand, sourceSet, phaseDir) {
    const runner = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'package runner (with spaces)', 'MeshService-2022 package runner (grouped).exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );
    const validPackage = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'package source (valid)', 'MeshService-2022 package source (valid).exe'),
        { includeDb: true, includeMsh: true, includeConf: false }
    );
    const invalidPackageSourcePath = path.join(phaseDir, 'package source (invalid directory)');
    ensureDir(invalidPackageSourcePath);

    let embedded = null;
    let embeddedError = null;
    try {
        embedded = loadIdentityFromEmbeddedExe(validPackage.exe, 'package_embedded_msh');
        writeText(path.join(phaseDir, 'package_embedded_msh.txt'), embedded.text);
    } catch (error) {
        embeddedError = error instanceof Error ? error.message : String(error);
    }

    let sidecarIdentity = null;
    let identityCompare = null;
    if (validPackage.msh) {
        sidecarIdentity = loadIdentityFromKvFile(validPackage.msh, 'package_sidecar_msh');
        if (embedded) {
            identityCompare = compareIdentity(embedded.identity, sidecarIdentity);
        }
    }

    const validRecord = runCommand('package-valid', runner.exe, [
        '-validate-package',
        `--package-source=${validPackage.exe}`,
        '--require-config=0',
        '--allow-installed-fallback=0'
    ], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(phaseDir, 'package-valid', validRecord);
    ensureSuccess(validRecord, 'valid package preflight');

    const invalidRecord = runCommand('package-invalid', runner.exe, [
        '-validate-package',
        `--package-source=${invalidPackageSourcePath}`,
        '--require-config=0',
        '--allow-installed-fallback=0'
    ], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(phaseDir, 'package-invalid', invalidRecord);
    ensureFailure(invalidRecord, 'invalid package preflight');

    const result = {
        runner,
        validPackage,
        invalidPackageSourcePath,
        validValidation: parseValidationJson(validRecord),
        invalidValidation: parseValidationJson(invalidRecord),
        embeddedIdentity: embedded ? embedded.identity : null,
        embeddedIdentityError: embeddedError,
        sidecarIdentity,
        identityCompare
    };
    writeJson(path.join(phaseDir, 'package_preflight.json'), result);
    summarizePhase(phaseDir, [
        `VALID_EXIT=${validRecord.exitCode}`,
        `INVALID_EXIT=${invalidRecord.exitCode}`,
        `VALID_PACKAGE=${validPackage.exe}`,
        `INVALID_PACKAGE_SOURCE=${invalidPackageSourcePath}`,
        `EMBEDDED_MSH=${embedded ? path.join(phaseDir, 'package_embedded_msh.txt') : '(absent)'}`,
        `EMBEDDED_MSH_ERROR=${embeddedError || '(none)'}`,
        `SIDECAR_MSH=${validPackage.msh || '(absent)'}`,
        `IDENTITY_MATCH=${identityCompare ? identityCompare.match : '(not-compared)'}`,
        `RUNNER_SHA256=${runner.sha256}`
    ]);
    return result;
}

function runJsSelfTest(runCommand, sourceSet, phaseDir) {
    const runner = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'js runner (with spaces)', 'MeshService-2022 js runner (LocalTests).exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );
    const scriptPath = path.join(REPO_ROOT, 'test', 'self-test.js');
    ensureFile(scriptPath, 'self-test.js');

    const record = runCommand('js-self-test', runner.exe, [scriptPath, '--LocalTests'], {
        cwd: REPO_ROOT,
        timeoutMs: 900000
    });
    writeCommandArtifacts(phaseDir, 'js-self-test', record);
    ensureSuccess(record, 'JS local self-test');

    const result = {
        runner,
        scriptPath,
        exitCode: record.exitCode
    };
    writeJson(path.join(phaseDir, 'js_self_test.json'), result);
    summarizePhase(phaseDir, [
        `EXIT=${record.exitCode}`,
        `RUNNER=${runner.exe}`,
        `SCRIPT=${scriptPath}`,
        `RUNNER_SHA256=${runner.sha256}`
    ]);
    return result;
}

function runMeshCentralSameSizeContracts(runCommand, phaseDir) {
    const tests = [
        {
            name: 'meshcentral-desktop-same-size-contract',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_desktop_same_size_contract.js'),
            evidenceDir: path.join(phaseDir, 'viewer_contract')
        },
        {
            name: 'meshcentral-multiplex-same-size-contract',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_multiplex_same_size_contract.js'),
            evidenceDir: path.join(phaseDir, 'multiplex_contract')
        },
        {
            name: 'meshcentral-desktop-reconnect-runtime',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_desktop_reconnect_runtime.js'),
            evidenceDir: path.join(phaseDir, 'reconnect_runtime')
        },
        {
            name: 'meshcentral-location-guard-contract',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_meshagent_location_guard_contract.js'),
            evidenceDir: path.join(phaseDir, 'location_guard_contract')
        },
        {
            name: 'meshcentral-svchost-selfupdate-contract',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_svchost_selfupdate_contract.js'),
            evidenceDir: path.join(phaseDir, 'svchost_selfupdate_contract')
        },
        {
            name: 'meshcentral-terminal-bridge-contract',
            script: path.join(REPO_ROOT, 'test', 'meshcentral_terminal_bridge_contract.js'),
            evidenceDir: path.join(phaseDir, 'terminal_bridge_contract')
        },
        {
            name: 'rundll32-bridge-smoke',
            script: path.join(REPO_ROOT, 'test', 'rundll32_bridge_smoke.js'),
            evidenceDir: path.join(phaseDir, 'bridge_smoke')
        },
        {
            name: 'kvm-initial-frame-runtime',
            script: path.join(REPO_ROOT, 'test', 'kvm_initial_frame_runtime.js'),
            evidenceDir: path.join(phaseDir, 'kvm_initial_frame_runtime')
        },
        {
            name: 'svchost-embedded-payload-contract',
            script: path.join(REPO_ROOT, 'test', 'svchost_embedded_payload_contract.js'),
            evidenceDir: path.join(phaseDir, 'svchost_embedded_payload_contract')
        },
        {
            name: 'kvm-system-picture-runtime',
            script: path.join(REPO_ROOT, 'test', 'kvm_system_picture_runtime.js'),
            evidenceDir: path.join(phaseDir, 'kvm_system_picture_runtime')
        }
    ];

    const records = [];
    for (const test of tests) {
        ensureFile(test.script, `${test.name} script`);
        const record = runCommand(test.name, 'node', [test.script, '--evidence', test.evidenceDir], {
            cwd: REPO_ROOT,
            timeoutMs: 240000
        });
        writeCommandArtifacts(phaseDir, test.name, record);
        ensureSuccess(record, `${test.name} failed`);
        records.push({
            name: test.name,
            script: test.script,
            evidenceDir: test.evidenceDir,
            exitCode: record.exitCode
        });
    }

    writeJson(path.join(phaseDir, 'meshcentral_same_size_contracts.json'), {
        generatedUtc: new Date().toISOString(),
        records
    });
    summarizePhase(phaseDir, [
        `VIEWER_CONTRACT=${path.join(phaseDir, 'viewer_contract', 'summary.txt')}`,
        `MULTIPLEX_CONTRACT=${path.join(phaseDir, 'multiplex_contract', 'summary.txt')}`,
        `LOCATION_GUARD_CONTRACT=${path.join(phaseDir, 'location_guard_contract', 'summary.txt')}`,
        `SVCHOST_SELFUPDATE_CONTRACT=${path.join(phaseDir, 'svchost_selfupdate_contract', 'summary.txt')}`,
        `TERMINAL_BRIDGE_CONTRACT=${path.join(phaseDir, 'terminal_bridge_contract', 'summary.txt')}`,
        `BRIDGE_SMOKE=${path.join(phaseDir, 'bridge_smoke', 'summary.txt')}`,
        `INITIAL_FRAME_RUNTIME=${path.join(phaseDir, 'kvm_initial_frame_runtime', 'summary.txt')}`,
        `SYSTEM_PICTURE_RUNTIME=${path.join(phaseDir, 'kvm_system_picture_runtime', 'summary.txt')}`
    ]);
    return { records };
}

function runNativeCliPhase(runCommand, sourceSet, phaseDir) {
    const cliRunner = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'native cli runner (spaces)', 'MeshService-2022 native cli (grouped).exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );
    const updateSource = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'update source (parentheses)', 'MeshService-2022 update source (grouped).exe'),
        { includeDb: true, includeMsh: true, includeConf: false }
    );

    const serviceName = queryServiceName(runCommand, cliRunner.exe);

    const cleanupBefore = runCommand('native-cleanup-before', cliRunner.exe, ['-fulluninstall'], {
        cwd: path.dirname(cliRunner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(phaseDir, 'native-cleanup-before', cleanupBefore);

    runValidationWithRetries(
        runCommand,
        cliRunner.exe,
        phaseDir,
        'native-validate-before',
        ['-validate-uninstall'],
        'validate uninstall before native roundtrip',
        { attempts: 12, delayMs: 5000 }
    );

    let install = null;
    let validateInstall = null;
    let installAttempts = 0;
    let installFailure = null;

    for (let attempt = 1; attempt <= 3; ++attempt) {
        install = runCommand(`native-install-attempt-${attempt}`, cliRunner.exe, ['-fullinstall'], {
            cwd: path.dirname(cliRunner.exe),
            timeoutMs: 600000
        });
        writeCommandArtifacts(phaseDir, `native-install-attempt-${attempt}`, install);

        try {
            validateInstall = runValidationWithRetries(
                runCommand,
                cliRunner.exe,
                phaseDir,
                `native-validate-install-attempt-${attempt}`,
                ['-validate-install'],
                `validate install after fullinstall attempt ${attempt}`,
                { attempts: 6, delayMs: 3000 }
            );
            installAttempts = attempt;
            writeCommandArtifacts(phaseDir, 'native-install', install);
            writeCommandArtifacts(phaseDir, 'native-validate-install', validateInstall.record);
            installFailure = null;
            break;
        } catch (error) {
            installFailure = error;
        }

        if (attempt < 3) {
            const cleanup = runCommand(`native-install-recovery-uninstall-attempt-${attempt}`, cliRunner.exe, ['-fulluninstall'], {
                cwd: path.dirname(cliRunner.exe),
                timeoutMs: 600000
            });
            writeCommandArtifacts(phaseDir, `native-install-recovery-uninstall-attempt-${attempt}`, cleanup);

            runValidationWithRetries(
                runCommand,
                cliRunner.exe,
                phaseDir,
                `native-install-recovery-validate-uninstall-attempt-${attempt}`,
                ['-validate-uninstall'],
                `validate uninstall after failed fullinstall attempt ${attempt}`,
                { attempts: 12, delayMs: 5000 }
            );
        }
    }

    if (!validateInstall) {
        if (install && install.error) {
            throw new Error(`fullinstall: ${install.error}`);
        }
        if (installFailure instanceof Error) {
            throw installFailure;
        }
        throw new Error(`fullinstall failed after retries: exit=${install ? install.exitCode : -1} stdout=${trimText(install ? install.stdout : '')} stderr=${trimText(install ? install.stderr : '')}`);
    }

    const svchostInstall = runCommand('native-svchost-install', cliRunner.exe, ['-svchost-status'], {
        cwd: path.dirname(cliRunner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(phaseDir, 'native-svchost-install', svchostInstall);
    ensureSuccess(svchostInstall, 'svchost status after install');

    const installedExe = resolveInstalledAgentExe(svchostInstall);
    const nodeBeforeState = waitForNodeIdConvergence(runCommand, serviceName, installedExe, 'native-install-nodeid');
    const nodeBefore = nodeBeforeState.registryNodeId;

    const update = runCommand('native-update', cliRunner.exe, ['-fullupdate', `--update-source=${updateSource.exe}`], {
        cwd: path.dirname(cliRunner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(phaseDir, 'native-update', update);
    ensureSuccess(update, 'fullupdate');

    const validateUpdate = runValidationWithRetries(
        runCommand,
        cliRunner.exe,
        phaseDir,
        'native-validate-update',
        ['-validate-update'],
        'validate update',
        { attempts: 6 }
    );

    const svchostUpdate = runCommand('native-svchost-update', cliRunner.exe, ['-svchost-status'], {
        cwd: path.dirname(cliRunner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(phaseDir, 'native-svchost-update', svchostUpdate);
    ensureSuccess(svchostUpdate, 'svchost status after update');

    const installedExeAfter = resolveInstalledAgentExe(svchostUpdate);
    const nodeAfterState = waitForNodeIdConvergence(runCommand, serviceName, installedExeAfter, 'native-update-nodeid');
    const nodeAfter = nodeAfterState.registryNodeId;
    if (!nodeBefore || !nodeAfter || nodeBefore !== nodeAfter) {
        throw new Error(`NodeId changed across update: before=${nodeBefore || '(missing)'} after=${nodeAfter || '(missing)'}`);
    }

    const uninstall = runCommand('native-uninstall', cliRunner.exe, ['-fulluninstall'], {
        cwd: path.dirname(cliRunner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(phaseDir, 'native-uninstall', uninstall);
    ensureSuccess(uninstall, 'fulluninstall');

    const validateUninstall = runValidationWithRetries(
        runCommand,
        cliRunner.exe,
        phaseDir,
        'native-validate-uninstall',
        ['-validate-uninstall'],
        'validate uninstall',
        { attempts: 12, delayMs: 5000 }
    );

    const result = {
        cliRunner,
        updateSource,
        serviceName,
        installedExe,
        nodeBefore,
        nodeAfter,
        installAttempts,
        validateInstallAttempts: validateInstall.attempts,
        validateUpdateAttempts: validateUpdate.attempts,
        validateUninstallAttempts: validateUninstall.attempts,
        installedNodeBeforeHex: nodeBeforeState.executableNodeId,
        installedNodeAfterHex: nodeAfterState.executableNodeId
    };
    writeJson(path.join(phaseDir, 'native_cli_roundtrip.json'), result);
    summarizePhase(phaseDir, [
        `SERVICE_NAME=${serviceName}`,
        `INSTALLED_EXE=${installedExeAfter}`,
        `NODE_BEFORE=${nodeBefore}`,
        `NODE_AFTER=${nodeAfter}`,
        `INSTALL_ATTEMPTS=${installAttempts}`,
        `VALIDATE_INSTALL_ATTEMPTS=${validateInstall.attempts}`,
        `VALIDATE_UPDATE_ATTEMPTS=${validateUpdate.attempts}`,
        `VALIDATE_UNINSTALL_ATTEMPTS=${validateUninstall.attempts}`,
        `INSTALLED_NODE_BEFORE_HEX=${nodeBeforeState.executableNodeId}`,
        `INSTALLED_NODE_AFTER_HEX=${nodeAfterState.executableNodeId}`,
        `RUNNER=${cliRunner.exe}`,
        `UPDATE_SOURCE=${updateSource.exe}`,
        `RUNNER_SHA256=${cliRunner.sha256}`,
        `UPDATE_SOURCE_SHA256=${updateSource.sha256}`
    ]);
    return result;
}

function runGuiHarnessPhase(runCommand, sourceSet, phaseDir, guiLogPath) {
    const buildRecord = runCommand('gui-harness-build', 'dotnet', ['build', HARNESS_PROJECT, '-c', 'Release'], {
        cwd: REPO_ROOT,
        timeoutMs: 240000
    });
    writeCommandArtifacts(phaseDir, 'gui-harness-build', buildRecord);
    ensureSuccess(buildRecord, 'build GUI harness');
    ensureFile(HARNESS_DLL, 'GUI harness output');

    const guiSource = stageExecutable(
        sourceSet,
        path.join(phaseDir, 'gui source (spaces)', 'MeshService-2022 gui source (grouped).exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );

    const args = [
        HARNESS_DLL,
        '--source-exe', guiSource.exe,
        '--evidence', phaseDir,
        '--gui-log', guiLogPath
    ];
    if (guiSource.db) { args.push('--source-db', guiSource.db); }
    if (guiSource.msh) { args.push('--source-msh', guiSource.msh); }
    if (guiSource.conf) { args.push('--source-conf', guiSource.conf); }
    if (guiSource.dll) { args.push('--source-dll', guiSource.dll); }
    const record = runCommand('gui-harness-run', 'dotnet', args, {
        cwd: REPO_ROOT,
        timeoutMs: 3600000
    });
    writeCommandArtifacts(phaseDir, 'gui-harness-run', record);
    ensureSuccess(record, 'run GUI harness');

    const summaryPath = path.join(phaseDir, 'summary.txt');
    const resultsPath = path.join(phaseDir, 'results.json');
    ensureFile(summaryPath, 'GUI harness summary');
    ensureFile(resultsPath, 'GUI harness results');

    const results = readJsonIfPresent(resultsPath);
    const scenarios = Array.isArray(results && results.scenarios) ? results.scenarios : [];
    const failing = scenarios.filter((scenario) => scenario && scenario.Passed !== true && scenario.passed !== true);
    if (failing.length > 0) {
        throw new Error(`GUI harness reported failing scenarios: ${failing.map((scenario) => scenario.Name || scenario.name).join(', ')}`);
    }

    const runnerSummaryPath = path.join(phaseDir, 'runner-summary.txt');
    writeText(runnerSummaryPath, [
        `HARNESS_DLL=${HARNESS_DLL}`,
        `GUI_SOURCE=${guiSource.exe}`,
        `GUI_LOG=${guiLogPath}`,
        `HARNESS_SUMMARY=${summaryPath}`,
        `HARNESS_RESULTS=${resultsPath}`,
        `RUNNER_SHA256=${guiSource.sha256}`
    ].join('\n') + '\n');

    return {
        guiSource,
        harnessSummaryPath: summaryPath,
        harnessResultsPath: resultsPath,
        runnerSummaryPath
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceRoot = getArg(
        args,
        'evidence',
        path.join(REPO_ROOT, 'artifacts', 'validation', `${timestampUtc()}_grouped_regression`)
    );
    const guiLogPath = getArg(args, 'gui-log', DEFAULT_GUI_LOG);
    const resolvedSourceSet = resolveSourceSet(args);
    const sourceSet = cacheSourceSet(resolvedSourceSet, path.join(evidenceRoot, 'source-cache'));
    const commandsPath = path.join(evidenceRoot, 'commands.txt');
    const commandRecords = [];
    const commandContext = {
        serviceName: 'WinDiagnosticHost',
        sourceDll: sourceSet.dll || null
    };
    const runCommand = createCommandRunner(commandsPath, commandRecords, commandContext);
    const phaseResults = [];
    const phaseFailures = [];

    ensureDir(evidenceRoot);

    let cleanupRunner = null;
    let pendingError = null;
    let serviceName = 'WinDiagnosticHost';

    writeJson(path.join(evidenceRoot, 'session.json'), {
        generatedUtc: new Date().toISOString(),
        evidenceRoot,
        guiLogPath,
        sourceSet
    });

    try {
        const elevation = getElevationState(runCommand);
        writeJson(path.join(evidenceRoot, 'session_elevation.json'), elevation);
        if (elevation.elevated === false) {
            throw new Error('Grouped regression requires an elevated Windows token because install/update/uninstall and GUI automation must execute through the native admin path.');
        }

        cleanupRunner = stageExecutable(
            sourceSet,
            path.join(evidenceRoot, 'stage', 'cleanup runner (grouped)', 'MeshService-2022 cleanup runner (grouped).exe'),
            { includeDb: true, includeMsh: true, includeConf: true }
        );
        serviceName = queryServiceName(runCommand, cleanupRunner.exe);
        commandContext.serviceName = serviceName;

        const phases = [
            {
                name: 'package_preflight',
                action: () => runPackagePreflight(runCommand, sourceSet, path.join(evidenceRoot, 'package_preflight'))
            },
            {
                name: 'js_local_tests',
                action: () => runJsSelfTest(runCommand, sourceSet, path.join(evidenceRoot, 'js_local_tests'))
            },
            {
                name: 'meshcentral_same_size_contracts',
                action: () => runMeshCentralSameSizeContracts(runCommand, path.join(evidenceRoot, 'meshcentral_same_size_contracts'))
            },
            {
                name: 'native_cli',
                action: () => runNativeCliPhase(runCommand, sourceSet, path.join(evidenceRoot, 'native_cli'))
            },
            {
                name: 'gui_lifecycle',
                action: () => runGuiHarnessPhase(runCommand, sourceSet, path.join(evidenceRoot, 'gui_lifecycle'), guiLogPath)
            }
        ];

        for (const phase of phases) {
            const phaseDir = path.join(evidenceRoot, phase.name);
            ensureDir(phaseDir);
            const startedUtc = new Date().toISOString();
            try {
                const artifacts = phase.action();
                phaseResults.push({
                    name: phase.name,
                    passed: true,
                    startedUtc,
                    completedUtc: new Date().toISOString(),
                    artifacts
                });
            } catch (error) {
                const failureText = error instanceof Error ? (error.stack || error.message) : String(error);
                writeText(path.join(phaseDir, 'fatal.txt'), failureText);
                phaseFailures.push(`${phase.name}: ${failureText}`);
                phaseResults.push({
                    name: phase.name,
                    passed: false,
                    startedUtc,
                    completedUtc: new Date().toISOString(),
                    error: failureText
                });
            }
        }

        if (phaseFailures.length > 0) {
            pendingError = new Error(phaseFailures.join('\n\n'));
        }
    } catch (error) {
        if (!pendingError) {
            pendingError = error;
        }
        writeText(path.join(evidenceRoot, 'fatal.txt'), error instanceof Error ? (error.stack || error.message) : String(error));
    } finally {
        if (cleanupRunner) {
            const cleanupDir = path.join(evidenceRoot, 'cleanup');
            ensureDir(cleanupDir);

            const uninstall = runCommand('cleanup-uninstall', cleanupRunner.exe, ['-fulluninstall'], {
                cwd: path.dirname(cleanupRunner.exe),
                timeoutMs: 600000
            });
            writeCommandArtifacts(cleanupDir, 'cleanup-uninstall', uninstall);

            const validate = runCommand('cleanup-validate-uninstall', cleanupRunner.exe, ['-validate-uninstall'], {
                cwd: path.dirname(cleanupRunner.exe),
                timeoutMs: 180000
            });
            writeCommandArtifacts(cleanupDir, 'cleanup-validate-uninstall', validate);

            writeJson(path.join(cleanupDir, 'cleanup.json'), {
                uninstall,
                validate
            });
        }

        const allOk = pendingError == null && phaseResults.every((phase) => phase.passed);
        const summaryLines = [
            `GENERATED_UTC=${new Date().toISOString()}`,
            `ALL_OK=${allOk}`,
            `SOURCE_EXE=${sourceSet.exe}`,
            `SOURCE_DB=${sourceSet.db || '(absent)'}`,
            `SOURCE_MSH=${sourceSet.msh || '(absent)'}`,
            `SOURCE_CONF=${sourceSet.conf || '(absent)'}`,
            `SOURCE_DLL=${sourceSet.dll || '(absent)'}`,
            `SERVICE_NAME=${serviceName}`,
            `GUI_LOG=${guiLogPath}`,
            `COMMANDS=${commandsPath}`
        ];
        for (const phase of phaseResults) {
            summaryLines.push(`PHASE=${phase.name} PASS=${phase.passed}`);
        }
        if (pendingError) {
            summaryLines.push(`FATAL=${pendingError instanceof Error ? trimText(pendingError.stack || pendingError.message) : trimText(String(pendingError))}`);
            summaryLines.push(`FATAL_ARTIFACT=${path.join(evidenceRoot, 'fatal.txt')}`);
        }
        writeText(path.join(evidenceRoot, 'summary.txt'), `${summaryLines.join('\n')}\n`);

        writeJson(path.join(evidenceRoot, 'results.json'), {
            generatedUtc: new Date().toISOString(),
            allOk,
            sourceSet,
            serviceName,
            guiLogPath,
            phaseResults,
            commands: commandRecords,
            fatal: pendingError ? (pendingError.stack || pendingError.message || String(pendingError)) : null
        });
    }

    if (pendingError) {
        throw pendingError;
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
}
