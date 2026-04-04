const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_SOURCE_EXE = path.join(REPO_ROOT, 'meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');

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
    const exe = args['source-exe'] ? path.resolve(args['source-exe']) : DEFAULT_SOURCE_EXE;
    ensureFile(exe, 'source exe');
    return {
        exe,
        db: args['source-db'] ? path.resolve(args['source-db']) : defaultSidecar(exe, '.db'),
        msh: args['source-msh'] ? path.resolve(args['source-msh']) : defaultSidecar(exe, '.msh'),
        conf: args['source-conf'] ? path.resolve(args['source-conf']) : defaultSidecar(exe, '.conf')
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

    ensureDir(path.dirname(destinationExe));
    fs.copyFileSync(sourceSet.exe, destinationExe);
    return {
        exe: destinationExe,
        db: includeDb ? copyIfPresent(sourceSet.db, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.db`)) : null,
        msh: includeMsh ? copyIfPresent(sourceSet.msh, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.msh`)) : null,
        conf: includeConf ? copyIfPresent(sourceSet.conf, path.join(path.dirname(destinationExe), `${path.basename(destinationExe, path.extname(destinationExe))}.conf`)) : null,
        sha256: hashFile(destinationExe)
    };
}

function sleepMs(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function trimText(value) {
    const text = String(value || '').replace(/\r/g, ' ').replace(/\n/g, ' ').trim();
    if (!text) { return '(empty)'; }
    return text.length <= 600 ? text : `${text.substring(0, 600)}...`;
}

function createCommandRunner(commandsPath, commandRecords) {
    return function runCommand(label, file, args, options = {}) {
        const start = Date.now();
        const cwd = options.cwd || REPO_ROOT;
        const result = childProcess.spawnSync(file, args, {
            cwd,
            encoding: 'utf8',
            timeout: options.timeoutMs || 120000,
            windowsHide: true
        });
        const record = {
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
        commandRecords.push(record);
        fs.appendFileSync(commandsPath, JSON.stringify({
            label: record.label,
            file: record.file,
            args: record.args,
            cwd: record.cwd,
            exitCode: record.exitCode,
            durationMs: record.durationMs,
            startedUtc: record.startedUtc
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

function parseJson(record) {
    return JSON.parse(record.stdout);
}

function queryServiceName(runCommand, runnerExe) {
    const record = runCommand('query-service-name', runnerExe, ['-name'], {
        cwd: path.dirname(runnerExe),
        timeoutMs: 60000
    });
    ensureSuccess(record, 'query service name');
    return record.stdout.trim() || 'WinDiagnosticHost';
}

function resolveInstalledPathsFromStatus(statusRecord) {
    const payload = parseJson(statusRecord);
    const values = payload.values || {};
    const serviceDll = values.expectedServiceDll || values.serviceDllExpanded || '';
    if (!serviceDll) {
        throw new Error('svchost status did not provide service DLL path');
    }

    const installDir = path.dirname(serviceDll);
    const preferredExe = path.join(installDir, 'diaghost.exe');
    let installedExe = preferredExe;
    if (!fs.existsSync(installedExe)) {
        const candidates = fs.readdirSync(installDir, { withFileTypes: true })
            .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.exe'))
            .map((entry) => entry.name)
            .filter((name) => name.toLowerCase() !== 'svchost.exe' && name.toLowerCase() !== 'masterservice.exe')
            .sort((left, right) => left.localeCompare(right, 'en', { sensitivity: 'base' }));
        if (candidates.length !== 1) {
            throw new Error(`Unable to resolve installed agent executable in ${installDir}`);
        }
        installedExe = path.join(installDir, candidates[0]);
    }

    return {
        installDir,
        installedExe,
        installedDll: serviceDll,
        installedConf: path.join(installDir, `${path.basename(installedExe, path.extname(installedExe))}.conf`),
        installedMsh: path.join(installDir, `${path.basename(installedExe, path.extname(installedExe))}.msh`),
        stageDir: path.join(installDir, 'state', 'update-stage'),
        backupDir: path.join(installDir, 'state', 'update-backup')
    };
}

function parseServiceState(stdout) {
    const match = String(stdout || '').match(/STATE\s*:\s*\d+\s+([A-Z_]+)/i);
    return match ? match[1].toUpperCase() : '';
}

function waitForServiceState(runCommand, serviceName, expectedState, timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    let lastState = '';
    while (Date.now() <= deadline) {
        const record = runCommand(`service-state-${expectedState.toLowerCase()}`, 'sc', ['query', serviceName], {
            timeoutMs: 30000
        });
        lastState = parseServiceState(record.stdout);
        if (record.exitCode !== 0 && expectedState === 'ABSENT') {
            return true;
        }
        if (lastState === expectedState) {
            return true;
        }
        sleepMs(500);
    }
    return false;
}

function stopService(runCommand, serviceName) {
    const record = runCommand('service-stop', 'sc', ['stop', serviceName], { timeoutMs: 30000 });
    if (record.exitCode !== 0 && !/service has not been started/i.test(record.stdout) && !/does not exist/i.test(record.stdout + record.stderr)) {
        throw new Error(`stop service failed: ${trimText(record.stdout)} ${trimText(record.stderr)}`);
    }
    waitForServiceState(runCommand, serviceName, 'STOPPED', 30000);
}

function killPid(pid) {
    if (!pid || pid <= 0) { return; }
    childProcess.spawnSync('taskkill', ['/PID', String(pid), '/F', '/T'], {
        windowsHide: true,
        encoding: 'utf8'
    });
}

function removeFileIfPresent(filePath) {
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }
}

function ensurePartialArtifacts(installedPaths, scenarioDir) {
    removeFileIfPresent(installedPaths.installedConf);
    removeFileIfPresent(installedPaths.installedMsh);

    ensureDir(installedPaths.stageDir);
    ensureDir(installedPaths.backupDir);
    writeText(path.join(installedPaths.stageDir, 'stale-stage.txt'), `stale-stage ${new Date().toISOString()}\n`);
    writeText(path.join(installedPaths.backupDir, 'stale-backup.txt'), `stale-backup ${new Date().toISOString()}\n`);
    writeText(path.join(scenarioDir, 'mutation.txt'), [
        `CONF_REMOVED=${!fs.existsSync(installedPaths.installedConf)}`,
        `MSH_REMOVED=${!fs.existsSync(installedPaths.installedMsh)}`,
        `STAGE_DIR=${installedPaths.stageDir}`,
        `BACKUP_DIR=${installedPaths.backupDir}`
    ].join('\n') + '\n');
}

function corruptServiceDll(runCommand, serviceName) {
    const key = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${serviceName}\\Parameters`;
    const bogusPath = 'C:\\Broken\\missing-diagsvc.dll';
    const record = runCommand('corrupt-service-dll', 'reg', ['add', key, '/v', 'ServiceDll', '/t', 'REG_EXPAND_SZ', '/d', bogusPath, '/f'], {
        timeoutMs: 30000
    });
    ensureSuccess(record, 'corrupt service dll');
    return bogusPath;
}

function spawnStrayLockProcess(installedExe) {
    const child = childProcess.spawn(installedExe, ['run'], {
        cwd: path.dirname(installedExe),
        detached: true,
        stdio: 'ignore',
        windowsHide: true
    });
    child.unref();
    sleepMs(1500);
    return child.pid;
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function mutatePartialState(runCommand, serviceName, installedPaths, scenarioDir) {
    stopService(runCommand, serviceName);
    const strayPid = spawnStrayLockProcess(installedPaths.installedExe);
    const bogusServiceDll = corruptServiceDll(runCommand, serviceName);
    ensurePartialArtifacts(installedPaths, scenarioDir);
    writeJson(path.join(scenarioDir, 'partial_state.json'), {
        generatedUtc: new Date().toISOString(),
        serviceName,
        bogusServiceDll,
        strayPid,
        installedPaths
    });
    return { strayPid, bogusServiceDll };
}

function validateRecoveredState(validationRecord, installedPaths, label) {
    ensureSuccess(validationRecord, label);
    const summary = parseJson(validationRecord);
    assert(summary.success === true, `${label}: validation payload reported failure`);
    assert(fs.existsSync(installedPaths.installedConf), `${label}: conf sidecar was not restored`);
    assert(fs.existsSync(installedPaths.installedMsh), `${label}: msh sidecar was not restored`);
    assert(!fs.existsSync(path.join(installedPaths.stageDir, 'stale-stage.txt')), `${label}: stale update-stage artifact was not removed`);
    assert(!fs.existsSync(path.join(installedPaths.backupDir, 'stale-backup.txt')), `${label}: stale update-backup artifact was not removed`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceRoot = args.evidence
        ? path.resolve(args.evidence)
        : path.join(REPO_ROOT, 'tmp', `partial-state-${timestampUtc()}`);
    const commandsPath = path.join(evidenceRoot, 'commands.jsonl');
    const commandRecords = [];
    const runCommand = createCommandRunner(commandsPath, commandRecords);
    const sourceSet = resolveSourceSet(args);
    const runner = stageExecutable(
        sourceSet,
        path.join(evidenceRoot, 'runner', 'MeshService-2022 partial-state runner.exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );
    const updateSource = stageExecutable(
        sourceSet,
        path.join(evidenceRoot, 'update-source', 'MeshService-2022 update-source.exe'),
        { includeDb: true, includeMsh: true, includeConf: false }
    );

    const summary = {
        generatedUtc: new Date().toISOString(),
        runner,
        updateSource,
        serviceName: queryServiceName(runCommand, runner.exe)
    };

    const cleanupBefore = runCommand('cleanup-before', runner.exe, ['-fulluninstall'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(evidenceRoot, 'cleanup-before', cleanupBefore);

    const validateBefore = runCommand('validate-before', runner.exe, ['-validate-uninstall'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'validate-before', validateBefore);
    ensureSuccess(validateBefore, 'validate uninstall before partial-state lifecycle');

    const install = runCommand('initial-install', runner.exe, ['-fullinstall'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(evidenceRoot, 'initial-install', install);
    ensureSuccess(install, 'initial fullinstall');

    const validateInstall = runCommand('initial-validate-install', runner.exe, ['-validate-install'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'initial-validate-install', validateInstall);
    ensureSuccess(validateInstall, 'initial validate-install');

    const initialStatus = runCommand('initial-svchost-status', runner.exe, ['-svchost-status'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'initial-svchost-status', initialStatus);
    ensureSuccess(initialStatus, 'initial svchost status');

    let installedPaths = resolveInstalledPathsFromStatus(initialStatus);
    summary.initialInstalledPaths = installedPaths;

    const updateMutationDir = path.join(evidenceRoot, 'update-partial-state');
    ensureDir(updateMutationDir);
    const updateMutation = mutatePartialState(runCommand, summary.serviceName, installedPaths, updateMutationDir);
    summary.updateMutation = updateMutation;

    try {
        const fullUpdate = runCommand('partial-state-update', runner.exe, ['-fullupdate', `--update-source=${updateSource.exe}`], {
            cwd: path.dirname(runner.exe),
            timeoutMs: 600000
        });
        writeCommandArtifacts(evidenceRoot, 'partial-state-update', fullUpdate);
        ensureSuccess(fullUpdate, 'update over partial state');
    } finally {
        killPid(updateMutation.strayPid);
    }

    const validateUpdate = runCommand('validate-update', runner.exe, ['-validate-update'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'validate-update', validateUpdate);
    validateRecoveredState(validateUpdate, installedPaths, 'validate-update');

    const updateStatus = runCommand('post-update-svchost-status', runner.exe, ['-svchost-status'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'post-update-svchost-status', updateStatus);
    ensureSuccess(updateStatus, 'post-update svchost status');
    installedPaths = resolveInstalledPathsFromStatus(updateStatus);
    summary.postUpdateInstalledPaths = installedPaths;

    const repairMutationDir = path.join(evidenceRoot, 'repair-partial-state');
    ensureDir(repairMutationDir);
    const repairMutation = mutatePartialState(runCommand, summary.serviceName, installedPaths, repairMutationDir);
    summary.repairMutation = repairMutation;

    try {
        const repairInstall = runCommand('partial-state-repair-install', runner.exe, ['-fullinstall'], {
            cwd: path.dirname(runner.exe),
            timeoutMs: 600000
        });
        writeCommandArtifacts(evidenceRoot, 'partial-state-repair-install', repairInstall);
        ensureSuccess(repairInstall, 'repair install over partial state');
    } finally {
        killPid(repairMutation.strayPid);
    }

    const validateRepair = runCommand('validate-repair-install', runner.exe, ['-validate-install'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'validate-repair-install', validateRepair);
    validateRecoveredState(validateRepair, installedPaths, 'validate-repair-install');

    const cleanupAfter = runCommand('cleanup-after', runner.exe, ['-fulluninstall'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 600000
    });
    writeCommandArtifacts(evidenceRoot, 'cleanup-after', cleanupAfter);
    ensureSuccess(cleanupAfter, 'cleanup uninstall after partial-state lifecycle');

    const validateAfter = runCommand('validate-after', runner.exe, ['-validate-uninstall'], {
        cwd: path.dirname(runner.exe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(evidenceRoot, 'validate-after', validateAfter);
    ensureSuccess(validateAfter, 'validate uninstall after partial-state lifecycle');

    summary.success = true;
    writeJson(path.join(evidenceRoot, 'partial_state_lifecycle_runtime.json'), summary);
    writeText(path.join(evidenceRoot, 'summary.txt'), [
        `GENERATED_UTC=${summary.generatedUtc}`,
        'SUCCESS=true',
        `SERVICE_NAME=${summary.serviceName}`,
        `RUNNER=${runner.exe}`,
        `UPDATE_SOURCE=${updateSource.exe}`,
        `RUNNER_SHA256=${runner.sha256}`,
        `UPDATE_SOURCE_SHA256=${updateSource.sha256}`,
        `INSTALLED_EXE=${installedPaths.installedExe}`,
        `INSTALLED_DLL=${installedPaths.installedDll}`
    ].join('\n') + '\n');

    if (!args.evidence) {
        process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
    }
}

main();
