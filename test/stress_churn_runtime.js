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
        conf: args['source-conf'] ? path.resolve(args['source-conf']) : defaultSidecar(exe, '.conf'),
        selfTestScript: args['source-selftest']
            ? path.resolve(args['source-selftest'])
            : (fs.existsSync(path.join(path.dirname(exe), 'agent-selftest.js')) ? path.join(path.dirname(exe), 'agent-selftest.js') : null)
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

function ensureFailure(record, message) {
    if (record.error) { return; }
    if (record.exitCode === 0) {
        throw new Error(`${message}: unexpectedly succeeded`);
    }
}

function parseJson(record) {
    return JSON.parse(record.stdout);
}

function tryParseJson(record) {
    try {
        return JSON.parse(record.stdout);
    } catch {
        return null;
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function parseIntegerArg(args, name, fallback) {
    if (args[name] == null) { return fallback; }
    const value = parseInt(args[name], 10);
    if (!Number.isFinite(value) || value < 0) {
        throw new Error(`Invalid --${name}: ${args[name]}`);
    }
    return value;
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
        installerLog: path.join(installDir, 'logs', 'installer.log')
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

function parseServicePid(stdout) {
    const match = String(stdout || '').match(/PID\s*:\s*(\d+)/i);
    return match ? parseInt(match[1], 10) : 0;
}

function isSuccessfulValidationRecord(record) {
    const payload = tryParseJson(record);
    return {
        payload,
        success: !record.error && record.exitCode === 0 && payload != null && payload.success === true
    };
}

function summarizePhase(phaseDir, lines) {
    writeText(path.join(phaseDir, 'summary.txt'), `${lines.join('\n')}\n`);
}

function tailLines(filePath, maxLines) {
    if (!fs.existsSync(filePath)) { return []; }
    return fs.readFileSync(filePath, 'utf8')
        .split(/\r?\n/)
        .filter((line) => line.length > 0)
        .slice(-maxLines);
}

function runValidation(runCommand, runnerExe, phaseDir, suffix, args, label) {
    const record = runCommand(label, runnerExe, args, {
        cwd: path.dirname(runnerExe),
        timeoutMs: 180000
    });
    writeCommandArtifacts(phaseDir, suffix, record);
    ensureSuccess(record, label);
    const payload = parseJson(record);
    assert(payload.success === true, `${label}: validation payload reported failure`);
    return payload;
}

function runRestartChurn(runCommand, runnerExe, serviceName, phaseDir, restartCount) {
    const samples = [];
    const sampleEvery = restartCount >= 20 ? 10 : 1;

    for (let i = 0; i < restartCount; ++i) {
        let record = null;
        let attemptsUsed = 0;
        let serviceRecovered = false;
        for (let attempt = 1; attempt <= 3; ++attempt) {
            attemptsUsed = attempt;
            record = runCommand(`restart-${i + 1}-attempt-${attempt}`, runnerExe, ['restart'], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 120000
            });
            serviceRecovered = (!record.error && record.exitCode === 0 && waitForServiceState(runCommand, serviceName, 'RUNNING', 30000));
            if (attempt > 1 || record.error || record.exitCode !== 0 || !serviceRecovered) {
                writeCommandArtifacts(phaseDir, `restart-${i + 1}-attempt-${attempt}`, record);
            }
            if (serviceRecovered) {
                break;
            }
            if (attempt < 3) {
                ensureInstalledServiceReady(runCommand, runnerExe, serviceName, phaseDir, `restart-${i + 1}-recovery-${attempt}`);
                sleepMs(1000);
            }
        }
        ensureSuccess(record, `restart cycle ${i + 1}`);
        assert(serviceRecovered, `service did not return to RUNNING after restart cycle ${i + 1}`);
        const cycle = {
            cycle: i + 1,
            exitCode: record.exitCode,
            durationMs: record.durationMs,
            attempts: attemptsUsed
        };
        if ((i + 1) % sampleEvery === 0 || (i + 1) === restartCount) {
            const statusRecord = runCommand(`restart-status-${i + 1}`, runnerExe, ['-svchost-status'], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 180000
            });
            writeCommandArtifacts(phaseDir, `restart-status-${i + 1}`, statusRecord);
            ensureSuccess(statusRecord, `svchost status after restart cycle ${i + 1}`);
            cycle.status = parseJson(statusRecord);
        }
        samples.push(cycle);
    }

    writeJson(path.join(phaseDir, 'restart_cycles.json'), samples);
    summarizePhase(phaseDir, [
        `RESTART_COUNT=${restartCount}`,
        `MAX_DURATION_MS=${Math.max(...samples.map((item) => item.durationMs), 0)}`,
        `MIN_DURATION_MS=${Math.min(...samples.map((item) => item.durationMs), Number.MAX_SAFE_INTEGER)}`,
        `AVG_DURATION_MS=${restartCount === 0 ? 0 : Math.round(samples.reduce((sum, item) => sum + item.durationMs, 0) / restartCount)}`
    ]);
    return samples;
}

function runUpdateChurn(runCommand, runnerExe, updateSourceExe, phaseDir, updateCount) {
    const cycles = [];
    const sampleEvery = updateCount >= 10 ? 5 : 1;

    for (let i = 0; i < updateCount; ++i) {
        let updateRecord = null;
        let validateRecord = null;
        let validatePayload = null;
        let attemptsUsed = 0;
        for (let attempt = 1; attempt <= 3; ++attempt) {
            attemptsUsed = attempt;
            updateRecord = runCommand(`update-${i + 1}-attempt-${attempt}`, runnerExe, ['-fullupdate', `--update-source=${updateSourceExe}`], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 600000
            });
            if (attempt > 1 || updateRecord.error || updateRecord.exitCode !== 0) {
                writeCommandArtifacts(phaseDir, `update-${i + 1}-attempt-${attempt}`, updateRecord);
            }
            if (updateRecord.error || updateRecord.exitCode !== 0) {
                if (attempt < 3) {
                    sleepMs(1000);
                    continue;
                }
                ensureSuccess(updateRecord, `update cycle ${i + 1}`);
            }

            validateRecord = runCommand(`validate-update-${i + 1}-attempt-${attempt}`, runnerExe, ['-validate-update'], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 180000
            });
            if (attempt > 1 || validateRecord.error || validateRecord.exitCode !== 0) {
                writeCommandArtifacts(phaseDir, `validate-update-${i + 1}-attempt-${attempt}`, validateRecord);
            }
            const validation = isSuccessfulValidationRecord(validateRecord);
            validatePayload = validation.payload;
            if (validation.success) {
                break;
            }
            if (attempt < 3) {
                sleepMs(1000);
                continue;
            }
            ensureSuccess(validateRecord, `validate update cycle ${i + 1}`);
            assert(validatePayload && validatePayload.success === true, `validate update cycle ${i + 1}: validation payload reported failure`);
        }

        writeCommandArtifacts(phaseDir, `update-${i + 1}`, updateRecord);
        writeCommandArtifacts(phaseDir, `validate-update-${i + 1}`, validateRecord);

        const cycle = {
            cycle: i + 1,
            updateExitCode: updateRecord.exitCode,
            updateDurationMs: updateRecord.durationMs,
            validateExitCode: validateRecord.exitCode,
            validateDurationMs: validateRecord.durationMs,
            attempts: attemptsUsed
        };
        if ((i + 1) % sampleEvery === 0 || (i + 1) === updateCount) {
            const statusRecord = runCommand(`update-status-${i + 1}`, runnerExe, ['-svchost-status'], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 180000
            });
            writeCommandArtifacts(phaseDir, `update-status-${i + 1}`, statusRecord);
            ensureSuccess(statusRecord, `svchost status after update cycle ${i + 1}`);
            cycle.status = parseJson(statusRecord);
        }
        cycles.push(cycle);
    }

    writeJson(path.join(phaseDir, 'update_cycles.json'), cycles);
    summarizePhase(phaseDir, [
        `UPDATE_COUNT=${updateCount}`,
        `MAX_UPDATE_DURATION_MS=${Math.max(...cycles.map((item) => item.updateDurationMs), 0)}`,
        `AVG_UPDATE_DURATION_MS=${updateCount === 0 ? 0 : Math.round(cycles.reduce((sum, item) => sum + item.updateDurationMs, 0) / updateCount)}`
    ]);
    return cycles;
}

function stageSelfTestScriptIfPresent(sourceScriptPath, installDir) {
    if (!sourceScriptPath || !fs.existsSync(sourceScriptPath)) {
        return null;
    }
    const destinationPath = path.join(installDir, 'agent-selftest.js');
    ensureDir(installDir);
    fs.copyFileSync(sourceScriptPath, destinationPath);
    return destinationPath;
}

function runMajorBugProbe(runCommand, serviceName, installedPaths, selfTestScriptSource, phaseDir, name) {
    assert(waitForServiceState(runCommand, serviceName, 'RUNNING', 120000), `${name}: service was not RUNNING before self-test`);
    const stagedSelfTestScript = stageSelfTestScriptIfPresent(selfTestScriptSource, installedPaths.installDir);
    const args = [
        '--selfTest=1',
        `--serviceName=${serviceName}`,
        '--majorBug=1',
        '--readonly=1',
        '--skipServiceRestart=1',
        '--skipCoreDump=1',
        `--installRoot=${installedPaths.installDir}`,
        `--confPath=${installedPaths.installedConf}`,
        `--mshPath=${installedPaths.installedMsh}`
    ];

    let lastRecord = null;
    for (let attempt = 1; attempt <= 24; ++attempt) {
        const record = runCommand(`${name}-attempt-${attempt}`, installedPaths.installedExe, args, {
            cwd: installedPaths.installDir,
            timeoutMs: 1800000
        });
        writeCommandArtifacts(phaseDir, `${name}-attempt-${attempt}`, record);
        if (!record.error && record.exitCode === 0) {
            writeJson(path.join(phaseDir, `${name}.json`), {
                selfTestBinary: installedPaths.installedExe,
                serviceName,
                stagedSelfTestScript,
                attempts: attempt
            });
            return record;
        }

        lastRecord = record;
        if (attempt < 24 && String(record.stdout || '').includes('CoreModule missing from datastore')) {
            sleepMs(5000);
            continue;
        }
        break;
    }

    ensureSuccess(lastRecord, `${name} major-bug self-test`);
    return lastRecord;
}

function runRollbackFaultInjection(commandRecords, commandsPath, runnerExe, updateSourceExe, installedPaths, phaseDir) {
    const start = Date.now();
    const cwd = path.dirname(runnerExe);
    const commitMarker = '[UPDATE] PendingUpdate marker written prior to commit';
    const baselineInstallerLogSize = fs.existsSync(installedPaths.installerLog) ? fs.statSync(installedPaths.installerLog).size : 0;
    const child = childProcess.spawn(runnerExe, ['-fullupdate', `--update-source=${updateSourceExe}`], {
        cwd,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let deletedAtUtc = null;
    let deleted = false;
    let commitMarkerSeen = false;
    let commitMarkerSeenAtUtc = null;
    let errorText = null;
    let timedOut = false;

    child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.on('error', (error) => { errorText = error.stack || error.message || String(error); });

    const deadline = Date.now() + 90000;
    while (child.exitCode == null && child.signalCode == null && Date.now() <= deadline) {
        if (!commitMarkerSeen && fs.existsSync(installedPaths.installerLog)) {
            const stats = fs.statSync(installedPaths.installerLog);
            const offset = Math.min(baselineInstallerLogSize, stats.size);
            const fd = fs.openSync(installedPaths.installerLog, 'r');
            const buffer = Buffer.alloc(Math.max(stats.size - offset, 0));
            try {
                if (buffer.length > 0) {
                    fs.readSync(fd, buffer, 0, buffer.length, offset);
                }
            } finally {
                fs.closeSync(fd);
            }
            const installerLogDelta = buffer.toString('utf8');
            if (installerLogDelta.includes(commitMarker)) {
                commitMarkerSeen = true;
                commitMarkerSeenAtUtc = new Date().toISOString();
            }
        }
        if (commitMarkerSeen && !deleted && fs.existsSync(installedPaths.installedConf)) {
            try {
                fs.unlinkSync(installedPaths.installedConf);
                deleted = true;
                deletedAtUtc = new Date().toISOString();
            } catch {
                // The updater can be racing the delete; keep polling until the delete lands or the child exits.
            }
        }
        sleepMs(100);
    }

    if (child.exitCode == null && child.signalCode == null) {
        timedOut = true;
        child.kill();
    }

    const record = {
        label: 'rollback-fault-update',
        file: runnerExe,
        args: ['-fullupdate', `--update-source=${updateSourceExe}`],
        cwd,
        startedUtc: new Date(start).toISOString(),
        durationMs: Date.now() - start,
        exitCode: Number.isInteger(child.exitCode) ? child.exitCode : -1,
        signal: child.signalCode || null,
        stdout,
        stderr,
        error: errorText,
        commitMarkerSeen,
        commitMarkerSeenAtUtc,
        deletedLiveConf: deleted,
        deletedLiveConfAtUtc: deletedAtUtc,
        timedOut
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
    writeCommandArtifacts(phaseDir, 'rollback-fault-update', record);
    return record;
}

function cleanupInstall(runCommand, runnerExe, phaseDir, suffix) {
    const attempts = [];

    for (let attempt = 1; attempt <= 3; ++attempt) {
        const uninstall = runCommand(`${suffix}-uninstall-attempt-${attempt}`, runnerExe, ['-fulluninstall'], {
            cwd: path.dirname(runnerExe),
            timeoutMs: 600000
        });
        writeCommandArtifacts(phaseDir, `${suffix}-uninstall-attempt-${attempt}`, uninstall);

        const validate = runCommand(`${suffix}-validate-uninstall-attempt-${attempt}`, runnerExe, ['-validate-uninstall'], {
            cwd: path.dirname(runnerExe),
            timeoutMs: 180000
        });
        writeCommandArtifacts(phaseDir, `${suffix}-validate-uninstall-attempt-${attempt}`, validate);

        const validation = isSuccessfulValidationRecord(validate);
        attempts.push({
            attempt,
            uninstallExitCode: uninstall.exitCode,
            validateExitCode: validate.exitCode,
            validatePayload: validation.payload
        });

        if (validation.success) {
            writeJson(path.join(phaseDir, `${suffix}-cleanup.json`), {
                attempts
            });
            summarizePhase(phaseDir, [
                `ATTEMPTS=${attempt}`,
                `FINAL_VALIDATE_EXIT=${validate.exitCode}`,
                `FINAL_VALIDATE_SUCCESS=true`
            ]);
            return {
                attempts,
                validatePayload: validation.payload
            };
        }

        if (attempt < 3) {
            sleepMs(1000);
            continue;
        }

        throw new Error(
            `${suffix} validate uninstall: exit=${validate.exitCode} stdout=${trimText(validate.stdout)} stderr=${trimText(validate.stderr)}`
        );
    }

    throw new Error(`${suffix} validate uninstall: exceeded bounded retries`);
}

function runInstallAndValidate(runCommand, runnerExe, phaseDir, suffix) {
    const attempts = [];
    let installRecord = null;
    let validateRecord = null;

    for (let installAttempt = 1; installAttempt <= 3; ++installAttempt) {
        installRecord = runCommand(`${suffix}-attempt-${installAttempt}`, runnerExe, ['-fullinstall'], {
            cwd: path.dirname(runnerExe),
            timeoutMs: 600000
        });
        writeCommandArtifacts(phaseDir, `${suffix}-attempt-${installAttempt}`, installRecord);

        for (let validateAttempt = 1; validateAttempt <= 12; ++validateAttempt) {
            validateRecord = runCommand(`${suffix}-validate-attempt-${installAttempt}-${validateAttempt}`, runnerExe, ['-validate-install'], {
                cwd: path.dirname(runnerExe),
                timeoutMs: 180000
            });
            writeCommandArtifacts(phaseDir, `${suffix}-validate-attempt-${installAttempt}-${validateAttempt}`, validateRecord);

            const validation = isSuccessfulValidationRecord(validateRecord);
            attempts.push({
                installAttempt,
                validateAttempt,
                installExitCode: installRecord.exitCode,
                validateExitCode: validateRecord.exitCode,
                validatePayload: validation.payload
            });
            if (validation.success) {
                writeCommandArtifacts(phaseDir, suffix, installRecord);
                writeCommandArtifacts(phaseDir, `${suffix}-validate-install`, validateRecord);
                writeJson(path.join(phaseDir, `${suffix}.json`), { attempts });
                return {
                    attempts,
                    installRecord,
                    validateRecord,
                    validatePayload: validation.payload
                };
            }
            if (validateAttempt < 12) {
                sleepMs(5000);
            }
        }

        if (installAttempt < 3) {
            sleepMs(1000);
        }
    }

    throw new Error(
        `${suffix}: exit=${installRecord ? installRecord.exitCode : -1} stdout=${trimText(installRecord ? installRecord.stdout : '')} stderr=${trimText(installRecord ? installRecord.stderr : '')}`
    );
}

function ensureInstalledServiceReady(runCommand, runnerExe, serviceName, phaseDir, prefix) {
    for (let attempt = 1; attempt <= 2; ++attempt) {
        const statusRecord = runCommand(`${prefix}-svchost-status-attempt-${attempt}`, runnerExe, ['-svchost-status'], {
            cwd: path.dirname(runnerExe),
            timeoutMs: 180000
        });
        writeCommandArtifacts(phaseDir, `${prefix}-svchost-status-attempt-${attempt}`, statusRecord);
        const statusPayload = tryParseJson(statusRecord);
        const ready = !statusRecord.error &&
            statusRecord.exitCode === 0 &&
            statusPayload != null &&
            statusPayload.statusMask === 0 &&
            statusPayload.checks != null &&
            statusPayload.checks.serviceInstalledInScm === true &&
            statusPayload.checks.serviceRunning === true;
        if (ready) {
            return resolveInstalledPathsFromStatus(statusRecord);
        }

        if (attempt < 2) {
            runInstallAndValidate(runCommand, runnerExe, phaseDir, `${prefix}-repair-install`);
            assert(waitForServiceState(runCommand, serviceName, 'RUNNING', 120000), `${prefix}: service did not return to RUNNING after repair`);
        }
    }

    throw new Error(`${prefix}: svchost status did not converge to a healthy installed service state`);
}

function main() {
    const args = parseArgs(process.argv);
    const restartCount = parseIntegerArg(args, 'restart-count', 200);
    const updateCount = parseIntegerArg(args, 'update-count', 50);
    const evidenceRoot = args.evidence
        ? path.resolve(args.evidence)
        : path.join(REPO_ROOT, 'docs', 'testing', 'evidence', 'advanced', `${timestampUtc()}_stress_churn`);
    const commandsPath = path.join(evidenceRoot, 'commands.jsonl');
    const commandRecords = [];
    const runCommand = createCommandRunner(commandsPath, commandRecords);
    const sourceSet = resolveSourceSet(args);
    const runner = stageExecutable(
        sourceSet,
        path.join(evidenceRoot, 'runner', 'MeshService-2022 stress runner.exe'),
        { includeDb: true, includeMsh: true, includeConf: true }
    );
    const updateSource = stageExecutable(
        sourceSet,
        path.join(evidenceRoot, 'update-source', 'MeshService-2022 stress update-source.exe'),
        { includeDb: true, includeMsh: true, includeConf: false }
    );
    const phaseResults = [];
    let serviceName = '';
    let installedPaths = null;
    let pendingError = null;

    ensureDir(evidenceRoot);
    writeJson(path.join(evidenceRoot, 'session.json'), {
        generatedUtc: new Date().toISOString(),
        evidenceRoot,
        restartCount,
        updateCount,
        runner,
        updateSource
    });

    try {
        serviceName = queryServiceName(runCommand, runner.exe);

        const cleanupBeforeDir = path.join(evidenceRoot, 'cleanup-before');
        ensureDir(cleanupBeforeDir);
        cleanupInstall(runCommand, runner.exe, cleanupBeforeDir, 'cleanup-before');

        const installDir = path.join(evidenceRoot, 'install');
        ensureDir(installDir);
        runInstallAndValidate(runCommand, runner.exe, installDir, 'initial-install');
        installedPaths = ensureInstalledServiceReady(runCommand, runner.exe, serviceName, installDir, 'initial-install');
        writeJson(path.join(installDir, 'installed_paths.json'), installedPaths);
        summarizePhase(installDir, [
            `SERVICE_NAME=${serviceName}`,
            `INSTALLED_EXE=${installedPaths.installedExe}`,
            `INSTALLED_DLL=${installedPaths.installedDll}`,
            `INSTALLED_CONF=${installedPaths.installedConf}`
        ]);
        phaseResults.push({ name: 'install', passed: true });

        const baselineMajorBugDir = path.join(evidenceRoot, 'majorbug-baseline');
        ensureDir(baselineMajorBugDir);
        runMajorBugProbe(runCommand, serviceName, installedPaths, sourceSet.selfTestScript, baselineMajorBugDir, 'majorbug-baseline');
        installedPaths = ensureInstalledServiceReady(runCommand, runner.exe, serviceName, baselineMajorBugDir, 'majorbug-baseline');
        summarizePhase(baselineMajorBugDir, [
            `SERVICE_NAME=${serviceName}`,
            'RESULT=PASS'
        ]);
        phaseResults.push({ name: 'majorbug-baseline', passed: true });

        const restartDir = path.join(evidenceRoot, 'restart-churn');
        ensureDir(restartDir);
        const restartCycles = runRestartChurn(runCommand, runner.exe, serviceName, restartDir, restartCount);
        phaseResults.push({ name: 'restart-churn', passed: true, cycles: restartCycles.length });

        const postRestartMajorBugDir = path.join(evidenceRoot, 'majorbug-post-restart');
        ensureDir(postRestartMajorBugDir);
        runMajorBugProbe(runCommand, serviceName, installedPaths, sourceSet.selfTestScript, postRestartMajorBugDir, 'majorbug-post-restart');
        installedPaths = ensureInstalledServiceReady(runCommand, runner.exe, serviceName, postRestartMajorBugDir, 'majorbug-post-restart');
        summarizePhase(postRestartMajorBugDir, [
            `SERVICE_NAME=${serviceName}`,
            'RESULT=PASS'
        ]);
        phaseResults.push({ name: 'majorbug-post-restart', passed: true });

        const updateDir = path.join(evidenceRoot, 'update-churn');
        ensureDir(updateDir);
        const updateCycles = runUpdateChurn(runCommand, runner.exe, updateSource.exe, updateDir, updateCount);
        phaseResults.push({ name: 'update-churn', passed: true, cycles: updateCycles.length });

        const postUpdateMajorBugDir = path.join(evidenceRoot, 'majorbug-post-update');
        ensureDir(postUpdateMajorBugDir);
        runMajorBugProbe(runCommand, serviceName, installedPaths, sourceSet.selfTestScript, postUpdateMajorBugDir, 'majorbug-post-update');
        installedPaths = ensureInstalledServiceReady(runCommand, runner.exe, serviceName, postUpdateMajorBugDir, 'majorbug-post-update');
        summarizePhase(postUpdateMajorBugDir, [
            `SERVICE_NAME=${serviceName}`,
            'RESULT=PASS'
        ]);
        phaseResults.push({ name: 'majorbug-post-update', passed: true });

        const statusBeforeRollback = runCommand('rollback-pre-status', runner.exe, ['-svchost-status'], {
            cwd: path.dirname(runner.exe),
            timeoutMs: 180000
        });
        ensureSuccess(statusBeforeRollback, 'rollback pre-status');
        installedPaths = resolveInstalledPathsFromStatus(statusBeforeRollback);

        const rollbackDir = path.join(evidenceRoot, 'rollback-safety');
        ensureDir(rollbackDir);
        const rollbackUpdate = runRollbackFaultInjection(commandRecords, commandsPath, runner.exe, updateSource.exe, installedPaths, rollbackDir);
        assert(rollbackUpdate.commitMarkerSeen === true, 'rollback fault injection did not observe the update commit marker');
        assert(rollbackUpdate.deletedLiveConf === true, 'rollback fault injection did not delete the live conf after commit');
        ensureFailure(rollbackUpdate, 'rollback fault-injection update');
        const rollbackValidate = runCommand('rollback-validate-update', runner.exe, ['-validate-update'], {
            cwd: path.dirname(runner.exe),
            timeoutMs: 180000
        });
        writeCommandArtifacts(rollbackDir, 'rollback-validate-update', rollbackValidate);
        ensureSuccess(rollbackValidate, 'rollback validate update');
        const rollbackValidatePayload = parseJson(rollbackValidate);
        assert(rollbackValidatePayload.success === true, 'rollback validate update reported failure');
        const rollbackStatus = runCommand('rollback-svchost-status', runner.exe, ['-svchost-status'], {
            cwd: path.dirname(runner.exe),
            timeoutMs: 180000
        });
        writeCommandArtifacts(rollbackDir, 'rollback-svchost-status', rollbackStatus);
        ensureSuccess(rollbackStatus, 'rollback svchost status');
        const rollbackLogTail = tailLines(installedPaths.installerLog, 400);
        writeText(path.join(rollbackDir, 'installer-log-tail.txt'), `${rollbackLogTail.join('\n')}\n`);
        const rollbackLogText = fs.existsSync(installedPaths.installerLog) ? fs.readFileSync(installedPaths.installerLog, 'utf8') : '';
        const rollbackAttemptLogged = rollbackLogText.includes('[UPDATE] Attempting rollback');
        const rollbackCompletedLogged = rollbackLogText.includes('[UPDATE] Rollback completed');
        writeText(path.join(rollbackDir, 'installer-log-search.txt'), [
            `ROLLBACK_ATTEMPT_LOGGED=${rollbackAttemptLogged}`,
            `ROLLBACK_COMPLETED_LOGGED=${rollbackCompletedLogged}`,
            `LOG_PATH=${installedPaths.installerLog}`
        ].join('\n') + '\n');
        summarizePhase(rollbackDir, [
            `UPDATE_EXIT=${rollbackUpdate.exitCode}`,
            `COMMIT_MARKER_SEEN=${rollbackUpdate.commitMarkerSeen}`,
            `COMMIT_MARKER_SEEN_AT_UTC=${rollbackUpdate.commitMarkerSeenAtUtc || '(missing)'}`,
            `LIVE_CONF_DELETED=${rollbackUpdate.deletedLiveConf}`,
            `LIVE_CONF_DELETED_AT_UTC=${rollbackUpdate.deletedLiveConfAtUtc || '(missing)'}`,
            `UPDATE_TIMED_OUT=${rollbackUpdate.timedOut}`,
            `ROLLBACK_ATTEMPT_LOGGED=${rollbackAttemptLogged}`,
            `ROLLBACK_COMPLETED_LOGGED=${rollbackCompletedLogged}`,
            `VALIDATE_EXIT=${rollbackValidate.exitCode}`
        ]);
        phaseResults.push({ name: 'rollback-safety', passed: true });

        const finalCleanupDir = path.join(evidenceRoot, 'cleanup-after');
        ensureDir(finalCleanupDir);
        cleanupInstall(runCommand, runner.exe, finalCleanupDir, 'cleanup-after');
        phaseResults.push({ name: 'cleanup-after', passed: true });

        writeJson(path.join(evidenceRoot, 'results.json'), {
            generatedUtc: new Date().toISOString(),
            serviceName,
            restartCount,
            updateCount,
            runner,
            updateSource,
            phases: phaseResults,
            success: true
        });
        writeText(path.join(evidenceRoot, 'summary.txt'), [
            `GENERATED_UTC=${new Date().toISOString()}`,
            'SUCCESS=true',
            `SERVICE_NAME=${serviceName}`,
            `RESTART_COUNT=${restartCount}`,
            `UPDATE_COUNT=${updateCount}`,
            `RUNNER=${runner.exe}`,
            `UPDATE_SOURCE=${updateSource.exe}`,
            `RUNNER_SHA256=${runner.sha256}`,
            `UPDATE_SOURCE_SHA256=${updateSource.sha256}`,
            `ROLLBACK_LOG=${path.join(evidenceRoot, 'rollback-safety', 'installer-log-tail.txt')}`,
            `PHASES=${phaseResults.map((phase) => `${phase.name}:${phase.passed ? 'PASS' : 'FAIL'}`).join(',')}`
        ].join('\n') + '\n');
    } catch (error) {
        pendingError = error instanceof Error ? error : new Error(String(error));
        writeText(path.join(evidenceRoot, 'fatal.txt'), pendingError.stack || pendingError.message);
        writeJson(path.join(evidenceRoot, 'results.json'), {
            generatedUtc: new Date().toISOString(),
            serviceName,
            restartCount,
            updateCount,
            runner,
            updateSource,
            phases: phaseResults,
            success: false,
            fatal: pendingError.stack || pendingError.message
        });
        writeText(path.join(evidenceRoot, 'summary.txt'), [
            `GENERATED_UTC=${new Date().toISOString()}`,
            'SUCCESS=false',
            `SERVICE_NAME=${serviceName || '(unknown)'}`,
            `RESTART_COUNT=${restartCount}`,
            `UPDATE_COUNT=${updateCount}`,
            `FATAL=${trimText(pendingError.stack || pendingError.message)}`,
            `FATAL_ARTIFACT=${path.join(evidenceRoot, 'fatal.txt')}`
        ].join('\n') + '\n');
    } finally {
        try {
            const cleanupDir = path.join(evidenceRoot, 'cleanup-finally');
            ensureDir(cleanupDir);
            cleanupInstall(runCommand, runner.exe, cleanupDir, 'cleanup-finally');
        } catch (cleanupError) {
            writeText(
                path.join(evidenceRoot, 'cleanup-finally', 'fatal.txt'),
                cleanupError instanceof Error ? (cleanupError.stack || cleanupError.message) : String(cleanupError)
            );
        }
    }

    if (pendingError) {
        throw pendingError;
    }
}

main();
