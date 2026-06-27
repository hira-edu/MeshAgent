const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

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
    if (!condition) {
        throw new Error(message);
    }
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function runCommand(file, args) {
    const result = childProcess.spawnSync(file, args, {
        windowsHide: true,
        encoding: 'utf8'
    });
    if (result.error) {
        throw result.error;
    }
    return result;
}

function formatTaskTime(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

async function waitForReadableFile(filePath, timeoutMs) {
    const start = Date.now();
    while ((Date.now() - start) < timeoutMs) {
        if (fs.existsSync(filePath)) {
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                if (content.trim().length > 0) {
                    return content;
                }
            } catch (error) {
                const message = String(error && error.message ? error.message : error);
                if (!(/being used by another process/i.test(message) || /resource busy or locked/i.test(message) || /EBUSY/i.test(message))) {
                    throw error;
                }
            }
        }
        await sleep(500);
    }
    throw new Error(`Timed out waiting for probe report: ${filePath}`);
}

async function runSystemProbe(exePath, mode) {
    const taskName = `MeshAgentKvmSessionProbe_${mode}_${process.pid}_${Date.now()}`;
    const reportPath = path.join(os.tmpdir(), `${taskName}.json`);
    const scheduleTime = formatTaskTime(new Date(Date.now() + 60000));
    const modeArgs = mode === 'auto' ? ' --auto-selected-tsid' : '';
    const commandLine = `"${exePath}" -kvm-bridge-session-change-probe-child "${reportPath}"${modeArgs}`;
    const create = runCommand('schtasks', [
        '/Create',
        '/TN', taskName,
        '/RU', 'SYSTEM',
        '/SC', 'ONCE',
        '/ST', scheduleTime,
        '/TR', commandLine,
        '/F'
    ]);
    if (create.status !== 0) {
        throw new Error(`Failed to create scheduled task\nstdout:\n${create.stdout}\nstderr:\n${create.stderr}`);
    }

    try {
        const run = runCommand('schtasks', ['/Run', '/TN', taskName]);
        if (run.status !== 0) {
            throw new Error(`Failed to run scheduled task\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`);
        }
        const reportContent = await waitForReadableFile(reportPath, 90000);
        return {
            taskName,
            reportPath,
            commandLine,
            create,
            run,
            reportContent
        };
    } finally {
        runCommand('schtasks', ['/Delete', '/TN', taskName, '/F']);
    }
}

function validateProbeJson(json, expectedAutoSelected) {
    const label = expectedAutoSelected ? 'auto-selected' : 'explicit';

    assert(json.success === true, `${label} session-change probe reported failure`);
    assert(json.autoSelectedTsid === expectedAutoSelected, `${label} probe reported unexpected TSID mode`);
    assert(json.relayStarted === true, `${label} relay did not start`);
    assert(json.initialSnapshotRead === true, `${label} relay snapshot was not available`);
    assert(json.initialProcessTSIDExplicit === !expectedAutoSelected, `${label} relay recorded wrong TSID contract`);
    if (expectedAutoSelected) {
        assert(json.unrelatedStartIgnored === true, 'auto-selected relay did not ignore invalid unrelated start event');
        assert(json.unrelatedStartChildPresent === true, 'auto-selected relay helper was not still present after invalid unrelated start');
        assert(json.unrelatedStartSessionUnchanged === true, 'auto-selected relay rebound to invalid unrelated start session');
        assert(json.unrelatedStartRestartSuppressed === false, 'auto-selected relay suppressed restart after unrelated start');
        assert(json.unrelatedStartPendingRestart === false, 'auto-selected relay recorded unrelated start as pending restart');
        assert(json.unrelatedStopIgnored === true, 'auto-selected relay did not ignore unrelated stop event');
        assert(json.unrelatedStopChildPresent === true, 'auto-selected relay helper was not still present after unrelated stop');
        assert(json.unrelatedStopRestartSuppressed === false, 'auto-selected relay suppressed restart after unrelated stop');
        assert(json.unrelatedStopPendingRestart === false, 'auto-selected relay recorded unrelated stop as pending restart');
        assert(json.validRebindOldSessionId > 0 && json.validRebindOldSessionId !== json.sessionId, 'auto-selected relay did not use a distinct old session for rebind proof');
        assert(json.validRebindForced === true, 'auto-selected relay could not seed old-session state for rebind proof');
        assert(json.validRebindStopped === true, 'auto-selected relay did not stop the old-session helper');
        assert(json.validRebindStopMs <= 2000, `auto-selected rebind stop exceeded 2000ms (${json.validRebindStopMs}ms)`);
        assert(json.validRebindRespawned === true, 'auto-selected relay did not respawn for the token-valid new session');
        assert(json.validRebindRespawnMs <= 2000, `auto-selected rebind respawn exceeded 2000ms (${json.validRebindRespawnMs}ms)`);
        assert(json.validRebindPid > 0 && json.validRebindPid !== json.initialPid, `auto-selected rebind pid was not a new helper (${json.validRebindPid})`);
        assert(json.validRebindSnapshotRead === true, 'auto-selected relay snapshot was unavailable after valid rebind');
        assert(json.validRebindSessionUpdated === true, 'auto-selected relay did not update to the token-valid new session');
        assert(json.validRebindProcessSessionId === json.sessionId, `auto-selected relay process session is ${json.validRebindProcessSessionId}, expected ${json.sessionId}`);
        assert(json.validRebindChildPresent === true, 'auto-selected relay did not record a helper after valid rebind');
        assert(json.validRebindRestartSuppressed === false, 'auto-selected relay remained restart-suppressed after valid rebind');
        assert(json.validRebindPendingRestart === false, 'auto-selected relay left a pending restart after valid rebind');
        assert(json.validRebindTransportActive === true, 'auto-selected relay transport was inactive after valid rebind');
        assert(json.validRebindBridgeUsed === true, 'auto-selected relay did not use the bridge path after valid rebind');
        assert(json.validRebindFallbackUsed === false, 'auto-selected relay used legacy fallback after valid rebind');
        assert(json.validRebindLaunchAttemptCount === 1, `auto-selected valid rebind needed fallback attempts (${json.validRebindLaunchAttemptCount})`);
        assert(json.validRebindSuccessfulSpawnType === 2, `auto-selected valid rebind used unexpected spawn type ${json.validRebindSuccessfulSpawnType}`);
        assert(json.validRebindSuccessfulSpawnAttemptOrdinal === 1, `auto-selected valid rebind succeeded on attempt ${json.validRebindSuccessfulSpawnAttemptOrdinal}`);
    }
    assert(json.initialBridgeAvailable === true, `${label} bridge DLL path was not resolved`);
    assert(json.initialBridgeUsed === true, `${label} rundll32 bridge path was not used`);
    assert(json.initialFallbackUsed === false, `${label} legacy fallback was used unexpectedly`);
    assert(json.initialLaunchAttemptCount === 1, `${label} initial bridge needed fallback attempts (${json.initialLaunchAttemptCount})`);
    assert(json.initialSuccessfulSpawnType === 2, `${label} initial bridge used unexpected spawn type ${json.initialSuccessfulSpawnType}`);
    assert(json.initialSuccessfulSpawnAttemptOrdinal === 1, `${label} initial bridge succeeded on attempt ${json.initialSuccessfulSpawnAttemptOrdinal}`);
    assert(json.initialTransportActive === true, `${label} bridge transport never became active`);
    assert(json.lockStopped === true, `${label} lock event did not stop the helper`);
    assert(json.lockStopMs <= 2000, `${label} lock stop exceeded 2000ms (${json.lockStopMs}ms)`);
    assert(json.helperAbsentDuringLock === true, `${label} helper remained present during lock`);
    assert(json.unlockRespawned === true, `${label} unlock event did not respawn the helper`);
    assert(json.unlockRespawnMs <= 2000, `${label} unlock respawn exceeded 2000ms (${json.unlockRespawnMs}ms)`);
    assert(json.postUnlockBridgeUsed === true, `${label} bridge path was not restored after unlock`);
    assert(json.postUnlockFallbackUsed === false, `${label} unlock restarted on legacy fallback unexpectedly`);
    assert(json.postUnlockLaunchAttemptCount === 1, `${label} unlock restart needed fallback attempts (${json.postUnlockLaunchAttemptCount})`);
    assert(json.postUnlockSuccessfulSpawnType === 2, `${label} unlock restart used unexpected spawn type ${json.postUnlockSuccessfulSpawnType}`);
    assert(json.postUnlockSuccessfulSpawnAttemptOrdinal === 1, `${label} unlock restart succeeded on attempt ${json.postUnlockSuccessfulSpawnAttemptOrdinal}`);
    assert(json.disconnectStopped === true, `${label} console disconnect did not stop the helper`);
    assert(json.disconnectStopMs <= 2000, `${label} console disconnect stop exceeded 2000ms (${json.disconnectStopMs}ms)`);
    assert(json.helperAbsentDuringDisconnect === true, `${label} helper remained present during disconnect`);
    assert(json.reconnectRespawned === true, `${label} console connect did not respawn the helper`);
    assert(json.reconnectRespawnMs <= 2000, `${label} console connect respawn exceeded 2000ms (${json.reconnectRespawnMs}ms)`);
    assert(json.reconnectLaunchAttemptCount === 1, `${label} reconnect restart needed fallback attempts (${json.reconnectLaunchAttemptCount})`);
    assert(json.reconnectSuccessfulSpawnType === 2, `${label} reconnect restart used unexpected spawn type ${json.reconnectSuccessfulSpawnType}`);
    assert(json.reconnectSuccessfulSpawnAttemptOrdinal === 1, `${label} reconnect restart succeeded on attempt ${json.reconnectSuccessfulSpawnAttemptOrdinal}`);
    assert(json.cleanupExited === true, `${label} cleanup did not stop the final helper`);
    assert(json.cleanupExitMs <= 5000, `${label} cleanup exit exceeded 5000ms (${json.cleanupExitMs}ms)`);
    assert(json.initialPid > 0, `${label} invalid initial pid ${json.initialPid}`);
    assert(json.unlockPid > 0 && json.unlockPid !== json.initialPid, `${label} unlock pid was not a new helper (${json.unlockPid})`);
    assert(json.reconnectPid > 0 && json.reconnectPid !== json.unlockPid, `${label} reconnect pid was not a new helper (${json.reconnectPid})`);
    assert((json.screenPackets + json.displayListPackets + json.displayInfoPackets + json.cursorPackets) > 0, `${label} probe did not observe any KVM packets`);
}

async function runAndParseProbe(exePath, mode) {
    const systemProbe = await runSystemProbe(exePath, mode);
    let json = null;

    try {
        json = JSON.parse(systemProbe.reportContent.trim());
    } catch (error) {
        throw new Error(`Failed to parse ${mode} session-change probe JSON\nreport:\n${systemProbe.reportContent}\nparse error: ${error.message}`);
    }

    validateProbeJson(json, mode === 'auto');
    return { systemProbe, json };
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = args.exe ? path.resolve(args.exe) : path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const logPath = args.log ? path.resolve(args.log) : path.join(path.dirname(exePath), 'svchost-debug.log');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);

    const explicitProbe = await runAndParseProbe(exePath, 'explicit');
    const autoProbe = await runAndParseProbe(exePath, 'auto');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        logPath,
        probes: {
            explicit: {
                taskName: explicitProbe.systemProbe.taskName,
                taskReportPath: explicitProbe.systemProbe.reportPath,
                taskCommandLine: explicitProbe.systemProbe.commandLine,
                createTaskStdout: explicitProbe.systemProbe.create.stdout || '',
                createTaskStderr: explicitProbe.systemProbe.create.stderr || '',
                runTaskStdout: explicitProbe.systemProbe.run.stdout || '',
                runTaskStderr: explicitProbe.systemProbe.run.stderr || '',
                probe: explicitProbe.json
            },
            auto: {
                taskName: autoProbe.systemProbe.taskName,
                taskReportPath: autoProbe.systemProbe.reportPath,
                taskCommandLine: autoProbe.systemProbe.commandLine,
                createTaskStdout: autoProbe.systemProbe.create.stdout || '',
                createTaskStderr: autoProbe.systemProbe.create.stderr || '',
                runTaskStdout: autoProbe.systemProbe.run.stdout || '',
                runTaskStderr: autoProbe.systemProbe.run.stderr || '',
                probe: autoProbe.json
            }
        },
        success: true
    };

    if (fs.existsSync(logPath)) {
        report.logTail = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean).slice(-120);
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_session_change_runtime.json'), report);
        writeText(path.join(evidenceDir, 'explicit_probe.json'), explicitProbe.systemProbe.reportContent.trim() + '\n');
        writeText(path.join(evidenceDir, 'auto_probe.json'), autoProbe.systemProbe.reportContent.trim() + '\n');
        writeText(path.join(evidenceDir, 'explicit-schtasks-create-stdout.txt'), report.probes.explicit.createTaskStdout);
        writeText(path.join(evidenceDir, 'explicit-schtasks-create-stderr.txt'), report.probes.explicit.createTaskStderr);
        writeText(path.join(evidenceDir, 'explicit-schtasks-run-stdout.txt'), report.probes.explicit.runTaskStdout);
        writeText(path.join(evidenceDir, 'explicit-schtasks-run-stderr.txt'), report.probes.explicit.runTaskStderr);
        writeText(path.join(evidenceDir, 'auto-schtasks-create-stdout.txt'), report.probes.auto.createTaskStdout);
        writeText(path.join(evidenceDir, 'auto-schtasks-create-stderr.txt'), report.probes.auto.createTaskStderr);
        writeText(path.join(evidenceDir, 'auto-schtasks-run-stdout.txt'), report.probes.auto.runTaskStdout);
        writeText(path.join(evidenceDir, 'auto-schtasks-run-stderr.txt'), report.probes.auto.runTaskStderr);
        if (Array.isArray(report.logTail)) {
            writeText(path.join(evidenceDir, 'svchost-debug-tail.txt'), report.logTail.join('\n') + '\n');
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `EXPLICIT_TASK_NAME=${report.probes.explicit.taskName}`,
            `EXPLICIT_SESSION_ID=${explicitProbe.json.sessionId}`,
            `EXPLICIT_TSID_EXPLICIT=${explicitProbe.json.initialProcessTSIDExplicit}`,
            `EXPLICIT_INITIAL_PID=${explicitProbe.json.initialPid}`,
            `EXPLICIT_UNLOCK_PID=${explicitProbe.json.unlockPid}`,
            `EXPLICIT_RECONNECT_PID=${explicitProbe.json.reconnectPid}`,
            `EXPLICIT_LOCK_STOP_MS=${explicitProbe.json.lockStopMs}`,
            `EXPLICIT_UNLOCK_RESPAWN_MS=${explicitProbe.json.unlockRespawnMs}`,
            `EXPLICIT_DISCONNECT_STOP_MS=${explicitProbe.json.disconnectStopMs}`,
            `EXPLICIT_RECONNECT_RESPAWN_MS=${explicitProbe.json.reconnectRespawnMs}`,
            `AUTO_TASK_NAME=${report.probes.auto.taskName}`,
            `AUTO_SESSION_ID=${autoProbe.json.sessionId}`,
            `AUTO_TSID_EXPLICIT=${autoProbe.json.initialProcessTSIDExplicit}`,
            `AUTO_UNRELATED_START_IGNORED=${autoProbe.json.unrelatedStartIgnored}`,
            `AUTO_UNRELATED_STOP_IGNORED=${autoProbe.json.unrelatedStopIgnored}`,
            `AUTO_UNRELATED_STOP_SESSION_ID=${autoProbe.json.unrelatedStopSessionId}`,
            `AUTO_VALID_REBIND_OLD_SESSION_ID=${autoProbe.json.validRebindOldSessionId}`,
            `AUTO_VALID_REBIND_FORCED=${autoProbe.json.validRebindForced}`,
            `AUTO_VALID_REBIND_STOPPED=${autoProbe.json.validRebindStopped}`,
            `AUTO_VALID_REBIND_RESPAWNED=${autoProbe.json.validRebindRespawned}`,
            `AUTO_VALID_REBIND_SESSION_UPDATED=${autoProbe.json.validRebindSessionUpdated}`,
            `AUTO_VALID_REBIND_PROCESS_SESSION_ID=${autoProbe.json.validRebindProcessSessionId}`,
            `AUTO_VALID_REBIND_PID=${autoProbe.json.validRebindPid}`,
            `AUTO_VALID_REBIND_STOP_MS=${autoProbe.json.validRebindStopMs}`,
            `AUTO_VALID_REBIND_RESPAWN_MS=${autoProbe.json.validRebindRespawnMs}`,
            `AUTO_INITIAL_PID=${autoProbe.json.initialPid}`,
            `AUTO_UNLOCK_PID=${autoProbe.json.unlockPid}`,
            `AUTO_RECONNECT_PID=${autoProbe.json.reconnectPid}`,
            `AUTO_LOCK_STOP_MS=${autoProbe.json.lockStopMs}`,
            `AUTO_UNLOCK_RESPAWN_MS=${autoProbe.json.unlockRespawnMs}`,
            `AUTO_DISCONNECT_STOP_MS=${autoProbe.json.disconnectStopMs}`,
            `AUTO_RECONNECT_RESPAWN_MS=${autoProbe.json.reconnectRespawnMs}`,
            `TOTAL_PACKETS=${explicitProbe.json.screenPackets + explicitProbe.json.displayListPackets + explicitProbe.json.displayInfoPackets + explicitProbe.json.cursorPackets + autoProbe.json.screenPackets + autoProbe.json.displayListPackets + autoProbe.json.displayInfoPackets + autoProbe.json.cursorPackets}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
