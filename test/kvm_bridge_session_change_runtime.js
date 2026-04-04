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

async function runSystemProbe(exePath) {
    const taskName = `MeshAgentKvmSessionProbe_${process.pid}_${Date.now()}`;
    const reportPath = path.join(os.tmpdir(), `${taskName}.json`);
    const scheduleTime = formatTaskTime(new Date(Date.now() + 60000));
    const commandLine = `"${exePath}" -kvm-bridge-session-change-probe-child "${reportPath}"`;
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

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const logPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'svchost-debug.log');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);

    const systemProbe = await runSystemProbe(exePath);
    let json = null;

    try {
        json = JSON.parse(systemProbe.reportContent.trim());
    } catch (error) {
        throw new Error(`Failed to parse session-change probe JSON\nreport:\n${systemProbe.reportContent}\nparse error: ${error.message}`);
    }

    assert(json.success === true, 'session-change probe reported failure');
    assert(json.relayStarted === true, 'relay did not start');
    assert(json.initialBridgeAvailable === true, 'bridge DLL path was not resolved');
    assert(json.initialBridgeUsed === true, 'rundll32 bridge path was not used');
    assert(json.initialFallbackUsed === false, 'legacy fallback was used unexpectedly');
    assert(json.initialTransportActive === true, 'bridge transport never became active');
    assert(json.lockStopped === true, 'lock event did not stop the helper');
    assert(json.lockStopMs <= 2000, `lock stop exceeded 2000ms (${json.lockStopMs}ms)`);
    assert(json.helperAbsentDuringLock === true, 'helper remained present during lock');
    assert(json.unlockRespawned === true, 'unlock event did not respawn the helper');
    assert(json.unlockRespawnMs <= 2000, `unlock respawn exceeded 2000ms (${json.unlockRespawnMs}ms)`);
    assert(json.postUnlockBridgeUsed === true, 'bridge path was not restored after unlock');
    assert(json.postUnlockFallbackUsed === false, 'unlock restarted on legacy fallback unexpectedly');
    assert(json.disconnectStopped === true, 'console disconnect did not stop the helper');
    assert(json.disconnectStopMs <= 2000, `console disconnect stop exceeded 2000ms (${json.disconnectStopMs}ms)`);
    assert(json.helperAbsentDuringDisconnect === true, 'helper remained present during disconnect');
    assert(json.reconnectRespawned === true, 'console connect did not respawn the helper');
    assert(json.reconnectRespawnMs <= 2000, `console connect respawn exceeded 2000ms (${json.reconnectRespawnMs}ms)`);
    assert(json.cleanupExited === true, 'cleanup did not stop the final helper');
    assert(json.cleanupExitMs <= 5000, `cleanup exit exceeded 5000ms (${json.cleanupExitMs}ms)`);
    assert(json.initialPid > 0, `invalid initial pid ${json.initialPid}`);
    assert(json.unlockPid > 0 && json.unlockPid !== json.initialPid, `unlock pid was not a new helper (${json.unlockPid})`);
    assert(json.reconnectPid > 0 && json.reconnectPid !== json.unlockPid, `reconnect pid was not a new helper (${json.reconnectPid})`);
    assert((json.screenPackets + json.displayListPackets + json.displayInfoPackets + json.cursorPackets) > 0, 'probe did not observe any KVM packets');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        logPath,
        taskName: systemProbe.taskName,
        taskReportPath: systemProbe.reportPath,
        taskCommandLine: systemProbe.commandLine,
        createTaskStdout: systemProbe.create.stdout || '',
        createTaskStderr: systemProbe.create.stderr || '',
        runTaskStdout: systemProbe.run.stdout || '',
        runTaskStderr: systemProbe.run.stderr || '',
        probe: json,
        success: true
    };

    if (fs.existsSync(logPath)) {
        report.logTail = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean).slice(-120);
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_session_change_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe.json'), systemProbe.reportContent.trim() + '\n');
        writeText(path.join(evidenceDir, 'schtasks-create-stdout.txt'), report.createTaskStdout);
        writeText(path.join(evidenceDir, 'schtasks-create-stderr.txt'), report.createTaskStderr);
        writeText(path.join(evidenceDir, 'schtasks-run-stdout.txt'), report.runTaskStdout);
        writeText(path.join(evidenceDir, 'schtasks-run-stderr.txt'), report.runTaskStderr);
        if (Array.isArray(report.logTail)) {
            writeText(path.join(evidenceDir, 'svchost-debug-tail.txt'), report.logTail.join('\n') + '\n');
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `TASK_NAME=${report.taskName}`,
            `SESSION_ID=${json.sessionId}`,
            `INITIAL_PID=${json.initialPid}`,
            `UNLOCK_PID=${json.unlockPid}`,
            `RECONNECT_PID=${json.reconnectPid}`,
            `INITIAL_BRIDGE_USED=${json.initialBridgeUsed}`,
            `POST_UNLOCK_BRIDGE_USED=${json.postUnlockBridgeUsed}`,
            `LOCK_STOP_MS=${json.lockStopMs}`,
            `UNLOCK_RESPAWN_MS=${json.unlockRespawnMs}`,
            `DISCONNECT_STOP_MS=${json.disconnectStopMs}`,
            `RECONNECT_RESPAWN_MS=${json.reconnectRespawnMs}`,
            `CLEANUP_EXIT_MS=${json.cleanupExitMs}`,
            `TOTAL_PACKETS=${json.screenPackets + json.displayListPackets + json.displayInfoPackets + json.cursorPackets}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
