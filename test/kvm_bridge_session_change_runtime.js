const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const { getSystemRundll32Path } = require('./lib/rundll32_lifecycle');

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

function formatTaskStartBoundary(date) {
    const year = String(date.getFullYear()).padStart(4, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
}

function xmlEscape(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function buildSystemScheduledTaskXml(rundll32Path, rundll32Arguments, startBoundary) {
    return [
        '<?xml version="1.0" encoding="UTF-16"?>',
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
        '  <RegistrationInfo>',
        `    <Date>${xmlEscape(startBoundary)}</Date>`,
        '    <Author>MeshAgentRuntimeProbe</Author>',
        '  </RegistrationInfo>',
        '  <Principals>',
        '    <Principal id="Author">',
        '      <UserId>S-1-5-18</UserId>',
        '    </Principal>',
        '  </Principals>',
        '  <Settings>',
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
        '    <IdleSettings>',
        '      <Duration>PT10M</Duration>',
        '      <WaitTimeout>PT1H</WaitTimeout>',
        '      <StopOnIdleEnd>false</StopOnIdleEnd>',
        '      <RestartOnIdle>false</RestartOnIdle>',
        '    </IdleSettings>',
        '  </Settings>',
        '  <Triggers>',
        '    <TimeTrigger>',
        `      <StartBoundary>${xmlEscape(startBoundary)}</StartBoundary>`,
        '    </TimeTrigger>',
        '  </Triggers>',
        '  <Actions Context="Author">',
        '    <Exec>',
        `      <Command>${xmlEscape(rundll32Path)}</Command>`,
        `      <Arguments>${xmlEscape(rundll32Arguments)}</Arguments>`,
        '    </Exec>',
        '  </Actions>',
        '</Task>',
        ''
    ].join('\r\n');
}

function resolveSystemRundll32Path(args) {
    if (args.rundll32) {
        return path.resolve(args.rundll32);
    }
    return getSystemRundll32Path();
}

function resolveKvmProbeDllPath(exePath, args) {
    if (args.dll) {
        return path.resolve(args.dll);
    }

    const exeDir = path.dirname(exePath);
    const parentDir = path.dirname(exeDir);
    const baseName = path.basename(exePath, path.extname(exePath));
    const candidates = [
        path.join(exeDir, 'diagsvc.dll'),
        path.join(exeDir, 'service_bundle.dll'),
        path.join(exeDir, `${baseName}.dll`),
        path.join(parentDir, 'MeshServiceBundle', `${baseName}.dll`)
    ];
    const found = candidates.find((candidate) => fs.existsSync(candidate));
    if (!found) {
        throw new Error(`probe DLL missing; checked: ${candidates.join(', ')}`);
    }
    return found;
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

async function runSystemProbe(rundll32Path, dllPath, mode) {
    const taskName = `MeshAgentKvmSessionProbe_${mode}_${process.pid}_${Date.now()}`;
    const reportPath = path.join(os.tmpdir(), `${taskName}.json`);
    const taskXmlPath = path.join(os.tmpdir(), `${taskName}.xml`);
    const startBoundary = formatTaskStartBoundary(new Date(Date.now() + 60000));
    const modeArgs = mode === 'auto' ? ' --auto-selected-tsid' : '';
    const rundll32Arguments = `"${dllPath}",MeshKvmProbeHostW -kvm-bridge-session-change-probe-child "${reportPath}"${modeArgs}`;
    const commandLine = `"${rundll32Path}" ${rundll32Arguments}`;
    const taskXml = buildSystemScheduledTaskXml(rundll32Path, rundll32Arguments, startBoundary);

    fs.writeFileSync(taskXmlPath, Buffer.from(`\ufeff${taskXml}`, 'utf16le'));
    const create = runCommand('schtasks', [
        '/Create',
        '/TN', taskName,
        '/XML', taskXmlPath,
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
            taskXmlPath,
            taskXml,
            commandLine,
            create,
            run,
            reportContent
        };
    } finally {
        runCommand('schtasks', ['/Delete', '/TN', taskName, '/F']);
        try { fs.unlinkSync(taskXmlPath); } catch (error) { if (error.code !== 'ENOENT') { throw error; } }
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
        assert(json.validRebindSuccessfulSpawnType === json.sessionExpectedSpawnType, `auto-selected valid rebind used unexpected spawn type ${json.validRebindSuccessfulSpawnType} (expected ${json.sessionExpectedSpawnType})`);
        assert(json.validRebindSuccessfulSpawnAttemptOrdinal === 1, `auto-selected valid rebind succeeded on attempt ${json.validRebindSuccessfulSpawnAttemptOrdinal}`);
    }
    assert(json.initialBridgeAvailable === true, `${label} bridge DLL path was not resolved`);
    assert(json.initialBridgeUsed === true, `${label} rundll32 bridge path was not used`);
    assert(json.initialFallbackUsed === false, `${label} legacy fallback was used unexpectedly`);
    assert(json.initialLaunchAttemptCount === 1, `${label} initial bridge needed fallback attempts (${json.initialLaunchAttemptCount})`);
    assert(json.initialSuccessfulSpawnType === json.initialExpectedSpawnType, `${label} initial bridge used unexpected spawn type ${json.initialSuccessfulSpawnType} (expected ${json.initialExpectedSpawnType})`);
    assert(json.initialSuccessfulSpawnAttemptOrdinal === 1, `${label} initial bridge succeeded on attempt ${json.initialSuccessfulSpawnAttemptOrdinal}`);
    assert(json.initialTransportActive === true, `${label} bridge transport never became active`);
    assert(json.lockKeptHelper === true, `${label} lock event stopped the helper; the viewer must keep seeing the lock screen`);
    assert(json.postLockChildPresent === true, `${label} relay lost its helper during lock`);
    assert(json.postLockChildExitSignaled === false, `${label} lock event signalled a helper exit`);
    assert(json.postLockRestartSuppressed === false, `${label} lock event suppressed helper restarts`);
    assert(json.postLockPendingRestart === false, `${label} lock event left a pending restart`);
    assert(json.postLockTransportActive === true, `${label} bridge transport was inactive during lock`);
    assert(json.lockPacketsReady === true, `${label} refresh during lock produced no KVM packets`);
    assert(json.unlockKeptHelper === true, `${label} unlock event replaced the helper that stayed attached through lock`);
    assert(json.postUnlockChildPresent === true, `${label} relay lost its helper after unlock`);
    assert(json.postUnlockRestartSuppressed === false, `${label} relay remained restart-suppressed after unlock`);
    assert(json.postUnlockPendingRestart === false, `${label} unlock left a pending restart`);
    assert(json.postUnlockTransportActive === true, `${label} bridge transport was inactive after unlock`);
    assert(json.unlockPacketsReady === true, `${label} refresh after unlock produced no KVM packets`);
    assert(json.postUnlockBridgeUsed === true, `${label} bridge path was not restored after unlock`);
    assert(json.postUnlockFallbackUsed === false, `${label} unlock restarted on legacy fallback unexpectedly`);
    assert(json.postUnlockLaunchAttemptCount === 1, `${label} unlock restart needed fallback attempts (${json.postUnlockLaunchAttemptCount})`);
    const expectedUnlockSpawnType = expectedAutoSelected ? json.sessionExpectedSpawnType : json.initialExpectedSpawnType;
    assert(json.postUnlockSuccessfulSpawnType === expectedUnlockSpawnType, `${label} helper used unexpected spawn type ${json.postUnlockSuccessfulSpawnType} (expected ${expectedUnlockSpawnType})`);
    assert(json.postUnlockSuccessfulSpawnAttemptOrdinal === 1, `${label} unlock restart succeeded on attempt ${json.postUnlockSuccessfulSpawnAttemptOrdinal}`);
    assert(json.disconnectStopped === true, `${label} console disconnect did not stop the helper`);
    assert(json.disconnectStopMs <= 2000, `${label} console disconnect stop exceeded 2000ms (${json.disconnectStopMs}ms)`);
    assert(json.helperAbsentDuringDisconnect === true, `${label} helper remained present during disconnect`);
    assert(json.reconnectRespawned === true, `${label} console connect did not respawn the helper`);
    assert(json.reconnectRespawnMs <= 2000, `${label} console connect respawn exceeded 2000ms (${json.reconnectRespawnMs}ms)`);
    assert(json.reconnectLaunchAttemptCount === 1, `${label} reconnect restart needed fallback attempts (${json.reconnectLaunchAttemptCount})`);
    assert(json.reconnectSuccessfulSpawnType === json.sessionExpectedSpawnType, `${label} reconnect restart used unexpected spawn type ${json.reconnectSuccessfulSpawnType} (expected ${json.sessionExpectedSpawnType})`);
    assert(json.reconnectSuccessfulSpawnAttemptOrdinal === 1, `${label} reconnect restart succeeded on attempt ${json.reconnectSuccessfulSpawnAttemptOrdinal}`);
    assert(json.cleanupExited === true, `${label} cleanup did not stop the final helper`);
    assert(json.cleanupExitMs <= 5000, `${label} cleanup exit exceeded 5000ms (${json.cleanupExitMs}ms)`);
    assert(json.initialPid > 0, `${label} invalid initial pid ${json.initialPid}`);
    assert(json.unlockPid > 0, `${label} invalid helper pid after unlock (${json.unlockPid})`);
    assert(json.reconnectPid > 0 && json.reconnectPid !== json.unlockPid, `${label} reconnect pid was not a new helper (${json.reconnectPid})`);
    assert((json.screenPackets + json.displayListPackets + json.displayInfoPackets + json.cursorPackets) > 0, `${label} probe did not observe any KVM packets`);
}

async function runAndParseProbe(rundll32Path, dllPath, mode) {
    const systemProbe = await runSystemProbe(rundll32Path, dllPath, mode);
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
    const exePath = args.exe ? path.resolve(args.exe) : path.resolve('meshservice', 'x64', 'MeshServiceRuntime', 'MeshService-2022.exe');
    const dllPath = resolveKvmProbeDllPath(exePath, args);
    const rundll32Path = resolveSystemRundll32Path(args);
    const logPath = args.log ? path.resolve(args.log) : path.join(path.dirname(exePath), 'service-host-debug.log');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `probe DLL missing at ${dllPath}`);
    assert(fs.existsSync(rundll32Path), `rundll32.exe missing at ${rundll32Path}`);

    const explicitProbe = await runAndParseProbe(rundll32Path, dllPath, 'explicit');
    const autoProbe = await runAndParseProbe(rundll32Path, dllPath, 'auto');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        rundll32Path,
        logPath,
        probes: {
            explicit: {
                taskName: explicitProbe.systemProbe.taskName,
                taskReportPath: explicitProbe.systemProbe.reportPath,
                taskXmlPath: explicitProbe.systemProbe.taskXmlPath,
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
                taskXmlPath: autoProbe.systemProbe.taskXmlPath,
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
        writeText(path.join(evidenceDir, 'explicit_task.xml'), explicitProbe.systemProbe.taskXml);
        writeText(path.join(evidenceDir, 'auto_task.xml'), autoProbe.systemProbe.taskXml);
        writeText(path.join(evidenceDir, 'explicit-schtasks-create-stdout.txt'), report.probes.explicit.createTaskStdout);
        writeText(path.join(evidenceDir, 'explicit-schtasks-create-stderr.txt'), report.probes.explicit.createTaskStderr);
        writeText(path.join(evidenceDir, 'explicit-schtasks-run-stdout.txt'), report.probes.explicit.runTaskStdout);
        writeText(path.join(evidenceDir, 'explicit-schtasks-run-stderr.txt'), report.probes.explicit.runTaskStderr);
        writeText(path.join(evidenceDir, 'auto-schtasks-create-stdout.txt'), report.probes.auto.createTaskStdout);
        writeText(path.join(evidenceDir, 'auto-schtasks-create-stderr.txt'), report.probes.auto.createTaskStderr);
        writeText(path.join(evidenceDir, 'auto-schtasks-run-stdout.txt'), report.probes.auto.runTaskStdout);
        writeText(path.join(evidenceDir, 'auto-schtasks-run-stderr.txt'), report.probes.auto.runTaskStderr);
        if (Array.isArray(report.logTail)) {
            writeText(path.join(evidenceDir, 'service-host-debug-tail.txt'), report.logTail.join('\n') + '\n');
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `RUNDLL32_PATH=${report.rundll32Path}`,
            `DLL_PATH=${report.dllPath}`,
            `EXPLICIT_TASK_NAME=${report.probes.explicit.taskName}`,
            `EXPLICIT_SESSION_ID=${explicitProbe.json.sessionId}`,
            `EXPLICIT_TSID_EXPLICIT=${explicitProbe.json.initialProcessTSIDExplicit}`,
            `EXPLICIT_INITIAL_PID=${explicitProbe.json.initialPid}`,
            `EXPLICIT_UNLOCK_PID=${explicitProbe.json.unlockPid}`,
            `EXPLICIT_RECONNECT_PID=${explicitProbe.json.reconnectPid}`,
            `EXPLICIT_LOCK_KEPT_HELPER=${explicitProbe.json.lockKeptHelper}`,
            `EXPLICIT_LOCK_PACKET_MS=${explicitProbe.json.lockPacketMs}`,
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
            `AUTO_LOCK_KEPT_HELPER=${autoProbe.json.lockKeptHelper}`,
            `AUTO_LOCK_PACKET_MS=${autoProbe.json.lockPacketMs}`,
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
