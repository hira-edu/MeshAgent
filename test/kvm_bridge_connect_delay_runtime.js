const fs = require('fs');
const path = require('path');
const {
    assert,
    parseArgs,
    runSystemProbeWithPsExec,
    writeJson,
    writeText
} = require('./lib/kvm_runtime_helpers');

function readLastJsonLine(label, text) {
    const lines = String(text || '')
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    const jsonLine = [...lines].reverse().find((line) => line.startsWith('{') && line.endsWith('}'));
    if (!jsonLine) {
        throw new Error(`Failed to locate trailing JSON line for ${label}\ncontent:\n${text}`);
    }
    try {
        return JSON.parse(jsonLine);
    } catch (error) {
        throw new Error(`Failed to parse trailing JSON line for ${label}\njson line:\n${jsonLine}\nparse error: ${error.message}`);
    }
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');
    const logPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'svchost-debug.log');
    const requestedConnectDelayMs = Number.parseInt(String(args['connect-delay-ms'] || '2000'), 10);
    const logStartOffset = fs.existsSync(logPath) ? fs.statSync(logPath).size : 0;

    assert(Number.isFinite(requestedConnectDelayMs) && requestedConnectDelayMs > 0, `invalid connect delay ${args['connect-delay-ms']}`);
    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);

    const systemProbe = await runSystemProbeWithPsExec(exePath, `-kvm-bridge-connect-delay-probe ${requestedConnectDelayMs}`, {
        prefix: `meshagent_kvm_connect_delay_${process.pid}_${Date.now()}`,
        timeoutMs: 180000
    });
    const json = readLastJsonLine('kvm-bridge-connect-delay-probe', systemProbe.reportContent);

    assert(json.success === true, 'connect-delay probe reported failure');
    assert(json.requestedConnectDelayMs === requestedConnectDelayMs, `delay mismatch (${json.requestedConnectDelayMs} != ${requestedConnectDelayMs})`);
    assert(json.bridgeDllReady === true, 'bridge DLL was not resolved');
    assert(json.chainStarted === true, 'probe chain did not start');
    assert(json.relayStarted === true, 'relay did not start');
    assert(json.bridgeSpawned === true, 'bridge helper was not observed');
    assert(json.bridgePid > 0, `invalid bridge pid ${json.bridgePid}`);
    assert(json.bridgePacketsReady === true, 'bridge did not produce packets after delayed connect');
    assert(json.bridgeUsed === true, 'rundll32 bridge path was not used');
    assert(json.fallbackUsed === false, 'legacy fallback was used unexpectedly');
    assert(json.launchAttemptCount === 1, `bridge required fallback attempts (${json.launchAttemptCount})`);
    assert(json.successfulSpawnType === 2, `bridge launched with unexpected spawn type ${json.successfulSpawnType}`);
    assert(json.successfulSpawnAttemptOrdinal === 1, `bridge succeeded on attempt ${json.successfulSpawnAttemptOrdinal}`);
    assert(json.transportActiveAfterPacket === true, 'transport never became active after delayed connect');
    assert(json.failureCount === 0, `unexpected failure count ${json.failureCount}`);
    assert(json.failureStage === 0, `unexpected failure stage ${json.failureStage}`);
    assert(json.failureError === 0, `unexpected failure error ${json.failureError}`);
    assert(json.cleanupExited === true, 'cleanup did not stop the delayed-connect helper');
    assert(json.chainThreadWaitResult === 0, `unexpected chain thread wait result ${json.chainThreadWaitResult}`);
    assert(json.relaySetupMs >= Math.max(0, requestedConnectDelayMs - 250), `relay setup returned too early (${json.relaySetupMs}ms for ${requestedConnectDelayMs}ms requested delay)`);
    assert((json.screenPackets + json.displayListPackets + json.displayInfoPackets + json.cursorPackets + json.picturePackets + json.jumboPackets) > 0, 'probe did not observe any KVM traffic');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        logPath,
        requestedConnectDelayMs,
        psexecPath: systemProbe.psexecPath,
        taskReportPath: systemProbe.reportPath,
        taskScriptPath: systemProbe.scriptPath,
        psexecExitCode: systemProbe.psexec.status,
        psexecStdout: systemProbe.psexec.stdout || '',
        psexecStderr: systemProbe.psexec.stderr || '',
        probe: json,
        success: true
    };

    if (fs.existsSync(logPath)) {
        const logBuffer = fs.readFileSync(logPath);
        const logDeltaBuffer = (logStartOffset > 0 && logStartOffset < logBuffer.length) ? logBuffer.slice(logStartOffset) : logBuffer;
        report.logDelta = logDeltaBuffer.toString('utf8');
        report.logTail = logBuffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-120);
        report.logDeltaTail = report.logDelta.split(/\r?\n/).filter(Boolean).slice(-120);
        assert(report.logTail.some((line) => line.includes(`KvmSessionBridgeW delaying pipe connect by ${requestedConnectDelayMs} ms`)), 'svchost log missing explicit connect-delay line');
        assert(report.logTail.some((line) => line.includes('KvmSessionBridgeW waiting for pipes (timeout=5000 ms)')), 'svchost log missing shared timeout trace');
        assert(report.logTail.some((line) => line.includes('KvmSessionBridgeW control pipe connected after')), 'svchost log missing control-pipe connect trace');
        assert(report.logTail.some((line) => line.includes('KvmSessionBridgeW data pipe connected after')), 'svchost log missing data-pipe connect trace');
    }

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_connect_delay_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe.json'), `${systemProbe.reportContent.trim()}\n`);
        writeText(path.join(evidenceDir, 'psexec-stdout.txt'), report.psexecStdout);
        writeText(path.join(evidenceDir, 'psexec-stderr.txt'), report.psexecStderr);
        if (Array.isArray(report.logTail)) {
            writeText(path.join(evidenceDir, 'svchost-debug-tail.txt'), `${report.logTail.join('\n')}\n`);
        }
        if (Array.isArray(report.logDeltaTail)) {
            writeText(path.join(evidenceDir, 'svchost-debug-delta-tail.txt'), `${report.logDeltaTail.join('\n')}\n`);
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `REQUESTED_CONNECT_DELAY_MS=${requestedConnectDelayMs}`,
            `RELAY_SETUP_MS=${json.relaySetupMs}`,
            `BRIDGE_PID=${json.bridgePid}`,
            `LAUNCH_ATTEMPT_COUNT=${json.launchAttemptCount}`,
            `SUCCESSFUL_SPAWN_TYPE=${json.successfulSpawnType}`,
            `SUCCESSFUL_SPAWN_ATTEMPT_ORDINAL=${json.successfulSpawnAttemptOrdinal}`,
            `BRIDGE_PACKET_MS=${json.bridgePacketMs}`,
            `SCREEN_PACKETS=${json.screenPackets}`,
            `DISPLAY_LIST_PACKETS=${json.displayListPackets}`,
            `PICTURE_PACKETS=${json.picturePackets}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
