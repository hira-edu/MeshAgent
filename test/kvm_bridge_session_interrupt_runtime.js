const fs = require('fs');
const path = require('path');
const {
    assert,
    parseArgs,
    readJsonText,
    resolveBridgeDllPath,
    runSystemRundll32ProbeTask,
    writeJson,
    writeText
} = require('./lib/kvm_runtime_helpers');

async function runInterruptProbe(options) {
    const {
        label,
        unrelatedSessionEvent,
        exePath,
        dllPath,
        masterLogPath,
        bridgeLogPath,
        connectDelayMs,
        interruptAfterMs
    } = options;
    const masterLogStartOffset = fs.existsSync(masterLogPath) ? fs.statSync(masterLogPath).size : 0;
    const bridgeLogStartOffset = fs.existsSync(bridgeLogPath) ? fs.statSync(bridgeLogPath).size : 0;
    const extraArgs = [String(connectDelayMs), String(interruptAfterMs)];
    if (unrelatedSessionEvent) {
        extraArgs.push('--unrelated-session');
    }
    const systemProbe = await runSystemRundll32ProbeTask(
        dllPath,
        '-kvm-bridge-session-interrupt-probe-child',
        {
            prefix: `meshagent_kvm_session_interrupt_${label}_${process.pid}_${Date.now()}`,
            extraArgs,
            timeoutMs: 180000
        });
    const json = readJsonText(`kvm-bridge-session-interrupt-probe-${label}`, systemProbe.reportContent);
    const report = {
        label,
        unrelatedSessionEvent,
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        masterLogPath,
        bridgeLogPath,
        connectDelayMs,
        interruptAfterMs,
        rundll32Path: systemProbe.rundll32Path,
        taskName: systemProbe.taskName,
        taskReportPath: systemProbe.reportPath,
        taskXmlPath: systemProbe.taskXmlPath,
        taskCommandLine: systemProbe.commandLine,
        createTaskStdout: systemProbe.create.stdout || '',
        createTaskStderr: systemProbe.create.stderr || '',
        runTaskStdout: systemProbe.run.stdout || '',
        runTaskStderr: systemProbe.run.stderr || '',
        probe: json
    };

    assert(json.success === true, `${label} session-interrupt probe reported failure`);
    assert(json.requestedConnectDelayMs === connectDelayMs, `${label} delay mismatch (${json.requestedConnectDelayMs} != ${connectDelayMs})`);
    assert(json.interruptAfterMs === interruptAfterMs, `${label} interrupt mismatch (${json.interruptAfterMs} != ${interruptAfterMs})`);
    assert(json.unrelatedSessionEvent === unrelatedSessionEvent, `${label} reported wrong session-event mode`);
    assert(json.bridgeDllReady === true, `${label} bridge DLL was not resolved`);
    assert(json.chainStarted === true, `${label} probe chain did not start`);
    assert(json.setupThreadStarted === true, `${label} setup worker did not start`);
    assert(json.setupThreadFinished === true, `${label} setup worker did not finish`);
    assert(json.setupThreadWaitResult === 0, `${label} unexpected setup wait result ${json.setupThreadWaitResult}`);
    assert(json.setupThreadExitCode === 0, `${label} unexpected setup thread exit ${json.setupThreadExitCode}`);
    assert(json.launchAttemptCount === 1, `${label} launch attempted fallback (${json.launchAttemptCount})`);
    assert(json.failureCount === 0, `${label} launch incremented failure count (${json.failureCount})`);
    assert(json.failureStage === 0, `${label} unexpected failure stage ${json.failureStage}`);
    assert(json.fallbackUsed === false, `${label} reported fallback use`);
    assert(json.chainThreadWaitResult === 0, `${label} unexpected chain wait result ${json.chainThreadWaitResult}`);

    if (unrelatedSessionEvent) {
        assert(json.notifySessionId !== json.sessionId, 'unrelated probe did not use a distinct session id');
        assert(json.relayStarted === true, 'unrelated session event interrupted the relay launch');
        assert(json.failureError === 0, `unrelated session event left failure error ${json.failureError}`);
        assert(json.bridgeUsed === true, 'unrelated session event did not keep bridge path active');
        assert(json.transportActive === true, 'unrelated session event left transport inactive');
        assert(json.childPresent === true, 'unrelated session event left no helper present');
        assert(json.bridgePacketsReady === true, 'unrelated session event produced no KVM packets');
        assert(json.cleanupExited === true, 'unrelated session event cleanup did not stop the helper');
    } else {
        assert(json.relayStarted === false, 'related interrupted relay unexpectedly reported success');
        assert(json.setupMs < connectDelayMs, `related setup was not interrupted before connect delay elapsed (${json.setupMs}ms)`);
        assert(json.notifyMs < connectDelayMs, `related session notification was blocked until stale connect timeout (${json.notifyMs}ms)`);
        assert(json.failureError === 995, `related unexpected interrupted failure error ${json.failureError}`);
        assert(json.transportActive === false, 'related interrupted launch left transport active');
        assert(json.childPresent === false, 'related interrupted launch left child present');
    }

    if (fs.existsSync(masterLogPath)) {
        const masterLogBuffer = fs.readFileSync(masterLogPath);
        const masterDeltaBuffer = (masterLogStartOffset > 0 && masterLogStartOffset < masterLogBuffer.length) ? masterLogBuffer.slice(masterLogStartOffset) : masterLogBuffer;
        report.masterLogDelta = masterDeltaBuffer.toString('utf8');
        report.masterLogTail = masterLogBuffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-160);
        report.masterLogDeltaTail = report.masterLogDelta.split(/\r?\n/).filter(Boolean).slice(-160);
        if (unrelatedSessionEvent) {
            assert(report.masterLogDelta.includes('session change ignored for explicit KVM TSID'), 'unrelated master log delta missing ignored explicit-session marker');
            assert(!report.masterLogDelta.includes('session change signal generation='), 'unrelated master log delta emitted a cancellation signal');
            assert(!report.masterLogDelta.includes('bridge stdin connect aborted by session change generation'), 'unrelated master log delta aborted stdin connect');
        } else {
            assert(report.masterLogDelta.includes('session change signal generation='), 'related master log delta missing session-change epoch signal');
            assert(report.masterLogDelta.includes('bridge stdin connect aborted by session change generation'), 'related master log delta missing interrupted stdin connect');
        }
    } else {
        assert(false, `master log missing at ${masterLogPath}`);
    }

    if (fs.existsSync(bridgeLogPath)) {
        const bridgeLogBuffer = fs.readFileSync(bridgeLogPath);
        const bridgeDeltaBuffer = (bridgeLogStartOffset > 0 && bridgeLogStartOffset < bridgeLogBuffer.length) ? bridgeLogBuffer.slice(bridgeLogStartOffset) : bridgeLogBuffer;
        report.bridgeLogDelta = bridgeDeltaBuffer.toString('utf8');
        report.bridgeLogTail = bridgeLogBuffer.toString('utf8').split(/\r?\n/).filter(Boolean).slice(-160);
        report.bridgeLogDeltaTail = report.bridgeLogDelta.split(/\r?\n/).filter(Boolean).slice(-160);
        assert(report.bridgeLogDelta.includes(`KvmSessionBridgeW delaying pipe connect by ${connectDelayMs} ms`), `${label} bridge log delta missing delayed connect marker`);
    } else {
        assert(false, `bridge log missing at ${bridgeLogPath}`);
    }

    report.success = true;
    return { systemProbe, report };
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = args.exe ? path.resolve(args.exe) : path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = resolveBridgeDllPath(exePath, args.dll);
    const masterLogPath = args['master-log'] ? path.resolve(args['master-log']) : path.resolve(path.dirname(dllPath), 'svchost-debug.log');
    const bridgeLogPath = args['bridge-log'] ? path.resolve(args['bridge-log']) : path.resolve(path.dirname(dllPath), 'svchost-debug.log');
    const connectDelayMs = Number.parseInt(String(args['connect-delay-ms'] || '4000'), 10);
    const interruptAfterMs = Number.parseInt(String(args['interrupt-after-ms'] || '500'), 10);

    assert(Number.isFinite(connectDelayMs) && connectDelayMs >= 1000, `invalid connect delay ${args['connect-delay-ms']}`);
    assert(Number.isFinite(interruptAfterMs) && interruptAfterMs >= 100, `invalid interrupt delay ${args['interrupt-after-ms']}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);

    const related = await runInterruptProbe({
        label: 'related',
        unrelatedSessionEvent: false,
        exePath,
        dllPath,
        masterLogPath,
        bridgeLogPath,
        connectDelayMs,
        interruptAfterMs
    });
    const unrelated = await runInterruptProbe({
        label: 'unrelated',
        unrelatedSessionEvent: true,
        exePath,
        dllPath,
        masterLogPath,
        bridgeLogPath,
        connectDelayMs,
        interruptAfterMs
    });

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        masterLogPath,
        bridgeLogPath,
        connectDelayMs,
        interruptAfterMs,
        probes: {
            related: related.report,
            unrelated: unrelated.report
        },
        success: true
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_session_interrupt_runtime.json'), report);
        for (const item of [related, unrelated]) {
            const label = item.report.label;
            writeText(path.join(evidenceDir, `${label}-probe.json`), `${item.systemProbe.reportContent.trim()}\n`);
            writeText(path.join(evidenceDir, `${label}-task.xml`), item.systemProbe.taskXml);
            writeText(path.join(evidenceDir, `${label}-schtasks-create-stdout.txt`), item.report.createTaskStdout);
            writeText(path.join(evidenceDir, `${label}-schtasks-create-stderr.txt`), item.report.createTaskStderr);
            writeText(path.join(evidenceDir, `${label}-schtasks-run-stdout.txt`), item.report.runTaskStdout);
            writeText(path.join(evidenceDir, `${label}-schtasks-run-stderr.txt`), item.report.runTaskStderr);
            if (Array.isArray(item.report.masterLogTail)) {
                writeText(path.join(evidenceDir, `${label}-master-svchost-debug-tail.txt`), `${item.report.masterLogTail.join('\n')}\n`);
            }
            if (Array.isArray(item.report.masterLogDeltaTail)) {
                writeText(path.join(evidenceDir, `${label}-master-svchost-debug-delta-tail.txt`), `${item.report.masterLogDeltaTail.join('\n')}\n`);
            }
            if (Array.isArray(item.report.bridgeLogTail)) {
                writeText(path.join(evidenceDir, `${label}-bridge-svchost-debug-tail.txt`), `${item.report.bridgeLogTail.join('\n')}\n`);
            }
            if (Array.isArray(item.report.bridgeLogDeltaTail)) {
                writeText(path.join(evidenceDir, `${label}-bridge-svchost-debug-delta-tail.txt`), `${item.report.bridgeLogDeltaTail.join('\n')}\n`);
            }
        }
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `RUNDLL32_PATH=${related.report.rundll32Path}`,
            `DLL_PATH=${report.dllPath}`,
            `CONNECT_DELAY_MS=${connectDelayMs}`,
            `INTERRUPT_AFTER_MS=${interruptAfterMs}`,
            `RELATED_SETUP_MS=${related.report.probe.setupMs}`,
            `RELATED_NOTIFY_MS=${related.report.probe.notifyMs}`,
            `RELATED_FAILURE_ERROR=${related.report.probe.failureError}`,
            `UNRELATED_NOTIFY_SESSION_ID=${unrelated.report.probe.notifySessionId}`,
            `UNRELATED_RELAY_STARTED=${unrelated.report.probe.relayStarted}`,
            `UNRELATED_FAILURE_ERROR=${unrelated.report.probe.failureError}`,
            `UNRELATED_BRIDGE_PACKETS_READY=${unrelated.report.probe.bridgePacketsReady}`,
            `UNRELATED_CLEANUP_EXITED=${unrelated.report.probe.cleanupExited}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
