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

function assertArrayEquals(actual, expected, label) {
    assert(Array.isArray(actual), `${label} is not an array`);
    assert(actual.length === expected.length, `${label} length mismatch (${actual.length} != ${expected.length})`);
    for (let i = 0; i < expected.length; ++i) {
        assert(actual[i] === expected[i], `${label}[${i}] expected ${expected[i]}, got ${actual[i]}`);
    }
}

function assertMonotonicIncreasing(values, label) {
    assert(Array.isArray(values), `${label} is not an array`);
    for (let i = 1; i < values.length; ++i) {
        assert(values[i] >= values[i - 1], `${label} is not monotonic at index ${i} (${values[i - 1]} -> ${values[i]})`);
    }
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = resolveBridgeDllPath(exePath, args.dll);
    const expectedBackoffMs = [2000, 4000, 8000, 16000, 32000, 60000];
    const observedIntervalToleranceMs = 100;

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);

    const systemProbe = await runSystemRundll32ProbeTask(dllPath, '-kvm-bridge-crash-recovery-probe-child', {
        prefix: `meshagent_kvm_crash_${process.pid}_${Date.now()}`,
        timeoutMs: 240000
    });
    const json = readJsonText('kvm-bridge-crash-recovery-probe', systemProbe.reportContent);

    assert(json.success === true, 'crash-recovery probe reported failure');
    assert(json.bridgeDllReady === true, 'bridge DLL was not ready');
    assert(json.chainStarted === true, 'probe chain did not start');
    assert(json.relayStarted === true, 'relay did not start');
    assert(json.cleanupSettled === true, 'cleanup did not settle');
    assert(json.failureCount === expectedBackoffMs.length, `unexpected failure count ${json.failureCount}`);
    assert(json.spawnAttemptCount >= json.failureCount, `spawn attempt count ${json.spawnAttemptCount} < failure count ${json.failureCount}`);
    assert(json.chainThreadWaitResult === 0, `unexpected chain thread wait result ${json.chainThreadWaitResult}`);

    assertArrayEquals(json.expectedBackoffMs, expectedBackoffMs, 'expectedBackoffMs');
    assertArrayEquals(json.recordedBackoffMs, expectedBackoffMs, 'recordedBackoffMs');

    assert(Array.isArray(json.failureStageSeries), 'failureStageSeries is not an array');
    assert(Array.isArray(json.failureErrorSeries), 'failureErrorSeries is not an array');
    assert(Array.isArray(json.retryScheduledSeries), 'retryScheduledSeries is not an array');
    assert(Array.isArray(json.failureTimelineMs), 'failureTimelineMs is not an array');
    assert(Array.isArray(json.observedIntervalsMs), 'observedIntervalsMs is not an array');

    assert(json.failureStageSeries.length === expectedBackoffMs.length, 'failureStageSeries length mismatch');
    assert(json.failureErrorSeries.length === expectedBackoffMs.length, 'failureErrorSeries length mismatch');
    assert(json.retryScheduledSeries.length === expectedBackoffMs.length, 'retryScheduledSeries length mismatch');
    assert(json.failureTimelineMs.length === expectedBackoffMs.length, 'failureTimelineMs length mismatch');
    assert(json.observedIntervalsMs.length === (expectedBackoffMs.length - 1), 'observedIntervalsMs length mismatch');

    assert(json.failureStageSeries.every((value) => value === 7), `unexpected failure stages ${json.failureStageSeries.join(',')}`);
    assert(json.failureErrorSeries.every((value) => value === 193), `unexpected failure errors ${json.failureErrorSeries.join(',')}`);
    assert(json.retryScheduledSeries.every((value) => value === true), `retryScheduledSeries contains false values (${json.retryScheduledSeries.join(',')})`);
    assertMonotonicIncreasing(json.failureTimelineMs, 'failureTimelineMs');

    for (let i = 0; i < json.observedIntervalsMs.length; ++i) {
        assert(
            (json.observedIntervalsMs[i] + observedIntervalToleranceMs) >= expectedBackoffMs[i],
            `observed interval ${i} (${json.observedIntervalsMs[i]}ms) was shorter than expected backoff ${expectedBackoffMs[i]}ms by more than ${observedIntervalToleranceMs}ms`
        );
    }

    assert(
        json.failureTimelineMs[json.failureTimelineMs.length - 1] >= expectedBackoffMs[expectedBackoffMs.length - 1],
        `final failure timeline ${json.failureTimelineMs[json.failureTimelineMs.length - 1]}ms did not reach the 60s cap`
    );

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        rundll32Path: systemProbe.rundll32Path,
        taskName: systemProbe.taskName,
        taskReportPath: systemProbe.reportPath,
        taskXmlPath: systemProbe.taskXmlPath,
        taskCommandLine: systemProbe.commandLine,
        createTaskStdout: systemProbe.create.stdout || '',
        createTaskStderr: systemProbe.create.stderr || '',
        runTaskStdout: systemProbe.run.stdout || '',
        runTaskStderr: systemProbe.run.stderr || '',
        probe: json,
        success: true
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_crash_recovery_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe.json'), `${systemProbe.reportContent.trim()}\n`);
        writeText(path.join(evidenceDir, 'task.xml'), systemProbe.taskXml);
        writeText(path.join(evidenceDir, 'schtasks-create-stdout.txt'), report.createTaskStdout);
        writeText(path.join(evidenceDir, 'schtasks-create-stderr.txt'), report.createTaskStderr);
        writeText(path.join(evidenceDir, 'schtasks-run-stdout.txt'), report.runTaskStdout);
        writeText(path.join(evidenceDir, 'schtasks-run-stderr.txt'), report.runTaskStderr);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `RUNDLL32_PATH=${report.rundll32Path}`,
            `DLL_PATH=${report.dllPath}`,
            `TASK_NAME=${report.taskName}`,
            `SESSION_ID=${json.sessionId}`,
            `FAILURE_COUNT=${json.failureCount}`,
            `SPAWN_ATTEMPT_COUNT=${json.spawnAttemptCount}`,
            `RECORDED_BACKOFF_MS=${json.recordedBackoffMs.join(',')}`,
            `OBSERVED_INTERVAL_MS=${json.observedIntervalsMs.join(',')}`,
            `FAILURE_STAGE_SERIES=${json.failureStageSeries.join(',')}`,
            `FAILURE_ERROR_SERIES=${json.failureErrorSeries.join(',')}`,
            `RETRY_SCHEDULED_SERIES=${json.retryScheduledSeries.join(',')}`,
            `OBSERVED_INTERVAL_TOLERANCE_MS=${observedIntervalToleranceMs}`,
            `FINAL_TIMELINE_MS=${json.failureTimelineMs[json.failureTimelineMs.length - 1]}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
