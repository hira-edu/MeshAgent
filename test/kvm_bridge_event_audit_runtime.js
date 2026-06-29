const fs = require('fs');
const path = require('path');
const {
    assert,
    parseArgs,
    queryServiceName,
    readJsonText,
    readLatestEventRecordId,
    runSystemRundll32ProbeTask,
    waitForEventLog,
    writeJson,
    writeText
} = require('./lib/kvm_runtime_helpers');

function toLowEventId(value) {
    return Number(value) % 65536;
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = path.resolve('meshservice', 'x64', 'StealthLab_DLL', 'MeshService-2022.dll');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);

    const providerName = queryServiceName(exePath);
    const baselineRecordId = readLatestEventRecordId(providerName, [8193, 8194]);

    const systemProbe = await runSystemRundll32ProbeTask(dllPath, '-kvm-bridge-event-audit-probe-child', {
        prefix: `meshagent_kvm_audit_${process.pid}_${Date.now()}`,
        timeoutMs: 180000
    });
    const json = readJsonText('kvm-bridge-event-audit-probe', systemProbe.reportContent);

    assert(json.success === true, 'event-audit probe reported failure');
    assert(json.serviceName === providerName, `service name mismatch (${json.serviceName} != ${providerName})`);
    assert(json.bridgeDllPath === dllPath, `bridge DLL path mismatch (${json.bridgeDllPath} != ${dllPath})`);
    assert(json.successRelayStarted === true, 'success relay did not start');
    assert(json.successBridgeSpawned === true, 'success bridge was not spawned');
    assert(json.successBridgePacketsReady === true, 'success bridge never produced packets');
    assert(json.successBridgeUsed === true, 'rundll32 bridge was not used on success path');
    assert(json.successFallbackUsed === false, 'legacy fallback was used on success path');
    assert(json.successBridgePid > 0, `invalid success bridge pid ${json.successBridgePid}`);
    assert(json.successCleanupExited === true, 'success cleanup did not stop the helper');
    assert(json.failureRelayStarted === true, 'failure relay did not start');
    assert(json.failureObserved === true, 'failure cycle was not observed');
    assert(json.failureCount >= 1, `failure count ${json.failureCount} was not incremented`);
    assert(json.failureDelayMs === 2000, `unexpected first backoff delay ${json.failureDelayMs}`);
    assert(json.failureStage === 7, `unexpected failure stage ${json.failureStage}`);
    assert(json.failureError === 193, `unexpected failure error ${json.failureError}`);
    assert(json.failureRetryScheduled === true, 'failure retry was not scheduled');
    assert(json.failureSpawnAttempts >= 1, `unexpected failureSpawnAttempts ${json.failureSpawnAttempts}`);
    assert(json.chainThreadWaitResult === 0, `unexpected chain thread wait result ${json.chainThreadWaitResult}`);

    const attemptEventId = toLowEventId(json.eventIdAttempt);
    const outcomeEventId = toLowEventId(json.eventIdOutcome);
    const eventLog = await waitForEventLog(
        providerName,
        [attemptEventId, outcomeEventId],
        baselineRecordId,
        (events) => {
            return events.some((event) => event.eventId === attemptEventId && event.outcome === 'ATTEMPT')
                && events.some((event) => event.eventId === outcomeEventId && event.outcome === 'SUCCESS' && event.pid === json.successBridgePid)
                && events.some((event) => event.eventId === outcomeEventId && event.outcome === 'DLL_LOAD_FAILURE' && event.errorCode === json.failureError);
        },
        {
            timeoutMs: 30000,
            count: 256,
            pollIntervalMs: 500
        }
    );

    const events = eventLog.events;
    const attemptEvents = events.filter((event) => event.eventId === attemptEventId && event.outcome === 'ATTEMPT');
    const successEvents = events.filter((event) => event.eventId === outcomeEventId && event.outcome === 'SUCCESS');
    const failureEvents = events.filter((event) => event.eventId === outcomeEventId && event.outcome === 'DLL_LOAD_FAILURE');

    assert(attemptEvents.length >= 1, 'no ATTEMPT events were written');
    assert(successEvents.length >= 1, 'no SUCCESS outcome events were written');
    assert(failureEvents.length >= 1, 'no DLL_LOAD_FAILURE outcome events were written');

    for (const event of events) {
        assert(event.providerName === providerName, `unexpected provider ${event.providerName}`);
        assert(event.sessionId === json.sessionId, `unexpected session id ${event.sessionId}`);
        assert(event.dllPath === dllPath, `unexpected DLL path ${event.dllPath}`);
        assert(event.tokenType === 'SYSTEM', `unexpected token type ${event.tokenType}`);
        assert(event.eventTimestamp.length > 0, 'event timestamp was empty');
    }

    assert(successEvents.some((event) => event.pid === json.successBridgePid && event.errorCode === 0), 'success event did not include the bridge PID with errorCode=0');
    assert(failureEvents.some((event) => event.errorCode === json.failureError), 'failure event did not carry the probe error code');

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        providerName,
        baselineRecordId,
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
        eventQuery: eventLog.query,
        eventQueryWaitMs: eventLog.waitedMs,
        events,
        counts: {
            total: events.length,
            attempt: attemptEvents.length,
            success: successEvents.length,
            failure: failureEvents.length
        },
        success: true
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_event_audit_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe.json'), `${systemProbe.reportContent.trim()}\n`);
        writeText(path.join(evidenceDir, 'eventlog.xml'), eventLog.stdout);
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
            `SERVICE_NAME=${providerName}`,
            `SESSION_ID=${json.sessionId}`,
            `SUCCESS_BRIDGE_PID=${json.successBridgePid}`,
            `ATTEMPT_EVENT_ID=${attemptEventId}`,
            `OUTCOME_EVENT_ID=${outcomeEventId}`,
            `BASELINE_RECORD_ID=${baselineRecordId}`,
            `NEW_EVENT_COUNT=${events.length}`,
            `ATTEMPT_EVENT_COUNT=${attemptEvents.length}`,
            `SUCCESS_EVENT_COUNT=${successEvents.length}`,
            `FAILURE_EVENT_COUNT=${failureEvents.length}`,
            `FAILURE_ERROR=${json.failureError}`,
            `FAILURE_DELAY_MS=${json.failureDelayMs}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
