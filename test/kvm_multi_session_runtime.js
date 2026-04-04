const fs = require('fs');
const path = require('path');
const {
    assert,
    parseArgs,
    readJsonText,
    runCommand,
    runSystemProbeWithPsExec,
    writeJson,
    writeText
} = require('./lib/kvm_runtime_helpers');

function parseQwinsta(output) {
    const sessions = [];
    const lines = String(output || '').split(/\r?\n/);
    for (const rawLine of lines) {
        const line = rawLine.trimEnd();
        if (!line || /^SESSIONNAME/i.test(line)) {
            continue;
        }
        const normalized = line.replace(/^>/, ' ').trim();
        const parts = normalized.split(/\s{2,}/).map((part) => part.trim()).filter((part) => part.length > 0);
        if (parts.length < 3) {
            continue;
        }

        let sessionName = '';
        let username = '';
        let idText = '';
        let state = '';

        if (parts.length === 3) {
            [sessionName, idText, state] = parts;
        } else {
            [sessionName, username, idText, state] = parts;
        }

        const id = Number.parseInt(idText, 10);
        if (!Number.isFinite(id)) {
            continue;
        }

        sessions.push({
            sessionName,
            username,
            id,
            state
        });
    }
    return sessions;
}

function chooseSessions(sessions) {
    const eligible = sessions.filter((session) => session.id > 0 && !/^services$/i.test(session.sessionName));
    const primary = eligible.find((session) => /^console$/i.test(session.sessionName) && /^active$/i.test(session.state))
        || eligible.find((session) => /^active$/i.test(session.state))
        || eligible.find((session) => /^conn/i.test(session.state))
        || eligible[0]
        || null;

    let alternate = null;
    if (primary) {
        alternate = eligible.find((session) => session.id !== primary.id && /^active$/i.test(session.state))
            || eligible.find((session) => session.id !== primary.id && /^conn/i.test(session.state))
            || null;
    }

    return {
        primary,
        alternate,
        sessions: eligible
    };
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);

    const qwinsta = runCommand('qwinsta', [], {
        timeoutMs: 15000
    });
    assert(qwinsta.status === 0, `qwinsta failed\nstdout:\n${qwinsta.stdout}\nstderr:\n${qwinsta.stderr}`);

    const topology = chooseSessions(parseQwinsta(qwinsta.stdout || ''));
    assert(topology.primary != null, 'unable to identify a primary interactive session from qwinsta');

    const probeArgument = topology.alternate
        ? `-kvm-multi-session-probe ${topology.primary.id} ${topology.alternate.id}`
        : `-kvm-multi-session-probe ${topology.primary.id}`;

    const systemProbe = await runSystemProbeWithPsExec(exePath, probeArgument, {
        prefix: `meshagent_kvm_multisession_${process.pid}_${Date.now()}`,
        timeoutMs: 180000
    });
    const json = readJsonText('kvm-multi-session-probe', systemProbe.reportContent);

    assert(json.success === true, 'multi-session probe reported failure');
    assert(json.primarySessionId === topology.primary.id, `primary session mismatch (${json.primarySessionId} != ${topology.primary.id})`);
    assert(json.chainStarted === true, 'probe chain did not start');
    assert(json.registeredContextCountAfterStart >= 2, `expected at least 2 relay contexts, got ${json.registeredContextCountAfterStart}`);
    assert(json.registeredContextCountAfterCleanup === 0, `relay contexts were not released after cleanup (${json.registeredContextCountAfterCleanup})`);
    assert(json.relay1Started === true && json.relay2Started === true, 'one or more relays did not start');
    assert(json.relay1Spawned === true && json.relay2Spawned === true, 'one or more relays did not spawn');
    assert(json.relay1PacketsReady === true && json.relay2PacketsReady === true, 'one or more relays did not produce packets');
    assert(json.relay1TransportActive === true && json.relay2TransportActive === true, 'one or more relay transports were inactive');
    assert(json.relay1BridgeUsed === true && json.relay2BridgeUsed === true, 'bridge transport was not used for both relays');
    assert(json.relay1FallbackUsed === false && json.relay2FallbackUsed === false, 'legacy fallback was used unexpectedly');
    assert(json.relay1Pid > 0 && json.relay2Pid > 0, `invalid relay pids ${json.relay1Pid}, ${json.relay2Pid}`);
    assert(json.relay1Pid !== json.relay2Pid, `relays did not get distinct helper pids (${json.relay1Pid})`);
    assert(json.relay1ProcessSessionId === topology.primary.id, `relay1 process session mismatch (${json.relay1ProcessSessionId} != ${topology.primary.id})`);
    assert(json.relay1IsolatedPacketsReady === true, 'relay1 isolated refresh did not complete');
    assert(json.relay2IsolatedPacketsReady === true, 'relay2 isolated refresh did not complete');
    assert(json.relay1Phase1Delta > 0, `relay1 phase1 delta was not positive (${json.relay1Phase1Delta})`);
    assert(json.relay2Phase1Delta === 0, `relay2 phase1 delta should be zero (${json.relay2Phase1Delta})`);
    assert(json.relay1Phase2Delta === 0, `relay1 phase2 delta should be zero (${json.relay1Phase2Delta})`);
    assert(json.relay2Phase2Delta > 0, `relay2 phase2 delta was not positive (${json.relay2Phase2Delta})`);
    assert(json.cleanup1Exited === true && json.cleanup2Exited === true, 'relay cleanup did not stop both helpers');
    assert(json.chainThreadWaitResult === 0, `unexpected chain thread wait result ${json.chainThreadWaitResult}`);

    let distinctSessionRuntime = false;
    if (topology.alternate) {
        distinctSessionRuntime = true;
        assert(json.secondaryRequestedTsid === topology.alternate.id, `secondary session mismatch (${json.secondaryRequestedTsid} != ${topology.alternate.id})`);
        assert(json.relay2ProcessSessionId === topology.alternate.id, `relay2 process session mismatch (${json.relay2ProcessSessionId} != ${topology.alternate.id})`);
    } else {
        assert(json.secondaryRequestedTsid === -1, `expected dynamic secondary TSID, got ${json.secondaryRequestedTsid}`);
        assert(json.relay2ProcessSessionId !== 0 && json.relay2ProcessSessionId !== 0xFFFFFFFF, `invalid relay2 process session ${json.relay2ProcessSessionId}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        probeArgument,
        qwinstaStdout: qwinsta.stdout || '',
        qwinstaStderr: qwinsta.stderr || '',
        parsedSessions: topology.sessions,
        primarySession: topology.primary,
        alternateSession: topology.alternate,
        distinctSessionRuntime,
        psexecPath: systemProbe.psexecPath,
        taskReportPath: systemProbe.reportPath,
        taskScriptPath: systemProbe.scriptPath,
        psexecExitCode: systemProbe.psexec.status,
        psexecStdout: systemProbe.psexec.stdout || '',
        psexecStderr: systemProbe.psexec.stderr || '',
        probe: json,
        success: true
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_multi_session_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe.json'), `${systemProbe.reportContent.trim()}\n`);
        writeText(path.join(evidenceDir, 'qwinsta.txt'), report.qwinstaStdout);
        writeText(path.join(evidenceDir, 'psexec-stdout.txt'), report.psexecStdout);
        writeText(path.join(evidenceDir, 'psexec-stderr.txt'), report.psexecStderr);
        writeText(path.join(evidenceDir, 'runtime-summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `PRIMARY_SESSION_ID=${topology.primary.id}`,
            `SECONDARY_REQUESTED_TSID=${json.secondaryRequestedTsid}`,
            `RELAY1_PID=${json.relay1Pid}`,
            `RELAY2_PID=${json.relay2Pid}`,
            `RELAY1_PROCESS_SESSION_ID=${json.relay1ProcessSessionId}`,
            `RELAY2_PROCESS_SESSION_ID=${json.relay2ProcessSessionId}`,
            `DISTINCT_SESSION_RUNTIME=${distinctSessionRuntime}`,
            `REGISTERED_CONTEXTS_START=${json.registeredContextCountAfterStart}`,
            `REGISTERED_CONTEXTS_CLEANUP=${json.registeredContextCountAfterCleanup}`,
            `RELAY1_PHASE1_DELTA=${json.relay1Phase1Delta}`,
            `RELAY2_PHASE1_DELTA=${json.relay2Phase1Delta}`,
            `RELAY1_PHASE2_DELTA=${json.relay1Phase2Delta}`,
            `RELAY2_PHASE2_DELTA=${json.relay2Phase2Delta}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
