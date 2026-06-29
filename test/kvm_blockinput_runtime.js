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

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = resolveBridgeDllPath(exePath, args.dll);
    const outputDir = evidenceDir || path.resolve('tmp', `kvm-blockinput-${Date.now()}`);
    const probeStdoutPath = path.join(outputDir, 'probe_stdout.json');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);
    ensureDir(outputDir);

    const systemProbe = await runSystemRundll32ProbeTask(dllPath, '-kvm-blockinput-probe', {
        prefix: `MeshAgentKvmBlockInput_${Date.now()}`,
        reportPath: probeStdoutPath,
        timeoutMs: 120000
    });
    const stdout = systemProbe.reportContent;
    const json = readJsonText('kvm-blockinput-probe', stdout);

    assert(json.success === true, 'probe reported failure');
    assert(json.bridgeUsed === true, 'rundll32 bridge was not used');
    assert(json.fallbackUsed === false, 'legacy fallback path was used unexpectedly');
    assert(json.bridgeSystemSid === true, 'bridge helper did not retain SYSTEM SID');
    assert((json.bridgeIntegrityRid >>> 0) >= 0x4000, `bridge integrity level was not SYSTEM: ${json.bridgeIntegrityRid}`);
    assert(json.targetHighIntegrity === true, 'target process was not elevated/high integrity');
    assert(json.blockerSpawned === true, 'blocker process did not spawn');
    assert(json.blockerReady === true, 'blocker process never signaled ready');
    assert(json.blockerReportAvailable === true, 'blocker JSON report was not captured');
    assert(json.blockerSuccess === true, 'blocker failed BlockInput acquisition or same-thread SendInput proof');
    assert(json.blockerBlockInputEnabled === true, 'blocker never acquired BlockInput(TRUE)');
    assert(json.blockerSameThreadSendInputSucceeded === true, 'same-thread SendInput did not succeed under BlockInput(TRUE)');
    assert(json.inputSent === true, 'probe could not send KVM input packets');
    assert(json.capturedMatches === true, 'typed marker did not round-trip while BlockInput(TRUE) was active');
    assert(json.targetExited === true, 'target process did not exit after input delivery');
    assert(json.blockerExited === true, 'blocker process did not exit during cleanup');
    assert(json.cleanupExited === true, 'bridge helper did not exit during cleanup');

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
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
        probe: json
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_blockinput_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe_stdout.json'), stdout.trim() + '\n');
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
            `BRIDGE_PID=${json.bridgePid}`,
            `BRIDGE_INTEGRITY_RID=${json.bridgeIntegrityRid}`,
            `TARGET_PID=${json.targetPid}`,
            `TARGET_INTEGRITY_RID=${json.targetIntegrityRid}`,
            `BLOCKER_EXIT_CODE=${json.blockerExitCode}`,
            `MARKER=${json.marker}`,
            `CAPTURED_TEXT=${json.capturedText}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
