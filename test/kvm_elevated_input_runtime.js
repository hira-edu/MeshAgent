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
    const outputDir = evidenceDir || path.resolve('tmp', `kvm-elevated-input-${Date.now()}`);
    const probeStdoutPath = path.join(outputDir, 'probe_stdout.json');

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    assert(fs.existsSync(dllPath), `bridge DLL missing at ${dllPath}`);
    ensureDir(outputDir);

    const systemProbe = await runSystemRundll32ProbeTask(dllPath, '-kvm-elevated-input-probe', {
        prefix: `MeshAgentKvmElevatedInput_${Date.now()}`,
        reportPath: probeStdoutPath,
        timeoutMs: 120000
    });
    const stdout = systemProbe.reportContent;
    const json = readJsonText('kvm-elevated-input-probe', stdout);

    assert(json.success === true, 'probe reported failure');
    assert(json.bridgeUsed === true, 'rundll32 bridge was not used');
    assert(json.fallbackUsed === false, 'legacy fallback path was used unexpectedly');
    assert(json.bridgeSystemSid === true, 'bridge helper did not retain SYSTEM SID');
    assert((json.bridgeIntegrityRid >>> 0) >= 0x4000, `bridge integrity level was not SYSTEM: ${json.bridgeIntegrityRid}`);
    assert(json.targetHighIntegrity === true, 'target cmd.exe was not elevated/high integrity');
    assert(json.inputSent === true, 'probe could not send KVM input packets');
    assert(json.capturedMatches === true, 'typed marker did not round-trip through elevated cmd.exe');
    assert(json.targetExited === true, 'target cmd.exe did not exit after input delivery');
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
        writeJson(path.join(evidenceDir, 'kvm_elevated_input_runtime.json'), report);
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
