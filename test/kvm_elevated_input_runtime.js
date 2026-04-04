const fs = require('fs');
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

function removeIfExists(filePath) {
    try {
        fs.unlinkSync(filePath);
    } catch (error) {
        if (!error || error.code !== 'ENOENT') {
            throw error;
        }
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForFile(filePath, timeoutMs, intervalMs) {
    const start = Date.now();
    while ((Date.now() - start) < timeoutMs) {
        if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) {
            return;
        }
        await sleep(intervalMs);
    }
    throw new Error(`Timed out waiting for file: ${filePath}`);
}

function execFileText(exePath, args) {
    return childProcess.spawnSync(exePath, args, {
        windowsHide: true,
        encoding: 'utf8'
    });
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const outputDir = evidenceDir || path.resolve('tmp', `kvm-elevated-input-${Date.now()}`);
    const probeStdoutPath = path.join(outputDir, 'probe_stdout.json');
    const probeStderrPath = path.join(outputDir, 'probe_stderr.txt');
    const taskQueryPath = path.join(outputDir, 'task_query.txt');
    const cmdPath = path.join(outputDir, 'run_probe.cmd');
    const taskName = `MeshAgentKvmElevatedInput_${Date.now()}`;
    const taskDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });

    assert(fs.existsSync(exePath), `probe executable missing at ${exePath}`);
    ensureDir(outputDir);
    removeIfExists(probeStdoutPath);
    removeIfExists(probeStderrPath);
    removeIfExists(taskQueryPath);

    fs.writeFileSync(cmdPath, `@echo off\r\n"${exePath}" -kvm-elevated-input-probe > "${probeStdoutPath}" 2> "${probeStderrPath}"\r\n`, 'ascii');

    let taskQuery = '';
    try {
        execFileText('schtasks', ['/Create', '/TN', taskName, '/SC', 'ONCE', '/SD', taskDate, '/ST', '23:59', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/TR', cmdPath, '/F']);
        execFileText('schtasks', ['/Run', '/TN', taskName]);
        await waitForFile(probeStdoutPath, 120000, 1000);
        taskQuery = (execFileText('schtasks', ['/Query', '/TN', taskName, '/V', '/FO', 'LIST']).stdout || '').trim();
        writeText(taskQueryPath, taskQuery + '\n');
    } finally {
        execFileText('schtasks', ['/Delete', '/TN', taskName, '/F']);
    }

    const stdout = fs.existsSync(probeStdoutPath) ? fs.readFileSync(probeStdoutPath, 'utf8') : '';
    const stderr = fs.existsSync(probeStderrPath) ? fs.readFileSync(probeStderrPath, 'utf8') : '';
    let json = null;
    try {
        json = JSON.parse(stdout.trim());
    } catch (error) {
        throw new Error(`Failed to parse probe JSON\nstdout:\n${stdout}\nstderr:\n${stderr}\nparse error: ${error.message}`);
    }

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
        taskName,
        taskQuery,
        probe: json
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_elevated_input_runtime.json'), report);
        writeText(path.join(evidenceDir, 'probe_stdout.json'), stdout.trim() + '\n');
        writeText(path.join(evidenceDir, 'probe_stderr.txt'), stderr);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
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
