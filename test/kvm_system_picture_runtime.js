const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const {
    assert,
    parseArgs,
    resolveBridgeDllPath,
    resolveRundll32Path,
    runSystemScheduledTask,
    waitForReadableFile,
    writeJson,
    writeText
} = require('./lib/kvm_runtime_helpers');

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForJsonReport(filePath, timeoutMs, predicate, label) {
    const started = Date.now();
    let lastText = '';
    let lastError = null;

    while ((Date.now() - started) < timeoutMs) {
        try {
            lastText = await waitForReadableFile(filePath, 1000);
            const json = JSON.parse(lastText.trim());
            if (!predicate || predicate(json)) {
                return { text: lastText, json };
            }
        } catch (error) {
            lastError = error;
        }
        await sleep(500);
    }

    throw new Error(`Timed out waiting for ${label}; lastError=${lastError ? lastError.message : '(none)'}; lastText=${lastText.slice(0, 1000)}`);
}

function createCollectorScript(scriptPath) {
    const script = [
        "const fs = require('fs');",
        "const cp = require('child_process');",
        "const net = require('net');",
        "const rundll32 = process.argv[2];",
        "const dll = process.argv[3];",
        "const reportPath = process.argv[4];",
        "function pkt(type, payload) {",
        "    const body = Buffer.from(payload || []);",
        "    const packet = Buffer.alloc(4 + body.length);",
        "    packet.writeUInt16BE(type, 0);",
        "    packet.writeUInt16BE(packet.length, 2);",
        "    body.copy(packet, 4);",
        "    return packet;",
        "}",
        "const controlPipeName = `\\\\\\\\.\\\\pipe\\\\MeshKvm_${process.pid}_${Date.now()}_in`;",
        "const dataPipeName = `\\\\\\\\.\\\\pipe\\\\MeshKvm_${process.pid}_${Date.now()}_out`;",
        "let buffer = Buffer.alloc(0);",
        "let stderr = '';",
        "let stdout = '';",
        "const counts = {};",
        "const pictures = [];",
        "let lastPacketAt = null;",
        "let child = null;",
        "let keepalive = null;",
        "let controlConn = null;",
        "let dataConn = null;",
        "function note(type, size) {",
        "    counts[type] = (counts[type] || 0) + 1;",
        "    lastPacketAt = Date.now();",
        "    if (type === 3 || type === 27) { pictures.push({ type, size, t: Date.now() }); }",
        "}",
        "function parse() {",
        "    let offset = 0;",
        "    while ((buffer.length - offset) >= 4) {",
        "        let type = buffer.readUInt16BE(offset);",
        "        let size = buffer.readUInt16BE(offset + 2);",
        "        if (type === 27) {",
        "            if ((buffer.length - offset) < 8) { break; }",
        "            size = 8 + buffer.readUInt32BE(offset + 4);",
        "        }",
        "        if (size < 4 || (buffer.length - offset) < size) { break; }",
        "        note(type, size);",
        "        offset += size;",
        "    }",
        "    if (offset > 0) { buffer = buffer.slice(offset); }",
        "}",
        "function flush(tag) {",
        "    fs.writeFileSync(reportPath, JSON.stringify({",
        "        rundll32,",
        "        dll,",
        "        controlPipeName,",
        "        dataPipeName,",
        "        tag,",
        "        counts,",
        "        pictures,",
        "        lastPacketAt,",
        "        stdout,",
        "        stderr,",
        "        now: new Date().toISOString()",
        "    }, null, 2));",
        "}",
        "const controlServer = net.createServer((conn) => {",
        "    controlConn = conn;",
        "    setTimeout(() => {",
        "        try {",
        "            controlConn.write(pkt(5, [1, 50, 0x04, 0x00, 0x00, 0x64]));",
        "            controlConn.write(pkt(8, [0]));",
        "            controlConn.write(pkt(87, [2]));",
        "            controlConn.write(pkt(6));",
        "            flush('write1');",
        "        } catch (e) {",
        "            stderr += '\\nWRITE1:' + e.message;",
        "            flush('write1err');",
        "        }",
        "    }, 500);",
        "    setTimeout(() => {",
        "        try { controlConn.write(pkt(6)); flush('write2'); } catch (e) { stderr += '\\nWRITE2:' + e.message; flush('write2err'); }",
        "    }, 2500);",
        "    setTimeout(() => {",
        "        try { controlConn.write(pkt(6)); flush('write3'); } catch (e) { stderr += '\\nWRITE3:' + e.message; flush('write3err'); }",
        "    }, 5000);",
        "    keepalive = setInterval(() => {",
        "        try {",
        "            controlConn.write(Buffer.from([0x00, 0xFF, 0x00, 0x04]));",
        "        } catch (e) {",
        "            stderr += '\\nKEEPALIVE:' + e.message;",
        "            flush('keepaliveerr');",
        "        }",
        "    }, 100);",
        "    setTimeout(() => {",
        "        try { if (keepalive) { clearInterval(keepalive); keepalive = null; } if (controlConn) { controlConn.destroy(); } if (dataConn) { dataConn.destroy(); } flush('pipe-end'); } catch (e) { stderr += '\\nEND:' + e.message; flush('pipe-end-err'); }",
        "    }, 9000);",
        "});",
        "const dataServer = net.createServer((conn) => {",
        "    dataConn = conn;",
        "    conn.on('data', (chunk) => { buffer = Buffer.concat([buffer, chunk]); parse(); flush('data'); });",
        "});",
        "controlServer.listen(controlPipeName, () => {",
        "    dataServer.listen(dataPipeName, () => {",
        "        child = cp.spawn(rundll32, [`${dll},KvmSessionBridgeW`, controlPipeName, dataPipeName], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: process.env });",
        "    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); flush('stdout'); });",
        "    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); flush('stderr'); });",
        "    child.on('exit', (code, signal) => {",
        "        fs.writeFileSync(reportPath, JSON.stringify({",
        "            rundll32,",
        "            dll,",
        "            controlPipeName,",
        "            dataPipeName,",
        "            tag: 'exit',",
        "            exitCode: code,",
        "            exitSignal: signal,",
        "            counts,",
        "            pictures,",
        "            lastPacketAt,",
        "            stdout,",
        "            stderr,",
        "            now: new Date().toISOString()",
        "        }, null, 2));",
        "    });",
        "    child.on('error', (error) => { stderr += '\\nSPAWN:' + error.message; flush('spawnerr'); });",
        "    });",
        "});",
        "setTimeout(() => { flush('timeout'); process.exit(0); }, 20000);"
    ].join('\n');
    fs.writeFileSync(scriptPath, script, 'ascii');
}

function createAnimationScript(scriptPath) {
    const script = [
        "Add-Type -AssemblyName System.Windows.Forms",
        "Add-Type -AssemblyName System.Drawing",
        "$form = New-Object Windows.Forms.Form",
        "$form.Text = 'KVM Probe Window'",
        "$form.StartPosition = 'Manual'",
        "$form.Location = New-Object Drawing.Point(40, 40)",
        "$form.Size = New-Object Drawing.Size(640, 360)",
        "$form.TopMost = $true",
        "$label = New-Object Windows.Forms.Label",
        "$label.Dock = 'Fill'",
        "$label.TextAlign = 'MiddleCenter'",
        "$label.Font = New-Object Drawing.Font('Segoe UI', 28, [Drawing.FontStyle]::Bold)",
        "$form.Controls.Add($label)",
        "$colors = @([Drawing.Color]::Red, [Drawing.Color]::Lime, [Drawing.Color]::Blue, [Drawing.Color]::Yellow, [Drawing.Color]::Orange, [Drawing.Color]::Cyan)",
        "$form.Show()",
        "for ($i = 0; $i -lt 12; $i++) {",
        "    $form.BackColor = $colors[$i % $colors.Count]",
        "    $label.Text = 'FRAME ' + $i",
        "    $form.Refresh()",
        "    Start-Sleep -Milliseconds 500",
        "}",
        "$form.Close()"
    ].join('\r\n');
    fs.writeFileSync(scriptPath, `${script}\r\n`, 'ascii');
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = args.exe ? path.resolve(args.exe) : path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = resolveBridgeDllPath(exePath, args.dll ? path.resolve(args.dll) : null);
    const rundll32Path = resolveRundll32Path();
    const collectorPath = path.join(os.tmpdir(), `kvm_system_picture_${process.pid}_${Date.now()}.js`);
    const reportPath = path.join(os.tmpdir(), `kvm_system_picture_${process.pid}_${Date.now()}.json`);
    const animationPath = path.join(os.tmpdir(), `kvm_system_picture_${process.pid}_${Date.now()}.ps1`);

    assert(fs.existsSync(dllPath), `probe bridge DLL missing at ${dllPath}`);

    createCollectorScript(collectorPath);
    createAnimationScript(animationPath);

    const systemTask = await runSystemScheduledTask(process.execPath, [collectorPath, rundll32Path, dllPath, reportPath], {
        prefix: `meshagent_kvm_system_picture_${process.pid}_${Date.now()}`,
        reportPath,
        timeoutMs: 60000
    });

    await sleep(2000);

    const animation = childProcess.spawnSync('powershell', ['-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', animationPath], {
        windowsHide: true,
        encoding: 'utf8',
        timeout: 30000
    });
    if (animation.error) { throw animation.error; }
    assert(animation.status === 0, `animation failed: exit=${animation.status} stdout=${animation.stdout} stderr=${animation.stderr}`);

    const finalReport = await waitForJsonReport(reportPath, 60000, (candidate) => {
        const pictureCount = Object.prototype.hasOwnProperty.call(candidate.counts || {}, '3') ? candidate.counts['3'] : 0;
        const jumboCount = Object.prototype.hasOwnProperty.call(candidate.counts || {}, '27') ? candidate.counts['27'] : 0;
        return (pictureCount + jumboCount) >= 2 || ['exit', 'timeout', 'pipe-end'].includes(candidate.tag);
    }, 'SYSTEM picture packet report');
    const reportText = finalReport.text;
    const report = finalReport.json;
    const pictureCount = Object.prototype.hasOwnProperty.call(report.counts || {}, '3') ? report.counts['3'] : 0;
    const jumboCount = Object.prototype.hasOwnProperty.call(report.counts || {}, '27') ? report.counts['27'] : 0;

    assert((pictureCount + jumboCount) >= 2, `expected repeated picture packets, got pictures=${pictureCount} jumbo=${jumboCount}`);
    assert(!/OpenInputDesktop failed/i.test(report.stderr || ''), `desktop bind still failing: ${report.stderr}`);
    assert(!/SetThreadDesktop failed/i.test(report.stderr || ''), `thread desktop bind still failing: ${report.stderr}`);

    const summary = [
        `GENERATED_UTC=${new Date().toISOString()}`,
        `SOURCE_EXE=${exePath}`,
        `DLL=${dllPath}`,
        `RUNDLL32=${rundll32Path}`,
        `SYSTEM_TASK=${systemTask.taskName}`,
        `PICTURE_PACKETS=${pictureCount}`,
        `JUMBO_PACKETS=${jumboCount}`,
        `TOTAL_PICTURE_EVENTS=${(report.pictures || []).length}`,
        `LAST_PACKET_AT=${report.lastPacketAt || 0}`
    ].join('\n') + '\n';

    if (evidenceDir) {
        ensureDir(evidenceDir);
        writeJson(path.join(evidenceDir, 'kvm_system_picture_runtime.json'), {
            generatedUtc: new Date().toISOString(),
            exePath,
            rundll32Path,
            systemTaskName: systemTask.taskName,
            systemTaskCommandLine: systemTask.commandLine,
            systemTaskCreateStdout: systemTask.create.stdout || '',
            systemTaskCreateStderr: systemTask.create.stderr || '',
            systemTaskRunStdout: systemTask.run.stdout || '',
            systemTaskRunStderr: systemTask.run.stderr || '',
            collectorPath,
            reportPath,
            animationPath,
            animation,
            report
        });
        writeText(path.join(evidenceDir, 'probe.json'), reportText.trim() + '\n');
        writeText(path.join(evidenceDir, 'schtasks-create-stdout.txt'), systemTask.create.stdout || '');
        writeText(path.join(evidenceDir, 'schtasks-create-stderr.txt'), systemTask.create.stderr || '');
        writeText(path.join(evidenceDir, 'schtasks-run-stdout.txt'), systemTask.run.stdout || '');
        writeText(path.join(evidenceDir, 'schtasks-run-stderr.txt'), systemTask.run.stderr || '');
        writeText(path.join(evidenceDir, 'animation.stdout.txt'), animation.stdout || '');
        writeText(path.join(evidenceDir, 'animation.stderr.txt'), animation.stderr || '');
        writeText(path.join(evidenceDir, 'summary.txt'), summary);
    } else {
        process.stdout.write(JSON.stringify({
            exePath,
            rundll32Path,
            systemTaskName: systemTask.taskName,
            report
        }, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
