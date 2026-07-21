const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { buildKvmPacket, resolveBridgeDllPath, resolveRundll32Path } = require('./lib/kvm_runtime_helpers');

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

function psQuote(value) {
    return String(value).replace(/'/g, "''");
}

function measureBrightness(imagePath) {
    const command = [
        "$ErrorActionPreference='Stop'",
        'Add-Type -AssemblyName System.Drawing',
        `$bmp=[System.Drawing.Bitmap]::FromFile('${psQuote(imagePath)}')`,
        'try {',
        '$sum=0.0; $count=0; $nonBlack=0',
        '$stepX=[Math]::Max(1,[int]($bmp.Width / 64))',
        '$stepY=[Math]::Max(1,[int]($bmp.Height / 64))',
        'for ($y = 0; $y -lt $bmp.Height; $y += $stepY) {',
        '  for ($x = 0; $x -lt $bmp.Width; $x += $stepX) {',
        '    $c = $bmp.GetPixel($x, $y)',
        '    $sum += ($c.R + $c.G + $c.B) / 3.0',
        '    if (($c.R -gt 8) -or ($c.G -gt 8) -or ($c.B -gt 8)) { $nonBlack++ }',
        '    $count++',
        '  }',
        '}',
        '[pscustomobject]@{width=$bmp.Width;height=$bmp.Height;samples=$count;avgBrightness=[Math]::Round(($sum / [Math]::Max(1,$count)),2);nonBlackSamples=$nonBlack} | ConvertTo-Json -Compress',
        '} finally { $bmp.Dispose() }'
    ].join('; ');
    const result = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', command], {
        encoding: 'utf8',
        windowsHide: true
    });
    if (result.error) {
        throw result.error;
    }
    if (result.status !== 0) {
        throw new Error(`brightness probe failed: exit=${result.status} stdout=${result.stdout} stderr=${result.stderr}`);
    }
    return JSON.parse(result.stdout);
}

function launchAnimationWindow(label) {
    const script = [
        'Add-Type -AssemblyName System.Windows.Forms',
        'Add-Type -AssemblyName System.Drawing',
        '$form = New-Object Windows.Forms.Form',
        `$form.Text = '${label.replace(/'/g, "''")}'`,
        "$form.StartPosition = 'Manual'",
        '$form.Location = New-Object Drawing.Point(48, 48)',
        '$form.Size = New-Object Drawing.Size(720, 420)',
        '$form.TopMost = $true',
        '$label = New-Object Windows.Forms.Label',
        "$label.Dock = 'Fill'",
        "$label.TextAlign = 'MiddleCenter'",
        "$label.Font = New-Object Drawing.Font('Segoe UI', 28, [Drawing.FontStyle]::Bold)",
        '$form.Controls.Add($label)',
        '$colors = @([Drawing.Color]::Red, [Drawing.Color]::Lime, [Drawing.Color]::Blue, [Drawing.Color]::Yellow, [Drawing.Color]::Orange, [Drawing.Color]::Cyan)',
        '$form.Show()',
        'for ($i = 0; $i -lt 16; $i++) {',
        '  $form.BackColor = $colors[$i % $colors.Count]',
        "  $label.Text = '" + label.replace(/'/g, "''") + " ' + $i",
        '  $form.Refresh()',
        '  Start-Sleep -Milliseconds 350',
        '}',
        '$form.Close()'
    ].join('; ');

    return spawn('powershell', ['-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-Command', script], {
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'ignore']
    });
}

function captureFirstFrame(exePath, dllPath, backend, outDir) {
    return new Promise((resolve, reject) => {
        const framePath = path.join(outDir, `first-frame-${backend}.jpg`);
        const controlPipeName = `\\\\.\\pipe\\MeshKvm_${process.pid}_${Date.now()}_${backend}_in`;
        const dataPipeName = `\\\\.\\pipe\\MeshKvm_${process.pid}_${Date.now()}_${backend}_out`;
        const stderrChunks = [];
        const stdoutChunks = [];
        let settled = false;
        let remainder = Buffer.alloc(0);
        let controlSocket = null;
        let dataSocket = null;
        let childExited = false;

        const env = { ...process.env };

        const finish = (error, payload) => {
            if (settled) { return; }
            settled = true;
            clearTimeout(timeoutHandle);
            try { if (controlSocket != null) { controlSocket.destroy(); } } catch {}
            try { if (dataSocket != null) { dataSocket.destroy(); } } catch {}
            try { controlServer.close(); } catch {}
            try { dataServer.close(); } catch {}
            try { child.kill(); } catch {}
            if (error) {
                reject(error);
            } else {
                resolve(payload);
            }
        };

        const parseChunk = (chunk, child) => {
            remainder = Buffer.concat([remainder, chunk]);
            let offset = 0;
            while ((remainder.length - offset) >= 4) {
                const type = remainder.readUInt16BE(offset);
                let size = remainder.readUInt16BE(offset + 2);
                if (type === 27) {
                    if ((remainder.length - offset) < 8) { break; }
                    size = 8 + remainder.readUInt32BE(offset + 4);
                }
                if (size < 4 || (remainder.length - offset) < size) { break; }
                if (type === 3) {
                    fs.writeFileSync(framePath, remainder.subarray(offset + 4, offset + size));
                    finish(null, {
                        framePath,
                        stderr: Buffer.concat(stderrChunks).toString('utf8'),
                        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                        packetBytes: size - 4
                    });
                    return;
                }
                if (type === 27) {
                    const inner = remainder.subarray(offset + 8, offset + size);
                    if (inner.length >= 8 && inner.readUInt16BE(0) === 3) {
                        fs.writeFileSync(framePath, inner.subarray(8));
                        finish(null, {
                            framePath,
                            stderr: Buffer.concat(stderrChunks).toString('utf8'),
                            stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                            packetBytes: inner.length - 8
                        });
                        return;
                    }
                }
                offset += size;
            }
            remainder = remainder.subarray(offset);
        };

        const controlServer = net.createServer((conn) => {
            controlSocket = conn;
            setTimeout(() => {
                try {
                    controlSocket.write(buildKvmPacket(5, Buffer.from([1, 50, 0x04, 0x00, 0x00, 0x64])));
                    controlSocket.write(buildKvmPacket(8, Buffer.from([0])));
                    controlSocket.write(buildKvmPacket(87, Buffer.from([2])));
                    controlSocket.write(buildKvmPacket(6));
                } catch (error) {
                    finish(error);
                }
            }, 500);
            setTimeout(() => {
                try {
                    controlSocket.write(buildKvmPacket(6));
                } catch (error) {
                    finish(error);
                }
            }, 2500);
            setTimeout(() => {
                try {
                    controlSocket.write(buildKvmPacket(6));
                } catch (error) {
                    finish(error);
                }
            }, 5000);
        });
        const dataServer = net.createServer((conn) => {
            dataSocket = conn;
            conn.on('data', (chunk) => parseChunk(chunk, child));
        });
        controlServer.on('error', (error) => finish(error));
        dataServer.on('error', (error) => finish(error));

        const child = spawn(resolveRundll32Path(), [`${dllPath},KvmSessionBridgeW`, controlPipeName, dataPipeName], {
            env,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true
        });

        const timeoutHandle = setTimeout(() => {
            finish(new Error(`Timed out waiting for first frame (${backend}) stderr=${Buffer.concat(stderrChunks).toString('utf8')}`));
        }, 15000);

        child.on('error', (error) => finish(error));
        child.on('exit', (code, signal) => {
            childExited = true;
            if (!settled) {
                finish(new Error(`KVM child exited before first frame (${backend}) code=${code} signal=${signal} stderr=${Buffer.concat(stderrChunks).toString('utf8')}`));
            }
        });
        child.stderr.on('data', (chunk) => {
            stderrChunks.push(Buffer.from(chunk));
        });
        child.stdout.on('data', (chunk) => stdoutChunks.push(Buffer.from(chunk)));

        controlServer.listen(controlPipeName, () => {
            dataServer.listen(dataPipeName, () => {
                if (childExited && !settled) {
                    finish(new Error(`KVM child exited before pipe connection (${backend}) stderr=${Buffer.concat(stderrChunks).toString('utf8')}`));
                }
            });
        });
    });
}

async function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const exePath = args.exe
        ? path.resolve(args.exe)
        : path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const dllPath = resolveBridgeDllPath(exePath, args.dll ? path.resolve(args.dll) : null);
    const minBrightness = Number(args['min-brightness'] || '5');
    const scenarios = ['gdi'];

    assert(fs.existsSync(exePath), `KVM executable missing: ${exePath}`);
    assert(fs.existsSync(dllPath), `KVM bridge DLL missing: ${dllPath}`);

    const workDir = evidenceDir || fs.mkdtempSync(path.join(os.tmpdir(), 'kvm-initial-frame-'));
    ensureDir(workDir);

    const report = {
        generatedUtc: new Date().toISOString(),
        exePath,
        dllPath,
        minBrightness,
        scenarios: []
    };

    for (const backend of scenarios) {
        const scenarioDir = path.join(workDir, backend);
        ensureDir(scenarioDir);
        const animation = launchAnimationWindow(`KVM ${backend.toUpperCase()}`);
        let capture;
        try {
            await new Promise((resolve) => setTimeout(resolve, 350));
            capture = await captureFirstFrame(exePath, dllPath, backend === 'auto' ? 'auto' : backend, scenarioDir);
        } finally {
            try { animation.kill(); } catch {}
        }
        const metrics = measureBrightness(capture.framePath);
        const scenario = {
            backend,
            framePath: capture.framePath,
            packetBytes: capture.packetBytes,
            stderr: capture.stderr,
            metrics
        };
        report.scenarios.push(scenario);
        assert(metrics.avgBrightness > minBrightness, `${backend} first frame was effectively black (avgBrightness=${metrics.avgBrightness})`);
    }

    report.success = true;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_initial_frame_runtime.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `EXE=${exePath}`,
            `DLL=${dllPath}`,
            `MIN_BRIGHTNESS=${minBrightness}`,
            `SCENARIOS=${report.scenarios.map((scenario) => `${scenario.backend}:${scenario.metrics.avgBrightness}`).join(',')}`,
            'SUCCESS=true'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
});
