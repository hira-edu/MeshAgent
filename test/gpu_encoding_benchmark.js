const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

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

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function runBenchmark(exePath, frames, outputPath) {
    const result = childProcess.spawnSync(exePath, ['-kvm-gpu-encoding-benchmark', String(frames)], {
        windowsHide: true,
        encoding: 'utf8',
        timeout: 120000,
        env: {
            ...process.env,
            MESH_GPU_BENCHMARK_JSON: outputPath
        }
    });
    const stdout = result.stdout || '';
    const stderr = result.stderr || '';
    const jsonText = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, 'utf8') : stdout.trim();
    let json;
    try {
        json = JSON.parse(jsonText.trim());
    } catch (error) {
        throw new Error(`Failed to parse benchmark JSON\nstatus=${result.status}\nstdout:\n${stdout}\nstderr:\n${stderr}\n${error.stack || error.message}`);
    }
    return {
        status: Number.isInteger(result.status) ? result.status : -1,
        signal: result.signal || null,
        stdout,
        stderr,
        jsonText,
        json
    };
}

function summarizeProvider(provider) {
    if (!provider) { return 'missing'; }
    if (provider.dllPresent === true && provider.requiredExportPresent !== false) { return 'runtime-export-present'; }
    if (provider.dllPresent === true) { return 'runtime-present-export-missing'; }
    return 'runtime-absent';
}

function buildResearchMarkdown(report) {
    const json = report.json;
    const nvenc = summarizeProvider(json.vendorProbe && json.vendorProbe.nvenc);
    const amf = summarizeProvider(json.vendorProbe && json.vendorProbe.amf);
    const qsvMft = json.vendorProbe && json.vendorProbe.qsvMft ? json.vendorProbe.qsvMft : {};
    const zero = json.zeroCopyDxgiToEncoderTexture || {};
    const jpeg = json.jpegReference || {};
    const adapters = Array.isArray(json.adapters) ? json.adapters : [];

    return [
        '# TODO-038 GPU Encoding Research Spike',
        '',
        `Generated UTC: ${new Date().toISOString()}`,
        '',
        '## Probe Results',
        '',
        `- NVENC: ${nvenc}`,
        `- AMF: ${amf}`,
        `- QSV hardware MFTs: H.264=${qsvMft.h264HardwareCount || 0}, HEVC=${qsvMft.hevcHardwareCount || 0}, Intel-class=${qsvMft.intelHardwareCount || 0}`,
        `- D3D11 adapters: ${adapters.map((item) => `${item.vendor}:${item.description}:keyedMutex=${item.keyedMutex}`).join('; ')}`,
        '',
        '## Zero-Copy DXGI-To-Encoder Texture Path',
        '',
        `- Success: ${zero.success === true}`,
        `- Size: ${zero.width || 0}x${zero.height || 0}`,
        `- Frames copied: ${zero.framesCopied || 0}`,
        `- Shared handle: ${zero.sharedHandleCreated === true}`,
        `- Opened on second D3D11 device: ${zero.openedOnEncoderDevice === true}`,
        `- IDXGIKeyedMutex synchronized: ${zero.keyedMutexSynchronized === true}`,
        `- GPU copy FPS: ${Number(zero.fps || 0).toFixed(3)}`,
        '',
        '## JPEG Reference',
        '',
        `- Success: ${jpeg.success === true}`,
        `- Capture backend: ${jpeg.captureBackend || 'unknown'} (${jpeg.captureReason || 'unknown'})`,
        `- Size: ${jpeg.width || 0}x${jpeg.height || 0}`,
        `- Frames encoded: ${jpeg.framesEncoded || 0}`,
        `- Average JPEG bytes: ${jpeg.averageBytes || 0}`,
        `- JPEG FPS: ${Number(jpeg.fps || 0).toFixed(3)}`,
        `- Process CPU ms: ${Number(jpeg.processCpuMs || 0).toFixed(3)}`,
        '',
        '## Recommendation',
        '',
        `${json.recommendation}`,
        '',
        'Production viewer codec negotiation remains disabled in this spike; fallback stays DXGI/WGC/GDI plus JPEG tiles.',
        ''
    ].join('\n');
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const frames = args.frames == null ? 5 : Number(args.frames);
    const exePath = args.exe ? path.resolve(args.exe) : path.resolve('meshservice', 'x64', 'StealthLab', 'MeshService-2022.exe');
    const outputDir = evidenceDir || fs.mkdtempSync(path.join(os.tmpdir(), 'gpu-encoding-benchmark-'));
    const outputPath = path.join(outputDir, 'gpu_encoding_benchmark.command.json');

    assert(Number.isInteger(frames) && frames >= 1 && frames <= 120, `Invalid --frames value: ${args.frames}`);
    assert(fs.existsSync(exePath), `Benchmark executable not found: ${exePath}`);

    ensureDir(outputDir);
    const report = runBenchmark(exePath, frames, outputPath);
    const json = report.json;
    const zero = json.zeroCopyDxgiToEncoderTexture || {};
    const jpeg = json.jpegReference || {};
    const vendorProbe = json.vendorProbe || {};
    const qsvMft = vendorProbe.qsvMft || {};
    const adapters = Array.isArray(json.adapters) ? json.adapters : [];

    assert(report.status === 0, `Benchmark command exited ${report.status}`);
    assert(json.success === true, 'Benchmark JSON did not report success');
    assert(json.productionPathChanged === false, 'Spike must not change production path');
    assert(json.viewerCodecNegotiationImplemented === false, 'Spike must not claim viewer codec negotiation');
    assert(zero.success === true, 'Zero-copy DXGI-to-shared-texture path did not validate');
    assert(zero.sharedHandleCreated === true, 'Shared texture handle was not created');
    assert(zero.openedOnEncoderDevice === true, 'Shared texture was not opened on encoder device');
    assert(zero.keyedMutexSynchronized === true, 'IDXGIKeyedMutex synchronization failed');
    assert(jpeg.success === true, 'JPEG reference benchmark failed');
    assert(jpeg.framesEncoded === frames, `JPEG encoded ${jpeg.framesEncoded}, expected ${frames}`);
    assert(adapters.some((item) => item.keyedMutex === true), 'No adapter validated keyed-mutex shared textures');
    assert(
        (vendorProbe.nvenc && vendorProbe.nvenc.dllPresent === true) ||
        (vendorProbe.amf && vendorProbe.amf.dllPresent === true) ||
        (qsvMft.h264HardwareCount > 0 || qsvMft.hevcHardwareCount > 0),
        'No NVENC/AMF/QSV-class encoder probe was present'
    );
    assert(typeof json.recommendation === 'string' && json.recommendation.length > 0, 'Recommendation missing');

    const researchMarkdown = buildResearchMarkdown(report);
    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'gpu_encoding_benchmark.json'), json);
        writeText(path.join(evidenceDir, 'gpu_encoding_benchmark.command.json'), report.jsonText);
        writeText(path.join(evidenceDir, 'gpu_encoding_benchmark.stdout.json'), report.stdout);
        writeText(path.join(evidenceDir, 'gpu_encoding_benchmark.stderr.txt'), report.stderr);
        writeText(path.join(evidenceDir, 'research_spike.md'), researchMarkdown);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${new Date().toISOString()}`,
            'SUCCESS=true',
            `EXE=${exePath}`,
            `FRAMES=${frames}`,
            `NVENC=${summarizeProvider(vendorProbe.nvenc)}`,
            `AMF=${summarizeProvider(vendorProbe.amf)}`,
            `QSV_H264_MFT_COUNT=${qsvMft.h264HardwareCount || 0}`,
            `QSV_HEVC_MFT_COUNT=${qsvMft.hevcHardwareCount || 0}`,
            `QSV_INTEL_MFT_COUNT=${qsvMft.intelHardwareCount || 0}`,
            `ZERO_COPY_SUCCESS=${zero.success === true}`,
            `ZERO_COPY_FRAMES=${zero.framesCopied || 0}`,
            `ZERO_COPY_FPS=${Number(zero.fps || 0).toFixed(3)}`,
            `JPEG_SUCCESS=${jpeg.success === true}`,
            `JPEG_FRAMES=${jpeg.framesEncoded || 0}`,
            `JPEG_FPS=${Number(jpeg.fps || 0).toFixed(3)}`,
            `JPEG_AVG_BYTES=${jpeg.averageBytes || 0}`,
            `RECOMMENDATION=${json.recommendation}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(researchMarkdown);
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
