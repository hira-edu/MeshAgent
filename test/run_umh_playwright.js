const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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

function runSpec(repoRoot, surface, evidenceDir) {
    const specPath = (surface === 'desktop'
        ? path.join('test', 'playwright', 'umh_operator_desktop.spec.js')
        : path.join('test', 'playwright', 'umh_operator_mobile.spec.js')).split(path.sep).join('/');
    const env = Object.assign({}, process.env, {
        UMH_PLAYWRIGHT_JSON: path.join(evidenceDir, 'playwright-results.json'),
        UMH_PLAYWRIGHT_OUTPUT_DIR: path.join(evidenceDir, 'artifacts')
    });

    let result;
    if (process.platform === 'win32') {
        const commandLine = `npx playwright test ${specPath} --config playwright.config.js`;
        result = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', commandLine], {
            cwd: repoRoot,
            encoding: 'utf8',
            env,
            timeout: 300000,
            windowsHide: true
        });
    } else {
        result = spawnSync('npx', ['playwright', 'test', specPath, '--config', 'playwright.config.js'], {
            cwd: repoRoot,
            encoding: 'utf8',
            env,
            timeout: 300000,
            windowsHide: true
        });
    }

    const record = {
        surface,
        exitCode: Number.isInteger(result.status) ? result.status : -1,
        signal: result.signal || null,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        error: result.error ? (result.error.stack || result.error.message || String(result.error)) : null
    };

    writeJson(path.join(evidenceDir, 'command.json'), record);
    writeText(path.join(evidenceDir, 'stdout.txt'), record.stdout);
    writeText(path.join(evidenceDir, 'stderr.txt'), record.stderr);
    writeText(path.join(evidenceDir, 'summary.txt'), [
        `SURFACE=${surface}`,
        `SUCCESS=${record.exitCode === 0 && !record.error}`,
        `EXIT_CODE=${record.exitCode}`,
        `ERROR=${record.error || ''}`
    ].join('\n') + '\n');
    return record;
}

function main() {
    const args = parseArgs(process.argv);
    const repoRoot = path.resolve(__dirname, '..');
    const evidenceRoot = args.evidence ? path.resolve(args.evidence) : path.join(repoRoot, 'test', 'playwright', 'evidence');
    const selected = (args.surface && args.surface !== 'all') ? [args.surface] : ['desktop', 'mobile'];
    const records = [];

    for (const surface of selected) {
        const evidenceDir = path.join(evidenceRoot, surface);
        ensureDir(evidenceDir);
        records.push(runSpec(repoRoot, surface, evidenceDir));
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: records.every((record) => record.exitCode === 0 && !record.error),
        records: records.map((record) => ({
            surface: record.surface,
            exitCode: record.exitCode,
            error: record.error
        }))
    };

    writeJson(path.join(evidenceRoot, 'playwright-summary.json'), report);
    writeText(path.join(evidenceRoot, 'summary.txt'), [
        `GENERATED_UTC=${report.generatedUtc}`,
        `SUCCESS=${report.success}`,
        ...report.records.map((record) => `SURFACE=${record.surface} EXIT_CODE=${record.exitCode} ERROR=${record.error || ''}`)
    ].join('\n') + '\n');

    if (!report.success) {
        process.exitCode = 1;
    }
}

main();
