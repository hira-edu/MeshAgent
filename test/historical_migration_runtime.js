// Destructive lifecycle validation on an explicitly approved Windows host.
// Builds belong to separate checkouts; every operation uses the native CLI.
const assert = require('assert');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const lifecycle = require('./lib/runtime_host_lifecycle');

const repo = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
assert(args.includes('--approved-host'), 'Requires an explicitly approved disposable host');
function option(name) { const i = args.indexOf(name); assert(i >= 0 && args[i + 1], `Missing ${name}`); return path.resolve(args[i + 1]); }
const fixture = option('--fixture-repo');
const evidence = option('--evidence');
const config = JSON.parse(fs.readFileSync(path.join(repo, 'branding_config.local.json'), 'utf8').replace(/^\uFEFF/, ''));
const oldConfig = JSON.parse(fs.readFileSync(path.join(fixture, 'branding_config.local.json'), 'utf8').replace(/^\uFEFF/, ''));
const installed = config.branding.installRoot;
const oldInstalled = oldConfig.branding.installRoot;
assert(path.resolve(installed) !== path.resolve(oldInstalled), 'Fixture must have a different install root');
assert(config.branding.serviceName !== oldConfig.branding.serviceName, 'Fixture must have a different SCM name');
fs.mkdirSync(evidence, { recursive: true });
const report = { startedUtc: new Date().toISOString(), operations: [], stage: 'preparing' };
function save() { fs.writeFileSync(path.join(evidence, 'status.json'), JSON.stringify(report, null, 2)); }
function run(label, file, argv, timeout = 600000) {
    const result = cp.spawnSync(file, argv, { cwd: repo, windowsHide: true, encoding: 'utf8', timeout });
    const record = { label, exitCode: result.status, stdout: result.stdout || '', stderr: result.stderr || '', error: result.error ? String(result.error) : null };
    report.operations.push(record); save();
    return record;
}
function checked(label, exe, argv) {
    const record = run(label, exe, argv);
    assert.strictEqual(record.exitCode, 0, `${label}: ${JSON.stringify(record)}`);
    if (argv.includes('--quiet')) assert(!record.stdout && !record.stderr, `${label} emitted quiet output`);
}
function copySource(root, leaf, disable) {
    const dir = path.join(evidence, leaf); fs.mkdirSync(dir, { recursive: true });
    const source = path.join(root, 'meshservice/x64/MeshServiceRuntime/MeshService-2022.exe');
    const exe = path.join(dir, `${leaf}.exe`);
    fs.copyFileSync(source, exe);
    if (disable !== null) {
        const msh = fs.readFileSync(path.join(path.dirname(source), 'MeshService-2022.msh'), 'utf8').replace(/^\uFEFF/, '').trimEnd();
        fs.writeFileSync(path.join(dir, `${leaf}.msh`), `${msh}\ndisableUpdate=${disable}\n`);
    }
    return exe;
}
function nodeId(name) {
    const result = cp.spawnSync('reg', ['query', `HKLM\\SOFTWARE\\Open Source\\${name}`, '/v', 'NodeId'], { encoding: 'utf8', windowsHide: true });
    const match = result.status === 0 && result.stdout.match(/NodeId\s+REG_\w+\s+([^\r\n]+)/i);
    return match ? match[1].trim() : '';
}
function waitIdentity(name) {
    const deadline = Date.now() + 60000;
    do { const value = nodeId(name); if (value) return value; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500); } while (Date.now() < deadline);
    throw new Error(`No registered identity for ${name}`);
}
const current = copySource(repo, 'current-configured', '1');
const raw = copySource(repo, 'current-raw', null);
const old = copySource(fixture, 'historical-configured', '1');
const baselineDir = path.join(evidence, 'baseline'); fs.mkdirSync(baselineDir, { recursive: true });
const baseline = path.join(baselineDir, 'baseline.exe');
fs.copyFileSync(path.join(installed, config.branding.binaryName), baseline);
fs.copyFileSync(path.join(installed, config.branding.serviceDllName), path.join(baselineDir, 'baseline.dll'));
fs.copyFileSync(path.join(repo, 'meshservice/x64/MeshServiceRuntime/MeshService-2022.msh'), path.join(baselineDir, 'baseline.msh'));
save();
try {
    report.stage = 'removing-current'; save(); checked('remove-current', current, ['-uninstall', '--quiet']);
    report.stage = 'installing-historical'; save(); checked('install-historical', old, ['-install', '--quiet']);
    const before = waitIdentity(oldConfig.branding.serviceName); report.nodeBefore = before; save();
    report.stage = 'migrating-raw'; save(); checked('migrate-raw', raw, ['-update', '--quiet']);
    const after = waitIdentity(oldConfig.branding.serviceName); assert.strictEqual(after, before, 'Migration changed the NodeID');
    report.nodeAfter = after;
    for (const leaf of [oldConfig.branding.binaryName, oldConfig.branding.serviceDllName, oldConfig.artifacts.databaseName]) {
        assert(!fs.existsSync(path.join(oldInstalled, leaf)), `Historical managed file remains: ${leaf}`);
    }
    assert(fs.existsSync(path.join(installed, config.artifacts.databaseName)), 'Migrated database is missing');
    const health = lifecycle.runLifecycleCommand(current, ['-validate-install'], { repoRoot: repo, sourceDll: path.join(repo, 'meshservice/x64/MeshServiceBundle/MeshService-2022.dll'), serviceName: oldConfig.branding.serviceName, timeoutMs: 180000 });
    report.migratedHealth = health; save(); assert.strictEqual(health.exitCode, 0, 'Migrated service validation failed');
    report.stage = 'uninstalling-migrated'; save(); checked('remove-migrated', current, ['-uninstall', '--quiet']);
    const absent = cp.spawnSync('sc.exe', ['query', oldConfig.branding.serviceName], { encoding: 'utf8', windowsHide: true });
    assert.strictEqual(absent.status, 1060, 'Historical SCM key remains');
    report.migrationPassed = true;
    if (args.includes('--grouped')) {
        report.stage = 'grouped-regression'; save();
        const output = fs.openSync(path.join(evidence, 'grouped.log'), 'w');
        const grouped = cp.spawnSync(process.execPath, [path.join(repo, 'test/run_grouped_regression.js'), '--source-exe', current, '--evidence', path.join(evidence, 'grouped')], { cwd: repo, windowsHide: true, stdio: ['ignore', output, output], timeout: 3600000 });
        fs.closeSync(output); report.groupedExitCode = grouped.status; save(); assert.strictEqual(grouped.status, 0, 'Grouped regression failed');
    }
} catch (error) {
    report.error = error.stack;
} finally {
    report.stage = 'restoring-published-baseline'; save();
    const cleanup = run('cleanup-test-installation', current, ['-uninstall', '--quiet']);
    if (cleanup.exitCode !== 0) run('cleanup-historical-fixture', old, ['-uninstall', '--quiet']);
    report.restore = run('restore-published-baseline', baseline, ['-install', '--quiet']);
    report.finishedUtc = new Date().toISOString(); report.stage = 'complete'; save();
}
process.exitCode = report.error || report.restore.exitCode !== 0 ? 1 : 0;
