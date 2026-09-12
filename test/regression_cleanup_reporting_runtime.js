// Exercise reporting only. All agent/service operations are replaced by fakes.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const evidence = path.resolve(process.argv[2] || path.join(root, 'artifacts', 'validation', 'cleanup-reporting'));
fs.mkdirSync(evidence, { recursive: true });
const groupedSource = fs.readFileSync(path.join(__dirname, 'run_grouped_regression.js'), 'utf8').replace(/\r\n/g, '\n');
const entry = groupedSource.lastIndexOf('\ntry {\n    main();');
assert(entry >= 0, 'grouped runner entry point missing');
const rows = [];

function groupedCase(name, options) {
    const documents = {};
    const sandbox = {
        __dirname, process: { platform: 'win32', env: {}, argv: [] }, Buffer, console,
        require(module) {
            if (module === './lib/provisioning_identity' || module === './lib/rundll32_lifecycle') { return {}; }
            if (module === 'child_process') { return { spawnSync() { throw Error('Unexpected product process launch'); } }; }
            if (module === 'fs') { return {}; }
            assert(['crypto', 'os', 'path'].includes(module), `Unexpected dependency ${module}`);
            return require(module);
        },
        capture(file, value) { documents[path.basename(file)] = value; },
        command(label) {
            if (label === 'cleanup-uninstall' && options.throwCleanup) { throw Error('injected cleanup exception'); }
            return { label, exitCode: label === 'cleanup-uninstall' ? options.uninstall : options.validate,
                stdout: '', stderr: '', error: null };
        },
        phase() { if (options.phaseFailure) { throw Error('injected phase failure'); } return {}; }
    };
    vm.runInNewContext(groupedSource.slice(0, entry) + `
        parseArgs = () => ({evidence: 'fixture'});
        resolveSourceSet = () => ({exe: 'fixture.exe', dll: 'fixture.dll'});
        cacheSourceSet = (source) => source;
        createCommandRunner = () => command;
        ensureDir = () => {};
        writeJson = capture;
        writeText = capture;
        writeCommandArtifacts = () => {};
        getElevationState = () => ({elevated: true});
        stageExecutable = () => ({exe: 'fixture.exe'});
        queryServiceName = () => 'Fixture';
        runPackagePreflight = phase;
        runJsSelfTest = runMeshCentralSameSizeContracts = runNativeCliPhase = runGuiHarnessPhase = () => ({});
        try { main(); capture('thrown', null); } catch (error) { capture('thrown', error.message); }
    `, sandbox, { timeout: 1000 });
    const expected = !options.phaseFailure && !options.throwCleanup && options.uninstall === 0 && options.validate === 0;
    const result = documents['results.json'];
    const passed = !!result && result.allOk === expected && (!!documents.thrown === !expected) &&
        (!options.phaseFailure || documents.thrown.includes('injected phase failure')) &&
        (options.uninstall === 0 || documents.thrown.includes('final cleanup uninstall')) &&
        (options.validate === 0 || documents.thrown.includes('final cleanup validation')) &&
        (!options.throwCleanup || documents.thrown.includes('injected cleanup exception'));
    rows.push({ name, passed, expectedSuccess: expected, result, thrown: documents.thrown });
}

groupedCase('all phases and cleanup succeed', { uninstall: 0, validate: 0 });
groupedCase('uninstall failure cannot pass', { uninstall: 1, validate: 0 });
groupedCase('cleanup validation failure cannot pass', { uninstall: 0, validate: 1 });
groupedCase('cleanup exception retains report', { uninstall: 0, validate: 0, throwCleanup: true });
groupedCase('phase and cleanup failures both retained', { uninstall: 1, validate: 1, phaseFailure: true });

// Compile the production final return statement in a reporting-only C# fixture.
const guiSource = fs.readFileSync(path.join(__dirname, 'gui_button_race_harness', 'Program.cs'), 'utf8');
const guiReturn = guiSource.match(/^return exitCode[^\r\n]*;/m);
assert(guiReturn, 'GUI final return statement missing');
const guiFixture = `using System;
using System.Linq;
using System.Collections.Generic;
var cases = new[] { (0, new[] { true, true }, 0), (0, new[] { true, false }, 1),
    (1, new[] { true, true }, 1), (0, Array.Empty<bool>(), 1) };
var failures = 0;
foreach (var (prior, outcomes, expected) in cases) {
    var actual = Finish(prior, outcomes);
    Console.WriteLine($"prior={prior} outcomes={string.Join(',', outcomes)} actual={actual} expected={expected}");
    if (actual != expected) { ++failures; }
}
return failures == 0 ? 0 : 1;
static int Finish(int exitCode, bool[] outcomes) {
    var results = outcomes.Select(value => new ScenarioResult(value)).ToList();
    ${guiReturn[0]}
}
record ScenarioResult(bool Passed);
`;
const fixtureDir = path.join(evidence, 'gui-reporting');
fs.mkdirSync(fixtureDir, { recursive: true });
fs.writeFileSync(path.join(fixtureDir, 'Program.cs'), guiFixture);
fs.writeFileSync(path.join(fixtureDir, 'fixture.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>');
const gui = spawnSync('dotnet', ['run', '--project', path.join(fixtureDir, 'fixture.csproj'), '-c', 'Release', '--no-launch-profile'],
    { encoding: 'utf8', timeout: 90000, windowsHide: true, env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: '1' } });
rows.push({ name: 'GUI exit includes cleanup and requires results', passed: gui.status === 0 && !gui.error,
    exitCode: gui.status, stdout: gui.stdout, stderr: gui.stderr, error: gui.error ? String(gui.error) : null });
const report = { ok: rows.every(row => row.passed), agentExecuted: false, serviceChanged: false, results: rows };
fs.writeFileSync(path.join(evidence, 'results.json'), JSON.stringify(report, null, 2));
for (const row of rows) { console.log(`${row.passed ? 'PASS' : 'FAIL'} ${row.name}`); }
process.exitCode = report.ok ? 0 : 1;
