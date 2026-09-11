'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const repo = path.resolve(__dirname, '..');
const evidence = path.resolve(process.argv[2] || path.join(repo, 'artifacts/validation/provisioning-copy-' + Date.now()));
const targets = path.resolve(process.argv[3] || path.join(repo, 'meshservice/MeshAgent.MSBuild.targets'));
fs.mkdirSync(evidence, { recursive: true });
const xml = value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const policy = host => Buffer.from('MeshServer=wss://' + host + '/agent.ashx\r\nServerID=' + 'ab'.repeat(48) + '\r\n');
const results = [];

function run(name, platform, selection, missing = false) {
    const dir = path.join(evidence, name);
    fs.mkdirSync(dir, { recursive: true });
    const source = path.join(dir, selection === 'override' ? 'override.msh' : selection === 'fallback' ? 'MeshAgent.msh' : 'WinDiagnosticHost.msh');
    const output = path.join(dir, 'MeshService-Test.msh');
    const exe = path.join(dir, 'MeshService-Test.exe');
    const expected = policy('good.example');
    const stale = policy('dead.example');
    fs.writeFileSync(output, stale);
    if (!missing) {
        fs.writeFileSync(source, expected);
        // The source is older and the same size: a timestamp/size shortcut is wrong.
        fs.utimesSync(source, new Date('2020-01-01Z'), new Date('2020-01-01Z'));
    }
    if (selection !== 'fallback') fs.writeFileSync(path.join(dir, 'MeshAgent.msh'), stale);
    if (selection === 'override') fs.writeFileSync(path.join(dir, 'WinDiagnosticHost.msh'), stale);
    const project = path.join(dir, 'fixture.proj');
    fs.writeFileSync(project, `<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <MeshAgentRepoRoot>${xml(dir)}</MeshAgentRepoRoot>
    <MeshAgentSkipStealthLabDllDependencyBuild>1</MeshAgentSkipStealthLabDllDependencyBuild>
    <Configuration>StealthLab</Configuration><Platform>${platform}</Platform>
    <TargetDir>${xml(dir + path.sep)}</TargetDir><TargetName>MeshService-Test</TargetName><TargetExt>.exe</TargetExt>
    ${selection === 'override' ? '<MeshAgentProvisioningManifest>' + xml(source) + '</MeshAgentProvisioningManifest>' : ''}
  </PropertyGroup>
  <Target Name="PrepareForBuild" />
  <Target Name="Build" DependsOnTargets="PrepareForBuild">
    <WriteLinesToFile File="${xml(exe)}" Lines="fixture binary" Overwrite="true" />
  </Target>
  <Import Project="${xml(targets)}" />
</Project>`);
    const result = spawnSync('msbuild', [project, '/nologo', '/verbosity:minimal'], { encoding: 'utf8', timeout: 30000, windowsHide: true });
    fs.writeFileSync(path.join(dir, 'msbuild.log'), (result.stdout || '') + (result.stderr || ''));
    if (result.error) throw result.error;
    if (missing) {
        assert.notStrictEqual(result.status, 0, name + ': missing manifest must fail');
        assert(!fs.existsSync(exe), name + ': missing manifest must fail before building');
        assert(fs.readFileSync(output).equals(stale), name + ': failure must preserve existing sidecar');
    } else {
        assert.strictEqual(result.status, 0, name + ': build failed; see msbuild.log');
        assert(fs.readFileSync(output).equals(expected), name + ': build left stale provisioning');
    }
    results.push({ name, passed: true });
}

try {
    for (const platform of ['x64', 'Win32']) {
        run(platform + '-default', platform, 'default');
        run(platform + '-override', platform, 'override');
        run(platform + '-fallback', platform, 'fallback');
        run(platform + '-missing', platform, 'override', true);
    }
    fs.writeFileSync(path.join(evidence, 'results.json'), JSON.stringify({ ok: true, results }, null, 2));
    console.log('PASS: ' + results.length + ' provisioning build cases');
} catch (error) {
    fs.writeFileSync(path.join(evidence, 'results.json'), JSON.stringify({ ok: false, results, error: error.message }, null, 2));
    console.error(error.message);
    process.exitCode = 1;
}
