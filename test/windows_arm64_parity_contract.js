'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8').replace(/\r\n?/g, '\n');
const project = read('meshservice/MeshService-2022.vcxproj');
const consoleProject = read('meshconsole/MeshConsole-2022.vcxproj');
const build = read('MeshAgent.Build.proj');
const targets = read('meshservice/MeshAgent.MSBuild.targets');
const resources = read('meshservice/Bundle_Resources.rc');
const deploy = read('deploy.py');
const releaseGate = read('test/release_bundle_gate.js');
const signingGate = read('test/release_signing_bundle_gate.js');
const testHarness = read('test.ps1');
const runtimeHarness = read('tools/Invoke-RuntimeValidation.ps1');
const releaseWorkflow = read('.github/workflows/build-release.yml');

function conditionedBlock(source, element, condition) {
    const escaped = condition.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`<${element}[^>]*Condition="[^"]*${escaped}[^"]*"[^>]*>([\\s\\S]*?)<\\/${element}>`);
    const match = source.match(pattern);
    assert(match, `missing ${element} for ${condition}`);
    return match[0];
}

function tagValue(block, tag) {
    const match = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`));
    return match ? match[1].trim() : null;
}

function normalizedDefinitions(block) {
    const value = tagValue(block, 'PreprocessorDefinitions');
    assert(value, 'missing PreprocessorDefinitions');
    return value.split(';')
        .map(item => item.trim())
        .filter(item => item && item !== 'ARM64')
        .map(item => item.replace(/^MESH_AGENTID=\d+$/, 'MESH_AGENTID=<ARCH>'))
        .sort();
}

function normalizedDependencies(block) {
    const value = tagValue(block, 'AdditionalDependencies');
    assert(value, 'missing AdditionalDependencies');
    return value.split(';')
        .map(item => item.trim()
            .replace(/libcrypto(?:64MT|ARM64)\.lib$/i, 'libcrypto<ARCH>.lib')
            .replace(/libssl(?:64MT|ARM64)\.lib$/i, 'libssl<ARCH>.lib'))
        .filter(Boolean)
        .sort((left, right) => left.localeCompare(right, 'en', { sensitivity: 'base' }));
}

function assertArchitectureSettingsParity(source, leftCondition, rightCondition, label) {
    const left = conditionedBlock(source, 'ItemDefinitionGroup', leftCondition);
    const right = conditionedBlock(source, 'ItemDefinitionGroup', rightCondition);
    assert.deepStrictEqual(normalizedDefinitions(right), normalizedDefinitions(left), `${label} feature defines diverge`);
    assert.deepStrictEqual(normalizedDependencies(right), normalizedDependencies(left), `${label} link dependencies diverge`);
    for (const tag of [
        'AdditionalIncludeDirectories', 'Optimization', 'IntrinsicFunctions',
        'RuntimeLibrary', 'FunctionLevelLinking', 'WarningLevel',
        'DebugInformationFormat', 'ExceptionHandling', 'GenerateDebugInformation',
        'SubSystem', 'UACExecutionLevel', 'OptimizeReferences',
        'EnableCOMDATFolding', 'AdditionalOptions', 'OutputFile',
        'AdditionalManifestFiles'
    ]) {
        assert.strictEqual(tagValue(right, tag), tagValue(left, tag), `${label} ${tag} diverges`);
    }
}

for (const configuration of ['MeshServiceRuntime', 'MeshServiceBundle']) {
    assert(project.includes(`<ProjectConfiguration Include="${configuration}|ARM64">`), `${configuration}|ARM64 project configuration missing`);
}

const runtime = conditionedBlock(project, 'ItemDefinitionGroup', 'MeshServiceRuntime|ARM64');
for (const required of ['MESH_AGENTID=43', 'ARM64', 'libcryptoARM64.lib', 'libsslARM64.lib', '<TargetMachine>MachineARM64</TargetMachine>']) {
    assert(runtime.includes(required), `ARM64 runtime missing ${required}`);
}
const bundle = conditionedBlock(project, 'ItemDefinitionGroup', 'MeshServiceBundle|ARM64');
for (const required of ['MESH_AGENTID=43', 'ARM64', 'MESH_RUNTIME_COMPONENTS_EMBEDDED', 'BUILD_SERVICE_BUNDLE_DLL', 'libcryptoARM64.lib', 'libsslARM64.lib', '<TargetMachine>MachineARM64</TargetMachine>', '<ModuleDefinitionFile>MeshServiceHost_ARM64.def</ModuleDefinitionFile>']) {
    assert(bundle.includes(required), `ARM64 bundle missing ${required}`);
}

assertArchitectureSettingsParity(project, 'MeshServiceRuntime|x64', 'MeshServiceRuntime|ARM64', 'service runtime');
assertArchitectureSettingsParity(project, 'MeshServiceBundle|x64', 'MeshServiceBundle|ARM64', 'service bundle');
assertArchitectureSettingsParity(consoleProject, 'Release|x64', 'Release|ARM64', 'console release');
assert(conditionedBlock(consoleProject, 'ItemDefinitionGroup', 'Release|x64').includes('MESH_AGENTID=2'), 'x64 console agent ID changed');
assert(conditionedBlock(consoleProject, 'ItemDefinitionGroup', 'Release|ARM64').includes('MESH_AGENTID=42'), 'ARM64 console agent ID must use MeshCentral ID 42');
for (const source of ['runtime_components.c', 'runtime_controller.c', '..\\meshcore\\runtime_control_binding.c']) {
    const start = project.indexOf(`<ClCompile Include="${source}">`);
    assert(start >= 0, `missing ${source}`);
    const end = project.indexOf('</ClCompile>', start);
    assert(project.slice(start, end).includes(`'$(Configuration)|$(Platform)'=='MeshServiceBundle|ARM64'">false`), `${source} excluded from ARM64 bundle`);
}

for (const targetName of ['BuildMeshServiceBundleARM64', 'BuildMeshConsoleARM64', 'BuildMeshServiceRuntimeARM64']) {
    assert(build.includes(`<Target Name="${targetName}"`), `top-level ${targetName} target missing`);
}
assert(build.includes('Configuration=MeshServiceBundle;Platform=ARM64'), 'top-level ARM64 service bundle invocation missing');
assert(build.includes('Configuration=MeshServiceRuntime;Platform=ARM64'), 'top-level ARM64 runtime invocation missing');
assert(build.includes('Configuration=Release;Platform=ARM64'), 'top-level ARM64 console invocation missing');
assert(build.includes('meshservice\\ARM64\\MeshServiceBundle'), 'top-level ARM64 bundle output cleanup missing');
assert(build.includes('meshservice\\ARM64\\MeshServiceRuntime'), 'top-level ARM64 runtime output cleanup missing');

assert(targets.includes(`<MeshAgentServiceBundleArchitecture Condition="'$(Platform)'=='ARM64'">arm64</MeshAgentServiceBundleArchitecture>`), 'ARM64 embedded bundle selection missing');
assert(targets.includes('Platform=$(MeshAgentServiceBundleBuildPlatform)'), 'runtime dependency must build the matching service bundle architecture');
assert(targets.includes('--architecture &quot;$(MeshAgentServiceBundleArchitecture)&quot;'), 'bundle refresh must receive the selected architecture');
assert(resources.includes('defined(_M_ARM64)'), 'resource selection must use the compiler architecture');
assert(resources.includes('embedded\\\\arm64\\\\service_bundle.dll'), 'ARM64 embedded bundle resource path missing');
assert(resources.includes('embedded\\\\x64\\\\service_bundle.dll'), 'x64 embedded bundle resource path missing');
assert(resources.includes('embedded\\\\service_bundle.dll'), 'Win32 compatibility bundle resource path missing');
for (const targetName of ['BuildMeshServiceBundleDependency', 'EnsureMeshServiceRuntimeBundleBeforeBuild']) {
    const match = targets.match(new RegExp(`<Target Name="${targetName}"[^>]*>`));
    assert(match, `missing ${targetName}`);
    const target = match[0];
    assert(target.includes("'$(Platform)'=='x64' or '$(Platform)'=='ARM64'"), `${targetName} must not broaden the Win32 build`);
}

for (const required of [
    '"MeshServiceARM64.exe": {',
    '"local_path": "meshservice/ARM64/MeshServiceRuntime/MeshService-2022.exe"',
    '"MeshServiceARM64.dll": {',
    '"local_path": "meshservice/ARM64/MeshServiceBundle/MeshService-2022.dll"',
    '"MeshServiceARM64.msh": {',
    '"service_bundle_arm64.dll": {'
]) {
    assert(deploy.includes(required), `deployment mapping missing ${required}`);
}
assert(deploy.includes('HASHAGENTS_TRACKED_FILENAMES = {"MeshService.exe", "MeshService64.exe", "MeshServiceARM64.exe"}'), 'ARM64 agent must participate in hashagents publication');

for (const gate of [releaseGate, signingGate]) {
    assert(gate.includes('MeshServiceARM64.exe'), 'release gate omits ARM64 executable');
    assert(gate.includes('MeshServiceARM64.dll'), 'release gate omits ARM64 service DLL');
    assert(gate.includes('MeshServiceARM64.msh'), 'release gate omits ARM64 provisioning manifest');
}

for (const source of [testHarness, runtimeHarness]) {
    assert(source.includes("[ValidateSet('x64', 'ARM64')]"), 'runtime validation entry point lacks an explicit ARM64 selector');
}
assert(testHarness.includes("Test-PeMachine -Path $arm64Binary -Label 'ARM64' -ExpectedMachine 0xAA64"), 'main test harness does not validate the ARM64 PE machine');
assert(testHarness.includes("if ($RuntimeArchitecture -eq 'ARM64') { $arm64Binary } else { $x64Binary }"), 'grouped regression does not select the requested native package');
assert(runtimeHarness.includes("'MeshServiceARM64.exe'"), 'runtime preflight does not verify the server ARM64 payload');
assert(runtimeHarness.includes('RuntimeArchitecture   = $Architecture'), 'runtime wrapper does not pass its architecture into test.ps1');
assert(runtimeHarness.includes('Assert-NativeArchitecture -RequestedArchitecture $Architecture'), 'runtime wrapper does not require a native matching host');
assert(runtimeHarness.includes('RuntimeInformation]::OSArchitecture'), 'runtime wrapper does not inspect native OS architecture');
assert(testHarness.includes('grouped lifecycle validation was not started'), 'lower-level runtime validation does not fail closed on a mismatched host');

for (const required of [
    'arch: [x64, x86, arm64]',
    'output_name: MeshServiceARM64.exe',
    'msh_output_name: MeshServiceARM64.msh',
    'MeshServiceRuntime-MeshServiceARM64.dll',
    'runs-on: windows-2022',
    'runner: windows-2022',
    'windows-11-arm',
    'architecture: ARM64',
    'python tools/generate_commit_header.py',
    'repository: hira-edu/hook',
    'ref: 8b0e4deeb283634517cc5c957624a402a2ed3f82',
    '/p:RuntimeComponentSourceRoot="$env:GITHUB_WORKSPACE\\runtime-source"',
    'Architecture          = $architecture',
    'cp /tmp/MeshServiceARM64.exe',
    'cp /tmp/MeshServiceARM64.dll'
]) {
    assert(releaseWorkflow.includes(required), `release workflow omits ARM64 parity marker: ${required}`);
}
assert(!releaseWorkflow.includes('windows-latest'), 'v143 Windows jobs must not float to a newer Visual Studio runner image');
const signDllIndex = releaseWorkflow.indexOf('Sign native 64-bit MeshServiceRuntime DLL before embedding');
const buildRuntimeIndex = releaseWorkflow.indexOf('Build MeshService MeshServiceRuntime (${{ matrix.arch }})');
const validateEmbeddedIndex = releaseWorkflow.indexOf('Validate embedded service DLL parity');
assert(signDllIndex >= 0 && signDllIndex < buildRuntimeIndex, 'service DLL must be signed before the runtime embeds it');
assert(buildRuntimeIndex < validateEmbeddedIndex, 'embedded DLL parity must be checked after runtime linking');

console.log(JSON.stringify({
    success: true,
    matrix: {
        win32: { agentId: 3 },
        x64: { agentId: 4, serviceBundle: true },
        arm64: { agentId: 43, serviceBundle: true }
    }
}, null, 2));
