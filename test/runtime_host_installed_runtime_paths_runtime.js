/* Pure parser/consumer probes: no Windows state or processes are changed. */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '..');
const system = 'D:\\Windows\\System32';
const dll = 'C:\\ProgramData\\Agent Space\\主机.dll';
const command = `"${system}\\rundll32.exe" "${dll}",MeshServiceHostW`;
let registryCommand = command;
const queries = [];
const marshal = {
    CreateVariable: () => ({ Wide2UTF8: system }),
    CreateNativeProxy: () => ({ CreateMethod() {}, GetSystemDirectoryW: () => ({ Val: system.length }) })
};
const context = {
    process: { platform: 'win32' }, module: { exports: {} },
    require(name) {
        if (name === '_GenericMarshal') return marshal;
        if (name === 'win-registry') return {
            HKEY: { LocalMachine: 1 },
            QueryKey(hive, key, value) { queries.push({ hive, key, value }); return registryCommand; }
        };
        throw new Error('Unexpected dependency: ' + name);
    }
};
vm.runInNewContext(fs.readFileSync(path.join(root, 'modules/win-system-paths.js'), 'utf8'), context);
const api = context.module.exports;
assert.equal(api.installedServiceRuntimeDll('MeshAgent'), dll);
assert.deepEqual(queries, [{ hive: 1, key: 'SYSTEM\\CurrentControlSet\\Services\\MeshAgent', value: 'ImagePath' }]);
assert.equal(api.serviceRuntimeDllFromCommand(command.replace('D:\\Windows', 'd:\\WINDOWS')), dll);
const rejected = [
    '', null, 3, `"${system}\\svchost.exe" "${dll}",MeshServiceHostW`,
    `"C:\\attacker\\rundll32.exe" "${dll}",MeshServiceHostW`,
    `"${system}\\rundll32.exe" "${dll}",ServiceHost_ServiceMain`,
    command.replace('MeshServiceHostW', 'meshservicehostw'), command + ' extra', command + '\n',
    command.replace(`"${dll}"`, dll), command.replace(`"${system}\\rundll32.exe"`, `${system}\\rundll32.exe`),
    ...['relative.dll', '\\\\server\\share\\agent.dll', 'C:agent.dll', 'C:\\a\\..\\agent.dll',
        'C:\\a\\.\\agent.dll', 'C:/agent.dll', 'C:\\a.dll:stream.dll', 'C:\\a?.dll', 'C:\\a,b.dll', 'C:\\a\\\\b.dll',
        'C:\\bad\u0000.dll', 'C:\\' + 'a'.repeat(260) + '.dll'].map(value => command.replace(dll, value))
];
for (const value of rejected) assert.throws(() => api.serviceRuntimeDllFromCommand(value), String(value));
for (const value of ['', '../Other', 'x\\Parameters', 'x\u0000']) assert.throws(() => api.installedServiceRuntimeDll(value));
registryCommand = '"C:\\old-agent.exe"';
assert.throws(() => api.installedServiceRuntimeDll('MeshAgent'));
assert.equal(queries[queries.length - 1].value, 'ImagePath');

function functionSource(file, name) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    const start = source.indexOf('function ' + name + '(');
    assert(start >= 0);
    let end = source.indexOf('{', start) + 1, depth = 1;
    while (depth) { depth += (source[end] === '{') - (source[end] === '}'); ++end; }
    return source.slice(start, end);
}
let resolutions = 0;
const dependencies = {
    process: { platform: 'win32' },
    resolveServiceName: () => 'MeshAgent', getWindowsLifecycleServiceName: () => 'MeshAgent',
    umhctlGetActiveAgentServiceName: () => 'MeshAgent',
    umhctlGetEnvValue: () => null, umhctlExpandWindowsEnvironmentStrings: v => v, umhctlNormalizeFilePath: v => v,
    require(name) { assert.equal(name, 'win-system-paths'); return { installedServiceRuntimeDll(name) { ++resolutions; assert.equal(name, 'MeshAgent'); return dll; } }; }
};
for (const [file, name] of [
    ['agent-installer', 'readWindowsInstalledServiceDllPath'], ['win-terminal', 'resolveInstalledServiceDllPath'],
    ['win-userconsent', 'resolveInstalledServiceDllPath'], ['umhctl', 'umhctlGetInstalledAgentServiceDllPath'],
    ['RecoveryCore', 'umhctlGetInstalledAgentServiceDllPath']
]) {
    const result = vm.runInNewContext(functionSource('modules/' + file + '.js', name) + '\n' + name + '();', dependencies);
    assert.equal(result, dll, file);
}
assert.equal(resolutions, 5);
const embedded = fs.readFileSync(path.join(root, 'microscript/ILibDuktape_Polyfills.c'), 'utf8');
for (const name of ['win-system-paths', 'agent-installer', 'win-userconsent']) {
    const variable = '_' + name.replace(/-/g, '');
    const chunks = [...embedded.matchAll(new RegExp('memcpy_s\\(' + variable + ' \\+ \\d+, \\d+, "([^"]+)", \\d+\\);', 'g'))].map(match => match[1]);
    assert(chunks.length > 0, name + ' embedded module');
    assert.equal(require('zlib').inflateSync(Buffer.from(chunks.join(''), 'base64')).toString('utf8').replace(/\r\n?/g, '\n'),
        fs.readFileSync(path.join(root, 'modules/' + name + '.js'), 'utf8').replace(/\r\n?/g, '\n'), name + ' embedded source parity');
}
console.log('Canonical RuntimeHost installed runtime: parser rejection and five consumer probes passed');
