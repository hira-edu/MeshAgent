const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extract(source, name) {
    const start = source.indexOf('function ' + name + '(');
    assert(start >= 0, 'Missing production function ' + name);
    const brace = source.indexOf('{', start);
    let depth = 1, end = brace + 1;
    while (depth && end < source.length) {
        if (source[end] === '{') ++depth;
        if (source[end] === '}') --depth;
        ++end;
    }
    return source.slice(start, end);
}

for (const file of ['modules/umhctl.js', 'modules/RecoveryCore.js']) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    let explicitPath = null;
    const context = vm.createContext({
        process: { platform: 'win32' },
        fs: { existsSync: () => false },
        umhctlGetEnvValue: key => key === 'UMH_MASTERSERVICE_EXE' ? explicitPath : null,
        umhctlProgramDataRoot: () => 'C:\\ProgramData',
        umhctlGetInstalledAgentServiceDllPath: () => 'C:\\ProgramData\\Agent\\Host.dll',
        umhctlGetMasterServiceCandidateNames: () => []
    });
    const names = ['umhctlNormalizeFilePath', 'umhctlNormalizeExecutablePath',
        'umhctlGetPreferredManagedMasterServicePaths', 'umhctlGetApprovedMasterServicePath',
        'umhctlResolveMasterServicePaths'];
    vm.runInContext(names.map(name => extract(source, name)).join('\n'), context);
    const resolve = value => { explicitPath = value; return context.umhctlResolveMasterServicePaths('C:\\Unapproved'); };
    assert.strictEqual(resolve(null).exePath, 'C:\\ProgramData\\UserModeHook\\MasterService.exe');
    assert.strictEqual(resolve('"C:\\ProgramData\\Agent\\MasterService.exe"').exePath, 'C:\\ProgramData\\Agent\\MasterService.exe');
    assert.strictEqual(resolve('C:/ProgramData/UserModeHook/temp/../MasterService.exe').exePath, 'C:\\ProgramData\\UserModeHook\\MasterService.exe');
    assert.strictEqual(resolve('c:/programdata/AGENT/工具/MasterService.exe').error, null);
    for (const rejected of [
        'C:\\Other\\MasterService.exe', 'C:\\Unapproved\\MasterService.exe',
        'C:\\ProgramData\\UserModeHook\\..\\MasterService.exe',
        'C:\\ProgramData\\UserModeHookSibling\\MasterService.exe',
        '\\\\server\\UserModeHook\\MasterService.exe', 'C:MasterService.exe',
        'C:\\ProgramData\\UserModeHook\\Other.exe',
        'C:\\ProgramData\\UserModeHook\\MasterService.exe:stream',
        'C:\\ProgramData\\UserModeHook\\MasterService.exe --status'
    ]) {
        const result = resolve(rejected);
        assert.strictEqual(result.exePath, null, rejected);
        assert.strictEqual(result.tmpPath, null, 'must not offer an unusable download path');
        assert(result.error.includes('UMH_MASTERSERVICE_EXE must name'), rejected);
    }
    console.log('PASS: ' + file + ' canonical selection, native-root parity, and early override rejection');
}
