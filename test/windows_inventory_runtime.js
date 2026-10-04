'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '..');
function variable(size) {
    const buffer = Buffer.alloc(size);
    return { _size: size, Wide2UTF8: 'probe.exe', toBuffer: () => buffer, Deref(offset = 0, length = size - offset) {
        const view = buffer.subarray(offset, offset + length);
        return { toBuffer: () => view, Wide2UTF8: 'probe.exe' };
    } };
}
function method(file, signature) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    const start = source.indexOf(signature);
    assert(start >= 0, signature);
    const begin = source.indexOf('function', start), brace = source.indexOf('{', begin);
    let depth = 1, end = brace + 1;
    while (depth) { depth += (source[end] === '{') - (source[end] === '}'); ++end; }
    return source.slice(begin, end);
}
for (const bits of [4, 8]) {
    for (const opened of [false, true]) {
        const closed = [], queries = [];
        const kernel = {
            CreateMethod() {}, GetLastError: () => ({Val: 5}),
            CreateToolhelp32Snapshot: () => ({Val: 10}),
            Process32FirstW(h, info) { info.toBuffer().writeUInt32LE(123, 8); return {Val: 1}; },
            Process32NextW: () => ({Val: 0}),
            OpenProcess: () => ({Val: opened ? 11 : 0}),
            QueryFullProcessImageNameW(h, flags, buffer, chars) {
                queries.push(h.Val);
                assert.equal(h.Val, 11, 'do not query a NULL process handle');
                assert.equal(chars.toBuffer().readUInt32LE(), buffer._size / 2, 'W API buffer size is in WCHARs');
                return {Val: 1};
            }, CloseHandle(h) { closed.push(h.Val); }
        };
        const context = {process: {platform: 'win32'}, module: {exports: {}}, Buffer,
            require(name) {
                if (name === '_GenericMarshal') return {PointerSize: bits, CreateVariable: variable, CreateNativeProxy: () => kernel};
                if (name === 'promise') return function() {};
                if (name === 'user-sessions') return {getProcessOwnerName: () => ({name: 'probe'})};
                throw Error(name);
            }};
        vm.runInNewContext(fs.readFileSync(path.join(root, 'modules/process-manager.js'), 'utf8'), context);
        let result;
        context.module.exports.getProcesses(p => { result = p; });
        assert.equal(result[123].cmd, 'probe.exe');
        assert.deepEqual(queries, opened ? [11] : []);
        assert.deepEqual(closed.sort(), opened ? [10, 11] : [10]);
        if (opened) {
            kernel.ProcessIdToSessionId = (pid, value) => { value.toBuffer().writeUInt32LE(7); return {Val: 1}; };
            kernel.GetProcessHandleCount = (h, value) => { value.toBuffer().writeUInt32LE(42); return {Val: 1}; };
            kernel.GetProcessTimes = (h, created, exited, system, user) => {
                created.toBuffer().writeBigUInt64LE(116444736000000000n + 10000000n);
                system.toBuffer().writeUInt32LE(5000000); user.toBuffer().writeUInt32LE(10000000);
                return {Val: 1};
            };
            const details = context.module.exports.getProcessInfo(123);
            assert.equal(details.sessionId, 7);
            assert.equal(details.handleCount, 42);
            assert.equal(details.startTime, '1970-01-01T00:00:01.000Z');
            assert.equal(details.totalProcessorTime, 1.5);
            assert.equal(closed.filter(h => h === 11).length, 2);
        } else {
            assert.throws(() => context.module.exports.getProcessInfo(123), /query process/);
        }
    }
}
for (const failure of ['token-user', 'lookup', null]) {
    const closed = [], token = {Val: 21};
    const ownerContext = {
        PROCESS_QUERY_INFORMATION: 0x400, PROCESS_QUERY_LIMITED_INFORMATION: 0x1000,
        TOKEN_QUERY: 8, TokenSessionId: 12, TokenUser: 1,
        ERROR_INSUFFICIENT_BUFFER: 122
    };
    const owner = vm.runInNewContext('(' + method('modules/user-sessions.js', 'this.getProcessOwnerName = function') + ')', ownerContext);
    const state = {_marshal: {CreateVariable: variable, CreatePointer: () => ({Deref: () => token})},
        _kernel32: {OpenProcess: () => ({Val: 20}), CloseHandle: h => closed.push(h.Val)},
        _advapi: {
            OpenProcessToken: () => ({Val: 1}),
            GetTokenInformation(h, type, data, size, needed) {
                if (type === 1 && !size) { needed.toBuffer().writeUInt32LE(32); return {Val: 0}; }
                return {Val: failure === 'token-user' && type === 1 ? 0 : 1};
            },
            LookupAccountSidW(host, sid, name, nameChars, domain, domainChars) {
                assert.notEqual(nameChars, domainChars, 'account and domain lengths need separate DWORDs');
                assert.equal(nameChars.toBuffer().readUInt32LE(), name._size / 2);
                assert.equal(domainChars.toBuffer().readUInt32LE(), domain._size / 2);
                return {Val: failure === 'lookup' ? 0 : 1};
            }
        }};
    try { owner.call(state, 123); } catch (error) { if (!failure) throw error; }
    assert.deepEqual(closed.sort(), [20,21], 'both handles must close after ' + failure);
}
const enumerate = vm.runInNewContext('(' + method('modules/service-manager.js', 'this.enumerateService = function ()') + ')',
    {parseServiceStatus: () => ({state: 'RUNNING'})});
for (const bits of [4, 8]) for (const fail of [false, true]) {
    let calls = 0, closed = 0;
    const state = {GM: {PointerSize: bits, CreateVariable: variable, CreatePointer: () => variable(bits)},
        proxy2: {GetLastError: () => ({Val: fail ? 5 : 234})}, proxy: {
            OpenSCManagerA: () => ({Val: 30}), CloseServiceHandle() { ++closed; },
            EnumServicesStatusExW(h, level, type, status, services, bytes, needed, count, resume) {
                if (!services) { needed.toBuffer().writeUInt32LE(128); return {Val: 0}; }
                ++calls;
                if (fail) return {Val: 0};
                count.toBuffer().writeUInt32LE(1); resume.toBuffer().writeUInt32LE(calls === 1 ? 1 : 0);
                services.Deref = () => ({Deref: () => ({Deref: () => ({Wide2UTF8: 'page' + calls})})});
                return {Val: calls === 1 ? 0 : 1};
            }
        }};
    if (fail) assert.throws(() => enumerate.call(state), /enumerat/i);
    else assert.equal(enumerate.call(state).length, 2, 'enumeration must consume both SCM pages');
    assert.equal(closed, 1, 'SCM handle must close on every path');
}
const registryTimestamp = vm.runInNewContext('(' + method('modules/win-registry.js', 'this.QueryKeyLastModified = function') + ')',
    {KEY_QUERY_VALUE: 1, require: () => ({convertFileTime: () => 'timestamp'})});
for (const failure of ['open', 'query', 'time', null]) {
    let closed = 0;
    const state = {_marshal: {CreateVariable: size => variable(typeof size === 'string' ? (size.length + 1) * 2 : size), CreatePointer: () => ({Deref: () => 31})},
        _AdvApi: {
            RegOpenKeyExW: () => ({Val: failure === 'open' ? 5 : 0}),
            RegQueryInfoKeyW(...args) {
                assert.equal(args.length, 12);
                assert(args.slice(1, 11).every(value => value === 0), 'unused registry metadata must not allocate output buffers');
                return {Val: failure === 'query' ? 5 : 0};
            },
            RegCloseKey(handle) { assert.equal(handle, 31); ++closed; }
        }, _Kernel32: {FileTimeToSystemTime: () => ({Val: failure === 'time' ? 0 : 1})}};
    if (failure) assert.throws(() => registryTimestamp.call(state, 1, 'probe'));
    else assert.equal(registryTimestamp.call(state, 1, 'probe'), 'timestamp');
    assert.equal(closed, failure === 'open' ? 0 : 1, 'registry keys must close on success and every post-open failure');
}
const getService = vm.runInNewContext(method('modules/service-manager.js', 'function windowsServiceError(') + ';(' + method('modules/service-manager.js', 'this.getService = function getService') + ')',
    {require: () => ({HKEY:{LocalMachine:1}, QueryKeyLastModified: () => 'timestamp'})});
for (const opened of [false, true]) {
    const closed = [];
    const state = {isAdmin: () => false,
        proxy2: {GetLastError: () => ({Val: opened ? 5 : 1060})},
        GM: {PointerSize:8, CreateVariable: size => variable(typeof size === 'string' ? (size.length + 1) * 2 : size), CreatePointer: () => variable(8)},
        proxy: {
            OpenSCManagerA: () => ({Val:30}), OpenServiceW: () => ({Val:opened ? 31 : 0}),
            QueryServiceStatusEx(handle, level, buffer, size, needed) {needed.toBuffer().writeUInt32LE(36);return {Val:0};},
            CloseServiceHandle(handle) {closed.push(handle.Val);}
        }};
    assert.throws(() => getService.call(state, 'probe'), (error) => error.code === (opened ? 'EWIN32' : 'ENOENT') && error.win32Error === (opened ? 5 : 1060));
    assert.deepEqual(closed.sort(), opened ? [30,31] : [30], 'failed service status queries must release both handles');
}
console.log('Windows inventory: bitness, WCHAR bounds, denied processes, token failures, service pagination and cleanup passed');
if (process.argv.includes('--native')) {
    assert.equal(process.platform, 'win32', '--native requires Windows');
    const code = ['global._noMessagePump=true;']; // A query-only process does not subscribe to desktop notifications.
    for (const name of ['process-manager', 'service-manager', 'user-sessions', 'win-registry']) {
        code.push('addModule(' + JSON.stringify(name) + ',require("fs").readFileSync(' + JSON.stringify(path.join(root, 'modules', name + '.js')) + ').toString(),' + JSON.stringify(new Date().toISOString()) + ');');
    }
    code.push(`
try {
var pm=require('process-manager'), sm=require('service-manager').manager;
var before, after, counts=[];
pm.getProcesses(function(p){if(!p[process.pid])throw Error('Current process missing');});
sm.enumerateService();
before=pm.getProcessInfo(process.pid).handleCount;
for(var i=0;i<3;++i){
    var processCount=0; pm.getProcesses(function(p){processCount=Object.keys(p).length;});
    counts.push({processes:processCount,services:sm.enumerateService().length});
}
after=pm.getProcessInfo(process.pid).handleCount;
if(after>before)throw Error('Inventory leaked handles: '+before+' -> '+after);
var details=pm.getProcessInfo(process.pid);
if(!details.processName || !details.startTime || typeof details.sessionId!='number')throw Error('Process details missing');
if(require('user-sessions').getAccountName('S-1-5-18').length==0)throw Error('SID lookup failed');
addModule('version-probe','module.exports="old";', '2020-01-01T00:00:00.000Z');
addModule('version-probe','module.exports="undated";');
if(getJSModule('version-probe').indexOf('old')<0)throw Error('Undated module unexpectedly replaced a dated module');
addModule('version-probe','module.exports="updated";', '2026-10-03T10:30:00.000Z');
if(getJSModule('version-probe').indexOf('updated')<0 || getJSModuleDate('version-probe')!=1791023400)throw Error('ISO module version was not accepted');
console.log(JSON.stringify({success:true,counts:counts,handlesBefore:before,handlesAfter:after,moduleVersionAccepted:true}));
} catch(error) {console.log(JSON.stringify({success:false,error:''+error}));}
process.exit();`);
    const result = require('child_process').spawnSync(path.join(root, 'meshconsole/Release/MeshConsole64.exe'),
        ['-b64exec', Buffer.from(code.join('\n')).toString('base64')], {encoding:'utf8', timeout:30000, windowsHide:true});
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.success, true, report.error);
    assert(report.counts.every(count => count.processes > 0 && count.services > 0));
    console.log(JSON.stringify(report));
}
