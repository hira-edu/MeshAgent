'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

for (const filename of ['meshcore.js', 'meshcore.min.js']) {
    const source = fs.readFileSync(path.resolve(__dirname, '../../MeshCentral/agents', filename), 'utf8');
    function cases(first, last) {
        const begin = source.indexOf("case '" + first + "':");
        const end = source.indexOf("case '" + last + "':", begin);
        assert(begin >= 0 && end > begin);
        return source.slice(begin, end);
    }
    for (const failure of [false, true]) {
        const messages = [];
        let enumerated = 0, closed = 0;
        const service = {name:'probe', status:{state:'RUNNING'}, installedBy:'S-1-5-18', close() { ++closed; }};
        const state = {
            processManager: {getProcesses(callback) {
                if (failure) throw Error('snapshot denied');
                callback({123:{pid:123,cmd:'probe.exe'}});
            }},
            mesh: {SendCommand: message => messages.push(message)},
            require(name) {
                if (name === 'user-sessions') return {getAccountName: () => 'NT AUTHORITY\\SYSTEM'};
                assert.equal(name, 'service-manager');
                return {manager: {
                    getService() { if (failure) throw Error('service removed'); return service; },
                    enumerateService() { ++enumerated; if (failure) throw Error('SCM denied'); return [{name:'probe'}]; }
                }};
            }
        };
        const dispatch = vm.runInNewContext('(function(data){switch(data.type){' +
            cases('ps', 'psinfo') + cases('service', 'serviceStop') + '}})', state);
        dispatch({type:'ps',sessionid:'s'});
        assert.equal(messages.length, 1);
        assert.equal(messages[0].type, 'ps');
        assert.equal(messages[0].sessionid, 's');
        assert.equal(Object.keys(JSON.parse(messages[0].value)).length, failure ? 0 : 1);
        assert.equal(Boolean(messages[0].error), failure);
        messages.length = 0;
        dispatch({type:'service',sessionid:'s',serviceName:'probe'});
        assert.equal(messages.length, 1, 'service details must send exactly one response');
        assert.equal(messages[0].type, 'service');
        assert.equal(enumerated, 0, 'service details must not fall through to service enumeration');
        assert.equal(closed, failure ? 0 : 1, 'service detail handles must close before the request returns');
        if (!failure) assert.equal(JSON.parse(messages[0].value).installedBy, 'NT AUTHORITY\\SYSTEM');
        else assert.match(messages[0].error, /service removed/);
        messages.length = 0;
        dispatch({type:'services',sessionid:'s'});
        assert.equal(messages.length, 1);
        assert.equal(messages[0].type, 'services');
        assert.equal(JSON.parse(messages[0].value).length, failure ? 0 : 1);
        assert.equal(Boolean(messages[0].error), failure);
        if (!failure) {
            messages.length = 0;
            Object.defineProperty(service, 'status', {get() { throw Error('status query failed'); }});
            dispatch({type:'service',sessionid:'s',serviceName:'probe'});
            assert.equal(messages.length, 1);
            assert.match(messages[0].error, /status query failed/);
            assert.equal(closed, 2, 'detail getter failures must also close service handles');
        }
    }
}
console.log('MeshCentral inventory requests return valid replies, isolate access failures and avoid service fallthrough.');
if (process.argv.includes('--native')) {
    assert.equal(process.platform, 'win32');
    const root = path.resolve(__dirname, '..');
    const source = fs.readFileSync(path.resolve(root, '../MeshCentral/agents/meshcore.js'), 'utf8');
    const begin = source.indexOf("case 'service': {"), end = source.indexOf("case 'services': {", begin);
    assert(begin >= 0 && end > begin);
    const code = ['global._noMessagePump=true;'];
    for (const name of ['process-manager', 'service-manager', 'user-sessions', 'win-registry']) {
        code.push('addModule(' + JSON.stringify(name) + ',require("fs").readFileSync(' + JSON.stringify(path.join(root, 'modules', name + '.js')) + ').toString(),' + JSON.stringify(new Date().toISOString()) + ');');
    }
    code.push("var messages=0;var mesh={SendCommand:function(message){if(message.error)throw Error(message.error);if(!JSON.parse(message.value).name)throw Error('Missing service details');++messages;}};");
    code.push('function dispatch(data){switch(data.type){' + source.slice(begin, end) + '}}');
    code.push(`
try {
    var pm=require('process-manager');
    dispatch({type:'service',serviceName:'EventLog',sessionid:'warmup'});
    messages=0;
    var before=pm.getProcessInfo(process.pid).handleCount;
    for(var i=0;i<20;++i){dispatch({type:'service',serviceName:'EventLog',sessionid:'probe'});}
    var after=pm.getProcessInfo(process.pid).handleCount;
    if(after>before)throw Error('Service detail handles grew: '+before+' -> '+after);
    if(messages!=20)throw Error('Missing replies');
    console.log(JSON.stringify({success:true,replies:messages,handlesBefore:before,handlesAfter:after}));
} catch(error) {console.log(JSON.stringify({success:false,error:''+error}));}
process.exit();`);
    const result = require('child_process').spawnSync(path.join(root, 'meshconsole/Release/MeshConsole64.exe'),
        ['-b64exec', Buffer.from(code.join('\n')).toString('base64')], {encoding:'utf8', timeout:30000, windowsHide:true});
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.success, true, report.error);
    console.log(JSON.stringify(report));
}
