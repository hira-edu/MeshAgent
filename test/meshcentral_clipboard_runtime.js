'use strict';
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm');
(async () => {
for (const filename of ['meshcore.js','meshcore.min.js']) {
    const source=fs.readFileSync(path.resolve(__dirname,'../../MeshCentral/agents',filename),'utf8');
    const msgBegin=source.indexOf("                    case 'getclip':"), msgEnd=source.indexOf("                    case 'userSessions':",msgBegin);
    const conBegin=source.indexOf("            case 'getclip':",msgEnd), conEnd=source.indexOf("            case 'openurl':",conBegin);
    assert(msgBegin>=0 && msgEnd>msgBegin && conEnd>conBegin);
    assert(!source.slice(msgBegin,msgEnd).includes('win-dispatcher'));
    for(const service of [true,false]) for(const mode of ['success','empty','reject','throw','nonstring']) {
        const messages=[], consoleMessages=[]; let finish;
        function read() { if(mode==='throw') throw Error('session missing'); return mode==='reject' ? Promise.reject(Error('busy')) : Promise.resolve(mode==='empty' ? '' : (mode==='nonstring' ? undefined : '日本 😀')); }
        function write() { if(mode==='throw') throw Error('session missing'); return mode==='reject' ? Promise.reject(Error('denied')) : new Promise(resolve=>{finish=resolve;}); }
        const writeSucceeds = mode==='success'||mode==='empty'||mode==='nonstring';
        write.read=write.dispatchRead=read; write.dispatchWrite=write;
        const context={mesh:{SendCommand:m=>messages.push(m)},MeshServerLogEx(){},sendConsoleText:(text,sid)=>consoleMessages.push({text,sid}),process:{platform:'win32'},
            require(name) { if(name==='MeshAgent')return {isService:service}; if(name==='clipboard')return write; throw Error('unexpected '+name); }};
        const dispatch=vm.runInNewContext('(function(data){switch(data.type){'+source.slice(msgBegin,msgEnd)+'}})',context);
        // Upstream viewers copy message.data without checking success, so a failed or
        // non-text read must send nothing; pulls and auto-sync never push empty text.
        for (const tag of [1,2,3]) {
            dispatch({type:'getclip',sessionid:'s',tag}); await Promise.resolve(); await Promise.resolve();
            const delivers = mode==='success' || (mode==='empty' && tag===1);
            assert.equal(messages.length,delivers?1:0,mode+' tag '+tag);
            if (delivers) { assert.equal(messages[0].tag,tag); assert.equal(messages[0].sessionid,'s'); assert.equal(typeof messages[0].data,'string'); assert.equal(messages[0].data,mode==='empty'?'':'日本 😀'); }
            messages.length=0;
        }
        dispatch({type:'setclip',sessionid:'s',tag:4,data:'text'});
        if(writeSucceeds) { assert.equal(messages.length,0,'success waits for native completion'); finish(); }
        await Promise.resolve(); assert.equal(messages.length,1); assert.equal(messages[0].success,writeSucceeds); assert.equal(messages[0].tag,4);
        const consoleDispatch=vm.runInNewContext('(function(action,args,sessionid){var response;switch(action){'+source.slice(conBegin,conEnd)+'}return response;})',context);
        consoleDispatch('getclip',{_:[]},'console'); await Promise.resolve(); assert.equal(consoleMessages.length,1); assert.equal(consoleMessages[0].sid,'console');
        consoleMessages.length=0; consoleDispatch('setclip',{_:['text']},'console');
        if(writeSucceeds) { assert.equal(consoleMessages.length,0); finish(); }
        await Promise.resolve(); assert.equal(consoleMessages.length,1);
        assert.match(consoleMessages[0].text,mode==='throw'||mode==='reject'?/failed/:/set/);
    }
}
console.log('Both MeshCentral cores: read failures and non-text stay silent for viewers, empty text reaches only the dialog, writes acknowledged only after completion; message and console paths passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
