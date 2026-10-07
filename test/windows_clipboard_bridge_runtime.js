'use strict';
// Executes production clipboard dispatch with injected process/pipe/timer observations.
// Does not read or alter the host clipboard or launch any Windows process.
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm');
const {EventEmitter} = require('events');
const source = fs.readFileSync(path.join(__dirname, '../modules/clipboard.js'), 'utf8');
{
    // The agent runs its embedded copy unless a newer-dated override arrives, so a stale
    // embed silently ships the previous implementation. Keep the two identical.
    const polyfills = fs.readFileSync(path.join(__dirname, '../microscript/ILibDuktape_Polyfills.c'), 'utf8');
    const embed = /addCompressedModule\('clipboard', Buffer\.from\('([^']+)', 'base64'\), '([^']+)'\)/.exec(polyfills);
    assert(embed, 'embedded clipboard module entry');
    const embedded = require('zlib').inflateSync(Buffer.from(embed[1], 'base64')).toString('utf8');
    assert.equal(embedded.replace(/\r\n?/g, '\n'), source.replace(/\r\n?/g, '\n'), 'embedded clipboard module matches modules/clipboard.js; re-embed it');
}
class Result {
    constructor(executor) { this.handlers = []; executor.call(this, v => this.settle(false, v), e => this.settle(true, e)); }
    settle(failed, value) { if (this.done) return; this.done = true; this.failed = failed; this.value = value; this.handlers.forEach(h => this.deliver(h)); }
    deliver(h) { const fn = this.failed ? h[1] : h[0]; if (fn) fn(this.value); }
    then(success, failure) { const h = [success, failure]; this.handlers.push(h); if (this.done) this.deliver(h); return this; }
    catch(failure) { this.then(null, failure); }
}
function fixture(options = {}) {
    let now = 1000, launched = 0, killed = 0, sessions = [{SessionId:'3'}], name;
    const children = [], timers = new Map(), fired = new Set(); let nextTimer = 0;
    const context = { module:{exports:{}}, Buffer, process:{platform:'win32',pid:123},
        Date:{now:() => now}, isFinite,
        setTimeout(fn, ms) { const id = ++nextTimer; timers.set(id,{fn,at:now + ms}); return id; },
        // Mirrors Duktape: clearing a timer that already fired throws instead of being a no-op.
        clearTimeout(id) { if (fired.has(id)) throw Error('timers.clearTimeout(): Invalid Parameter'); timers.delete(id); },
        require(module) {
            if (module === 'promise') return Result;
            if (module === 'user-sessions') return {Current() { if (options.sessionError) throw Error('session enumeration denied'); return {Active:sessions}; }};
            if (module === '_agentNodeId') return {serviceName:() => 'incumbent-service'};
            if (module === 'win-system-paths') return {installedServiceRuntimeDll(service) { name = service; if(options.pathError) throw Error('DLL missing'); return 'C:\\Agent With Spaces\\agent.dll'; }, system32Path:()=> 'C:\\Windows\\System32\\rundll32.exe'};
            if (module === 'child_process') return {execFile(exe,args) {
                ++launched; assert.equal(exe, 'C:\\Windows\\System32\\rundll32.exe');
                assert.equal(args.length, 2); assert.equal(args[0], 'C:\\Agent With Spaces\\agent.dll,MeshClipboardBridgeW');
                if (options.launchError) throw Error('launch denied');
                const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter(); child.writes = [];
                child.stdin.write = frame => { if (options.writeError) throw Error('pipe broken'); child.writes.push(frame); };
                child.stdin.end = () => { if (options.endError) throw Error('end failed'); }; child.kill = () => { ++killed; if(options.killError) throw Error('kill denied'); if(!options.delayedExit) child.emit('exit', 0); };
                child.args = args; children.push(child); return child;
            }};
            throw Error('Unexpected dependency: ' + module);
        }};
    vm.runInNewContext(source, context);
    return { clip:context.module.exports, children, timers,
        counts:() => ({launched,killed,name}), sessions(value) { sessions = value; },
        advance(ms) { now += ms; const due = [...timers.entries()].filter(([,t])=>t.at <= now); for (const [id,t] of due) { if(timers.delete(id)) { fired.add(id); t.fn(); } } },
        reply(child, text='', code=0, splits=[]) {
            const request = child.writes[child.writes.length - 1]; const data = Buffer.from(text);
            const header = Buffer.alloc(12); header.writeUInt32LE(request.readUInt32LE(0)); header.writeUInt32LE(code,4); header.writeUInt32LE(data.length,8);
            const frame = Buffer.concat([header,data]); let offset = 0;
            for (const size of splits) { child.stdout.emit('data',frame.slice(offset,offset + size)); offset += size; }
            if(offset < frame.length) child.stdout.emit('data',frame.slice(offset));
        }};
}
function rejected(result, pattern) { assert.equal(result.done,true); assert.equal(result.failed,true); assert.match(String(result.value),pattern); }
{
    const f = fixture(), first = f.clip.dispatchRead();
    const shared = [first];
    for(let i=0;i<63;++i) shared.push(f.clip.dispatchRead());
    for(let i=0;i<1000;++i) rejected(f.clip.dispatchRead(),/waiter limit/);
    assert.equal(f.counts().launched,1); assert.equal(f.counts().name,'incumbent-service');
    f.reply(f.children[0], 'Unicode ✓ 日本 😀',0,[1,2,3,4,1,2,1]);
    assert.equal(first.value,'Unicode ✓ 日本 😀');
    shared.forEach(result => assert.equal(result.value,first.value));
    const clear = f.clip.dispatchWrite(''), after = f.clip.dispatchRead();
    assert.equal(clear.done,undefined); assert.equal(after.done,undefined);
    assert.equal(f.children[0].writes.length,2);
    f.reply(f.children[0]); assert.equal(clear.done,true); assert.equal(f.children[0].writes.length,3);
    f.reply(f.children[0]); assert.equal(after.value,'');
    const text = "' ; $() `\r\n日本 😀", write = f.clip.dispatchWrite(text);
    assert.equal(f.children[0].writes.at(-1).slice(12).toString(),text);
    assert.equal(f.children[0].args.length,2,'text never reaches command line');
    f.reply(f.children[0]); assert.equal(write.failed,false);
    f.advance(60000); assert.equal(f.counts().killed,1); assert.equal(f.timers.size,0);
    f.clip.dispatchRead(); assert.equal(f.counts().launched,2); f.advance(30000); assert.equal(f.timers.size,0);
}
{
    const f=fixture({endError:true}), read=f.clip.dispatchRead(); f.advance(30000);
    rejected(read,/timed out/); assert.equal(f.counts().killed,1,'stdin cleanup failure must not skip process cleanup');
}
for (const options of [{launchError:true},{pathError:true},{writeError:true}]) {
    const f = fixture(options); rejected(f.clip.dispatchRead(),/denied|missing|broken/);
    for(let i=0;i<1000;++i) rejected(f.clip.dispatchRead(),/denied|missing|broken/);
    assert.equal(f.counts().launched,options.pathError ? 0 : 1,'failed polling must not relaunch');
    f.advance(30000); f.clip.dispatchRead(); assert.equal(f.counts().launched,options.pathError ? 0 : 2); assert.equal(f.timers.size,0);
}
{
    const f=fixture(), r=f.clip.dispatchRead(), w=f.clip.dispatchWrite('queued'); f.advance(30000);
    rejected(r,/timed out/); rejected(w,/timed out/); assert.equal(f.counts().killed,1);
    rejected(f.clip.dispatchRead(),/timed out/); assert.equal(f.counts().launched,1); assert.equal(f.timers.size,0);
    f.advance(30000); const retry=f.clip.dispatchRead(); f.reply(f.children[1],'ok'); assert.equal(retry.value,'ok'); f.advance(60000);
}
{
    const f=fixture(), r=f.clip.dispatchRead(); f.reply(f.children[0],'',5); rejected(r,/error=5/);
    const next=f.clip.dispatchRead(); f.reply(f.children[0],''); assert.equal(next.value,''); assert.equal(f.counts().launched,1);
    f.advance(60000);
}
for(const mode of ['id','oversize','status','write-data','extra','exit','end','error','stderr-error']) {
    const f=fixture(), r= mode==='write-data' ? f.clip.dispatchWrite('x') : f.clip.dispatchRead(), child=f.children[0];
    if(mode==='exit') child.emit('exit',1314);
    else if(mode==='end') child.stdout.emit('end');
    else if(mode==='stderr-error') child.stderr.emit('error',Error('stderr broken'));
    else if(mode==='error') child.stdin.emit('error',Error('broken'));
    else {
        const frame=Buffer.alloc(13); frame.writeUInt32LE(mode==='id' ? 99 : 1); frame.writeUInt32LE(mode==='status' ? 5 : 0,4);
        frame.writeUInt32LE(mode==='oversize' ? 1024*1024+1 : (mode==='status'||mode==='write-data' ? 1 : 0),8);
        child.stdout.emit('data',frame);
    }
    rejected(r,/Invalid|exited|ended|broken/); assert.equal(f.counts().killed,mode==='exit' ? 0 : 1); assert.equal(f.timers.size,0);
}
{
    const f=fixture();
    for(const id of [0,-1,1.5,NaN,Infinity,0xFFFFFFFF,'3']) rejected(f.clip.dispatchRead(id),/session ID/);
    for(const value of ['a\0b','x'.repeat(1024*1024+1),'😀'.repeat(300000),{}]) rejected(f.clip.dispatchWrite(value),/text|1 MiB/);
    f.sessions([]); rejected(f.clip.dispatchRead(),/No interactive/); assert.equal(f.counts().launched,0);
    f.sessions([{SessionId:'3'}]); const read=f.clip.dispatchRead();
    for(let i=0;i<16;++i) f.clip.dispatchWrite('q'); rejected(f.clip.dispatchWrite('overflow'),/queue is full/);
    for(let i=0;i<17;++i) f.reply(f.children[0]); assert.equal(read.value,''); f.advance(60000);
    for(let id=1;id<=4;++id) f.clip.dispatchRead(id); rejected(f.clip.dispatchRead(5),/session limit/);
    f.advance(30000); assert.equal(f.counts().killed,5); f.advance(30000);
    f.clip.dispatchRead(5); assert.equal(f.counts().launched,6); f.advance(30000);
}
{
    const f=fixture(); const local=f.clip.read(); assert.equal(f.children[0].args[1],'local'); f.reply(f.children[0],'local'); assert.equal(local.value,'local'); f.advance(60000);
    rejected(fixture({sessionError:true}).clip.dispatchRead(),/enumeration denied/);
}
{
    // A fresh helper's first request includes launch; later requests get the steady-state bound.
    const f=fixture(), first=f.clip.dispatchRead(); f.advance(29999); assert.equal(first.done,undefined);
    f.reply(f.children[0],'up'); assert.equal(first.value,'up');
    const next=f.clip.dispatchRead(); f.advance(14999); assert.equal(next.done,undefined);
    f.advance(1); rejected(next,/timed out/); assert.equal(f.counts().killed,1); assert.equal(f.timers.size,0);
}
{
    // Timeout and idle callbacks run on fired timers; neither may abort cleanup.
    const f=fixture(), r=f.clip.dispatchRead(); f.reply(f.children[0],'x'); f.advance(60000);
    assert.equal(r.value,'x'); assert.equal(f.counts().killed,1,'idle close kills the broker');
    const again=f.clip.dispatchRead(); assert.equal(f.counts().launched,2); f.advance(30000);
    rejected(again,/timed out/); assert.equal(f.counts().killed,2,'timeout close kills the broker');
}
{
    const f=fixture({killError:true}), a=f.clip.dispatchRead(), b=f.clip.dispatchRead();
    a.then(null,()=>{ throw Error('caller failed'); });
    f.advance(30000); rejected(b,/timed out/);
    f.advance(30000);
    for(let i=0;i<1000;i++) rejected(f.clip.dispatchRead(),/still terminating/);
    assert.equal(f.counts().launched,1,'failed kill cannot cause overlapping helpers');
    f.children[0].emit('exit',0); f.clip.dispatchRead(); assert.equal(f.counts().launched,2);
}
{
    const f=fixture(), a=f.clip.dispatchRead(), b=f.clip.dispatchRead();
    a.then(()=>{ throw Error('caller failed'); });
    f.reply(f.children[0],'ok'); assert.equal(b.value,'ok');
    const c=f.clip.dispatchRead(); f.reply(f.children[0],'again'); assert.equal(c.value,'again'); f.advance(60000);
}
{
    const f=fixture({delayedExit:true}), a=f.clip.dispatchRead(); f.reply(f.children[0],'ok'); f.advance(60000);
    rejected(f.clip.dispatchRead(),/still terminating/); assert.equal(f.counts().launched,1);
    f.children[0].emit('exit',0); f.clip.dispatchRead(); assert.equal(f.counts().launched,2);
}
console.log('Windows clipboard dispatch: reuse, coalescing, serialization, Unicode/empty text, bounded queues, failure backoff, timeouts and cleanup passed.');
