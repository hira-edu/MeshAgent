#!/usr/bin/env python3
"""Exercise production clipboard dispatch with real Duktape promises, buffers and timers.

The Windows process/session APIs are injected, so this runs on any built agent
without launching helpers or touching a clipboard, service, or network.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
prefix = r'''
var process = {platform:'win32',pid:123};
// Real Duktape timers, 1000x faster: clearTimeout keeps its fired-timer semantics.
var setTimeout = function(fn,ms){return global.clipboardFastTimer(fn,ms);};
var originalRequire = require;
require = function(name) {
    if(name=='child_process')return global.clipboardChildren;
    if(name=='win-system-paths')return {system32Path:function(){return 'rundll32';},installedServiceRuntimeDll:function(){return 'C:\\agent.dll';}};
    if(name=='_agentNodeId')return {serviceName:function(){return 'probe';}};
    if(name=='user-sessions')return {Current:function(){return {Active:[{SessionId:'3'}]};}};
    return originalRequire(name);
};
'''
script = r'''
var failures=[], child, launches=0, completed=0, kills=0;
global.clipboardFastTimer=function(fn,ms){return setTimeout(fn,Math.max(1,ms/1000));};
process.on('uncaughtException',function(e){failures.push('uncaught: '+e);});
function assert(value,label){if(!value)failures.push(label);}
function emitter(){return {listeners:{},on:function(name,fn){this.listeners[name]=fn;},emit:function(name,value){if(this.listeners[name])this.listeners[name](value);}};}
global.clipboardChildren={execFile:function(){
    ++launches;child=emitter();child.stdout=emitter();child.stderr=emitter();child.stdin=emitter();child.writes=[];
    child.stdin.write=function(frame){this.writes.push(frame);}.bind(child);child.stdin.end=function(){};child.kill=function(){++kills;this.emit('exit',0);};return child;
}};
addModule('clipboard',SOURCE,'2099-01-01T00:00:00.000Z');
var clipboard=require('clipboard');
var reads=[];
for(var i=0;i<32;++i){reads.push(clipboard.dispatchRead());reads[i].then(function(value){assert(value=='日本 😀','unicode');++completed;},function(error){failures.push('read: '+error);});}
assert(launches==1 && child.writes.length==1,'coalesced native read');
var value=Buffer.from('e697a5e69cac20f09f9880','hex'),frame=Buffer.alloc(12+value.length);frame.writeUInt32LE(1,0);frame.writeUInt32LE(0,4);frame.writeUInt32LE(value.length,8);value.copy(frame,12);
child.stdout.emit('data',frame.slice(0,5));child.stdout.emit('data',frame.slice(5));
assert(completed==32,'every Duktape subscriber completes');
var wrote=false;clipboard.dispatchWrite('日本 😀').then(function(){wrote=true;},function(error){failures.push('write: '+error);});
assert(child.writes[1].slice(12).toString('hex').toLowerCase()=='e697a5e69cac20f09f9880','surrogate pairs encode as UTF-8: '+child.writes[1].slice(12).toString('hex'));
assert(!wrote,'async write');frame=Buffer.alloc(12);frame.writeUInt32LE(2,0);child.stdout.emit('data',frame);assert(wrote,'write complete');
var empty=false;clipboard.dispatchWrite('').then(function(){empty=true;});frame.writeUInt32LE(3,0);child.stdout.emit('data',frame);assert(empty,'empty write complete');
var errors=0;clipboard.dispatchRead().then(function(){failures.push('read unexpectedly succeeded');},function(){++errors;});child.emit('exit',1314);
for(var i=0;i<100;++i){clipboard.dispatchRead().then(function(){failures.push('failed read succeeded');},function(){++errors;});}
assert(errors==101 && launches==1,'failed-start retry backoff');
// Ignored legacy write failures must also remain contained.
clipboard.dispatchWrite('ignored');
// Request timeout (first request: 30 ms scaled) must kill the broker and reject the caller.
var timedOut=null;clipboard.dispatchRead(7).then(function(){failures.push('timeout read succeeded');},function(e){timedOut=''+e;});
// Idle close (60 ms scaled) fires after a completed request and must kill the broker.
var idleChild=null,idleValue=null;clipboard.dispatchRead(8).then(function(v){idleValue=v;},function(e){failures.push('idle read: '+e);});
idleChild=child;var reply=Buffer.alloc(12);reply.writeUInt32LE(idleChild.writes[0].readUInt32LE(0),0);idleChild.stdout.emit('data',reply);
// One consumer's exception must not strand another waiter or close the helper.
var thrower=clipboard.dispatchRead(9),sibling=null;thrower.then(function(){throw new Error('consumer failure');});
clipboard.dispatchRead(9).then(function(v){sibling=v;},function(e){failures.push('sibling: '+e);});
var shared=child;reply.writeUInt32LE(shared.writes[0].readUInt32LE(0),0);shared.stdout.emit('data',reply);
setTimeout(function(){
    assert(timedOut && /timed out/.test(timedOut),'request timeout rejected: '+timedOut);
    assert(idleValue==='','idle request completed');
    assert(sibling==='','sibling waiter completed after consumer exception');
    assert(kills==3,'timeout and both idle closes killed their brokers: '+kills);
    console.log('CLIPBOARD '+JSON.stringify({failures:failures,completed:completed,errors:errors,launches:launches,kills:kills}));process.exit(failures.length?1:0);
},250);
'''
script = script.replace('SOURCE', json.dumps(prefix+(root/'modules/clipboard.js').read_text()))
with tempfile.TemporaryDirectory(prefix='mesh-clipboard-agent-') as directory:
    probe=Path(directory)/'probe.js'
    probe.write_text(script)
    result=subprocess.run([str(args.agent.resolve()),str(probe)],cwd=directory,capture_output=True,text=True,timeout=20)
    line=next((line for line in result.stdout.splitlines() if line.startswith('CLIPBOARD ')),None)
    assert result.returncode==0 and line is not None, result
    report=json.loads(line[len('CLIPBOARD '):])
    assert not report['failures'],report
    print('PASS: real Duktape promises/buffers/timers, 32 shared read subscribers, Unicode, completion acknowledgements, 101 handled failures, '
      'ignored-write containment, timeout and idle cleanup on fired timers, consumer exception isolation')
