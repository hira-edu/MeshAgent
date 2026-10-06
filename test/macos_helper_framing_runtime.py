#!/usr/bin/env python3
"""Exercise production macOS helper framing in Node and optionally MeshAgent.

The native probe also uses a temporary Unix socket to verify actual unshift
behavior. No GUI helper, clipboard command, or LaunchAgent is started.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path)
args = parser.parse_args()
source = (Path(__file__).resolve().parents[1] / 'modules/message-box.js').read_text()
start = source.index("if (process.platform == 'darwin')\n{\n    var MAC_HELPER_MAX_FRAME")
helpers = source[start:source.index('\nfunction macos_messageBox()', start)]
setup = 'var h=(new Function("process",' + json.dumps(helpers+'\nreturn {encode:translateObject,handler:macHelperDataHandler};') + '))({platform:"darwin"});\n'
script = r'''
function check(value, reason) { if (!value) { throw new Error(reason); } }
var value={command:'writeClip',clipText:'日本語 — café 😀\nquotes " and \\'};
var first=h.encode(value), second=h.encode({command:'DIALOG',button:'許可'}), stream=Buffer.concat([first,second]);
check(first.readUInt32LE(0)===first.length,'encoded byte length');
console.log('WIRE:'+first.toString('hex'));
var pending, messages, ended, rejected;
var socket={unshift:function(b){pending=Buffer.concat([b]);},end:function(){ended=true;},promise:{_rej:function(){rejected=true;}}};
function reset(){pending=Buffer.alloc(0);messages=[];ended=false;rejected=false;}
function feed(bytes){
    var data=Buffer.concat([pending,bytes]);pending=Buffer.alloc(0);
    h.handler(function(p){messages.push(p);}).call(socket,data);
}
for(var split=0;split<=stream.length;++split){
    reset();feed(stream.slice(0,split));feed(stream.slice(split));
    check(!ended&&pending.length===0&&messages.length===2,'fragment/coalesce '+split);
    check(messages[0].clipText===value.clipText&&messages[1].button==='許可','Unicode round trip');
}
reset();for(var i=0;i<stream.length;++i){feed(stream.slice(i,i+1));}check(messages.length===2,'bytewise fragments');
for(var n=0;n<6;++n){reset();var bad=Buffer.alloc(4);bad.writeUInt32LE(n,0);feed(bad);check(ended&&rejected&&!messages.length,'invalid short length');}
reset();var bad=Buffer.alloc(4);bad.writeUInt32LE(16*1024*1024+1,0);feed(bad);check(ended&&rejected,'frame bound');
reset();feed(h.encode({wrong:'field'}));check(ended&&rejected,'invalid command object');
console.log('PASS: helper UTF-8 framing, every split, coalesced messages, invalid lengths and commands');
'''
native_socket = r'''
var fs=require('fs'),net=require('net'), count=0, server=net.createServer();
var timer=setTimeout(function(){console.log('FAIL: native helper socket timed out');process.exit(1);},5000);
server.on('connection',function(c){
    c.on('data',h.handler(function(p){
        ++count;
        check(count===1?p.clipText===value.clipText:p.button==='許可','native decoded data');
        if(count===2){
            this.end();client.end();server.close();clearTimeout(timer);
            console.log('PASS: native Unix socket partial header and coalesced frame delivery');process.exit(0);
        }
    }));
});
server.listen({path:socketPath});
var client=net.createConnection({path:socketPath},function(){
    this.write(stream.slice(0,2));
    client.delayed=setTimeout(function(){client.write(stream.slice(2));},50);
});
'''
with tempfile.TemporaryDirectory(prefix='mesh-helper-frame-', dir='/tmp') as directory:
    probe = Path(directory) / 'probe.js'
    probe.write_text(setup + script)
    node = subprocess.run([shutil.which('node') or 'node', str(probe)], check=True, timeout=20, capture_output=True, text=True)
    expected_wire = bytes.fromhex(next(line[5:] for line in node.stdout.splitlines() if line.startswith('WIRE:')))
    assert int.from_bytes(expected_wire[:4], 'little') == len(expected_wire)
    assert '日本語' in json.loads(expected_wire[4:].decode('utf-8'))['clipText']
    print('\n'.join(line for line in node.stdout.splitlines() if not line.startswith('WIRE:')))
    if args.agent:
        # A short private directory fits Darwin's sockaddr_un and isolates peers.
        socket_path = str(Path(directory) / 'socket')
        probe.write_text(setup+script+'\nvar socketPath='+json.dumps(socket_path)+';\n'+native_socket)
        try:
            result = subprocess.run([str(args.agent.resolve()),str(probe)],cwd=directory,
                                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
            actual_wire = bytes.fromhex(next(line[5:] for line in result.stdout.splitlines() if line.startswith('WIRE:')))
            assert actual_wire == expected_wire, 'Native and Node JSON wire encodings differ'
            print('\n'.join(line for line in result.stdout.splitlines() if not line.startswith('WIRE:')))
            if result.returncode or 'PASS: native Unix socket' not in result.stdout:
                raise SystemExit('Native helper framing probe failed: '+str(result.returncode))
        finally:
            Path(socket_path).unlink(missing_ok=True)
