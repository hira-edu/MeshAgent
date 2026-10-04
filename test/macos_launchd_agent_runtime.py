#!/usr/bin/env python3
"""Verify the built single executable under a disposable user launchd job.

Registers only a unique job in the current GUI domain, backed by a temporary
plist. It never touches system services or installed agent state. The job is
removed in finally even if the native probe fails.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import uuid

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent',type=Path,required=True)
args=parser.parse_args()
if sys.platform != 'darwin' or os.getuid()==0:
    parser.error('Run as a logged-in macOS user, without sudo')
agent=args.agent.resolve()
label='com.meshagent.test.'+uuid.uuid4().hex
domain='gui/'+str(os.getuid())
subprocess.run(['/bin/launchctl','print',domain],check=True,stdout=subprocess.DEVNULL)
root=Path(__file__).resolve().parents[1]
source=(root/'modules/service-manager.js').read_text()
a=source.index("if (process.platform == 'darwin')\n{");b=source.index('\nfunction serviceManager()',a)
with tempfile.TemporaryDirectory(prefix='mesh-launchd-session-') as temporary:
    temp=Path(temporary);folder=temp/'LaunchAgents';folder.mkdir()
    marker=temp/'worker-pid.txt';worker=temp/'worker.js'
    worker.write_text('require("fs").writeFileSync('+json.dumps(str(marker))+', ""+process.pid);setInterval(function(){},1000);')
    plist=folder/(label+'.plist')
    plist.write_bytes(plistlib.dumps({'Label':label,'ProgramArguments':[str(agent),str(worker)],'RunAtLoad':False,'KeepAlive':False}))
    script='function serviceNotFound(name){return new Error(name);}\n'+source[a:b]+'\n'
    script+='var folder='+json.dumps(str(folder))+';var label='+json.dumps(label)+';var marker='+json.dumps(str(marker))+';\n'
    script+='''
var fs=require('fs'), job=fetchPlist(folder,label), first;
function fail(e) { if((''+e).indexOf('Process.exit() forced script termination')>=0){throw e;} console.log('FAIL: '+e);process.exit(1); }
function waitWorker(old, next) {
    var tries=0,timer=setInterval(function(){
        try {
            var pid=fs.existsSync(marker)?parseInt(fs.readFileSync(marker).toString()):0;
            if(pid>0&&pid!=old&&job.getPID()==pid){clearInterval(timer);next(pid);return;}
            if(++tries>=40){clearInterval(timer);throw new Error('Worker did not start');}
        } catch(e){clearInterval(timer);fail(e);}
    },250);
}
try {
    if(job.isLoaded()){throw new Error('Unexpected existing fixture');}
    job.start();
    waitWorker(0,function(pid){
        first=pid;job.restart();
        waitWorker(first,function(second){
            job.stop();
            if(job.isLoaded()||job.isRunning()){throw new Error('Job retained after stop');}
            job.start();
            waitWorker(second,function(){
                job.unload();job.unload();
                console.log('PASS: single built executable under launchd; start, restart, stop, reload, idempotent removal');
                process.exit(0);
            });
        });
    });
} catch(e){fail(e);}
'''
    probe=temp/'probe.js';probe.write_text(script)
    try:
        result=subprocess.run([str(agent),str(probe)],cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=45)
        print(result.stdout,end='')
        if result.returncode or 'PASS: single built executable' not in result.stdout:
            raise SystemExit('User launchd probe failed: '+str(result.returncode))
    finally:
        # Only the unique job created above may be removed.
        subprocess.run(['/bin/launchctl','bootout',domain+'/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        check=subprocess.run(['/bin/launchctl','print',domain+'/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode!=113:
            raise RuntimeError('Could not prove fixture job was removed: '+label)
