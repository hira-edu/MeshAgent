#!/usr/bin/env python3
"""Run macOS lifecycle primitives in the built MeshAgent JS runtime.

Uses temporary files, real plutil, and read-only launchctl queries. No service
installation, screen access, or changes to an installed agent.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, required=True)
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('This probe requires macOS')
root = Path(__file__).resolve().parents[1]
source = (root/'modules/service-manager.js').read_text()
a=source.index("if (process.platform == 'darwin')\n{")
b=source.index('\nfunction serviceManager()',a)
with tempfile.TemporaryDirectory(prefix='mesh-agent-runtime-') as temporary:
    temp=Path(temporary)
    script = '''
var fs = require('fs');
function check(value, message) { if (!value) { throw new Error(message); } }
function serviceNotFound(name) { var e=new Error('Service not found: '+name);e.code='ENOENT';return e; }
''' + source[a:b] + '\nvar root=' + json.dumps(str(temp)) + ''';
try {
    var installed = require('service-manager');
    check(installed.getOSVersion().compareTo('10.10') >= 0, 'embedded launchd adapter');
    fs.mkdirSync(root+'/LaunchAgents');
    var file=root+'/LaunchAgents/Quote & Agent.plist';
    var executable=root+'/A & <quoted> agent';
    var xml='<plist version="1.0"><dict><key>Label</key><string>com.meshagent.runtime.fixture</string><key>ProgramArguments</key><array><string>'+macPlistString(executable)+'</string></array></dict></plist>';
    macWritePlist(file,xml);
    var job=fetchPlist(root+'/LaunchAgents','Quote & Agent');
    check(job.appLocation()==executable,'XML escaped executable path');
    check(job.appWorkingDirectory()=='/','launchd default working directory');
    check(!job.isLoaded(),'nonexistent job is not loaded');
    macServiceCommand('/usr/bin/plutil',['-convert','binary1','--',file]);
    check(job.appLocation()==executable,'binary plist');
    var stale=file+'.'+process.pid+'.tmp';fs.writeFileSync(stale,'keep');
    var rejected=false;try{macWritePlist(file,xml);}catch(e){rejected=true;}
    check(rejected && fs.readFileSync(stale).toString()=='keep','exclusive-create ownership');
    fs.unlinkSync(stale);
    rejected=false;try{macWritePlist(file,'<invalid>');}catch(e){rejected=true;}
    check(rejected && job.appLocation()==executable,'failed validation retains incumbent plist');
    rejected=false;try{macServiceCommand('/bin/launchctl',['print','system/com.meshagent.runtime.fixture']);}catch(e){rejected=e.exitCode==113;}
    check(rejected,'real launchctl exit propagation');
    console.log('PASS: built agent, embedded lifecycle module, native child exit, XML/binary plists and exclusive writes');
    process.exit(0);
} catch(e) {
    if((''+e).indexOf('Process.exit() forced script termination')>=0){throw e;}
    console.log('FAIL: '+e);process.exit(1);
}
'''
    probe = temp/'probe.js';probe.write_text(script)
    result=subprocess.run([str(args.agent.resolve()),str(probe)],cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=45)
    print(result.stdout,end='')
    if result.returncode != 0 or 'PASS: built agent' not in result.stdout:
        raise SystemExit('Built-agent macOS probe failed: '+str(result.returncode))
