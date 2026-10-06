#!/usr/bin/env python3
"""Verify launchctl moves the single agent executable from Background to Aqua.

Creates two unique temporary jobs that only query their context and exit. With
root and --uid, uses the system domain to verify the privileged transition.
Without root, a denied cross-audit-session transition is explicitly skipped (77).
Neither job invokes KVM or accesses the desktop.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, required=True)
parser.add_argument('--uid', type=int, help='Active desktop user, required when running as root')
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('This probe requires macOS')
agent = str(args.agent.resolve())
root_worker = os.getuid() == 0
uid = args.uid if args.uid is not None else os.getuid()
if uid <= 0 or os.stat('/dev/console').st_uid != uid or (not root_worker and uid != os.getuid()):
    parser.error('Select the active desktop UID; only root can select another user')
domain = 'system' if root_worker else 'user/' + str(uid)
subprocess.run(['/bin/launchctl','print','gui/'+str(uid)],check=True,stdout=subprocess.DEVNULL)
worker = r'''
function query(argument) {
    var c=require('child_process').execFile('/bin/launchctl',['launchctl',argument]), out='', status=null;
    c.stdout.on('data',function(b){out+=b.toString();});c.stderr.on('data',function(){});
    c.on('exit',function(code){status=code;});c.waitExit(5000);
    if(status!==0){throw new Error('launchctl query failed');}return out.trim();
}
require('fs').writeFileSync(marker, JSON.stringify({pid:process.pid,uid:require('user-sessions').Self(),domain:query('managername'),managerUid:query('manageruid')}));
process.exit(0);
'''
labels = []
with tempfile.TemporaryDirectory(prefix='mesh-gui-launch-') as directory:
    folder = Path(directory)
    try:
        observations = {}
        for mode in ['background','aqua']:
            label = 'com.meshagent.test.' + uuid.uuid4().hex
            labels.append(label)
            marker = folder / (mode+'.json')
            script = folder / (mode+'.js')
            script.write_text('var marker='+json.dumps(str(marker))+';\n'+worker)
            argv = [agent,str(script)]
            if mode == 'aqua':
                argv = ['/bin/launchctl','asuser',str(uid)] + argv
            job = folder / (mode+'.plist')
            log = folder / (mode+'.log')
            config = {'Label':label,'ProgramArguments':argv,'RunAtLoad':True,'KeepAlive':False,'StandardOutPath':str(log),'StandardErrorPath':str(log)}
            if not root_worker:
                config['LimitLoadToSessionType'] = ['Background']
            job.write_bytes(plistlib.dumps(config))
            subprocess.run(['/bin/launchctl','bootstrap',domain,str(job)],check=True,capture_output=True,text=True,timeout=10)
            deadline = time.monotonic()+10
            while not marker.exists() and time.monotonic()<deadline:
                time.sleep(0.1)
            if not marker.exists():
                error = log.read_text() if log.exists() else 'no launch log'
                if not root_worker and mode == 'aqua' and 'Could not switch to audit session' in error and 'Operation not permitted' in error:
                    print('SKIP: privileged Background-to-Aqua transition requires a root test context (--uid selects the desktop user).')
                    sys.exit(77)
                raise RuntimeError(mode+' worker did not publish its context: '+error)
            observations[mode] = json.loads(marker.read_text())
        assert observations['background']['domain'] == ('System' if root_worker else 'Background'), observations
        assert observations['aqua']['domain'] == 'Aqua', observations
        assert all(row['uid']==os.getuid() for row in observations.values()), observations
        assert int(observations['aqua']['managerUid'])==uid, observations
        print('PASS: single built executable enters Aqua through launchctl asuser; launcher credentials remain unchanged for the helper to drop')
    finally:
        for label in labels:
            subprocess.run(['/bin/launchctl','bootout',domain+'/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            result = subprocess.run(['/bin/launchctl','print',domain+'/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if result.returncode != 113:
                raise RuntimeError('Could not verify removal of fixture '+label)
