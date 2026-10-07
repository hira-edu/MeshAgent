#!/usr/bin/env python3
"""Exercise the embedded helper through a real disposable Aqua LaunchAgent.

The request is deliberately unsupported: it verifies same-binary launch,
authenticated IPC, error delivery and cleanup without accessing the clipboard,
showing UI, capturing the screen or posting input.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', required=True, type=Path)
parser.add_argument('--child-logs', action='store_true', help='Capture fixture child startup diagnostics')
args = parser.parse_args()
if sys.platform != 'darwin' or os.getuid() == 0:
    parser.error('Run as the logged-in macOS user, without sudo')
uid = os.getuid()
if os.stat('/dev/console').st_uid != uid:
    parser.error('The caller must own the active desktop')
domain = 'gui/' + str(uid)
subprocess.run(['/bin/launchctl', 'print', domain], check=True, stdout=subprocess.DEVNULL)
with tempfile.TemporaryDirectory(prefix='mesh-helper-native-') as directory:
    root = Path(directory)
    # launchd must not load the test binary from a privacy-protected development
    # folder such as Documents. Use an isolated executable, as installation does.
    agent = root / 'meshagent'
    shutil.copy2(args.agent.resolve(), agent)
    marker = root / 'owned.json'
    script = 'var marker=' + json.dumps(str(marker)) + ';var childLog=' + json.dumps(str(root / 'child.log') if args.child_logs else '') + r''';
var fs=require('fs'), helper=require('message-box'), ret;
// Capture only this fixture's child startup failures, never clipboard/UI data.
var manager=require('service-manager').manager, install=manager.installLaunchAgent;
if(childLog){manager.installLaunchAgent=function(options){
    options.stdout=childLog;options.stderr=childLog;
    options.parameters[1]=options.parameters[1].replace('catch(e) { process.exit(1); }','catch(e) { console.log("HELPER START: "+e); process.exit(1); }');
    return install.call(this,options);
};}
function fail(e) { console.log('FAIL: '+e);process.exit(1); }
ret=helper._request({command:'UNSUPPORTED_PROBE'},function(){throw new Error('Unexpected success');});
var session=helper._session;
if (!session) { fail('No helper session'); }
fs.writeFileSync(marker,JSON.stringify({service:session.service,directory:session.directory,uid:session.uid}));
if (!session.directory || (fs.statSync(session.directory).mode & 511)!==448) { fail('Private directory mode'); }
function unsupported(error, label) {
    if ((''+error).indexOf('Unknown helper command')<0) {
        console.log('STATE ('+label+'): job='+!!session.job+', authenticated='+!!session.connection);
        if(childLog&&fs.existsSync(childLog)){console.log(fs.readFileSync(childLog).toString());}
        fail(error);return false;
    }
    return true;
}
ret.then(function(){fail('Unsupported request accepted');},function(error){
    if (!unsupported(error,'first')) { return; }
    // The next request reuses the same helper: one LaunchAgent, one background item.
    var second=helper._request({command:'UNSUPPORTED_PROBE'},function(){throw new Error('Unexpected success');});
    if (helper._session!==session) { fail('Second request started another helper');return; }
    second.then(function(){fail('Unsupported request accepted');},function(error2){
        if (!unsupported(error2,'second')) { return; }
        helper._closeSession(session);
        setTimeout(function(){
            if (fs.existsSync(session.directory)||fs.existsSync(session.plist)) { fail('Helper files retained');return; }
            console.log('PASS: embedded same-binary Aqua helper, authenticated IPC, reused for a second request, error responses and cleanup');
            process.exit(0);
        },2000);
    });
});
setTimeout(function(){fail('Probe deadline; done='+ret._done+', job='+!!session.job+', authenticated='+!!session.connection);},25000);
'''
    probe = root / 'probe.js'
    probe.write_text(script)
    try:
        result = subprocess.run([str(agent), str(probe)], cwd=root,
                                preexec_fn=lambda: os.umask(0), timeout=35,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout, end='')
        if result.returncode or 'PASS: embedded same-binary Aqua helper' not in result.stdout:
            raise SystemExit('Native helper probe failed: ' + str(result.returncode))
    finally:
        if marker.exists():
            owned = json.loads(marker.read_text())
            service = owned.get('service', '')
            if re.fullmatch(r'mesh-ui-\d{1,39}', service):
                if owned.get('uid') != uid or owned.get('directory') != '/var/tmp/' + service:
                    raise RuntimeError('Unexpected helper ownership record')
                label = service + '-launchagent'
                target = domain + '/' + label
                subprocess.run(['/bin/launchctl', 'bootout', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                check = subprocess.run(['/bin/launchctl', 'print', target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode != 113:
                    raise RuntimeError('Could not prove helper job removal: ' + target)
                plist = Path(pwd.getpwuid(uid).pw_dir) / 'Library/LaunchAgents' / (service + '.plist')
                if plist.exists():
                    if plistlib.loads(plist.read_bytes()).get('Label') != label:
                        raise RuntimeError('Unexpected fixture plist identity')
                    plist.unlink()
                private = Path(owned['directory'])
                if private.exists():
                    for name in ('ipc', 'config.json'):
                        try:
                            (private / name).unlink()
                        except FileNotFoundError:
                            pass
                    private.rmdir()
