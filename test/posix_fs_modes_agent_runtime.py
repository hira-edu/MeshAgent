#!/usr/bin/env python3
"""Check creation modes in the built runtime with umask 0, using only temp files."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', required=True, type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='mesh-fs-modes-') as directory:
    root = Path(directory)
    (root / 'target').write_text('keep')
    (root / 'link').symlink_to(root / 'target')
    script = 'var root=' + json.dumps(directory) + ';var numericFlags=' + str(os.O_WRONLY | os.O_CREAT | os.O_EXCL) + r''';
var fs=require('fs');
function check(ok, reason) { if (!ok) { throw new Error(reason); } }
function mode(path) { return fs.statSync(root+'/'+path).mode & 4095; }
function refused(fn) { var failed=false;try{fn();}catch(e){failed=true;}check(failed,'operation unexpectedly accepted'); }
try {
    fs.mkdirSync(root+'/private',448);
    check(mode('private')===448,'directory was not initially 0700');
    var fd=fs.openSync(root+'/secret','wx',384);
    check(mode('secret')===384,'string open was not initially 0600');
    fs.writeSync(fd,'secret');fs.closeSync(fd);
    refused(function(){fs.openSync(root+'/secret','wx',511);});
    check(mode('secret')===384&&fs.readFileSync(root+'/secret').toString()==='secret','exclusive collision changed incumbent');
    refused(function(){fs.openSync(root+'/link','wx',384);});
    check(fs.readFileSync(root+'/target').toString()==='keep','exclusive open followed symlink');
    fd=fs.openSync(root+'/secret','a',384);fs.writeSync(fd,'!');fs.closeSync(fd);
    check(fs.readFileSync(root+'/secret').toString()==='secret!','append lost existing bytes');
    fd=fs.openSync(root+'/secret','r+',511);fs.closeSync(fd);
    check(mode('secret')===384,'opening incumbent changed permissions');
    fd=fs.openSync(root+'/numeric',numericFlags,384);
    check(fd>=0&&mode('numeric')===384,'numeric creation mode');fs.closeSync(fd);
    fd=fs.openSync(root+'/numeric-default',numericFlags);
    check(fd>=0&&mode('numeric-default')===438,'numeric default mode');fs.closeSync(fd);
    fd=fs.openSync(root+'/zero','wx',0);fs.closeSync(fd);
    check(mode('zero')===0,'zero mode ignored');
    [NaN,Infinity,-1,4096,384.5].forEach(function(bad){
        refused(function(){fs.openSync(root+'/invalid','wx',bad);});
        refused(function(){fs.mkdirSync(root+'/invalid-directory',bad);});
    });
    check(!fs.existsSync(root+'/invalid')&&!fs.existsSync(root+'/invalid-directory'),'invalid mode created a path');
    console.log('PASS: initial creation modes, numeric default, exclusive collision, symlink, append and invalid modes');
    process.exit(0);
} catch(e) {
    if((''+e).indexOf('Process.exit() forced script termination')>=0){throw e;}
    console.log('FAIL: '+e);process.exit(1);
}
'''
    probe = root / 'probe.js'
    probe.write_text(script)
    result = subprocess.run([str(args.agent.resolve()), str(probe)], cwd=root,
                            preexec_fn=lambda: os.umask(0), timeout=20,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, end='')
    if result.returncode or 'PASS: initial creation modes' not in result.stdout:
        raise SystemExit('Filesystem mode probe failed: ' + str(result.returncode))
