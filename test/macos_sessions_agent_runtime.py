#!/usr/bin/env python3
"""Read-only account/session checks using the real built MeshAgent runtime."""
import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, required=True)
parser.add_argument('--source', action='store_true', help='Load current source instead of the embedded module')
args = parser.parse_args()
if sys.platform != 'darwin':
    parser.error('This probe requires macOS')
account = pwd.getpwuid(os.getuid())
console = os.stat('/dev/console').st_uid
source = (Path(__file__).resolve().parents[1] / 'modules/user-sessions.js').read_text()
setup = 'var s = require("user-sessions");'
if args.source:
    setup = 'var m={exports:{}}; (new Function("require","module","exports",' + json.dumps(source) + '))(require,m,m.exports); var s=m.exports;'
script = setup + '\nvar expected=' + json.dumps({'uid':account.pw_uid, 'gid':account.pw_gid, 'name':account.pw_name, 'home':account.pw_dir, 'console':console}) + r''';
function check(value, reason) { if (!value) { throw new Error(reason); } }
try {
    check(s.Self() === expected.uid, 'native self UID');
    check(s.getUsername(expected.uid) === expected.name, 'native account lookup');
    check(s.getUid(expected.name) === expected.uid, 'name to UID');
    check(s.getGroupID(expected.uid) === expected.gid, 'primary group');
    check(s.getHomeFolder(expected.name) === expected.home, 'home plist through native stdin');
    check(s._users().nobody == '4294967294', 'historical signed nobody ID');
    if (expected.console > 0 && expected.console < 4294967294) { check(s.consoleUid() === expected.console, 'foreground console ownership'); }
    else { var absent=false;try{s.consoleUid();}catch(e){absent=true;}check(absent,'no console user'); }
    var sessions=s.Current();
    for (var name in sessions) { check(sessions[name].uid === s.getUid(name), 'every session has its own UID'); }
    var failed=false;try{s.getUsername('501;exit');}catch(e){failed=true;}check(failed,'invalid ID rejected');
    failed=false;try{s.getUid('meshagent-nonexistent-account-fixture');}catch(e){failed=true;}check(failed,'native lookup failure propagated');
    console.log('PASS: built-agent account queries, console ownership, home plist stdin, current session IDs and failure handling');
    process.exit(0);
} catch(e) {
    if ((''+e).indexOf('Process.exit() forced script termination') >= 0) { throw e; }
    console.log('FAIL: '+e);process.exit(1);
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-sessions-native-') as directory:
    probe = Path(directory) / 'probe.js'
    probe.write_text(script)
    result = subprocess.run([str(args.agent.resolve()), str(probe)], cwd=directory,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    print(result.stdout, end='')
    if result.returncode or 'PASS: built-agent account' not in result.stdout:
        raise SystemExit('Native session probe failed: ' + str(result.returncode))
