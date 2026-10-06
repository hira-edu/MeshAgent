#!/usr/bin/env python3
"""Exercise production macOS installation with native MeshAgent filesystem APIs.

All /Library paths are redirected into a temporary directory. No live service
is installed, started, or removed; plutil validates the actual resulting files.
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
source = (Path(__file__).resolve().parents[1] / 'modules/service-manager.js').read_text()
helpers = source[source.index('function extractFileName('):source.index('function prepareFolders(')]
start = source.index("if (process.platform == 'darwin')\n{")
block = source[start:source.index('\nfunction serviceManager()', start)]
with tempfile.TemporaryDirectory(prefix='mesh-install-native-') as directory:
    script = 'var root = ' + json.dumps(directory) + r''';
var nativeRequire = require, nativeFS = require('fs'), fixtureFS = {}, failWrite = '';
function check(value, reason) { if (!value) { throw new Error(reason); } }
function map(path) { return typeof path == 'string' && (path == '/Library' || path.indexOf('/Library/') == 0) ? root + '/system' + path : path; }
['existsSync','statSync','mkdirSync','chmodSync','unlinkSync','rmdirSync','readFileSync'].forEach(function (key) {
    fixtureFS[key] = function (path) { return nativeFS[key].apply(nativeFS, [map(path)].concat(Array.prototype.slice.call(arguments, 1))); };
});
fixtureFS.openSync = function (path, flags, mode) { if (failWrite && path.indexOf(failWrite) >= 0) { throw new Error('injected failure'); } return nativeFS.openSync(map(path), flags, mode); };
fixtureFS.writeSync = function () { return nativeFS.writeSync.apply(nativeFS, arguments); };
fixtureFS.closeSync = function () { return nativeFS.closeSync.apply(nativeFS, arguments); };
fixtureFS.renameSync = function (a,b) { return nativeFS.renameSync(map(a),map(b)); };
require = function (name) { return name == 'fs' ? fixtureFS : nativeRequire(name); };
''' + helpers + block + r'''
var originalCommand = macServiceCommand;
macServiceCommand = function (executable, argv, options) {
    check(executable == '/usr/bin/plutil', 'Unexpected child: ' + executable);
    return originalCommand(executable, argv.map(map), options);
};
try {
    nativeFS.mkdirSync(root+'/system');
    nativeFS.writeFileSync(root+'/source', 'binary fixture');
    nativeFS.writeFileSync(root+'/source.msh', 'incoming provisioning');
    var manager = {isAdmin: function () { return true; }};
    function options() { return {name:'Mesh & fixture', target:'agent', servicePath:root+'/source', installPath:root+'/installed', startType:'AUTO_START', files:[{source:root+'/source.msh',newName:'agent.msh'}]}; }
    var receipt = macInstallService(options(), manager);
    check(nativeFS.readFileSync(root+'/installed/agent.msh').toString() == 'incoming provisioning', 'native file copy');
    var config = JSON.parse(macServiceCommand('/usr/bin/plutil',['-convert','json','-o','-','--','/Library/LaunchDaemons/Mesh & fixture.plist']));
    check(config.ProgramArguments[0] == root+'/installed/agent' && config.KeepAlive.SuccessfulExit === false, 'installed launchd configuration');
    check((nativeFS.statSync(root+'/installed/agent').mode & 511) == 493, 'executable mode');
    check((nativeFS.statSync(root+'/installed/agent.msh').mode & 511) == 384, 'private provisioning mode');
    receipt.rollback();
    check(!nativeFS.existsSync(root+'/installed'), 'rollback removes new files and directory');
    nativeFS.mkdirSync(root+'/installed');
    nativeFS.writeFileSync(root+'/installed/agent.msh', 'incumbent identity');
    receipt = macInstallService(options(), manager); receipt.rollback();
    check(nativeFS.readFileSync(root+'/installed/agent.msh').toString() == 'incumbent identity', 'rollback retains prior provisioning');
    nativeFS.unlinkSync(root+'/installed/agent.msh');
    failWrite = '/agent.msh';
    var failed = false; try { macInstallService(options(), manager); } catch(e) { failed = (''+e).indexOf('injected failure') >= 0; }
    check(failed && !nativeFS.existsSync(root+'/installed/agent'), 'failed extras roll back binary');
    check(!nativeFS.existsSync(map('/Library/LaunchDaemons/Mesh & fixture.plist')), 'failed install never publishes job');
    console.log('PASS: native installation writes, modes, plutil, rollback, and incumbent provisioning');
    process.exit(0);
} catch(e) {
    if ((''+e).indexOf('Process.exit() forced script termination') >= 0) { throw e; }
    console.log('FAIL: '+e); process.exit(1);
}
'''
    probe = Path(directory) / 'probe.js'
    probe.write_text(script)
    result = subprocess.run([str(args.agent.resolve()), str(probe)], cwd=directory,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    print(result.stdout, end='')
    if result.returncode or 'PASS: native installation' not in result.stdout:
        raise SystemExit('Native installation probe failed: ' + str(result.returncode))
