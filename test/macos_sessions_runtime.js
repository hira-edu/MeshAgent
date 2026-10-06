'use strict';
// Fault-injected execution of the production Darwin module. No host account or
// privacy settings are changed, and no external process is launched.
const assert = require('assert'), fs = require('fs'), vm = require('vm'), EventEmitter = require('events');
const source = fs.readFileSync(require('path').join(__dirname, '../modules/user-sessions.js'), 'utf8');
let owner = 501, failure = null, killed = 0, calls = [], home = '/Users/A & B é', homeXML = '<plist>fixture</plist>';
const responses = {
    '/usr/bin/id -u': '0\n',
    '/usr/bin/id -u -- desktop': '501\n',
    '/usr/bin/id -u -- odd;$(value)': '503\n',
    '/usr/bin/id -u -- network': '700\n',
    '/usr/bin/id -un -- 501': 'desktop\n',
    '/usr/bin/id -un -- 502': 'ssh\n',
    '/usr/bin/id -un -- 248': '_mbsetupuser\n',
    '/usr/bin/id -un -- 4294967294': 'nobody\n',
    '/usr/bin/id -g -- 501': '20\n',
    '/usr/bin/dscl . -list /Users UniqueID': 'desktop     501\nssh 502\nnobody -2\n',
    '/usr/bin/dscl . -list /Groups PrimaryGroupID': 'staff 20\nnogroup -1\n',
    '/usr/bin/who': 'ssh ttys001 Oct 4\ndesktop console Oct 4\nnetwork ttys002 Oct 4\ndesktop ttys003 Oct 4\n'
};
function Events() {
    EventEmitter.call(this);
    this.on = EventEmitter.prototype.on;
    this.emit = EventEmitter.prototype.emit;
    this.createEvent = () => this;
    this.addMethod = () => this;
    return this;
}
const c = {module: {exports:{}}, Buffer, process: {platform:'darwin'}, require(name) {
    if (name === 'events') return {EventEmitter:Events};
    if (name === 'fs') return {statSync(path) {assert.equal(path,'/dev/console');return {uid:owner};}};
    if (name === 'child_process') return {execFile(exe, argv) {
        assert.notEqual(exe, '/bin/sh');
        const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
        child.stdin = {end(input) {child.input=input;}};
        child.kill = () => {killed++;};
        child.waitExit = timeout => {
            assert.equal(timeout,30000);
            const key=(exe+' '+Array.from(argv).slice(1).join(' ')).trim();calls.push({exe,argv:Array.from(argv),input:child.input});
            if (failure === 'timeout') return;
            if (failure === 'exit') {child.stderr.emit('data',Buffer.from('lookup failed'));child.emit('exit',65);return;}
            let out=responses[key];
            if (exe === '/usr/bin/dscl' && argv[1] === '-plist') {
                assert.equal(argv[4],'/Users/desktop');out=homeXML;
            }
            if (exe === '/usr/bin/plutil') {
                assert.equal(child.input,homeXML);out=JSON.stringify({'dsAttrTypeStandard:NFSHomeDirectory':[home]});
            }
            assert.notEqual(out,undefined,key);
            // Split at every byte, including inside multibyte home-directory names.
            for (const byte of Buffer.from(out)) child.stdout.emit('data',Buffer.from([byte]));
            child.emit('exit',0);
        };
        return child;
    }};
    throw Error('Unexpected dependency: '+name);
}};
vm.createContext(c); vm.runInContext(source,c);
const s=c.module.exports;
assert.equal(s.Self(),0);
assert.equal(s.consoleUid(),501);assert(!calls.some(c=>c.exe==='/usr/bin/who'));
owner=502;assert.equal(s.consoleUid(),502);owner=0;assert.throws(()=>s.consoleUid(),/nobody logged/);
owner=248;assert.throws(()=>s.consoleUid(),/nobody logged/);owner=501;
assert.equal(s.getUid('odd;$(value)'),503);assert.deepEqual(calls.at(-1).argv,['id','-u','--','odd;$(value)']);
for (const bad of [-1, '501;id', '501x', NaN, 1.2, 4294967295, {}, null]) assert.throws(()=>s.getUsername(bad),/Invalid account ID/);
assert.throws(()=>s.getUid('../root'),/Invalid account name/);
assert.equal(s.getGroupID(501),20);assert.equal(s.getGroupname(20),'staff');
assert.equal(s.getUsername(-2),'nobody');assert.equal(s.getGroupname(-1),'nogroup');
assert.equal(s._users().nobody,'4294967294');
assert.equal(s.getHomeFolder('desktop'),home);home='relative';assert.throws(()=>s.getHomeFolder('desktop'),/Invalid home/);
const users=s.Current();assert.equal(users.desktop.uid,501);assert.equal(users.ssh.uid,502);assert.equal(users.network.uid,700);assert.equal(users.Active.length,3);
failure='exit';assert.throws(()=>s.getUsername(501),/failed \(65\).*lookup failed/);
failure='timeout';assert.throws(()=>s.getUsername(501),/timed out/);assert.equal(killed,1);failure=null;
responses['/usr/bin/id -un -- 501']='';assert.throws(()=>s.getUsername(501),/Invalid account name/);
responses['/usr/bin/id -g -- 501']='not-a-number';assert.throws(()=>s.getGroupID(501),/Invalid account ID/);
console.log('PASS: macOS console selection, literal argv, account validation, home parsing, session UIDs, failures and timeouts');
