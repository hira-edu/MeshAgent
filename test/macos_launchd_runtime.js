'use strict';
// Executes the production launchd adapter with injected launchctl results. On
// macOS it also round-trips XML/binary plists through the real Apple parser.
// No jobs are registered and no installed files are changed.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const cp = require('child_process');
const EventEmitter = require('events');
const source = fs.readFileSync(path.join(__dirname, '../modules/service-manager.js'), 'utf8');
const begin = source.indexOf("if (process.platform == 'darwin')\n{");
const end = source.indexOf('\nfunction serviceManager()', begin);
assert(begin > 0 && end > begin);
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-launchd-'));
let self = 0, loaded = false, pid = 0, fail = null, calls = [], kills = 0;
const files = new Map();
function command(executable, args) {
    calls.push([executable, ...args]);
    if (fail && fail.match(executable, args)) return fail.result;
    if (executable === '/usr/bin/sw_vers') return {code: 0, out: '15.0\n'};
    if (executable === '/usr/bin/plutil') {
        if (process.platform === 'darwin') {
            const result = cp.spawnSync(executable, args, {encoding: 'utf8'});
            return {code: result.status, out: result.stdout, err: result.stderr};
        }
        return {code: 0, out: JSON.stringify(files.get(args[args.length - 1]))};
    }
    assert.equal(executable, '/bin/launchctl');
    if (args[0] === 'print') {
        if (args[1] === 'system' || /^gui\/\d+$/.test(args[1])) return {code: 0, out: 'domain = {}'};
        return loaded ? {code: 0, out: `job = {\n state = ${pid ? 'running' : 'waiting'}\n${pid ? ` pid = ${pid}\n` : ''}}`} : {code: 113};
    }
    if (args[0] === 'bootstrap') { loaded = true; return {code: 0}; }
    if (args[0] === 'bootout') { loaded = false; pid = 0; return {code: 0}; }
    if (args[0] === 'kickstart') { pid = 12345; return {code: 0}; }
    throw Error('Unexpected launchctl arguments: ' + args);
}
const c = {process: {platform: 'darwin', pid: process.pid}, console,
    serviceNotFound(name) { return Object.assign(Error('Service not found: ' + name), {code: 'ENOENT'}); },
    require(name) {
        if (name === 'fs') return fs;
        if (name === 'user-sessions') return {Self: () => self, consoleUid: () => 501};
        if (name === 'child_process') return {execFile(executable, argv) {
            assert.equal(argv[0], path.basename(executable));
            const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
            child.kill = () => kills++;
            child.waitExit = ms => {
                assert.equal(ms, 120000);
                const result = command(executable, Array.from(argv.slice(1)));
                if (result.out) child.stdout.emit('data', Buffer.from(result.out));
                if (result.err) child.stderr.emit('data', Buffer.from(result.err));
                if (result.code != null) child.emit('exit', result.code);
            };
            return child;
        }};
        throw Error(name);
    }};
vm.createContext(c); vm.runInContext(source.slice(begin, end), c);
try {
    const folder = path.join(temp, 'LaunchDaemons'); fs.mkdirSync(folder);
    const file = path.join(folder, "Example & ' Agent.plist");
    const label = 'com.example.agent', executable = "/Applications/Example & ' <Agent>/agent";
    const contents = `<plist version="1.0"><dict><key>Label</key><string>${label}</string><key>ProgramArguments</key><array><string>${c.macPlistString(executable)}</string><string>a &amp; b</string></array><key>WorkingDirectory</key><string>/tmp/Example &amp; Agent</string><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict></dict></plist>`;
    const config = {Label: label, ProgramArguments: [executable, 'a & b'], WorkingDirectory: '/tmp/Example & Agent', RunAtLoad: true, KeepAlive: {SuccessfulExit: false}};
    files.set(file, config); c.macWritePlist(file, contents);
    const job = c.fetchPlist(folder, "Example & ' Agent");
    assert.equal(job.appLocation(), executable);
    assert.equal(job.appWorkingDirectory(), '/tmp/Example & Agent/');
    assert.equal(job.parameters()[1], 'a & b');
    assert.equal(job.startType, 'AUTO_START');
    assert.equal(job._keepAlive, 'ALWAYS');
    assert.equal(c.fetchPlist(folder, label).plist, file, 'find a renamed plist by Label');
    assert.throws(() => c.fetchPlist(folder, '../agent'), /Invalid service name/);
    assert.throws(() => c.macPlistString('bad\0value'), /control character/);
    assert.equal(c.getOSVersion().compareTo('15.0.0'), 0);
    assert(!job.isLoaded()); job.load(); assert(job.isLoaded()); assert(!job.isRunning(), 'loaded job may have no PID');
    job.start(); assert(job.isRunning()); job.restart();
    assert(calls.some(a => a.join('|') === '/bin/launchctl|kickstart|-k|system/' + label));
    job.stop(); assert(!job.isLoaded()); job.unload();
    fail = {match: (exe, a) => exe === '/bin/launchctl' && a[0] === 'bootstrap', result: {code: 5, err: 'Input/output error'}};
    assert.throws(() => job.load(), /failed \(5\)/); assert(!loaded);
    fail = {match: (exe, a) => exe === '/bin/launchctl' && a[0] === 'print', result: {code: 1, err: 'not permitted'}};
    assert.throws(() => job.isLoaded(), /not permitted/, 'permission errors are not absence');
    fail = {match: (exe, a) => exe === '/bin/launchctl' && a[1] === 'system', result: {code: 125}};
    assert.throws(() => job.isLoaded(), /failed \(125\)/, 'missing domain is not service absence');
    fail = {match: () => true, result: {}};
    assert.throws(() => c.getOSVersion(), /timed out/); assert.equal(kills, 1); fail = null;
    self = 501;
    assert.throws(() => job.load(), /root/);
    const agent = c.fetchPlist(folder, "Example & ' Agent"); agent.daemon = false;
    agent.start(); assert(calls.some(a => a[0] === '/bin/launchctl' && a[1] === 'kickstart' && a[2] === 'gui/501/' + label));
    assert.throws(() => agent.start(502), /another user/); agent.stop(); self = 0;
    const stale = file + '.' + process.pid + '.tmp'; fs.writeFileSync(stale, 'owned by someone else');
    assert.throws(() => c.macWritePlist(file, contents));
    assert.equal(fs.readFileSync(stale, 'utf8'), 'owned by someone else'); fs.unlinkSync(stale);
    fail = {match: (exe, a) => exe === '/usr/bin/plutil' && a[0] === '-lint', result: {code: 1, err: 'invalid plist'}};
    assert.throws(() => c.macWritePlist(file, '<invalid>'), /invalid plist/);
    assert.equal(fs.readFileSync(file, 'utf8'), contents); assert(!fs.existsSync(stale)); fail = null;
    if (process.platform === 'darwin') {
        cp.execFileSync('/usr/bin/plutil', ['-convert', 'binary1', '--', file]);
        assert.equal(job.appLocation(), executable);
        assert(fs.readFileSync(file).subarray(0, 8).equals(Buffer.from('bplist00')));
    }
    console.log('PASS: macOS launchd domains, checked failures, plist round trips, and atomic writes');
} finally { fs.rmSync(temp, {recursive: true, force: true}); }
