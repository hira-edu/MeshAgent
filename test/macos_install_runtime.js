'use strict';
// Production macOS lifecycle functions, real temporary files/plutil, injected
// launchctl. /Library writes are redirected before any filesystem operation.
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const vm = require('vm'), cp = require('child_process'), EventEmitter = require('events');
const managerSource = fs.readFileSync(path.join(__dirname, '../modules/service-manager.js'), 'utf8');
const installerSource = fs.readFileSync(path.join(__dirname, '../modules/agent-installer.js'), 'utf8');
const start = managerSource.indexOf("if (process.platform == 'darwin')\n{");
const end = managerSource.indexOf('\nfunction serviceManager()', start);
const agentStart = managerSource.indexOf('this.installLaunchAgent = function');
const agentEnd = managerSource.indexOf('\n    this.uninstallService =', agentStart);
const installAgent = managerSource.slice(agentStart, agentEnd).replace('this.installLaunchAgent =', 'var installAgent =').replace(/\n    }\s*$/, '');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mesh-mac-install-'));
let failWrite = '', failStart = false, failChown = false, agentInstalls = 0;
let closed = 0, uninstalled = [], commands = [], loaded = new Set(), userDomain = '', domainData = {}, mockCrontab = '';
const map = p => typeof p === 'string' && (p === '/Library' || p.startsWith('/Library/')) ? root + '/system' + p : p;
fs.mkdirSync(root + '/system');
const fixtureFS = {};
for (const key of ['existsSync', 'statSync', 'readdirSync', 'readFileSync', 'unlinkSync', 'rmdirSync', 'chmodSync', 'mkdirSync']) {
    fixtureFS[key] = (...a) => fs[key](map(a[0]), ...a.slice(1));
}
fixtureFS.openSync = (p, flags) => { if (failWrite && p.endsWith(failWrite)) throw Error('injected write failure'); return fs.openSync(map(p), flags); };
fixtureFS.writeSync = fs.writeSync.bind(fs); fixtureFS.closeSync = fs.closeSync.bind(fs);
fixtureFS.renameSync = (a, b) => fs.renameSync(map(a), map(b));
fixtureFS.chownSync = (p, uid, gid) => { assert(Number.isInteger(Number(uid)) && Number.isInteger(Number(gid))); if (failChown) throw Error('injected chown failure'); };
const sessions = {Self: () => 0, tty: () => 'fixture', getUid: () => 501, consoleUid: () => { throw Error('must not select Aqua console'); },
    getUsername: uid => {assert.equal(uid, 501);return 'fixture';}, getGroupID: uid => {assert.equal(uid, 501);return 20;}, getHomeFolder: () => root + '/home'};
const c = {Buffer, Date, global: {}, module: {exports: {}}, console: {log() {}, info1() {}, setDestination() {}, setInfoLevel() {}, Destinations: {DISABLED: 0}},
    process: {platform: 'darwin', pid: process.pid, execPath: root + '/source-agent', stdout: {write() {}}, stderr: {write() {}}, exit() {}},
    serviceNotFound: name => Object.assign(Error(name), {code: 'ENOENT'}),
    extractFileName: f => typeof f === 'string' ? path.basename(f) : f.newName,
    extractFileSource: f => typeof f === 'string' ? f : f.source,
    require(name) {
        if (name === 'fs') return fixtureFS;
        if (name === 'user-sessions') return sessions;
        if (name === 'service-manager') return {manager};
        if (name === 'child_process') return {execFile(exe, argv) {
            const child = new EventEmitter();child.stdout = new EventEmitter();child.stderr = new EventEmitter();child.stdin={_data:'',write(d){this._data+=d;},end(){}};child.kill = () => {};
            child.waitExit = () => {
                const args = Array.from(argv.slice(1));commands.push([exe, ...args]);let status=0, out='', err='';
                if (exe === '/usr/bin/plutil') {
                    const r=cp.spawnSync(exe,args.map(map),{encoding:'utf8'});status=r.status;out=r.stdout;err=r.stderr;
                } else if (exe === '/bin/launchctl') {
                    if (args[0] === 'print') {
                        if (args[1] === 'user/0') { out=userDomain; }
                        else if (domainData[args[1]]) { out=domainData[args[1]]; }
                        else if (args[1] === 'system') { out='system = {}'; }
                        else if (loaded.has(args[1])) { out='job = {\n pid = 123\n}'; }
                        else { status=113; }
                    } else if (args[0] === 'bootout') { loaded.delete(args[1]); }
                    else throw Error('Unexpected launchctl '+args);
                } else if (exe === '/usr/bin/crontab') {
                    if (args[0] === '-l') { if (mockCrontab) { out = mockCrontab; } else { status = 1; } }
                    else if (args[0] === '-') { mockCrontab = child.stdin._data; }
                } else if (exe === '/bin/kill' || exe === '/bin/sh' || exe === '/bin/sleep') {
                    // no-op for test
                } else throw Error('Unexpected executable '+exe);
                if(out)child.stdout.emit('data',Buffer.from(out));if(err)child.stderr.emit('data',Buffer.from(err));child.emit('exit',status);
            };return child;
        }};
        throw Error(name);
    }};
vm.createContext(c);vm.runInContext(managerSource.slice(start,end)+'\n'+installAgent,c);
const manager = {isAdmin: () => true,
    installService: options => c.macInstallService(options, manager),
    installLaunchAgent(options) { agentInstalls++;return c.installAgent.call(manager,options); },
    getLaunchAgent(name) {return c.fetchPlist('/Library/LaunchAgents',name);},
    uninstallService(name, options) { uninstalled.push([name, options]); },
    getService(name) {var cron=c.fetchCronService(name),loc=cron?cron.appLocation.bind(cron):c.fetchPlist('/Library/LaunchDaemons',name).appLocation;return {
        appLocation: () => loc(),
        start() { if(cron){assert(c.macCrontabFind(c.macCronMarker(name))!=null);}else{assert(fs.existsSync(map('/Library/LaunchDaemons/'+name+'.plist')));}if(failStart)throw Error('injected start failure'); },
        unload() {}, close() {closed++;}
    };}};
try {
    fs.writeFileSync(c.process.execPath,'binary fixture');
    const provision=root+'/source.msh';fs.writeFileSync(provision,'provisioning');
    const opts=()=>({name:'Mesh & Agent',target:'historical-agent',servicePath:c.process.execPath,installPath:root+'/installed',startType:'AUTO_START',parameters:['--value=a & "b"'],files:[{source:provision,newName:'historical-agent.msh'}]});
    let receipt=manager.installService(opts());
    let heartbeat=fs.readFileSync(root+'/installed/.meshagent_cron.sh','utf8');
    assert(heartbeat.indexOf('\'--value=a & "b"\'')>=0,'heartbeat must contain quoted parameter');assert(heartbeat.indexOf('--__daemon')>=0);assert(mockCrontab.indexOf('meshagent-cron:Mesh & Agent')>=0);
    assert.equal(fs.readFileSync(root+'/installed/historical-agent.msh','utf8'),'provisioning');
    assert.throws(()=>manager.installService(opts()),/already exists/);receipt.rollback();assert(!fs.existsSync(root+'/installed'));
    failWrite='historical-agent.msh';assert.throws(()=>manager.installService(opts()),/write failure/);failWrite='';
    assert(!fs.existsSync(root+'/installed')&&mockCrontab.indexOf('meshagent-cron:Mesh & Agent')<0);
    fs.mkdirSync(root+'/installed');fs.writeFileSync(root+'/installed/historical-agent.msh','incumbent identity');
    receipt=manager.installService(opts());assert.equal(fs.readFileSync(root+'/installed/historical-agent.msh','utf8'),'incumbent identity');receipt.rollback();
    assert.equal(fs.readFileSync(root+'/installed/historical-agent.msh','utf8'),'incumbent identity');
    assert.throws(()=>manager.installService({...opts(),files:[{source:provision,newName:'../escape'}]}),/Invalid service name/);
    assert(!fs.existsSync(root+'/installed/historical-agent'));
    manager.installLaunchAgent({name:'login-helper',servicePath:c.process.execPath,sessionTypes:['LoginWindow'],parameters:['-kvm1']});
    const login=manager.getLaunchAgent('login-helper');assert(!login.isLoaded());login.unload();
    assert.throws(()=>login.load(),/session is not active/);
    userDomain='subdomains = {\n login/77\n login/88\n}\n';domainData={'login/77':'session = LoginWindow\n','login/88':'session = Aqua\n'};
    loaded=new Set(['login/77/'+login.alias,'system/'+login.alias]);login.unload();assert.equal(loaded.size,0);
    assert(!commands.some(a=>a[1]==='bootout'&&a[2].startsWith('login/88')));
    fs.unlinkSync(map(login.plist));
    failChown=true;assert.throws(()=>manager.installLaunchAgent({name:'user-helper',servicePath:c.process.execPath,uid:501}),/chown failure/);failChown=false;
    assert(!fs.existsSync(root+'/home/Library/LaunchAgents/user-helper.plist'));
    // Run the production installer orchestration, including rollback of only its own files.
    vm.runInContext(installerSource,c);
    // Remote desktop relays Screen Sharing from the daemon, so installation publishes no KVM LaunchAgent.
    for (const scenario of ['start','success']) {
        failStart=scenario==='start';userDomain='';domainData={};commands=[];agentInstalls=0;mockCrontab='';
        const params=['--meshServiceName=Orchestrated','--target=main','--installPath='+root+'/orchestrated','--__skipExit=1'];
        if(scenario==='success')c.installService(params);else assert.throws(()=>c.installService(params),/Service start\/setup failed/);
        const helper=map('/Library/LaunchAgents/Orchestrated.plist');
        assert.equal(mockCrontab.indexOf('meshagent-cron:Orchestrated')>=0,scenario==='success');assert(!fs.existsSync(helper)&&agentInstalls===0);
        assert.equal(fs.existsSync(root+'/orchestrated/main'),scenario==='success');
        assert(!commands.some(a=>a[1]==='bootstrap'),'orchestrator starts the daemon only through the service object');
    }
    assert.equal(closed,2);
    // The relay credential survives a reinstall and is removed by a completed uninstall.
    fs.mkdirSync(root+'/relay');
    const relayMsh=root+'/relay/Orchestrated.msh', relaySecret=root+'/relay/vncrelay.secret';
    for (const stop of [false, true]) {
        fs.writeFileSync(relayMsh,'provisioning');fs.writeFileSync(relaySecret,'secret\n',{mode:0o600});
        const params=['--meshServiceName=Orchestrated'];if(stop)params.push('_stop');
        let reinstalled=0;const install=c.installService;c.installService=()=>{reinstalled++;};
        try { c.uninstallService2(params, relayMsh); } finally { c.installService=install; }
        assert.equal(uninstalled.pop()[0],'Orchestrated');
        assert.equal(fs.existsSync(relaySecret),!stop);assert.equal(fs.existsSync(relayMsh),!stop);assert.equal(reinstalled,stop?0:1);
    }
    c.removeMacRelaySecret(null);c.removeMacRelaySecret(relayMsh);	// Absent credential or path: nothing to do
    console.log('PASS: macOS install ordering, owned rollback, retained provisioning, LaunchAgent ownership, LoginWindow domain cleanup, no KVM LaunchAgent, relay credential kept on reinstall and removed on uninstall, start/setup failures');
} finally {fs.rmSync(root,{recursive:true,force:true});}
