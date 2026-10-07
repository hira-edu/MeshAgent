'use strict';
// Production parent/client modules, real private Unix sockets and filesystem,
// injected launchd and command execution. Never touches the desktop or clipboard.
const fs=require('fs'),path=require('path'),os=require('os'),net=require('net'),vm=require('vm'),assert=require('assert'),EventEmitter=require('events');
const source=fs.readFileSync(path.join(__dirname,'../modules/message-box.js'),'utf8');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'mesh-msg-'));
const home=root+'/home',agents=home+'/Library/LaunchAgents';
fs.mkdirSync(agents,{recursive:true});
let nonce=100,fail='',consoleUid=501,response=null,commands=[],jobs=[],ownership=[],holdLaunch=false,heldStart=null,unloads=0,commandDelay=0;
// Preserve the randomized basename and any descendants while shortening the socket path.
const mapPath=p=>typeof p==='string'&&p.startsWith('/var/tmp/mesh-ui-')?root+'/'+p.slice('/var/tmp/'.length):p;
const fakeFS={};
const activeTimers=new Set();
// Timers are capped so the 15 s start, 30 s idle and retry delays run quickly.
function nativeTimeout(callback,ms){const timer=setTimeout(()=>{activeTimers.delete(timer);callback();},Math.min(ms,300));activeTimers.add(timer);return timer;}
function nativeClear(timer){if(activeTimers.delete(timer))clearTimeout(timer);}
for(const name of ['mkdirSync','chmodSync','openSync','existsSync','unlinkSync','rmdirSync','readFileSync','readdirSync'])fakeFS[name]=(...a)=>fs[name](mapPath(a[0]),...a.slice(1));
for(const name of ['writeSync','closeSync'])fakeFS[name]=fs[name].bind(fs);
fakeFS.chownSync=(p,u,g)=>{ownership.push([p,u,g]);};
class Task{constructor(executor){this.p=new Promise((r,j)=>executor.call(this,r,j));this.p.catch(()=>{});}then(a,b){return this.p.then(a,b);}}
const fakeNet={createServer(){const s=net.createServer(),listen=s.listen;s.listen=function(o,cb){return listen.call(this,{path:mapPath(o.path)},cb);};return s;},createConnection(o,cb){return net.createConnection({path:mapPath(o.path)},cb);}};
let realNow=Date.now;
function context(uid){
 const c={module:{exports:{}},Buffer,console,Date,process:{platform:'darwin',execPath:'/Applications/Agent " & support',env:{HOME:'/Users/fixture'},exit(){}},
  setTimeout:nativeTimeout,clearTimeout:nativeClear,setImmediate,require(name){
   if(name==='message-box')return c.module.exports;
   if(name==='promise')return Task;if(name==='fs')return fakeFS;if(name==='net')return fakeNet;
   if(name==='tls')return {generateRandomInteger:()=>String(++nonce)};
   if(name==='user-sessions')return {Self:()=>uid,consoleUid:()=>{if(!consoleUid)throw Error('No console');return consoleUid;},getGroupID:()=>20,
    getUsername:id=>{assert.equal(id,501);return 'fixture';},getHomeFolder:name=>{assert.equal(name,'fixture');return home;}};
   if(name==='service-manager')return {manager};
   if(name==='child_process')return {execFile(exe,argv,options){
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{child.killed=true;};
    child.stdin={end(input){commands.push({exe,argv:Array.from(argv),input,options});setTimeout(()=>{
      if(child.killed)return;
      let out='',error='',code=0;
      if(exe==='/usr/bin/pbpaste')out='text 日本語 😀\nlast line\n';
      else if(exe==='/usr/bin/pbcopy'){assert(Buffer.isBuffer(input));assert.equal(input.toString('utf8'),'quote " $(command) 日本語 😀\n');}
      else if(exe==='/usr/bin/osascript'){
       assert.equal(argv[1],'-l');assert.equal(argv[2],'JavaScript');assert.equal(argv[5],'--');
       const request=JSON.parse(argv[6]);assert(!argv[4].includes('$(command)'));
       out=JSON.stringify(response||{button:request.buttons?request.buttons[0]:undefined});
      }else throw Error('Unexpected program '+exe);
      if(fail==='command'){code=7;error='injected tool failure';}
      for(const byte of Buffer.from(out))child.stdout.emit('data',Buffer.from([byte]));
      child.stderr.emit('data',Buffer.from(error));child.emit('exit',code);
    },commandDelay);}};return child;
   }};
   throw Error('Unexpected require '+name);
  }};vm.createContext(c);vm.runInContext(source,c);return c;
}
const manager={installLaunchAgent(options){
 assert.equal(options.uid,501);assert.equal(options.failureRestart,0);assert.deepEqual(Array.from(options.sessionTypes),['Aqua']);
 assert(!options.parameters[1].includes('token:'));
 if(fail==='install')throw Error('injected install failure');
 const plist=agents+'/'+options.name+'.plist';fs.writeFileSync(plist,'fixture');jobs.push({options,plist});return {plist};
},getLaunchAgent(name,uid){assert.equal(uid,501);const job=jobs.find(j=>j.options.name===name)||{options:{name},plist:agents+'/'+name+'.plist'};return {
 plist:job.plist,load(){if(fail==='load')throw Error('injected load failure');const start=()=>{const c=context(501);vm.runInContext(job.options.parameters[1],c);};if(holdLaunch)heldStart=start;else start();},
 unload(){++unloads;if(fail==='unload')throw Error('injected unload failure');},close(){}
};}};
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function outcome(p){try{return {value:await p};}catch(e){return {error:String(e)};}}
// After the idle period the helper is unloaded and every file it owned is gone.
async function expectIdleCleanup(m){
 await wait(450);
 assert.equal(m._session,null,'helper still active after idle');
 assert.deepEqual(fs.readdirSync(agents).filter(n=>n.startsWith('mesh-ui-')),[],'helper plist retained');
 assert.deepEqual(fs.readdirSync(root).filter(n=>n.startsWith('mesh-ui-')),[],'helper directory retained');
}
(async()=>{try{
 // A plist left by an agent that exited while its helper ran is swept before the first helper starts.
 fs.writeFileSync(agents+'/mesh-ui-7.plist','stale');fs.writeFileSync(agents+'/unrelated.plist','keep');
 const c=context(0),m=c.module.exports;
 assert.equal((await outcome(m.getClipboard())).value,'text 日本語 😀\nlast line\n');
 assert(!fs.existsSync(agents+'/mesh-ui-7.plist')&&fs.existsSync(agents+'/unrelated.plist'),'stale helper not swept');
 // Further requests reuse the running helper: one LaunchAgent, one background item.
 assert.equal((await outcome(m.setClipboard('quote " $(command) 日本語 😀\n'))).error,undefined);
 assert.equal((await outcome(m.create('Title " $(command)','Caption 日本語 😀\n',2,['Allow, yes','No']))).value,'Allow, yes');
 response={button:'No'};assert((await outcome(m.create('Title','Caption',2))).error.includes('denied'));
 response={timeout:true};assert((await outcome(m.create('Title','Caption',2))).error.includes('TIMEOUT'));
 response={cancelled:true};assert.equal((await outcome(m.create('T','C',2,['Yes','Cancel']))).value,'Cancel');response=null;
 // Masked password entry returns only through private IPC; argv contains no answer.
 const passwordValue='Ab3$ ~x9';response={button:'Save',value:passwordValue};
 assert.equal((await outcome(m.password('Screen Sharing setup','Enter password'))).value,passwordValue);
 const passwordCommand=commands[commands.length-1];
 assert(!passwordCommand.argv.some(arg=>arg.includes(passwordValue)));
 let passwordOptions;
 const jxa={Application:{currentApplication:()=>({displayDialog(caption,options){passwordOptions=options;return {buttonReturned:'Save',textReturned:passwordValue};}})}};
 vm.runInNewContext(passwordCommand.argv[4],jxa);
 assert.equal(JSON.parse(jxa.run([passwordCommand.argv[6]])).value,passwordValue);
 assert.equal(passwordOptions.hiddenAnswer,true);assert.equal(passwordOptions.defaultAnswer,'');
 assert.equal(passwordOptions.givingUpAfter,120);
 response={cancelled:true};assert((await outcome(m.password('T','C'))).error.includes('cancelled'));
 response={timeout:true};assert((await outcome(m.password('T','C'))).error.includes('cancelled'));
 response={button:'Save'};assert((await outcome(m.password('T','C'))).error.includes('Invalid password'));
 response=null;fail='command';assert.equal((await outcome(m.password('T','C'))).error,'Password dialog failed');fail='';
 assert.equal((await outcome(m.notify('Title " $(command)','Caption 日本語 😀'))).value,'DISMISSED');
 assert.equal((await outcome(m.lock())).error,undefined);
 fail='command';assert((await outcome(m.getClipboard())).error.includes('tool failure'));fail='';	// The helper survives a failed command
 assert.equal(jobs.length,1,'requests started more than one helper');
 await expectIdleCleanup(m);

 // Remote desktop polls the clipboard: concurrent reads share one read, and mixed requests run
 // one at a time through a single helper.
 commandDelay=40;const installs=jobs.length,before=commands.length;
 const reads=[m.getClipboard(),m.getClipboard(),m.getClipboard()];
 const mixed=[m.setClipboard('quote " $(command) 日本語 😀\n'),m.notify('T','C'),m.getClipboard()];
 const results=await Promise.all(reads.concat(mixed).map(outcome));
 assert(results.every(r=>r.error===undefined),JSON.stringify(results));
 assert.equal(reads[0],reads[1]);assert.equal(reads[1],reads[2]);
 assert.equal(jobs.length,installs+1,'concurrent requests started more than one helper');
 const ran=commands.slice(before).map(x=>x.exe);
 assert.deepEqual(ran,['/usr/bin/pbpaste','/usr/bin/pbcopy','/usr/bin/osascript','/usr/bin/pbpaste']);
 commandDelay=0;await expectIdleCleanup(m);

 // A queued request can be cancelled; the active one completes.
 const first=m.create('T','C',2),second=m.create('T','C',2);second.close();
 assert.equal((await outcome(first)).value,'Yes');assert((await outcome(second)).error.includes('denied'));
 await expectIdleCleanup(m);

 // No desktop user: nothing is launched.
 const noConsole=commands.length,noConsoleJobs=jobs.length;consoleUid=0;
 assert((await outcome(m.getClipboard())).error.includes('No console'));consoleUid=501;
 assert.equal(commands.length,noConsole);assert.equal(jobs.length,noConsoleJobs);
 assert((await outcome(m.create('T','C',-1))).error.includes('Invalid macOS dialog'));

 // A helper that cannot start fails its requests, and further requests fail fast instead of
 // registering a new LaunchAgent each time, until the retry delay passes.
 for(const mode of ['install','load']){
  fail=mode;const count=jobs.length;
  assert((await outcome(m.getClipboard())).error.includes(mode+' failure'));
  assert((await outcome(m.getClipboard())).error.includes('macOS helper unavailable'));
  assert(jobs.length<=count+1,'retry registered another helper');
  fail='';m._failedUntil=0;await wait(20);	// Cleanup runs on the next turn of the event loop
  assert.deepEqual(fs.readdirSync(root).filter(n=>n.startsWith('mesh-ui-')),[],mode+' left its directory');
 }
 await wait(50);assert.deepEqual(fs.readdirSync(agents).filter(n=>n.startsWith('mesh-ui-')),[]);

 // Valid frame with a wrong token never launches a command or takes over the helper.
 holdLaunch=true;const pending=m.getClipboard();
 await wait(20);assert(heldStart&&m._session);const callsBefore=commands.length,sessionPath=m._session.path;
 await new Promise((resolve,reject)=>{
  const rogue=net.createConnection({path:mapPath(sessionPath)},()=>{
   const j=Buffer.from(JSON.stringify({command:'HELLO',token:'wrong',uid:501})),b=Buffer.alloc(j.length+4);
   b.writeUInt32LE(b.length);j.copy(b,4);rogue.write(b);
  });rogue.on('end',()=>rogue.end());rogue.on('close',resolve);rogue.on('error',reject);
 });
 assert.equal(commands.length,callsBefore);assert(!pending._done&&!m._session.connection);
 holdLaunch=false;heldStart();assert.equal((await outcome(pending)).value,'text 日本語 😀\nlast line\n');
 await expectIdleCleanup(m);

 // A helper that never connects times out, and its files are removed.
 holdLaunch=true;heldStart=null;assert((await outcome(m.getClipboard())).error.includes('connection timeout'));
 holdLaunch=false;heldStart=null;m._failedUntil=0;await wait(50);
 assert.deepEqual(fs.readdirSync(agents).filter(n=>n.startsWith('mesh-ui-')),[]);

 // Files are removed even if launchd refuses to unload the job, so no background item stays registered.
 fail='unload';const unloadsBefore=unloads;assert.equal((await outcome(m.getClipboard())).value,'text 日本語 😀\nlast line\n');
 await expectIdleCleanup(m);assert(unloads>unloadsBefore);fail='';

 // A password from a helper on a desktop that switched users is rejected.
 response={button:'Save',value:passwordValue};commandDelay=60;
 const switched=m.password('T','C');await wait(30);consoleUid=502;
 assert((await outcome(switched)).error.includes('Desktop user changed'));
 consoleUid=501;response=null;commandDelay=0;await expectIdleCleanup(m);

 assert(ownership.some(([p,u])=>p.endsWith('/config.json')&&u===501));
 assert(ownership.some(([p,u])=>!p.includes('/config.json')&&!p.endsWith('/ipc')&&u===0));
 assert(!commands.some(x=>x.exe==='/bin/sh'||x.exe==='/bin/zsh'));
 console.log('PASS: one reused helper per desktop user, serialized and coalesced requests, idle cleanup, start backoff, stale sweep, cancellation, authentication, Unicode, literal commands, dialog outcomes, private ownership and cleanup despite unload failure');
}finally{await wait(20);fs.rmSync(root,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
