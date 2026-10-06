'use strict';
// Production parent/client modules, real private Unix sockets and filesystem,
// injected launchd and command execution. Never touches the desktop or clipboard.
const fs=require('fs'),path=require('path'),os=require('os'),net=require('net'),vm=require('vm'),assert=require('assert'),EventEmitter=require('events');
const source=fs.readFileSync(path.join(__dirname,'../modules/message-box.js'),'utf8');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'mesh-msg-'));
let nonce=100,fail='',self=0,consoleUid=501,response=null,commands=[],jobs=[],ownership=[],children=[],holdLaunch=false,heldStart=null;
// Preserve the randomized basename and any descendants while shortening the socket path.
const mapPath=p=>typeof p==='string'&&p.startsWith('/var/tmp/mesh-ui-')?root+'/'+p.slice('/var/tmp/'.length):p;
const fakeFS={};
const activeTimers=new Set();
function nativeTimeout(callback,ms){const timer=setTimeout(()=>{activeTimers.delete(timer);callback();},Math.min(ms,500));activeTimers.add(timer);return timer;}
function nativeClear(timer){assert(activeTimers.delete(timer),'clearing an expired or already cleared native timer');clearTimeout(timer);}
for(const name of ['mkdirSync','chmodSync','openSync','existsSync','unlinkSync','rmdirSync','readFileSync'])fakeFS[name]=(...a)=>fs[name](mapPath(a[0]),...a.slice(1));
for(const name of ['writeSync','closeSync'])fakeFS[name]=fs[name].bind(fs);
fakeFS.chownSync=(p,u,g)=>{ownership.push([p,u,g]);};
class Task{constructor(executor){this.p=new Promise((r,j)=>executor.call(this,r,j));}then(a,b){return this.p.then(a,b);}}
const fakeNet={createServer(){const s=net.createServer(),listen=s.listen;s.listen=function(o,cb){return listen.call(this,{path:mapPath(o.path)},cb);};return s;},createConnection(o,cb){return net.createConnection({path:mapPath(o.path)},cb);}};
function context(uid){
 const c={module:{exports:{}},Buffer,console,process:{platform:'darwin',execPath:'/Applications/Agent " & support',env:{HOME:'/Users/fixture'},exit(){}},
  setTimeout:nativeTimeout,clearTimeout:nativeClear,setImmediate,require(name){
   if(name==='message-box')return c.module.exports;
   if(name==='promise')return Task;if(name==='fs')return fakeFS;if(name==='net')return fakeNet;
   if(name==='tls')return {generateRandomInteger:()=>String(++nonce)};
   if(name==='user-sessions')return {Self:()=>uid,consoleUid:()=>{if(!consoleUid)throw Error('No console');return consoleUid;},getGroupID:()=>20};
   if(name==='service-manager')return {manager};
   if(name==='child_process')return {execFile(exe,argv,options){
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{child.killed=true;};
    child.stdin={end(input){commands.push({exe,argv:Array.from(argv),input,options});setImmediate(()=>{
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
    });}};return child;
   }};
   throw Error('Unexpected require '+name);
  }};vm.createContext(c);vm.runInContext(source,c);return c;
}
const manager={installLaunchAgent(options){
 assert.equal(options.uid,501);assert.equal(options.failureRestart,0);assert.deepEqual(Array.from(options.sessionTypes),['Aqua']);
 assert(!options.parameters[1].includes('token:'));
 if(fail==='install')throw Error('injected install failure');
 const plist=root+'/'+options.name+'.plist';fs.writeFileSync(plist,'fixture');jobs.push({options,plist});return {plist};
},getLaunchAgent(name,uid){const job=jobs.find(j=>j.options.name===name);assert.equal(uid,501);return {
 plist:job.plist,load(){if(fail==='load')throw Error('injected load failure');const start=()=>{const c=context(501);children.push(c);vm.runInContext(job.options.parameters[1],c);};if(holdLaunch)heldStart=start;else start();},
 unload(){if(fail==='unload')throw Error('injected unload failure');},close(){}
};}};
async function checkRequest(make,expectedError){
 const ret=make();let result,error;
 try{result=await ret;}catch(e){error=String(e);}
 if(expectedError)assert(error&&error.includes(expectedError),error);else assert.equal(error,undefined);
 if(ret.directory)assert(!fs.existsSync(mapPath(ret.directory)),'owned directory retained');
 if(ret.plist)assert(!fs.existsSync(ret.plist),'job retained');
 return result;
}
(async()=>{try{
 const c=context(0),m=c.module.exports;
 assert.equal(await checkRequest(()=>m.getClipboard()),'text 日本語 😀\nlast line\n');
 await checkRequest(()=>m.setClipboard('quote " $(command) 日本語 😀\n'));
 assert.equal(await checkRequest(()=>m.create('Title " $(command)','Caption 日本語 😀\n',2,['Allow, yes','No'])),'Allow, yes');
 response={button:'No'};await checkRequest(()=>m.create('Title','Caption',2),'denied');
 response={timeout:true};await checkRequest(()=>m.create('Title','Caption',2),'TIMEOUT');
 response={cancelled:true};assert.equal(await checkRequest(()=>m.create('T','C',2,['Yes','Cancel'])),'Cancel');response=null;
 await checkRequest(()=>m.notify('Title " $(command)','Caption 日本語 😀'));await checkRequest(()=>m.lock());
 for(const mode of ['command','install','load']){fail=mode;await checkRequest(()=>m.getClipboard(),mode==='command'?'tool failure':mode+' failure');}fail='';
 const before=commands.length;consoleUid=0;await checkRequest(()=>m.getClipboard(),'No console');consoleUid=501;assert.equal(commands.length,before);
 await checkRequest(()=>m.create('T','C',-1),'Invalid macOS dialog');
 // Valid frame with a wrong token never launches a command or consumes the real helper.
 holdLaunch=true;const pending=m._request({command:'readClip'},r=>r.value);pending.p.catch(()=>{});
 await new Promise(r=>setTimeout(r,10));assert(heldStart);const callsBefore=commands.length;
 await new Promise((resolve,reject)=>{
  const rogue=net.createConnection({path:mapPath(pending.path)},()=>{
   const j=Buffer.from(JSON.stringify({command:'HELLO',token:'wrong',uid:501})),b=Buffer.alloc(j.length+4);
   b.writeUInt32LE(b.length);j.copy(b,4);rogue.write(b);
  });rogue.on('end',()=>rogue.end());rogue.on('close',resolve);rogue.on('error',reject);
 });
 assert.equal(commands.length,callsBefore);assert(!pending._done&&!pending.connection);
 holdLaunch=false;heldStart();await pending;
 holdLaunch=true;heldStart=null;await checkRequest(()=>m.getClipboard(),'connection timeout');
 holdLaunch=false;heldStart=null;
 fail='unload';const retained=m.getClipboard();let cleanupError;try{await retained;}catch(e){cleanupError=String(e);}
 assert(cleanupError.includes('LaunchAgent stop'));assert(fs.existsSync(retained.plist)&&fs.existsSync(mapPath(retained.config)));
 fail='';fs.unlinkSync(retained.plist);fs.unlinkSync(mapPath(retained.config));fs.rmdirSync(mapPath(retained.directory));
 assert(ownership.some(([p,u])=>p.endsWith('/config.json')&&u===501));
 assert(ownership.some(([p,u])=>!p.includes('/config.json')&&!p.endsWith('/ipc')&&u===0));
 assert(!commands.some(x=>x.exe==='/bin/sh'||x.exe==='/bin/zsh'));
 console.log('PASS: authenticated helper requests, Unicode, literal commands, dialog outcomes, private ownership, setup/command failures and cleanup');
}finally{await new Promise(r=>setTimeout(r,10));fs.rmSync(root,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
