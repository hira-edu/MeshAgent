'use strict';
// Run production first-start orchestration with injected private pipes and UI.
// No password dialog, service, privileged write or Screen Sharing connection.
const assert=require('assert'),fs=require('fs'),path=require('path'),vm=require('vm'),EventEmitter=require('events');
const source=fs.readFileSync(path.join(__dirname,'../modules/agent-installer.js'),'utf8');
const fixturePassword='Ab3$ ~x9';
function fixture(options={}) {
 const state={status:1,uid:0,console:501,platform:'darwin',answer:fixturePassword,save:0,calls:[],dialogs:[],timers:new Map(),buffers:[],...options};
 const ui={password(title,caption){state.dialogs.push({title,caption,password:true});return state.cancel?Promise.reject(Error('cancelled')):Promise.resolve(state.answer);},
  create(title,caption){state.dialogs.push({title,caption});return Promise.resolve('OK');}};
 const c={module:{exports:{}},global:{},Buffer,Date,console:{info1(){}},setImmediate,
  setTimeout(fn,ms){const id={};state.timers.set(id,{fn,ms});return id;},clearTimeout(id){state.timers.delete(id);},
  process:{platform:state.platform,pid:123,execPath:'/fixture/Agent " & support',stdout:{write(){throw Error('Unexpected stdout');}},stderr:{write(){throw Error('Unexpected stderr');}}},
  require(name){
   if(name==='user-sessions')return {Self:()=>state.uid,consoleUid(){if(!state.console)throw Error('No console');return state.console;}};
   if(name==='message-box')return ui;
   if(name==='child_process')return {execFile(executable,argv){
    const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{state.killed=true;};
    state.calls.push({executable,argv:Array.from(argv)});
    assert.equal(executable,c.process.execPath);assert.equal(argv[0],'Agent " & support');assert.equal(argv.length,2);
    child.stdin={end(input){
     const supplied=Buffer.isBuffer(input)?Buffer.from(input):Buffer.from(input);
     if(Buffer.isBuffer(input))state.buffers.push(input);
     setImmediate(()=>{
      child.stderr.emit('data',Buffer.from('fixture stderr '+fixturePassword)); // Must never be logged or shown
      const status=argv[1]==='-kvmcredentialstatus'?state.status:state.save;
      if(argv[1]==='-kvmprovision') {
       assert.equal(supplied.toString(),state.answer);assert(!argv.some(a=>a.includes(state.answer)));
       if(status===0)state.status=0;
      } else assert.equal(supplied.length,0);
      child.emit('exit',status);
     });
    }};return child;
   }};
   throw Error('Unexpected module '+name);
  }};
 vm.createContext(c);vm.runInContext(source,c);
 return {state,start:c.module.exports.startMacRelaySetup};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function drain(){for(let i=0;i<8;++i)await tick();}
(async()=>{
 let f=fixture();f.start();f.start();await drain();
 assert.deepEqual(f.state.calls.map(x=>x.argv[1]),['-kvmcredentialstatus','-kvmprovision']);
 assert.equal(f.state.dialogs.length,1);assert(f.state.dialogs[0].password);assert.equal(f.state.status,0);
 assert(f.state.buffers.every(b=>b.every(byte=>byte===0)),'answer buffer retained after child exit');
 assert.equal(f.state.timers.size,0);
 // Restart, an unsafe credential, Windows, and non-root never show password UI.
 for(const options of [{status:0},{status:2},{platform:'win32'},{uid:501}]) {
  f=fixture(options);f.start();await drain();assert.equal(f.state.dialogs.length,0);assert(!f.state.calls.some(x=>x.argv[1]==='-kvmprovision'));
 }
 // A boot before login waits for an Aqua user, then asks once.
 f=fixture({console:0});f.start();await drain();assert.equal(f.state.dialogs.length,0);
 assert.equal(f.state.timers.size,1);const [id,timer]=Array.from(f.state.timers.entries())[0];assert.equal(timer.ms,30000);
 f.state.timers.delete(id);f.state.console=501;timer.fn();await drain();assert.equal(f.state.dialogs.length,1);assert.equal(f.state.status,0);
 // A credential supplied while waiting for login is reused without prompting.
 f=fixture({console:0});f.start();await drain();const retry=Array.from(f.state.timers.values())[0];f.state.status=0;retry.fn();await drain();assert.equal(f.state.dialogs.length,0);
 // Cancel does not save and is not repeatedly requested by this daemon.
 f=fixture({cancel:true});f.start();await drain();f.start();await drain();
 assert.equal(f.state.status,1);assert.equal(f.state.dialogs.length,1);assert.equal(f.state.calls.length,1);
 for(const answer of ['', '123456789','caf\u00e9','a\nb']) {
  f=fixture({answer});f.start();await drain();assert.equal(f.state.status,1);assert.equal(f.state.calls.length,1);assert.equal(f.state.dialogs.length,2);
 }
 // Failed authentication/storage shows only a generic explanation and wipes input.
 f=fixture({save:1});f.start();await drain();assert.equal(f.state.status,1);assert.equal(f.state.dialogs.length,2);
 assert(!f.state.dialogs.some(d=>d.caption.includes(fixturePassword)));assert(f.state.buffers.every(b=>b.every(byte=>byte===0)));
 console.log('PASS: one-time macOS setup, saved credential reuse, boot before login, cancellation, invalid input, private argv/stdin, generic errors and buffer cleanup');
})().catch(e=>{console.error(e);process.exitCode=1;});
