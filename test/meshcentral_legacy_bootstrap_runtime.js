'use strict';

// Executes the real generated endpoint expression, native ABI mocks, and the
// real control-channel handler. No endpoint, service, or network is contacted.
const assert = require('assert');
const vm = require('vm');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const helper = require('../tools/meshcentral_legacy_bootstrap');
const exe = 'C:\\ProgramData\\RecoveryFixture\\package.exe';
const contents = [Buffer.from('fixture executable'), Buffer.from('fixture DLL'), Buffer.from('fixture provisioning')];
const hashes = contents.map(b => crypto.createHash('sha384').update(b).digest('hex'));
const config = { controlUrl:'wss://fixture.invalid/control.ashx', loginUser:'user//operator', nodeId:'node//fixture', expectedNodeIdentity:'a'.repeat(96), sourceExe:exe, sourceSha384:hashes[0], dllSha384:hashes[1], mshSha384:hashes[2], timeoutMs:1000 };

function endpoint(options = {}) {
    const pointerSize = options.pointerSize || 8, addresses = new Map(), calls = [];
    let next = 4096;
    class Variable {
        constructor(value) {
            this._size = typeof value === 'number' ? value : 0;
            this.bytes = Buffer.alloc(this._size);
            if (typeof value === 'string') this.Wide2UTF8 = value;
            this.address = next; next += 256; addresses.set(this.address, this);
        }
        toBuffer() { return this.bytes; }
        pointerBuffer() { const b = Buffer.alloc(pointerSize); b.writeUInt32LE(this.address); return b; }
        Deref(offset, size) {
            if (size !== undefined) { const v = new Variable(0); v.bytes = this.bytes.subarray(offset, offset + size); v._size = size; return v; }
            return addresses.get(this.bytes.readUInt32LE(0));
        }
    }
    function pointer(out, target) { target.pointerBuffer().copy(out.bytes); }
    function value(n) { return { Val:n }; }
    const processHandle = new Variable(0), threadHandle = new Variable(0);
    const kernel = {
        GetModuleFileNameW(module, out) { out.Wide2UTF8 = options.host || 'C:\\ProgramData\\DiagnosticHost\\svchost.exe'; return value(out.Wide2UTF8.length); },
        GetDriveTypeW() { return value(options.remoteDrive ? 4 : 3); },
        CreateFileW(p, access, share, security, creation, flags) {
            assert.deepStrictEqual([access,share,security,creation,flags],[0,7,0,3,35651584]);
            const v = new Variable(0); v.path = p.Wide2UTF8; v.Val = v.address; return v;
        },
        GetFinalPathNameByHandleW(handle, out, size, flags) {
            assert.strictEqual(size,4096); assert.strictEqual(flags,1);
            const tail = options.alias && handle.path.endsWith('RecoveryFixture') ? 'ProgramData\\DiagnosticHost' : handle.path.slice(3);
            out.Wide2UTF8 = '\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\' + tail;
            return value(out.Wide2UTF8.length);
        },
        GetFileAttributesW(p) {
            calls.push(['attributes', p.Wide2UTF8]);
            const file = /\.(exe|dll|msh)$/i.test(p.Wide2UTF8);
            if (p.Wide2UTF8 === options.missing) return value(-1);
            return value((file ? 0 : 16) | (p.Wide2UTF8 === options.reparse ? 1024 : 0));
        },
        LocalFree(v) { calls.push(['free',v.address]); return value(0); },
        GetLastError() { return value(5); },
        CloseHandle(v) { calls.push([v.path ? 'close-path' : 'close',v.address]); if (options.closeThrows && !v.path) throw Error('Close fixture failed after launch'); return value(1); },
        CreateProcessW(app, command, processAttrs, threadAttrs, inherit, flags, env, cwd, si, pi) {
            calls.push(['create',app.Wide2UTF8,command.Wide2UTF8]);
            assert.strictEqual(app.Wide2UTF8, exe);
            assert.strictEqual(command.Wide2UTF8, '"' + exe + '" -update --quiet');
            assert.strictEqual(inherit,0); assert.strictEqual(flags,0x08000000);
            assert.strictEqual(processAttrs,0); assert.strictEqual(threadAttrs,0); assert.strictEqual(env,0);
            assert.strictEqual(cwd.Wide2UTF8,'C:\\ProgramData\\RecoveryFixture');
            assert.strictEqual(si.bytes.readUInt32LE(0),pointerSize === 8 ? 104 : 68);
            if (options.createFail) return value(0);
            processHandle.pointerBuffer().copy(pi.bytes,0); threadHandle.pointerBuffer().copy(pi.bytes,pointerSize);
            pi.bytes.writeUInt32LE(9876,pointerSize*2); return value(1);
        }
    };
    const advapi = {
        GetNamedSecurityInfoW(p, type, information, owner, group, dacl, sacl, out) {
            calls.push(['security',p.Wide2UTF8]); assert.strictEqual(type,1); assert.strictEqual(information,5);
            if (options.securityFail) return value(5);
            const v = new Variable(0); v.path = p.Wide2UTF8; pointer(out,v); return value(0);
        },
        GetSecurityDescriptorDacl(sd,present,dacl) {
            present.bytes.writeUInt32LE(options.noDacl ? 0 : 1);
            if (!options.nullDacl) pointer(dacl,new Variable(8));
            return value(1);
        },
        GetSecurityDescriptorControl(sd, control) { control.bytes.writeUInt16LE(options.unprotected ? 0 : 4096); return value(1); },
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, rev, info, output) {
            assert.strictEqual(rev,1); assert.strictEqual(info,5);
            const directory = !/\.(exe|dll|msh)$/i.test(sd.path);
            const owner = options.badOwner ? 'O:BU' : options.adminOwner ? 'O:BA' : 'O:SY';
            const fileFlags = options.inheritedFiles ? 'ID' : options.inheritOnly ? 'IO' : '';
            const rights = options.partialRights ? 'FR' : options.hexRights ? '0x1f01ff' : 'FA';
            const flags = directory ? 'OICI' : fileFlags;
            let aces = ['(' + (options.denyAce ? 'D' : 'A') + ';' + flags + ';' + rights + ';;;SY)', '(A;' + flags + ';' + rights + ';;;' + (options.duplicateTrustee ? 'SY' : 'BA') + ')'];
            if (options.reverseAces) aces.reverse();
            const acl = (directory ? 'D:P' : options.inheritedFiles ? 'D:AI' : 'D:') + aces.join('');
            pointer(output,new Variable(owner + acl + (options.extraAce || options.fileExtraAce && !directory ? '(A;;FA;;;BU)' : ''))); return value(1);
        }
    };
    for (const proxy of [kernel,advapi]) proxy.CreateMethod = function (name) { assert.strictEqual(typeof this[name],'function','Unexpected native API: '+name); };
    const files = new Map([exe,exe.slice(0,-4)+'.dll',exe.slice(0,-4)+'.msh'].map((name,i)=>[name,contents[i]]));
    function remoteRequire(name) {
        if (name === '_agentNodeId') return () => options.wrongIdentity ? 'b'.repeat(96) : config.expectedNodeIdentity.toUpperCase();
        if (name === '_GenericMarshal') return { PointerSize:pointerSize, CreateNativeProxy:n => n === 'kernel32.dll' ? kernel : advapi, CreateVariable:v=>new Variable(v), CreatePointer:()=>new Variable(pointerSize) };
        if (name === 'fs') return { readFileSync:p => { calls.push(['read',p]); if (options.badHash && p.endsWith(options.corruptExtension || '.dll')) return Buffer.from('changed'); return files.get(p); } };
        if (name === 'SHA384Stream') return { create:()=>({ syncHash:b=>crypto.createHash('sha384').update(b).digest() }) };
        throw Error('Unexpected module: '+name);
    }
    return { calls, run:expression=>vm.runInNewContext(expression,{ require:remoteRequire, process:{execPath:options.installed || 'C:\\ProgramData\\DiagnosticHost\\diaghost.exe'}, Buffer },{timeout:1000}), closed:[threadHandle.address,processHandle.address] };
}
function transport(fixture, options = {}) {
    const instances = [];
    class Socket extends EventEmitter {
        constructor(url, opts) {
            super(); instances.push(this);
            assert.strictEqual(opts.rejectUnauthorized,true); assert.strictEqual(opts.handshakeTimeout,15000);
            const u = new URL(url); assert.strictEqual(u.protocol,'wss:'); assert(u.searchParams.get('auth')); this.terminated = false;
            queueMicrotask(()=>this.emit('open'));
        }
        send(raw, callback) {
            const msg = JSON.parse(raw); assert.strictEqual(msg.nodeid,config.nodeId); assert.strictEqual(msg.type,'console');
            const expression = JSON.parse(msg.value.slice(5));
            if (options.silent) return;
            if (options.close) { queueMicrotask(()=>this.emit('close')); return; }
            const reply = fixture.run(expression);
            const envelope = {action:'msg',type:'console',nodeid:config.nodeId,value:JSON.stringify(reply)};
            queueMicrotask(()=>{
                this.emit('message',JSON.stringify({...envelope,nodeid:'node//other'}));
                if (options.foreignOnly) return;
                this.emit('message',JSON.stringify({...envelope,value:JSON.stringify({...reply,marker:'wrong'})}));
                if (options.markerOnly) return;
                if (options.corruptResult) envelope.value = JSON.stringify({...reply,result:{...reply.result,updated:true}});
                this.emit('message',JSON.stringify(envelope));
                this.emit('message',JSON.stringify(envelope));
            });
            if (callback) callback();
        }
        terminate() { this.terminated = true; }
    }
    return { Socket,instances };
}

async function main() {
    let checks = 0;
    for (const pointerSize of [4,8]) {
        const f = endpoint({pointerSize}), t = transport(f);
        const result = await helper.launch(config,Buffer.alloc(80),t.Socket);
        assert.deepStrictEqual([result.launched,result.updated,result.waitedForChild,result.pid],[true,false,false,9876]);
        assert.strictEqual(f.calls.filter(c=>c[0]==='create').length,1);
        assert.deepStrictEqual(f.calls.filter(c=>c[0]==='close').map(c=>c[1]),f.closed);
        assert.strictEqual(t.instances[0].terminated,true); checks++;
    }
    for (const options of [{reverseAces:true},{inheritedFiles:true},{hexRights:true},{adminOwner:true}]) {
        const f = endpoint(options), t = transport(f);
        assert.strictEqual((await helper.launch(config,Buffer.alloc(80),t.Socket)).launched,true); checks++;
    }
    const cases = [
        {wrongIdentity:true},{badHash:true},{badHash:true,corruptExtension:'.exe'},{badHash:true,corruptExtension:'.msh'},
        {unprotected:true},{extraAce:true},{fileExtraAce:true},{badOwner:true},{nullDacl:true},{noDacl:true},{securityFail:true},{remoteDrive:true},{alias:true},
        {inheritOnly:true},{partialRights:true},{denyAce:true},{duplicateTrustee:true},
        {reparse:'C:\\ProgramData'},{reparse:'C:\\ProgramData\\RecoveryFixture'},{reparse:exe},
        {missing:exe.slice(0,-4)+'.msh'},{installed:'C:\\ProgramData\\RecoveryFixture\\old.exe'},
        {host:'C:\\ProgramData\\RecoveryFixture\\svchost.exe'}
    ];
    for (const options of cases) {
        const f = endpoint(options), t = transport(f);
        await assert.rejects(helper.launch(config,Buffer.alloc(80),t.Socket),e=>/Endpoint rejected bootstrap/.test(e.message) && e.launchState === 'not-launched');
        assert.strictEqual(f.calls.filter(c=>c[0]==='create').length,0); assert(t.instances[0].terminated); checks++;
    }
    for (const options of [{close:true},{silent:true},{foreignOnly:true},{markerOnly:true},{corruptResult:true}]) {
        const f = endpoint(), t = transport(f,options);
        await assert.rejects(helper.launch(config,Buffer.alloc(80),t.Socket), e=>e.submitted === true && e.launchState === 'unknown');
        assert(t.instances[0].terminated); checks++;
    }
    const f = endpoint({createFail:true}), t = transport(f);
    await assert.rejects(helper.launch(config,Buffer.alloc(80),t.Socket),e=>/creation failed/.test(e.message) && e.launchState === 'not-launched');
    assert.strictEqual(f.calls.filter(c=>c[0]==='close').length,0); checks++;
    {
        const f = endpoint({fileExtraAce:true}), t = transport(f);
        await assert.rejects(helper.launch(config,Buffer.alloc(80),t.Socket),e=>e.message.includes(exe) && e.message.includes('observedSDDL=O:SYD:') && e.launchState === 'not-launched'); checks++;
    }
    {
        const f = endpoint({closeThrows:true}), t = transport(f);
        await assert.rejects(helper.launch(config,Buffer.alloc(80),t.Socket),e=>e.launchState === 'unknown');
        assert.strictEqual(f.calls.filter(c=>c[0]==='create').length,1); checks++;
    }
    for (const change of [
        {controlUrl:'ws://fixture.invalid/control.ashx'},{controlUrl:'wss://fixture.invalid/control.ashx?auth=secret'},
        {loginUser:'operator'},{nodeId:'fixture'},{sourceSha384:'x'.repeat(96)},{sourceExe:'C:\\safe\\..\\package.exe'},
        {sourceExe:'C:\\safe\\package.exe:stream'},{sourceExe:'\\\\server\\share\\package.exe'},{sourceExe:'C:\\safe\\NUL.exe'},
        {sourceExe:'C:\\safe \\package.exe'},{sourceExe:'C:/safe/package.exe'},{timeoutMs:0}
    ]) {
        let opened = false;
        assert.throws(()=>helper.launch({...config,...change},Buffer.alloc(80),class {constructor(){opened=true;}}));
        assert.strictEqual(opened,false); checks++;
    }
    assert.throws(()=>helper.launch(config,Buffer.alloc(79),class {})); checks++;
    assert.throws(()=>helper.parseArgs(['--command','arbitrary'])); checks++;
    assert.throws(()=>helper.parseArgs(['--keyfile','a','--keyfile','b'])); checks++;
    console.log('PASS meshcentral legacy bootstrap: '+checks+' fixture cases; no remote calls');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
