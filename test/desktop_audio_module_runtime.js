'use strict';
// Executes production desktop-audio dispatch with injected process/pipe/timer observations.
// Does not capture audio or launch any Windows process.
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm'), zlib = require('zlib');
const {EventEmitter} = require('events');
const source = fs.readFileSync(path.join(__dirname, '../modules/desktop-audio.js'), 'utf8');
{
    // The agent runs its embedded copy unless a newer-dated override arrives, so a stale
    // embed silently ships the previous implementation. Keep the two identical.
    const polyfills = fs.readFileSync(path.join(__dirname, '../microscript/ILibDuktape_Polyfills.c'), 'utf8');
    const embed = /addCompressedModule\('desktop-audio', Buffer\.from\('([^']+)', 'base64'\), '([^']+)'\)/.exec(polyfills);
    assert(embed, 'embedded desktop-audio module entry');
    const embedded = zlib.inflateSync(Buffer.from(embed[1], 'base64')).toString('utf8');
    assert.equal(embedded.replace(/\r\n?/g, '\n'), source.replace(/\r\n?/g, '\n'), 'embedded desktop-audio module matches modules/desktop-audio.js; re-embed it');
}

const DLL = 'C:\\Agent With Spaces\\agent.dll', RUNDLL = 'C:\\Windows\\System32\\rundll32.exe';
function pointer(low, high = 0) { const b = Buffer.alloc(8); b.writeUInt32LE(low >>> 0, 0); b.writeUInt32LE(high >>> 0, 4); return {pointerBuffer:() => b}; }
function fixture(options = {}) {
    let now = 1000, launched = 0, killed = 0, ended = 0, dbValue = options.db === undefined ? null : options.db;
    const children = [], timers = new Map(), fired = new Set(), immediates = []; let nextTimer = 0;
    const lookups = [];
    const context = { module:{exports:{}}, Buffer, isFinite, Math, Object,
        process:{platform:options.platform || 'win32'},
        Date:{now:() => now},
        setTimeout(fn, ms) { const id = ++nextTimer; timers.set(id, {fn, at:now + ms}); return id; },
        // Mirrors Duktape: clearing a timer that already fired throws instead of being a no-op.
        clearTimeout(id) { if (fired.has(id)) throw Error('timers.clearTimeout(): Invalid Parameter'); timers.delete(id); },
        setImmediate(fn) { immediates.push(fn); },
        _MSH() { return {meshServiceName:'msh-service'}; },
        require(name) {
            if (name === 'events') return {EventEmitter:{call(target) {
                // Duktape's EventEmitter.call(this, true) mixes emitter methods into the target, and
                // createEvent(name) installs an instance accessor named after the event that shadows
                // any prototype member of that name; addMethod defines an own method.
                const emitter = new EventEmitter(); target.on = emitter.on.bind(emitter); target.emit = emitter.emit.bind(emitter);
                const chain = {
                    createEvent(event) { Object.defineProperty(target, event, {configurable:true, get() { return undefined; }, set(fn) { emitter.on(event, fn); }}); return chain; },
                    addMethod(method, fn) { Object.defineProperty(target, method, {configurable:true, writable:true, value:fn}); return chain; }};
                return chain; }}};
            if (name === 'MeshAgent') { if (options.agentError) throw Error('no agent'); return {isService:options.isService !== false}; }
            if (name === 'SimpleDataStore') return {Shared() { if (options.dbNull) return null; return {Get(key) { lookups.push(key); if (options.dbError) throw Error('db closed'); return dbValue; }}; }};
            if (name === 'user-sessions') return {consoleUid() { if (options.consoleError) throw 'Nobody logged in'; return options.console === undefined ? 3 : options.console; }};
            if (name === '_agentNodeId') return {serviceName:() => 'incumbent-service'};
            if (name === 'win-system-paths') return {
                installedServiceRuntimeDll(service) { assert.equal(service, 'incumbent-service'); if (options.pathError) throw Error('DLL missing'); return DLL; },
                system32Path(file) { assert.equal(file, 'rundll32.exe'); return RUNDLL; }};
            if (name === '_GenericMarshal') return {
                CreateVariable(value, opts) { return {value, wide:!!(opts && opts.wide)}; },
                CreateNativeProxy(lib) {
                    assert.equal(lib, 'kernel32.dll'); const proxy = {};
                    proxy.CreateMethod = method => {
                        if (method === 'GetModuleHandleW') proxy[method] = v => { assert.equal(v.value, DLL); assert(v.wide); return options.moduleHandle || pointer(0, 0x7FF8); };
                        else if (method === 'GetProcAddress') proxy[method] = (h, v) => { assert.equal(v.value, 'MeshAudioBridgeW'); assert(!v.wide); return options.procAddress || pointer(0x1234); };
                        else throw Error('Unexpected method ' + method);
                    };
                    return proxy; }};
            if (name === 'child_process') return {execFile(exe, args) {
                ++launched; assert.equal(exe, RUNDLL);
                assert.deepEqual(args.slice(0, 1), [DLL + ',MeshAudioBridgeW']); assert.equal(args.length, 2);
                if (options.launchError) throw Error('launch denied');
                if (options.launchNull) return null;
                const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = new EventEmitter();
                child.stdin.end = () => { ++ended; if (options.endError) throw Error('end failed'); };
                child.kill = () => { ++killed; if (options.killError) throw Error('kill denied'); if (!options.delayedExit) child.emit('exit', 1); };
                child.args = args; children.push(child); return child;
            }};
            throw Error('Unexpected dependency: ' + name);
        }};
    vm.runInNewContext(source, context);
    return { da:context.module.exports, context, children, timers, lookups,
        counts:() => ({launched, killed, ended}), db(value) { dbValue = value; },
        flush() { while (immediates.length) immediates.shift()(); },
        advance(ms) { const end = now + ms; for (;;) { const due = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0]; if (!due) break; now = Math.max(now, due[1].at); timers.delete(due[0]); fired.add(due[0]); due[1].fn(); } now = end; } };
}
function packet(type, payload = Buffer.alloc(0), flags = 0, seq = 0, ts = 0, version = 1) {
    const h = Buffer.alloc(16); h[0] = version; h[1] = type; h.writeUInt16LE(flags, 2); h.writeUInt32LE(seq >>> 0, 4); h.writeUInt32LE(ts >>> 0, 8); h.writeUInt32LE(payload.length, 12);
    return Buffer.concat([h, payload]);
}
function configPayload(over = {}) {
    const p = Buffer.alloc(16); p.writeUInt32LE(over.codec ?? 1, 0); p.writeUInt32LE(over.rate ?? 48000, 4); p.writeUInt16LE(over.channels ?? 2, 8);
    p.writeUInt16LE(over.frame ?? 20, 10); p.writeUInt32LE(over.bitrate ?? 64000, 12); return p;
}
const CONFIG = packet(1, configPayload(), 1, 0, 0);
const AUDIO = packet(2, Buffer.from([0xfc, 0xff, 0xfe, 1, 2, 3]), 0, 1, 20);
const SILENCE = packet(3, Buffer.alloc(0), 0, 2, 250);
function statusPacket(code, reason, raw) { const p = Buffer.alloc(4); p.writeUInt32LE(code >>> 0, 0); return packet(4, Buffer.concat([p, raw || Buffer.from(reason || '')]), 0, 3, 0); }
function watch(stream) {
    const log = { events:[], packets:[], statuses:[] };
    stream.on('status', s => { log.events.push('status:' + s.state); log.statuses.push(s); });
    stream.on('packet', p => { log.events.push('packet:' + p[1]); log.packets.push(Buffer.from(p)); });
    stream.on('close', () => log.events.push('close'));
    return log;
}
function emitSplit(child, data, sizes) { let offset = 0; for (const size of sizes) { child.stdout.emit('data', data.slice(offset, offset + size)); offset += size; } if (offset < data.length) child.stdout.emit('data', data.slice(offset)); }

// supported(): Windows service whose loaded, installed DLL exports the bridge.
{
    assert.equal(fixture().da.supported(), true, 'handle with zero low 32 bits is still a loaded module');
    assert.equal(fixture({isService:false}).da.supported(), false, 'console agents are unsupported');
    assert.equal(fixture({agentError:true}).da.supported(), false);
    assert.equal(fixture({platform:'linux'}).da.supported(), false);
    assert.equal(fixture({pathError:true}).da.supported(), false);
    assert.equal(fixture({moduleHandle:pointer(0, 0)}).da.supported(), false, 'installed DLL not loaded here (console or pending update)');
    assert.equal(fixture({procAddress:pointer(0, 0)}).da.supported(), false, 'DLL without MeshAudioBridgeW');
}
// disabled(): datastore key desktopAudio == '0'; unreadable datastore fails closed.
{
    for (const [value, expected] of [[null, false], [undefined, false], ['1', false], ['', false], ['00', false], ['0', true], [0, true]]) {
        const f = fixture({db:value}); assert.equal(f.da.disabled(), expected, 'desktopAudio=' + value); assert.deepEqual(f.lookups, ['desktopAudio']);
    }
    assert.equal(fixture({dbError:true}).da.disabled(), true);
    assert.equal(fixture({dbNull:true}).da.disabled(), true, 'no shared datastore (script mode) fails closed');
}
// Refusals launch nothing and end with one terminal status, then close, after open() returns.
for (const [options, tsid, state, pattern] of [
    [{isService:false}, 3, 'unavailable', /not supported/], [{platform:'linux'}, 3, 'unavailable', /not supported/],
    [{db:'0'}, 3, 'unavailable', /disabled/], [{dbError:true}, 3, 'unavailable', /disabled/],
    ...[0, -1, 1.5, NaN, Infinity, 0xFFFFFFFF, '3', {}].map(id => [{}, id, 'error', /session ID/]),
    [{consoleError:true}, null, 'error', /Nobody logged in/], [{console:-1}, null, 'error', /No interactive/], [{console:0}, undefined, 'error', /No interactive/]]) {
    const f = fixture(options), s = f.da.open(tsid), log = watch(s);
    assert.deepEqual(log.events, [], 'no synchronous events');
    f.flush();
    assert.deepEqual(log.events, ['status:' + state, 'close']); assert.match(log.statuses[0].reason, pattern);
    assert.equal(f.counts().launched, 0); assert.equal(f.timers.size, 0);
    s.close(); assert.equal(log.events.length, 2, 'close after close is silent');
}
// Happy path: framing across arbitrary chunk boundaries, forwarding exact packets, shared helper.
{
    const f = fixture(), a = f.da.open(3), la = watch(a); f.flush();
    assert.equal(f.counts().launched, 1); assert.deepEqual(f.children[0].args, [DLL + ',MeshAudioBridgeW', 'tsid=3']);
    assert.deepEqual(la.events, [], 'nothing before CONFIG');
    const stream = Buffer.concat([CONFIG, AUDIO, SILENCE, AUDIO]);
    emitSplit(f.children[0], stream, [1, 2, 3, 10, 1, 15, 7, 1]);
    assert.deepEqual(la.events, ['status:started', 'packet:1', 'packet:2', 'packet:3', 'packet:2']);
    assert.deepEqual(la.packets, [CONFIG, AUDIO, SILENCE, AUDIO]);
    assert.equal(f.context.desktopAudioHelpers['tsid=3'].pending.length, 0);
    // A late joiner shares the helper and starts from the current configuration.
    const b = f.da.open(3), lb = watch(b); f.flush();
    assert.equal(f.counts().launched, 1);
    assert.deepEqual(lb.events, ['status:started', 'packet:1']); assert.deepEqual(lb.packets[0], CONFIG);
    // A device change replaces the configuration for both consumers and later joiners.
    const changed = packet(1, configPayload({bitrate:96000}), 1, 9, 900);
    f.children[0].stdout.emit('data', Buffer.concat([changed, SILENCE]));
    assert.deepEqual(la.events.slice(-2), ['packet:1', 'packet:3']); assert.deepEqual(lb.events.slice(-2), ['packet:1', 'packet:3']);
    // No session ID means the console session, as for the desktop; it shares that session's helper.
    const c = f.da.open(null), lc = watch(c); f.flush(); assert.deepEqual(lc.packets[0], changed); assert.equal(f.counts().launched, 1);
    // Consumer callbacks that throw cannot starve the others.
    a.on('packet', () => { throw Error('consumer failed'); });
    f.children[0].stdout.emit('data', AUDIO);
    assert.equal(lb.events.at(-1), 'packet:2'); assert.equal(lc.events.at(-1), 'packet:2');
    a.close(); c.close();
    assert.deepEqual(la.events.slice(-2), ['status:stopped', 'close']); assert.equal(f.counts().killed, 0, 'helper survives while consumers remain');
    f.children[0].stdout.emit('data', AUDIO); assert.equal(la.events.at(-1), 'close', 'no events after close');
    assert.equal(lb.events.at(-1), 'packet:2');
    b.close();
    assert.deepEqual(lb.events.slice(-2), ['status:stopped', 'close']);
    assert.deepEqual(f.counts(), {launched:1, killed:1, ended:1}, 'last consumer ends stdin and kills the helper');
    assert.equal(f.timers.size, 0); assert.deepEqual(Object.keys(f.context.desktopAudioHelpers), []);
    // A graceful stop leaves no backoff.
    const d = f.da.open(3); watch(d); f.flush(); assert.equal(f.counts().launched, 2); d.close();
}
// close() before attachment launches nothing; close() from inside a callback is safe.
{
    const f = fixture(), s = f.da.open(3), log = watch(s); s.close(); f.flush();
    assert.deepEqual(log.events, ['status:stopped', 'close']); assert.equal(f.counts().launched, 0);
    const r = f.da.open(4), lr = watch(r); r.on('status', st => { if (st.state === 'started') r.close(); }); f.flush();
    f.children[0].stdout.emit('data', Buffer.concat([CONFIG, AUDIO]));
    assert.deepEqual(lr.events, ['status:started', 'status:stopped', 'close'], 'no packet after re-entrant close');
    assert.equal(f.counts().killed, 1); assert.equal(f.timers.size, 0);
}
// Malformed output fails closed: helper killed, one error status, close, 30 s backoff, then relaunch.
const malformed = {
    version: packet(2, Buffer.alloc(0), 0, 0, 0, 2).slice(0, 16),
    typeZero: packet(0, Buffer.alloc(0)), typeFive: packet(5, Buffer.alloc(0)),
    flags: packet(1, configPayload(), 3), oversize: (() => { const p = packet(2, Buffer.alloc(0)); p.writeUInt32LE(4097, 12); return p; })(),
    configNoDiscontinuity: packet(1, configPayload(), 0), configShort: packet(1, configPayload().slice(0, 12), 1),
    configCodec: packet(1, configPayload({codec:2}), 1), configRate: packet(1, configPayload({rate:44100}), 1),
    configChannels: packet(1, configPayload({channels:1}), 1), configFrame: packet(1, configPayload({frame:10}), 1),
    configBitrate: packet(1, configPayload({bitrate:0}), 1),
    audioFirst: AUDIO, silenceFirst: SILENCE,
    emptyAudio: Buffer.concat([CONFIG, packet(2, Buffer.alloc(0))]), silencePayload: Buffer.concat([CONFIG, packet(3, Buffer.from([0]))]),
    statusShort: packet(4, Buffer.from([1, 2])), statusLong: statusPacket(5, 'x'.repeat(257)),
    statusUtf8: statusPacket(5, null, Buffer.from([0xc3, 0x28])),
    trailingGarbage: Buffer.concat([CONFIG, Buffer.from('MZ\x90\x00 not a header ...')]),
};
for (const [name, data] of Object.entries(malformed)) {
    const f = fixture(), s = f.da.open(3), log = watch(s); f.flush();
    f.children[0].stdout.emit('data', data);
    const final = log.events.slice(-2);
    assert.deepEqual(final, ['status:error', 'close'], name); assert.match(log.statuses.at(-1).reason, /Invalid desktop audio packet/, name);
    assert.equal(log.packets.filter(p => p[1] !== 1).length, 0, name + ': nothing after the bad frame is forwarded');
    assert.equal(f.counts().killed, 1, name); assert.equal(f.timers.size, 0, name);
    const retry = f.da.open(3), lr = watch(retry); f.flush();
    assert.deepEqual(lr.events, ['status:error', 'close'], name + ': backoff'); assert.equal(f.counts().launched, 1, name);
    f.advance(30000); const again = f.da.open(3); watch(again); f.flush(); assert.equal(f.counts().launched, 2, name + ': relaunch after backoff'); again.close();
}
// An oversize length is rejected from the header alone; retained bytes never exceed one frame.
{
    const parse = fixture().context.desktopAudioParse;
    let pending = Buffer.alloc(0);
    const big = packet(2, Buffer.alloc(4096, 7));
    for (let i = 0; i < big.length - 1; i += 97) { const r = parse(pending, big.slice(i, Math.min(i + 97, big.length - 1))); assert.equal(r.packets.length, 0); pending = r.pending; assert(pending.length < 16 + 4096); }
    const done = parse(pending, big.slice(big.length - 1)); assert.equal(done.packets.length, 1); assert.deepEqual(done.packets[0], big); assert.equal(done.pending.length, 0);
    const header = packet(2, Buffer.alloc(0)); header.writeUInt32LE(0xFFFFFFFF, 12);
    assert.throws(() => parse(Buffer.alloc(0), header), /length/);
}
// STATUS ends the helper: no-device codes are 'unavailable', others 'error', 0 a normal stop.
for (const [code, state, reason, backoff] of [
    [0x80070490, 'unavailable', 'No render endpoint', true], [0x88890004, 'unavailable', 'Device invalidated', true],
    [1168, 'unavailable', '', true], [5, 'error', 'Access denied\r\n\x00', true], [0, 'stopped', 'Session ended', false]]) {
    const f = fixture(), s = f.da.open(7), log = watch(s); f.flush();
    f.children[0].stdout.emit('data', Buffer.concat([CONFIG, statusPacket(code, reason), AUDIO]));
    assert.deepEqual(log.events, ['status:started', 'packet:1', 'status:' + state, 'close']);
    const st = log.statuses.at(-1); assert.equal(st.code, code);
    assert.equal(st.reason, reason ? reason.replace(/[\r\n\x00]/g, ' ').trim() : 'Desktop audio capture ended (error=1168).');
    assert.equal(f.counts().killed, 1);
    const next = f.da.open(7); const ln = watch(next); f.flush();
    assert.equal(f.counts().launched, backoff ? 1 : 2); if (backoff) assert.deepEqual(ln.events, ['status:' + state, 'close']); else next.close();
}
{
    // STATUS before CONFIG reports the startup failure.
    const f = fixture(), s = f.da.open(7), log = watch(s); f.flush();
    f.children[0].stdout.emit('data', statusPacket(0x88890010, 'Audio service not running'));
    assert.deepEqual(log.events, ['status:unavailable', 'close']);
}
// Process and pipe failures.
for (const mode of ['exit', 'end', 'stdin-error', 'stdout-error', 'stderr-error', 'error']) {
    const f = fixture(), a = f.da.open(3), b = f.da.open(3), la = watch(a), lb = watch(b), child = (f.flush(), f.children[0]);
    child.stdout.emit('data', CONFIG); child.stderr.emit('data', Buffer.from('diagnostic noise'));
    if (mode === 'exit') child.emit('exit', 1314);
    else if (mode === 'end') child.stdout.emit('end');
    else if (mode === 'stdin-error') child.stdin.emit('error', Error('broken'));
    else if (mode === 'stdout-error') child.stdout.emit('error', Error('broken'));
    else if (mode === 'stderr-error') child.stderr.emit('error', Error('broken'));
    else child.emit('error', Error('broken'));
    for (const log of [la, lb]) { assert.deepEqual(log.events.slice(-2), ['status:error', 'close'], mode); }
    if (mode === 'exit') { assert.equal(la.statuses.at(-1).code, 1314); assert.equal(f.counts().killed, 0); } else assert.equal(f.counts().killed, 1);
    assert.equal(f.timers.size, 0, mode);
}
// Launch failures are cached for 30 seconds so repeated requests cannot storm.
for (const options of [{launchError:true}, {launchNull:true}]) {
    const f = fixture(options);
    for (let i = 0; i < 100; ++i) { const s = f.da.open(3), log = watch(s); f.flush(); assert.deepEqual(log.events, ['status:error', 'close']); assert.match(log.statuses[0].reason, /denied/); }
    assert.equal(f.counts().launched, 1); f.advance(30000); const s = f.da.open(3); watch(s); f.flush(); assert.equal(f.counts().launched, 2);
}
// Watchdog: no CONFIG within 30 s, or no packet for 10 s once started, fails closed.
{
    const f = fixture(), s = f.da.open(3), log = watch(s); f.flush();
    f.advance(29999); assert.deepEqual(log.events, []); f.advance(1);
    assert.deepEqual(log.events, ['status:error', 'close']); assert.match(log.statuses[0].reason, /did not start/); assert.equal(f.counts().killed, 1);
    assert.equal(f.timers.size, 0);
}
{
    const f = fixture(), s = f.da.open(3), log = watch(s); f.flush(); f.children[0].stdout.emit('data', CONFIG);
    for (let i = 0; i < 400; ++i) { f.advance(250); f.children[0].stdout.emit('data', SILENCE); }
    assert.equal(log.events.at(-1), 'packet:3', 'SILENCE every 250 ms keeps the helper alive');
    f.advance(10000);
    assert.deepEqual(log.events.slice(-2), ['status:error', 'close']); assert.match(log.statuses.at(-1).reason, /stopped sending/);
    assert.equal(f.timers.size, 0);
}
// At most four helpers; a terminating helper is never overlapped.
{
    const f = fixture({delayedExit:true}), streams = [];
    for (let id = 1; id <= 4; ++id) { streams.push(f.da.open(id)); }
    const fifth = f.da.open(5), l5 = watch(fifth); f.flush();
    assert.equal(f.counts().launched, 4); assert.deepEqual(l5.events, ['status:error', 'close']); assert.match(l5.statuses[0].reason, /limit/);
    streams[0].close(); assert.equal(f.counts().killed, 1);
    const sameSession = f.da.open(1), ls = watch(sameSession), other = f.da.open(5), lo = watch(other); f.flush();
    assert.match(ls.statuses[0].reason, /still terminating/); assert.match(lo.statuses[0].reason, /limit/, 'terminating helpers still count');
    f.children[0].emit('exit', 0);
    const retry = f.da.open(1), five = f.da.open(5); f.flush(); assert.equal(f.counts().launched, 5, 'exit frees the slot');
    const six = f.da.open(6), l6 = watch(six); f.flush(); assert.match(l6.statuses[0].reason, /limit/);
    streams.slice(1).concat([retry, five]).forEach(s => s.close());
}
{
    // A denied kill keeps the helper accounted until its exit event arrives.
    const f = fixture({killError:true}), s = f.da.open(3); f.flush(); s.close();
    for (let i = 0; i < 50; ++i) { const t = f.da.open(3), l = watch(t); f.flush(); assert.match(l.statuses[0].reason, /still terminating/); }
    assert.equal(f.counts().launched, 1); f.children[0].emit('exit', 0);
    const t = f.da.open(3); watch(t); f.flush(); assert.equal(f.counts().launched, 2);
}
{
    // stdin cleanup failure must not skip process cleanup.
    const f = fixture({endError:true}), s = f.da.open(3); f.flush(); s.close(); assert.equal(f.counts().killed, 1);
}
console.log('Desktop audio module: support/kill-switch checks, shared refcounted helper, strict framing, fail-closed errors, backoff, watchdog, helper cap and cleanup passed.');
