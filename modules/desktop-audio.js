/*
Copyright 2026

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Windows desktop audio. One native MeshAudioBridgeW broker per session captures
// speaker output (WASAPI loopback, never the microphone) and writes framed Opus
// packets to its stdout. Every consumer of a session shares that broker, which
// ends with the last consumer. Packets are validated and forwarded unchanged;
// audio is never stored, queued or logged. A failed helper is cached for 30
// seconds so repeated viewer requests cannot create a launch storm.
//
// Packet: 16-byte little-endian header (version 1, type, flags, sequence,
// timestamp_ms, payload length <= 4096) followed by the payload.
var DESKTOP_AUDIO_VERSION = 1;
var DESKTOP_AUDIO_HEADER_BYTES = 16;
var DESKTOP_AUDIO_MAX_PAYLOAD = 4096;
var DESKTOP_AUDIO_CONFIG = 1;
var DESKTOP_AUDIO_AUDIO = 2;
var DESKTOP_AUDIO_SILENCE = 3;
var DESKTOP_AUDIO_STATUS = 4;
var DESKTOP_AUDIO_DISCONTINUITY = 1;
var DESKTOP_AUDIO_MAX_REASON = 256;
var DESKTOP_AUDIO_HELPER_LIMIT = 4;
var DESKTOP_AUDIO_RETRY_MS = 30000;
// Startup covers token selection, helper start and audio client initialization.
// Once started the helper sends at least one SILENCE packet every 250 ms.
var DESKTOP_AUDIO_START_MS = 30000;
var DESKTOP_AUDIO_STALL_MS = 10000;
// Helper STATUS codes meaning no usable render endpoint: ERROR_NOT_FOUND,
// E_NOTFOUND, AUDCLNT_E_DEVICE_INVALIDATED and AUDCLNT_E_SERVICE_NOT_RUNNING.
var DESKTOP_AUDIO_NO_DEVICE = [1168, 0x80070490, 0x88890004, 0x88890010];

var desktopAudioHelpers = {};
var desktopAudioNative = null;

// Duktape's clearTimeout throws for a timer that already fired, unlike Node.
function desktopAudioCancel(timer)
{
    try { if (timer) { clearTimeout(timer); } } catch (timerError) { }
    return null;
}
function desktopAudioState(state, code, reason)
{
    var ret = { state: state };
    if (code != null) { ret.code = code; }
    if (reason != null) { ret.reason = reason; }
    return ret;
}
function desktopAudioErrorText(error)
{
    return (error && error.message) ? error.message : ('' + error);
}
function desktopAudioInvalid(message)
{
    throw new Error('Invalid desktop audio packet: ' + message + '.');
}
// Duktape buffers expose raw bytes rather than Node's UTF-8 codec. decodeURIComponent
// rejects malformed UTF-8; control characters never reach viewers or audit records.
function desktopAudioReason(buffer)
{
    var escaped = [];
    for (var i = 0; i < buffer.length; ++i) { escaped.push('%' + ('0' + buffer[i].toString(16)).slice(-2)); }
    return decodeURIComponent(escaped.join('')).replace(/[\x00-\x1f\x7f]/g, ' ').trim();
}
function desktopAudioStatusInfo(packet)
{
    return { code: packet.readUInt32LE(DESKTOP_AUDIO_HEADER_BYTES), reason: desktopAudioReason(packet.slice(DESKTOP_AUDIO_HEADER_BYTES + 4)) };
}
function desktopAudioValidatePayload(type, flags, packet)
{
    var length = packet.length - DESKTOP_AUDIO_HEADER_BYTES;
    switch (type)
    {
        case DESKTOP_AUDIO_CONFIG:
            // Opus, 48 kHz, stereo, 20 ms frames; a new format always restarts playback.
            if (length != 16 || (flags & DESKTOP_AUDIO_DISCONTINUITY) == 0 ||
                packet.readUInt32LE(16) != 1 || packet.readUInt32LE(20) != 48000 || packet.readUInt16LE(24) != 2 ||
                packet.readUInt16LE(26) != 20 || packet.readUInt32LE(28) < 6000 || packet.readUInt32LE(28) > 510000)
            { desktopAudioInvalid('configuration'); }
            break;
        case DESKTOP_AUDIO_AUDIO:
            if (length == 0) { desktopAudioInvalid('empty audio'); }
            break;
        case DESKTOP_AUDIO_SILENCE:
            if (length != 0) { desktopAudioInvalid('silence payload'); }
            break;
        case DESKTOP_AUDIO_STATUS:
            if (length < 4 || length > 4 + DESKTOP_AUDIO_MAX_REASON) { desktopAudioInvalid('status length'); }
            try { desktopAudioStatusInfo(packet); } catch (reasonError) { desktopAudioInvalid('status reason'); }
            break;
        default:
            desktopAudioInvalid('type');
    }
}
// Splits helper output into complete packets. Only the trailing partial frame is
// retained, and its header is validated as soon as it arrives, so the retained
// bytes never exceed one maximum-size packet. Any malformed frame throws.
function desktopAudioParse(pending, chunk)
{
    var data = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    var offset = 0, packets = [];
    while (data.length - offset >= DESKTOP_AUDIO_HEADER_BYTES)
    {
        var type = data[offset + 1], flags = data.readUInt16LE(offset + 2), length = data.readUInt32LE(offset + 12);
        if (data[offset] != DESKTOP_AUDIO_VERSION) { desktopAudioInvalid('version'); }
        if (type < DESKTOP_AUDIO_CONFIG || type > DESKTOP_AUDIO_STATUS) { desktopAudioInvalid('type'); }
        if ((flags & ~DESKTOP_AUDIO_DISCONTINUITY) != 0) { desktopAudioInvalid('flags'); }
        if (length > DESKTOP_AUDIO_MAX_PAYLOAD) { desktopAudioInvalid('length'); }
        if (data.length - offset < DESKTOP_AUDIO_HEADER_BYTES + length) { break; }
        var packet = data.slice(offset, offset + DESKTOP_AUDIO_HEADER_BYTES + length);
        desktopAudioValidatePayload(type, flags, packet);
        packets.push(packet);
        offset += DESKTOP_AUDIO_HEADER_BYTES + length;
    }
    var rest = Buffer.alloc(data.length - offset);
    if (rest.length) { data.copy(rest, 0, offset); }
    return { packets: packets, pending: rest };
}

function desktopAudioServiceDll()
{
    var serviceName = null, msh = null;
    try { serviceName = require('_agentNodeId').serviceName(); } catch (identityError) { }
    if (!serviceName) { try { msh = _MSH(); } catch (mshError) { } serviceName = msh && msh.meshServiceName ? msh.meshServiceName : 'meshagent'; }
    return require('win-system-paths').installedServiceRuntimeDll('' + serviceName);
}
function desktopAudioNullPointer(value)
{
    var bytes = value.pointerBuffer();
    for (var i = 0; i < bytes.length; ++i) { if (bytes[i] != 0) { return false; } }
    return true;
}
// The service host already has its DLL loaded; GetModuleHandleW neither loads nor
// pins it. A console agent, or an installed DLL that is not the running one (an
// update pending restart), reports no support rather than launching a mismatch.
function desktopAudioExportPresent(dll)
{
    if (desktopAudioNative == null)
    {
        var marshal = require('_GenericMarshal');
        var kernel32 = marshal.CreateNativeProxy('kernel32.dll');
        kernel32.CreateMethod('GetModuleHandleW');
        kernel32.CreateMethod('GetProcAddress');
        desktopAudioNative = { marshal: marshal, kernel32: kernel32 };
    }
    var handle = desktopAudioNative.kernel32.GetModuleHandleW(desktopAudioNative.marshal.CreateVariable(dll, { wide: true }));
    if (desktopAudioNullPointer(handle)) { return false; }
    return !desktopAudioNullPointer(desktopAudioNative.kernel32.GetProcAddress(handle, desktopAudioNative.marshal.CreateVariable('MeshAudioBridgeW')));
}
function desktopAudioSupported()
{
    if (process.platform != 'win32') { return false; }
    try
    {
        if (require('MeshAgent').isService !== true) { return false; }
        return desktopAudioExportPresent(desktopAudioServiceDll());
    }
    catch (supportError) { return false; }
}
// Agent datastore key desktopAudio == '0' disables audio on this device. A
// datastore that cannot be read cannot prove the switch is off.
function desktopAudioDisabled()
{
    try
    {
        var value = require('SimpleDataStore').Shared().Get('desktopAudio');
        return value != null && ('' + value) == '0';
    }
    catch (datastoreError) { return true; }
}

function desktopAudioEmit(stream, name, value)
{
    // A consumer callback can throw or re-enter close(); contain it so the shared
    // helper and the other consumers of the session are unaffected.
    try { stream.emit(name, value); } catch (consumerError) { }
}
// Exactly one terminal status, then 'close'. No event follows.
function desktopAudioFinish(stream, status)
{
    if (stream.closed) { return; }
    stream.closed = true;
    stream.helper = null;
    desktopAudioEmit(stream, 'status', status);
    desktopAudioEmit(stream, 'close');
}
function desktopAudioClose(state, status)
{
    if (state.closed) { return; }
    var failed = status != null && status.state != 'stopped';
    state.closed = true;
    state.watchdog = desktopAudioCancel(state.watchdog);
    state.retryAt = failed ? Date.now() + DESKTOP_AUDIO_RETRY_MS : 0;
    state.failure = failed ? status : null;
    state.pending = Buffer.alloc(0);
    state.config = null;
    var child = state.child;
    // Retain the child until its exit event confirms termination. A denied kill
    // must not permit another broker to overlap it after the retry cooldown.
    try { if (child) { child.stdin.end(); } } catch (inputCleanupError) { }
    try { if (child) { child.kill(); } } catch (processCleanupError) { }
    var consumers = state.consumers;
    state.consumers = [];
    for (var i = 0; i < consumers.length; ++i) { desktopAudioFinish(consumers[i], status || desktopAudioState('stopped')); }
    if (!failed && !state.child && desktopAudioHelpers[state.key] === state) { delete desktopAudioHelpers[state.key]; }
}
function desktopAudioWatch(state, delay)
{
    state.watchdog = setTimeout(function ()
    {
        state.watchdog = null;
        if (state.closed) { return; }
        if (!state.started) { desktopAudioClose(state, desktopAudioState('error', null, 'Desktop audio helper did not start.')); return; }
        if (Date.now() - state.activityAt >= DESKTOP_AUDIO_STALL_MS)
        {
            desktopAudioClose(state, desktopAudioState('error', null, 'Desktop audio helper stopped sending packets.'));
            return;
        }
        desktopAudioWatch(state, DESKTOP_AUDIO_STALL_MS / 2);
    }, delay);
}
function desktopAudioPacket(state, packet)
{
    var type = packet[1];
    if (type == DESKTOP_AUDIO_STATUS)
    {
        // The helper reports a failure and then exits. Code 0 is a normal end.
        var info = desktopAudioStatusInfo(packet);
        var name = info.code == 0 ? 'stopped' : (DESKTOP_AUDIO_NO_DEVICE.indexOf(info.code) >= 0 ? 'unavailable' : 'error');
        desktopAudioClose(state, desktopAudioState(name, info.code,
            info.reason.length ? info.reason : 'Desktop audio capture ended (error=' + info.code + ').'));
        return;
    }
    state.activityAt = Date.now();
    if (type == DESKTOP_AUDIO_CONFIG)
    {
        // Retained for consumers that join a running helper; a copy so the
        // output chunk it was sliced from is not kept alive.
        state.config = Buffer.alloc(packet.length);
        packet.copy(state.config);
    }
    var consumers = state.consumers.slice(0), i;
    if (!state.started)
    {
        if (type != DESKTOP_AUDIO_CONFIG)
        {
            desktopAudioClose(state, desktopAudioState('error', null, 'Invalid desktop audio packet: configuration must come first.'));
            return;
        }
        state.started = true;
        state.watchdog = desktopAudioCancel(state.watchdog);
        desktopAudioWatch(state, DESKTOP_AUDIO_STALL_MS / 2);
        for (i = 0; i < consumers.length; ++i)
        {
            if (consumers[i].helper === state) { desktopAudioEmit(consumers[i], 'status', desktopAudioState('started')); }
        }
    }
    for (i = 0; i < consumers.length && !state.closed; ++i)
    {
        if (consumers[i].helper === state) { desktopAudioEmit(consumers[i], 'packet', packet); }
    }
}
function desktopAudioData(state, chunk)
{
    if (state.closed) { return; }
    var parsed;
    try { parsed = desktopAudioParse(state.pending, chunk); }
    catch (parseError)
    {
        // Fail closed: a framing error means the stream can no longer be trusted.
        desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(parseError)));
        return;
    }
    state.pending = parsed.pending;
    for (var i = 0; i < parsed.packets.length && !state.closed; ++i) { desktopAudioPacket(state, parsed.packets[i]); }
}
function desktopAudioLaunch(state)
{
    try
    {
        var paths = require('win-system-paths');
        var dll = desktopAudioServiceDll();
        state.child = require('child_process').execFile(paths.system32Path('rundll32.exe'), [dll + ',MeshAudioBridgeW', state.key]);
        if (!state.child) { throw new Error('Desktop audio helper launch denied.'); }
        // Only packet frames go to stdout; discard incidental stderr.
        state.child.stdout.on('data', function (chunk) { desktopAudioData(state, chunk); });
        state.child.stderr.on('data', function () { });
        state.child.stdout.on('end', function () { desktopAudioClose(state, desktopAudioState('error', null, 'Desktop audio helper output ended.')); });
        state.child.stdin.on('error', function (error) { desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(error))); });
        state.child.stdout.on('error', function (error) { desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(error))); });
        state.child.stderr.on('error', function (error) { desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(error))); });
        state.child.on('error', function (error) { desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(error))); });
        state.child.on('exit', function (code)
        {
            state.child = null;
            if (state.closed && !state.retryAt && desktopAudioHelpers[state.key] === state) { delete desktopAudioHelpers[state.key]; }
            desktopAudioClose(state, desktopAudioState('error', code, 'Desktop audio helper exited (error=' + code + ').'));
        });
        desktopAudioWatch(state, DESKTOP_AUDIO_START_MS);
    }
    catch (startError) { desktopAudioClose(state, desktopAudioState('error', null, desktopAudioErrorText(startError))); }
}
// Returns { helper } for a running or starting helper, or { status } when none can be used.
function desktopAudioAcquire(key)
{
    var state = desktopAudioHelpers[key];
    if (state && state.closed)
    {
        if (Date.now() < state.retryAt) { return { status: state.failure }; }
        if (state.child) { return { status: desktopAudioState('error', null, 'Desktop audio helper is still terminating.') }; }
        delete desktopAudioHelpers[key];
        state = null;
    }
    if (state) { return { helper: state }; }
    var keys = Object.keys(desktopAudioHelpers);
    for (var k = 0; k < keys.length; ++k)
    {
        var old = desktopAudioHelpers[keys[k]];
        if (old.closed && !old.child && Date.now() >= old.retryAt) { delete desktopAudioHelpers[keys[k]]; }
    }
    if (Object.keys(desktopAudioHelpers).length >= DESKTOP_AUDIO_HELPER_LIMIT)
    {
        return { status: desktopAudioState('error', null, 'Desktop audio session limit reached.') };
    }
    state = { key: key, consumers: [], child: null, pending: Buffer.alloc(0), config: null, watchdog: null,
        closed: false, started: false, retryAt: 0, failure: null, activityAt: 0 };
    desktopAudioHelpers[key] = state;
    desktopAudioLaunch(state);
    return state.closed ? { status: state.failure } : { helper: state };
}
function desktopAudioSessionId(tsid)
{
    return typeof (tsid) == 'number' && isFinite(tsid) && Math.floor(tsid) == tsid && tsid > 0 && tsid < 0xFFFFFFFF;
}
function desktopAudioAttach(stream)
{
    if (stream.closed) { return; }
    var tsid = stream.tsid, result;
    if (tsid != null && !desktopAudioSessionId(tsid))
    {
        result = { status: desktopAudioState('error', null, 'Invalid desktop audio session ID.') };
    }
    else if (!desktopAudioSupported())
    {
        result = { status: desktopAudioState('unavailable', null, 'Desktop audio is not supported by this agent.') };
    }
    else if (desktopAudioDisabled())
    {
        result = { status: desktopAudioState('unavailable', null, 'Desktop audio is disabled on this device.') };
    }
    else
    {
        try
        {
            // No session means the console session, which is what the desktop shows without one.
            if (tsid == null) { tsid = Number(require('user-sessions').consoleUid()); }
            result = desktopAudioSessionId(tsid) ? desktopAudioAcquire('tsid=' + tsid) :
                { status: desktopAudioState('error', null, 'No interactive Windows session.') };
        }
        catch (acquireError) { result = { status: desktopAudioState('error', null, desktopAudioErrorText(acquireError)) }; }
    }
    if (result.status) { desktopAudioFinish(stream, result.status); return; }
    var state = result.helper;
    state.consumers.push(stream);
    stream.helper = state;
    if (state.started)
    {
        // A consumer joining a running helper starts from its current configuration,
        // which always carries the DISCONTINUITY flag.
        desktopAudioEmit(stream, 'status', desktopAudioState('started'));
        if (stream.helper === state && state.config) { desktopAudioEmit(stream, 'packet', state.config); }
    }
}
function desktopAudioRelease(stream)
{
    if (stream.closed) { return; }
    var state = stream.helper;
    if (state)
    {
        var index = state.consumers.indexOf(stream);
        if (index >= 0) { state.consumers.splice(index, 1); }
        if (state.consumers.length == 0) { desktopAudioClose(state, null); }
    }
    desktopAudioFinish(stream, desktopAudioState('stopped'));
}

// Events: 'status' { state: 'started'|'stopped'|'unavailable'|'error', code?, reason? },
// 'packet' (Buffer holding one validated packet) and 'close'. All events are
// delivered after open() returns; none follow 'close' or a close() call.
// createEvent('close') installs an instance accessor that would shadow a prototype
// close(), so the method is added on the instance after the event.
function DesktopAudioStream(tsid)
{
    this._ObjectID = 'desktop-audio.stream';
    require('events').EventEmitter.call(this, true)
        .createEvent('packet')
        .createEvent('status')
        .createEvent('close')
        .addMethod('close', function close() { desktopAudioRelease(this); });
    this.tsid = tsid;
    this.helper = null;
    this.closed = false;
    var self = this;
    setImmediate(function () { desktopAudioAttach(self); });
}

module.exports =
{
    supported: desktopAudioSupported,
    disabled: desktopAudioDisabled,
    open: function open(tsid) { return (new DesktopAudioStream(tsid)); }
};
