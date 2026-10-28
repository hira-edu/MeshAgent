/*
Copyright 2018-2026 Open Source Mesh Agent Project

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

var childProcess = require('child_process');
var duplex = require('stream').Duplex;
var net = require('net');

var bridgeCounter = 0;
var SHELL_COMMAND = 'cmd';
var SHELL_AUTOMATION = 'powershell';
var BRIDGE_CONNECT_TIMEOUT_MS = 15000;
var BRIDGE_READY_MARKER = '\x1b]MeshConsoleBridgeReady\x07';

// Records a bridge failure in the agent log where no caller is left to report it to.
function logBridge(text)
{
    require('MeshAgent').log('Console bridge: ' + text);
}

// The running service's SCM key comes first: the native installer retains an incumbent key
// (for example 'Mesh Agent') across branding migrations, so the package .msh name can differ
// from the key that owns the installed ServiceDll. Without either name there is no ServiceDll to
// launch, so the bridge fails here instead of guessing a service.
function resolveServiceName()
{
    var reasons = [];
    var name = null;
    var msh = null;
    try { name = require('_agentNodeId').serviceName(); } catch (ex) { reasons.push('service name: ' + ex); }
    if (name != null && ('' + name).length > 0) { return ('' + name); }
    try { msh = _MSH(); } catch (ex2) { reasons.push('.msh: ' + ex2); }
    if (msh != null && msh.meshServiceName != null && ('' + msh.meshServiceName).length > 0) { return ('' + msh.meshServiceName); }
    throw new Error('Windows terminal bridge: the agent service identity is unavailable' + ((reasons.length > 0) ? (' (' + reasons.join('; ') + ')') : '') + '.');
}

function resolveInstalledServiceDllPath()
{
    return require('win-system-paths').installedServiceRuntimeDll(resolveServiceName());
}

function makePipeName(suffix)
{
    bridgeCounter++;
    return ('\\\\.\\pipe\\MeshConsoleBridge_' + process.pid + '_' + Date.now() + '_' + bridgeCounter + suffix);
}

function normalizeSize(value, fallback, minValue, maxValue)
{
    var parsed = parseInt(value);
    if (isNaN(parsed)) { parsed = fallback; }
    if (parsed < minValue) { parsed = minValue; }
    if (parsed > maxValue) { parsed = maxValue; }
    return (parsed);
}

function chunkToInputData(chunk)
{
    var data = null;
    var text = null;
    var textValue = null;
    if (chunk == null) { return ({ payload: '', length: 0 }); }
    if (typeof(chunk) == 'string')
    {
        data = Buffer.from(chunk, 'utf8');
        return ({ payload: data, length: data.length });
    }
    try { if (Buffer.isBuffer && Buffer.isBuffer(chunk)) { data = Buffer.from(chunk); return ({ payload: data, length: data.length }); } } catch (ex0) { }
    try { data = Buffer.from(chunk); } catch (ex1) { data = null; }
    if (data != null && data.length > 0) { return ({ payload: data, length: data.length }); }
    try { text = chunk.toString ? chunk.toString() : ('' + chunk); } catch (ex2) { text = null; }
    try { textValue = (text != null ? ('' + text) : null); } catch (ex3) { textValue = null; }
    if (textValue != null && textValue.length > 0 && textValue != '[object Object]')
    {
        data = Buffer.from(textValue, 'utf8');
        return ({ payload: data, length: data.length });
    }
    return ({ payload: (data != null ? data : ''), length: (data != null ? data.length : 0) });
}

function ConsoleBridgeTerminal(shellName, cols, rows, targetSessionId, mode, tokenMode)
{
    var self = this;
    var stream = null;

    this.shellName = shellName;
    this.mode = (mode == 'exec') ? 'exec' : 'pty';
    this.cols = normalizeSize(cols, 80, 20, 300);
    this.rows = normalizeSize(rows, 25, 10, 100);
    this.targetSessionId = ((typeof(targetSessionId) == 'number') && targetSessionId >= 0) ? parseInt(targetSessionId) : null;
    this.tokenMode = tokenMode || ((this.targetSessionId == null) ? 'privileged-agent' : 'session-user');
    if (this.tokenMode != 'privileged-agent' && this.tokenMode != 'session-user') { throw new Error('Invalid terminal token mode.'); }
    if (targetSessionId != null && (typeof(targetSessionId) != 'number' || !isFinite(targetSessionId) ||
        Math.floor(targetSessionId) != targetSessionId || targetSessionId < 0 || targetSessionId >= 0xFFFFFFFF))
    { throw new Error('Invalid terminal session ID.'); }
    if (this.tokenMode == 'privileged-agent' && this.targetSessionId != null)
    { throw new Error('Privileged-agent terminal cannot target a user session.'); }
    if (this.tokenMode == 'session-user' && (this.targetSessionId == null || this.targetSessionId == 0))
    { throw new Error('Session-user terminal requires an explicit interactive session.'); }
    this.inputPipeName = makePipeName('_in');
    this.outputPipeName = makePipeName('_out');
    this.inputServer = null;
    this.outputServer = null;
    this.inputSocket = null;
    this.outputSocket = null;
    this.child = null;
    this.closed = false;
    this.ended = false;
    this.startTimer = null;
    this.closeEmitted = false;
    this.pendingWrites = [];
    this.readyEmitted = false;
    this.readyBuffer = '';
    this.readyCallbacks = [];
    this.dataCallbacks = [];
    this.inputEnded = false;
    this.endInputWhenConnected = false;
    this.lastError = '';

    stream = new duplex({
        read: function read(size) {
        },
        write: function write(chunk, encoding, flush) {
            if (typeof(encoding) == 'function' && flush == null) { flush = encoding; }
            return (self.writeInput(chunk, flush));
        },
        final: function final(flush) {
            if (self.mode == 'exec') { self.closeInput(); }
            else { self.closeBridge(); }
            flush();
        }
    });
    // Duktape emitters only emit declared events.
    if (stream.createEvent) { stream.createEvent('ready'); }
    stream._bridge = this;
    stream.resizeTerminal = function resizeTerminal(w, h) {
        self.cols = normalizeSize(w, self.cols, 20, 300);
        self.rows = normalizeSize(h, self.rows, 10, 100);
    };
    stream.closeBridge = function closeBridge() {
        self.closeBridge();
    };
    stream.closeInput = function closeInput() {
        self.closeInput();
    };
    stream.writeBridgeInput = function writeBridgeInput(chunk, flush) {
        return (self.writeInput(chunk, flush));
    };
    stream.isBridgeClosed = function isBridgeClosed() {
        return (self.closed || self.ended);
    };
    stream.isBridgeReady = function isBridgeReady() {
        return (self.readyEmitted && self.closed == false && self.ended == false);
    };
    stream.onBridgeReady = function onBridgeReady(callback) {
        return (self.onReady(callback));
    };
    stream.onBridgeData = function onBridgeData(callback) {
        return (self.onData(callback));
    };
    // The error that ended the bridge, or '' while it has not failed.
    stream.lastError = function lastError() {
        return (self.lastError);
    };
    this.stream = stream;
    // Let the caller attach error/close listeners before registry or policy
    // validation can fail. Native pipe handles are still created before launch.
    setImmediate(function startBridge() {
        if (self.closed == false) { self.start(); }
    });
    return (stream);
}

ConsoleBridgeTerminal.prototype.clearStartTimer = function clearStartTimer()
{
    if (this.startTimer == null) { return; }
    clearTimeout(this.startTimer);
    this.startTimer = null;
};

ConsoleBridgeTerminal.prototype.emitCloseOnce = function emitCloseOnce()
{
    if (this.closeEmitted) { return; }
    this.closeEmitted = true;
    try { this.stream.emit('close'); } catch (ex) { logBridge('a close listener failed: ' + ex); }
};

// A caller callback or listener threw: the bridge cannot keep serving that caller, so it fails with
// the exception.
ConsoleBridgeTerminal.prototype.callbackFailed = function callbackFailed(error)
{
    if (this.ended) { logBridge('a callback failed after the bridge ended: ' + error); return; }
    this.fail(error);
};

ConsoleBridgeTerminal.prototype.emitReadyOnce = function emitReadyOnce()
{
    var callbacks = null;
    var i = 0;
    if (this.readyEmitted) { return; }
    this.readyEmitted = true;
    this.clearStartTimer();
    this.flushPendingWrites();
    callbacks = this.readyCallbacks;
    this.readyCallbacks = [];
    for (i = 0; i < callbacks.length; ++i)
    {
        try { callbacks[i](); } catch (callbackEx) { this.callbackFailed(callbackEx); return; }
    }
    try { this.stream.emit('ready'); } catch (ex) { this.callbackFailed(ex); }
};

// Runs the callback once the bridge is ready: now when it already is (an exception reaches the
// caller), otherwise at the ready handshake.
ConsoleBridgeTerminal.prototype.onReady = function onReady(callback)
{
    if (typeof(callback) != 'function') { return (false); }
    if (this.readyEmitted && this.closed == false && this.ended == false)
    {
        callback();
        return (true);
    }
    this.readyCallbacks.push(callback);
    return (false);
};

ConsoleBridgeTerminal.prototype.onData = function onData(callback)
{
    if (typeof(callback) != 'function') { return (false); }
    this.dataCallbacks.push(callback);
    return (true);
};

ConsoleBridgeTerminal.prototype.fail = function fail(error)
{
    if (this.ended) { return; }
    this.ended = true;
    this.lastError = String(error);
    this.clearStartTimer();
    try { this.stream.emit('error', error); } catch (ex) { logBridge('error not handled by a listener: ' + this.lastError + ((ex !== error) ? (' (the listener failed: ' + ex + ')') : '')); }
    try { this.stream.push(null); } catch (ex2) { logBridge('could not end the output stream: ' + ex2); }
    this.closeBridge();
    this.emitCloseOnce();
};

ConsoleBridgeTerminal.prototype.finish = function finish()
{
    if (this.ended) { return; }
    this.ended = true;
    this.clearStartTimer();
    try { this.stream.push(null); } catch (ex) { logBridge('could not end the output stream: ' + ex); }
    this.closeBridge();
    this.emitCloseOnce();
};

ConsoleBridgeTerminal.prototype.flushPendingWrites = function flushPendingWrites()
{
    var item = null;
    if (this.readyEmitted == false) { return; }
    while (this.pendingWrites.length > 0 && this.inputSocket != null && this.closed == false)
    {
        item = this.pendingWrites.shift();
        this.writeInput(item.chunk, item.flush);
    }
    if (this.endInputWhenConnected) { this.closeInput(); }
};

ConsoleBridgeTerminal.prototype.closeInput = function closeInput()
{
    this.endInputWhenConnected = true;
    if (this.inputEnded) { return; }
    if (this.readyEmitted == false) { return; }
    if (this.inputSocket == null) { return; }
    this.inputEnded = true;
    this.endInputWhenConnected = false;
    try { this.inputSocket.end(); } catch (ex) { this.fail(ex); }
};

ConsoleBridgeTerminal.prototype.writeInput = function writeInput(chunk, flush)
{
    var input = chunkToInputData(chunk);
    var fallbackText = null;
    var flushCalled = false;
    function completeFlush()
    {
        if (flushCalled) { return; }
        flushCalled = true;
        if (flush) { flush(); }
    }
    if (typeof(flush) != 'function') { flush = null; }
    if (input.length == 0 && chunk != null && chunk.toString)
    {
        try { fallbackText = '' + chunk.toString(); } catch (ex3) { fallbackText = null; }
        if (fallbackText != null && fallbackText.length > 0 && fallbackText != '[object Object]') { input = chunkToInputData(fallbackText); }
    }
    if (this.closed || this.inputEnded)
    {
        completeFlush();
        return (true);
    }
    if (this.readyEmitted == false || this.inputSocket == null)
    {
        this.pendingWrites.push({ chunk: input.payload, flush: flush });
        return (false);
    }
    try
    {
        if (flush) { this.inputSocket.write(input.payload, completeFlush); }
        else { this.inputSocket.write(input.payload); }
    }
    catch (ex)
    {
        this.fail(ex);
        completeFlush();
        return (true);
    }
    if (!flush) { completeFlush(); }
    return (true);
};

ConsoleBridgeTerminal.prototype.pushOutputChunk = function pushOutputChunk(chunk)
{
    var i = 0;
    for (i = 0; i < this.dataCallbacks.length; ++i)
    {
        try { this.dataCallbacks[i](chunk); } catch (callbackEx) { this.callbackFailed(callbackEx); return; }
    }
    try { this.stream.push(chunk); } catch (ex) { this.fail(ex); }
};

ConsoleBridgeTerminal.prototype.processOutputChunk = function processOutputChunk(chunk)
{
    var markerIndex = -1;
    var outputText = '';
    if (this.readyEmitted)
    {
        this.pushOutputChunk(chunk);
        return;
    }
    this.readyBuffer += chunk.toString();
    markerIndex = this.readyBuffer.indexOf(BRIDGE_READY_MARKER);
    if (markerIndex < 0) { return; }
    outputText = this.readyBuffer.substring(0, markerIndex) + this.readyBuffer.substring(markerIndex + BRIDGE_READY_MARKER.length);
    this.readyBuffer = '';
    this.emitReadyOnce();
    if (outputText.length > 0 && this.ended == false) { this.pushOutputChunk(Buffer.from(outputText, 'utf8')); }
};

ConsoleBridgeTerminal.prototype.launchBridge = function launchBridge()
{
    var runtimeHostPath = require('win-system-paths').system32Path('rundll32.exe');
    var serviceDllPath = resolveInstalledServiceDllPath();
    var args = [serviceDllPath + ',MeshConsoleBridgeW', this.inputPipeName, this.outputPipeName, this.shellName, '' + this.cols, '' + this.rows];
    var self = this;
    if (this.child != null || this.closed || this.ended) { return; }
    args.push('token=' + this.tokenMode);
    if (this.targetSessionId != null) { args.push('tsid=' + this.targetSessionId); }
    if (this.mode == 'exec') { args.push('mode=exec'); }
    this.child = childProcess.execFile(runtimeHostPath, args);
    if (this.child == null) {
        this.fail(new Error('Windows terminal bridge launch was denied by process policy.'));
        return;
    }
    this.child.on('exit', function onExit() {
        self.child = null;
        if (self.readyEmitted == false && self.closed == false && self.ended == false)
        {
            self.fail(new Error('Windows terminal bridge exited before ready handshake through MeshConsoleBridgeW.'));
            return;
        }
        if (self.mode == 'exec' && self.outputSocket != null)
        {
            return;
        }
        self.finish();
    });
    this.child.on('error', function onError(error) {
        self.child = null;
        self.fail(error);
    });
};

ConsoleBridgeTerminal.prototype.start = function start()
{
    var self = this;
    this.startTimer = setTimeout(function onBridgeConnectTimeout() {
        self.startTimer = null;
        self.fail(new Error('Windows terminal bridge did not become ready within ' + BRIDGE_CONNECT_TIMEOUT_MS + ' ms.'));
    }, BRIDGE_CONNECT_TIMEOUT_MS);
    this.inputServer = net.createServer(function onInputConnection(socket) {
        self.inputSocket = socket;
        socket.on('error', function onInputError(error) { self.fail(error); });
        socket.on('close', function onInputClose() {
            self.inputSocket = null;
            self.inputEnded = true;
            self.endInputWhenConnected = false;
        });
        self.flushPendingWrites();
    });
    this.outputServer = net.createServer(function onOutputConnection(socket) {
        self.outputSocket = socket;
        socket.on('data', function onOutputData(chunk) {
            self.processOutputChunk(chunk);
        });
        socket.on('error', function onOutputError(error) { self.fail(error); });
        socket.on('close', function onOutputClose() {
            if (self.readyEmitted == false && self.closed == false)
            {
                self.fail(new Error('Windows terminal bridge output closed before ready handshake through MeshConsoleBridgeW.'));
                return;
            }
            self.finish();
        });
    });
    this.inputServer.on('error', function onServerError(error) { self.fail(error); });
    this.outputServer.on('error', function onServerError(error) { self.fail(error); });
    this.inputServer.listen(this.inputPipeName);
    this.outputServer.listen(this.outputPipeName);
    try { self.launchBridge(); } catch (ex) { self.fail(ex); }
};

ConsoleBridgeTerminal.prototype.closeBridge = function closeBridge()
{
    var child = null;
    var item = null;
    if (this.closed) { return; }
    this.closed = true;
    this.clearStartTimer();
    try { if (this.inputSocket != null) { this.inputSocket.end(); } } catch (ex) { logBridge('could not close the input pipe: ' + ex); }
    try { if (this.outputSocket != null) { this.outputSocket.end(); } } catch (ex2) { logBridge('could not close the output pipe: ' + ex2); }
    try { if (this.inputServer != null) { this.inputServer.close(); } } catch (ex3) { logBridge('could not close the input pipe server: ' + ex3); }
    try { if (this.outputServer != null) { this.outputServer.close(); } } catch (ex4) { logBridge('could not close the output pipe server: ' + ex4); }
    child = this.child;
    if (child != null)
    {
        if (this.lastError.length > 0)
        {
            logBridge('stopping bridge pid ' + child.pid + ' (' + this.shellName + ', ' + this.mode + ', ' + this.tokenMode + ') after: ' + this.lastError);
        }
        try { child.kill(); } catch (ex5) { logBridge('could not stop bridge pid ' + child.pid + ': ' + ex5); }
    }
    while (this.pendingWrites.length > 0)
    {
        item = this.pendingWrites.shift();
        try { if (item.flush) { item.flush(); } } catch (ex6) { logBridge('a pending write callback failed: ' + ex6); }
    }
    this.emitCloseOnce();
};

function windowsTerminal()
{
    this._ObjectID = 'windows_terminal';
    this.supported = (process.platform == 'win32');
}

windowsTerminal.prototype.PowerShellCapable = function PowerShellCapable()
{
    return (process.platform == 'win32');
};

windowsTerminal.prototype.Start = function Start(cols, rows, targetSessionId)
{
    if (process.platform != 'win32') { throw new Error('Windows terminal bridge is only available on Windows.'); }
    return (new ConsoleBridgeTerminal(SHELL_COMMAND, cols, rows, targetSessionId));
};

windowsTerminal.prototype.StartPowerShell = function StartPowerShell(cols, rows, targetSessionId)
{
    if (process.platform != 'win32') { throw new Error('Windows terminal bridge is only available on Windows.'); }
    return (new ConsoleBridgeTerminal(SHELL_AUTOMATION, cols, rows, targetSessionId));
};

// Picks the session a user terminal (tunnel protocols 8 and 9) runs in. The viewer's choice
// (requestedSessionId, from the tunnel's tsid option) must be an active user session. Without one,
// the console session is used when a user is active there, then the only active user session.
// Anything else is ambiguous or empty, and the terminal is refused.
windowsTerminal.prototype.SelectUserSession = function SelectUserSession(requestedSessionId)
{
    var sessions = require('user-sessions');
    var active = sessions.Current().Active;
    var ids = [];
    var consoleId = null;
    var consoleError = null;
    var i = 0;
    for (i = 0; i < active.length; ++i) { ids.push(parseInt(active[i].SessionId)); }
    if (requestedSessionId != null)
    {
        if (ids.indexOf(requestedSessionId) < 0) { throw new Error('the selected session ' + requestedSessionId + ' has no active user'); }
        return (requestedSessionId);
    }
    try { consoleId = sessions.consoleUid(); } catch (ex) { consoleError = ex; }
    if (consoleId != null && ids.indexOf(consoleId) >= 0) { return (consoleId); }
    if (ids.length == 1) { return (ids[0]); }
    if (ids.length == 0) { throw new Error('no active user session found'); }
    throw new Error('several user sessions are active and none was selected (console: ' + ((consoleError != null) ? consoleError : ('session ' + consoleId + ' has no active user')) + ')');
};

// Runs one run-commands script through MeshConsoleBridgeW in exec mode, in PowerShell. The script is
// written to the shell's standard input once the bridge is ready, and input then closes, so the shell
// exits at the end of the script.
//   options.targetSessionId: a user session ID to run with that session's user token, or null to run
//     with the agent's own privileged token.
//   options.timeoutMs: required time limit for the whole run, in milliseconds.
//   options.onOutput(text): optional; receives the output as it arrives.
// callback({ ok, output, error, timedOut }) runs exactly once. ok is false when the bridge failed,
// closed before the script was sent, or reached the time limit (then timedOut is true); error is the
// reason, or null. Returns the bridge stream; closeBridge() on it stops the run.
windowsTerminal.prototype.RunCommand = function RunCommand(script, options, callback)
{
    var stream = null;
    var bridge = null;
    var output = '';
    var scriptSent = false;
    var completed = false;
    var timer = null;
    if (process.platform != 'win32') { throw new Error('Windows run commands are only available on Windows.'); }
    if (typeof(callback) != 'function') { throw new Error('RunCommand requires a completion callback.'); }
    if (options == null || typeof(options.timeoutMs) != 'number' || !(options.timeoutMs > 0)) { throw new Error('RunCommand requires a positive time limit.'); }
    stream = new ConsoleBridgeTerminal(SHELL_AUTOMATION, 80, 25, options.targetSessionId, 'exec');
    bridge = stream._bridge;
    function complete(error, timedOut)
    {
        if (completed) { return; }
        completed = true;
        if (timer != null) { clearTimeout(timer); timer = null; }
        callback({ ok: (error == null), output: output, error: (error == null) ? null : ((error.message != null) ? error.message : String(error)), timedOut: (timedOut === true) });
    }
    bridge.onData(function onRunCommandOutput(chunk) {
        var text = chunk.toString();
        output += text;
        if (options.onOutput) { options.onOutput(text); }
    });
    bridge.onReady(function onRunCommandReady() {
        scriptSent = true;
        bridge.writeInput(script + '\r\n', function onScriptWritten() { bridge.closeInput(); });
    });
    stream.on('error', function onRunCommandError(error) { complete(error); });
    stream.on('close', function onRunCommandClose() {
        if (scriptSent) { complete(null); }
        else { complete(new Error('the bridge closed before the script was sent')); }
    });
    timer = setTimeout(function onRunCommandTimeout() {
        timer = null;
        complete(new Error('no result within ' + Math.round(options.timeoutMs / 1000) + ' s'), true);
        bridge.closeBridge();
    }, options.timeoutMs);
    return (stream);
};

module.exports = new windowsTerminal();
