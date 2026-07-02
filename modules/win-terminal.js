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

function expandEnvironmentStrings(value)
{
    return (('' + value).replace(/%([^%]+)%/g, function replaceEnv(match, name) {
        var replacement = process.env[name];
        return (replacement == null ? match : replacement);
    }));
}

function resolveServiceName()
{
    var msh = null;
    var name = null;
    try { msh = _MSH(); } catch (ex) { }
    if (msh != null && msh.meshServiceName != null && ('' + msh.meshServiceName).length > 0) { name = '' + msh.meshServiceName; }
    if (name == null || name.length == 0) {
        try { name = '' + require('_agentNodeId').serviceName(); } catch (ex2) { }
    }
    if (name == null || name.length == 0) { name = 'meshagent'; }
    return (name);
}

function resolveInstalledServiceDllPath()
{
    var registry = require('win-registry');
    var serviceName = resolveServiceName();
    var raw = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + serviceName + '\\Parameters', 'ServiceDll');
    var resolved = null;
    if (raw != null) { resolved = expandEnvironmentStrings(raw.toString()); }
    if (resolved == null || resolved.length == 0 || !/\.dll$/i.test(resolved)) {
        throw new Error('Windows terminal bridge requires the installed service ServiceDll.');
    }
    return (resolved);
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

function ConsoleBridgeTerminal(shellName, cols, rows, targetSessionId, mode)
{
    var self = this;
    var stream = null;

    this.shellName = shellName;
    this.mode = (mode == 'exec') ? 'exec' : 'pty';
    this.cols = normalizeSize(cols, 80, 20, 300);
    this.rows = normalizeSize(rows, 25, 10, 100);
    this.targetSessionId = ((typeof(targetSessionId) == 'number') && targetSessionId >= 0) ? parseInt(targetSessionId) : null;
    this.inputPipeName = makePipeName('_in');
    this.outputPipeName = makePipeName('_out');
    this.inputServer = null;
    this.outputServer = null;
    this.inputSocket = null;
    this.outputSocket = null;
    this.child = null;
    this.closed = false;
    this.ended = false;
    this.inputConnected = false;
    this.outputConnected = false;
    this.startTimer = null;
    this.closeEmitted = false;
    this.pendingWrites = [];
    this.bridgeLaunched = false;
    this.bridgeLaunchAttempts = 0;
    this.readyEmitted = false;
    this.readyBuffer = '';
    this.readyCallbacks = [];
    this.dataCallbacks = [];
    this.inputEnded = false;
    this.endInputWhenConnected = false;

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
    try { if (stream.createEvent) { stream.createEvent('ready'); } } catch (ex) { }
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
    stream._meshTerminalClosed = false;
    stream._meshTerminalReady = false;
    stream._meshTerminalStarted = Date.now();
    stream._meshTerminalBridgeLaunched = false;
    stream._meshTerminalLaunchAttempts = 0;
    stream._meshTerminalReadyMarkerProtocol = true;
    stream._meshTerminalPipesConnected = false;
    stream._meshTerminalInputConnected = false;
    stream._meshTerminalOutputConnected = false;
    stream._meshTerminalChildPid = 0;
    stream._meshTerminalBridgeExited = false;
    stream._meshTerminalLastError = '';
    stream._meshTerminalMode = this.mode;
    stream._meshTerminalWriteCount = 0;
    stream._meshTerminalLastWriteBytes = 0;
    stream._meshTerminalLastChunkType = '';
    stream._meshTerminalLastChunkLength = -1;
    stream._meshTerminalLastChunkTextLength = -1;
    stream._meshTerminalOutputChunks = 0;
    stream._meshTerminalOutputBytes = 0;
    stream._meshTerminalHandshakeBytes = 0;
    this.stream = stream;
    this.start();
    return (stream);
}

ConsoleBridgeTerminal.prototype.clearStartTimer = function clearStartTimer()
{
    if (this.startTimer == null) { return; }
    try { clearTimeout(this.startTimer); } catch (ex) { }
    this.startTimer = null;
};

ConsoleBridgeTerminal.prototype.emitCloseOnce = function emitCloseOnce()
{
    if (this.closeEmitted) { return; }
    this.closeEmitted = true;
    try { this.stream.emit('close'); } catch (ex) { }
};

ConsoleBridgeTerminal.prototype.checkBridgeConnected = function checkBridgeConnected()
{
    if (this.inputConnected && this.outputConnected)
    {
        this.stream._meshTerminalPipesConnected = true;
    }
};

ConsoleBridgeTerminal.prototype.emitReadyOnce = function emitReadyOnce()
{
    var callbacks = null;
    var i = 0;
    if (this.readyEmitted) { return; }
    this.readyEmitted = true;
    this.stream._meshTerminalReady = true;
    this.clearStartTimer();
    this.flushPendingWrites();
    callbacks = this.readyCallbacks;
    this.readyCallbacks = [];
    for (i = 0; i < callbacks.length; ++i)
    {
        try { callbacks[i](); } catch (callbackEx) { }
    }
    try { this.stream.emit('ready'); } catch (ex) { }
};

ConsoleBridgeTerminal.prototype.onReady = function onReady(callback)
{
    if (typeof(callback) != 'function') { return (false); }
    if (this.readyEmitted && this.closed == false && this.ended == false)
    {
        try { callback(); } catch (ex) { }
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
    this.stream._meshTerminalClosed = true;
    try { this.stream._meshTerminalLastError = error.toString(); } catch (ex0) { }
    this.clearStartTimer();
    try { this.stream.emit('error', error); } catch (ex) { }
    try { this.stream.push(null); } catch (ex2) { }
    this.closeBridge();
    this.emitCloseOnce();
};

ConsoleBridgeTerminal.prototype.finish = function finish()
{
    if (this.ended) { return; }
    this.ended = true;
    this.stream._meshTerminalClosed = true;
    this.clearStartTimer();
    try { this.stream.push(null); } catch (ex) { }
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
    try { this.stream._meshTerminalLastChunkType = typeof(chunk); } catch (ex0) { }
    try { this.stream._meshTerminalLastChunkLength = (chunk != null && chunk.length != null) ? chunk.length : -1; } catch (ex1) { this.stream._meshTerminalLastChunkLength = -1; }
    try { this.stream._meshTerminalLastChunkTextLength = (chunk != null && chunk.toString) ? chunk.toString().length : -1; } catch (ex2) { this.stream._meshTerminalLastChunkTextLength = -1; }
    if (input.length == 0 && this.stream._meshTerminalLastChunkTextLength > 0)
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
        this.stream._meshTerminalWriteCount++;
        this.stream._meshTerminalLastWriteBytes = input.length;
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
    this.stream._meshTerminalOutputChunks++;
    this.stream._meshTerminalOutputBytes += chunk.length;
    for (i = 0; i < this.dataCallbacks.length; ++i)
    {
        try { this.dataCallbacks[i](chunk); } catch (callbackEx) { }
    }
    try { this.stream.push(chunk); } catch (ex) { this.fail(ex); }
};

ConsoleBridgeTerminal.prototype.processOutputChunk = function processOutputChunk(chunk)
{
    var text = '';
    var markerIndex = -1;
    var outputText = '';
    if (this.readyEmitted)
    {
        this.pushOutputChunk(chunk);
        return;
    }
    try { text = chunk.toString(); } catch (ex) { text = ''; }
    this.readyBuffer += text;
    this.stream._meshTerminalHandshakeBytes = this.readyBuffer.length;
    markerIndex = this.readyBuffer.indexOf(BRIDGE_READY_MARKER);
    if (markerIndex < 0) { return; }
    outputText = this.readyBuffer.substring(0, markerIndex) + this.readyBuffer.substring(markerIndex + BRIDGE_READY_MARKER.length);
    this.readyBuffer = '';
    this.stream._meshTerminalHandshakeBytes = 0;
    this.emitReadyOnce();
    if (outputText.length > 0) { this.pushOutputChunk(Buffer.from(outputText, 'utf8')); }
};

ConsoleBridgeTerminal.prototype.launchBridge = function launchBridge()
{
    var rundll32Path = require('win-system-paths').system32Path('rundll32.exe');
    var serviceDllPath = resolveInstalledServiceDllPath();
    var args = [serviceDllPath + ',MeshConsoleBridgeW', this.inputPipeName, this.outputPipeName, this.shellName, '' + this.cols, '' + this.rows];
    var self = this;
    if (this.child != null || this.closed || this.ended) { return; }
    this.bridgeLaunched = true;
    this.bridgeLaunchAttempts++;
    this.stream._meshTerminalBridgeLaunched = true;
    this.stream._meshTerminalLaunchAttempts = this.bridgeLaunchAttempts;
    this.stream._meshTerminalChildPid = 0;
    if (this.targetSessionId != null) { args.push('tsid=' + this.targetSessionId); }
    if (this.mode == 'exec') { args.push('mode=exec'); }
    this.child = childProcess.execFile(rundll32Path, args);
    if (this.child == null) {
        this.fail(new Error('Windows terminal bridge launch was denied by process policy.'));
        return;
    }
    try { this.stream._meshTerminalChildPid = this.child.pid ? this.child.pid : 0; } catch (ex) { }
    this.child.on('exit', function onExit() {
        self.child = null;
        self.stream._meshTerminalChildPid = 0;
        self.stream._meshTerminalBridgeExited = true;
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
        self.stream._meshTerminalChildPid = 0;
        self.fail(error);
    });
};

ConsoleBridgeTerminal.prototype.start = function start()
{
    var self = this;
    this.startTimer = setTimeout(function onBridgeConnectTimeout() {
        self.fail(new Error('Windows terminal bridge did not become ready within ' + BRIDGE_CONNECT_TIMEOUT_MS + ' ms.'));
    }, BRIDGE_CONNECT_TIMEOUT_MS);
    this.inputServer = net.createServer(function onInputConnection(socket) {
        self.inputConnected = true;
        self.stream._meshTerminalInputConnected = true;
        self.inputSocket = socket;
        socket.on('error', function onInputError(error) { self.fail(error); });
        socket.on('close', function onInputClose() {
            self.inputSocket = null;
            if (self.mode != 'exec') { self.finish(); }
        });
        self.checkBridgeConnected();
        self.flushPendingWrites();
    });
    this.outputServer = net.createServer(function onOutputConnection(socket) {
        self.outputConnected = true;
        self.stream._meshTerminalOutputConnected = true;
        self.outputSocket = socket;
        socket.on('data', function onOutputData(chunk) {
            self.processOutputChunk(chunk);
        });
        socket.on('error', function onOutputError(error) { self.fail(error); });
        socket.on('close', function onOutputClose() { self.finish(); });
        self.checkBridgeConnected();
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
    if (this.closed) { return; }
    this.closed = true;
    this.stream._meshTerminalClosed = true;
    this.clearStartTimer();
    try { if (this.inputSocket != null) { this.inputSocket.end(); } } catch (ex) { }
    try { if (this.outputSocket != null) { this.outputSocket.end(); } } catch (ex2) { }
    try { if (this.inputServer != null) { this.inputServer.close(); } } catch (ex3) { }
    try { if (this.outputServer != null) { this.outputServer.close(); } } catch (ex4) { }
    child = this.child;
    if (child != null)
    {
        try { child.kill(); } catch (ex5) { }
    }
    while (this.pendingWrites.length > 0)
    {
        var item = this.pendingWrites.shift();
        try { if (item.flush) { item.flush(); } } catch (ex6) { }
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

windowsTerminal.prototype.ResolveOfficialConsoleTarget = function ResolveOfficialConsoleTarget(target)
{
    return (target);
};

windowsTerminal.prototype.Start = function Start(cols, rows, targetSessionId)
{
    if (process.platform != 'win32') { throw new Error('Windows terminal bridge is only available on Windows.'); }
    return (new ConsoleBridgeTerminal(SHELL_COMMAND, cols, rows, targetSessionId));
};

windowsTerminal.prototype.StartAsUser = function StartAsUser(cols, rows, targetSessionId)
{
    return (this.Start(cols, rows, targetSessionId));
};

windowsTerminal.prototype.StartEx = function StartEx(cols, rows, target)
{
    var selected = SHELL_COMMAND;
    if (target != null && ('' + target).toLowerCase().indexOf(SHELL_AUTOMATION) >= 0) { selected = SHELL_AUTOMATION; }
    if (process.platform != 'win32') { throw new Error('Windows terminal bridge is only available on Windows.'); }
    return (new ConsoleBridgeTerminal(selected, cols, rows, null));
};

windowsTerminal.prototype.StartPowerShell = function StartPowerShell(cols, rows, targetSessionId)
{
    if (process.platform != 'win32') { throw new Error('Windows terminal bridge is only available on Windows.'); }
    return (new ConsoleBridgeTerminal(SHELL_AUTOMATION, cols, rows, targetSessionId));
};

windowsTerminal.prototype.StartPowerShellAsUser = function StartPowerShellAsUser(cols, rows, targetSessionId)
{
    return (this.StartPowerShell(cols, rows, targetSessionId));
};

windowsTerminal.prototype.RunPowerShellCommand = function RunPowerShellCommand(cols, rows, targetSessionId)
{
    if (process.platform != 'win32') { throw new Error('Windows run commands are only available on Windows.'); }
    return (new ConsoleBridgeTerminal(SHELL_AUTOMATION, cols, rows, targetSessionId, 'exec'));
};

windowsTerminal.prototype.RunPowerShellCommandAsUser = function RunPowerShellCommandAsUser(cols, rows, targetSessionId)
{
    return (this.RunPowerShellCommand(cols, rows, targetSessionId));
};

module.exports = new windowsTerminal();
