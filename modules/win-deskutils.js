/*
Copyright 2022 Intel Corporation
@author Bryan Roe

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

//
// win-deskutils is a utility module that exposes various desktop related features for Windows
// such as MouseTrails Accessability and Windows Desktop Background
//

//
// MSDN documention for the system call this module relies on can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa
//

var SPI_GETDESKWALLPAPER = 0x0073;
var SPI_SETDESKWALLPAPER = 0x0014;
var SPI_GETMOUSETRAILS = 0x005E;
var SPI_SETMOUSETRAILS = 0x005D;
var WTSIdleTime = 17;

var GM = require('_GenericMarshal');
var promise = require('promise');
var kernel32 = GM.CreateNativeProxy('kernel32.dll');
var user32 = GM.CreateNativeProxy('user32.dll');
var wtsapi32 = null;
kernel32.CreateMethod('GetTickCount');
kernel32.CreateMethod('GetLastError');
user32.CreateMethod('SystemParametersInfoA');
user32.CreateMethod('GetLastInputInfo');
try
{
    wtsapi32 = GM.CreateNativeProxy('Wtsapi32.dll');
    wtsapi32.CreateMethod('WTSQuerySessionInformationW');
    wtsapi32.CreateMethod('WTSFreeMemory');
}
catch (ex)
{
}

//
// This function is a helper method to dispatch method calls to different user sessions
//
function sessionDispatch(tsid, parent, method, args)
{
    throw ('Windows desktop utility session dispatch is disabled until an approved rundll32 contract export exists.');
}

function resolvedPromise(value)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    ret._res(value);
    return (ret);
}

//
// This function returns the caller's current-session idle time, in seconds.
// It is used only as a local fallback when service-safe WTS metadata is not
// available for the requested session.
//
function idle_getCurrentSessionSeconds()
{
    var lastInputInfo = GM.CreateVariable(8);
    lastInputInfo.toBuffer().writeUInt32LE(8, 0);
    if (user32.GetLastInputInfo(lastInputInfo).Val == 0)
    {
        throw ('Error calling GetLastInputInfo: ' + kernel32.GetLastError().Val);
    }

    var now = kernel32.GetTickCount().Val >>> 0;
    var then = lastInputInfo.toBuffer().readUInt32LE(4);
    var elapsed = now >= then ? (now - then) : ((0x100000000 - then) + now);
    return (Math.floor(elapsed / 1000));
}

function idle_getWtsSessionSeconds(tsid)
{
    if (wtsapi32 == null || tsid == null) { return (null); }

    var buffer = GM.CreatePointer();
    var bytesReturned = GM.CreateVariable(4);
    if (wtsapi32.WTSQuerySessionInformationW(0, tsid, WTSIdleTime, buffer, bytesReturned).Val == 0)
    {
        return (null);
    }

    try
    {
        var bytes = bytesReturned.toBuffer().readUInt32LE(0);
        if (bytes < 4) { return (null); }
        var data = buffer.Deref().Deref(0, bytes).toBuffer();
        var seconds = data.readUInt32LE(0);
        return (isNaN(seconds) ? null : seconds);
    }
    finally
    {
        wtsapi32.WTSFreeMemory(buffer.Deref());
    }
}

//
// This function returns the current or requested session idle time, in seconds.
// WTS idle metadata is service-safe and avoids spawning a child process into
// every interactive session just to collect optional status telemetry.
//
function idle_getSeconds(tsid)
{
    if (tsid === null)
    {
        try { tsid = require('user-sessions').consoleUid(); } catch (ex) { return (idle_getCurrentSessionSeconds()); }
    }

    if (tsid != null)
    {
        var wtsSeconds = idle_getWtsSessionSeconds(tsid);
        if (wtsSeconds != null) { return (wtsSeconds); }

        try
        {
            if (require('user-sessions').getProcessOwnerName(process.pid).tsid == tsid)
            {
                return (idle_getCurrentSessionSeconds());
            }
        }
        catch (ex)
        {
        }
        throw ('Idle time unavailable for session ' + tsid);
    }

    return (idle_getCurrentSessionSeconds());
}

//
// This function returns the least idle active Windows session. This preserves the
// device-level "active if any user is active" semantics expected by MeshCentral.
//
function idle_getSecondsAllSessions()
{
    var sessions;
    var seconds = -1;

    try
    {
        sessions = require('user-sessions').Current().Active;
    }
    catch (ex)
    {
        try { seconds = idle_getCurrentSessionSeconds(); } catch (ex2) { seconds = -1; }
        return (resolvedPromise(seconds));
    }

    for (var i = 0; i < sessions.length; ++i)
    {
        if (sessions[i] == null || sessions[i].SessionId == null) { continue; }
        var sessionSeconds;
        try { sessionSeconds = idle_getSeconds(sessions[i].SessionId); } catch (ex3) { continue; }
        if (seconds < 0 || sessionSeconds < seconds) { seconds = sessionSeconds; }
    }

    if (seconds < 0) { try { seconds = idle_getCurrentSessionSeconds(); } catch (ex4) { } }
    return (resolvedPromise(seconds));
}

//
// This function gets the path of the windows desktop background of the specified user desktop session
//
function background_get(tsid)
{
    if (tsid != null || tsid === null) // TSID is not undefined or is explicitly null
    {
        // Need to disatch to different session first
        return (sessionDispatch(tsid, 'background', 'get', []));
    }
    var v = GM.CreateVariable(1024);
    var ret = user32.SystemParametersInfoA(SPI_GETDESKWALLPAPER, v._size, v, 0);
    if (ret.Val == 0)
    {
        throw ('Error occured trying to fetch wallpaper');
    }
    return (v.String);
}

//
// This function sets the path for the windows desktop background of the specified user desktop session
//
function background_set(path, tsid)
{
    if (tsid != null || tsid === null) // TSID is not undefined or is explicitly null
    {
        // Need to disatch to different session first
        return (sessionDispatch(tsid, 'background', 'set', [path]));
    }
    var nb = GM.CreateVariable(path);
    var ret = user32.SystemParametersInfoA(SPI_SETDESKWALLPAPER, nb._size, nb, 0);
    if (ret.Val == 0)
    {
        throw ('Error occured trying to set wallpaper');
    }
    return;
}

//
// This is a helper function that is called by the child process from sessionDispatch()
//
function dispatch(parent, method, args)
{
    try
    {
        return (this[parent][method].apply(this, args));
    }
    catch (e)
    {
        console.log('ERROR: ' + e);
        throw ('Error occured trying to dispatch: ' + method);
    }
}

//
// This function sets the mousetrail accessibility feature, for the specified user desktop session.
// Setting value 0 or one disables this feature
// Otherwise, value is the number of cursors to render for this feature
//
function mousetrails_set(value, tsid)
{
    if (tsid != null || tsid === null) // TSID is not undefined or is explicitly null
    {
        // Need to disatch to different session first
        return (sessionDispatch(tsid, 'mouse', 'setTrails', [value]));
    }
    var ret = user32.SystemParametersInfoA(SPI_SETMOUSETRAILS, value, 0, 0);
    if (ret.Val == 0)
    {
        throw ('Error occured trying to fetch wallpaper');
    }
}

//
// This function returns the number of cursors the mousetrail accessibility feature will render
// A value of 0 or 1 means the feature is disabled, otherwise it is the number of cursors that will be rendered
//
function mousetrails_get(tsid)
{
    if (tsid != null || tsid === null) // TSID is not undefined or is explicitly null
    {
        // Need to disatch to different session first
        return (sessionDispatch(tsid, 'mouse', 'getTrails', []));
    }
    var v = GM.CreateVariable(4);
    var ret = user32.SystemParametersInfoA(SPI_GETMOUSETRAILS, v._size, v, 0);
    if (ret.Val == 0)
    {
        throw ('Error occured trying to fetch wallpaper');
    }
    return (v.toBuffer().readUInt32LE());
}

module.exports = { background: { get: background_get, set: background_set } };
module.exports.mouse = { getTrails: mousetrails_get, setTrails: mousetrails_set };
module.exports.idle = { getSeconds: idle_getSeconds, getSecondsAllSessions: idle_getSecondsAllSessions };
module.exports.dispatch = dispatch;
