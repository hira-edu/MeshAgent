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

var nativeState = null;

function nativeKernel32()
{
    if (process.platform != 'win32')
    {
        throw new Error('Windows system paths are only available on Windows.');
    }
    if (nativeState == null)
    {
        var marshal = require('_GenericMarshal');
        var kernel32 = marshal.CreateNativeProxy('kernel32.dll');
        var shell32 = marshal.CreateNativeProxy('shell32.dll');
        var ole32 = marshal.CreateNativeProxy('ole32.dll');
        kernel32.CreateMethod('GetSystemDirectoryW');
        shell32.CreateMethod('SHGetKnownFolderPath');
        ole32.CreateMethod('CLSIDFromString');
        ole32.CreateMethod('CoTaskMemFree');
        nativeState = { marshal: marshal, kernel32: kernel32, shell32: shell32, ole32: ole32 };
    }
    return nativeState;
}

function guidFromString(state, value)
{
    var text = state.marshal.CreateVariable(value, { wide: true });
    var guid = state.marshal.CreateVariable(16);
    if (state.ole32.CLSIDFromString(text, guid).Val != 0)
    {
        throw new Error('CLSIDFromString failed for known folder id.');
    }
    return guid;
}

function systemDirectory()
{
    var state = nativeKernel32();
    var bufferCch = 32768;
    var buffer = state.marshal.CreateVariable(bufferCch * 2);
    var len = state.kernel32.GetSystemDirectoryW(buffer, bufferCch).Val;
    if (len == 0 || len >= bufferCch)
    {
        throw new Error('GetSystemDirectoryW failed or returned a truncated path.');
    }
    return (buffer.Wide2UTF8.replace(/[\\\/]+$/, ''));
}

function system32Path(relativePath)
{
    if (relativePath == null || relativePath == '')
    {
        throw new Error('A relative system path is required.');
    }
    if (/[\\\/]/.test(relativePath))
    {
        throw new Error('system32Path only accepts a single relative file name.');
    }
    return (systemDirectory() + '\\' + relativePath);
}

function knownFolderPath(folderId)
{
    var state = nativeKernel32();
    var folderGuid = guidFromString(state, folderId);
    var pathPointer = state.marshal.CreatePointer();
    var hr = state.shell32.SHGetKnownFolderPath(folderGuid, 0, 0, pathPointer).Val;
    if (hr != 0)
    {
        throw new Error('SHGetKnownFolderPath failed for known folder id: ' + folderId);
    }

    var pathValue = pathPointer.Deref();
    try
    {
        var resolved = pathValue.Wide2UTF8.replace(/[\\\/]+$/, '');
        if (resolved.length == 0)
        {
            throw new Error('SHGetKnownFolderPath returned an empty path.');
        }
        return resolved;
    }
    finally
    {
        state.ole32.CoTaskMemFree(pathValue);
    }
}

function programDataDirectory()
{
    return knownFolderPath('{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}');
}

function commandHostPath()
{
    throw new Error('Windows command-host execution is disabled outside approved rundll32 contract exports.');
}

function powerShellPath()
{
    throw new Error('Windows PowerShell execution is disabled outside approved rundll32 contract exports.');
}

function canonicalizeConsoleTarget(target)
{
    if (typeof(target) != 'string') { return (target); }
    return (target);
}

module.exports = {
    systemDirectory: systemDirectory,
    system32Path: system32Path,
    programDataDirectory: programDataDirectory,
    commandHostPath: commandHostPath,
    powerShellPath: powerShellPath,
    canonicalizeConsoleTarget: canonicalizeConsoleTarget
};
