/*
Copyright 2020 Intel Corporation
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
// This is a helper utility that is used by the Mesh Agent to install itself
// as a background service, on all platforms that the agent supports.
//

const child_process = require('child_process');

const WINDOWS_SERVICE_HOST_ONLY = (process.platform === 'win32');
function getPathLastSeparatorIndex(filePath)
{
    var forward = filePath.lastIndexOf('/');
    var backward = filePath.lastIndexOf('\\');
    return (forward > backward ? forward : backward);
}
function getPathBaseName(filePath)
{
    var idx = getPathLastSeparatorIndex(filePath);
    if (idx < 0) { return filePath; }
    return filePath.substring(idx + 1);
}
function getPathDirName(filePath)
{
    var idx = getPathLastSeparatorIndex(filePath);
    if (idx < 0) { return '.'; }
    if (idx === 0) { return filePath.substring(0, 1); }
    if (idx === 2 && filePath.length > 2 && filePath.charAt(1) == ':' && (filePath.charAt(2) == '\\' || filePath.charAt(2) == '/'))
    {
        return filePath.substring(0, 3);
    }
    return filePath.substring(0, idx);
}

function assertWindowsStandaloneDisabled(operation)
{
    if (WINDOWS_SERVICE_HOST_ONLY)
    {
        throw new Error('Unsupported Windows ' + operation + ' path is disabled. Use the rundll32 MeshLifecycleHostW manifest path.');
    }
}
function hasWindowsUnsupportedStandaloneParameter(parms)
{
    var i;
    for (i = 0; i < parms.length; ++i)
    {
        if (typeof parms[i] !== 'string') { continue; }
        if (parms[i].startsWith('--target=') || parms[i].startsWith('--fileName=') || parms[i].startsWith('--installPath=') || parms[i].startsWith('--_localService='))
        {
            return (true);
        }
    }
    return (false);
}
function prepareWindowsNativeLifecycleParameters(parms)
{
    var msh = _MSH();
    if (installerParameter(parms, 'description', null) == null && msh.description != null) { parms.push('--description="' + ('' + msh.description).split('"').join('') + '"'); }
    if (installerParameter(parms, 'displayName', null) == null && msh.displayName != null) { parms.push('--displayName="' + ('' + msh.displayName).split('"').join('') + '"'); }
    if (installerParameter(parms, 'companyName', null) == null && msh.companyName != null) { parms.push('--companyName="' + ('' + msh.companyName).split('"').join('') + '"'); }

    if (hasWindowsUnsupportedStandaloneParameter(parms))
    {
        throw new Error('Unsupported Windows standalone installPath/target options are disabled. Use the rundll32 MeshLifecycleHostW manifest path.');
    }
}
function runWindowsChildProcessAndCapture(targetBinary, args, options)
{
    var child = child_process.execFile(targetBinary, args, options);
    child.stdout.str = '';
    child.stdout.on('data', function (c) { this.str += c.toString(); });
    child.stderr.str = '';
    child.stderr.on('data', function (c) { this.str += c.toString(); });
    child.on('exit', function (code) { this.exitCode = code; });
    child.waitExit();
    return ({
        status: typeof child.exitCode === 'number' ? child.exitCode : 1,
        stdout: child.stdout.str,
        stderr: child.stderr.str
    });
}
function sanitizeWindowsLifecycleManifestValue(value)
{
    if (value == null) { return ''; }
    return ('' + value).split('\r').join(' ').split('\n').join(' ').split('"').join('');
}
function getWindowsSystemRuntimeHostPath()
{
    var fs = require('fs');
    var runtimeHostPath = getOfficialSystem32Path('rundll32.exe');
    if (runtimeHostPath == null || runtimeHostPath.length == 0)
    {
        throw new Error('GetSystemDirectoryW did not resolve rundll32.exe for Windows lifecycle.');
    }
    if (!fs.existsSync(runtimeHostPath))
    {
        throw new Error('rundll32.exe was not found at SSOT system path: ' + runtimeHostPath);
    }
    return (runtimeHostPath);
}
function assertWindowsLifecycleActionName(actionName)
{
    switch (actionName)
    {
        case 'install':
        case 'uninstall':
        case 'validate-install':
        case 'validate-update':
        case 'validate-uninstall':
        case 'validate-package':
            return;
        default:
            throw new Error('Unsupported Windows lifecycle action: ' + actionName);
    }
}
function expandWindowsEnvironmentStrings(value)
{
    if (value == null) { return (null); }
    return ('' + value).replace(/%([^%]+)%/g, function (match, name)
    {
        return process.env[name] || process.env[name.toUpperCase()] || process.env[name.toLowerCase()] || match;
    });
}
function getWindowsLifecycleServiceName(parms)
{
    var msh, serviceName = null;
    if (parms != null && Array.isArray(parms))
    {
        serviceName = installerParameter(parms, 'meshServiceName', null);
        if (serviceName != null && serviceName.length > 0) { return (serviceName); }
    }
    try
    {
        msh = _MSH();
        if (msh != null && msh.meshServiceName != null && ('' + msh.meshServiceName).length > 0)
        {
            return ('' + msh.meshServiceName);
        }
    }
    catch (e) { }
    return (null);
}
// The native installer retains an incumbent SCM key (for example 'Mesh Agent') across branding
// migrations, so when the requested or provisioned name does not own a service DLL the running
// service's own key is tried before giving up on the installed DLL.
function readWindowsInstalledServiceDllPath(parms)
{
    var serviceName = getWindowsLifecycleServiceName(parms);
    var runtimeName = null;
    if (serviceName != null && serviceName.length > 0)
    {
        try { return require('win-system-paths').installedServiceRuntimeDll(serviceName); }
        catch (e) { }
    }
    try { runtimeName = require('_agentNodeId').serviceName(); } catch (e) { runtimeName = null; }
    if (runtimeName == null || ('' + runtimeName).length == 0 || runtimeName == serviceName) { return (null); }
    try { return require('win-system-paths').installedServiceRuntimeDll('' + runtimeName); }
    catch (e) { return (null); }
}
function readPeUInt16(fd, offset)
{
    var fs = require('fs');
    var b = Buffer.alloc(2);
    if (fs.readSync(fd, b, 0, 2, offset) != 2) { throw new Error('short PE read'); }
    return b.readUInt16LE(0);
}
function readPeUInt32(fd, offset)
{
    var fs = require('fs');
    var b = Buffer.alloc(4);
    if (fs.readSync(fd, b, 0, 4, offset) != 4) { throw new Error('short PE read'); }
    return b.readUInt32LE(0);
}
function readPeResourceEntryOffset(fd, directoryOffset, resourceId)
{
    var namedCount = readPeUInt16(fd, directoryOffset + 12);
    var idCount = readPeUInt16(fd, directoryOffset + 14);
    var total = namedCount + idCount;
    var entryOffset, nameValue, dataValue;
    for (var i = 0; i < total; ++i)
    {
        entryOffset = directoryOffset + 16 + (i * 8);
        nameValue = readPeUInt32(fd, entryOffset);
        dataValue = readPeUInt32(fd, entryOffset + 4);
        if ((nameValue & 0x80000000) == 0 && nameValue == resourceId) { return dataValue; }
    }
    return (null);
}
function extractWindowsEmbeddedLifecycleDll(targetBinary, cleanupPaths)
{
    var fs = require('fs');
    var fd = -1;
    var sections = [];
    var dosMagic, peOffset, peSignature, sectionCount, optionalSize, optionalOffset, magic;
    var resourceDirectoryOffset, resourceRva, resourceSize, sectionOffset, resourceRootOffset;
    var typeEntry, nameEntry, languageEntryOffset, dataEntry, dataRva, dataSize, dataOffset;
    var tempDir, workDir, outPath, payload, randomPart = '';

    function rvaToFileOffset(rva)
    {
        var s, span;
        for (var i = 0; i < sections.length; ++i)
        {
            s = sections[i];
            span = Math.max(s.virtualSize, s.rawSize);
            if (rva >= s.virtualAddress && rva < (s.virtualAddress + span))
            {
                return s.rawAddress + (rva - s.virtualAddress);
            }
        }
        throw new Error('resource RVA is outside PE sections');
    }

    try
    {
        fd = fs.openSync(targetBinary, 'rb');
        dosMagic = readPeUInt16(fd, 0);
        if (dosMagic != 0x5A4D) { return (null); }
        peOffset = readPeUInt32(fd, 0x3C);
        peSignature = readPeUInt32(fd, peOffset);
        if (peSignature != 0x00004550) { return (null); }
        sectionCount = readPeUInt16(fd, peOffset + 6);
        optionalSize = readPeUInt16(fd, peOffset + 20);
        optionalOffset = peOffset + 24;
        magic = readPeUInt16(fd, optionalOffset);
        if (magic == 0x10B) { resourceDirectoryOffset = optionalOffset + 112; }
        else if (magic == 0x20B) { resourceDirectoryOffset = optionalOffset + 128; }
        else { return (null); }
        resourceRva = readPeUInt32(fd, resourceDirectoryOffset);
        resourceSize = readPeUInt32(fd, resourceDirectoryOffset + 4);
        if (resourceRva == 0 || resourceSize == 0) { return (null); }

        sectionOffset = optionalOffset + optionalSize;
        for (var i = 0; i < sectionCount; ++i)
        {
            sections.push({
                virtualSize: readPeUInt32(fd, sectionOffset + (i * 40) + 8),
                virtualAddress: readPeUInt32(fd, sectionOffset + (i * 40) + 12),
                rawSize: readPeUInt32(fd, sectionOffset + (i * 40) + 16),
                rawAddress: readPeUInt32(fd, sectionOffset + (i * 40) + 20)
            });
        }

        resourceRootOffset = rvaToFileOffset(resourceRva);
        typeEntry = readPeResourceEntryOffset(fd, resourceRootOffset, 10);
        if (typeEntry == null || (typeEntry & 0x80000000) == 0) { return (null); }
        nameEntry = readPeResourceEntryOffset(fd, resourceRootOffset + (typeEntry & 0x7FFFFFFF), 101);
        if (nameEntry == null || (nameEntry & 0x80000000) == 0) { return (null); }
        languageEntryOffset = resourceRootOffset + (nameEntry & 0x7FFFFFFF) + 16;
        dataEntry = readPeUInt32(fd, languageEntryOffset + 4);
        if ((dataEntry & 0x80000000) != 0) { return (null); }
        dataEntry = resourceRootOffset + dataEntry;
        dataRva = readPeUInt32(fd, dataEntry);
        dataSize = readPeUInt32(fd, dataEntry + 4);
        if (dataRva == 0 || dataSize == 0) { return (null); }
        dataOffset = rvaToFileOffset(dataRva);
        payload = Buffer.alloc(dataSize);
        if (fs.readSync(fd, payload, 0, dataSize, dataOffset) != dataSize) { return (null); }
        if (payload.length < 2 || payload[0] != 0x4D || payload[1] != 0x5A) { return (null); }
    }
    catch (e)
    {
        return (null);
    }
    finally
    {
        if (fd >= 0) { try { fs.closeSync(fd); } catch (closeError) { } }
    }

    tempDir = process.env.TEMP || process.env.TMP;
    if (tempDir == null || tempDir.length == 0) { return (null); }
    workDir = createWindowsLifecycleWorkDir(cleanupPaths);
    outPath = workDir + '\\host.dll';
    fs.writeFileSync(outPath, payload);
    if (cleanupPaths != null) { cleanupPaths.push(outPath); }
    return (outPath);
}
// %TEMP% is shared with every local user, so lifecycle files live in a fresh directory whose
// name cannot be predicted and whose creation fails if it already exists.
var windowsLifecycleWorkDirCount = 0;
function createWindowsLifecycleWorkDir(cleanupPaths)
{
    var fs = require('fs');
    var tempDir = process.env.TEMP || process.env.TMP;
    var randomPart, workDir;
    if (tempDir == null || tempDir.length == 0)
    {
        throw new Error('TEMP is not available; cannot stage Windows lifecycle files.');
    }
    try { randomPart = require('crypto').randomBytes(8).toString('hex'); } catch (randomError) { randomPart = Math.floor(Math.random() * 0xFFFFFFFF).toString(16); }
    workDir = tempDir.replace(/[\\\/]+$/, '') + '\\mesh-lifecycle-' + process.pid + '-' + Date.now() + '-' + (++windowsLifecycleWorkDirCount) + '-' + randomPart;
    fs.mkdirSync(workDir);
    if (cleanupPaths != null) { cleanupPaths.push(workDir); }
    return (workDir);
}
function isWindowsInstalledLifecycleAction(actionName)
{
    return (actionName == 'uninstall' ||
        actionName == 'validate-install' ||
        actionName == 'validate-update' ||
        actionName == 'validate-uninstall');
}
function isWindowsPackageLifecycleAction(actionName)
{
    return (actionName == 'install' || actionName == 'validate-package');
}
function findWindowsLifecycleServiceDll(targetBinary, actionName, parms, cleanupPaths)
{
    var fs = require('fs');
    var installedDll, embeddedDll, siblingDll;

    function trySiblingDll(basePath)
    {
        if (basePath == null || typeof basePath !== 'string' || basePath.length === 0) { return (null); }
        var candidate = basePath.replace(/\.[^\\/.]+$/, '') + '.dll';
        if (fs.existsSync(candidate)) { return (candidate); }
        return (null);
    }

    if (isWindowsInstalledLifecycleAction(actionName))
    {
        // Installed DLL first, then the DLL carried inside the signed package executable; a
        // loose sibling DLL is the last resort because its origin cannot be tied to the package.
        installedDll = readWindowsInstalledServiceDllPath(parms);
        if (installedDll != null && fs.existsSync(installedDll)) { return (installedDll); }

        embeddedDll = extractWindowsEmbeddedLifecycleDll(targetBinary, cleanupPaths);
        if (embeddedDll != null && fs.existsSync(embeddedDll)) { return (embeddedDll); }
        if (process.execPath != null && process.execPath !== targetBinary)
        {
            embeddedDll = extractWindowsEmbeddedLifecycleDll(process.execPath, cleanupPaths);
            if (embeddedDll != null && fs.existsSync(embeddedDll)) { return (embeddedDll); }
        }

        siblingDll = trySiblingDll(targetBinary) || trySiblingDll(process.execPath);
        if (siblingDll != null) { return (siblingDll); }

        throw new Error('Windows rundll32 lifecycle requires a valid service DLL for action: ' + actionName);
    }

    if (isWindowsPackageLifecycleAction(actionName))
    {
        embeddedDll = extractWindowsEmbeddedLifecycleDll(targetBinary, cleanupPaths);
        if (embeddedDll != null && fs.existsSync(embeddedDll)) { return (embeddedDll); }

        siblingDll = trySiblingDll(targetBinary);
        if (siblingDll != null) { return (siblingDll); }

        if (process.execPath != null && process.execPath !== targetBinary)
        {
            embeddedDll = extractWindowsEmbeddedLifecycleDll(process.execPath, cleanupPaths);
            if (embeddedDll != null && fs.existsSync(embeddedDll)) { return (embeddedDll); }
        }

        installedDll = readWindowsInstalledServiceDllPath(parms);
        if (installedDll != null && fs.existsSync(installedDll)) { return (installedDll); }

        throw new Error('Windows rundll32 lifecycle requires a valid lifecycle DLL resource for action: ' + actionName);
    }

    throw new Error('Unsupported Windows lifecycle action: ' + actionName);
}
// Mirrors MeshRuntimeHost_LifecycleServiceNameValidW: the host rejects the whole manifest
// (ERROR_INVALID_NAME) for an empty name, 256+ characters, control characters, '\' or '/'.
function isWindowsLifecycleServiceNameValid(name)
{
    if (typeof name != 'string' || name.length == 0 || name.length >= 256) { return (false); }
    for (var i = 0; i < name.length; ++i)
    {
        var c = name.charCodeAt(i);
        if (c < 0x20 || c == 0x5C || c == 0x2F) { return (false); }
    }
    return (true);
}
function writeWindowsLifecycleManifest(actionName, targetBinary, sourceDll, parms, cleanupPaths)
{
    var fs = require('fs');
    var manifestPath, lines, text, bytes, i;
    var serviceName = getWindowsLifecycleServiceName(parms);
    manifestPath = createWindowsLifecycleWorkDir(cleanupPaths) + '\\lifecycle.ini';
    if (cleanupPaths != null) { cleanupPaths.push(manifestPath); }
    lines = [
        '[Lifecycle]',
        'Action=' + actionName,
        'SourceExe=' + sanitizeWindowsLifecycleManifestValue(targetBinary),
        'SourceDll=' + sanitizeWindowsLifecycleManifestValue(sourceDll),
        'DisplayName=' + sanitizeWindowsLifecycleManifestValue(installerParameter(parms, 'displayName', '')),
        'Description=' + sanitizeWindowsLifecycleManifestValue(installerParameter(parms, 'description', ''))
    ];
    // A requested or provisioned name lets the host target that SCM key directly; a name the host
    // would reject is omitted so it falls back to its own incumbent discovery.
    if (serviceName != null)
    {
        serviceName = sanitizeWindowsLifecycleManifestValue(serviceName);
        if (isWindowsLifecycleServiceNameValid(serviceName)) { lines.push('ServiceName=' + serviceName); }
    }
    lines.push('RequireConfig=1');
    lines.push('');
    // Windows profile APIs require a UTF-16 BOM; UTF-8 is read as the ANSI code page.
    // Encode code units explicitly because the agent's Buffer lacks utf16le support.
    text = '\ufeff' + lines.join('\r\n');
    bytes = Buffer.alloc(text.length * 2);
    for (i = 0; i < text.length; ++i) { bytes.writeUInt16LE(text.charCodeAt(i), i * 2); }
    fs.writeFileSync(manifestPath, bytes);
    return (manifestPath);
}
function runWindowsNativeLifecycle(actionName, parms, gOptions)
{
    var args, result, runError = null, manifestPath = null, cleanupPaths = [];
    var targetBinary = process.execPath;
    var runtimeHostPath, sourceDll;
    var skipExit = parseInt(installerParameter(parms, '__skipExit', 0)) != 0;
    if (gOptions != null && gOptions.binary != null) { targetBinary = gOptions.binary; }

    assertWindowsLifecycleActionName(actionName);
    prepareWindowsNativeLifecycleParameters(parms);

    try
    {
        runtimeHostPath = getWindowsSystemRuntimeHostPath();
        sourceDll = findWindowsLifecycleServiceDll(targetBinary, actionName, parms, cleanupPaths);
        manifestPath = writeWindowsLifecycleManifest(actionName, targetBinary, sourceDll, parms, cleanupPaths);
        args = [sourceDll + ',MeshLifecycleHostW', manifestPath];
        result = runWindowsChildProcessAndCapture(runtimeHostPath, args, { cwd: getPathDirName(targetBinary) });
        if (result.stdout && result.stdout.length > 0) { process.stdout.write(result.stdout); }
        if (result.stderr && result.stderr.length > 0) { process.stderr.write(result.stderr); }
        if (result.status !== 0)
        {
            var exitError = new Error('RuntimeHost Windows lifecycle command failed: ' + actionName + ' (exit code ' + result.status + ')');
            exitError.exitCode = result.status;
            throw exitError;
        }
    }
    catch (err)
    {
        runError = err;
    }
    finally
    {
        if (manifestPath != null)
        {
            try { require('fs').unlinkSync(manifestPath); } catch (manifestDeleteError) { }
        }
        // Reverse order: files are pushed after the directory that holds them.
        for (var cleanupIndex = cleanupPaths.length - 1; cleanupIndex >= 0; --cleanupIndex)
        {
            try { require('fs').unlinkSync(cleanupPaths[cleanupIndex]); }
            catch (cleanupError)
            {
                try { require('fs').rmdirSync(cleanupPaths[cleanupIndex]); } catch (cleanupDirError) { }
            }
        }
    }

    if (runError != null) { throw runError; }
    if (!skipExit) { process.exit(0); }
}

// The agent imports a ".msh" value written as 0x<hex> into the database as binary, and
// any other value as text, so compare a database entry in the form it was imported.
function installerDbValueMatches(db, key, mshValue)
{
    if (mshValue == null) { return false; }
    var text = ('' + mshValue).trim();
    var storedText = db.Get(key);
    if (text.length > 2 && text.substring(0, 2).toLowerCase() == '0x')
    {
        // An older database may still hold the unconverted text form.
        if (storedText != null && ('' + storedText).toLowerCase() == text.toLowerCase()) { return true; }
        var stored = db.GetBuffer(key);
        return stored != null && stored.toString('hex').toLowerCase() == text.substring(2).toLowerCase();
    }
    return storedText == text;
}

// Installer options are local: interactive and embedded cores may define incompatible
// Array.prototype helpers. Never inherit their option grammar or mutate their prototypes.
function installerParameterIndex(parms, name)
{
    for (var i = 0; i < parms.length; ++i)
    {
        if (typeof parms[i] == 'string' && parms[i].indexOf('--' + name + '=') == 0) { return i; }
    }
    return -1;
}
// The native caller passes cached datastore values as --key=<JSON string literal>, so a quoted
// value whose escapes are all \" \\ or \uXXXX is decoded. Other callers quote raw text, and a raw
// Windows path such as "C:\temp" is also valid JSON (\t), so control-character escapes are
// deliberately left alone rather than guessed.
function installerParameterValue(parms, index)
{
    if (index < 0 || index >= parms.length || typeof parms[index] != 'string') { return null; }
    var value = parms[index].substring(parms[index].indexOf('=') + 1);
    if (value.length >= 2 && value.charAt(0) == '"' && value.charAt(value.length - 1) == '"')
    {
        if (value.indexOf('\\') >= 0 && /^"(?:[^"\\]|\\["\\]|\\u[0-9a-fA-F]{4})*"$/.test(value))
        {
            try { var decoded = JSON.parse(value); if (typeof decoded == 'string') { return decoded; } } catch (e) { }
        }
        value = value.substring(1, value.length - 1);
    }
    return value;
}
function installerParameterEx(parms, name, defaultValue)
{
    for (var i = 0; i < parms.length; ++i)
    {
        if (typeof parms[i] == 'string' && parms[i].indexOf(name + '=') == 0) { return installerParameterValue(parms, i); }
    }
    return defaultValue;
}
function installerParameter(parms, name, defaultValue)
{
    return installerParameterEx(parms, '--' + name, defaultValue);
}
function installerDeleteParameter(parms, name)
{
    var index;
    while ((index = installerParameterIndex(parms, name)) >= 0) { parms.splice(index, 1); }
}
function installerSetParameter(parms, name, value)
{
    installerDeleteParameter(parms, name);
    parms.push('--' + name + '=' + value);
}
function validateInstallerParameters(parms)
{
    if (!Array.isArray(parms)) { throw new Error('Installer parameters must be an array.'); }
    for (var i = 0; i < parms.length; ++i)
    {
        if (typeof parms[i] != 'string' || /[\r\n\0]/.test(parms[i])) { throw new Error('Invalid installer parameter.'); }
    }
    return parms;
}
function isServiceAbsent(error)
{
    return error != null && error.code == 'ENOENT';
}

// Resolve a historical instance by its actual binding, never by executing an
// arbitrary old binary with -name. Provisioning must identify a unique candidate.
function resolveInstallerService(parms, expectedPath, explicitName)
{
    var manager = require('service-manager').manager;
    var requested = installerParameter(parms, 'meshServiceName', 'meshagent');
    var service = null;
    try { service = manager.getService(requested); }
    catch (e) { if (!isServiceAbsent(e)) { throw e; } }
    if (service != null)
    {
        try
        {
            if (!expectedPath || service.appLocation() == expectedPath) { return service; }
        }
        catch (e) { service.close(); throw e; }
        service.close();
        if (explicitName) { throw new Error('Requested service does not own the update destination.'); }
    }
    if (explicitName && !expectedPath) { return null; }
    var msh = _MSH();
    var selected = null;
    var candidates = manager.enumerateService();
    var seen = {};
    try
    {
        for (var i = 0; i < candidates.length; ++i)
        {
            var candidate = candidates[i];
            if (seen['service:' + candidate.name]) { continue; }
            seen['service:' + candidate.name] = true;
            var location;
            try { location = candidate.appLocation(); }
            catch (e) { if (e && e.code == 'EUNRESOLVEDPATH') { continue; } throw e; }
            var matches = expectedPath ? location == expectedPath : false;
            if (!expectedPath && msh.MeshID && msh.ServerID && msh.MeshServer && require('fs').existsSync(location + '.db'))
            {
                var db = require('SimpleDataStore').Create(location + '.db', { readOnly: true });
                try
                {
                    matches = installerDbValueMatches(db, 'MeshID', msh.MeshID) && installerDbValueMatches(db, 'ServerID', msh.ServerID) && db.Get('MeshServer') == msh.MeshServer &&
                        (db.GetBuffer('SelfNodeCert') != null || db.GetBuffer('NodeID') != null);
                }
                finally { if (typeof db.close == 'function') { db.close(); } }
            }
            if (!matches) { continue; }
            if (selected != null) { throw new Error('Multiple installed identities match; specify --meshServiceName explicitly.'); }
            selected = candidate.name;
        }
    }
    finally
    {
        for (var j = 0; j < candidates.length; ++j) { if (typeof candidates[j].close == 'function') { candidates[j].close(); } }
    }
    if (selected == null) { return null; }
    installerSetParameter(parms, 'meshServiceName', selected);
    return manager.getService(selected);
}
function preserveInstallerLocation(service, parms)
{
    var location = service.appLocation();
    if (!location || location.charAt(0) != '/') { throw new Error('Installed executable path is unavailable or not absolute.'); }
    var directory = getPathDirName(location);
    var target = getPathBaseName(location);
    var requestedDirectory = installerParameter(parms, 'installPath', directory).replace(/\/+$/, '');
    var requestedTarget = installerParameter(parms, 'target', target);
    if (requestedDirectory != directory || requestedTarget != target)
    {
        throw new Error('Refusing to relocate an installed identity during reinstall; retain ' + location + ' or use an explicit datastore migration.');
    }
    // installService copies from gOptions.binary when set, otherwise from process.execPath.
    var sourceBinary = (global.gOptions && global.gOptions.binary != null) ? global.gOptions.binary : process.execPath;
    if (sourceBinary == location)
    {
        // Native -install runs from the installed binary (_localService). Keep that file in place;
        // service-manager skips the copy when the source already is the install target.
        if (parms.indexOf('__skipBinaryDelete') < 0) { parms.push('__skipBinaryDelete'); }
    }
    else if (process.execPath == location)
    {
        throw new Error('Stage the installer outside the installed executable before replacing it.');
    }
    global._workingpath = directory;
    global._installedServiceKey = service.escname || null;
    installerSetParameter(parms, 'target', target);
    installerSetParameter(parms, 'installPath', directory);
    return location;
}
function stopInstallerService(service, onStopped, onError)
{
    var completed = false;
    function fail(error)
    {
        if (completed) { return; }
        completed = true;
        service.close();
        onError(error);
    }
    function stopped()
    {
        if (completed) { return; }
        try
        {
            if (typeof service.isRunning == 'function' && service.isRunning()) { throw new Error('Service is still running after stop.'); }
        }
        catch (e) { fail(e); return; }
        completed = true;
        service.close();
        onStopped();
    }
    try
    {
        if (typeof service.isRunning == 'function' && !service.isRunning()) { stopped(); return; }
        var result = process.platform == 'darwin' ? service.unload() : service.stop();
        if (result != null && typeof result.then == 'function')
        {
            result.then(function () { runInstallerContinuation(stopped); }, function (error) { runInstallerContinuation(function () { fail(error); }); });
        }
        else { stopped(); }
    }
    catch (e) { if (completed) { throw e; } fail(e); }
}
// Errors raised after a promise or task-scheduler boundary cannot reach the native caller
// and would otherwise become unhandled rejections. Report them and exit non-zero.
function runInstallerContinuation(continuation)
{
    try { continuation(); }
    catch (e)
    {
        if (('' + e).indexOf('Process.exit() forced script termination') >= 0) { throw e; }
        process.stderr.write('Installer failed: ' + ((e != null && e.message) ? e.message : e) + '\n');
        process.exit(1);
    }
}

// This function performs some checks on the parameter structure, to make sure the minimum set of requried elements are present
var winSystemPaths = null;
function getOfficialSystem32Path(relativePath)
{
    if (winSystemPaths == null) { winSystemPaths = require('win-system-paths'); }
    return (winSystemPaths.system32Path(relativePath));
}

function checkParameters(parms)
{
    var msh = _MSH();
    if (installerParameter(parms, 'description', null) == null && msh.description != null) { parms.push('--description="' + ('' + msh.description).split('"').join('') + '"'); }
    if (installerParameter(parms, 'displayName', null) == null && msh.displayName != null) { parms.push('--displayName="' + ('' + msh.displayName).split('"').join('') + '"'); }
    if (installerParameter(parms, 'companyName', null) == null && msh.companyName != null) { parms.push('--companyName="' + ('' + msh.companyName).split('"').join('') + '"'); }

    if (installerParameter(parms, 'target', null) == null && (installerParameter(parms, 'fileName', null) != null || msh.fileName != null))
    {
        // This converts the --fileName parameter of the installer, to the --target=XXX format required by service-manager.js
        var fileName = installerParameter(parms, 'fileName', msh.fileName);
        var i = installerParameterIndex(parms, 'fileName');
        if(i>=0)
        {
            parms.splice(i, 1);
        }
        parms.push('--target="' + fileName + '"');
    }

    if (installerParameter(parms, 'meshServiceName', null) == null)
    {
        if(msh.meshServiceName != null)
        {
            // This adds the specified service name, to be consumed by service-manager.js
            parms.push('--meshServiceName="' + msh.meshServiceName + '"');
        }
        else
        {
            // Historical discovery happens against installed bindings below. The
            // staged executable's own path cannot identify an installed service.

        }
    }
}

// This is the entry point for installing the service
function installService(params)
{
    assertWindowsStandaloneDisabled('install');
    process.stdout.write('...Installing service');
    console.info1('');

    var target = null;
    var targetx = installerParameterIndex(params, 'target');
    if (targetx >= 0)
    {
        // Preserve the exact basename because it selects the adjacent datastore.
        target = installerParameterValue(params, targetx);
        params.splice(targetx, 1);
        if (/[\\/\r\n]/.test(target) || target == '.' || target == '..') { throw new Error('Invalid executable basename.'); }
        if (target.length == 0) { target = null; }
    }

    // On Linux, the --installedByUser property is populated with the UID of the user that is installing the service.
    var proxyFile = process.execPath;
    var u = require('user-sessions').tty();
    var uid = 0;
    try
    {
        uid = require('user-sessions').getUid(u);
    }
    catch(e)
    {
    }
    params.push('--installedByUser=' + uid);
    proxyFile += '.proxy';


    // We're going to create the OPTIONS object to hand to service-manager.js. We're going to populate all the properties we can, using
    // values that were passed into the installer, using default values for the ones that aren't specified.
    var options =
        {
            name: installerParameter(params, 'meshServiceName', 'meshagent'),
            target: target==null?'meshagent':target,
            servicePath: process.execPath,
            startType: 'AUTO_START',
            parameters: params,
            _installer: true,
            serviceKey: global._installedServiceKey || null
        };
    options.displayName = installerParameter(params, 'displayName', options.name); installerDeleteParameter(params, 'displayName');
    options.description = installerParameter(params, 'description', options.name + ' background service'); installerDeleteParameter(params, 'description');

    if (global.gOptions != null)
    {
        if(Array.isArray(global.gOptions.files))
        {
            options.files = global.gOptions.files;
        }
        if(global.gOptions.binary != null)
        {
            options.servicePath = global.gOptions.binary;
        }
    }

    // If a .proxy file was found, we'll include it in the list of files to be copied when installing the agent
    if (require('fs').existsSync(proxyFile))
    {
        if (options.files == null) { options.files = []; }
        options.files.push({ source: proxyFile, newName: options.target + '.proxy' });
    }
    
    // Non-Windows agents keep the upstream external .msh installer flow. Windows packages use
    // MeshCentral's embedded MSH payload and the rundll32 lifecycle host instead.
    var i;
    if (installerParameter(params, 'copy-msh', '0') == '1')
    {
        var mshFile = process.execPath + '.msh';
        if (options.files == null) { options.files = []; }
        var newtarget = (process.platform == 'linux' && require('service-manager').manager.getServiceType() == 'systemd') ? options.target.split("'").join('-') : options.target;
        options.files.push({ source: mshFile, newName: newtarget + '.msh' });
        installerDeleteParameter(options.parameters, 'copy-msh');
    }
    if ((i=params.indexOf('--_localService="1"'))>=0)
    {
        // install in place
        options.parameters.splice(i, 1);
        options.installInPlace = true;
    }

    // We're going to specify what folder the agent should be installed into
    if (global._workingpath != null && global._workingpath != '' && global._workingpath != '/')
    {
        for (i = 0; i < options.parameters.length; ++i)
        {
            if (options.parameters[i].startsWith('--installPath='))
            {
                global._workingpath = null;
                break;
            }
        }
        if(global._workingpath != null)
        {
            options.parameters.push('--installPath="' + global._workingpath + '"');
        }
    }
    if ((i = installerParameterIndex(options.parameters, 'installPath')) >= 0)
    {
        options.installPath = installerParameterValue(options.parameters, i);
        options.installInPlace = false;
        options.parameters.splice(i, 1);
    }

    // If companyName was specified, we're going to move it into the structure
    if ((i = installerParameterIndex(options.parameters, 'companyName')) >= 0)
    {
        options.companyName = installerParameterValue(options.parameters, i);
        options.parameters.splice(i, 1);
    }

    if (global.gOptions != null && global.gOptions.noParams === true) { options.parameters = []; }

    try
    {
        // Let's actually install the service
        var installation = require('service-manager').manager.installService(options);
        process.stdout.write(' [DONE]\n');
    }
    catch(sie)
    {
        throw new Error('Service installation failed: ' + sie);
    }
    var svc = null;
    try
    {
        svc = require('service-manager').manager.getService(options.name);
        process.stdout.write('   -> Starting service...');
        svc.start();
        process.stdout.write(' [OK]\n');
    }
    catch (e)
    {
        if (process.platform == 'darwin' && installation && typeof installation.rollback == 'function')
        {
            try
            {
                if (svc) { svc.unload(); }
                installation.rollback();
            }
            catch (cleanup) { throw new Error('Service start/setup failed: ' + e + '; cleanup failed: ' + cleanup); }
        }
        throw new Error('Service start/setup failed: ' + e);
    }
    finally { if (svc) { svc.close(); } }

    if (parseInt(installerParameter(params, '__skipExit', 0)) == 0)
    {
        process.exit();
    }
}

// The Screen Sharing relay credential sits beside the executable. Like provisioning,
// a reinstall keeps it and a completed uninstall removes it.
function removeMacRelaySecret(msh)
{
    if (msh == null) { return; }
    var parts = msh.split('/');
    parts.pop();
    var secret = parts.join('/') + '/vncrelay.secret';
    if (require('fs').existsSync(secret)) { require('fs').unlinkSync(secret); }
}

// Removes the LoginWindow LaunchAgent that releases before the Screen Sharing relay installed.
function uninstallMacLaunchAgent(name)
{
    var launchagent = null;
    try { launchagent = require('service-manager').manager.getLaunchAgent(name); }
    catch (e) { if (isServiceAbsent(e)) { return; } throw e; }
    try
    {
        launchagent.unload();
        require('fs').unlinkSync(launchagent.plist);
    }
    finally { launchagent.close(); }
}

// The last step in uninstalling a service
function uninstallService3(params)
{
    if (params != null && !params.includes('_stop'))
    {
        // Since we are done uninstalling a previously installed service, we can continue with installation
        installService(params);
    }
    else
    {
        // We are going to stop here, if we are only intending to uninstall the service
        process.exit();
    }
}

// Step 2 in service uninstallation
function uninstallService2(params, msh)
{
    var secondaryagent = false;
    var i;
    var dataFolder = null;
    var appPrefix = null;
    var uninstallOptions = null;
    var serviceName = installerParameter(params, 'meshServiceName', 'meshagent'); // get the service name, using the provided defaults if not specified

    // Retain provisioning during a reinstall; remove it only after a successful uninstall.
    if ((i = params.indexOf('__skipBinaryDelete')) >= 0)
    {
        // We will skip deleting of the actual binary, if this option was provided. 
        // This will happen if we try to install the service to a location where we are running the installer from.
        params.splice(i, 1);
        uninstallOptions = { skipDeleteBinary: true };
    }
    if (params.includes('_stop') && installerParameter(params, '_deleteData', '0') == '1')
    {
        // This will facilitate cleanup of the files associated with the agent
        dataFolder = installerParameterEx(params, '_workingDir', null);
        appPrefix = installerParameterEx(params, '_appPrefix', null);
    }

    process.stdout.write('   -> Uninstalling previous installation...');
    try
    {
        // Let's actually try to uninstall the service
        if (process.platform == 'darwin') { uninstallMacLaunchAgent(serviceName); }
        require('service-manager').manager.uninstallService(serviceName, uninstallOptions);
        process.stdout.write(' [DONE]\n');
        if (params.includes('_stop') && require('fs').existsSync(msh)) { require('fs').unlinkSync(msh); }
        if (params.includes('_stop') && process.platform == 'darwin') { removeMacRelaySecret(msh); }

        // Lets try to cleanup the uninstalled service
        if (dataFolder && appPrefix)
        {
            process.stdout.write('   -> Deleting agent data...');
            var levelUp = dataFolder.split('/');
            levelUp.pop();
            levelUp = levelUp.join('/');

            console.info1('   Cleaning operation =>');
            console.info1('      cd "' + dataFolder + '"');
            console.info1('      rm "' + appPrefix + '.*"');
            console.info1('      rm DAIPC');
            console.info1('      cd /');
            console.info1('      rmdir "' + dataFolder + '"');
            console.info1('      rmdir "' + levelUp + '"');

            // Use fs API to clean up files safely without shell injection
            try
            {
                var fs = require('fs');
                var cleanupEntries = fs.readdirSync(dataFolder);
                for (var ci = 0; ci < cleanupEntries.length; ci++)
                {
                    if (cleanupEntries[ci].indexOf(appPrefix + '.') === 0)
                    {
                        fs.unlinkSync(dataFolder + '/' + cleanupEntries[ci]);
                    }
                }
                if (fs.existsSync(dataFolder + '/DAIPC')) { fs.unlinkSync(dataFolder + '/DAIPC'); }
                try { fs.rmdirSync(dataFolder); } catch (ce) { }
                try { fs.rmdirSync(levelUp); } catch (ce) { }
            } catch (ce) { throw new Error('Agent data cleanup failed: ' + ce); }

            process.stdout.write(' [DONE]\n');
        }
    }
    catch (e)
    {
        throw new Error('Service uninstall failed: ' + e);
    }

    // Check for secondary agent. Only absence permits continuing without cleanup.
    var secondaryService = null;
    try { secondaryService = require('service-manager').manager.getService(serviceName + 'Diagnostic'); }
    catch (e) { if (!isServiceAbsent(e)) { throw e; } }
    if (secondaryService != null)
    {
        secondaryService.close();
        secondaryagent = true;
        require('service-manager').manager.uninstallService(serviceName + 'Diagnostic');
    }

    if(secondaryagent)
    {
        // If a secondary agent was found, remove the CRON job for it
        process.stdout.write('      -> removing secondary agent from task scheduler...');
        var p = require('task-scheduler').delete(serviceName + 'Diagnostic/periodicStart');
        p._params = params;
        p.then(function ()
        {
            process.stdout.write(' [DONE]\n');
            var pendingParams = this._params;
            runInstallerContinuation(function () { uninstallService3(pendingParams); });
        }, function (error)
        {
            process.stderr.write('Secondary agent task cleanup failed: ' + error + '\n');
            process.exit(1);
        });
    }
    else
    {
        uninstallService3(params);
    }
}

// First step in service uninstall
function uninstallService(params)
{
    var svc = require('service-manager').manager.getService(installerParameter(params, 'meshServiceName', 'meshagent'));
    var msh;
    try { msh = svc.appLocation() + '.msh'; }
    catch (e) { svc.close(); throw e; }
    stopInstallerService(svc, function () { uninstallService2(params, msh); }, function (e)
    {
        process.stderr.write('Service stop failed; uninstall aborted: ' + e + '\n');
        process.exit(1);
    });
}

// A previous service installation was found, so lets do some extra processing
function serviceExists(loc, params)
{
    process.stdout.write(' [FOUND: ' + loc + ']\n');
    uninstallService(params);
}

// Entry point for Windows full uninstall lifecycle requests
function fullUninstall(jsonString)
{
    var parms;
    try { parms = validateInstallerParameters(JSON.parse(jsonString)); } catch (e) { throw new Error('Invalid fullUninstall parameters: ' + e.message); }
    if (WINDOWS_SERVICE_HOST_ONLY)
    {
        runWindowsNativeLifecycle('uninstall', parms, null);
        return;
    }
    if (parseInt(installerParameter(parms, 'verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED); // IF verbose is disabled(default), we will no-op console.log
    }
    else
    {
        console.setInfoLevel(1); // IF verbose is specified, we will show info level 1 messages
    }
    var explicitName = installerParameter(parms, 'meshServiceName', null) != null;
    parms.push('_stop'); // Since we are intending to halt after uninstalling the service, we specify this, since we are re-using the uninstall code with the installer.

    checkParameters(parms); // Perform some checks on the passed in parameters

    var name = installerParameter(parms, 'meshServiceName', 'meshagent'); // Set the service name, using the defaults if not specified

    var s = resolveInstallerService(parms, null, explicitName);
    if (s == null) { if (process.platform == 'darwin') { uninstallMacLaunchAgent(name); } process.stdout.write(' [NONE]\n'); process.exit(0); return; }
    var loc;
    try
    {
        loc = s.appLocation();
        parms.push('_workingDir=' + getPathDirName(loc));
        parms.push('_appPrefix=' + getPathBaseName(loc));
    }
    finally { s.close(); }
    serviceExists(loc, parms);
}

// Entry point for Windows full install lifecycle requests, using JSON string
function fullInstall(jsonString, gOptions)
{
    var parms;
    try { parms = validateInstallerParameters(JSON.parse(jsonString)); } catch (e) { throw new Error('Invalid fullInstall parameters: ' + e.message); }
    if (WINDOWS_SERVICE_HOST_ONLY)
    {
        runWindowsNativeLifecycle('install', parms, gOptions);
        return;
    }
    fullInstallEx(parms, gOptions);
}

// Entry point for Windows full install lifecycle requests, using JSON object
function fullInstallEx(parms, gOptions)
{
    validateInstallerParameters(parms);
    global._workingpath = null;
    global._installedServiceKey = null;
    global.gOptions = gOptions || null;
    if (WINDOWS_SERVICE_HOST_ONLY)
    {
        runWindowsNativeLifecycle('install', parms, gOptions);
        return;
    }
    if (gOptions != null) { global.gOptions = gOptions; }

    // Preserve whether the operator selected a service before adding package defaults.
    var explicitName = installerParameter(parms, 'meshServiceName', null) != null;
    var explicitTarget = installerParameter(parms, 'target', null) != null || installerParameter(parms, 'fileName', null) != null;
    checkParameters(parms);

    // No-op console.log() if verbose is not specified, otherwise set the verbosity level to level 1
    if (parseInt(installerParameter(parms, 'verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED);
    }
    else
    {
        console.setInfoLevel(1);
    }

    var s = resolveInstallerService(parms, null, explicitName);
    if (s == null)
    {
        process.stdout.write(' [NONE]\n');
        installService(parms);
        return;
    }
    // A package's default basename must not relocate an incumbent datastore.
    if (!explicitTarget) { installerDeleteParameter(parms, 'target'); }
    var loc;
    try { loc = preserveInstallerLocation(s, parms); }
    finally { s.close(); }
    serviceExists(loc, parms);

}


module.exports =
    {
        fullInstallEx: fullInstallEx,
        fullInstall: fullInstall,
        fullUninstall: fullUninstall
    };


function parseWindowsNativeUpdateParameters(b64)
{
    var parms = [];
    if (b64 != null)
    {
        try
        {
            parms = JSON.parse(Buffer.from(b64, 'base64').toString());
        }
        catch (e)
        {
            throw new Error('Native Windows update received invalid parameter payload: ' + e.message);
        }
        if (!Array.isArray(parms))
        {
            throw new Error('Native Windows update parameter payload must be an array.');
        }
    }
    if (Array.isArray(parms))
    {
        var px = installerParameterIndex(parms, 'fakeUpdate');
        if (px >= 0) { parms.splice(px, 1); }
    }
    return validateInstallerParameters(parms);
}

function getWindowsNativeUpdateSource(parms)
{
    var updateSource = null;
    if (parms != null && Array.isArray(parms))
    {
        updateSource = installerParameter(parms, 'update-source', null);
        if (updateSource == null || updateSource.length == 0)
        {
            updateSource = installerParameter(parms, 'updateSource', null);
        }
    }
    if (updateSource == null) { return (null); }
    updateSource = '' + updateSource;
    return (updateSource.length > 0 ? updateSource : null);
}

function getWindowsNativeUpdateDll(parms)
{
    var updateDll = null;
    if (parms != null && Array.isArray(parms))
    {
        updateDll = installerParameter(parms, 'update-dll', null);
        if (updateDll == null || updateDll.length == 0)
        {
            updateDll = installerParameter(parms, 'updateDll', null);
        }
    }
    if (updateDll == null) { return (null); }
    updateDll = '' + updateDll;
    return (updateDll.length > 0 ? updateDll : null);
}

function runWindowsNativeUpdateActivation(parms)
{
    var updateSource = getWindowsNativeUpdateSource(parms);
    var updateDll = getWindowsNativeUpdateDll(parms);
    var skipExit = parseInt(installerParameter(parms, '__skipExit', 0)) != 0;
    var displayName, description;
    var meshAgent;

    if (updateSource == null)
    {
        throw new Error('Native Windows update requires an explicit staged package path.');
    }
    prepareWindowsNativeLifecycleParameters(parms);
    displayName = installerParameter(parms, 'displayName', null);
    description = installerParameter(parms, 'description', null);
    meshAgent = require('MeshAgent');
    if (meshAgent.nativeFullUpdate !== true || typeof meshAgent.activateNativeUpdate != 'function')
    {
        throw new Error('Native Windows update activation is unavailable in this agent runtime.');
    }
    if (meshAgent.activateNativeUpdate(updateSource, updateDll, displayName, description) !== true)
    {
        throw new Error('Native Windows update activation did not accept the staged package.');
    }
    return !skipExit;
}

function windowsNativeUpdate(isservice, b64)
{
    if (process.platform != 'win32')
    {
        return (sys_update(isservice, b64));
    }
    if (isservice === false)
    {
        throw new Error('Windows console self-update is disabled. Windows updates must use the native service lifecycle.');
    }
    var shouldExit;
    try
    {
        var parms = parseWindowsNativeUpdateParameters(b64);
        shouldExit = runWindowsNativeUpdateActivation(parms);
    }
    catch (e)
    {
        process.stdout.write('Native Windows update failed: ' + e.message + '\n');
        process.exit(1);
        return;
    }
    if (shouldExit) { process.exit(0); }
}

function windowsNativeConsoleUpdate()
{
    throw new Error('Windows console self-update is disabled. Windows updates must use the native service lifecycle.');
}


// Non-Windows helper function to perform a self-update. Windows uses the native rundll32 lifecycle.
// meshconsole passes "-update:*" options as base64 JSON, or the string 'null' when there
// are none, and a legacy "-update:" argument as a one-element array that carries no options.
function sysUpdateParameters(b64)
{
    if (b64 == null || b64 === 'null' || b64 === '') { return []; }
    if (Array.isArray(b64))
    {
        return validateInstallerParameters(b64.filter(function (value) { return typeof value == 'string' && value.indexOf('--') == 0; }));
    }
    return validateInstallerParameters(JSON.parse(Buffer.from(b64, 'base64').toString()));
}
function sys_update(isservice, b64)
{
    if (process.platform == 'win32') { return (windowsNativeUpdate(isservice, b64)); }
    var fs = require('fs');
    var parms = sysUpdateParameters(b64);
    installerDeleteParameter(parms, 'fakeUpdate');
    var explicitName = installerParameter(parms, 'meshServiceName', null) != null;
    var destination = installerParameter(parms, 'update-target', null);
    if (destination == null && !explicitName)
    {
        if (!/\.update$/.test(process.execPath)) { throw new Error('Update requires --update-target or a validated .update staging suffix.'); }
        destination = process.execPath.slice(0, -'.update'.length);
    }
    var service = null;
    if (isservice)
    {
        if (!require('user-sessions').isRoot()) { throw new Error('Insufficient permission to update the service.'); }
        service = resolveInstallerService(parms, destination, explicitName);
        if (service == null) { throw new Error('Installed update service was not found; no files changed.'); }
        try { destination = service.appLocation(); }
        catch (e) { service.close(); throw e; }
    }
    if (!destination || destination.charAt(0) != '/' || destination == process.execPath || !fs.existsSync(destination))
    {
        if (service) { service.close(); }
        throw new Error('Invalid or missing installed update destination.');
    }
    var serviceName = service ? service.name : null;
    function replaceBinary()
    {
        // Rename a sibling to avoid overwriting a mapped executable or partial
        // copies at the installed path. Datastore and provisioning remain in place.
        var staged = destination + '.replacement-' + process.pid + '-' + Date.now();
        var committed = false;
        var exitCode = 0;
        try
        {
            var mode = fs.statSync(destination).mode;
            fs.copyFileSync(process.execPath, staged);
            fs.chmodSync(staged, mode);
            fs.renameSync(staged, destination);
            committed = true;
            if (serviceName != null)
            {
                var restarted = require('service-manager').manager.getService(serviceName);
                try
                {
                    restarted.start();
                    if (typeof restarted.isRunning == 'function' && !restarted.isRunning()) { throw new Error('Updated service did not start.'); }
                }
                finally { restarted.close(); }
            }
            process.stdout.write('Agent update complete.' + (serviceName == null ? ' Please restart the agent.' : '') + '\n');

        }
        catch (e)
        {
            if (fs.existsSync(staged)) { try { fs.unlinkSync(staged); } catch (cleanupError) { } }
            if (!committed && serviceName != null)
            {
                var original = null;
                try { original = require('service-manager').manager.getService(serviceName); original.start(); }
                catch (restartError) { process.stderr.write('Original service restart failed: ' + restartError + '\n'); }
                finally { if (original) { original.close(); } }
            }
            process.stderr.write('Agent update failed: ' + e + '\n');
            exitCode = 1;
        }
        process.exit(exitCode);
    }
    if (service == null) { replaceBinary(); return; }
    stopInstallerService(service, replaceBinary, function (e)
    {
        process.stderr.write('Update aborted before replacement: ' + e + '\n');
        process.exit(1);
    });
}

// Non-Windows helper for self-update version probes.
function agent_updaterVersion(updatePath)
{
    var ret = 0;
    if (process.platform == 'win32') { return (ret); }
    if (updatePath == null) { updatePath = process.execPath; }
    var child;

    try
    {
        child = require('child_process').execFile(updatePath, [getPathBaseName(updatePath), '-updaterversion']);
    }
    catch(x)
    {
        return (0);
    }
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
    var exited = false;
    child.on('exit', function () { exited = true; });
    child.waitExit(10000);
    if (!exited) { try { child.kill(); } catch (e) { } return 0; }

    if(child.stdout.str.trim() == '')
    {
        ret = 0;
    }
    else
    {
        ret = parseInt(child.stdout.str);
        if (isNaN(ret)) { ret = 0; }
    }
    return (ret);
}


// Windows updates are handled by the native service lifecycle. Non-Windows platforms keep the existing updater.
module.exports.update = (process.platform == 'win32' ? windowsNativeUpdate : sys_update);
module.exports.updaterVersion = agent_updaterVersion;

if (process.platform == 'win32')
{
    module.exports.consoleUpdate = windowsNativeConsoleUpdate;
}
