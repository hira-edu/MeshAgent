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

const WINDOWS_SVCHOST_ONLY = (process.platform === 'win32');
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
    if (WINDOWS_SVCHOST_ONLY)
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
    if (parms.getParameter('description', null) == null && msh.description != null) { parms.push('--description="' + ('' + msh.description).split('"').join('') + '"'); }
    if (parms.getParameter('displayName', null) == null && msh.displayName != null) { parms.push('--displayName="' + ('' + msh.displayName).split('"').join('') + '"'); }
    if (parms.getParameter('companyName', null) == null && msh.companyName != null) { parms.push('--companyName="' + ('' + msh.companyName).split('"').join('') + '"'); }

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
        status: typeof child.exitCode === 'number' ? child.exitCode : 0,
        stdout: child.stdout.str,
        stderr: child.stderr.str
    });
}
function sanitizeWindowsLifecycleManifestValue(value)
{
    if (value == null) { return ''; }
    return ('' + value).split('\r').join(' ').split('\n').join(' ').split('"').join('');
}
function getWindowsSystemRundll32Path()
{
    var fs = require('fs');
    var rundll32Path = getOfficialSystem32Path('rundll32.exe');
    if (rundll32Path == null || rundll32Path.length == 0)
    {
        throw new Error('GetSystemDirectoryW did not resolve rundll32.exe for Windows lifecycle.');
    }
    if (!fs.existsSync(rundll32Path))
    {
        throw new Error('rundll32.exe was not found at SSOT system path: ' + rundll32Path);
    }
    return (rundll32Path);
}
function assertWindowsLifecycleActionName(actionName)
{
    switch (actionName)
    {
        case 'install':
        case 'update':
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
    if (parms != null && typeof parms.getParameter == 'function')
    {
        serviceName = parms.getParameter('meshServiceName', null);
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
function readWindowsInstalledServiceDllPath(parms)
{
    var serviceName = getWindowsLifecycleServiceName(parms);
    var reg, rawPath;
    if (serviceName == null || serviceName.length == 0) { return (null); }
    try
    {
        reg = require('win-registry');
        rawPath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + serviceName + '\\Parameters', 'ServiceDll');
    }
    catch (e) { return (null); }
    return (expandWindowsEnvironmentStrings(rawPath));
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
    try { randomPart = require('crypto').randomBytes(8).toString('hex'); } catch (randomError) { randomPart = Math.floor(Math.random() * 0xFFFFFFFF).toString(16); }
    workDir = tempDir + '\\mesh-lifecycle-' + process.pid + '-' + Date.now() + '-' + randomPart;
    fs.mkdirSync(workDir);
    outPath = workDir + '\\host.dll';
    fs.writeFileSync(outPath, payload);
    if (cleanupPaths != null) { cleanupPaths.push(outPath); cleanupPaths.push(workDir); }
    return (outPath);
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
    return (actionName == 'install' || actionName == 'update' || actionName == 'validate-package');
}
function findWindowsLifecycleServiceDll(targetBinary, actionName, parms, cleanupPaths)
{
    var fs = require('fs');
    var installedDll, embeddedDll;

    if (isWindowsInstalledLifecycleAction(actionName))
    {
        installedDll = readWindowsInstalledServiceDllPath(parms);
        if (installedDll != null && fs.existsSync(installedDll)) { return (installedDll); }
        throw new Error('Windows rundll32 lifecycle requires the installed service ServiceDll for action: ' + actionName);
    }

    if (isWindowsPackageLifecycleAction(actionName))
    {
        embeddedDll = extractWindowsEmbeddedLifecycleDll(targetBinary, cleanupPaths);
        if (embeddedDll != null && fs.existsSync(embeddedDll)) { return (embeddedDll); }
        throw new Error('Windows rundll32 lifecycle requires the embedded lifecycle DLL resource for action: ' + actionName);
    }

    throw new Error('Unsupported Windows lifecycle action: ' + actionName);
}
function writeWindowsLifecycleManifest(actionName, targetBinary, sourceDll, parms)
{
    var fs = require('fs');
    var tempDir = process.env.TEMP || process.env.TMP;
    var manifestPath, lines;
    if (tempDir == null || tempDir.length == 0)
    {
        throw new Error('TEMP is not available; cannot write Windows lifecycle manifest.');
    }
    manifestPath = tempDir + '\\mesh-lifecycle-' + process.pid + '-' + Date.now() + '.ini';
    lines = [
        '[Lifecycle]',
        'Action=' + actionName,
        'SourceExe=' + sanitizeWindowsLifecycleManifestValue(targetBinary),
        'SourceDll=' + sanitizeWindowsLifecycleManifestValue(sourceDll),
        'DisplayName=' + sanitizeWindowsLifecycleManifestValue(parms.getParameter('displayName', '')),
        'Description=' + sanitizeWindowsLifecycleManifestValue(parms.getParameter('description', '')),
        'RequireConfig=1',
        ''
    ];
    fs.writeFileSync(manifestPath, lines.join('\r\n'));
    return (manifestPath);
}
function runWindowsNativeLifecycle(actionName, parms, gOptions)
{
    var args, result, runError = null, manifestPath = null, cleanupPaths = [];
    var targetBinary = process.execPath;
    var rundll32Path, sourceDll;
    var skipExit = parseInt(parms.getParameter('__skipExit', 0)) != 0;
    if (gOptions != null && gOptions.binary != null) { targetBinary = gOptions.binary; }

    assertWindowsLifecycleActionName(actionName);
    prepareWindowsNativeLifecycleParameters(parms);

    try
    {
        rundll32Path = getWindowsSystemRundll32Path();
        sourceDll = findWindowsLifecycleServiceDll(targetBinary, actionName, parms, cleanupPaths);
        manifestPath = writeWindowsLifecycleManifest(actionName, targetBinary, sourceDll, parms);
        args = [sourceDll + ',MeshLifecycleHostW', manifestPath];
        result = runWindowsChildProcessAndCapture(rundll32Path, args, { cwd: getPathDirName(targetBinary) });
        if (result.stdout && result.stdout.length > 0) { process.stdout.write(result.stdout); }
        if (result.stderr && result.stderr.length > 0) { process.stderr.write(result.stderr); }
        if (result.status !== 0)
        {
            var exitError = new Error('Rundll32 Windows lifecycle command failed: ' + actionName + ' (exit code ' + result.status + ')');
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
        for (var cleanupIndex = 0; cleanupIndex < cleanupPaths.length; ++cleanupIndex)
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

try
{
    // This property is a polyfill for an Array, to fetch the specified element if it exists, removing the surrounding quotes if they are there
    Object.defineProperty(Array.prototype, 'getParameterEx',
        {
            value: function (name, defaultValue)
            {
                var i, ret;
                for (i = 0; i < this.length; ++i)
                {
                    if (this[i].startsWith(name + '='))
                    {
                        ret = this[i].substring(name.length + 1);
                        if (ret.startsWith('"')) { ret = ret.substring(1, ret.length - 1); }
                        return (ret);
                    }
                }
                return (defaultValue);
            }
        });

    // This property is a polyfill for an Array, to fetch the specified element if it exists 
    Object.defineProperty(Array.prototype, 'getParameter',
        {
            value: function (name, defaultValue)
            {
                return (this.getParameterEx('--' + name, defaultValue));
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to fetch the index of the specified element, if it exists
    Object.defineProperty(Array.prototype, 'getParameterIndex',
        {
            value: function (name)
            {
                var i;
                for (i = 0; i < this.length; ++i)
                {
                    if (this[i].startsWith('--' + name + '='))
                    {
                        return (i);
                    }
                }
                return (-1);
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to remove the specified element, if it exists
    Object.defineProperty(Array.prototype, 'deleteParameter',
        {
            value: function (name)
            {
                var i = this.getParameterIndex(name);
                if(i>=0)
                {
                    this.splice(i, 1);
                }
            }
        });
}
catch(x)
{ }
try
{
    // This property is a polyfill for an Array, to to fetch the value YY of an element XX in the format --XX=YY, if it exists
    Object.defineProperty(Array.prototype, 'getParameterValue',
        {
            value: function (i)
            {
                if (i < 0 || i >= this.length || typeof this[i] != 'string') { return null; }
                var eqIdx = this[i].indexOf('=');
                if (eqIdx < 0) { return this[i]; }
                var ret = this[i].substring(eqIdx + 1);
                if (ret.startsWith('"')) { ret = ret.substring(1, ret.length - 1); }
                return (ret);
            }
        });
}
catch(x)
{ }

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
    if (parms.getParameter('description', null) == null && msh.description != null) { parms.push('--description="' + ('' + msh.description).split('"').join('') + '"'); }
    if (parms.getParameter('displayName', null) == null && msh.displayName != null) { parms.push('--displayName="' + ('' + msh.displayName).split('"').join('') + '"'); }
    if (parms.getParameter('companyName', null) == null && msh.companyName != null) { parms.push('--companyName="' + ('' + msh.companyName).split('"').join('') + '"'); }

    if (msh.fileName != null)
    {
        // This converts the --fileName parameter of the installer, to the --target=XXX format required by service-manager.js
        var i = parms.getParameterIndex('fileName');
        if(i>=0)
        {
            parms.splice(i, 1);
        }
        parms.push('--target="' + msh.fileName + '"');
    }

    if (parms.getParameter('meshServiceName', null) == null)
    {
        if(msh.meshServiceName != null)
        {
            // This adds the specified service name, to be consumed by service-manager.js
            parms.push('--meshServiceName="' + msh.meshServiceName + '"');
        }
        else
        {
            // Still no meshServiceName specified... Let's also check installed services...
            var tmp = 'meshagent';
            try
            {
                tmp = require('_agentNodeId').serviceName();
            }
            catch(xx)
            {
            }

            // The default is 'meshagent' on non-Windows service-manager paths.
            if(tmp != 'meshagent')
            {
                parms.push('--meshServiceName="' + tmp + '"');
            }
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
    var targetx = params.getParameterIndex('target');
    if (targetx >= 0)
    {
        // Let's remove any embedded spaces in 'target' as that can mess up some OSes
        target = params.getParameterValue(targetx);
        params.splice(targetx, 1);
        target = target.split(' ').join('');
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
            name: params.getParameter('meshServiceName', 'meshagent'),
            target: target==null?'meshagent':target,
            servicePath: process.execPath,
            startType: 'AUTO_START',
            parameters: params,
            _installer: true
        };
    options.displayName = params.getParameter('displayName', options.name); params.deleteParameter('displayName');
    options.description = params.getParameter('description', options.name + ' background service'); params.deleteParameter('description');

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
    if ((i = params.indexOf('--copy-msh="1"')) >= 0)
    {
        var mshFile = process.execPath + '.msh';
        if (options.files == null) { options.files = []; }
        var newtarget = (process.platform == 'linux' && require('service-manager').manager.getServiceType() == 'systemd') ? options.target.split("'").join('-') : options.target;
        options.files.push({ source: mshFile, newName: newtarget + '.msh' });
        options.parameters.splice(i, 1);
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
    if ((i = options.parameters.getParameterIndex('installPath')) >= 0)
    {
        options.installPath = options.parameters.getParameterValue(i);
        options.installInPlace = false;
        options.parameters.splice(i, 1);
    }

    // If companyName was specified, we're going to move it into the structure
    if ((i = options.parameters.getParameterIndex('companyName')) >= 0)
    {
        options.companyName = options.parameters.getParameterValue(i);
        options.parameters.splice(i, 1);
    }

    if (global.gOptions != null && global.gOptions.noParams === true) { options.parameters = []; }

    try
    {
        // Let's actually install the service
        require('service-manager').manager.installService(options);
        process.stdout.write(' [DONE]\n');
    }
    catch(sie)
    {
        process.stdout.write(' [ERROR] ' + sie);
        process.exit();
    }
    var svc = require('service-manager').manager.getService(options.name);

    // macOS needs a LaunchAgent to help with some usages that need to run from within the user session, 
    // so we can setup ourselves to accomplish that.
    if (process.platform == 'darwin')
    {
        svc.load();
        process.stdout.write('   -> setting up launch agent...');
        try
        {
            require('service-manager').manager.installLaunchAgent(
                {
                    name: options.name,
                    servicePath: svc.appLocation(),
                    startType: 'AUTO_START',
                    sessionTypes: ['LoginWindow'],
                    parameters: ['-kvm1']
                });
            process.stdout.write(' [DONE]\n');
        }
        catch (sie)
        {
            process.stdout.write(' [ERROR] ' + sie);
        }
    }

    // Let's try to start the service that we just installed (non-Windows platforms)
    process.stdout.write('   -> Starting service...');
    try
    {
        svc.start();
        process.stdout.write(' [OK]\n');
    }
    catch (ee)
    {
        process.stdout.write(' [ERROR]\n');
    }

    if (parseInt(params.getParameter('__skipExit', 0)) == 0)
    {
        process.exit();
    }
}

// The last step in uninstalling a service
function uninstallService3(params)
{
    // macOS has a LaunchAgent, that we need to uninstall
    if (process.platform == 'darwin')
    {
        process.stdout.write('   -> Uninstalling launch agent...');
        try
        {
            var launchagent = require('service-manager').manager.getLaunchAgent(params.getParameter('meshServiceName', 'meshagent'));
            launchagent.unload();
            require('fs').unlinkSync(launchagent.plist);
            process.stdout.write(' [DONE]\n');
        }
        catch (e)
        {
            process.stdout.write(' [ERROR]\n');
        }
    }

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
    var serviceName = params.getParameter('meshServiceName', 'meshagent'); // get the service name, using the provided defaults if not specified

    // Remove the .msh file if present
    try { require('fs').unlinkSync(msh); } catch (mshe) { }
    if ((i = params.indexOf('__skipBinaryDelete')) >= 0)
    {
        // We will skip deleting of the actual binary, if this option was provided. 
        // This will happen if we try to install the service to a location where we are running the installer from.
        params.splice(i, 1);
        uninstallOptions = { skipDeleteBinary: true };
    }
    if (params && params.includes('--_deleteData="1"'))
    {
        // This will facilitate cleanup of the files associated with the agent
        dataFolder = params.getParameterEx('_workingDir', null);
        appPrefix = params.getParameterEx('_appPrefix', null);
    }

    process.stdout.write('   -> Uninstalling previous installation...');
    try
    {
        // Let's actually try to uninstall the service
        require('service-manager').manager.uninstallService(serviceName, uninstallOptions);
        process.stdout.write(' [DONE]\n');

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
                        try { fs.unlinkSync(dataFolder + '/' + cleanupEntries[ci]); } catch (ce) { }
                    }
                }
                try { fs.unlinkSync(dataFolder + '/DAIPC'); } catch (ce) { }
                try { fs.rmdirSync(dataFolder); } catch (ce) { }
                try { fs.rmdirSync(levelUp); } catch (ce) { }
            } catch (ce) { }

            process.stdout.write(' [DONE]\n');
        }
    }
    catch (e)
    {
        process.stdout.write(' [ERROR]\n');
    }

    // Check for secondary agent
    try
    {
        process.stdout.write('   -> Checking for secondary agent...');
        var s = require('service-manager').manager.getService(serviceName + 'Diagnostic');
        var loc = s.appLocation();
        s.close();
        process.stdout.write(' [FOUND]\n');
        process.stdout.write('      -> Uninstalling secondary agent...');
        secondaryagent = true;
        try
        {
            require('service-manager').manager.uninstallService(serviceName + 'Diagnostic');
            process.stdout.write(' [DONE]\n');
        }
        catch (e)
        {
            process.stdout.write(' [ERROR]\n');
        }
    }
    catch (e)
    {
        process.stdout.write(' [NONE]\n');
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
            uninstallService3(this._params);
        }, function ()
        {
            process.stdout.write(' [ERROR]\n');
            uninstallService3(this._params);
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
    // Before we uninstall, we need to fetch the service from service-manager.js
    var svc = require('service-manager').manager.getService(params.getParameter('meshServiceName', 'meshagent'));

    // We can calculate what the .msh file location is, based on the appLocation of the service
    var msh = svc.appLocation() + '.msh';

    // Let's try to stop the service if we think it might be running
    if (svc.isRunning == null || svc.isRunning())
    {
        process.stdout.write('   -> Stopping Service...');
        if (process.platform == 'darwin')
        {
            // macOS requries us to unload the service
            svc.unload();
        }
        else
        {
            svc.stop();
        }
        process.stdout.write(' [STOPPED]\n');
        uninstallService2(params, msh);
    }
    else
    {
        uninstallService2(params, msh);
    }
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
    try { parms = JSON.parse(jsonString); } catch (e) { process.stdout.write('ERROR: invalid JSON for fullUninstall: ' + e.message + '\n'); return; }
    if (WINDOWS_SVCHOST_ONLY)
    {
        runWindowsNativeLifecycle('uninstall', parms, null);
        return;
    }
    if (parseInt(parms.getParameter('verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED); // IF verbose is disabled(default), we will no-op console.log
    }
    else
    {
        console.setInfoLevel(1); // IF verbose is specified, we will show info level 1 messages
    }
    parms.push('_stop'); // Since we are intending to halt after uninstalling the service, we specify this, since we are re-using the uninstall code with the installer.

    checkParameters(parms); // Perform some checks on the passed in parameters

    var name = parms.getParameter('meshServiceName', 'meshagent'); // Set the service name, using the defaults if not specified

    var loc = null;
    // Check for a previous installation of the service
    try
    {
        process.stdout.write('...Checking for previous installation of "' + name + '"');
        var s = require('service-manager').manager.getService(name);
        loc = s.appLocation();
        var appPrefix = loc.split('/').pop();

        parms.push('_workingDir=' + s.appWorkingDirectory());
        parms.push('_appPrefix=' + appPrefix);

        s.close();
    }
    catch (e)
    {
        // No previous installation was found, so we can just exit
        process.stdout.write(' [NONE]\n');
        process.exit();
    }
    serviceExists(loc, parms);
}

// Entry point for Windows full install lifecycle requests, using JSON string
function fullInstall(jsonString, gOptions)
{
    var parms;
    try { parms = JSON.parse(jsonString); } catch (e) { process.stdout.write('ERROR: invalid JSON for fullInstall: ' + e.message + '\n'); return; }
    if (WINDOWS_SVCHOST_ONLY)
    {
        runWindowsNativeLifecycle('install', parms, gOptions);
        return;
    }
    fullInstallEx(parms, gOptions);
}

// Entry point for Windows full install lifecycle requests, using JSON object
function fullInstallEx(parms, gOptions)
{
    if (WINDOWS_SVCHOST_ONLY)
    {
        runWindowsNativeLifecycle('install', parms, gOptions);
        return;
    }
    if (gOptions != null) { global.gOptions = gOptions; }

    // Perform some checks on the specified parameters
    checkParameters(parms);

    var loc = null;
    var i;
    var name = parms.getParameter('meshServiceName', 'meshagent'); // Set the service name, using defaults if not specified
    name = name.split(' ').join('_');

    // No-op console.log() if verbose is not specified, otherwise set the verbosity level to level 1
    if (parseInt(parms.getParameter('verbose', 0)) == 0)
    {
        console.setDestination(console.Destinations.DISABLED);
    }
    else
    {
        console.setInfoLevel(1); 
    }

    // Check for a previous installation of the service
    try
    {
        process.stdout.write('...Checking for previous installation of "' + name + '"');
        var s = require('service-manager').manager.getService(name);
        loc = s.appLocation();

        global._workingpath = s.appWorkingDirectory();
        console.info1('');
        console.info1('Previous Working Path: ' + global._workingpath);
        s.close();
    }
    catch (e)
    {
        // No previous installation was found, so we can continue with installation
        process.stdout.write(' [NONE]\n');
        installService(parms);
        return;
    }
    if (process.execPath == loc)
    {
        parms.push('__skipBinaryDelete'); // If the installer is running from the installed service path, skip deleting the binary
    }
    serviceExists(loc, parms); // Previous installation was found, so we need to do some extra processing before we continue with installation
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
        if (!(parms instanceof Array))
        {
            throw new Error('Native Windows update parameter payload must be an array.');
        }
    }
    if (typeof(parms.getParameterIndex) == 'function')
    {
        var px = parms.getParameterIndex('fakeUpdate');
        if (px >= 0) { parms.splice(px, 1); }
    }
    return (parms);
}

function getWindowsNativeUpdateSource(parms)
{
    var updateSource = null;
    if (parms != null && typeof(parms.getParameter) == 'function')
    {
        updateSource = parms.getParameter('update-source', null);
        if (updateSource == null || updateSource.length == 0)
        {
            updateSource = parms.getParameter('updateSource', null);
        }
    }
    if (updateSource == null) { return (null); }
    updateSource = '' + updateSource;
    return (updateSource.length > 0 ? updateSource : null);
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
    try
    {
        var parms = parseWindowsNativeUpdateParameters(b64);
        var updateSource = getWindowsNativeUpdateSource(parms);
        runWindowsNativeLifecycle('update', parms, updateSource != null ? { binary: updateSource } : null);
    }
    catch (e)
    {
        process.stdout.write('Native Windows update failed: ' + e.message + '\n');
        process.exit(1);
    }
}

function windowsNativeConsoleUpdate()
{
    throw new Error('Windows console self-update is disabled. Windows updates must use the native service lifecycle.');
}


// Non-Windows helper function to perform a self-update. Windows uses the native rundll32 lifecycle.
function sys_update(isservice, b64)
{
    if (process.platform == 'win32') { return (windowsNativeUpdate(isservice, b64)); }

    // This is run on the 'updated' agent. 
    
    var service = null;
    var serviceLocation = "";
    var px;

    if (isservice)
    {
        var parm = b64 != null ? JSON.parse(Buffer.from(b64, 'base64').toString()) : null;
        if (parm != null)
        {
            console.info1('sys_update(' + isservice + ', ' + JSON.stringify(parm) + ')');
            if ((px = parm.getParameterIndex('fakeUpdate')) >= 0)
            {
                console.info1('Removing "fakeUpdate" parameter');
                parm.splice(px, 1);
            }
        }

        //
        // Service  Mode
        //

        // Check if we have sufficient permission
        if (!require('user-sessions').isRoot())
        {
            // We don't have enough permissions, so copying the binary will likely fail, and we can't start...
            // This is just to prevent looping, because agentcore.c should not call us in this scenario
            console.log('* insufficient permission to continue with update');
            process._exit();
            return;
        }
        var servicename = parm != null ? parm.getParameter('meshServiceName', 'meshagent') : 'meshagent';
        try
        {
            service = require('service-manager').manager.getService(servicename)
            serviceLocation = service.appLocation();
            console.log(' Updating service: ' + servicename);
        }
        catch (f)
        {
            // Check to see if we can figure out the service name before we fail
            var old = process.execPath.substring(0, process.execPath.length - 7);
            var child = require('child_process').execFile(old, [getPathBaseName(old), '-name']);
            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
            child.waitExit();
              
            if (child.stdout.str.trim() == '' && b64 == null) { child.stdout.str = 'Mesh Agent'; }
            if (child.stdout.str.trim() != '')
            {
                if (child.stdout.str.trim().split('\n').length > 1) { child.stdout.str = 'Mesh Agent'; }
                try
                {
                    service = require('service-manager').manager.getService(child.stdout.str.trim())
                    serviceLocation = service.appLocation();
                    console.log(' Updating service: ' + child.stdout.str.trim());
                }
                catch (ff)
                {
                    console.log(' * ' + servicename + ' SERVICE NOT FOUND *');
                    console.log(' * ' + child.stdout.str.trim() + ' SERVICE NOT FOUND *');
                    process._exit();
                }
            }
            else
            {
                console.log(' * ' + servicename + ' SERVICE NOT FOUND *');
                process._exit();
            }
        }
    }

    if (!global._interval)
    {
        global._interval = setInterval(sys_update, 60000, isservice, b64);
    }

    if (isservice === false)
    {
        //
        // Console Mode
        //
        serviceLocation = process.execPath.substring(0, process.execPath.length - 7);

        if (serviceLocation != process.execPath)
        {
            try
            {
                require('fs').copyFileSync(process.execPath, serviceLocation);
            }
            catch (ce)
            {
                console.log('\nAn error occured while updating agent.');
                process.exit();
            }
        }

        // Copied agent binary... Need to start agent in console mode
        console.log('\nAgent update complete... Please re-start agent.');
        process.exit();
    }


    service.stop().finally(function ()
    {
        require('process-manager').enumerateProcesses().then(function (proc)
        {
            for (var p in proc)
            {
                if (proc[p].path == serviceLocation)
                {
                    process.kill(proc[p].pid);
                }
            }

            try
            {
                require('fs').copyFileSync(process.execPath, serviceLocation);
            }
            catch (ce)
            {
                console.log('Could not copy file.. Trying again in 60 seconds');
                service.close();
                return;
            }

            console.log('Agent update complete. Starting service...');
            service.start();
            process._exit();
        });
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
    child.waitExit();

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
