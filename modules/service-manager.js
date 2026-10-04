/*
Copyright 2018 Intel Corporation

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
var promise = require('promise');
var systemd_escape = null;
var WINDOWS_SERVICE_MANAGER_INSTALL_DISABLED = 'Windows service-manager install is disabled. Use the rundll32 MeshLifecycleHostW manifest path.';
var WINDOWS_SERVICE_MANAGER_UNINSTALL_DISABLED = 'Windows service-manager uninstall is disabled. Use the rundll32 MeshLifecycleHostW manifest path.';

function windowsServiceManagerLifecycleDisabledError(operation)
{
    switch (operation)
    {
        case 'install':
            return (WINDOWS_SERVICE_MANAGER_INSTALL_DISABLED);
        case 'uninstall':
            return (WINDOWS_SERVICE_MANAGER_UNINSTALL_DISABLED);
        default:
            return ('Windows service-manager lifecycle operation is disabled. Use the rundll32 MeshLifecycleHostW manifest path.');
    }
}

function serviceNotFound(name)
{
    var error = new Error('Service not found: ' + name);
    error.code = 'ENOENT';
    return error;
}
function windowsServiceError(operation, code)
{
    var error = new Error(operation + ' failed (Windows error ' + code + ')');
    error.code = code == 1060 ? 'ENOENT' : 'EWIN32';
    error.win32Error = code;
    return error;
}
function windowsServiceExecutable(command)
{
    command = ('' + command).replace(/%([^%]+)%/g, function (match, name)
    {
        for (var key in process.env) { if (key.toLowerCase() == name.toLowerCase()) { return process.env[key]; } }
        throw new Error('Unresolved service path environment variable: ' + name);
    }).trim();
    var match = command.charAt(0) == '"' ? /^"([^"\r\n]+)"(?:\s|$)/.exec(command) : /^(.+?\.exe)(?:\s|$)/i.exec(command);
    if (!match || !/\.exe$/i.test(match[1])) { throw new Error('Invalid service executable command line: ' + command); }
    return match[1];
}

function readSystemdDirective(file, name)
{
    var lines = require('fs').readFileSync(file).toString().replace(/\\\r?\n/g, ' ').split(/\r?\n/);
    var value = null;
    for (var i = 0; i < lines.length; ++i)
    {
        var match = /^\s*([A-Za-z]+)\s*=(.*)$/.exec(lines[i]);
        if (match && match[1] == name) { value = match[2].trim(); }
    }
    return value;
}
function unresolvedServicePath(file)
{
    var error = new Error('Unresolved service executable in ' + file);
    error.code = 'EUNRESOLVEDPATH';
    return error;
}
function systemdExecutable(file)
{
    var value = readSystemdDirective(file, 'ExecStart');
    if (!value) { throw unresolvedServicePath(file); }
    value = value.replace(/^[-@:+!]+/, '');
    var match = /^(?:"((?:\\.|[^"\\])*)"|'([^']*)'|(\S+))/.exec(value);
    if (!match) { throw unresolvedServicePath(file); }
    var executable = (match[1] || match[2] || match[3]).replace(/\\x([0-9a-f]{2})/gi, function (_, hex) { return String.fromCharCode(parseInt(hex, 16)); }).replace(/\\([\\"'])/g, '$1');
    if (executable.charAt(0) != '/' || executable.indexOf('%') >= 0) { throw unresolvedServicePath(file); }
    return executable;
}

// Use argv directly so historical service keys containing spaces/backslashes survive intact.
function runSystemctl(args)
{
    var fs = require('fs');
    var executable = fs.existsSync('/bin/systemctl') ? '/bin/systemctl' : '/usr/bin/systemctl';
    var child = require('child_process').execFile(executable, ['systemctl'].concat(args));
    var output = '', errors = '', code = null;
    child.stdout.on('data', function (chunk) { output += chunk.toString(); });
    child.stderr.on('data', function (chunk) { errors += chunk.toString(); });
    child.on('exit', function (status) { code = status; });
    child.waitExit(120000);
    if (code == null) { try { child.kill(); } catch (e) { } throw new Error('systemctl timed out: ' + args[0]); }
    if (code !== 0) { throw new Error('systemctl ' + args[0] + ' failed (' + code + '): ' + errors.trim()); }
    return output;
}
function systemdIsRunning(name)
{
    var output = runSystemctl(['show', '--property=ActiveState', '--property=MainPID', name + '.service']);
    var state = /^ActiveState=(.*)$/m.exec(output);
    var pid = /^MainPID=(\d+)$/m.exec(output);
    if (!state || !pid) { throw new Error('Unable to verify service state: ' + name); }
    if (parseInt(pid[1]) != 0) { return true; }
    if (state[1] == 'inactive' || state[1] == 'failed') { return false; }
    if (/^(active|activating|deactivating|reloading|refreshing)$/.test(state[1])) { return true; }
    throw new Error('Unrecognized service state: ' + state[1]);
}

function failureActionToInteger(action)
{
    var ret;
    switch(action)
    {
        default:
        case 'NONE':
            ret=0;
            break;
        case 'SERVICE_RESTART':
            ret=1;
            break;
        case 'REBOOT':
            ret=2;
            break;
    }
    return(ret);
}

function extractFileName(filePath)
{
    if (typeof (filePath) == 'string')
    {
        var tokens = filePath.split('\\').join('/').split('/');
        var name;

        while ((name = tokens.pop()) == '');
        return (name);
    }
    else
    {
        return(filePath.newName)
    }
}
function extractFileSource(filePath)
{
    return (typeof (filePath) == 'string' ? filePath : filePath.source);
}

function prepareFolders(folderPath)
{
    var dlmtr = process.platform == 'win32' ? '\\' : '/';

    var tokens = folderPath.split(dlmtr);
    var path = null;

    while (tokens.length>0)
    {
        path = (path == null ? tokens.shift() : (path + dlmtr + tokens.shift()));
        if (path.indexOf(process.platform == 'win32' ? '\\' : '/') < 0) { continue; }
        try { require('fs').mkdirSync(path); } catch (e) { if (e.code !== 'EEXIST') { throw e; } }
    }
}

function parseServiceStatus(token)
{
    var j = {};
    var serviceType = token.Deref(0, 4).IntVal;
    j.isFileSystemDriver = ((serviceType & 0x00000002) == 0x00000002);
    j.isKernelDriver = ((serviceType & 0x00000001) == 0x00000001);
    j.isSharedProcess = ((serviceType & 0x00000020) == 0x00000020);
    j.isOwnProcess = ((serviceType & 0x00000010) == 0x00000010);
    j.isInteractive = ((serviceType & 0x00000100) == 0x00000100);
    j.waitHint = token.Deref((6 * 4), 4).toBuffer().readUInt32LE();
    j.rawState = token.Deref((1 * 4), 4).toBuffer().readUInt32LE();
    switch (j.rawState)
    {
        case 0x00000005:
            j.state = 'CONTINUE_PENDING';
            break;
        case 0x00000006:
            j.state = 'PAUSE_PENDING';
            break;
        case 0x00000007:
            j.state = 'PAUSED';
            break;
        case 0x00000004:
            j.state = 'RUNNING';
            break;
        case 0x00000002:
            j.state = 'START_PENDING';
            break;
        case 0x00000003:
            j.state = 'STOP_PENDING';
            break;
        case 0x00000001:
            j.state = 'STOPPED';
            break;
    }
    var controlsAccepted = token.Deref((2 * 4), 4).toBuffer().readUInt32LE();
    j.controlsAccepted = [];
    if ((controlsAccepted & 0x00000010) == 0x00000010)
    {
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDADD');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDREMOVE');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDENABLE');
        j.controlsAccepted.push('SERVICE_CONTROL_NETBINDDISABLE');
    }
    if ((controlsAccepted & 0x00000008) == 0x00000008) { j.controlsAccepted.push('SERVICE_CONTROL_PARAMCHANGE'); }
    if ((controlsAccepted & 0x00000002) == 0x00000002) { j.controlsAccepted.push('SERVICE_CONTROL_PAUSE'); j.controlsAccepted.push('SERVICE_CONTROL_CONTINUE'); }
    if ((controlsAccepted & 0x00000100) == 0x00000100) { j.controlsAccepted.push('SERVICE_CONTROL_PRESHUTDOWN'); }
    if ((controlsAccepted & 0x00000004) == 0x00000004) { j.controlsAccepted.push('SERVICE_CONTROL_SHUTDOWN'); }
    if ((controlsAccepted & 0x00000001) == 0x00000001) { j.controlsAccepted.push('SERVICE_CONTROL_STOP'); }
    if ((controlsAccepted & 0x00000020) == 0x00000020) { j.controlsAccepted.push('SERVICE_CONTROL_HARDWAREPROFILECHANGE'); }
    if ((controlsAccepted & 0x00000040) == 0x00000040) { j.controlsAccepted.push('SERVICE_CONTROL_POWEREVENT'); }
    if ((controlsAccepted & 0x00000080) == 0x00000080) { j.controlsAccepted.push('SERVICE_CONTROL_SESSIONCHANGE'); }
    j.pid = token.Deref((7 * 4), 4).toBuffer().readUInt32LE();
    return (j);
}

if (process.platform == 'linux')
{
    function _upstart_GetServiceTable()
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("initctl list | tr '\n' '`' | awk -F'`' '");
        child.stdin.write('{');
        child.stdin.write('   printf "{"; ');
        child.stdin.write('   for(i=1;i<NF;++i) ');
        child.stdin.write('   {');
        child.stdin.write('      c=split($i,name,","); ');
        child.stdin.write('      c2=split(name[1],state," "); ');
        child.stdin.write('      sname=substr(name[1],0,length(name[1])-length(state[c2])-1); ');
        child.stdin.write('      split(state[c2],rstate,"/"); ');
        child.stdin.write('      rs = rstate[2]=="running"?"RUNNING":"STOPPED";');
        child.stdin.write('      spid=""; ');
        child.stdin.write('      if(c==2) ');
        child.stdin.write('      { ');
        child.stdin.write('         split(name[2],pid," "); ');
        child.stdin.write('         spid=pid[2]; ');
        child.stdin.write('      } ');
        child.stdin.write('      printf "%s\\"%s\\": {\\"state\\": \\"%s\\", \\"pid\\":\\"%s\\"}",(i==1?"":","),sname,rs,spid; ');
        child.stdin.write('   } ');
        child.stdin.write('   printf "}"; ');
        child.stdin.write("}'\nexit\n");
        child.waitExit();
        var ret = {};
        try
        {
            ret = JSON.parse(child.stdout.str);
        }
        catch(e)
        {
        }
        return (ret);
    }
    function _systemd_GetServiceTable()
    {
        var child = require('child_process').execFile('/bin/sh', ['sh']);
        child.stderr.str = ''; child.stderr.on('data', function (c) { this.str += c.toString(); });
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.stdin.write("systemctl --type=service --state=running | grep .service | tr '\n' '`' | awk -F'`' '");
        child.stdin.write('{');
        child.stdin.write('   printf "{"; ');
        child.stdin.write('   for(i=1;i<NF;++i) ');
        child.stdin.write('   {');
        child.stdin.write('      c=split($i,name," "); ');
        child.stdin.write('      printf "%s\\"%s\\": \\"%s\\"", (i==1?"":","), name[1], name[4]; ');
        child.stdin.write('   } ');
        child.stdin.write('   printf "}"; ');
        child.stdin.write("}'\nexit\n");
        child.waitExit();

        var ret = {};
        try
        {
            ret = JSON.parse(child.stdout.str);
        }
        catch (e)
        {
        }
        return (ret);
    }
}







if (process.platform == 'darwin')
{
    function macPlistString(value)
    {
        value = '' + value;
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) { throw new Error('Invalid control character in launchd configuration'); }
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
    }
    function macServiceName(value)
    {
        if (typeof value != 'string' || !value.length || value == '.' || value == '..' || /[\/\x00-\x1f]/.test(value))
        { throw new Error('Invalid service name'); }
        return value;
    }
    function macWritePlist(file, contents)
    {
        var fs = require('fs'), temporary = file + '.' + process.pid + '.tmp', fd = null, created = false;
        try
        {
            // Exclusive creation avoids following an existing staging symlink.
            fd = fs.openSync(temporary, 'wx');
            created = true;
            fs.chmodSync(temporary, 384);
            fs.writeSync(fd, contents);
            var closing = fd; fd = null;
            fs.closeSync(closing);
            macServiceCommand('/usr/bin/plutil', ['-lint', '--', temporary]);
            fs.chmodSync(temporary, 420);
            fs.renameSync(temporary, file);
        }
        catch (e)
        {
            if (fd != null) { try { fs.closeSync(fd); } catch (ignored) { } }
            if (created) { try { fs.unlinkSync(temporary); } catch (ignored) { } }
            throw e;
        }
    }
    function macPrepareFolders(folder, created)
    {
        var fs = require('fs'), path = '';
        if (typeof folder != 'string' || folder.charAt(0) != '/' || /[\x00-\x1f]/.test(folder)) { throw new Error('Invalid installation directory'); }
        var parts = folder.split('/');
        for (var i = 1; i < parts.length; ++i)
        {
            if (!parts[i]) { continue; }
            if (parts[i] == '.' || parts[i] == '..') { throw new Error('Installation directory must not contain dot segments'); }
            path += '/' + parts[i];
            if (fs.existsSync(path))
            {
                if (!fs.statSync(path).isDirectory()) { throw new Error('Not a directory: ' + path); }
            }
            else { fs.mkdirSync(path); if (created) { created.push(path); } }
        }
    }
    function macBuildLaunchdPlist(options, agent)
    {
        macServiceName(options.name);
        var executable = agent ? options.servicePath : options.installPath + options.target;
        var directory = options.workingDirectory || (agent ? executable.substring(0, executable.lastIndexOf('/')) || '/' : options.installPath);
        if (typeof executable != 'string' || executable.charAt(0) != '/' || directory.charAt(0) != '/') { throw new Error('Launchd requires absolute program and working directory paths'); }
        var parameters = options.parameters || [];
        if (!Array.isArray(parameters)) { throw new Error('Invalid launchd parameters'); }
        var xml = '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>';
        xml += '<key>Label</key><string>' + macPlistString(options.name + (agent ? '-launchagent' : '')) + '</string>';
        xml += '<key>ProgramArguments</key><array><string>' + macPlistString(executable) + '</string>';
        for (var i = 0; i < parameters.length; ++i)
        {
            if (typeof parameters[i] != 'string') { throw new Error('Launchd arguments must be strings'); }
            xml += '<string>' + macPlistString(parameters[i]) + '</string>';
        }
        xml += '</array><key>WorkingDirectory</key><string>' + macPlistString(directory) + '</string>';
        var paths = { stdout: 'StandardOutPath', stderr: 'StandardErrorPath' };
        for (var key in paths)
        {
            if (options[key] != null)
            {
                if (typeof options[key] != 'string' || options[key].charAt(0) != '/') { throw new Error('Invalid launchd log path'); }
                xml += '<key>' + paths[key] + '</key><string>' + macPlistString(options[key]) + '</string>';
            }
        }
        if (agent && options.sessionTypes && options.sessionTypes.length)
        {
            xml += '<key>LimitLoadToSessionType</key><array>';
            for (var i = 0; i < options.sessionTypes.length; ++i)
            {
                if (['Aqua', 'LoginWindow', 'Background', 'StandardIO', 'System'].indexOf(options.sessionTypes[i]) < 0) { throw new Error('Invalid launchd session type'); }
                xml += '<string>' + options.sessionTypes[i] + '</string>';
            }
            xml += '</array>';
        }
        xml += '<key>RunAtLoad</key>' + (options.startType == 'AUTO_START' || options.startType == 'BOOT_START' ? '<true/>' : '<false/>');
        var restart = options.failureRestart;
        if (restart != null && (typeof restart != 'number' || !isFinite(restart) || restart < 0)) { throw new Error('Invalid restart interval'); }
        xml += '<key>KeepAlive</key>' + (restart == null || restart > 0
            ? (agent ? '<dict><key>Crashed</key><true/></dict>' : '<dict><key>SuccessfulExit</key><false/></dict>') : '<false/>');
        if (restart != null) { xml += '<key>ThrottleInterval</key><integer>' + Math.max(1, Math.ceil(restart / 1000)) + '</integer>'; }
        return xml + '</dict></plist>';
    }
    function macInstallService(options, manager)
    {
        if (!manager.isAdmin()) { throw new Error('Installing as Service requires root'); }
        var fs = require('fs'), created = [], directories = [];
        macServiceName(options.name);
        options.target = macServiceName(options.target || options.name);
        if (options.installPath && options.installInPlace) { throw new Error('Cannot specify both installPath and installInPlace'); }
        if (options.installInPlace)
        {
            if (!options.servicePath || options.servicePath.charAt(0) != '/') { throw new Error('Invalid in-place executable'); }
            options.installPath = options.servicePath.substring(0, options.servicePath.lastIndexOf('/')) || '/';
            if (options.target != options.servicePath.split('/').pop()) { throw new Error('In-place installation must preserve the executable basename'); }
        }
        if (options.installPath == null)
        {
            options.installPath = '/usr/local/mesh_services/' + (options.companyName != null ? macServiceName(options.companyName) + '/' : '') + options.name;
        }
        options.installPath = options.installPath.replace(/\/+$/, '') + '/';
        var executable = options.installPath + options.target, plist = '/Library/LaunchDaemons/' + options.name + '.plist';
        var xml = macBuildLaunchdPlist(options, false);
        if (fs.existsSync(plist)) { throw new Error('Service already exists: ' + options.name); }
        var receipt = { rollback: function ()
        {
            var errors = [];
            for (var i = created.length - 1; i >= 0; --i)
            {
                try { fs.unlinkSync(created[i]); created.splice(i, 1); } catch (e) { errors.push(created[i] + ': ' + e); }
            }
            for (var i = directories.length - 1; i >= 0; --i) { try { fs.rmdirSync(directories[i]); } catch (ignored) { } }
            if (errors.length) { throw new Error('Installation cleanup failed: ' + errors.join('; ')); }
        } };
        function createFile(path, content, mode)
        {
            var fd = null;
            try
            {
                fd = fs.openSync(path, 'wx'); created.push(path);
                fs.chmodSync(path, 384);
                var bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
                if (fs.writeSync(fd, bytes) != bytes.length) { throw new Error('Incomplete installation file: ' + path); }
                var closing = fd; fd = null; fs.closeSync(closing);
                fs.chmodSync(path, mode);
            }
            finally { if (fd != null) { fs.closeSync(fd); } }
        }
        try
        {
            macPrepareFolders(options.installPath, directories);
            if (!options.binary && options.servicePath == executable)
            {
                if (!fs.statSync(executable).isFile()) { throw new Error('Invalid in-place executable'); }
            }
            else { createFile(executable, options.binary || fs.readFileSync(options.servicePath), 493); }
            var files = options.files || [];
            for (var i = 0; i < files.length; ++i)
            {
                var name = macServiceName(extractFileName(files[i])), destination = options.installPath + name;
                var source = extractFileSource(files[i]);
                if (source == destination) { continue; }
                // Reinstall must retain the incumbent's identity and provisioning.
                if (fs.existsSync(destination) && [options.target + '.db', options.target + '.msh', options.target + '.mshx', options.target + '.proxy'].indexOf(name) >= 0) { continue; }
                createFile(destination, files[i]._buffer || fs.readFileSync(source), 384);
            }
            macPrepareFolders('/Library/LaunchDaemons', directories);
            // Publish the job only after every required binary/provisioning write succeeded.
            macWritePlist(plist, xml); created.push(plist);
            return receipt;
        }
        catch (e)
        {
            try { receipt.rollback(); } catch (cleanup) { throw new Error(e + '; ' + cleanup); }
            throw e;
        }
    }
    // MeshAgent's execFile takes argv[0] explicitly. Never interpret service
    // labels, paths, or arguments as shell input.
    function macServiceCommand(executable, args, options)
    {
        var child = require('child_process').execFile(executable, [executable.split('/').pop()].concat(args), options);
        var output = '', errors = '', code = null;
        child.stdout.on('data', function (chunk) { output += chunk.toString(); });
        child.stderr.on('data', function (chunk) { errors += chunk.toString(); });
        child.on('exit', function (status) { code = status; });
        child.waitExit(120000);
        if (code == null)
        {
            try { child.kill(); } catch (ignored) { }
            throw new Error(executable + ' timed out: ' + args[0]);
        }
        if (code !== 0)
        {
            var error = new Error(executable + ' ' + args[0] + ' failed (' + code + '): ' + errors.trim());
            error.code = 'ELAUNCHD';
            error.exitCode = code;
            throw error;
        }
        return output;
    }
    function getOSVersion()
    {
        var value = macServiceCommand('/usr/bin/sw_vers', ['-productVersion']).trim();
        if (!/^\d+(\.\d+)*$/.test(value)) { throw new Error('Invalid macOS version: ' + value); }
        var ret = { raw: value.split('.'), toString: function () { return this.raw.join('.'); } };
        ret.compareTo = function (val)
        {
            var other = typeof val == 'string' ? val.split('.') : val.raw;
            for (var i = 0; i < Math.max(this.raw.length, other.length); ++i)
            {
                var a = parseInt(this.raw[i] || '0', 10), b = parseInt(other[i] || '0', 10);
                if (a != b) { return a < b ? -1 : 1; }
            }
            return 0;
        };
        return ret;
    }
    function macServicePlist(file)
    {
        // plutil handles both XML and binary plists, including escaped strings.
        var data = JSON.parse(macServiceCommand('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '--', file]));
        if (!data || typeof data.Label != 'string' || !data.Label.length || /[\/\x00-\x1f]/.test(data.Label))
        { throw new Error('Invalid launchd Label in ' + file); }
        return data;
    }
    function macLoginWindowDomains()
    {
        if (require('user-sessions').Self() != 0) { throw new Error('LoginWindow LaunchAgent requires root'); }
        var output;
        try { output = macServiceCommand('/bin/launchctl', ['print', 'user/0']); }
        catch (e) { if (e.exitCode == 125) { return []; } throw e; }
        var candidates = [], domains = [], match, pattern = /^\s*((?:gui|login)\/\d+)\s*$/gm;
        while ((match = pattern.exec(output)) != null) { if (candidates.indexOf(match[1]) < 0) { candidates.push(match[1]); } }
        match = /^\s*gui asid = (\d+)\s*$/m.exec(output);
        if (match && candidates.indexOf('login/' + match[1]) < 0) { candidates.push('login/' + match[1]); }
        for (var i = 0; i < candidates.length; ++i)
        {
            try { output = macServiceCommand('/bin/launchctl', ['print', candidates[i]]); }
            catch (e) { if (e.exitCode == 125) { continue; } throw e; }
            if (/^\s*session = LoginWindow\s*$/m.test(output)) { domains.push(candidates[i]); }
        }
        return domains;
    }
    function fetchPlist(folder, name, userid)
    {
        macServiceName(name);
        var fs = require('fs');
        folder = folder.replace(/\/$/, '');
        var file = folder + '/' + name + '.plist';
        if (!fs.existsSync(file))
        {
            var files;
            if (!fs.existsSync(folder)) { throw serviceNotFound(name); }
            try { files = fs.readdirSync(folder); }
            catch (e) { if (e.code == 'ENOENT') { throw serviceNotFound(name); } throw e; }
            file = null;
            for (var i = 0; i < files.length; ++i)
            {
                if (!files[i].endsWith('.plist')) { continue; }
                var candidate = folder + '/' + files[i];
                if (macServicePlist(candidate).Label == name) { file = candidate; break; }
            }
            if (!file) { throw serviceNotFound(name); }
        }
        var data = macServicePlist(file);
        var ret = { name: file.substring(folder.length + 1, file.length - 6), plist: file,
            alias: data.Label, daemon: folder.endsWith('/LaunchDaemons'), _uid: userid, close: function () {} };
        try { ret.installedDate = fs.statSync(file).ctime; } catch (ignored) { }
        var types = data.LimitLoadToSessionType;
        ret._loginWindowOnly = types == 'LoginWindow' || (Array.isArray(types) && types.length == 1 && types[0] == 'LoginWindow');
        ret.appLocation = function ()
        {
            var config = macServicePlist(this.plist);
            var executable = config.Program || (config.ProgramArguments && config.ProgramArguments[0]);
            if (typeof executable != 'string' || executable.charAt(0) != '/') { throw new Error('Missing absolute launchd program: ' + this.plist); }
            return executable;
        };
        ret.appWorkingDirectory = function ()
        {
            var directory = macServicePlist(this.plist).WorkingDirectory;
            if (directory == null) { directory = '/'; }
            if (typeof directory != 'string' || directory.charAt(0) != '/') { throw new Error('Invalid launchd working directory'); }
            return directory.replace(/\/$/, '') + '/';
        };
        ret.parameters = function () { return macServicePlist(this.plist).ProgramArguments || []; };
        Object.defineProperty(ret, '_runAtLoad', { get: function () { return macServicePlist(this.plist).RunAtLoad === true; } });
        Object.defineProperty(ret, 'startType', { get: function () { return this._runAtLoad ? 'AUTO_START' : 'DEMAND_START'; } });
        Object.defineProperty(ret, '_keepAlive', { get: function ()
        {
            var keep = macServicePlist(this.plist).KeepAlive;
            if (!keep) { return ''; }
            if (typeof keep == 'object' && Object.keys(keep).length == 1 && keep.Crashed === true) { return 'Crashed'; }
            return 'ALWAYS';
        } });
        ret._domain = function (uid, mutate)
        {
            var self = require('user-sessions').Self();
            if (this._uid != null) { uid = this._uid; }
            if (this.daemon)
            {
                if ((uid != null && uid != 0) || (mutate && self != 0)) { throw new Error('LaunchDaemon requires the system domain and root for changes'); }
                return 'system';
            }
            if (this._loginWindowOnly)
            {
                if (uid != null && uid != 0) { throw new Error('LoginWindow LaunchAgent cannot run in a user GUI domain'); }
                var domains = macLoginWindowDomains();
                if (domains.length > 1) { throw new Error('Multiple LoginWindow domains; cannot select a startup session'); }
                return domains.length ? domains[0] : null;
            }
            if (uid == null) { uid = self == 0 ? require('user-sessions').consoleUid() : self; }
            if (!/^\d+$/.test('' + uid) || Number(uid) <= 0) { throw new Error('LaunchAgent requires a logged-in user UID'); }
            if (mutate && self != 0 && Number(uid) != self) { throw new Error('Cannot change another user launchd domain'); }
            return 'gui/' + uid;
        };
        ret._stateInDomain = function (domain)
        {
            if (domain == null) { return { loaded: false, pid: 0 }; }
            var output;
            try { output = macServiceCommand('/bin/launchctl', ['print', domain + '/' + this.alias]); }
            catch (e)
            {
                // 113 is launchctl's missing-service result. Check the domain
                // too so an unavailable login session is never reported healthy.
                if (e.exitCode != 113) { throw e; }
                macServiceCommand('/bin/launchctl', ['print', domain]);
                return { loaded: false, pid: 0 };
            }
            var pid = /^\s*pid = (\d+)\s*$/m.exec(output);
            return { loaded: true, pid: pid ? parseInt(pid[1], 10) : 0 };
        };
        ret._state = function (uid) { return this._stateInDomain(this._domain(uid, false)); };
        ret.getPID = function (uid, asString)
        {
            var state = this._state(uid);
            return asString ? (state.loaded ? '' + state.pid : '') : state.pid;
        };
        ret.isLoaded = function (uid) { return this._state(uid).loaded; };
        ret.isRunning = function (uid) { return this._state(uid).pid > 0; };
        ret.isMe = function (uid) { return this._state(uid).pid == process.pid; };
        ret.load = function (uid)
        {
            var domain = this._domain(uid, true);
            if (domain == null) { throw new Error('LoginWindow session is not active; launchd will load the agent when that session starts'); }
            if (!this.isLoaded(uid)) { macServiceCommand('/bin/launchctl', ['bootstrap', domain, this.plist]); }
            if (!this.isLoaded(uid)) { throw new Error('launchd did not load ' + this.alias); }
        };
        ret.unload = function (uid)
        {
            var domains;
            if (this._loginWindowOnly)
            {
                if (uid != null && uid != 0) { throw new Error('LoginWindow LaunchAgent cannot run in a user GUI domain'); }
                // Include historical system-domain registrations and every active
                // LoginWindow context, without selecting an unrelated Aqua user.
                domains = ['system'].concat(macLoginWindowDomains());
            }
            else { domains = [this._domain(uid, true)]; }
            for (var i = 0; i < domains.length; ++i)
            {
                if (this._stateInDomain(domains[i]).loaded) { macServiceCommand('/bin/launchctl', ['bootout', domains[i] + '/' + this.alias]); }
                if (this._stateInDomain(domains[i]).loaded) { throw new Error('launchd did not unload ' + this.alias); }
            }
        };
        ret.start = function (uid)
        {
            var domain = this._domain(uid, true);
            this.load(uid);
            macServiceCommand('/bin/launchctl', ['kickstart', domain + '/' + this.alias]);
        };
        ret.stop = function (uid)
        {
            // Removing the job prevents all KeepAlive policies from respawning it.
            this.unload(uid);
        };
        ret.restart = function (uid)
        {
            var domain = this._domain(uid, true);
            this.load(uid);
            macServiceCommand('/bin/launchctl', ['kickstart', '-k', domain + '/' + this.alias]);
        };
        return ret;
    }
}


function serviceManager()
{
    this._ObjectID = 'service-manager';
    if (process.platform == 'win32') 
    {
        this.GM = require('_GenericMarshal');
        this.proxy = this.GM.CreateNativeProxy('Advapi32.dll');
        this.proxy.CreateMethod('OpenSCManagerA');
        this.proxy.CreateMethod('EnumServicesStatusExW');
        this.proxy.CreateMethod('OpenServiceW');
        this.proxy.CreateMethod('QueryServiceStatusEx');
        this.proxy.CreateMethod('QueryServiceConfigA');
        this.proxy.CreateMethod('QueryServiceConfig2A');
        this.proxy.CreateMethod('ControlService');
        this.proxy.CreateMethod('StartServiceA');
        this.proxy.CreateMethod('CloseServiceHandle');
        this.proxy.CreateMethod('ChangeServiceConfig2W');
        this.proxy.CreateMethod('AllocateAndInitializeSid');
        this.proxy.CreateMethod('CheckTokenMembership');
        this.proxy.CreateMethod('FreeSid');

        this.proxy2 = this.GM.CreateNativeProxy('Kernel32.dll');
        this.proxy2.CreateMethod('GetLastError');

        this.isAdmin = function isAdmin() {
            var NTAuthority = this.GM.CreateVariable(6);
            NTAuthority.toBuffer().writeInt8(5, 5);
            var AdministratorsGroup = this.GM.CreatePointer();
            var admin = false;

            if (this.proxy.AllocateAndInitializeSid(NTAuthority, 2, 32, 544, 0, 0, 0, 0, 0, 0, AdministratorsGroup).Val != 0)
            {
                var member = this.GM.CreateInteger();
                if (this.proxy.CheckTokenMembership(0, AdministratorsGroup.Deref(), member).Val != 0)
                {
                    if (member.toBuffer().readUInt32LE() != 0) { admin = true; }
                }
                this.proxy.FreeSid(AdministratorsGroup.Deref());
            }
            return admin;
        };
        this.getProgramFolder = function getProgramFolder()
        {
            if (require('os').arch() == 'x64')
            {
                // 64 bit Windows
                if (this.GM.PointerSize == 4)
                {
                    return (process.env['ProgramFiles(x86)'] ? process.env['ProgramFiles(x86)'] : process.env['ProgramFiles']);
                } 
                return process.env['ProgramFiles'];             // 64 bit App
            }

            // 32 bit Windows
            return process.env['ProgramFiles'];                 
        };

        this.enumerateService = function () {
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004);
            if (handle.Val == 0) { throw new Error('Error opening service manager: ' + this.proxy2.GetLastError().Val); }
            try
            {
            var bytesNeeded = this.GM.CreateVariable(4);
            var servicesReturned = this.GM.CreateVariable(4);
            var resumeHandle = this.GM.CreateVariable(4);
            resumeHandle.toBuffer().writeUInt32LE(0);
            // The SCM limit is 256 KiB. Consume partial pages before resuming;
            // a size probe followed by one unchecked call can lose services.
            var sz = 262144;
            var services = this.GM.CreateVariable(sz);
            var ptrSize = this.GM.PointerSize;
            var blockSize = 36 + (2 * ptrSize);
            blockSize += ((ptrSize - (blockSize % ptrSize)) % ptrSize);
            var retVal = [];
            for (;;)
            {
                var previousResume = resumeHandle.toBuffer().readUInt32LE();
                var success = this.proxy.EnumServicesStatusExW(handle, 0, 0x00000030, 0x00000003, services, sz, bytesNeeded, servicesReturned, resumeHandle, 0x00).Val;
                var error = success ? 0 : this.proxy2.GetLastError().Val;
                if (!success && error != 234) { throw new Error('Error enumerating services: ' + error); }
                var count = servicesReturned.toBuffer().readUInt32LE();
                if (count * blockSize > sz) { throw new Error('Invalid service enumeration page'); }
                for (var i = 0; i < count; ++i)
                {
                var token = services.Deref(i * blockSize, blockSize);
                var j = {};
                j.name = token.Deref(0, ptrSize).Deref().Wide2UTF8;
                j.displayName = token.Deref(ptrSize, ptrSize).Deref().Wide2UTF8;
                j.status = parseServiceStatus(token.Deref(2 * ptrSize, 36));
                retVal.push(j);
                }
                if (success) { break; }
                if (resumeHandle.toBuffer().readUInt32LE() == previousResume) { throw new Error('Service enumeration did not advance'); }
            }
            return (retVal);
            }
            finally { this.proxy.CloseServiceHandle(handle); }
        }
        this.getService = function getService(name)
        {
            var isroot = this.isAdmin();

            var serviceName = this.GM.CreateVariable(name, { wide: true });
            var ptr = this.GM.CreatePointer();
            var bytesNeeded = this.GM.CreateVariable(ptr._size);
            var handle = this.proxy.OpenSCManagerA(0x00, 0x00, 0x0001 | 0x0004 | 0x0010 | (isroot ? 0x0020 : 0x00));
            if (handle.Val == 0) { throw windowsServiceError('OpenSCManager', this.proxy2.GetLastError().Val); }
            var h = this.proxy.OpenServiceW(handle, serviceName, 0x0001 | 0x0004 | (isroot ? (0x0002 | 0x0020 | 0x0010 | 0x00010000): 0x00));
            if (h.Val == 0)
            {
                var openError = this.proxy2.GetLastError().Val;
                this.proxy.CloseServiceHandle(handle);
                throw windowsServiceError('OpenService(' + name + ')', openError);
            }
            try
            {
            if (h.Val != 0)
            {
                var retVal = { _ObjectID: 'service-manager.service' }
                retVal._scm = handle;
                retVal._service = h;
                retVal._GM = this.GM;
                retVal._proxy = this.proxy;
                retVal._proxy2 = this.proxy2;
                retVal.name = name;

                Object.defineProperty(retVal, 'status', 
                    { 
                        get: function()
                        {
                            var bytesNeeded = this._GM.CreateVariable(this._GM.PointerSize);
                            this._proxy.QueryServiceStatusEx(this._service, 0, 0, 0, bytesNeeded);
                            var st = this._GM.CreateVariable(bytesNeeded.toBuffer().readUInt32LE());
                            if (this._proxy.QueryServiceStatusEx(this._service, 0, st, st._size, bytesNeeded).Val != 0)
                            {
                                return(parseServiceStatus(st));
                            }
                            else
                            {
                                return ({ state: 'UNKNOWN' });
                            }
                        }
                    });
                Object.defineProperty(retVal, 'installedBy',
                    {
                        get: function()
                        {
                            var reg = require('win-registry');
                            try
                            {
                                return(reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + this.name, '_InstalledBy'));
                            }
                            catch(xx)
                            {
                                return (null);
                            }
                        }
                    });
                try
                {
                    Object.defineProperty(retVal, 'installedDate',
                        {
                            value: require('win-registry').QueryKeyLastModified(require('win-registry').HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + name, 'ImagePath')
                        });
                }
                catch(xx)
                {
                }
                if (retVal.status.state != 'UNKNOWN')
                {
                    require('events').EventEmitter.call(retVal);
                    retVal.close = function ()
                    {
                        if (this._stopPromise && !this._stopPromise._settled) { this._stopPromise.finish(new Error('Service handle closed while waiting for stop')); }
                        if(this._service && this._scm)
                        {
                            this._proxy.CloseServiceHandle(this._service);
                            this._proxy.CloseServiceHandle(this._scm);
                            this._service = this._scm = null;
                        }
                    };
                    retVal.on('~', retVal.close);
                    retVal.isMe = function isMe()
                    {
                        return (parseInt(this.status.pid) == process.pid);
                    }
                    retVal.update = function update()
                    {
                        if (this.failureActions)
                        {
                            var actions = this._GM.CreateVariable(this.failureActions.actions.length * 8);                                // len*sizeof(SC_ACTION)
                            for (var i = 0; i < this.failureActions.actions.length && i < 3; ++i)
                            {
                                actions.Deref(i*8, 4).toBuffer().writeUInt32LE(failureActionToInteger(this.failureActions.actions[i].type));   // SC_ACTION[i].type
                                actions.Deref(4+(i*8), 4).toBuffer().writeUInt32LE(this.failureActions.actions[i].delay);                      // SC_ACTION[i].delay
                            }

                            var updatedFailureActions = this._GM.CreateVariable(40);                                         // sizeof(SERVICE_FAILURE_ACTIONS)
                            updatedFailureActions.Deref(0, 4).toBuffer().writeUInt32LE(this.failureActions.resetPeriod);    // dwResetPeriod
                            updatedFailureActions.Deref(this._GM.PointerSize == 8 ? 24 : 12, 4).toBuffer().writeUInt32LE(this.failureActions.actions.length); // cActions
                            actions.pointerBuffer().copy(updatedFailureActions.Deref(this._GM.PointerSize == 8 ? 32 : 16, this._GM.PointerSize).toBuffer());
                            if (this._proxy.ChangeServiceConfig2W(this._service, 2, updatedFailureActions).Val == 0)
                            {
                                throw('Unable to set FailureActions...');
                            }
                        }
                    };
                    retVal.appLocation = function ()
                    {
                        var reg = require('win-registry');
                        var imagePath = reg.QueryKey(reg.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + this.name, 'ImagePath').toString();
                        return windowsServiceExecutable(imagePath);
                    };
                    retVal.appWorkingDirectory = function ()
                    {
                        var tokens = this.appLocation().split('\\');
                        tokens.pop();
                        return (tokens.join('\\'));
                    };
                    retVal.setStartType = function (newType)
                    {
                        var mapping =
                            {
                                'AUTO_START': 0x00000002,
                                'DEMAND_START': 0x00000003,
                                'DISABLED': 0x00000004
                            };
                        var target = mapping[newType];
                        if (target == null) { throw ('Invalid start type: ' + newType); }
                        var SERVICE_NO_CHANGE = 0xFFFFFFFF;
                        if (this._proxy.ChangeServiceConfigW(this._service, SERVICE_NO_CHANGE, target, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0).Val == 0)
                        {
                            var err = this._proxy2.GetLastError().Val;
                            throw ('ChangeServiceConfigW failed (' + err + ')');
                        }
                        this.startType = newType;
                    };
                    retVal.isRunning = function ()
                    {
                        var status = this.status;
                        if (status.state == 'UNKNOWN') { throw new Error('Unable to query service state'); }
                        return status.state != 'STOPPED' || status.pid > 0;
                    };

                    retVal._stopEx = function(s, p)
                    {
                        if (p._settled) { return; }
                        try
                        {
                            if (!s._service) { throw new Error('Service handle closed while waiting for stop'); }
                            var status = s.status;
                            if (status.state == 'UNKNOWN') { throw new Error('Unable to query service stop status'); }
                            if (status.state == 'STOPPED' && !(status.pid > 0)) { p.finish(null); return; }
                            if (Date.now() - p._startTime >= 10000) { throw new Error('Timed out waiting for ' + s.name + ' to stop (' + status.state + ')'); }
                            if (!p._stopRequested && (status.state == 'RUNNING' || status.state == 'PAUSED'))
                            {
                                var newstate = s._GM.CreateVariable(36);
                                if (s._proxy.ControlService(s._service, 0x00000001, newstate).Val == 0)
                                {
                                    var reason = s._proxy2.GetLastError().Val;
                                    if (reason != 1062) { throw windowsServiceError(s.name + '.stop()', reason); }
                                }
                                p._stopRequested = true;
                            }
                            p.timer = setTimeout(s._stopEx, p._waitTime, s, p);
                        }
                        catch (e) { p.finish(e); }
                    };
                    retVal.stop = function ()
                    {
                        if (this._stopPromise && !this._stopPromise._settled) { return this._stopPromise; }
                        var ret = new promise(function (a, r) { this._res = a; this._rej = r; });
                        this._stopPromise = ret;
                        ret._settled = false;
                        ret.finish = function (error)
                        {
                            if (this._settled) { return; }
                            this._settled = true;
                            if (this.timer != null) { clearTimeout(this.timer); this.timer = null; }
                            if (error != null) { this._rej(error); } else { this._res('STOPPED'); }
                        };
                        ret._startTime = Date.now();
                        try
                        {
                            var status = this.status;
                            ret._waitTime = Math.max(500, Math.min(5000, (status.waitHint || 5000) / 10));
                            // Poll every transitional state under one deadline; never kill a shared host.
                            this._stopEx(this, ret);
                        }
                        catch (e) { ret.finish(e); }
                        return ret;
                    };
                    retVal.start = function ()
                    {
                        if (this.status.state == 'STOPPED')
                        {
                            var success = this._proxy.StartServiceA(this._service, 0, 0);
                            if (success.Val == 0)
                            {
                                throw (this.name + '.start() failed');
                            }
                        }
                        else
                        {
                            throw ('cannot call ' + this.name + '.start(), when current state is: ' + this.status.state);
                        }
                    }
                    retVal.restart = function ()
                    {
                        if (this.isMe())
                        {
                            throw ('Windows self restart through a command host is disabled in this build; use the native lifecycle host or SCM control path.');
                        }
                        else
                        {
                            var p = this.stop();
                            p.startp = new promise(function (a, r) { this._a = a; this._r = r; });
                            p.service = this;
                            p.then(function ()
                            {
                                try
                                {
                                    this.service.start();
                                }
                                catch (e)
                                {
                                    this.startp._r(e);
                                    return;
                                }
                                this.startp._a();
                            }, function (e) { this.startp._r(e); });
                            return (p.startp);
                        }
                    }
                    var query_service_configa_DWORD = this.GM.CreateVariable(4);
                    this.proxy.QueryServiceConfigA(h, 0, 0, query_service_configa_DWORD);
                    if (query_service_configa_DWORD.toBuffer().readUInt32LE() > 0)
                    {
                        var query_service_configa = this.GM.CreateVariable(query_service_configa_DWORD.toBuffer().readUInt32LE());
                        if(this.proxy.QueryServiceConfigA(h, query_service_configa, query_service_configa._size, query_service_configa_DWORD).Val != 0)
                        {
                            var val = query_service_configa.Deref(this.GM.PointerSize == 4 ? 28 : 48, this.GM.PointerSize).Deref().String;
                            Object.defineProperty(retVal, 'user', { value: val });
                            switch(query_service_configa.Deref(4,4).toBuffer().readUInt32LE())
                            {
                                case 0x00:
                                case 0x01:
                                case 0x02:
                                    retVal.startType = 'AUTO_START';
                                    break;
                                case 0x03:
                                    retVal.startType = 'DEMAND_START';
                                    break;
                                case 0x04:
                                    retVal.startType = 'DISABLED';
                                    break;
                            }
                        }
                    }


                    var failureactions = this.GM.CreateVariable(8192);
                    var bneeded = this.GM.CreateVariable(4);        
                    if (this.proxy.QueryServiceConfig2A(h, 2, failureactions, 8192, bneeded).Val != 0)
                    {
                        var cActions = failureactions.toBuffer().readUInt32LE(this.GM.PointerSize == 8 ? 24 : 12);
                        retVal.failureActions = {};
                        retVal.failureActions.resetPeriod = failureactions.Deref(0, 4).toBuffer().readUInt32LE(0);
                        retVal.failureActions.actions = [];
                        for(var act = 0 ; act < cActions; ++act)
                        {
                            var action = failureactions.Deref(this.GM.PointerSize == 8 ? 32 : 16, this.GM.PointerSize).Deref().Deref(act*8,8).toBuffer();
                            switch(action.readUInt32LE())
                            {
                                case 0:
                                    retVal.failureActions.actions.push({ type: 'NONE' });
                                    break;
                                case 1:
                                    retVal.failureActions.actions.push({ type: 'SERVICE_RESTART' });
                                    break;
                                case 2:
                                    retVal.failureActions.actions.push({ type: 'REBOOT' });
                                    break;
                                default:
                                    retVal.failureActions.actions.push({ type: 'OTHER' });
                                    break;
                            }
                            retVal.failureActions.actions.peek().delay = action.readUInt32LE(4);
                        }
                    }
                    return (retVal);
                }
                else { throw windowsServiceError('QueryServiceStatusEx(' + name + ')', this.proxy2.GetLastError().Val); }
            }
            }
            catch (e)
            {
                this.proxy.CloseServiceHandle(h);
                this.proxy.CloseServiceHandle(handle);
                if (retVal) { retVal._service = retVal._scm = null; }
                throw e;
            }
        }
    }
    else
    {
        // Linux, MacOS, FreeBSD

        this.isAdmin = function isAdmin() 
        {
            return (require('user-sessions').isRoot());
        }

        if (process.platform == 'freebsd')
        {
            Object.defineProperty(this, 'OPNsense',
                {
                    get: function()
                    {
                        if (this.__opnsense != null) { return (this.__opnsense); }
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stderr.on('data', function (c) { });
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("opnsense-version | awk '{ print $2; }'\nexit\n");
                        child.waitExit();
                        this.__opnsense = child.stdout.str.trim() != '' ? true : false;
                        return (this.__opnsense);
                    }
                });
            Object.defineProperty(this, 'pfSense',
                {
                    get: function ()
                    {
                        if (this.__ispfsense != null) { return (this.__ispfsense); }
                        try
                        {
                            if (require('fs').existsSync('/etc/psSense-rc') || require('fs').readFileSync('/etc/platform').toString().trim() == 'pfSense')
                            {
                                this.__ispfsense = true;
                                return (true);
                            }
                        }
                        catch (e)
                        {
                        }
                        this.__ispfsense = false;
                        return (false);
                    }
                });
            this.getService = function getService(name)
            {
                var ret = { name: name, close: function () { } };
                Object.defineProperty(ret, "OpenBSD", { value: !require('fs').existsSync('/usr/sbin/daemon') });

                if(require('fs').existsSync('/etc/rc.d/' + name)) 
                {
                    Object.defineProperty(ret, 'rc', { value: '/etc/rc.d/' + name });
                }
                else if(require('fs').existsSync('/usr/local/etc/rc.d/' + name))
                {
                    Object.defineProperty(ret, 'rc', { value: '/usr/local/etc/rc.d/' + name });
                }
                else
                {
                    throw serviceNotFound(name);
                }
                Object.defineProperty(ret, "startType",
                    {
                        get: function ()
                        {
                            if (!this.OpenBSD)
                            {
                                // FreeBSD
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('service ' + this.name + ' rcvar | grep _enable= | awk \'{ a=split($0, b, "\\""); if(b[2]=="YES") { print "YES"; } }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                            }
                            else
                            {
                                // OpenBSD
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('rcctl ls on | awk \'{ if($0=="' + this.name + '") { print "AUTO_START"; } }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                            }
                        }
                    });

                ret.description = function description()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep desc= | awk -F= '" + '{ if($1=="desc") { $1=""; a=split($0, res, "\\""); if(a>1) { print res[2]; } else { print $0; } } }\'\nexit\n');
                    child.waitExit();
                    return (child.stdout.str.trim());
                };
                ret.appWorkingDirectory = function appWorkingDirectory()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep " + this.name + "_chdir= | awk -F= '");
                    child.stdin.write('{');
                    child.stdin.write('   gsub(/"/,"",$2);');
                    child.stdin.write('   gsub("/$","",$2);');
                    child.stdin.write('   gsub(/\\\\ /," ",$2);');
                    child.stdin.write('   printf "%s/",$2;');
                    child.stdin.write("}'");
                    child.stdin.write('\nexit\n');
                    child.waitExit();
                    return (child.stdout.str.trim());
                };
                try
                {
                    Object.defineProperty(ret, 'installedDate', { value: require('fs').statSync(ret.rc).ctime });
                }
                catch (xx)
                {
                }

                ret.appLocation = function appLocation()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("cat " + this.rc + " | grep daemon= | awk '{ if($0 ~ /_loader\"$/) { gsub(/^daemon=/,\"\", $0); gsub(/_loader\"$/,\"\\\"\",$0); print $0; } else { gsub(/^daemon=/,\"\",$0); print $0; } }'\nexit\n");
                        child.waitExit();
                        var ret = child.stdout.str.trim();
                        if (ret != '') { ret = ret.substring(1, ret.length - 1); }
                        return (ret);
                    }
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + " | grep command= | awk -F= '{ print $2 }' | awk -F\\\" '{ print $2 }'\nexit\n");
                    child.waitExit();
                    var tmp = child.stdout.str.trim().split('${name}').join(this.name);
                    if(tmp=='/usr/sbin/daemon')
                    {
                        child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("cat " + this.rc + " | grep command_args= | awk NR==1'");
                        child.stdin.write('{');
                        child.stdin.write('   split($0,V,"-f ");');
                        child.stdin.write('   if(V[2] ~ /^\\\\"/)');
                        child.stdin.write('   {');
                        child.stdin.write('      split(V[2],RET,"\\"");');
                        child.stdin.write('      gsub(/\\\\$/,"",RET[2]);');
                        child.stdin.write('      print RET[2];');
                        child.stdin.write('   }');
                        child.stdin.write('   else');
                        child.stdin.write('   {');
                        child.stdin.write('      split(V[2],RET," ");');
                        child.stdin.write('      print RET[1];');
                        child.stdin.write('   }');
                        child.stdin.write("}'");
                        child.stdin.write('\nexit\n');
                        child.waitExit();
                        return(child.stdout.str.trim());
                    }
                    else
                    {
                        return(tmp);
                    }
                };
                ret.isRunning = function isRunning()
                {
                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stderr.on('data', function (c) { });
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write('rcctl ls started | awk \'{ if($0=="' + this.name + '") { print "STARTED"; } }\'\nexit\n');
                        child.waitExit();
                        return (child.stdout.str.trim() == '' ? false : true);
                    }
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("service " + this.name + " onestatus | awk '{ print $3 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == 'running');
                };
                ret.pid = function pid()
                {
                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        try
                        {
                            var pid = require('fs').readFileSync('/var/run/' + this.name + '.pid');
                            return(parseInt(pid.toString().trim()));
                        }
                        catch(e)
                        {
                            return (-1);
                        }
                    }
                    else
                    {
                        // FreeBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestatus | awk '");
                        child.stdin.write('{ split($6, res, ".");  ');
                        child.stdin.write('  cm=sprintf("ps -p %s -w", res[1]);');
                        child.stdin.write('  system(cm); ')
                        child.stdin.write('}\' | awk \'NR>1\' | awk \'');
                        child.stdin.write('{');
                        child.stdin.write('   if($5=="daemon:") { split($0, T, "["); split(T[2], X, "]"); print X[1]; } else { print $1; }');
                        child.stdin.write('}\'\nexit\n');
                        child.waitExit();
                        return (parseInt(child.stdout.str.trim()));
                    }
                };
                ret.isMe = function isMe()
                {
                    return (this.pid() == process.pid);
                };
                ret.stop = function stop()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl stop " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestop\nexit\n");
                        child.waitExit();
                    }
                };
                ret.start = function start()
                {
                    if (this.OpenBSD)
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl start " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onestart\nexit\n");
                        child.waitExit();
                    }
                };
                ret.restart = function restart()
                {
                    if (this.isMe())
                    {
                        var parameters = this.parameters();
                        parameters.unshift(process.execPath);
                        require('child_process')._execve(process.execPath, parameters);
                        throw ('Error Restarting via execve()');
                    }

                    if (this.OpenBSD)
                    {
                        // OpenBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("rcctl restart " + this.name + "\nexit\n");
                        child.waitExit();
                    }
                    else
                    {
                        // FreeBSD
                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                        child.stdin.write("service " + this.name + " onerestart\nexit\n");
                        child.waitExit();
                    }
                };
                ret.parameters = function parameters()
                {
                    if (this.OpenBSD)
                    {
                        var s = require('fs').readFileSync('/etc/rc.d/' + this.name).toString();

                        var loader = s.match('\ndaemon=.*\n');
                        if (loader && loader[0].match('/' + this.name + '_loader"\n$'))
                        {
                            // This is our daemon
                            var i;
                            var lines = s.split('\n');
                            for (i = 0; i < lines.length; ++i)
                            {
                                if (lines[i].match('^daemon_flags='))
                                {
                                    var b64 = lines[i].split(' ')[1];
                                    b64 = Buffer.from(b64, 'base64').toString();
                                    var match = b64.match('\\[.*\\]');
                                    match = JSON.parse(match);
                                    return (match);
                                }
                            }
                            return ([]);
                        }
                        else
                        {
                            // Non-Daemon
                            return ([]);
                        }
                    }

                    // FreeBSD
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("cat " + this.rc + ' | grep "^\\s*command_args=" | awk \'NR==1');
                    child.stdin.write('{ gsub(/^\\s*command_args=/,"",$0); gsub(/^"([^\\\\^\\/]+)/,"\\"",$0); print $0; }\'\nexit\n');
                    child.waitExit();
                    var str = JSON.parse(child.stdout.str.trim());
                    return (str.match(/(?:[^\s"]+|"[^"]*")+/g));
                };
                return (ret);
            };
        }

        if (process.platform == 'darwin')
        {
            this.getService = function getService(name) { return (fetchPlist('/Library/LaunchDaemons', name)); };
            this.getLaunchAgent = function getLaunchAgent(name, userid)
            {
                if (userid == null)
                {
                    return (fetchPlist('/Library/LaunchAgents', name));
                }
                else
                {
                    return (fetchPlist(require('user-sessions').getHomeFolder(require('user-sessions').getUsername(userid)) + '/Library/LaunchAgents', name, userid));
                }
            };
        }
        if(process.platform == 'linux')
        {
            this.getService = function getService(name, platform)
            {
                if (!platform) { platform = this.getServiceType(); }
                var ret = { name: name, close: function () { }, serviceType: platform};
                switch(platform)
                {
                    case 'procd':
                        if (!require('fs').existsSync('/etc/init.d/' + name)) { throw serviceNotFound(name); }
                        ret.conf = '/etc/init.d/' + name;
                        ret.appWorkingDirectory = function appWorkingDirectory()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                            child.stdin.write('cat ' + this.conf + ' | grep "procd_set_param command /bin/sh " | tr ' + "'\\n' '`' | awk -F'`' '");
                            child.stdin.write('{');
                            child.stdin.write('   for(n=1;n<NF;++n)');
                            child.stdin.write('   {');
                            child.stdin.write('      if($n~/^#/) { continue; }');
                            child.stdin.write('      v=split($n,tokens,"\\"");');
                            child.stdin.write('      if(v==1) { continue; }');
                            child.stdin.write('      sh=sprintf("cat \\"%s\\"", tokens[2]);');
                            child.stdin.write('      shval=system(sh);');
                            child.stdin.write('   }');
                            child.stdin.write("}'");
                            child.stdin.write(' | grep "cd " | awk ' + "NR==1'");
                            child.stdin.write('{');
                            child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                            child.stdin.write('   p=substr($0,4);');
                            child.stdin.write('   gsub(/"/,"",p);');
                            child.stdin.write('   gsub("/$","",p);');
                            child.stdin.write('   printf "%s/",p;');
                            child.stdin.write("}'");
                            child.stdin.write('\nexit\n');
                            child.waitExit();
                            return (child.stdout.str.trim() == '' ? '/' : child.stdout.str.trim());
                        };
                        ret.appLocation = function appLocation()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                            child.stdin.write('cat ' + this.conf + ' | grep "procd_set_param command"' + " | awk NR==1'");
                            child.stdin.write('{');
                            child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                            child.stdin.write('   cmd=substr($0, 25);')
                            child.stdin.write('   if(substr(cmd,0,8)=="/bin/sh ")');
                            child.stdin.write('   {');
                            child.stdin.write('      cmd=substr(cmd,8);');
                            child.stdin.write('      x=split(cmd,tok,"\\"");');
                            child.stdin.write('      cmd = (x==1?cmd:tok[2]);');
                            child.stdin.write('   }');
                            child.stdin.write('   print cmd;');
                            child.stdin.write("}'");
                            child.stdin.write('\nexit\n');
                            child.waitExit();

                            var ret = child.stdout.str.trim();
                            if (ret.endsWith('.sh'))
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stderr.on('data', function (c) { });
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat "' +ret + '" | grep "exec "' + " | awk NR==1'");
                                child.stdin.write('{');
                                child.stdin.write('   gsub(/^[ \\t]+/, "", $0);');
                                child.stdin.write('   if($0 ~ "^exec \\"")');
                                child.stdin.write('   {');
                                child.stdin.write('      split($0,V,"\\"");');
                                child.stdin.write('      val=V[2];');
                                child.stdin.write('   }');
                                child.stdin.write('   else');
                                child.stdin.write('   {');
                                child.stdin.write('      split($0,V," ");');
                                child.stdin.write('      val=V[2];');
                                child.stdin.write('   }');
                                child.stdin.write('   gsub("^./","",val);');
                                child.stdin.write('   print val;');
                                child.stdin.write("}'");
                                child.stdin.write('\nexit\n');
                                child.waitExit();

                                ret = child.stdout.str.trim();
                                if(!ret.startsWith('/'))
                                {
                                    ret = (this.appWorkingDirectory() + ret);
                                }
                            }
                            return (ret);
                        };
                        ret.start = function start()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' start\nexit\n');
                            child.waitExit();
                        };
                        ret.stop = function stop()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' stop\nexit\n');
                            child.waitExit();
                        };
                        ret.restart = function restart()
                        {
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stderr.on('data', function (c) { });
                            child.stdout.on('data', function (c) { });
                            child.stdin.write('/etc/init.d/' + this.name + ' restart\nexit\n');
                            child.waitExit();
                        };
                        ret.isMe = function isMe() { return (true); } 
                        break;
                    case 'init':
                    case 'upstart':
                        if (require('fs').existsSync('/etc/init.d/' + name)) { platform = 'init'; }
                        if (require('fs').existsSync('/etc/init/' + name + '.conf')) { platform = 'upstart'; }
                        if ((platform == 'init' && require('fs').existsSync('/etc/init.d/' + name)) ||
                            (platform == 'upstart' && require('fs').existsSync('/etc/init/' + name + '.conf')))
                        {
                            ret.conf = (platform == 'upstart' ? ('/etc/init/' + name + '.conf') : ('/etc/init.d/' + name));
                            ret.serviceType = platform;
                            if (platform == 'init')
                            {
                                Object.defineProperty(ret, 'OpenRC', { value: require('fs').existsSync('/sbin/openrc-run') });
                                if(ret.OpenRC)
                                {
                                    Object.defineProperty(ret, '_autorestart', {
                                        value: (function ()
                                        {
                                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                                            child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                            child.stderr.on('data', function () { });
                                            child.stdin.write('cat ' + ret.conf + ' | grep "^\\s*supervisor=\\"supervise-daemon\\""\nexit\n');
                                            child.waitExit();
                                            return (child.stdout.str.trim() != '');
                                        })()
                                    });
                                }
                            }
                            Object.defineProperty(ret, "startType",
                                {
                                    get: function ()
                                    {
                                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                                        child.stderr.on('data', function (c) { });
                                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                        if (this.OpenRC)
                                        {
                                            child.stdin.write('rc-status default | grep "^\\s' + this.name + ' *\\["\n\exit\n');
                                        }
                                        else
                                        {
                                            if (this.serviceType == 'upstart')
                                            {
                                                child.stdin.write('cat ' + this.conf + ' | grep "start on runlevel"\nexit\n');
                                            }
                                            else
                                            {
                                                child.stdin.write('find /etc/rc* -maxdepth 2 -type l -ls | grep " ../init.d/' + this.name + '" | awk -F"-> " \'{ if($2=="../init.d/' + this.name + '") { print "true"; } }\'\nexit\n');
                                            }
                                        }
                                        child.waitExit();
                                        return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');

                                    }
                                });

                            ret.description = function description()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                if(description.platform == 'upstart')
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep description | awk '" + '{ if($1=="description") { $1=""; a=split($0, res, "\\""); if(a>1) { print res[2]; } else { print $0; }}}\'\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init.d/" + this.name + " | grep Short-Description: | awk '" + '{ if($2=="Short-Description:") { $1=""; $2=""; print $0; }}\'\nexit\n');
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            }
                            ret.description.platform = platform;
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (appWorkingDirectory.platform == 'init')
                                {
                                    if (this.OpenRC)
                                    {
                                        if (this._autorestart)
                                        {
                                            child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "^\\s*supervise_daemon_args=" | awk \'NR==1{ split($0,A,"--chdir "); split(A[2],B,"\\\\\\\\\\""); gsub("/$","",B[2]); printf "%s/",B[2]; }\'\nexit\n');
                                        }
                                        else
                                        {
                                            child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "^\\s*start_stop_daemon_args=" | awk \'NR==1{ split($0,A,"--chdir "); split(A[2],B,"\\\\\\\\\\""); gsub("/$","",B[2]); printf "%s/",B[2]; }\'\nexit\n');
                                        }
                                    }
                                    else
                                    {
                                        child.stdin.write("cat /etc/init.d/" + this.name + " | grep 'SCRIPT=' | awk -F= '{ len=split($2, a, \"/\"); print substr($2,0,length($2)-length(a[len])); }'\nexit\n");
                                    }
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep 'chdir ' | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   if(split($0,v,"\\\"")>1)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      gsub(/\\/$/,"",v[2]);');
                                    child.stdin.write('      print v[2];');
                                    child.stdin.write('   }');
                                    child.stdin.write('   else');
                                    child.stdin.write('   {');
                                    child.stdin.write('      gsub(/\\/$/,"",$2);');
                                    child.stdin.write('      print $2;');
                                    child.stdin.write('   }');
                                    child.stdin.write("}'");
                                    child.stdin.write('\nexit\n');

                                }
                                child.waitExit();
                                if (child.stdout.str.trim() == '') { return ('/'); }
                                return (child.stdout.str.trim());
                            };
                            ret.appWorkingDirectory.platform = platform;
                            ret.appLocation = function appLocation()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (appLocation.platform == 'init')
                                {
                                    if (this.OpenRC)
                                    {
                                        child.stdin.write('cat /etc/init.d/' + this.name + ' | grep "\\s*command=" | awk \'NR==1{ split($0,A,"\\""); print A[2]; }\'\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write("cat /etc/init.d/" + this.name + " | grep 'SCRIPT=' | awk -F= '{print $2}'\nexit\n");
                                    }
                                }
                                else
                                {
                                    child.stdin.write("cat /etc/init/" + this.name + ".conf | grep 'exec ' | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   if(split($0,v,"\\\"")>1)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      print v[2];');
                                    child.stdin.write('   }');
                                    child.stdin.write('   else');
                                    child.stdin.write('   {');
                                    child.stdin.write('      print $2;');
                                    child.stdin.write('   }');
                                    child.stdin.write("}'");
                                    child.stdin.write('\nexit\n');
                                }
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation.platform = platform;
                            ret.isMe = function isMe()
                            {
                                if (this.OpenRC)
                                {
                                    return (this.pid() == process.pid);
                                }
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (isMe.platform == 'upstart')
                                {
                                    child.stdin.write("initctl status " + this.name + " | awk '{print $NF}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("service " + this.name + " status | awk '");
                                    child.stdin.write('{');
                                    child.stdin.write('   sh=sprintf("ps -e -o pid -o ppid | grep %s", $NF);');
                                    child.stdin.write('   shval=system(sh);');
                                    child.stdin.write("}'");
                                    child.stdin.write(' | tr ' + "'\\n' '`' | awk -F'`' '");
                                    child.stdin.write('{');
                                    child.stdin.write('   root="";');
                                    child.stdin.write('   pid="";');
                                    child.stdin.write('   for(n=1;n<NF;++n)');
                                    child.stdin.write('   {');
                                    child.stdin.write('      split($n, i, " ");');
                                    child.stdin.write('      if(i[2]=="1") { root=i[1]; } else { pid=i[1]; }');
                                    child.stdin.write('   }');
                                    child.stdin.write('   printf("%s", pid==""?root:pid);');
                                    child.stdin.write("}'\nexit\n");
                                }
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isMe.platform = platform;
                            ret.isRunning = function isRunning()
                            {
                                if (this.OpenRC) { return (!isNaN(this.pid())); }
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                if (isRunning.platform == 'upstart')
                                {
                                    child.stdin.write("initctl status " + this.name + " | awk '{print $2}' | awk -F, '{print $1}'\nexit\n");
                                }
                                else
                                {
                                    child.stdin.write("service " + this.name + " status | awk '{print $2}' | awk -F, '{print $1}'\nexit\n");
                                }
                                child.waitExit();
                                return (child.stdout.str.trim() == 'start/running');
                            };
                            ret.isRunning.platform = platform;
                            ret.start = function start()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                child.stdout.on('data', function (chunk) { });
                                if (start.platform == 'upstart')
                                {
                                    child.stdin.write('initctl start ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write('service ' + this.name + ' start\nexit\n');
                                }
                                child.waitExit();
                            };
                            ret.start.platform = platform;
                            ret.stop = function stop()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                child.stdout.on('data', function (chunk) { });
                                if (stop.platform == 'upstart')
                                {
                                    child.stdin.write('initctl stop ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    child.stdin.write('service ' + this.name + ' stop\nexit\n');
                                }
                                child.waitExit();
                            };
                            ret.stop.platform = platform;
                            ret.restart = function restart()
                            {
                                if (this.isMe() && this.OpenRC)
                                {
                                    // On OpenRC platforms, we cannot restart our own service using rc-service, so we must use execv
                                    var args = this.parameters();
                                    args.unshift(process.execPath);
                                    require('child_process')._execve(process.execPath, args);
                                }
                                else
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh'], this.OpenRC ? { type: require('child_process').SpawnTypes.TERM } : null);
                                    child.stdout.on('data', function (chunk) { });
                                    if (restart.platform == 'upstart')
                                    {
                                        child.stdin.write('initctl restart ' + this.name + '\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write('service ' + this.name + ' restart\nexit\n');
                                    }
                                    child.waitExit();
                                }
                            };
                            ret.restart.platform = platform;
                            ret.status = function status()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                if (status.platform == 'upstart')
                                {
                                    child.stdin.write('initctl status ' + this.name + '\nexit\n');
                                }
                                else
                                {
                                    if (this.OpenRC)
                                    {
                                        child.stdin.write('rc-status | grep "\\s*' + this.name + ' "\nexit\n');
                                    }
                                    else
                                    {
                                        child.stdin.write('service ' + this.name + ' status\nexit\n');
                                    }
                                }
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            if (ret.OpenRC)
                            {
                                ret.pid = function pid()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    if (this._autorestart)
                                    {
                                        child.stdin.write('cat /var/run/' + this.name + ".pid | awk 'NR==1{ sh=sprintf(\"ps -o pid -o ppid | grep %s\",$0); system(sh); }' | awk '{ if($2!=\"1\") { print $1; }}' | awk 'NR==1{ print $0; }'\nexit\n");
                                    }
                                    else
                                    {
                                        child.stdin.write('cat /var/run/' + this.name + '.pid\nexit\n');
                                    }
                                    child.waitExit();
                                    return (parseInt(child.stdout.str.trim()));
                                }
                                ret.parameters = function()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stderr.on('data', function () { });
                                    child.stdin.write('cat ' + this.conf + ' | grep "^\\s*command_args=" | awk \'NR==1{ gsub(/^\\s*command_args=/,"",$0); print $0; }\'\nexit\n');
                                    child.waitExit();
                                    var val = JSON.parse(child.stdout.str.trim());
                                    val = val.match(/(?:[^\s"]+|"[^"]*")+/g);
                                    return (val);
                                }
                            }
                            ret.status.platform = platform;
                            if(platform == "upstart")
                            {
                                ret.parameters = function parameters()
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout._str = '';
                                    child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                    child.stdin.write('cat ' + this.conf + ' | grep "^exec " | awk \'NR==1{ gsub(/^exec /,"",$0); print $0; }\'\nexit\n');
                                    child.waitExit();
                                    var str = child.stdout._str.trim();
                                    return (str.match(/(?:[^\s"]+|"[^"]*")+/g));

                                };
                            }
                        }
                        else
                        {
                            throw serviceNotFound(name);
                        }
                        break;
                    case 'systemd':
                        var unitNames = [this.escape(name), name];
                        var unitDirs = ['/etc/systemd/system/', '/lib/systemd/system/', '/usr/lib/systemd/system/'];
                        for (var unitDir = 0; unitDir < unitDirs.length && !ret.conf; ++unitDir)
                        {
                            for (var unitName = 0; unitName < unitNames.length && !ret.conf; ++unitName)
                            {
                                var unitPath = unitDirs[unitDir] + unitNames[unitName] + '.service';
                                if (require('fs').existsSync(unitPath)) { ret.conf = unitPath; ret.escname = unitNames[unitName]; }
                            }
                        }

                        if (ret.conf)
                        {
                            Object.defineProperty(ret, "startType",
                                {
                                    get: function ()
                                    {
                                        var child = require('child_process').execFile('/bin/sh', ['sh']);
                                        child.stderr.on('data', function (c) { });
                                        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                        child.stdin.write('systemctl status ' + this.escname.split('\\').join('\\\\') + ' | grep Loaded: | awk \'{ a=split($0, b, ";"); for(c=1;c<=a;++c) { if(b[c]=="enabled" || b[c]==" enabled") { print "true"; } } }\'\nexit\n');
                                        child.waitExit();
                                        return (child.stdout.str.trim() == '' ? 'DEMAND_START' : 'AUTO_START');
                                    }
                                });
                            ret.description = function description()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                if (require('fs').existsSync('/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service'))
                                {
                                    console.info1('cat /lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service')
                                    child.stdin.write('cat /lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service');
                                }
                                else
                                {
                                    console.info1('cat /usr/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service')
                                    child.stdin.write('cat /usr/lib/systemd/system/' + this.escname.split('\\').join('\\\\') + '.service');
                                }
                                child.stdin.write(' | grep Description= | awk -F= \'{ if($1=="Description") { $1=""; print $0; }}\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim());
                            }
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var value = readSystemdDirective(this.conf, 'WorkingDirectory');
                                if (value == null || value == '') { return '/'; }
                                if (value.charAt(0) == '-') { value = value.substring(1); }
                                if (value.charAt(0) == '"' && value.charAt(value.length - 1) == '"') { value = value.substring(1, value.length - 1); }
                                return value.replace(/\\x([0-9a-f]{2})/gi, function (_, hex) { return String.fromCharCode(parseInt(hex, 16)); });
                            };
                            ret.appLocation = function () { return systemdExecutable(this.conf); };
                            ret.isMe = function isMe()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = '';
                                child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                                console.info1("systemctl status " + this.escname.split('\\').join('\\\\') + ".service");
                                child.stdin.write("systemctl status " + this.escname.split('\\').join('\\\\') + ".service | grep 'Main PID:' | awk 'NR==1{print $3}'\nexit\n");
                                child.waitExit();
                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.isRunning = function isRunning() { return systemdIsRunning(this.escname); };
                            ret.start = function start() { runSystemctl(['start', this.escname + '.service']); };
                            ret.stop = function stop() { runSystemctl(['stop', this.escname + '.service']); };
                            ret.restart = function restart() { runSystemctl(['restart', this.escname + '.service']); };
                            ret.status = function status() {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                child.stdin.write('systemctl status ' + this.escname.split('\\').join('\\\\') + '.service\nexit\n');
                                child.waitExit();
                                return (child.stdout._str);
                            };
                            ret.parameters = function parameters()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout._str = '';
                                child.stdout.on('data', function (chunk) { this._str += chunk.toString(); });
                                child.stdin.write('cat ' + this.conf.split('\\').join('\\\\') + ' | grep "^ExecStart=" | awk \'NR==1{ gsub(/^ExecStart=/,"",$0); print $0; }\'\nexit\n');
                                child.waitExit();
                                var str = child.stdout._str.trim();
                                return (str.match(/(?:[^\s"]+|"[^"]*")+/g));
                            };
                        }
                        else
                        {
                            throw serviceNotFound(name);
                        }
                        break;
                    default:
                        // Pseudo Service (meshDaemon)
                        if (require('fs').existsSync('/usr/local/mesh_daemons/' + name + '.service'))
                        {
                            ret.conf = '/usr/local/mesh_daemons/' + name + '.service';
                            ret.parameters = function parameters()
                            {
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) { });
                                child.stdin.write('cat ' + this.conf + ' | grep "^[ \\t]*parameters=" | awk \'NR==1{ gsub(/^[ \t]*parameters=/,"",$0); print $0; }\'\nexit\n');
                                child.waitExit();
                                try
                                {
                                    return (JSON.parse(child.stdout.str.trim()));
                                }
                                catch(e)
                                {
                                    return ([]);
                                }
                            };
                            ret.start = function start()
                            {
                                var child;
                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) {  });
                                child.stdin.write('cat ' + this.conf + ' | grep "^[ \\t]*respawn$"\nexit\n');
                                child.waitExit();

                                var respawn = child.stdout.str.trim() != '';
                                var wd = this.appWorkingDirectory();
                                var parameters = this.parameters();
                                var location = wd + parameters.shift();

                                var options = { pidPath: wd + 'pid', logOutputs: true, crashRestart: respawn, cwd: wd };
                                require('service-manager').manager.daemon(location, parameters, options);
                            };
                            ret.stop = function stop()
                            {
                                var pidpath = this.appWorkingDirectory().split(' ').join('\\ ') + 'pid';
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat ' + pidpath + '\nexit\n');
                                child.waitExit();
                                try
                                {
                                    process.kill(parseInt(child.stdout.str.trim()), 'SIGTERM');
                                }
                                catch(x)
                                {
                                }
                            };
                            ret.restart = function restart()
                            {
                                if(!this.isMe())
                                {
                                    this.stop();
                                    this.start();
                                    return;
                                }

                                var p = this.parameters();
                                p.unshift(process.execPath);
                                require('child_process')._execve(process.execPath, p);
                            }
                            ret.isMe = function isMe()
                            {
                                var pidpath = this.appWorkingDirectory().split(' ').join('\\ ') + 'pid';
                                var child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('cat ' + pidpath + '\nexit\n');
                                child.waitExit();
                                var pid = child.stdout.str.trim();
                                if (pid == '') { return (false); }

                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stdin.write('ps -e -o pid -o ppid | grep "[ \\t]*' + pid + '$" | awk \'NR==1{ print $1; }\'\nexit\n');
                                child.waitExit();

                                return (parseInt(child.stdout.str.trim()) == process.pid);
                            };
                            ret.appWorkingDirectory = function appWorkingDirectory()
                            {
                                var child;
                                child = require('child_process').execFile('/bin/sh', ['sh']);
                                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                child.stderr.on('data', function (c) { });
                                child.stdin.write('cat ' + this.conf + " | grep 'workingDirectory=' | awk 'NR==1" +  '{ gsub(/^.+=/,"",$0); gsub("/$","",$0); printf "%s/",$0; }\'\nexit\n');
                                child.waitExit();
                                return (child.stdout.str.trim());
                            };
                            ret.appLocation = function appLocation()
                            {
                                return (this.appWorkingDirectory() + this.parameters().shift());
                            };
                            ret.isRunning = function isRunning()
                            {
                                var pidpath = this.appWorkingDirectory() + 'pid';
                                console.log('pidpath', pidpath);

                                if(require('fs').existsSync(pidpath))
                                {
                                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stdin.write('cat ' + pidpath.split(' ').join('\\ ') + '\nexit\n');
                                    child.waitExit();
                                    var pid = child.stdout.str.trim();

                                    child = require('child_process').execFile('/bin/sh', ['sh']);
                                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                                    child.stdin.write('ps -p ' + pid + ' -o pid h\nexit\n');
                                    child.waitExit();
                                    if(child.stdout.str.trim() == pid)
                                    {
                                        return (true);
                                    }
                                    else
                                    {
                                        try
                                        {
                                            require('fs').unlinkSync('/usr/local/mesh_daemons/' + name + '/pid');
                                        }
                                        catch(x)
                                        {
                                        }
                                        return (false);
                                    }
                                }
                                else
                                {
                                    return (false);
                                }
                            };
                        }
                        else
                        {
                            throw serviceNotFound(name);
                        }
                        break;
                }
                try
                {
                    Object.defineProperty(ret, 'installedDate', { value: require('fs').statSync(ret.conf).ctime });
                }
                catch (xx)
                {
                    console.log(xx);
                }
                return (ret);
            };
        }
        this.enumerateService = function (options)
        {
            var results = [];
            var paths = [];
            var runtable = {};
            switch(process.platform)
            {
                case 'linux':
                    switch((options && options.platformType)?options.platformType : this.getServiceType())
                    {
                        case 'init':
                            paths.push('/etc/init.d');
                            break;
                        case 'upstart':
                            paths.push('/etc/init');
                            runtable = _upstart_GetServiceTable();
                            break;
                        case 'systemd':
                            paths.push('/etc/systemd/system');
                            paths.push('/lib/systemd/system');
                            paths.push('/usr/lib/systemd/system');
                            runtable = _systemd_GetServiceTable();
                            break;
                        default:
                            paths.push('/usr/local/mesh_daemons');
                            break;
                    }
                    break;
                case 'freebsd':
                    paths.push('/etc/rc.d');
                    paths.push('/usr/local/etc/rc.d');
                    break;
                case 'darwin':
                    paths.push('/Library/LaunchDaemons');
                    paths.push('/System/Library/LaunchDaemons');
                    break;
            }

            for(var i in paths)
            {
                if (!require('fs').existsSync(paths[i])) { continue; }
                var files = require('fs').readdirSync(paths[i]);
                for(var j in files)
                {
                    switch(process.platform)
                    {
                        case 'linux':
                            switch ((options && options.platformType) ? options.platformType : this.getServiceType())
                            {
                                case 'init':
                                    try
                                    {
                                        results.push(this.getService(files[j], 'init'));
                                    }
                                    catch (e)
                                    {
                                    }
                                    break;
                                case 'upstart':
                                    if (files[j].endsWith('.conf'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.conf')[0], 'upstart'));
                                            if(runtable[results.peek().name])
                                            {
                                                results.peek().state = runtable[results.peek().name].state;
                                                if(runtable[results.peek().name].pid != '')
                                                {
                                                    try
                                                    {
                                                        results.peek().pid = parseInt(runtable[results.peek().name].pid);
                                                    }
                                                    catch(px)
                                                    {
                                                    }
                                                }
                                            }
                                        }
                                        catch (e)
                                        {
                                        }
                                    }
                                    break;
                                case 'systemd':
                                    if (files[j].endsWith('.service'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.service')[0], 'systemd'));
                                            if (runtable[results.peek().conf.split('/').pop()]) { results.peek().state = 'RUNNING'; }
                                        }
                                        catch(e)
                                        {
                                        }
                                    }
                                    break;
                                default:
                                    if (files[j].endsWith('.service'))
                                    {
                                        try
                                        {
                                            results.push(this.getService(files[j].split('.service')[0], 'unknown'));
                                        }
                                        catch (e)
                                        {
                                        }
                                    }
                                    break;
                            }
                            break;
                        case 'freebsd':
                            try
                            {
                                results.push(this.getService(files[j]));
                            }
                            catch (e)
                            {
                            }
                            break;
                        case 'darwin':
                            if (files[j].endsWith('.plist'))
                            {
                                try
                                {
                                    results.push(fetchPlist(paths[i], files[j].split('.plist')[0]));
                                }
                                catch (e)
                                {
                                }
                            }
                            break;
                    }
                }
            }
            for (var k in results)
            {
                if (results[k].description) { results[k].description = results[k].description(); }
            }
            return (results);
        };
    }
    this.installService = function installService(options)
    {
        if (process.platform == 'darwin') { return macInstallService(options, this); }
        if (process.platform == 'linux') { options.name = options.serviceKey || this.escape(options.name); }
        if (!options.target) { options.target = options.name; }
        if (!options.displayName) { options.displayName = options.name; }
        if (options.installPath && options.installInPlace) { throw ('Cannot specify both installPath and installInPlace'); }
        if (process.platform == 'win32') { throw (windowsServiceManagerLifecycleDisabledError('install')); }
        if (process.platform != 'win32')
        {
            if (!options.servicePlatform) { options.servicePlatform = this.getServiceType(); }
            if (options.servicePlatform == 'systemd' && options.target.indexOf("'") >= 0) { throw new Error('Unsupported apostrophe in executable basename; refusing to rename identity.'); }
            if (options.installInPlace)
            {
                var svcPath = options.servicePath.replace(/\/+$/, '');
                var parts = svcPath.split('/');
                if (parts.length > 1)
                {
                    parts.pop();
                    options.installPath = parts.join('/');
                    if (options.installPath === '') { options.installPath = '/'; }
                }
                else
                {
                    options.installPath = '/';
                }
            }
            if (options.installPath == null)
            {
                if (options.servicePlatform == 'unknown')
                {
                    options.installPath = '/usr/local/mesh_daemons/' + (options.companyName!=null?(options.companyName + '/'):('')) + options.name;
                }
                else
                {
                    options.installPath = '/usr/local/mesh_services/' + (options.companyName != null ? (options.companyName + '/') : ('')) + this.unescape(options.name).split("'").join('-');
                }
            }
        }
        if (options.installPath) { if (!options.installPath.endsWith(process.platform == 'win32' ? '\\' : '/')) { options.installPath += (process.platform == 'win32' ? '\\' : '/'); } }
        console.info1('Service Install Path = ' + options.installPath);
        if (options.installPath == null) { options.installPath = '/usr/local/mesh_services/' + options.name + '/'; }
        prepareFolders(options.installPath);

        if (options.binary)
        {
            require('fs').writeFileSync(options.installPath + options.target, options.binary);
        }
        else
        {
            if (options.servicePath != (options.installPath + options.target))
            {
                require('fs').copyFileSync(options.servicePath, options.installPath + options.target);
            }
        }
        console.info1('Files Copied');
        var m = require('fs').statSync(options.installPath + options.target).mode;
        m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
        require('fs').chmodSync(options.installPath + options.target, m);
        if (process.platform == 'freebsd')
        {
            if (!this.isAdmin()) { console.log('Installing a Service requires root'); throw ('Installing as Service, requires root'); }
            var parameters = options.parameters ? options.parameters.join(' ') : '';
            var m;
            if (require('fs').existsSync('/usr/sbin/daemon'))
            {
                // FreeBSD
                var rc = require('fs').createWriteStream('/usr/local/etc/rc.d/' + options.name, { flags: 'wb' });
                rc.write('#!/bin/sh\n');
                rc.write('# PROVIDE: ' + options.name + '\n');
                rc.write('# REQUIRE: FILESYSTEMS NETWORKING\n');
                rc.write('# KEYWORD: shutdown\n');
                rc.write('. /etc/rc.subr\n\n');
                rc.write('name="' + options.name + '"\n');
                rc.write('desc="' + (options.description ? options.description : 'MeshCentral Agent') + '"\n');
                rc.write('rcvar=${name}_enable\n');
                rc.write('pidfile="/var/run/' + options.name + '.pid"\n');
                rc.write(options.name + '_chdir="' + options.installPath.split(' ').join('\\ ') + '"\n');

                rc.write('command="/usr/sbin/daemon"\n');
                rc.write('command_args="-P ${pidfile} ' + ((options.failureRestart == null || options.failureRestart > 0) ? '-r' : '') + ' -f \\"' + options.installPath + options.target + '\\" ' + parameters.split('"').join('\\"') + '"\n');

                rc.write('\n');
                rc.write('load_rc_config $name\n');
                rc.write(': ${' + options.name + '_enable="' + ((options.startType == 'AUTO_START' || options.startType == 'BOOT_START') ? 'YES' : 'NO') + '"}\n');
                rc.write('run_rc_command "$1"\n');
                rc.end();
                m = require('fs').statSync('/usr/local/etc/rc.d/' + options.name).mode;
                m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                require('fs').chmodSync('/usr/local/etc/rc.d/' + options.name, m);
            }
            else
            {
                // OpenBSD
                var script = "require('service-manager').manager.daemonEx('" + options.installPath + options.target + "', " + JSON.stringify(options.parameters) + ", {crashRestart: " + ((options.failureRestart == null || options.failureRestart > 0) ? "true" : "false") + ', cwd: "' + options.installPath.split(' ').join('\\ ') + '"});';
                script = Buffer.from(script).toString('base64');

                var rc = require('fs').createWriteStream('/etc/rc.d/' + options.name, { flags: 'wb' });
                rc.write('#!/bin/sh\n');
                rc.write('# PROVIDE: ' + options.name + '\n');
                rc.write('name="' + options.name + '"\n');
                rc.write('desc="' + (options.description ? options.description : 'MeshCentral Agent') + '"\n');
                rc.write(options.name + '_chdir="' + options.installPath.split(' ').join('\\ ') + '"\n');
                rc.write('daemon="' + options.installPath + options.target + '_loader"\n');
                rc.write('daemon_flags="-b64exec ' + script + ' &"\n');
                rc.write('. /etc/rc.d/rc.subr\n\n');
                rc.write('rc_cmd "$1"\n');
                rc.end();
                m = require('fs').statSync('/etc/rc.d/' + options.name).mode;
                m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                require('fs').chmodSync('/etc/rc.d/' + options.name, m);

                require('fs').copyFileSync(process.execPath, options.installPath + options.target + '_loader');
                require('fs').chmodSync(options.installPath + options.target + '_loader', m);
                if(options.startType == 'AUTO_START' || options.startType == 'BOOT_START')
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("rcctl enable " + options.name + "\nexit\n");
                    child.waitExit();
                }
            }

            if ((this.pfSense || this.OPNsense) && (options.startType == 'AUTO_START' || options.startType == 'BOOT_START'))
            {
                if (this.pfSense)
                {
                    // pfSense requries scripts in rc.d to end with .sh, unlike other *bsd, for AUTO_START to work
                    require('fs').copyFileSync('/usr/local/etc/rc.d/' + options.name, '/usr/local/etc/rc.d/' + options.name + '.sh');
                    require('fs').chmodSync('/usr/local/etc/rc.d/' + options.name + '.sh', m);
                }
                if (this.OPNsense)
                {
                    // OPNsense requires a syshook start script
                    var s = require('fs').createWriteStream('/usr/local/etc/rc.syshook.d/start/50-' + options.name.split(' ').join(''), { flags: 'wb' });
                    s.write('#!/bin/sh\n');
                    s.write('echo -n "Starting ' + options.name + ': "\n');
                    s.write('service "' + options.name + '" start\n\n');
                    s.end();
                    require('fs').chmodSync('/usr/local/etc/rc.syshook.d/start/50-' + options.name.split(' ').join(''), m);
                }

                // pfSense and OPNsense needs to have rc.conf.local override enable, for AUTO_START to work correctly, unlike other *BSD
                var s = require('fs').createWriteStream('/etc/rc.conf.local', { flags: 'a' });
                s.write('\n' + options.name + '_enable="YES"\n');
                s.end();
            }
        }
        if(process.platform == 'linux')
        {
            if (!this.isAdmin()) { console.log('Installing a Service requires root'); throw ('Installing as Service, requires root'); }
            var parameters = options.parameters ? options.parameters.join(' ') : '';
            var conf;
           
            switch (options.servicePlatform)
            {
                case 'procd':
                    var conf = require('fs').createWriteStream('/etc/init.d/' + options.name, { flags: 'wb' });    
                    conf.write('#!/bin/sh /etc/rc.common\n');
                    conf.write('USE_PROCD=1\n');
                    conf.write('START=95\n');
                    conf.write('STOP=01\n');
                    conf.write('start_service()\n');
                    conf.write('{\n');
                    conf.write('    procd_open_instance\n');
                    conf.write('    procd_set_param command /bin/sh "' + options.installPath + options.name + '.sh"\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('    procd_set_param respawn ${threshold:-10} ${timeout:-' + (options.failureRestart == null ? 2 : (options.failureRestart / 1000)) + '} ${retry:-0}\n');
                    }
                    conf.write('    procd_close_instance\n');
                    conf.write('}\n');
                    conf.end();

                    conf = require('fs').createWriteStream(options.installPath + options.name + '.sh', { flags: 'wb' });
                    conf.write('#!/bin/sh\n');
                    conf.write('cd "' + options.installPath + '"\n');
                    conf.write('exec "./' + options.target + '" ' + options.parameters.join(' ') + '\n');
                    conf.end();

                    m = require('fs').statSync('/etc/init.d/' + options.name).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/etc/init.d/' + options.name, m);

                    m = require('fs').statSync(options.installPath + options.name + '.sh').mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync(options.installPath + options.name + '.sh', m);

                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.on('data', function (chunk) { });
                            child.stdin.write('/etc/init.d/' + options.name + ' enable\nexit\n');
                            child.waitExit();
                            break;
                        default:
                            break;
                    }

                    break;
                case 'init':
                    conf = require('fs').createWriteStream('/etc/init.d/' + options.name, { flags: 'wb' });
                    var isOpenRC = false;
                    if (require('fs').existsSync('/sbin/openrc-run'))
                    {
                        // OpenRC
                        isOpenRC = true;
                        conf.write('#!/sbin/openrc-run\n\n');
                        conf.write('name="' + options.name + '"\n');
                        conf.write('command="' + options.installPath + options.target + '"\n');
                        conf.write('command_args="' + parameters.split('"').join('\\"') + '"\n');
                        if (options.failureRestart == null || options.failureRestart > 0)
                        {
                            // Auto Crash Restart
                            conf.write('supervisor="supervise-daemon"\n');
                            conf.write('supervise_daemon_args="--chdir \\"' + options.installPath + '\\""\n\n');
                        }
                        else
                        {
                            // No Auto Crash Restartclear
                            conf.write('command_background=true\n');
                            conf.write('start_stop_daemon_args="--chdir \\"' + options.installPath + '\\""\n\n');                     
                        }
                        conf.write('pidfile="/var/run/' + options.name + '.pid"\n');
                        conf.write('depend() {\n');
                        conf.write(' want net\n');
                        conf.write('}\n');
                        conf.end();
                    }
                    else
                    {
                        // Traditional init.d

                        if (options.failureRestart == null || options.failureRestart > 0)
                        {
                            // Crash Restart is enabled, but it isn't inherently supported by INIT, so we must fake it with JS
                            var tmp_parameters = options.parameters ? options.parameters.slice() : [];
                            tmp_parameters.unshift('{{{}}}');
                            tmp_parameters = JSON.stringify(tmp_parameters).split('"{{{}}}"').join('process.argv0');
                            parameters = "var child; process.on('SIGTERM', function () { child.removeAllListeners('exit'); child.kill(); process.exit(); }); function start() { child = require('child_process').execFile(process.execPath, " + tmp_parameters + "); child.stdout.on('data', function (c) { }); child.stderr.on('data', function (c) { }); child.on('exit', function (status) { start(); }); } start();";
                            parameters = '-b64exec ' + Buffer.from(parameters).toString('base64');
                        }

                        // The following is the init.d script I wrote. Rather than having to deal with escaping the thing, I just Base64 encoded it to prevent issues.
                        conf.write(Buffer.from('IyEvYmluL3NoCgoKU0NSSVBUPVpaWlpaWVlZWVkKUlVOQVM9cm9vdAoKUElERklMRT0vdmFyL3J1bi9YWFhYWC5waWQKTE9HRklMRT0vdmFyL2xvZy9YWFhYWC5sb2cKCnN0YXJ0KCkgewogIGlmIFsgLWYgIiRQSURGSUxFIiBdICYmIGtpbGwgLTAgJChjYXQgIiRQSURGSUxFIikgMj4vZGV2L251bGw7IHRoZW4KICAgIGVjaG8gJ1NlcnZpY2UgYWxyZWFkeSBydW5uaW5nJyA+JjIKICAgIHJldHVybiAxCiAgZmkKICBlY2hvICdTdGFydGluZyBzZXJ2aWNl4oCmJyA+JjIKICBsb2NhbCBDTUQ9IiRTQ1JJUFQge3tQQVJNU319ICY+IFwiJExPR0ZJTEVcIiAmIGVjaG8gXCQhIgogIGxvY2FsIENNRFBBVEg9JChlY2hvICRTQ1JJUFQgfCBhd2sgJ3sgbGVuPXNwbGl0KCQwLCBhLCAiLyIpOyBwcmludCBzdWJzdHIoJDAsIDAsIGxlbmd0aCgkMCktbGVuZ3RoKGFbbGVuXSkpOyB9JykKICBjZCAkQ01EUEFUSAogIHN1IC1jICIkQ01EIiAkUlVOQVMgPiAiJFBJREZJTEUiCiAgZWNobyAnU2VydmljZSBzdGFydGVkJyA+JjIKfQoKc3RvcCgpIHsKICBpZiBbICEgLWYgIiRQSURGSUxFIiBdOyB0aGVuCiAgICBlY2hvICdTZXJ2aWNlIG5vdCBydW5uaW5nJyA+JjIKICAgIHJldHVybiAxCiAgZWxzZQoJcGlkPSQoIGNhdCAiJFBJREZJTEUiICkKCWlmIGtpbGwgLTAgJHBpZCAyPi9kZXYvbnVsbDsgdGhlbgogICAgICBlY2hvICdTdG9wcGluZyBzZXJ2aWNl4oCmJyA+JjIKICAgICAga2lsbCAtMTUgJHBpZAogICAgICBlY2hvICdTZXJ2aWNlIHN0b3BwZWQnID4mMgoJZWxzZQoJICBlY2hvICdTZXJ2aWNlIG5vdCBydW5uaW5nJwoJZmkKCXJtIC1mICQiUElERklMRSIKICBmaQp9CnJlc3RhcnQoKXsKCXN0b3AKCXN0YXJ0Cn0Kc3RhdHVzKCl7CglpZiBbIC1mICIkUElERklMRSIgXQoJdGhlbgoJCXBpZD0kKCBjYXQgIiRQSURGSUxFIiApCgkJaWYga2lsbCAtMCAkcGlkIDI+L2Rldi9udWxsOyB0aGVuCgkJCWVjaG8gIlhYWFhYIHN0YXJ0L3J1bm5pbmcsIHByb2Nlc3MgJHBpZCIKCQllbHNlCgkJCWVjaG8gJ1hYWFhYIHN0b3Avd2FpdGluZycKCQlmaQoJZWxzZQoJCWVjaG8gJ1hYWFhYIHN0b3Avd2FpdGluZycKCWZpCgp9CgoKY2FzZSAiJDEiIGluCglzdGFydCkKCQlzdGFydAoJCTs7CglzdG9wKQoJCXN0b3AKCQk7OwoJcmVzdGFydCkKCQlzdG9wCgkJc3RhcnQKCQk7OwoJc3RhdHVzKQoJCXN0YXR1cwoJCTs7CgkqKQoJCWVjaG8gIlVzYWdlOiBzZXJ2aWNlIFhYWFhYIHtzdGFydHxzdG9wfHJlc3RhcnR8c3RhdHVzfSIKCQk7Owplc2FjCmV4aXQgMAoK', 'base64').toString()
                            .split('ZZZZZ').join(options.installPath)
                            .split('XXXXX').join(options.name)
                            .split('YYYYY').join(options.target)
                            .replace('{{PARMS}}', parameters));
                        conf.end();
                    }

                    m = require('fs').statSync('/etc/init.d/' + options.name).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/etc/init.d/' + options.name, m);
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            var child = require('child_process').execFile('/bin/sh', ['sh']);
                            child.stdout.on('data', function (chunk) { });
                            if (isOpenRC)
                            {
                                child.stdin.write('rc-update add ' + options.name + ' default\nexit\n');
                            }
                            else
                            {
                                child.stdin.write('update-rc.d ' + options.name + ' defaults\nexit\n');
                            }
                            child.waitExit();
                            break;
                        default:
                            break;
                    }
                    break;
                case 'upstart':
                    conf = require('fs').createWriteStream('/etc/init/' + options.name + '.conf', { flags: 'wb' });
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            if (require('os').Name.startsWith('CHROMEOS_'))
                            {
                                conf.write('start on started system-services\n');
                            }
                            else
                            {
                                conf.write('start on runlevel [2345]\n');
                            }
                            break;
                        default:
                            break;
                    }
                    conf.write('stop on runlevel [016]\n\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('respawn\n\n');
                    }
                    conf.write('chdir "' + options.installPath + '"\n');
                    conf.write('exec "' + options.installPath + options.target + '" ' + parameters + '\n\n');
                    conf.end();
                    break;
                case 'systemd':
                    var serviceDescription = options.description ? options.description : 'MeshCentral Agent';
                    if (require('fs').existsSync('/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                        console.info1('/lib/systemd/system/' + options.name + '.service');
                    }
                    else if (require('fs').existsSync('/usr/lib/systemd/system'))
                    {
                        conf = require('fs').createWriteStream('/usr/lib/systemd/system/' + options.name + '.service', { flags: 'wb' });
                        console.info1('/usr/lib/systemd/system/' + options.name + '.service');
                    }
                    else
                    {
                        throw ('unknown location for systemd configuration files');
                    }
                    conf.write('[Unit]\n');
                    conf.write('Description=' + serviceDescription + '\n');
                    conf.write('Wants=network-online.target\n');
                    conf.write('After=network-online.target\n');
                    conf.write('[Service]\n');
                    conf.write('WorkingDirectory=' + options.installPath + '\n');
                    conf.write('ExecStart=' + options.installPath.split(' ').join('\\x20') + options.target.split(' ').join('\\x20') + ' ' + parameters + '\n');
                    conf.write('StandardOutput=null\n');
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('Restart=on-failure\n');
                        if (options.failureRestart == null)
                        {
                            conf.write('RestartSec=3\n');
                        }
                        else
                        {
                            conf.write('RestartSec=' + (options.failureRestart / 1000) + '\n');
                        }
                    }
                    switch (options.startType)
                    {
                        case 'BOOT_START':
                        case 'SYSTEM_START':
                        case 'AUTO_START':
                            conf.write('[Install]\n');
                            conf.write('WantedBy=multi-user.target\n');
                            conf.write('Alias=' + options.name + '.service\n');
                            conf.end();
                            this._update = require('child_process').execFile('/bin/sh', ['sh']);
                            this._update._moduleName = options.name;
                            this._update.stdout.on('data', function (chunk) { });
                            this._update.stderr.on('data', function (chunk) { console.info1(chunk.toString()); });
                            this._update.stdin.write('systemctl --system daemon-reload\n');
                            console.info1('systemctl enable ' + options.name + '.service');
                            this._update.stdin.write('systemctl enable ' + options.name.split('\\').join('\\\\') + '.service\n');
                            this._update.stdin.write('exit\n');
                            this._update.waitExit();
                        default:
                            conf.end();
                            this._update = require('child_process').execFile('/bin/sh', ['sh']);
                            this._update._moduleName = options.name;
                            this._update.stdout.on('data', function (chunk) { });
                            this._update.stdin.write('systemctl --system daemon-reload\n');
                            this._update.stdin.write('exit\n');
                            this._update.waitExit();
                            break;
                    }
                    break;
                default: // Unknown Service Type, install as a Pseudo Service (MeshDaemon)
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/')) { require('fs').mkdirSync('/usr/local/mesh_daemons'); }
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/' + options.name)) { require('fs').mkdirSync('/usr/local/mesh_daemons/' + options.name); }
                    if (!require('fs').existsSync('/usr/local/mesh_daemons/daemon'))
                    {
                        var exeGuid = 'B996015880544A19B7F7E9BE44914C18';
                        var daemonJS = Buffer.from('LyoKQ29weXJpZ2h0IDIwMTkgSW50ZWwgQ29ycG9yYXRpb24KCkxpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSAiTGljZW5zZSIpOwp5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuCllvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdAoKICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMAoKVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZQpkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiAiQVMgSVMiIEJBU0lTLApXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC4KU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZApsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4KKi8KCgppZiAocHJvY2Vzcy5hcmd2Lmxlbmd0aCA8IDMpCnsKICAgIGNvbnNvbGUubG9nKCd1c2FnZTogZGFlbW9uIFsgc3RhcnQgfCBzdG9wIHwgc3RhdHVzIF0gW3NlcnZpY2VdJyk7CiAgICBwcm9jZXNzLmV4aXQoKTsKfQoKdmFyIHMgPSBudWxsOwp0cnkKewogICAgcyA9IHJlcXVpcmUoJ3NlcnZpY2UtbWFuYWdlcicpLm1hbmFnZXIuZ2V0U2VydmljZShwcm9jZXNzLmFyZ3ZbMl0pOwp9CmNhdGNoKHgpCnsKICAgIGNvbnNvbGUubG9nKHgpOwogICAgcHJvY2Vzcy5leGl0KCk7Cn0KCnN3aXRjaChwcm9jZXNzLmFyZ3ZbMV0pCnsKICAgIGNhc2UgJ3N0YXJ0JzoKICAgICAgICBzLnN0YXJ0KCk7CiAgICAgICAgY29uc29sZS5sb2coJ1N0YXJ0aW5nLi4uJyk7CiAgICAgICAgYnJlYWs7CiAgICBjYXNlICdzdG9wJzoKICAgICAgICBzLnN0b3AoKTsKICAgICAgICBjb25zb2xlLmxvZygnU3RvcHBpbmcuLi4nKTsKICAgICAgICBicmVhazsKICAgIGNhc2UgJ3N0YXR1cyc6CiAgICAgICAgaWYgKHMuaXNSdW5uaW5nKCkpCiAgICAgICAgewogICAgICAgICAgICBjb25zb2xlLmxvZygnUnVubmluZywgUElEID0gJyArIHJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvdXNyL2xvY2FsL21lc2hfZGFlbW9ucy8nICsgcHJvY2Vzcy5hcmd2WzJdICsgJy9waWQnKS50b1N0cmluZygpKTsKICAgICAgICB9CiAgICAgICAgZWxzZQogICAgICAgIHsKICAgICAgICAgICAgY29uc29sZS5sb2coJ05vdCBydW5uaW5nJyk7CiAgICAgICAgfQogICAgICAgIGJyZWFrOwogICAgZGVmYXVsdDoKICAgICAgICBjb25zb2xlLmxvZygnVW5rbm93biBjb21tYW5kOiAnICsgcHJvY2Vzcy5hcmd2WzFdKTsKICAgICAgICBicmVhazsKfQoKcHJvY2Vzcy5leGl0KCk7Cg==', 'base64');
                        var exe = require('fs').readFileSync(process.execPath);
                        var padding = Buffer.alloc(8 - ((exe.length + daemonJS.length + 16 + 4) % 8));
                        var w = require('fs').createWriteStream('/usr/local/mesh_daemons/daemon', { flags: "wb" });
                        var daemonJSLen = Buffer.alloc(4);
                        daemonJSLen.writeUInt32BE(daemonJS.length);

                        w.write(exe);
                        if (padding.length > 0) { w.write(padding); }
                        w.write(daemonJS);
                        w.write(daemonJSLen);
                        w.write(Buffer.from(exeGuid, 'hex'));
                        w.end();

                        require('fs').chmodSync('/usr/local/mesh_daemons/daemon', require('fs').statSync('/usr/local/mesh_daemons/daemon').mode | require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP);
                    }

                    if (options.servicePath != '/usr/local/mesh_daemons/' + options.name + '/' + options.target)
                    {
                        require('fs').copyFileSync(options.servicePath, '/usr/local/mesh_daemons/' + options.name + '/' + options.target);
                    }
                    var m = require('fs').statSync('/usr/local/mesh_daemons/' + options.name + '/' + options.target).mode;
                    m |= (require('fs').CHMOD_MODES.S_IXUSR | require('fs').CHMOD_MODES.S_IXGRP | require('fs').CHMOD_MODES.S_IXOTH);
                    require('fs').chmodSync('/usr/local/mesh_daemons/' + options.name + '/' + options.target, m);

                    conf = require('fs').createWriteStream('/usr/local/mesh_daemons/' + options.name + '.service', { flags: 'wb' });
                    conf.write('workingDirectory=' + '/usr/local/mesh_daemons/' + (options.companyName!=null?(options.companyName + '/'):'') + options.name + '\n');

                    if(!options.parameters) {options.parameters = [];}
                    options.parameters.unshift(options.target);
                    conf.write('parameters=' + JSON.stringify(options.parameters) + '\n');
                    options.parameters.shift();
                    if (options.failureRestart == null || options.failureRestart > 0)
                    {
                        conf.write('respawn\n');
                    }
                    conf.end();
                    break;
            }
        }
        if (options.files)
        {
            for (var i in options.files)
            {
                if (options.files[i]._buffer)
                {
                    console.log('writing ' + extractFileName(options.files[i]));
                    require('fs').writeFileSync(options.installPath + extractFileName(options.files[i]), options.files[i]._buffer);
                }
                else
                {
                    console.log('copying ' + extractFileSource(options.files[i]));
                    require('fs').copyFileSync(extractFileSource(options.files[i]), options.installPath + extractFileName(options.files[i]));
                }
            }
        }

    }
    if (process.platform == 'darwin')
    {
        this.installLaunchAgent = function installLaunchAgent(options)
        {
            macServiceName(options.name);
            var sessions = require('user-sessions'), fs = require('fs');
            var uid = options.uid;
            if (uid == null && options.user != null) { uid = sessions.getUid(options.user); }
            if (uid != null && (!/^\d+$/.test('' + uid) || Number(uid) <= 0)) { throw new Error('Invalid LaunchAgent user UID'); }
            if (!this.isAdmin() && (uid == null || Number(uid) != sessions.Self())) { throw new Error('Cannot install a LaunchAgent for another user'); }
            var username = uid != null ? sessions.getUsername(uid) : null;
            var folder = username != null ? sessions.getHomeFolder(username) + '/Library/LaunchAgents' : '/Library/LaunchAgents';
            var file = folder + '/' + options.name + '.plist', created = false;
            if (fs.existsSync(file)) { throw new Error('LaunchAgent already exists: ' + options.name); }
            var xml = macBuildLaunchdPlist(options, true), directories = [];
            try
            {
                macPrepareFolders(folder, directories);
                if (uid != null)
                {
                    var gid = sessions.getGroupID(uid);
                    for (var i = 0; i < directories.length; ++i) { fs.chownSync(directories[i], uid, gid); }
                }
                macWritePlist(file, xml); created = true;
                if (uid != null) { fs.chownSync(file, uid, gid); }
                return { plist: file };
            }
            catch (e)
            {
                if (created) { try { fs.unlinkSync(file); } catch (cleanup) { throw new Error(e + '; LaunchAgent cleanup failed: ' + cleanup); } }
                for (var i = directories.length - 1; i >= 0; --i) { try { fs.rmdirSync(directories[i]); } catch (ignored) { } }
                throw e;
            }
        };
    }

    this.uninstallService = function uninstallService(name, options)
    {
        if (process.platform == 'win32') { throw (windowsServiceManagerLifecycleDisabledError('uninstall')); }
        if (!this.isAdmin()) { throw ('Uninstalling a service, requires admin'); }

        if (typeof (name) == 'object') { name = name.name; }
        var service = this.getService(name);
        var servicePath = service.appLocation();
        var workingPath = service.appWorkingDirectory();
        // procd service objects have no isRunning(); their stop is handled per service type below.
        if (typeof service.isRunning == 'function' && service.isRunning())
        {
            if (process.platform == 'darwin') { service.unload(); } else { service.stop(); }
            if (service.isRunning()) { throw new Error('Service remains running; uninstall aborted: ' + name); }
        }

        if(process.platform == 'linux')
        {
            switch (this.getServiceType())
            {
                case 'procd':
                    this._update = require('child_process').execFile('/bin/sh', ['sh']);
                    this._update.stdout.on('data', function (chunk) { });
                    this._update.stdin.write('/etc/init.d/' + name + ' stop\n');
                    this._update.stdin.write('/etc/init.d/' + name + ' disable\n');
                    this._update.stdin.write('exit\n');
                    this._update.waitExit();
                    try
                    {
                        require('fs').unlinkSync(service.conf);
                        if (!options || !options.skipDeleteBinary)
                        {
                            require('fs').unlinkSync(servicePath);
                            require('fs').unlinkSync(workingPath + name + '.sh');
                        }
                        console.log(name + ' uninstalled');
                    }
                    catch (e)
                    {
                        console.log(name + ' could not be uninstalled', e)
                    }
                    
                    break;
                case 'init':
                case 'upstart':
                    if (require('fs').existsSync('/etc/init.d/' + name))
                    {
                        // init.d service
                        this._update = require('child_process').execFile('/bin/sh', ['sh']);
                        this._update.stdout.on('data', function (chunk) { });
                        this._update.stdin.write('service ' + name + ' stop\n');
                        if (service.OpenRC)
                        {
                            if (service.startType == 'AUTO_START')
                            {
                                this._update.stdin.write('rc-update del ' + name + ' default\n');
                            }
                        }
                        else
                        {
                            this._update.stdin.write('update-rc.d -f ' + name + ' remove\n');
                        }
                        this._update.stdin.write('exit\n');
                        this._update.waitExit();
                        try
                        {
                            require('fs').unlinkSync('/etc/init.d/' + name);
                            if (!options || !options.skipDeleteBinary)
                            {
                                require('fs').unlinkSync(servicePath);
                            }
                            console.log(name + ' uninstalled');
                        }
                        catch (e) {
                            console.log(name + ' could not be uninstalled', e)
                        }
                    }
                    if (require('fs').existsSync('/etc/init/' + name + '.conf'))
                    {
                        // upstart service
                        this._update = require('child_process').execFile('/bin/sh', ['sh']);
                        this._update.stdout.on('data', function (chunk) { });
                        this._update.stdin.write('service ' + name + ' stop\n');
                        this._update.stdin.write('exit\n');
                        this._update.waitExit();
                        try
                        {
                            require('fs').unlinkSync('/etc/init/' + name + '.conf');
                            if (!options || !options.skipDeleteBinary)
                            {
                                require('fs').unlinkSync(servicePath);
                            }
                            console.log(name + ' uninstalled');
                        }
                        catch (e) {
                            console.log(name + ' could not be uninstalled', e)
                        }
                    }
                    break;
                case 'systemd':
                    service.stop();
                    if (service.isRunning()) { throw new Error('Service remains running; uninstall aborted: ' + name); }
                    runSystemctl(['disable', service.escname + '.service']);
                    // Delete the resolved binding only; guessed vendor paths may belong to another instance.
                    if (service.conf && require('fs').existsSync(service.conf)) { require('fs').unlinkSync(service.conf); }
                    runSystemctl(['daemon-reload']);
                    if ((!options || !options.skipDeleteBinary) && require('fs').existsSync(servicePath)) { require('fs').unlinkSync(servicePath); }
                    console.log(name + ' uninstalled');
                    break;
                default: // unknown platform service type
                    if (typeof service.isRunning == 'function' && service.isRunning())
                    {
                        service.stop();
                    }
                    if (!options || !options.skipDeleteBinary)
                    {
                        try
                        {
                            require('fs').unlinkSync(servicePath);
                        }
                        catch (x)
                        {
                        }
                    }
                    try
                    {
                        require('fs').unlinkSync(service.conf);
                    }
                    catch(x)
                    {
                    }
                    console.log(name + ' uninstalled');
                    break;
            }
        }
        else if(process.platform == 'darwin')
        {
            service.unload();
            try
            {
                require('fs').unlinkSync(service.plist);
                if (!options || !options.skipDeleteBinary)
                {
                    require('fs').unlinkSync(servicePath);
                }
            }
            catch (e)
            {
                throw ('Error uninstalling service: ' + name + ' => ' + e);
            }

            try
            {
                require('fs').rmdirSync(workingPath);
            }
            catch (e)
            {
            }
        }
        else if(process.platform == 'freebsd')
        {
            service.stop();
            if (!options || !options.skipDeleteBinary)
            {
                require('fs').unlinkSync(service.appLocation());
            }
            if (service.OpenBSD)
            {
                // OpenBSD specific 
                try
                {
                    require('fs').unlinkSync(workingPath + name + '_loader');
                }
                catch(e)
                {
                }
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stdin.write("rcctl disable " + name + "\nexit\n");
                child.waitExit();
            }
            if (this.pfSense)
            {
                try
                {
                    require('fs').unlinkSync(service.rc + '.sh');
                }
                catch (ee)
                {
                }
            }
            if (this.OPNsense)
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                child.stderr.on('data', function (c) { });
                child.stdin.write("ls /usr/local/etc/rc.syshook.d/start | tr '\\n' '`' | awk -F'`' '");
                child.stdin.write('{');
                child.stdin.write('   DEL="";');
                child.stdin.write('   printf "[";');
                child.stdin.write('   for(i=1;i<NF;++i)');
                child.stdin.write('   {');
                child.stdin.write('      if($i ~ /^[0-9][0-9]-' + name.split(' ').join('') + '$/)');
                child.stdin.write('      {');
                child.stdin.write('         printf "%s\\"%s\\"", DEL, $i;');
                child.stdin.write('         DEL=",";');
                child.stdin.write('      }');
                child.stdin.write('   }');
                child.stdin.write('   printf "]";');
                child.stdin.write("}'");
                child.stdin.write('\nexit\n');
                child.waitExit();

                var hooks = JSON.parse(child.stdout.str.trim());
                for (var i in hooks)
                {
                    try
                    {
                        require('fs').unlinkSync('/usr/local/etc/rc.syshook.d/start/' + hooks[i]);
                    }
                    catch (ee)
                    {
                    }
                }
            }
            require('fs').unlinkSync(service.rc);
            if ((this.pfSense || this.OPNsense) && require('fs').existsSync('/etc/rc.conf.local'))
            {
                var local = null;
                try
                {
                    local = require('fs').readFileSync('/etc/rc.conf.local');
                }
                catch(ee)
                {
                }
                if(local!=null)
                {
                    var lines = local.toString().split('\n');
                    var i;
                    var m = require('fs').createWriteStream('/etc/rc.conf.local', { flags: 'wb' });
                    for(i=0;i<lines.length;++i)
                    {
                        if (lines[i].split('=')[0].trim() != (name + '_enable') && lines[i].trim() != '')
                        {
                            m.write(lines[i] + '\n');
                        }
                    }
                    m.end();
                }
            }


            try
            {
                require('fs').rmdirSync(workingPath);
            }
            catch (e)
            { }
        }
    }

    this.getServiceType = function getServiceType()
    {
        if (this._platform != null) { return (this._platform); }
        var platform = 'unknown';
        switch(process.platform)
        {
            case 'win32':
                platform = 'windows';
                break;
            case 'freebsd':
                platform = 'freebsd';
                break;
            case 'darwin':
                platform = 'launchd';
                break;
            case 'linux':
                platform = require('process-manager').getProcessInfo(1).Name;
                if (platform == "busybox")
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
                    child.stdin.write("ps -ax -o pid -o command | awk '{ if($1==\"1\") { $1=\"\"; split($0, res, \" \"); print res[2]; }}'\nexit\n");
                    child.waitExit();
                    platform = child.stdout.str.trim();
                }
                if (platform == 'init')
                {
                    if (require('fs').existsSync('/etc/init'))
                    {
                        platform = 'upstart';
                    }
                }
                switch (platform)
                {
                    case 'init':
                    case 'upstart':
                    case 'systemd':
                    case 'procd':
                        break;
                    default:
                        platform = 'unknown';
                        break;
                }
                break;
        }

        this._platform = platform;
        return (platform);
    };

    this.escape = function escape(str)
    {
        if (this.getServiceType() != 'systemd') { return (str); }
        if (systemd_escape == null)
        {
            systemd_escape = require('lib-finder').findBinary('systemd-escape');
            if (systemd_escape == null) { systemd_escape = false; }
        }
        if (systemd_escape === false) { return (str); }

        var child = require('child_process').execFile(systemd_escape, ['systemd-escape', str]);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.waitExit();

        return (child.stdout.str.trim());
    }
    this.unescape = function unescape(str)
    {
        if (this.getServiceType() != 'systemd') { return (str); }
        if (systemd_escape == null)
        {
            systemd_escape = require('lib-finder').findBinary('systemd-escape');
            if (systemd_escape == null) { systemd_escape = false; }
        }
        if (systemd_escape === false) { return (str); }

        var child = require('child_process').execFile(systemd_escape, ['systemd-escape', '-u', str]);
        child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });
        child.waitExit();

        return (child.stdout.str.trim());
    }


    this.daemon = function daemon(path, parameters, options)
    {
        require('code-utils');
        console.log('PATH => ' + JSON.stringify(path, null, 1));
        console.log('parameters => ' + JSON.stringify(parameters, null, 1));
        console.log('options => ' + JSON.stringify(options, null, 1));
    
        var z = -1;
        for (var parameterIndex = 0; parameterIndex < parameters.length; ++parameterIndex)
        { if (parameters[parameterIndex].indexOf('--meshServiceName=') == 0) { z = parameterIndex; break; } }
        console.log('meshServiceName => ' + z);
        if (z >= 0)
        {
            parameters.splice(z, 1);
            console.log('parameters => ' + JSON.stringify(parameters, null, 1));
        }

        var tmp = JSON.stringify(parameters);
        tmp = tmp.substring(1, tmp.length - 1);

        if (options.cwd)
        {
            process.chdir(options.cwd);
            console.log('Setting CWD to: ' + options.cwd);
        }


        console.log('\n\n');
        console.log("child = require('child_process').execFile('" + path + "', ['" + (process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop() + "'" + (tmp != '' ? (", " + tmp) : "")) + "]);");
        console.log('\n\n');



        if (!options) { options = {}; }
        var childParms = "\
            var child = null; \
            var options = " + JSON.stringify(options) + ";\
            if(options.logOutputs)\
            { console.setDestination(console.Destinations.LOGFILE); console.log('Logging Outputs...'); }\
            else\
            {\
              console.setDestination(console.Destinations.DISABLED);\
            }\
            if(options.cwd) { process.chdir(options.cwd); }\
            function cleanupAndExit()\
            {\
                if(options.pidPath) { try{require('fs').unlinkSync(options.pidPath);} catch(x){} }\
            }\
            function spawnChild()\
            {\
                child = require('child_process').execFile('" + path + "', ['" + (process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop() + "'" + (tmp != '' ? (", " + tmp) : "")) + "]);\
                if(child)\
                {\
                    child.stdout.on('data', function(c) { console.log(c.toString()); });\
                    child.stderr.on('data', function(c) { console.log(c.toString()); });\
                    child.once('exit', function (code) \
                    {\
                        console.log('Child Exited');\
                        if(options.crashRestart) { spawnChild(); } else { cleanupAndExit(); }\
                    });\
                    console.log('Child Spawned');\
                }\
                else\
                {\
                    console.log('Child Spawn Failed');\
                }\
            }\
            if(options.pidPath) { require('fs').writeFileSync(options.pidPath, process.pid.toString()); }\
            spawnChild();\
            process.on('SIGTERM', function()\
            {\
                if(child) { child.kill(); }\
                cleanupAndExit();\
                process.exit();\
            });";
        
        if (process.platform == 'win32') { throw ('Windows daemon wrapper re-entry is disabled until represented by an approved rundll32 contract export.'); }

        var parms = [process.execPath.split('/').pop()];
        parms.push('-b64exec');
        parms.push(Buffer.from(childParms).toString('base64'));
        options._parms = parms;
        options.detached = true;
        options.type = 4;

        var child = require('child_process').execFile(process.execPath, options._parms, options);       
        if (!child) { throw ('Error spawning process'); }
    }
    this.daemonEx = function daemonEx(path, parameters, options)
    {
        if (process.platform == 'win32') { throw ('Windows daemon wrapper re-entry is disabled until represented by an approved rundll32 contract export.'); }
        parameters.unshift(process.platform == 'win32' ? path.split('\\').pop() : path.split('/').pop());
        var name = options.name ? options.name : parameters[0];
        if (options.cwd) { process.chdir(options.cwd); }

        function spawnChild()
        {
            global.child = require('child_process').execFile(path, parameters);
            if(global.child)
            {
                require('fs').writeFileSync('/var/run/' + name + '.pid', global.child.pid.toString() + '\n');
                global.child.stdout.on('data', function(c) { console.log(c.toString()); });
                global.child.stderr.on('data', function(c) { console.log(c.toString()); });
                global.child.once('exit', function (code) 
                {
                    require('fs').unlinkSync('/var/run/' + name + '.pid');
                    if(options.crashRestart) { spawnChild(); } 
                });
            }
        }
        
        if(options.logOutput)
        {
            console.setDestination(console.Destinations.LOGFILE);
            console.log('Logging Outputs...'); 
        }
        else
        {
            console.setDestination(console.Destinations.DISABLED);
        }
        if(options.cwd) { process.chdir(options.cwd); }
        spawnChild();
        process.on('SIGTERM', function()
        {
            if (global.child)
            {
                child.kill();
                require('fs').unlinkSync('/var/run/' + name + '.pid');
            }
            process.exit();
        });
    }
}

module.exports = serviceManager;
module.exports.manager = new serviceManager();

if (process.platform == 'darwin')
{
    module.exports.getOSVersion = getOSVersion;
}
