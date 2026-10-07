/*
Copyright 2020 Intel Corporation

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


const MB_OK                     = 0x00000000;
const MB_OKCANCEL               = 0x00000001;
const MB_ABORTRETRYIGNORE       = 0x00000002;
const MB_YESNOCANCEL            = 0x00000003;
const MB_YESNO                  = 0x00000004;
const MB_RETRYCANCEL            = 0x00000005;
const MB_TOPMOST                = 0x00040000;
const MB_SETFOREGROUND          = 0x00010000;
const MB_SYSTEMMODAL            = 0x00001000;

const MB_DEFBUTTON1             = 0x00000000;
const MB_DEFBUTTON2             = 0x00000100;
const MB_DEFBUTTON3             = 0x00000200;
const MB_ICONHAND               = 0x00000010;
const MB_ICONQUESTION           = 0x00000020;
const MB_ICONEXCLAMATION        = 0x00000030;
const MB_ICONASTERISK           = 0x00000040;

const IDOK     = 1;
const IDCANCEL = 2;
const IDABORT  = 3;
const IDRETRY  = 4;
const IDIGNORE = 5;
const IDYES    = 6;
const IDNO     = 7;
const WM_CLOSE = 0x0010;

var promise = require('promise');

function sendConsoleText(msg)
{
    require('MeshAgent').SendCommand({ action: 'msg', type: 'console', value: msg });
}


function messageBox()
{
    this._ObjectID = 'message-box';
    this.create = function create(title, caption, timeout, layout, sid)
    {
        if (title == 'MeshCentral') { try { title = require('MeshAgent').displayName; } catch (x) { } }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.options = { launch: { module: 'message-box', method: 'slave', args: [] } };
        ret.title = title;
        ret.caption = caption;
        ret.timeout = timeout;
        ret.layout = layout;

        //ret.options._debugIPC = true;
        //ret.options._ipcInteger = 1500;

        try
        {
            ret.options.uid = sid == null ? require('user-sessions').consoleUid() : sid;
            if (ret.options.uid == require('user-sessions').getProcessOwnerName(process.pid).tsid) { delete ret.options.uid; }
            if (sid == null && require('user-sessions').locked()) { ret.options.uid = -1; }
        }
        catch (ee)
        {
            if (sid == null)
            {
                ret.options.uid = -1;
            }
            else
            {
                ret._rej(ee);
                return (ret);
            }
        }

        ret._ipc = require('child-container').create(ret.options);
        ret._ipc.master = ret;
        ret._ipc.on('ready', function ()
        {
            this.descriptorMetadata = 'message-box';
            if (this.master.timeout != null) { this.master._timeout = setTimeout(function (mstr) { mstr._ipc.exit(); }, this.master.timeout * 1000, this.master); }
            if (this.master.layout == null)
            {
                this.message({ command: 'YESNO', caption: this.master.caption, title: this.master.title });
            }
            else
            {
                this.message({ command: 'ALERT', caption: this.master.caption, title: this.master.title });
            }
        });
        ret._ipc.on('message', function (msg)
        {
            try
            {
                switch(msg.command)
                {
                    case 'response':
                        if (this.master._timeout) { clearTimeout(this.master._timeout); this.master._timeout = null; }
                        if (msg.response == IDYES || msg.response == IDOK)
                        {
                            this.master._res();
                        }
                        else
                        {
                            this.master._rej(msg.response);
                        }
                        break;
                    default:
                        break;
                }
            }
            catch(ff)
            {
            }
        });
        ret._ipc.on('exit', function (c) { this.master._rej('child exited with code: ' + c); });
        ret.close = function close()
        {
            ret._ipc.exit();
        };
        return (ret);
    };
    this.slave = function()
    {
        var master = require('child-container');
        master.on('message', function (msg)
        {
            switch(msg.command)
            {
                case 'YESNO':
                case 'ALERT':
                    this.GM = require('_GenericMarshal');
                    this.user32 = this.GM.CreateNativeProxy('user32.dll');
                    this.user32.CreateMethod('MessageBoxW');

                    layout = msg.command == 'YESNO' ? (MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION | MB_TOPMOST | MB_SYSTEMMODAL) : (MB_OK | MB_DEFBUTTON2 | MB_ICONEXCLAMATION | MB_TOPMOST | MB_SYSTEMMODAL);
                    this.user32.MessageBoxW.async(0, this.GM.CreateVariable(msg.caption, { wide: true }), this.GM.CreateVariable(msg.title, { wide: true }), layout)
                        .then(function (r)
                        {
                            try
                            {
                                switch(r.Val)
                                {
                                    case IDOK:
                                    case IDCANCEL:
                                    case IDABORT:
                                    case IDRETRY:
                                    case IDIGNORE:
                                    case IDYES:
                                        this.that.message({command: 'response', response: r.Val});
                                        break;
                                    default:
                                        this.that.message({command: 'response', response: IDNO});
                                        break;
                                }
                            }
                            catch(ff)
                            {
                            }
                            process.exit();
                        }, function () { process.exit(); }).parentPromise.that = this;
                    break;
                default:
                    break;
            }
        });
    }
}

function linux_messageBox()
{
    this._ObjectID = 'message-box';
    Object.defineProperty(this, 'zenity',
        {
            value: (function ()
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("whereis zenity | awk '{ print $2 }'\nexit\n");
                child.waitExit();
                var location = child.stdout.str.trim();
                if (location.split('/man/').length > 1) { location = ''; }
                if (location == '' && require('fs').existsSync('/usr/local/bin/zenity')) { location = '/usr/local/bin/zenity'; }
                if (location == '') { return (null); }

                var ret = { path: location, timeout: child.stdout.str.trim() == '' ? false : true };
                Object.defineProperty(ret, "timeout", {
                    get: function ()
                    {
                        if (this._timeout == null)
                        {
                            var uid, xinfo;
                            try
                            {
                                uid = require('user-sessions').consoleUid();
                                xinfo = require('monitor-info').getXInfo(uid);
                            }
                            catch (e)
                            {
                                uid = 0;
                                xinfo = require('monitor-info').getXInfo(0);
                            }
                            if (xinfo == null) { return (false); }
                            var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stdin.write(location + ' --help-all | grep timeout\nexit\n');
                            child.stderr.on('data', function (e) { });
                            child.waitExit();
                            Object.defineProperty(this, "_timeout", { value: child.stdout.str.trim() == '' ? false : true });
                            return (this._timeout);
                        }
                        else
                        {
                            return (this._timeout);
                        }
                    }
                });
                Object.defineProperty(ret, "extra", {
                    get: function ()
                    {
                        if (this._extra == null)
                        {
                            var uid, xinfo;
                            try
                            {
                                uid = require('user-sessions').consoleUid();
                                xinfo = require('monitor-info').getXInfo(uid);
                            }
                            catch (e)
                            {
                                uid = 0;
                                xinfo = require('monitor-info').getXInfo(0);
                            }
                            if (xinfo == null) { return (false); }
                            var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stdin.write(location + ' --help-all | grep extra-button\nexit\n');
                            child.stderr.on('data', function (e) { });
                            child.waitExit();
                            Object.defineProperty(this, "_extra", { value: child.stdout.str.trim() == '' ? false : true });
                            return (this._extra);
                        }
                        else
                        {
                            return (this._extra);
                        }
                    }
                });
                Object.defineProperty(ret, "version", {
                    get: function ()
                    {
                        if (this._version == null)
                        {
                            var uid, xinfo;
                            try
                            {
                                uid = require('user-sessions').consoleUid();
                                xinfo = require('monitor-info').getXInfo(uid);
                            }
                            catch (e)
                            {
                                uid = 0;
                                xinfo = require('monitor-info').getXInfo(0);
                            }
                            if (xinfo == null) { return (false); }

                            var child = require('child_process').execFile('/bin/sh', ['sh'], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
                            child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stderr.str = ''; child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
                            child.stdin.write(location + ' --version | awk -F. \'{ printf "[%s, %s]\\n", $1, $2; } \'\nexit\n');
                            child.waitExit();

                            try
                            {
                                if (child.stderr.str.includes('-CRITICAL **')) { object.defineProperty(this, "broken", { value: true }); }
                                Object.defineProperty(this, "_version", {value: JSON.parse(child.stdout.str.trim())});
                                return (this._version);
                            }
                            catch (e)
                            {
                                Object.defineProperty(this, "_version", { value: [2, 16] });
                                return (this._version);
                            }
                        }
                        else
                        {
                            return (this._version);
                        }
                    }
                });
                return (ret);
            })()
        });
    if (!this.zenity)
    {
        Object.defineProperty(this, 'kdialog',
            {
                value: (function ()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis kdialog | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
                })()
            });
        Object.defineProperty(this, 'xmessage',
            {
                value: (function ()
                {
                    var child = require('child_process').execFile('/bin/sh', ['sh']);
                    child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                    child.stdin.write("whereis xmessage | awk '{ print $2 }'\nexit\n");
                    child.waitExit();
                    return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
                })()
            });
    }

    Object.defineProperty(this, 'notifysend',
        {
            value: (function ()
            {
                var child = require('child_process').execFile('/bin/sh', ['sh']);
                child.stdout.str = ''; child.stdout.on('data', function (chunk) { this.str += chunk.toString(); });
                child.stdin.write("whereis notify-send | awk '{ print $2 }'\nexit\n");
                child.waitExit();
                return (child.stdout.str.trim() == '' ? null : { path: child.stdout.str.trim() });
            })()
        });
    

    this.create = function create(title, caption, timeout, layout)
    {
        if (timeout == null) { timeout = 10; }
        if (title == 'MeshCentral') { try { title = require('MeshAgent').displayName; } catch (x) { } }
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        var uid;    
        var xinfo;
        var min = require('user-sessions').minUid();

        try
        {
            uid = require('user-sessions').consoleUid();
            xinfo = require('monitor-info').getXInfo(uid);
        }
        catch(e)
        {
            uid = 0;
            xinfo = require('monitor-info').getXInfo(0);
        }

        if (xinfo == null || (uid != 0 && uid < min))
        {
            ret._rej('This system cannot display a user dialog box when a user is not logged in');
            return (ret);
        }
        if (this.zenity)
        {
            if (!this.zenity.extra && Array.isArray(layout) && layout.length > 1)
            {
                ret._rej('This system does not support custom button layouts');
                return (ret);
            }
            // GNOME/ZENITY
            ret._options = { title: title.trim().split('').join('\\'), caption: caption.trim().split('').join('\\'), timeout: timeout, layout: layout, zenity: this.zenity };
            var parms = ['zenity'];
            if (Array.isArray(layout))
            {
                var i;
                parms.push('--info');
                for(i=0;i<layout.length;++i)
                {
                    if(i==0)
                    {
                        parms.push('--ok-label=' + layout[i]);
                    }
                    else
                    {
                        parms.push('--extra-button=' + layout[i]);
                    }
                }
            }
            else
            {
                parms.push(layout == null ? '--question' : '--warning');
            }
            parms.push('--title=' + title);
            parms.push('--text=' + caption);
            parms.push('--no-wrap');
            if (this.zenity.timeout) { parms.push('--timeout=' + timeout); }
            ret.child = require('child_process').execFile(this.zenity.path, parms, { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
            if (this.zenity.timeout)
            {
                ret.child.timeout = setTimeout(function (c)
                {
                    c.timeout = null;
                    c.promise._rej('timeout');
                    c.kill();
                }, timeout * 1000, ret.child);
            }

            ret.child.descriptorMetadata = 'zenity, message-box'
            ret.child.promise = ret;
            ret.child.stderr.str = ''; ret.child.stderr.on('data', function (chunk) { this.str += chunk.toString(); });
            ret.child.stdout.ostr = ''; ret.child.stdout.on('data', function (chunk) { this.ostr += chunk.toString(); });
            ret.child.on('exit', function (code)
            {
                if (this.timeout) { clearTimeout(this.timeout); }
                if (!(this.stderr.str.includes('option is not') && this.promise._options.zenity.timeout))
                {
                    if (Array.isArray(this.promise._options.layout))
                    {
                        if (code == 0 && ((process.platform == 'freebsd' && this.stdout.ostr.trim() == '') || process.platform != 'freebsd'))
                        {
                            this.promise._res(this.promise._options.layout[0]);
                        }
                        else
                        {
                            var val = this.stdout.ostr.trim();
                            for (var i = 1; i < this.promise._options.layout.length; ++i)
                            {
                                if (this.promise._options.layout[i] == val)
                                {
                                    this.promise._res(val);
                                    return;
                                }
                            }
                            this.promise._rej('timeout');
                        }
                    }
                }
                switch (code)
                {
                    case 0:
                        this.promise._res();
                        break;
                    case 1:
                        this.promise._rej('denied');
                        break;
                    default:
                        if (this.stderr.str.includes('option is not') && this.promise._options.zenity.timeout)
                        {
                            var uname = require('user-sessions').getUsername(uid);
                            this.promise._ch = require('child_process').execFile('/bin/sh', ['sh'], { type: require('child_process').SpawnTypes.TERM });
                            this.promise._ch.promise = this.promise;
                            this.promise.child = this.promise._ch;
                            this.promise._ch.stderr.str = ''; this.promise._ch.stderr.on('data', function (c) { this.str += c.toString(); });
                            this.promise._ch.stdout.str = ''; this.promise._ch.stdout.on('data', function (c)
                            {
                                this.str += c.toString();
                                if (Array.isArray(layout))
                                {
                                    var i;
                                    var tmp = c.toString().trim();
                                    for (i = 0; i < layout.length; ++i)
                                    {
                                        if(layout[i] == tmp)
                                        {
                                            this.parent.result = tmp;
                                            //this.parent.promise._res(tmp);
                                            return;
                                        }
                                    }
                                }
                                if (this.str.includes('<<<<$_RESULT>>>>')) { this.str = this.str.split('<<<<$_RESULT>>>>')[1]; }
                                if (this.str.includes('>>>>')) { this.parent.kill(); }
                            });
                            this.promise._ch.stdin.write('su - ' + uname + '\n');
                            this.promise._ch.stdin.write('export DISPLAY=' + xinfo.display + '\n');
                            this.promise._ch.stdin.write('zenity ');
                            if (Array.isArray(layout))
                            {
                                var i;
                                this.promise._ch.stdin.write('--info');
                                for (i = 0; i < layout.length; ++i)
                                {
                                    if (i == 0)
                                    {
                                        this.promise._ch.stdin.write(' --ok-label=' + layout[i]);
                                    }
                                    else
                                    {
                                        this.promise._ch.stdin.write(' --extra-button=' + layout[i]);
                                    }
                                }
                            }
                            else
                            {
                                this.promise._ch.stdin.write((this.promise._options.layout == null ? '--question' : '--warning'));
                            }
                            this.promise._ch.stdin.write(' --title=' + this.promise._options.title + ' --text=' + this.promise._options.caption);
                            this.promise._ch.stdin.write(' --timeout=' + this.promise._options.timeout + '\nexport _RESULT=$?\necho "<<<<$_RESULT>>>>"\nexit');
                            this.promise._ch.on('exit', function ()
                            {
                                if (this.result != null)
                                {
                                    this.promise._res(this.result);
                                    return;
                                }
                                var res = this.stdout.str.split('>>>>')[0].split('<<<<')[1];
                                switch(parseInt(res))
                                {
                                    case 0:
                                        this.promise._res();
                                        break;
                                    case 1:
                                        this.promise._rej('denied');
                                        break;
                                    default:
                                        this.promise._rej(this.stderr.str.toString());
                                        break;
                                }
                            });

                        }
                        else
                        {
                            this.promise._rej(this.stderr.str.trim());
                        }
                        break;
                }
            });
        }
        else if(this.kdialog)
        {
            var msgparms = ['kdialog', '--title', title];
            if (Array.isArray(layout))
            {
                if (layout.length > 3) { ret._rej('KDialog only supports up to 3 button layouts'); return (ret); }
                ret.user = true;
                switch(layout.length)
                {
                    case 0:
                    case 1:
                        msgparms.push('--msgbox');
                        break;
                    case 2:
                        msgparms.push('--yesno');
                        break;
                    case 3:
                        msgparms.push('--yesnocancel');
                        break;
                }
                msgparms.push(caption);

                for (var i = 0; i < layout.length; ++i)
                {
                    switch(i)
                    {
                        case 0:
                            msgparms.push('--yes-label=' + layout[i]);
                            break;
                        case 1:
                            msgparms.push('--no-label=' + layout[i]);
                            break;
                        case 2:
                            msgparms.push('--cancel-label=' + layout[i]);
                            break;
                    }
                }
            }
            else
            {
                msgparms.push(layout == null ? '--yesno' : '--msgbox');
                msgparms.push(caption);
            }

            if (process.platform != 'freebsd' && process.env['DISPLAY'])
            {
                ret.child = require('child_process').execFile(this.kdialog.path, msgparms);
                ret.child.promise = ret;
            }
            else
            {
                var xdg = require('user-sessions').findEnv(uid, 'XDG_RUNTIME_DIR'); if (xdg == null) { xdg = ''; }
                if (!xinfo || !xinfo.display || !xinfo.xauthority) { ret._rej('Interal Error, could not determine X11/XDG env'); return (ret); }
                ret.child = require('child_process').execFile(this.kdialog.path, msgparms, { uid: uid, env: { DISPLAY: xinfo.display, XAUTHORITY: xinfo.xauthority, XDG_RUNTIME_DIR: xdg } });
                ret.child.promise = ret;
            }
            ret.child.descriptorMetadata = 'kdialog, message-box'
            ret.child.timeout = setTimeout(function (c)
            {
                c.timeout = null;
                c.kill();
            }, timeout * 1000, ret.child);
            ret.child.stdout.on('data', function (chunk) { });
            ret.child.stderr.on('data', function (chunk) { });
            ret.child.buttons = layout;
            ret.child.on('exit', function (code)
            {
                if (this.timeout)
                {
                    clearTimeout(this.timeout);
                    if (this.promise.user)
                    {
                        this.promise._res(this.buttons[code]);
                    }
                    else
                    {
                        switch (code)
                        {
                            case 0:
                                this.promise._res();
                                break;
                            case 1:
                                this.promise._rej('denied');
                                break;
                            default:
                                this.promise._rej('timeout');
                                break;
                        }
                    }
                }
                else
                {
                    this.promise._rej('timeout');
                }
            });
        }
        else if (this.xmessage)
        {
            // title, caption, timeout, layout
            ret.child = require('child_process').execFile(this.xmessage.path, ['xmessage', '-center', '-buttons', layout == null ? 'No:1,Yes:2' : 'OK:2', '-timeout', timeout.toString(), '-default', layout==null?'No':'OK', '-title', title, caption], { uid: uid, env: { XAUTHORITY: xinfo.xauthority ? xinfo.xauthority : "", DISPLAY: xinfo.display } });
            ret.child.stdout.on('data', function (c) {  });
            ret.child.stderr.on('data', function (c) {  });
            ret.child.descriptorMetadata = 'xmessage, message-box'
            ret.child.promise = ret;
            ret.child.on('exit', function (code)
            {
                switch(code)
                {
                    case 2:
                        this.promise._res();
                        break;
                    case 1:
                        this.promise._rej('denied');
                        break;
                    default:
                        this.promise._rej('timeout');
                        break;
                }
            });
        }
        else
        {
            ret._rej('Unable to create dialog box');
        }

        ret.close = function close()
        {
            if (this.timeout) { clearTimeout(this.timeout); }
            if (this.child)
            {
                this._rej('denied');
                this.child.kill();
            }
        }
        return (ret);
    };
}

if (process.platform == 'darwin')
{
    var MAC_HELPER_MAX_FRAME = 16 * 1024 * 1024;
    function translateObject(obj)
    {
        // Duktape strings can contain CESU-8 surrogate bytes. JSON escapes keep
        // the wire valid UTF-8 and identical to standard JSON implementations.
        var serialized = JSON.stringify(obj).replace(/[\u007f-\uffff]/g, function (character)
        {
            return '\\u' + ('0000' + character.charCodeAt(0).toString(16)).slice(-4);
        });
        var json = Buffer.from(serialized);
        if (json.length > MAC_HELPER_MAX_FRAME - 4) { throw new Error('macOS helper message is too large'); }
        var frame = Buffer.alloc(json.length + 4);
        frame.writeUInt32LE(frame.length, 0);
        json.copy(frame, 4);
        return frame;
    }
    function readMacHelperMessage(socket, buffer)
    {
        if (buffer.length < 4) { socket.unshift(buffer); return null; }
        var length = buffer.readUInt32LE(0);
        if (length < 6 || length > MAC_HELPER_MAX_FRAME)
        {
            if (socket.promise) { socket.promise._rej('Invalid macOS helper message length'); }
            socket.end(); return null;
        }
        if (length > buffer.length) { socket.unshift(buffer); return null; }
        var value;
        try
        {
            value = JSON.parse(buffer.slice(4, length).toString());
            if (value == null || typeof value != 'object' || Array.isArray(value) || typeof value.command != 'string') { throw new Error('Invalid command'); }
        }
        catch (error)
        {
            if (socket.promise) { socket.promise._rej('Invalid macOS helper message'); }
            socket.end(); return null;
        }
        return value;
    }
    function macHelperDataHandler(handler)
    {
        return function (buffer)
        {
            var offset = 0;
            while (offset < buffer.length)
            {
                var remainder = buffer.slice(offset);
                var message = readMacHelperMessage(this, remainder);
                if (message == null) { return; }
                offset += remainder.readUInt32LE(0);
                try { handler.call(this, message); }
                catch (error) { if (this.promise) { this.promise._rej(error); } this.end(); return; }
            }
        };
    }
    function macJsonText(value)
    {
        return JSON.stringify(value).replace(/[\u007f-\uffff]/g, function (c) { return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4); });
    }
    function macUtf8Encode(value)
    {
        var escaped = encodeURIComponent(value), buffer = Buffer.alloc(escaped.length), offset = 0;
        for (var i = 0; i < escaped.length; ++i)
        {
            if (escaped[i] == '%') { buffer[offset++] = parseInt(escaped.substring(i + 1, i + 3), 16); i += 2; }
            else { buffer[offset++] = escaped.charCodeAt(i); }
        }
        return buffer.slice(0, offset);
    }
    function macUtf8Decode(buffer)
    {
        var escaped = [];
        for (var i = 0; i < buffer.length; ++i) { escaped.push('%' + ('0' + buffer[i].toString(16)).slice(-2)); }
        return decodeURIComponent(escaped.join(''));
    }
    var MAC_UI_SCRIPT = 'function run(argv) {\n' +
        'var p=JSON.parse(argv[0]), app=Application.currentApplication(); app.includeStandardAdditions=true;\n' +
        'if(p.command==="NOTIFY"){app.displayNotification(p.caption,{withTitle:p.title});return "{}";}\n' +
        'if(p.command==="LOCK"){ObjC.import("ApplicationServices"); if(!$.AXIsProcessTrusted()){throw new Error("Accessibility permission is required to lock the desktop");}' +
        'var down=$.CGEventCreateKeyboardEvent(null,12,true), up=$.CGEventCreateKeyboardEvent(null,12,false);' +
        'try{if(!down||!up){throw new Error("Could not create lock shortcut");}' +
        '$.CGEventSetFlags(down,$.kCGEventFlagMaskControl|$.kCGEventFlagMaskCommand);$.CGEventSetFlags(up,$.kCGEventFlagMaskControl|$.kCGEventFlagMaskCommand);' +
        '$.CGEventPost($.kCGHIDEventTap,down);$.CGEventPost($.kCGHIDEventTap,up);}' +
        'finally{if(down){$.CFRelease(down);}if(up){$.CFRelease(up);}}return "{}";}\n' +
        'var options={withTitle:p.title,withIcon:"caution",buttons:p.buttons,defaultButton:p.buttons[p.buttons.length-1]};' +
        'if(p.command==="PASSWORD"){options.defaultAnswer="";options.hiddenAnswer=true;}' +
        'if(p.timeout>0){options.givingUpAfter=p.timeout;}' +
        'try{var r=app.displayDialog(p.caption,options);return JSON.stringify({button:r.buttonReturned,timeout:!!r.gaveUp,value:p.command==="PASSWORD"?r.textReturned:undefined});}' +
        'catch(e){if(e.errorNumber===-128||e.number===-128){return JSON.stringify({cancelled:true});}throw e;}\n}';
    function macExecuteHelperCommand(client, request, callback)
    {
        if (!request || ['writeClip','readClip','DIALOG','PASSWORD','NOTIFY','LOCK'].indexOf(request.command) < 0) { throw new Error('Unknown helper command'); }
        var executable, argv, input = null, seconds = 15;
        if (request.command == 'writeClip')
        {
            if (typeof request.clipText != 'string') { throw new Error('Invalid clipboard text'); }
            executable = '/usr/bin/pbcopy'; argv = ['pbcopy']; input = macUtf8Encode(request.clipText);
        }
        else if (request.command == 'readClip') { executable = '/usr/bin/pbpaste'; argv = ['pbpaste']; }
        else
        {
            if (request.command != 'LOCK' && (typeof request.title != 'string' || typeof request.caption != 'string')) { throw new Error('Invalid helper text'); }
            if (request.command == 'DIALOG' || request.command == 'PASSWORD')
            {
                if (!Array.isArray(request.buttons) || request.buttons.length < 1 || request.buttons.length > 3 ||
                    request.buttons.some(function (b) { return typeof b != 'string' || !b.length; }) ||
                    typeof request.timeout != 'number' || !isFinite(request.timeout) || request.timeout < 0 || request.timeout > 86400 || Math.floor(request.timeout) != request.timeout)
                { throw new Error('Invalid helper dialog'); }
                seconds = request.timeout;
            }
            executable = '/usr/bin/osascript'; argv = ['osascript','-l','JavaScript','-e',MAC_UI_SCRIPT,'--',macJsonText(request)];
        }
        var environment = {};
        for (var key in process.env) { environment[key] = process.env[key]; }
        environment.LANG = 'en_US.UTF-8'; environment.LC_CTYPE = 'en_US.UTF-8';
        var child = require('child_process').execFile(executable, argv, {env:environment});
        client._shell = child;
        var output = [], errors = [], total = 0, done = false;
        function finish(error, result)
        {
            if (done) { return; } done = true;
            if (client._deadline) { clearTimeout(client._deadline); client._deadline = null; }
            client._shell = null;
            callback(error, result);
        }
        function collect(destination, chunk)
        {
            total += chunk.length;
            if (total > MAC_HELPER_MAX_FRAME) { try { child.kill(); } catch (ignored) {} finish('Helper output exceeds the message limit'); return; }
            destination.push(Buffer.concat([chunk]));
        }
        child.stdout.on('data', function (chunk) { collect(output, chunk); });
        child.stderr.on('data', function (chunk) { collect(errors, chunk); });
        child.on('exit', function (code)
        {
            if (done) { return; }
            try
            {
                var error = macUtf8Decode(Buffer.concat(errors));
                if (code !== 0)
                {
                    if ((request.command == 'DIALOG' || request.command == 'PASSWORD') && error.indexOf('(-128)') >= 0) { finish(null, {cancelled:true}); }
                    else { finish(request.command == 'PASSWORD' ? 'Password dialog failed' : error || 'Helper command failed (' + code + ')'); }
                    return;
                }
                var text = macUtf8Decode(Buffer.concat(output));
                if (request.command == 'readClip') { finish(null, {value:text}); }
                else if (request.command == 'writeClip') { finish(null, {}); }
                else { finish(null, JSON.parse(text)); }
            }
            catch (e) { finish(request.command == 'PASSWORD' ? 'Password dialog failed' : e); }
            finally
            {
                if (request.command == 'PASSWORD')
                {
                    output.concat(errors).forEach(function (b) { b.fill(0); });
                    output = []; errors = [];
                }
            }
        });
        child.on('error', function (e) { finish(e); });
        if (seconds > 0)
        {
            client._deadline = setTimeout(function () { client._deadline = null; finish('Helper command timeout'); try { child.kill(); } catch (ignored) {} }, (seconds + 5) * 1000);
        }
        try { child.stdin.end(input == null ? '' : input); }
        catch (e) { try { child.kill(); } catch (ignored) {} finish(e); }
    }

}

function macos_messageBox()
{
    this._ObjectID = 'message-box';
    // One helper LaunchAgent per desktop user serves queued requests over one authenticated
    // connection and is removed after it has been idle. Every LaunchAgent load posts a macOS
    // background-item notification, and remote desktop polls the clipboard every few seconds,
    // so requests must never each start their own helper or run concurrently.
    var MAC_HELPER_IDLE_MS = 30000, MAC_HELPER_START_MS = 15000, MAC_HELPER_RETRY_MS = 30000;
    var self = this, fs = require('fs'), sessions = require('user-sessions');
    this._queue = [];
    this._session = null;
    this._active = null;
    this._failedUntil = 0;
    this._failure = null;
    this._swept = false;
    this._nextId = 0;

    // Removing the plist removes the background item; the helper exits when its connection closes.
    function removeSessionFiles(session)
    {
        var files = [session.plist, session.config, session.path];
        for (var i = 0; i < files.length; ++i) { if (files[i]) { try { if (fs.existsSync(files[i])) { fs.unlinkSync(files[i]); } } catch (ignored) { } } }
        if (session.directory) { try { fs.rmdirSync(session.directory); } catch (ignored) { } }
    }
    // An agent that stops or updates while a helper is running must not leave it registered.
    function releaseAtExit() { if (self._session != null) { var s = self._session; self._session = null; removeSessionFiles(s); } }
    try { require('events').EventEmitter.call(this); this.on('~', releaseAtExit); } catch (ignored) { }
    try { process.on('exit', releaseAtExit); } catch (ignored) { }

    this._request = function (request, interpret)
    {
        var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        ret.request = request; ret.interpret = interpret; ret._done = false;
        ret.close = function () { self._cancel(ret); };
        // A read queued after any other request must see its effect, so it cannot share an earlier read.
        if (request.command != 'readClip') { this._pendingRead = null; }
        if (Date.now() < this._failedUntil)
        {
            // A helper that just failed to start would fail again; do not register another one.
            ret._done = true; ret._rej('macOS helper unavailable: ' + this._failure);
            return ret;
        }
        this._queue.push(ret);
        this._pump();
        return ret;
    };
    this._settle = function (ret, error, response)
    {
        if (ret._done) { return; }
        ret._done = true;
        if (ret.timer) { clearTimeout(ret.timer); ret.timer = null; }
        if (error) { ret._rej('' + error); return; }
        try { ret._res(ret.interpret(response)); } catch (e) { ret._rej('' + e); }
    };
    this._cancel = function (ret)
    {
        var index = this._queue.indexOf(ret);
        if (index >= 0) { this._queue.splice(index, 1); this._settle(ret, 'denied'); return; }
        // Closing the helper ends a dialog or command that is still on screen or running.
        if (this._active === ret && this._session != null) { this._sessionFailed(this._session, 'denied'); }
    };
    this._pump = function ()
    {
        if (this._active != null || this._queue.length == 0) { return; }
        var uid;
        try { uid = sessions.consoleUid(); }
        catch (e) { this._rejectQueue(e); return; }
        var session = this._session;
        if (session != null && session.uid !== uid) { this._closeSession(session); session = null; }
        if (session == null)
        {
            session = this._startSession(uid);
            if (session == null) { return; }
        }
        if (!session.ready) { return; }	// _onReady pumps once the helper authenticates
        if (session.idleTimer) { clearTimeout(session.idleTimer); session.idleTimer = null; }
        var ret = this._queue.shift();
        ret.id = ++this._nextId;
        this._active = ret;
        var seconds = (ret.request.command == 'DIALOG' || ret.request.command == 'PASSWORD') ? ret.request.timeout : 15;
        if (seconds > 0) { ret.timer = setTimeout(function () { ret.timer = null; self._sessionFailed(session, 'macOS helper operation timeout'); }, (seconds + 10) * 1000); }
        try { session.connection.write(translateObject({command:'REQUEST',token:session.token,id:ret.id,request:ret.request})); }
        catch (e) { this._sessionFailed(session, e); }
    };
    this._onReady = function (session)
    {
        if (session.closed || this._session !== session) { return; }
        session.ready = true;
        if (session.startTimer) { clearTimeout(session.startTimer); session.startTimer = null; }
        this._failedUntil = 0; this._failure = null;
        this._pump();
    };
    this._complete = function (session, message)
    {
        var ret = this._active;
        if (ret == null || message.command != 'RESULT' || message.token !== session.token || message.id !== ret.id || message.request !== ret.request.command)
        { this._sessionFailed(session, 'Invalid macOS helper response'); return; }
        if (ret.request.command == 'PASSWORD')
        {
            try { if (require('user-sessions').consoleUid() !== session.uid) { throw new Error('Desktop user changed'); } }
            catch (e) { this._sessionFailed(session, 'Desktop user changed'); return; }
        }
        this._active = null;
        this._settle(ret, message.error || null, message);
        this._next(session);
    };
    this._next = function (session)
    {
        setImmediate(function ()
        {
            if (self._queue.length > 0) { self._pump(); return; }
            if (self._session === session && self._active == null && session.idleTimer == null)
            {
                session.idleTimer = setTimeout(function ()
                {
                    session.idleTimer = null;
                    if (self._session === session && self._active == null && self._queue.length == 0) { self._closeSession(session); }
                }, MAC_HELPER_IDLE_MS);
            }
        });
    };
    this._rejectQueue = function (error)
    {
        var queued = this._queue; this._queue = [];
        for (var i = 0; i < queued.length; ++i) { this._settle(queued[i], error); }
    };
    // A helper that never became ready fails every queued request and starts a retry delay, so
    // clipboard polling cannot register a new LaunchAgent every few seconds. A ready helper that
    // fails only fails the request it was serving; the next request starts a fresh helper.
    this._sessionFailed = function (session, error)
    {
        if (this._session !== session) { return; }
        var wasReady = session.ready;
        this._closeSession(session);
        if (this._active != null) { var ret = this._active; this._active = null; this._settle(ret, error); }
        if (!wasReady)
        {
            this._failedUntil = Date.now() + MAC_HELPER_RETRY_MS;
            this._failure = '' + error;
            this._rejectQueue(error);
        }
        else if (this._queue.length > 0) { setImmediate(function () { self._pump(); }); }
    };
    this._closeSession = function (session)
    {
        if (this._session === session) { this._session = null; }
        if (session.closed) { return; }
        session.closed = true;
        if (session.startTimer) { clearTimeout(session.startTimer); session.startTimer = null; }
        if (session.idleTimer) { clearTimeout(session.idleTimer); session.idleTimer = null; }
        // launchctl waits run a nested native event loop. Cleanup must not remove the server
        // while its receive callback is still on the stack.
        setImmediate(function ()
        {
            if (session.connection) { try { session.connection.end(); } catch (ignored) { } }
            if (session.server) { try { session.server.close(); } catch (ignored) { } }
            if (session.job)
            {
                try { session.job.unload(); } catch (ignored) { }
                try { session.job.close(); } catch (ignored) { }
            }
            // Remove the files even if launchd kept the job: a plist left behind keeps a background
            // item registered, while a job without one disappears at logout.
            removeSessionFiles(session);
        });
    };
    // Helpers left by an agent that exited while one was running.
    this._sweep = function (uid, manager)
    {
        if (this._swept) { return; }
        this._swept = true;
        var folder;
        try { folder = sessions.getHomeFolder(sessions.getUsername(uid)) + '/Library/LaunchAgents'; } catch (e) { return; }
        var names = [];
        try { names = fs.readdirSync(folder); } catch (e) { return; }
        for (var i = 0; i < names.length; ++i)
        {
            var match = /^(mesh-ui-\d{1,39})\.plist$/.exec(names[i]);
            if (match == null) { continue; }
            try { var job = manager.getLaunchAgent(match[1], uid); try { job.unload(); } finally { job.close(); } } catch (ignored) { }
            try { fs.unlinkSync(folder + '/' + names[i]); } catch (ignored) { }
        }
    };
    this._startSession = function (uid)
    {
        var manager = require('service-manager').manager;
        var session = { uid: uid, ready: false, closed: false };
        this._session = session;
        try
        {
            var me = sessions.Self(), gid = sessions.getGroupID(uid);
            if (me != 0 && me != uid) { throw new Error('Cannot launch a helper for another desktop user'); }
            this._sweep(uid, manager);
            var nonce = require('tls').generateRandomInteger('0', '340282366920938463463374607431768211455');
            session.token = require('tls').generateRandomInteger('0', '115792089237316195423570985008687907853269984665640564039457584007913129639935');
            if (!/^\d{1,39}$/.test(nonce) || !/^\d{1,78}$/.test(session.token)) { throw new Error('Invalid helper randomness'); }
            var directory = '/var/tmp/mesh-ui-' + nonce;
            // Exclusive mkdir with its initial mode closes the chmod-after-create race.
            fs.mkdirSync(directory, 448); session.directory = directory;
            session.path = directory + '/ipc'; session.config = directory + '/config.json';
            session.service = 'mesh-ui-' + nonce;
            var fd = fs.openSync(session.config, 'wx', 384);
            try { fs.chmodSync(session.config, 384); fs.writeSync(fd, JSON.stringify({path:session.path, token:session.token, uid:uid})); }
            finally { fs.closeSync(fd); }
            fs.chownSync(session.config, uid, gid);
            session.startTimer = setTimeout(function () { session.startTimer = null; self._sessionFailed(session, 'macOS helper connection timeout'); }, MAC_HELPER_START_MS);
            session.server = require('net').createServer();
            session.server.on('error', function (e) { self._sessionFailed(session, e); });
            session.server.on('connection', function (socket)
            {
                if (session.closed || session.connection) { socket.end(); return; }
                socket.on('error', function (e) { if (socket === session.connection) { self._sessionFailed(session, e); } });
                socket.on('end', function () { if (socket === session.connection) { self._sessionFailed(session, 'macOS helper disconnected'); } });
                socket.on('data', macHelperDataHandler(function (message)
                {
                    if (session.closed) { this.end(); return; }
                    if (!this.authenticated)
                    {
                        if (message.command != 'HELLO' || message.token !== session.token || message.uid !== uid || session.connection)
                        { this.end(); return; }
                        this.promise = {_rej:function (e) { self._sessionFailed(session, e); }};
                        if (sessions.consoleUid() !== uid) { self._sessionFailed(session, 'Desktop user changed'); return; }
                        this.authenticated = true; session.connection = this;
                        // The helper usually connects while launchctl load is still waiting in a nested
                        // event loop. Requests and callers' callbacks must not run there: timers created
                        // inside it never fire. Finish once load returns.
                        if (session.loading) { session.pendingReady = true; } else { self._onReady(session); }
                        return;
                    }
                    self._complete(session, message);
                }));
            });
            session.server.listen({path:session.path}, function ()
            {
                if (session.closed) { return; }
                try
                {
                    fs.chmodSync(session.path, 384); fs.chownSync(session.path, uid, gid);
                    // Root retains ownership of the directory: the desktop user
                    // cannot replace path components before privileged cleanup.
                    fs.chownSync(directory, me, gid); fs.chmodSync(directory, me == uid ? 448 : 456);
                    var code = 'try { var c=require("message-box").startClient({config:' + JSON.stringify(session.config) + '}); c.on("close",function(){process.exit();}).on("error",function(){process.exit(1);}); } catch(e) { process.exit(1); }';
                    var installed = manager.installLaunchAgent({name:session.service,servicePath:process.execPath,uid:uid,
                        sessionTypes:['Aqua'],startType:'AUTO_START',failureRestart:0,parameters:['-exec',code]});
                    session.plist = installed.plist;
                    session.job = manager.getLaunchAgent(session.service, uid);
                    session.loading = true;
                    try { session.job.load(); } finally { session.loading = false; }
                }
                catch (e) { self._sessionFailed(session, e); return; }
                if (session.pendingReady) { session.pendingReady = false; self._onReady(session); }
            });
        }
        catch (e) { this._sessionFailed(session, e); return null; }
        return session;
    };
    this.create = function (title, caption, timeout, layout)
    {
        if (title == 'MeshCentral') { try { title = require('MeshAgent').displayName; } catch (ignored) { } }
        var custom = Array.isArray(layout), buttons = custom ? layout.slice() : layout == null ? ['Yes','No'] : ['OK'];
        var seconds = timeout == null ? 60 : timeout;
        if (typeof title != 'string' || typeof caption != 'string' || !buttons.length || buttons.length > 3 ||
            typeof seconds != 'number' || !isFinite(seconds) || seconds < 0 || seconds > 86400 || Math.floor(seconds) != seconds ||
            buttons.some(function (b) { return typeof b != 'string' || !b.length; }))
        { return new promise(function (res, rej) { rej('Invalid macOS dialog options'); }); }
        return this._request({command:'DIALOG',title:title,caption:caption,timeout:seconds,buttons:buttons}, function (reply)
        {
            if (reply.timeout) { throw new Error('TIMEOUT'); }
            if (reply.cancelled) { if (custom) { return 'Cancel'; } throw new Error('denied'); }
            if (buttons.indexOf(reply.button) < 0) { throw new Error('Invalid dialog button'); }
            if (!custom && reply.button != 'Yes' && reply.button != 'OK') { throw new Error('denied'); }
            return reply.button;
        });
    };
    this.setClipboard = function (text)
    {
        if (typeof text != 'string') { return new promise(function (res, rej) { rej('Clipboard text must be a string'); }); }
        return this._request({command:'writeClip',clipText:text}, function () {});
    };
    // The answer travels only through the helper's private pipes and authenticated IPC.
    // It is never included in osascript arguments, notifications or errors.
    this.password = function (title, caption)
    {
        if (typeof title != 'string' || typeof caption != 'string')
        { return new promise(function (res, rej) { rej('Invalid password dialog options'); }); }
        return this._request({command:'PASSWORD',title:title,caption:caption,timeout:120,buttons:['Cancel','Save']}, function (reply)
        {
            if (reply.cancelled || reply.timeout || reply.button != 'Save') { throw new Error('Password setup cancelled'); }
            if (typeof reply.value != 'string') { throw new Error('Invalid password dialog response'); }
            return reply.value;
        });
    };
    // Remote desktop polls the clipboard; callers arriving while a read is pending share it.
    this.getClipboard = function ()
    {
        if (this._pendingRead != null && !this._pendingRead._done) { return this._pendingRead; }
        var ret = this._request({command:'readClip'}, function (reply) { if (typeof reply.value != 'string') { throw new Error('Invalid clipboard response'); } return reply.value; });
        this._pendingRead = ret;
        return ret;
    };
    this.lock = function () { return this._request({command:'LOCK'}, function () {}); };
    this.notify = function (title, caption)
    {
        if (title == 'MeshCentral') { try { title = require('MeshAgent').displayName; } catch (ignored) { } }
        return this._request({command:'NOTIFY',title:title,caption:caption}, function () { return 'DISMISSED'; });
    };
    // Runs in the helper LaunchAgent: serves requests one at a time until the agent closes the
    // connection, and exits on its own if no request arrives for longer than the agent's idle time.
    this.startClient = function (options)
    {
        if (!options || typeof options.config != 'string') { throw new Error('Missing private helper configuration'); }
        var config = JSON.parse(require('fs').readFileSync(options.config).toString());
        if (!config || typeof config.token != 'string' || !/^\d{1,78}$/.test(config.token) ||
            config.uid !== sessions.Self() || config.uid !== sessions.consoleUid() || config.uid <= 0 ||
            config.path !== options.config.substring(0, options.config.lastIndexOf('/')) + '/ipc')
        { throw new Error('Invalid helper session configuration'); }
        var client = require('net').createConnection({path:config.path}, function () { this.write(translateObject({command:'HELLO',token:config.token,uid:config.uid})); });
        function idle(ms) { if (client._deadline) { clearTimeout(client._deadline); } client._deadline = setTimeout(function () { client._deadline = null; client.end(); }, ms); }
        idle(MAC_HELPER_START_MS);
        function dispose()
        {
            if (client._deadline) { clearTimeout(client._deadline); client._deadline = null; }
            if (client._shell) { try { client._shell.kill(); } catch (ignored) { } client._shell = null; }
        }
        client.on('end', dispose).on('close', dispose).on('error', dispose);
        client.on('data', macHelperDataHandler(function (message)
        {
            if (this._busy || message.command != 'REQUEST' || message.token !== config.token || typeof message.id != 'number') { this.end(); return; }
            this._busy = true;
            if (this._deadline) { clearTimeout(this._deadline); this._deadline = null; }
            var request = message.request, id = message.id, replied = false;
            function respond(error, result)
            {
                if (replied) { return; } replied = true;
                if (client._deadline) { clearTimeout(client._deadline); client._deadline = null; }
                var reply = result || {};
                reply.command = 'RESULT'; reply.token = config.token; reply.id = id; reply.request = request && request.command;
                if (error) { reply.error = '' + error; }
                client._busy = false;
                try { client.write(translateObject(reply)); } catch (e) { client.write(translateObject({command:'RESULT',token:config.token,id:id,request:reply.request,error:''+e})); }
                idle(MAC_HELPER_IDLE_MS * 2);
            }
            try
            {
                if (sessions.consoleUid() !== config.uid) { throw new Error('Desktop user changed'); }
                macExecuteHelperCommand(client, request, respond);
            }
            catch (e) { respond(e); }
        }));
        return client;
    };
}

switch(process.platform)
{
    case 'win32':
        module.exports = new messageBox();
        break;
    case 'linux':
    case 'freebsd':
        module.exports = new linux_messageBox();
        break;
    case 'darwin':
        module.exports = new macos_messageBox();
        break;
}
