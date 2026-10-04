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

var promise = require('promise');

// Native agentcore accepts no new update transfer until this promise settles, so an
// extraction that never finishes (a stalled stream or a throwing async callback) must fail.
var EXTRACT_TIMEOUT_MS = 600000;

function start(updatePath)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    try
    {
        if (!require('zip-reader').isZip(updatePath)) { ret._res(); return (ret); }
        ret._readpromise = require('zip-reader').read(updatePath);
    }
    catch (e) { ret._rej(e); return ret; }
    ret._timeout = setTimeout(function ()
    {
        ret.timedOut = true;
        try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
        ret._rej(new Error('Update extraction timed out'));
    }, EXTRACT_TIMEOUT_MS);
    ret._readpromise.then(function _updatehelper(zipped)
    {
        var p = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        p.failed = false;
        p.fail = function fail(e)
        {
            if (this.failed) { return; }
            this.failed = true;
            if (this.source && this.dest && typeof this.source.unpipe == 'function') { try { this.source.unpipe(this.dest); } catch (ignored) { } }
            if (this.dest) { try { this.dest.end(); } catch (ignored) { } }
            try { zipped.close(); } catch (ignored) { }
            try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
            this._rej(e);
        };
        if (zipped.files.length != 1)
        {
            p.fail('Unexpected contents in zip file');
        }
        else
        {
            var entryName = zipped.files[0];
            try
            {
                p.dest = require('fs').createWriteStream(updatePath + '_unzipped', { flags: 'wb' });
            }
            catch (e)
            {
                p.fail(e);
                return (p);
            }
            p.dest.prom = p;
            p.dest.zipped = zipped;
            p.dest.entryName = entryName;
            p.dest.on('error', function (e) { this.prom.fail(e); });
            p.dest.on('close', function ()
            {
                if (this.prom.failed) { try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { } return; }
                if (this.prom.completed) { return; }
                try
                {
                    var actualSize = require('fs').statSync(updatePath + '_unzipped').size;
                    if (actualSize != this.zipped.size(this.entryName)) { throw new Error('Extracted update size mismatch'); }
                    if (this.prom.source.crc != this.zipped.crc(this.entryName)) { throw new Error('Extracted update CRC mismatch'); }
                    this.zipped.close();
                    this.prom.completed = true;
                    this.prom._res();
                }
                catch (e) { this.prom.fail(e); }
            });
            try
            {
                p.source = zipped.getStream(entryName);
                p.source.on('error', function (e) { p.fail(e); });
                p.source.pipe(p.dest);
            }
            catch (e) { p.fail(e); }
        }
        return (p);
    })
    .then(function ()
    {
        clearTimeout(ret._timeout);
        if (ret.timedOut)
        {
            // The agent already abandoned this package; do not recreate it.
            try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
            return;
        }
        try
        {
            require('fs').copyFileSync(updatePath + '_unzipped', updatePath);
        }
        catch(e)
        {
            try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
            ret._rej(e);
            return;
        }
        try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
        ret._res('done');
    })
    .catch(function (e) { clearTimeout(ret._timeout); ret._rej(e); });

    return (ret);
}

module.exports = { start: start };
