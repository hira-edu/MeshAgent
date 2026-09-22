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

function start(updatePath)
{
    var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    if (!require('zip-reader').isZip(updatePath)) { ret._res(); return (ret); }
    ret._readpromise = require('zip-reader').read(updatePath);
    ret._readpromise.then(function _updatehelper(zipped)
    {
        var p = new promise(function (res, rej) { this._res = res; this._rej = rej; });
        p.failed = false;
        p.fail = function fail(e)
        {
            if (this.failed) { return; }
            this.failed = true;
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
                var actualSize = -1;
                try { actualSize = require('fs').statSync(updatePath + '_unzipped').size; } catch (e) { this.prom.fail(e); return; }
                if (actualSize != this.zipped.size(this.entryName))
                {
                    this.prom.fail('Extracted update size mismatch');
                    return;
                }
                if (this.prom.source.crc != this.zipped.crc(this.entryName))
                {
                    this.prom.fail('Extracted update CRC mismatch');
                    return;
                }
                this.zipped.close();
                this.prom._res();
            });
            p.source = zipped.getStream(entryName);
            p.source.on('error', function (e) { p.fail(e); try { p.dest.end(); } catch (ignored) { } });
            p.source.pipe(p.dest);
        }
        return (p);
    })
    .then(function ()
    {
        try
        {
            require('fs').copyFileSync(updatePath + '_unzipped', updatePath);
        }
        catch(e)
        {
            ret._rej(e);
            return;
        }
        try { require('fs').unlinkSync(updatePath + '_unzipped'); } catch (ignored) { }
        ret._res('done');
    })
    .catch(function (e) { ret._rej(e); });

    return (ret);
}

module.exports = { start: start };
