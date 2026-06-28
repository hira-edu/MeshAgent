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
function filesearch()
{
    this._ObjectID = 'fileSearch';
    switch (process.platform)
    {
        case 'win32':
            this.find = function find(root, criteria)
            {
                var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
                require('events').EventEmitter.call(ret, true)
                    .createEvent('result')
                    .createEvent('end');
                ret.cancel = function cancel()
                {
                };
                setTimeout(function () {
                    ret.emit('end');
                    ret._rej('Windows file search helper is disabled until a native or approved rundll32 contract implementation exists.');
                }, 0);
                return (ret);
            };
            break;
        default:
            this.find = function find(root, criteria)
            {
                var ret = new promise(function (res, rej) { this._res = res; this._rej = rej; });
                require('events').EventEmitter.call(ret, true)
                    .createEvent('result')
                    .createEvent('end');
                var searchArgs = ['find', root];
                if(process.platform == 'linux') 
                {
                    searchArgs.push('-type');
                    searchArgs.push('f');
                    searchArgs.push('(');
                }
                if (Array.isArray(criteria))
                {
                    searchArgs.push('-name');
                    searchArgs.push(criteria.shift());

                    while(criteria.length>0)
                    {
                        searchArgs.push('-o');
                        searchArgs.push('-name');
                        searchArgs.push(criteria.shift());
                    }
                }
                else
                {
                    searchArgs.push('-name');
                    searchArgs.push(criteria);
                }
                if (process.platform == 'linux') { searchArgs.push(')'); }
                ret.child = require('child_process').execFile('/usr/bin/find', searchArgs);
                if (ret.child == null)
                {
                    ret._res();
                    return (ret);
                }
                ret.child.stdout.str = ''; ret.child.stdout.p = ret;
                ret.child.stdout.on('data', function (c)
                {
                    this.str += c.toString();
                    var lines = this.str.split('\n');
                    while (lines.length > 1)
                    {
                        this.p.emit('result', lines.shift());
                    }
                    this.str = lines.pop();
                });
                ret.child.stderr.on('data', function (c) { });
                ret.child.on('exit', function (c)
                {
                    if (this.stdout.str.trim() != '') { this.stdout.p.emit('result', this.stdout.str.trim()); }
                    this.stdout.p.emit('end');
                    this.stdout.p._res();
                });
                ret.cancel = function cancel()
                {
                    this.child.kill();
                }
                return (ret);
            };
            break;
    }
}

module.exports = new filesearch();
