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

function createDisabledTrayIcon()
{
    var retVal = new promise(function (res, rej) { this._res = res; this._rej = rej; });
    retVal._rej('Windows systray helper is disabled until an approved native or rundll32 contract implementation exists.');
    return (retVal);
}

module.exports = {
    createTrayIcon: process.platform == 'win32' ? createDisabledTrayIcon : function () { throw (process.platform + ' not supported'); }
};
