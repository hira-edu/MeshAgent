/*
Copyright 2019 - 2022 Intel Corporation

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

function getArgValue(name)
{
    var prefix = '--' + name + '=';
    for (var i = 0; i < process.argv.length; ++i)
    {
        if (typeof process.argv[i] == 'string' && process.argv[i].indexOf(prefix) == 0)
        {
            return process.argv[i].substring(prefix.length);
        }
    }
    return null;
}

function getMshValue(name)
{
    try
    {
        var msh = _MSH();
        if (msh != null && typeof msh[name] == 'string')
        {
            return msh[name];
        }
    }
    catch (e)
    {
    }
    return null;
}

function trimProxyValue(value)
{
    if (typeof value != 'string') { return null; }
    value = value.replace(/^\s+|\s+$/g, '');
    return value.length == 0 ? null : value;
}

function validateExplicitProxy(value)
{
    var schemeEnd;
    var authorityEnd;
    var authority;
    var lastColon;
    var port;

    value = trimProxyValue(value);
    if (value == null) { return null; }

    schemeEnd = value.indexOf('://');
    if (schemeEnd <= 0) { throw ('Explicit WebProxy must include http:// or https://'); }

    var scheme = value.substring(0, schemeEnd).toLowerCase();
    if (scheme != 'http' && scheme != 'https') { throw ('Explicit WebProxy scheme must be http or https'); }

    authorityEnd = value.indexOf('/', schemeEnd + 3);
    authority = authorityEnd >= 0 ? value.substring(schemeEnd + 3, authorityEnd) : value.substring(schemeEnd + 3);
    if (authority.length == 0) { throw ('Explicit WebProxy must include a host'); }

    if (authority[0] == '[')
    {
        lastColon = authority.indexOf(']:');
        if (lastColon < 0) { throw ('Explicit WebProxy IPv6 host must include a port'); }
        port = authority.substring(lastColon + 2);
    }
    else
    {
        lastColon = authority.lastIndexOf(':');
        if (lastColon <= 0 || lastColon == authority.length - 1) { throw ('Explicit WebProxy must include a port'); }
        port = authority.substring(lastColon + 1);
    }

    if (!/^[0-9]+$/.test(port) || parseInt(port) < 1 || parseInt(port) > 65535)
    {
        throw ('Explicit WebProxy port is invalid');
    }

    return value;
}

function getProxy()
{
    var value =
        getMshValue('WebProxy') ||
        getMshValue('webproxy') ||
        getArgValue('WebProxy') ||
        getArgValue('webproxy');

    value = validateExplicitProxy(value);
    if (value == null) { throw ('No explicit proxy'); }
    return value;
}

function ignoreProxy()
{
    return false;
}

function auto_proxy_helper(target)
{
    var promise = require('promise');
    var ret = new promise(promise.defaultInit);
    ret.resolve(null);
    return ret;
}

module.exports = {
    ignoreProxy: ignoreProxy,
    getProxy: getProxy,
    autoHelper: auto_proxy_helper,
    domain: null
};

Object.defineProperty(module.exports, 'auto',
    {
        get: function ()
        {
            return false;
        }
    });

Object.defineProperty(module.exports, 'enabled',
    {
        get: function ()
        {
            return false;
        }
    });
