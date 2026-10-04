/*
Copyright 2019 Intel Corporation

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

// Matches MeshAgent_MakeAbsolutePath(exePath, ".db") on Windows: the last extension of the file
// name is replaced (any case), or '.db' is appended when there is none. A plain
// replace('.exe', '.db') misses '.EXE' and edits the first '.exe' anywhere in the path.
function _meshDbPath(exePath)
{
    var sep = Math.max(exePath.lastIndexOf('\\'), exePath.lastIndexOf('/'));
    var dot = exePath.lastIndexOf('.');
    return ((dot > sep ? exePath.substring(0, dot) : exePath) + '.db');
}

// The service name the running agent was started with, when the agent object is available.
function _runtimeServiceName()
{
    try
    {
        var name = require('MeshAgent').serviceName;
        if (typeof name == 'string' && name.length > 0) { return (name); }
    }
    catch (e)
    {
    }
    return (null);
}

function _meshNodeId()
{
    var ret = '';
    switch (process.platform)
    {
        case 'linux':
        case 'darwin':
            try
            {
                var db = require('SimpleDataStore').Create(process.execPath + '.db', { readOnly: true });
                ret = require('tls').loadCertificate({ pfx: db.GetBuffer('SelfNodeCert'), passphrase: 'hidden' }).getKeyHash().toString('hex');
            }
            catch(e)
            {
            }
            break;
        case 'win32':
            // First Check if the db Contains the NodeID
            try
            {
                var db = require('SimpleDataStore').Create(_meshDbPath(process.execPath), { readOnly: true });
                var v = db.GetBuffer('SelfNodeCert');
                if (v)
                {
                    try
                    {
                        ret = require('tls').loadCertificate({ pfx: v, passphrase: 'hidden' }).getKeyHash().toString('hex');
                    }
                    catch(e)
                    {
                        v = null;
                    }
                }
                if (v == null && (v = db.GetBuffer('NodeID')) != null)
                {
                    ret = v.toString('hex');
                }
            }
            catch (e)
            {
            }
            break;
        default:
            break;
    }
    return (ret);
}

function _meshName()
{
    // On Windows the runtime name is the running service's SCM key. Elsewhere it falls back to
    // this build's default, which can hide an upstream installation's real name, so it is only
    // used after discovery.
    var name = (process.platform == 'win32') ? _runtimeServiceName() : null;
    if (name == null) { name = _MSH().meshServiceName; }
    if(name==null)
    {
        switch(process.platform)
        {
            case 'win32':
                // Enumerate the registry to see if the we can find our NodeID           
                var reg = require('win-registry');
                var nid = _meshNodeId();
                var key, hive;
                var source = [reg.HKEY.LocalMachine, reg.HKEY.CurrentUser];
                var val;

                // Without a NodeID every registry entry would be compared against '', so skip the scan.
                while (nid != '' && name == null && source.length > 0)
                {
                    hive = source.shift();
                    try { val = reg.QueryKey(hive, 'Software\\Open Source'); } catch (qe) { continue; }
                    for (key = 0; key < val.subkeys.length;++key)
                    {
                        try
                        {
                            if (nid == Buffer.from(reg.QueryKey(hive, 'Software\\Open Source\\' + val.subkeys[key], 'NodeId').split('@').join('+').split('$').join('/'), 'base64').toString('hex'))
                            {
                                name = val.subkeys[key];
                                break;
                            }
                        }
                        catch (ex)
                        {
                        }
                    }
                }
                if (name == null) { name = _runtimeServiceName(); }
                if (name == null) { throw new Error('Cannot resolve the installed Windows agent service name.'); }
                break;
            default:
                var service = [];
                try { service = require('service-manager').manager.enumerateService(); } catch (ee) { }
                for (var i = 0; i < service.length; ++i)
                {
                    try
                    {
                        if (service[i].appLocation() == process.execPath)
                        {
                            name = service[i].name;
                            break;
                        }
                    }
                    catch (ae)
                    {
                    }
                }
                if (name == null) { name = _runtimeServiceName(); }
                if (name == null) { name = 'meshagent'; }
                break;
        }
    }
    return (name);
}

function _resetNodeId()
{
    var name = _meshName();
    require('win-registry').WriteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId', 1);
    console.log('Resetting NodeID for: ' + name);
}
function _checkResetNodeId(name)
{
    var status = false;
    try
    {
        // Check if reset node id was set in the registry
        status = require('win-registry').QueryKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId') == 1 ? true : false;
    }
    catch(x)
    {
    }
    if (status)
    {
        try
        {
            // Delete the reset node id field in the registry
            require('win-registry').DeleteKey(require('win-registry').HKEY.LocalMachine, 'Software\\Open Source\\' + name, 'ResetNodeId');
        }
        catch(y)
        {
            // If we can't delete it, we must pretend that it was never set, otherwise we risk getting in a loop where we constantly reset the node id
            status = false;
        }
    }
    return (status);
}

module.exports = _meshNodeId;
module.exports.serviceName = _meshName;
module.exports.resetNodeId = _resetNodeId;
module.exports.checkResetNodeId = _checkResetNodeId;

