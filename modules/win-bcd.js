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

//
function rejectWinBcdOperation(operation)
{
    throw new Error('Windows ' + operation + ' is disabled by the rundll32-only runtime contract. Use the native MeshLifecycleHostW lifecycle path for Windows state changes.');
}

function getKeys()
{
    return rejectWinBcdOperation('BCD query');
}

//
// Returns the value associated with the specified key
//
function getKey(key)
{
    return (this.getKeys()[key]);
}

function setKey(key, value)
{
    return rejectWinBcdOperation('BCD mutation');
}

function deleteKey(key)
{
    return rejectWinBcdOperation('BCD mutation');
}

function enableSafeModeService(serviceName)
{
    return rejectWinBcdOperation('SafeBoot service registration');
}

function isSafeModeService(serviceName)
{
    return rejectWinBcdOperation('SafeBoot service query');
}

function disableSafeModeService(serviceName)
{
    return rejectWinBcdOperation('SafeBoot service registration');
}

function restart(delay)
{
    return rejectWinBcdOperation('shutdown utility execution');
}

if (require('_GenericMarshal').PointerSize == 4 && require('os').arch() == 'x64')
{
    //
    // 32 bit agent running on 64 bit windows, we do not expose BCD functions, because bcdedit does not work from a 32 bit process on 64 bit windows
    //
    module.exports =
    {
        enableSafeModeService: enableSafeModeService,
        disableSafeModeService: disableSafeModeService, restart: restart, isSafeModeService: isSafeModeService
    };
}
else
{
    module.exports =
        {
            getKeys: getKeys, setKey: setKey, deleteKey: deleteKey, enableSafeModeService: enableSafeModeService,
            disableSafeModeService: disableSafeModeService, getKey: getKey, restart: restart, isSafeModeService: isSafeModeService
        };

    Object.defineProperty(module.exports, "bootMode",
        {
            get: function ()
            {
                return rejectWinBcdOperation('SafeBoot option query');
            }
        });
}
