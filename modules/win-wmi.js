/*
Copyright 2021 Intel Corporation

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
var GM = require('_GenericMarshal');
const CLSID_WbemAdministrativeLocator = '{CB8555CC-9128-11D1-AD9B-00C04FD8FDFF}';
const IID_WbemLocator = '{dc12a687-737f-11cf-884d-00aa004b2e24}';
const WBEM_FLAG_BIDIRECTIONAL = 0;
const WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
const WBEM_FLAG_FORWARD_ONLY = 0x20;
const WBEM_QUERY_FLAGS = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;
const WBEM_DEFAULT_QUERY_TIMEOUT_MS = 15000;
const WBEM_S_FALSE = 1;
const WBEM_S_TIMEDOUT = 0x00040004;
const WBEM_FLAG_ALWAYS = 0;
const E_NOINTERFACE = 0x80004002;
var OleAut32 = GM.CreateNativeProxy('OleAut32.dll');
OleAut32.CreateMethod('SafeArrayAccessData');
OleAut32.CreateMethod('SafeArrayUnaccessData');
OleAut32.CreateMethod('SafeArrayDestroy');
OleAut32.CreateMethod('VariantClear');

var wmi_handlers = {};

const LocatorFunctions = ['QueryInterface', 'AddRef', 'Release', 'ConnectToServer'];

//
// Reference for IWbemServices can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
//
const ServiceFunctions = [
    'QueryInterface',
    'AddRef',
    'Release',
    'OpenNamespace',
    'CancelAsyncCall',
    'QueryObjectSink',
    'GetObject',
    'GetObjectAsync',
    'PutClass',
    'PutClassAsync',
    'DeleteClass',
    'DeleteClassAsync',
    'CreateClassEnum',
    'CreateClassEnumAsync',
    'PutInstance',
    'PutInstanceAsync',
    'DeleteInstance',
    'DeleteInstanceAsync',
    'CreateInstanceEnum',
    'CreateInstanceEnumAsync',
    'ExecQuery',
    'ExecQueryAsync',
    'ExecNotificationQuery',
    'ExecNotificationQueryAsync',
    'ExecMethod',
    'ExecMethodAsync'
];

//
// Reference to IEnumWbemClassObject can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
//
const ResultsFunctions = [
        'QueryInterface',
        'AddRef',
        'Release',
        'Reset',
        'Next',
        'NextAsync',
        'Clone',
        'Skip'
];

//
// Reference to IWbemClassObject can be found at:
// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
//
const ResultFunctions = [
            'QueryInterface',
            'AddRef',
            'Release',
            'GetQualifierSet',
            'Get',
            'Put',
            'Delete',
            'GetNames',
            'BeginEnumeration',
            'Next',
            'EndEnumeration',
            'GetPropertyQualifierSet',
            'Clone',
            'GetObjectText',
            'SpawnDerivedClass',
            'SpawnInstance',
            'CompareTo',
            'GetPropertyOrigin',
            'InheritsFrom',
            'GetMethod',
            'PutMethod',
            'DeleteMethod',
            'BeginMethodEnumeration',
            'NextMethod',
            'EndMethodEnumeration',
            'GetMethodQualifierSet',
            'GetMethodOrigin'
];

//
// Reference to IWbemObjectSink can be found at:
// https://learn.microsoft.com/en-us/windows/win32/wmisdk/iwbemobjectsink
//
const QueryAsyncHandler =
    [
        {
            cx: 10, parms: 3, name: 'QueryInterface', func: function (j, riid, ppv)
            {
                var ret = GM.CreateVariable(4);
                console.info1('QueryInterface', riid.Deref(0, 16).toBuffer().toString('hex'));
                switch (riid.Deref(0, 16).toBuffer().toString('hex'))
                {
                    case '0000000000000000C000000000000046': // IID_IUnknown
                        j.pointerBuffer().copy(ppv.Deref(0, GM.PointerSize).toBuffer());
                        ret.increment(0, true);
                        //++this.p.refcount;
                        console.info1('QueryInterface (IID_IUnknown)', this.refcount);
                        break;
                    case '0178857C8173CF11884D00AA004B2E24': // IID_IWmiObjectSink
                        j.pointerBuffer().copy(ppv.Deref(0, GM.PointerSize).toBuffer());
                        ret.increment(0, true);
                        //++this.p.refcount;
                        console.info1('QueryInterface (IID_IWmiObjectSink)', this.refcount);
                        break;
                    default:
                        ret.increment(E_NOINTERFACE, true);
                        console.info1(riid.Deref(0, 16).toBuffer().toString('hex'), 'returning E_NOINTERFACE');
                        break;
                }

                return (ret);
            }
        },
        {
            cx: 11, parms: 1, name: 'AddRef', func: function ()
            {
                ++this.refcount;
                console.info1('AddRef', this.refcount);
                return (GM.CreateVariable(4));
            }
        },
        {
            cx: 12, parms: 1, name: 'Release', func: function ()
            {
                --this.refcount;
                console.info1('Release', this.refcount);
                if (this.refcount == 0)
                {
                    console.info1('No More References');

                    this.cleanup();
                    this.services.funcs.Release(this.services.Deref());

                    this.services = null;
                    this.p = null;
                    if (this.callbackDispatched)
                    {
                        setImmediate(function (j) { j.locator = null; }, this);
                    }
                    else
                    {
                        this.locator = null;
                    }
                    
                    console.info1('No More References [END]');
                }
                return (GM.CreateVariable(4));
            }
        },
        {
            cx: 13, parms: 3, name: 'Indicate', func: function (j, count, arr)
            {
                console.info1('Indicate', count.Val);
                var j, nme, len, nn;

                for (var i = 0; i < count.Val; ++i)
                {
                    j = arr.Deref((i * GM.PointerSize) + 0, GM.PointerSize);
                    this.results.push(enumerateProperties(j, this.fields));
                }

                var ret = GM.CreateVariable(4);
                ret.increment(0, true);
                return (ret);
            }
        },
        {
            cx: 14, parms: 5, name: 'SetStatus', func: function (j, lFlags, hResult, strParam, pObjParam)
            {
                console.info1('SetStatus', hResult.Val);

                var ret = GM.CreateVariable(4);
                ret.increment(0, true);

                if (hResult.Val == 0)
                {
                    this.p.resolve(this.results);
                }
                else
                {
                    this.p.reject(hResult.Val);
                }
                return (ret);
            }
        }
    ];


function _isNullPointer(j)
{
    if (j == null) { return (true); }
    var b = j.toBuffer();
    for (var i = 0; i < b.length; ++i)
    {
        if (b[i] != 0) { return (false); }
    }
    return (true);
}

function _readWidePointer(j)
{
    if (_isNullPointer(j)) { return (null); }
    return (j.Deref().Wide2UTF8);
}

function _queryTimeoutMs(options)
{
    var timeoutMs = WBEM_DEFAULT_QUERY_TIMEOUT_MS;
    if (typeof (options) == 'number')
    {
        timeoutMs = options;
    }
    else if (options != null && typeof (options.timeoutMs) == 'number')
    {
        timeoutMs = options.timeoutMs;
    }
    return (timeoutMs > 0 ? timeoutMs : WBEM_DEFAULT_QUERY_TIMEOUT_MS);
}

function _releaseComPointer(j, funcs)
{
    try
    {
        if (j != null && funcs != null)
        {
            funcs.Release(j);
        }
    }
    catch (x)
    {
    }
}

function enumerateProperties(j, fields)
{
    //
    // Reference to SafeArrayAccessData() can be found at:
    // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayaccessdata
    //

    var nme, len, nn;
    var properties = [];
    var values = {};

    j.funcs = require('win-com').marshalFunctions(j.Deref(), ResultFunctions);

    // First we need to enumerate the COM Array
    if (fields != null && Array.isArray(fields))
    {
        properties = fields;
    }
    else
    {
        nme = GM.CreatePointer();
        if (j.funcs.GetNames(j.Deref(), 0, WBEM_FLAG_ALWAYS, 0, nme).Val == 0)
        {
            var namesArray = nme.Deref();
            len = namesArray.Deref(GM.PointerSize == 8 ? 24 : 16, 4).toBuffer().readUInt32LE();
            nn = GM.CreatePointer();
            if (OleAut32.SafeArrayAccessData(namesArray, nn).Val == 0)
            {
                try
                {
                    for (var i = 0; i < len; ++i)
                    {
                        var propName = _readWidePointer(nn.Deref().increment(i * GM.PointerSize));
                        if (propName == null || propName.length === 0) { continue; }
                        properties.push(propName);
                    }
                }
                finally
                {
                    OleAut32.SafeArrayUnaccessData(namesArray);
                }
            }
            OleAut32.SafeArrayDestroy(namesArray);
        }
    }

    // Now we need to introspect the Array Fields
    for (var i = 0; i < properties.length; ++i)
    {
        var tmp1 = GM.CreateVariable(24);
        if (j.funcs.Get(j.Deref(), GM.CreateVariable(properties[i], { wide: true }), 0, tmp1, 0, 0).Val == 0)
        {
            //
            // Reference for IWbemClassObject::Get() can be found at:
            // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get
            //

            var vartype = tmp1.toBuffer().readUInt16LE();
            var isArray = (vartype & 0x2000) != 0;  // VT_ARRAY flag
            var baseType = vartype & 0x0FFF;

            try
            {
                if (isArray)
                {
                    // Handle array types (VT_ARRAY | base type)
                    var safeArrayPointer = tmp1.Deref(8, GM.PointerSize);
                    var arrayValues = [];
                    if (!_isNullPointer(safeArrayPointer))
                    {
                        var safeArray = safeArrayPointer.Deref();
                        var arrayLength = safeArray.Deref(GM.PointerSize == 8 ? 24 : 16, 4).toBuffer().readUInt32LE();
                        var arrayData = GM.CreatePointer();
                        if (OleAut32.SafeArrayAccessData(safeArray, arrayData).Val == 0)
                        {
                            try
                            {
                                for (var k = 0; k < arrayLength; ++k)
                                {
                                    switch (baseType)
                                    {
                                        case 0x0002:    // VT_I2
                                            arrayValues.push(arrayData.Deref().Deref(k * 2, 2).toBuffer().readInt16LE());
                                            break;
                                        case 0x0003:    // VT_I4
                                        case 0x0016:    // VT_INT
                                            arrayValues.push(arrayData.Deref().Deref(k * 4, 4).toBuffer().readInt32LE());
                                            break;
                                        case 0x000B:    // VT_BOOL
                                            arrayValues.push(arrayData.Deref().Deref(k * 2, 2).toBuffer().readInt16LE() != 0);
                                            break;
                                        case 0x0010:    // VT_I1
                                            arrayValues.push(arrayData.Deref().Deref(k, 1).toBuffer().readInt8());
                                            break;
                                        case 0x0011:    // VT_UI1
                                            arrayValues.push(arrayData.Deref().Deref(k, 1).toBuffer().readUInt8());
                                            break;
                                        case 0x0012:    // VT_UI2
                                            arrayValues.push(arrayData.Deref().Deref(k * 2, 2).toBuffer().readUInt16LE());
                                            break;
                                        case 0x0013:    // VT_UI4
                                        case 0x0017:    // VT_UINT
                                            arrayValues.push(arrayData.Deref().Deref(k * 4, 4).toBuffer().readUInt32LE());
                                            break;
                                        case 0x0008:    // VT_BSTR
                                            arrayValues.push(_readWidePointer(arrayData.Deref().Deref(k * GM.PointerSize, GM.PointerSize)));
                                            break;
                                    }
                                }
                            }
                            finally
                            {
                                OleAut32.SafeArrayUnaccessData(safeArray);
                            }
                        }
                    }
                    values[properties[i]] = arrayValues;
                }
                else
                {
                    // Handle scalar types
                    switch (vartype)
                    {
                        case 0x0000:    // VT_EMPTY
                        case 0x0001:    // VT_NULL
                            values[properties[i]] = null;
                            break;
                        case 0x0002:    // VT_I2
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readInt16LE();
                            break;
                        case 0x0003:    // VT_I4
                        case 0x0016:    // VT_INT
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readInt32LE();
                            break;
                        case 0x000B:    // VT_BOOL
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readInt32LE() != 0;
                            break;
                        case 0x000E:    // VT_DECIMAL
                            break;
                        case 0x0010:    // VT_I1
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readInt8();
                            break;
                        case 0x0011:    // VT_UI1
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readUInt8();
                            break;
                        case 0x0012:    // VT_UI2
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readUInt16LE();
                            break;
                        case 0x0013:    // VT_UI4
                        case 0x0017:    // VT_UINT
                            values[properties[i]] = tmp1.Deref(8, GM.PointerSize).toBuffer().readUInt32LE();
                            break;
                        //case 0x0014:    // VT_I8
                        //    break;
                        //case 0x0015:    // VT_UI8
                        //    break;
                        case 0x0008:    // VT_BSTR
                            values[properties[i]] = _readWidePointer(tmp1.Deref(8, GM.PointerSize));
                            break;
                        default:
                            console.info1('VARTYPE: ' + vartype);
                            break;
                    }
                }
            }
            finally
            {
                OleAut32.VariantClear(tmp1);
            }
        }
    }

    return (values);
}

function queryAsync(resourceString, queryString, fields)
{
    var p = new promise(require('promise').defaultInit);
    var resource = GM.CreateVariable(resourceString, { wide: true });
    var language = GM.CreateVariable("WQL", { wide: true });
    var query = GM.CreateVariable(queryString, { wide: true });
    var results = GM.CreatePointer();

    // Setup the Async COM handler for QueryAsync() 
    var handlers = require('win-com').marshalInterface(QueryAsyncHandler);
    handlers.refcount = 1;
    handlers.results = [];
    handlers.fields = fields;
    handlers.locator = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_WbemAdministrativeLocator), require('win-com').IID_IUnknown);
    handlers.locator.funcs = require('win-com').marshalFunctions(handlers.locator, LocatorFunctions);

    handlers.services = require('_GenericMarshal').CreatePointer();
    if (handlers.locator.funcs.ConnectToServer(handlers.locator, resource, 0, 0, 0, 0, 0, 0, handlers.services).Val != 0) { throw ('Error calling ConnectToService'); }

    handlers.services.funcs = require('win-com').marshalFunctions(handlers.services.Deref(), ServiceFunctions);
    handlers.p = p;
    
    // Make the COM call
    if (handlers.services.funcs.ExecQueryAsync(handlers.services.Deref(), language, query, WBEM_QUERY_FLAGS, 0, handlers).Val != 0)
    {
        throw ('Error in Query');
    }

    // Hold a reference to the callback object
    wmi_handlers[handlers._hashCode()] = handlers;
    return (p);
}
function query(resourceString, queryString, fields, options)
{
    var timeoutMs = _queryTimeoutMs(options);
    var resource = GM.CreateVariable(resourceString, { wide: true });
    var language = GM.CreateVariable("WQL", { wide: true });
    var query = GM.CreateVariable(queryString, { wide: true });
    var results = GM.CreatePointer();
    var locator = null;
    var services = null;
    var ret = [];

    try
    {
        // Connect the locator connection for WMI
        locator = require('win-com').createInstance(require('win-com').CLSIDFromString(CLSID_WbemAdministrativeLocator), require('win-com').IID_IUnknown);
        locator.funcs = require('win-com').marshalFunctions(locator, LocatorFunctions);
        services = require('_GenericMarshal').CreatePointer();
        if (locator.funcs.ConnectToServer(locator, resource, 0, 0, 0, 0, 0, 0, services).Val != 0) { throw ('Error calling ConnectToService'); }

        // Execute as a forward-only semisynchronous query. Enumeration owns the bounded wait.
        services.funcs = require('win-com').marshalFunctions(services.Deref(), ServiceFunctions);
        if (services.funcs.ExecQuery(services.Deref(), language, query, WBEM_QUERY_FLAGS, 0, results).Val != 0) { throw ('Error in Query'); }

        results.funcs = require('win-com').marshalFunctions(results.Deref(), ResultsFunctions);
        var returnedCount = GM.CreateVariable(4);
        var result = GM.CreatePointer();

        // Enumerate the results with a finite provider wait so a bad WMI provider cannot stall the microstack chain.
        while (true)
        {
            returnedCount.toBuffer().fill(0);
            var nextResult = results.funcs.Next(results.Deref(), timeoutMs, 1, result, returnedCount).Val;
            var count = returnedCount.toBuffer().readUInt32LE();

            if ((nextResult == 0 || nextResult == WBEM_S_TIMEDOUT) && count > 0)
            {
                try
                {
                    ret.push(enumerateProperties(result, fields));
                }
                finally
                {
                    _releaseComPointer(result.Deref(), result.funcs);
                    result = GM.CreatePointer();
                }
            }

            if (nextResult == 0 && count > 0) { continue; }
            if (nextResult == WBEM_S_FALSE || nextResult == WBEM_S_TIMEDOUT || count == 0) { break; }
            throw ('Error enumerating Query: ' + nextResult);
        }
    }
    finally
    {
        if (results != null && results.funcs != null) { _releaseComPointer(results.Deref(), results.funcs); }
        if (services != null && services.funcs != null) { _releaseComPointer(services.Deref(), services.funcs); }
        if (locator != null && locator.funcs != null) { _releaseComPointer(locator, locator.funcs); }
    }

    return (ret);
}

module.exports = { query: query, queryAsync: queryAsync };
