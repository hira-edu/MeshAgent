var http = require('http');
var childProcess = require('child_process');
var fs = require('fs');
var net = require('net');
function sendConsoleText(msg, sessionid)
{
    var cmd = { "action": "msg", "type": "console", "value": msg };
    if (sessionid != null) { cmd.sessionid = sessionid; }
    require('MeshAgent').SendCommand(cmd);
}

function splitArgs(str)
{
    var ret = [];
    var token = '';
    var inQuote = false;
    var quoteChar = null;
    var escaped = false;
    if (str == null) { return ret; }
    for (var i = 0; i < str.length; ++i)
    {
        var c = str.charAt(i);
        if (escaped) { token += c; escaped = false; continue; }
        if (inQuote)
        {
            if (c == '\\') { escaped = true; continue; }
            if (c == quoteChar) { inQuote = false; quoteChar = null; continue; }
            token += c;
            continue;
        }
        if (c == '"' || c == '\'') { inQuote = true; quoteChar = c; continue; }
        if (c <= ' ')
        {
            if (token.length > 0) { ret.push(token); token = ''; }
            continue;
        }
        token += c;
    }
    if (escaped) { token += '\\'; }
    if (token.length > 0) { ret.push(token); }
    return ret;
}

function toNumberIfNumber(x) { if ((typeof x == 'string') && x.length > 0 && /^-?\d+(\.\d+)?$/.test(x)) { x = +x; } return x; }

function parseArgs(argv)
{
    var results = { '_': [] }, current = null;
    for (var i = 1, len = argv.length; i < len; i++)
    {
        var x = argv[i];
        if (x.length > 2 && x[0] == '-' && x[1] == '-')
        {
            if (current != null) { results[current] = true; }
            current = x.substring(2);
        }
        else
        {
            if (current != null) { results[current] = toNumberIfNumber(x); current = null; } else { results['_'].push(toNumberIfNumber(x)); }
        }
    }
    if (current != null) { results[current] = true; }
    return results;
}

function countObjectKeys(obj)
{
    if (obj == null || typeof obj != 'object') { return 0; }
    return Object.keys(obj).length;
}

// SSOT: meshcore/config/umh_defines.h — keep in sync with MESHAGENT_UMH_CONTROL_PIPE_NAME
var umhControlPipePath = '\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control';
var umhctlRequestSizeLimit = 64 * 1024;
var umhctlResponseSizeLimit = 512 * 1024;
var umhctlControlOpMap = {
    status: 'status',
    listprocesses: 'listProcesses',
    getflowcontract: 'getFlowContract',
    getcapabilities: 'getCapabilities',
    getpolicy: 'getPolicy',
    getconfig: 'getConfig',
    inject: 'inject',
    injectall: 'injectAll',
    telemetry: 'telemetry',
    repair: 'repair',
    setpolicy: 'setPolicy',
    setconfig: 'setConfig',
    profileprocess: 'profileProcess',
    hookprofile: 'hookProfile',
    methodpolicy: 'methodPolicy',
    safetystate: 'safetyState',
    securityboundary: 'securityBoundary',
    injecttargetset: 'injectTargetSet',
    cleartargetscope: 'clearTargetScope',
    lockdownbypass: 'lockdownBypass',
    examsoftbypass: 'examsoftBypass',
    ipcbypass: 'ipcBypass'
};
var umhctlPidRequiredOps = {
    inject: 1,
    telemetry: 1,
    repair: 1,
    disable: 1,
    profileprocess: 1,
    registerprotectedpid: 1,
    unregisterprotectedpid: 1
};
var umhctlStateChangingOps = {
    inject: 1,
    injectall: 1,
    telemetry: 1,
    repair: 1,
    setpolicy: 1,
    setconfig: 1,
    injecttargetset: 1,
    cleartargetscope: 1,
    methodpolicy: 1,
    safetystate: 1,
    lockdownbypass: 1,
    examsoftbypass: 1,
    ipcbypass: 1
};
var umhctlFlowScopedOps = { injecttargetset: 1, injectall: 1, cleartargetscope: 1 };
var umhctlRuntimeControlOps = {
    telemetry: 1,
    repair: 1,
    setpolicy: 1,
    setconfig: 1,
    methodpolicy: 1,
    safetystate: 1
};
var umhctlFlowContractCache = null;
var umhctlFlowContractCacheUpdated = 0;
var umhctlFlowContractMaxAgeMs = 30000;
var umhctlFlowContextBySession = {};
var umhctlFlowContextMaxAgeMs = 900000;
var umhctlDefaultFlowContract = {
    protocol: 'umh-control',
    contractVersion: '2026-03-05',
    flowProfile: 'report-driven-lockdown-v1',
    requiredHeaders: [
        'x-umh-contract-version',
        'x-umh-flow-profile',
        'x-umh-run-id',
        'x-umh-client',
        'x-umh-target-tag',
        'x-umh-method-key'
    ]
};
var umhctlDefaultClientId = 'meshagent-umhctl';
var umhctlActionAllowedByOp = {
    ipcbypass: { listtargets: 'list-targets', status: 'status', disable: 'disable', enable: 'enable' },
    lockdownbypass: { status: 'status', apply: 'apply', applyharness: 'apply-harness', revert: 'revert', revertharness: 'revert-harness' },
    examsoftbypass: { status: 'status', secureenter: 'secure-enter', secureexit: 'secure-exit' }
};
var umhctlLifecycleOp = null;
var umhctlLifecycleState = null;

function umhctlNormalizeControlOp(op)
{
    if (typeof op != 'string' || op.length == 0) { return null; }
    return op.toLowerCase().split('-').join('').split('_').join('').split(' ').join('');
}

function umhctlNormalizeAction(action)
{
    if (typeof action != 'string' || action.length == 0) { return null; }
    return action.toLowerCase().split('-').join('').split('_').join('').split(' ').join('');
}

function umhctlCanonicalControlOp(op)
{
    var key = umhctlNormalizeControlOp(op);
    if (key == null) { return null; }
    return umhctlControlOpMap[key];
}

function umhctlIsControlOp(op)
{
    return (umhctlCanonicalControlOp(op) != null);
}

function umhctlCanonicalAction(op, action)
{
    var opKey = umhctlNormalizeControlOp(op);
    if (opKey == null) { return null; }
    var allowed = umhctlActionAllowedByOp[opKey];
    if (allowed == null) { return null; }
    var actionKey = umhctlNormalizeAction(action);
    if (actionKey == null) { return null; }
    return allowed[actionKey];
}

function umhctlParsePositiveInt(v)
{
    if (typeof v == 'number')
    {
        if ((v > 0) && (Math.floor(v) === v)) { return v; }
        return null;
    }
    if (typeof v != 'string') { return null; }
    var s = v.trim();
    if (!/^[0-9]+$/.test(s)) { return null; }
    var n = parseInt(s);
    if (!(n > 0)) { return null; }
    return n;
}

function umhctlParseJsonArg(raw)
{
    if (raw == null) { return null; }
    var txt = ('' + raw).trim();
    if (txt.length == 0) { return null; }
    try { return JSON.parse(txt); } catch (e) { }
    if (txt.indexOf('\\"') >= 0)
    {
        try { return JSON.parse(txt.split('\\"').join('"')); } catch (e) { }
    }
    return null;
}

function umhctlCloneObject(obj)
{
    var copy = {};
    if (obj == null || typeof obj != 'object') { return copy; }
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) { copy[keys[i]] = obj[keys[i]]; }
    return copy;
}

function umhctlBuildRunId()
{
    var now = new Date();
    var ts = '' + now.getUTCFullYear()
        + ('0' + (now.getUTCMonth() + 1)).slice(-2)
        + ('0' + now.getUTCDate()).slice(-2)
        + 'T'
        + ('0' + now.getUTCHours()).slice(-2)
        + ('0' + now.getUTCMinutes()).slice(-2)
        + ('0' + now.getUTCSeconds()).slice(-2)
        + ('00' + now.getUTCMilliseconds()).slice(-3);
    return 'run-' + ts + '-' + Math.floor(Math.random() * 1000000);
}

function umhctlSessionKey(sessionid)
{
    if (typeof sessionid != 'string' || sessionid.length == 0) { return null; }
    return sessionid;
}

function umhctlGetFlowContext(sessionid)
{
    var key = umhctlSessionKey(sessionid);
    if (key == null) { return null; }
    var ctxEntry = umhctlFlowContextBySession[key];
    if (ctxEntry == null || typeof ctxEntry != 'object') { return null; }
    var storedAt = 0;
    var ctx = ctxEntry;
    if (ctxEntry.headers != null && typeof ctxEntry.headers == 'object')
    {
        ctx = ctxEntry.headers;
        if (typeof ctxEntry.storedAt == 'number') { storedAt = ctxEntry.storedAt; }
    }
    if (typeof storedAt == 'number' && storedAt > 0 && (Date.now() - storedAt) > umhctlFlowContextMaxAgeMs)
    {
        delete umhctlFlowContextBySession[key];
        return null;
    }
    if (ctx == null || typeof ctx != 'object')
    {
        delete umhctlFlowContextBySession[key];
        return null;
    }
    return umhctlCloneObject(ctx);
}

function umhctlSetFlowContext(sessionid, headers)
{
    var key = umhctlSessionKey(sessionid);
    if (key == null) { return false; }
    umhctlFlowContextBySession[key] = { storedAt: Date.now(), headers: umhctlCloneObject(headers) };
    return true;
}

function umhctlClearFlowContext(sessionid)
{
    var key = umhctlSessionKey(sessionid);
    if (key == null) { return; }
    delete umhctlFlowContextBySession[key];
}

function umhctlResetFlowState()
{
    umhctlFlowContractCache = null;
    umhctlFlowContractCacheUpdated = 0;
    umhctlFlowContextBySession = {};
}

// Periodically prune stale flow context entries to prevent unbounded memory growth.
// Some agent runtimes return a timer handle without Node's unref() method.
var umhctlFlowContextGcTimer = setInterval(function ()
{
    var now = Date.now();
    var keys = Object.keys(umhctlFlowContextBySession);
    for (var i = 0; i < keys.length; i++)
    {
        var entry = umhctlFlowContextBySession[keys[i]];
        if (entry == null || typeof entry.storedAt != 'number' || (now - entry.storedAt) > umhctlFlowContextMaxAgeMs)
        {
            delete umhctlFlowContextBySession[keys[i]];
        }
    }
}, 300000);
if (umhctlFlowContextGcTimer != null && typeof umhctlFlowContextGcTimer.unref == 'function') { umhctlFlowContextGcTimer.unref(); }

function umhctlHasFreshFlowContract()
{
    if (umhctlFlowContractCache == null || typeof umhctlFlowContractCache != 'object') { return false; }
    if (typeof umhctlFlowContractCacheUpdated != 'number' || umhctlFlowContractCacheUpdated <= 0) { return false; }
    return ((Date.now() - umhctlFlowContractCacheUpdated) <= umhctlFlowContractMaxAgeMs);
}

function umhctlGetFlowContract()
{
    if (umhctlFlowContractCache != null && typeof umhctlFlowContractCache == 'object')
    {
        return umhctlCloneObject(umhctlFlowContractCache);
    }
    return {
        protocol: umhctlDefaultFlowContract.protocol,
        contractVersion: umhctlDefaultFlowContract.contractVersion,
        flowProfile: umhctlDefaultFlowContract.flowProfile,
        requiredHeaders: umhctlDefaultFlowContract.requiredHeaders.slice(0)
    };
}

function umhctlMaybeCacheFlowContract(parsed)
{
    try
    {
        if (parsed == null || parsed.ok !== true || parsed.data == null || typeof parsed.data != 'object') { return false; }
        var data = parsed.data;
        var contractVersion = data.contract_version || data.current_version;
        var flowProfile = data.flow_profile;
        if (typeof contractVersion != 'string' || contractVersion.length == 0) { return false; }
        if (typeof flowProfile != 'string' || flowProfile.length == 0) { return false; }
        var requiredHeaders = (data.required_headers instanceof Array) ? data.required_headers.slice(0) : umhctlDefaultFlowContract.requiredHeaders.slice(0);
        umhctlFlowContractCache = {
            protocol: (typeof data.protocol == 'string' && data.protocol.length > 0) ? data.protocol : umhctlDefaultFlowContract.protocol,
            contractVersion: contractVersion,
            flowProfile: flowProfile,
            requiredHeaders: requiredHeaders
        };
        umhctlFlowContractCacheUpdated = Date.now();
        return true;
    } catch (e) { }
    return false;
}

function umhctlIsStateChangingRequest(controlReq)
{
    var opKey = umhctlNormalizeControlOp(controlReq != null ? controlReq.op : null);
    return (opKey != null && umhctlStateChangingOps[opKey] === 1);
}

function umhctlSanitizeHeaderToken(value)
{
    if (value == null) { return null; }
    var s = ('' + value).trim();
    if (s.length == 0) { return null; }
    s = s.toLowerCase().replace(/[^a-z0-9._:-]+/g, '-').replace(/-+/g, '-');
    s = s.replace(/^-+/, '').replace(/-+$/, '');
    return (s.length > 0) ? s : null;
}

function umhctlCanonicalTargetTag(raw)
{
    var normalized = umhctlNormalizeControlOp(raw);
    if (normalized == null) { return null; }
    switch (normalized)
    {
        case 'proproctor': return 'proproctor';
        case 'ets':
        case 'etssecurebrowser': return 'ets_secure_browser';
        case 'lockdown':
        case 'lockdownbrowser':
        case 'respondus':
        case 'responduslockdownbrowser': return 'lockdown_browser';
        case 'examplify':
        case 'examplifybrowser':
        case 'examsoft':
        case 'examsoftbrowser': return 'examplify_browser';
        case 'onvue':
        case 'onvuebrowser': return 'onvue_browser';
        case 'psi':
        case 'psibridge':
        case 'psibridgesecurebrowser':
        case 'psibridgesecure':
        case 'psibrowser': return 'psi_bridge_secure_browser';
        case 'seb':
        case 'safeexambrowser':
        case 'safeexam': return 'safe_exam_browser';
        case 'proctortrack':
        case 'verificient':
        case 'verificientproctortrack': return 'proctortrack';
        case 'pteb':
        case 'proctortrackexambrowser':
        case 'proctortrackexam': return 'proctortrack_exam_browser';
        case 'hooktesthost':
        case 'hooktest':
        case 'synthetichost':
        case 'synthetichooktarget': return 'hook_test_host';
    }
    return null;
}

function umhctlMakeAdhocTargetTag(raw)
{
    var token = umhctlSanitizeHeaderToken(raw);
    if (token == null) { return null; }
    if (token.indexOf('pid-') == 0) { return token; }
    return 'pid-' + token;
}

function umhctlCanonicalMethodHeaderKey(raw)
{
    if (typeof raw != 'string') { return null; }
    var trimmed = raw.trim();
    if (trimmed.length == 0) { return null; }
    if (umhctlNormalizeControlOp(trimmed) == 'ipcbypass') { return 'ipc-bypass'; }
    var colon = trimmed.indexOf(':');
    if (colon > 0) { trimmed = trimmed.substring(0, colon); }
    var token = umhctlSanitizeHeaderToken(trimmed);
    if (token == null) { return null; }
    if (token == 'default') { return 'auto'; }
    return token;
}

function umhctlNormalizeHeaderMap(headers)
{
    var normalized = {};
    if (headers == null || typeof headers != 'object') { return normalized; }
    for (var k in headers)
    {
        if (typeof k != 'string') { continue; }
        var name = k.trim().toLowerCase();
        if (name.length == 0) { continue; }
        normalized[name] = headers[k];
    }
    return normalized;
}

function umhctlNormalizeRequiredHeaderList(flowContract)
{
    var list = {};
    var ordered = [];
    var headers = null;
    if (flowContract != null && flowContract.requiredHeaders instanceof Array) { headers = flowContract.requiredHeaders; }
    if (!(headers instanceof Array)) { headers = umhctlDefaultFlowContract.requiredHeaders; }
    for (var i = 0; i < headers.length; ++i)
    {
        if (typeof headers[i] != 'string') { continue; }
        var name = headers[i].trim().toLowerCase();
        if (name.length == 0 || list[name] === 1) { continue; }
        list[name] = 1;
        ordered.push(name);
    }
    return ordered;
}

function umhctlHasHeaderValue(headers, name)
{
    if (headers == null || typeof headers != 'object' || typeof name != 'string') { return false; }
    var value = headers[name];
    if (typeof value == 'string') { return value.trim().length > 0; }
    return (value != null);
}

function umhctlCopyHeaderIfMissing(headers, source, name)
{
    if (umhctlHasHeaderValue(headers, name) || source == null || typeof source != 'object') { return; }
    if (!umhctlHasHeaderValue(source, name)) { return; }
    headers[name] = source[name];
}

function umhctlDeriveTargetTag(controlReq, opKey, existingHeaders, flowContext)
{
    if (existingHeaders != null && typeof existingHeaders['x-umh-target-tag'] == 'string' && existingHeaders['x-umh-target-tag'].trim().length > 0)
    {
        return existingHeaders['x-umh-target-tag'].trim();
    }
    if (umhctlRuntimeControlOps[opKey] === 1) { return 'runtime'; }
    if (opKey == 'ipcbypass' && umhctlCanonicalAction(controlReq != null ? controlReq.op : null, controlReq != null ? controlReq.action : null) == 'list-targets') { return 'runtime'; }
    if (typeof controlReq.target_tag == 'string' && controlReq.target_tag.trim().length > 0)
    {
        var explicitCanonical = umhctlCanonicalTargetTag(controlReq.target_tag);
        if (explicitCanonical != null) { return explicitCanonical; }
        var explicitAdhoc = umhctlMakeAdhocTargetTag(controlReq.target_tag);
        if (explicitAdhoc != null) { return explicitAdhoc; }
        return controlReq.target_tag.trim();
    }
    if (typeof controlReq.target == 'string' && controlReq.target.trim().length > 0)
    {
        var targetCanonical = umhctlCanonicalTargetTag(controlReq.target);
        if (targetCanonical != null) { return targetCanonical; }
        var targetAdhoc = umhctlMakeAdhocTargetTag(controlReq.target);
        if (targetAdhoc != null) { return targetAdhoc; }
    }
    if (typeof controlReq.exe == 'string' && controlReq.exe.trim().length > 0)
    {
        var exeCanonical = umhctlCanonicalTargetTag(controlReq.exe);
        if (exeCanonical != null) { return exeCanonical; }
        var exeAdhoc = umhctlMakeAdhocTargetTag(controlReq.exe);
        if (exeAdhoc != null) { return exeAdhoc; }
    }
    if (typeof controlReq.name == 'string' && controlReq.name.trim().length > 0)
    {
        var nameAdhoc = umhctlMakeAdhocTargetTag(controlReq.name);
        if (nameAdhoc != null) { return nameAdhoc; }
    }
    if (typeof controlReq.processName == 'string' && controlReq.processName.trim().length > 0)
    {
        var processCanonical = umhctlCanonicalTargetTag(controlReq.processName);
        if (processCanonical != null) { return processCanonical; }
        var processAdhoc = umhctlMakeAdhocTargetTag(controlReq.processName);
        if (processAdhoc != null) { return processAdhoc; }
    }
    if (typeof controlReq.serviceName == 'string' && controlReq.serviceName.trim().length > 0)
    {
        var serviceAdhoc = umhctlMakeAdhocTargetTag(controlReq.serviceName);
        if (serviceAdhoc != null) { return serviceAdhoc; }
    }
    if (typeof controlReq.taskName == 'string' && controlReq.taskName.trim().length > 0)
    {
        var taskAdhoc = umhctlMakeAdhocTargetTag(controlReq.taskName);
        if (taskAdhoc != null) { return taskAdhoc; }
    }
    if (typeof controlReq.pid == 'number' && controlReq.pid > 0) { return 'pid-' + controlReq.pid; }
    if (opKey == 'lockdownbypass') { return 'lockdown_browser'; }
    if (opKey == 'examsoftbypass') { return 'examplify_browser'; }
    if (flowContext != null && typeof flowContext['x-umh-target-tag'] == 'string' && flowContext['x-umh-target-tag'].trim().length > 0)
    {
        return flowContext['x-umh-target-tag'].trim();
    }
    return 'pid-' + (umhctlSanitizeHeaderToken(opKey) || 'runtime');
}

function umhctlDeriveMethodKey(controlReq, opKey, existingHeaders, flowContext)
{
    if (existingHeaders != null && typeof existingHeaders['x-umh-method-key'] == 'string' && existingHeaders['x-umh-method-key'].trim().length > 0)
    {
        return existingHeaders['x-umh-method-key'].trim();
    }
    if (typeof controlReq.methodKey == 'string' && controlReq.methodKey.trim().length > 0) { return controlReq.methodKey.trim(); }
    if (opKey == 'ipcbypass') { return 'ipc-bypass'; }
    if (umhctlRuntimeControlOps[opKey] === 1) { return 'runtime-control'; }
    if (typeof controlReq.method == 'string' && controlReq.method.trim().length > 0)
    {
        var methodToken = umhctlCanonicalMethodHeaderKey(controlReq.method);
        if (methodToken != null) { return methodToken; }
    }
    if (flowContext != null && typeof flowContext['x-umh-method-key'] == 'string' && flowContext['x-umh-method-key'].trim().length > 0)
    {
        return flowContext['x-umh-method-key'].trim();
    }
    return 'auto';
}

function umhctlMethodKeyIsAutoOrDefault(methodKey)
{
    if (typeof methodKey != 'string') { return true; }
    var normalized = umhctlSanitizeHeaderToken(methodKey);
    return (normalized == null || normalized == 'auto' || normalized == 'default');
}

function umhctlValidateExactInjectionHeaders(opName, headers)
{
    var targetTag = (headers != null && typeof headers['x-umh-target-tag'] == 'string') ? headers['x-umh-target-tag'].trim() : '';
    var methodKey = (headers != null && typeof headers['x-umh-method-key'] == 'string') ? headers['x-umh-method-key'].trim() : '';
    if (targetTag.length == 0 || umhctlCanonicalTargetTag(targetTag) == null)
    {
        return { ok: false, error: 'umhctl ' + opName + ' requires an explicit report-backed --target-tag; pid/ad-hoc target routing is not valid under the control contract.' };
    }
    if (umhctlMethodKeyIsAutoOrDefault(methodKey))
    {
        return { ok: false, error: 'umhctl ' + opName + ' requires an explicit exact --method-key; auto/default is not valid for direct injection control.' };
    }
    return { ok: true };
}

function umhctlResolveControlHeaders(controlReq, sessionid)
{
    var opKey = umhctlNormalizeControlOp(controlReq != null ? controlReq.op : null);
    if (opKey == null || !umhctlIsStateChangingRequest(controlReq))
    {
        return { ok: true, headers: (controlReq != null && typeof controlReq.headers == 'object') ? umhctlNormalizeHeaderMap(controlReq.headers) : null };
    }

    var flowContract = umhctlGetFlowContract();
    var flowContext = umhctlNormalizeHeaderMap(umhctlGetFlowContext(sessionid));
    var headers = (controlReq != null && typeof controlReq.headers == 'object' && controlReq.headers != null) ? umhctlNormalizeHeaderMap(controlReq.headers) : {};
    var scopedFlow = (umhctlFlowScopedOps[opKey] === 1);
    var injectOp = (opKey == 'inject');
    var requiredHeaders = umhctlNormalizeRequiredHeaderList(flowContract);

    if (typeof headers['x-umh-contract-version'] != 'string' || headers['x-umh-contract-version'].trim().length == 0)
    {
        headers['x-umh-contract-version'] = flowContract.contractVersion || umhctlDefaultFlowContract.contractVersion;
    }
    if (typeof headers['x-umh-flow-profile'] != 'string' || headers['x-umh-flow-profile'].trim().length == 0)
    {
        headers['x-umh-flow-profile'] = flowContract.flowProfile || umhctlDefaultFlowContract.flowProfile;
    }
    if (typeof headers['x-umh-client'] != 'string' || headers['x-umh-client'].trim().length == 0)
    {
        if (flowContext != null && scopedFlow && typeof flowContext['x-umh-client'] == 'string' && flowContext['x-umh-client'].trim().length > 0)
        {
            headers['x-umh-client'] = flowContext['x-umh-client'].trim();
        }
        else
        {
            headers['x-umh-client'] = umhctlDefaultClientId;
        }
    }

    if (opKey == 'injecttargetset')
    {
        if (typeof headers['x-umh-run-id'] != 'string' || headers['x-umh-run-id'].trim().length == 0) { headers['x-umh-run-id'] = umhctlBuildRunId(); }
        if (typeof headers['x-umh-target-tag'] != 'string' || headers['x-umh-target-tag'].trim().length == 0) { headers['x-umh-target-tag'] = umhctlDeriveTargetTag(controlReq, opKey, headers, flowContext); }
        if (typeof headers['x-umh-method-key'] != 'string' || headers['x-umh-method-key'].trim().length == 0) { headers['x-umh-method-key'] = umhctlDeriveMethodKey(controlReq, opKey, headers, flowContext); }
        var injectScopeValidation = umhctlValidateExactInjectionHeaders(controlReq.op, headers);
        if (!injectScopeValidation.ok) { return injectScopeValidation; }
        for (var i = 0; i < requiredHeaders.length; ++i) { umhctlCopyHeaderIfMissing(headers, flowContext, requiredHeaders[i]); }
        var injectScopeMissing = [];
        for (var j = 0; j < requiredHeaders.length; ++j)
        {
            if (!umhctlHasHeaderValue(headers, requiredHeaders[j])) { injectScopeMissing.push(requiredHeaders[j]); }
        }
        if (injectScopeMissing.length > 0)
        {
            return { ok: false, error: 'umhctl ' + controlReq.op + ' is missing required flow header(s): ' + injectScopeMissing.join(', ') + '.' };
        }
        return { ok: true, headers: headers, storeFlowContext: true };
    }

    if (opKey == 'injectall' || opKey == 'cleartargetscope')
    {
        if ((typeof headers['x-umh-run-id'] != 'string' || headers['x-umh-run-id'].trim().length == 0) && flowContext != null) { headers['x-umh-run-id'] = flowContext['x-umh-run-id']; }
        if ((typeof headers['x-umh-target-tag'] != 'string' || headers['x-umh-target-tag'].trim().length == 0) && flowContext != null) { headers['x-umh-target-tag'] = flowContext['x-umh-target-tag']; }
        if ((typeof headers['x-umh-method-key'] != 'string' || headers['x-umh-method-key'].trim().length == 0) && flowContext != null) { headers['x-umh-method-key'] = flowContext['x-umh-method-key']; }
        if (typeof headers['x-umh-run-id'] != 'string' || headers['x-umh-run-id'].trim().length == 0 ||
            typeof headers['x-umh-target-tag'] != 'string' || headers['x-umh-target-tag'].trim().length == 0 ||
            typeof headers['x-umh-method-key'] != 'string' || headers['x-umh-method-key'].trim().length == 0)
        {
            return { ok: false, error: 'umhctl ' + controlReq.op + ' requires an active target scope. Run "umhctl injectTargetSet ..." first or supply matching --run-id/--target-tag/--method-key.' };
        }
        var scopedValidation = umhctlValidateExactInjectionHeaders(controlReq.op, headers);
        if (!scopedValidation.ok) { return scopedValidation; }
        for (var k = 0; k < requiredHeaders.length; ++k) { umhctlCopyHeaderIfMissing(headers, flowContext, requiredHeaders[k]); }
        var scopedMissing = [];
        for (var m = 0; m < requiredHeaders.length; ++m)
        {
            if (!umhctlHasHeaderValue(headers, requiredHeaders[m])) { scopedMissing.push(requiredHeaders[m]); }
        }
        if (scopedMissing.length > 0)
        {
            return { ok: false, error: 'umhctl ' + controlReq.op + ' is missing required flow header(s): ' + scopedMissing.join(', ') + '.' };
        }
        return { ok: true, headers: headers, clearFlowContextOnSuccess: (opKey == 'cleartargetscope') };
    }

    if (typeof headers['x-umh-run-id'] != 'string' || headers['x-umh-run-id'].trim().length == 0)
    {
        if (injectOp && flowContext != null && typeof flowContext['x-umh-run-id'] == 'string' && flowContext['x-umh-run-id'].trim().length > 0)
        {
            headers['x-umh-run-id'] = flowContext['x-umh-run-id'].trim();
        }
        else
        {
            headers['x-umh-run-id'] = umhctlBuildRunId();
        }
    }
    if (typeof headers['x-umh-target-tag'] != 'string' || headers['x-umh-target-tag'].trim().length == 0)
    {
        headers['x-umh-target-tag'] = umhctlDeriveTargetTag(controlReq, opKey, headers, injectOp ? flowContext : null);
    }
    if (typeof headers['x-umh-method-key'] != 'string' || headers['x-umh-method-key'].trim().length == 0)
    {
        headers['x-umh-method-key'] = umhctlDeriveMethodKey(controlReq, opKey, headers, injectOp ? flowContext : null);
    }
    if (injectOp)
    {
        var injectValidation = umhctlValidateExactInjectionHeaders(controlReq.op, headers);
        if (!injectValidation.ok) { return injectValidation; }
    }

    for (var n = 0; n < requiredHeaders.length; ++n) { umhctlCopyHeaderIfMissing(headers, flowContext, requiredHeaders[n]); }
    var missingHeaders = [];
    for (var p = 0; p < requiredHeaders.length; ++p)
    {
        if (!umhctlHasHeaderValue(headers, requiredHeaders[p])) { missingHeaders.push(requiredHeaders[p]); }
    }
    if (missingHeaders.length > 0)
    {
        return { ok: false, error: 'umhctl ' + controlReq.op + ' is missing required flow header(s): ' + missingHeaders.join(', ') + '.' };
    }
    return { ok: true, headers: headers };
}

function umhctlGetControlToken()
{
    try
    {
        if (typeof process == 'object' && process != null && process.env != null)
        {
            var tok = process.env.HOOKDLL_TELEMETRY_TOKEN;
            if (tok != null)
            {
                tok = ('' + tok).trim();
                if (tok.length > 0) { return tok; }
            }
        }
    } catch (e) { }

    if (process.platform == 'win32')
    {
        try
        {
            var reg = require('win-registry');
            var regPath = 'Software\\UserModeHook\\Flags';
            var tokHklm = reg.QueryKey(reg.HKEY.LocalMachine, regPath, 'HOOKDLL_TELEMETRY_TOKEN');
            if (tokHklm != null)
            {
                tokHklm = ('' + tokHklm).trim();
                if (tokHklm.length > 0) { return tokHklm; }
            }
        } catch (e) { }
        try
        {
            var reg2 = require('win-registry');
            var regPath2 = 'Software\\UserModeHook\\Flags';
            var tokHkcu = reg2.QueryKey(reg2.HKEY.CurrentUser, regPath2, 'HOOKDLL_TELEMETRY_TOKEN');
            if (tokHkcu != null)
            {
                tokHkcu = ('' + tokHkcu).trim();
                if (tokHkcu.length > 0) { return tokHkcu; }
            }
        } catch (e) { }
    }
    return null;
}

function umhctlNormalizeDigest(v)
{
    if (typeof v != 'string') { return null; }
    var d = v.toLowerCase().replace(/[^0-9a-f]/g, '');
    if (d.length != 96) { return null; }
    return d;
}

function umhctlComputeFileHashSync(filePath)
{
    try
    {
        var data = fs.readFileSync(filePath);
        var hash = require('SHA384Stream');
        if (hash != null && typeof hash.hashData == 'function') { return hash.hashData(data).toString('hex').toLowerCase(); }
        // Fallback: use built-in SHA384 if available via agent crypto
        var h2 = require('MeshAgent').SHA384;
        if (typeof h2 == 'function') { return h2(data).toString('hex').toLowerCase(); }
    } catch (e) { }
    return null;
}

function umhctlGetServerPinnedDigest()
{
    try
    {
        var info = require('MeshAgent').ServerInfo;
        if (info != null && typeof info == 'object' && typeof info.ServerID == 'string')
        {
            var d = umhctlNormalizeDigest(info.ServerID);
            if (d != null) { return d; }
        }
    } catch (e) { }
    return null;
}

function umhctlBuildPinnedCertVerifier(expectedDigest)
{
    var pin = umhctlNormalizeDigest(expectedDigest);
    if (pin == null) { return null; }

    return function ()
    {
        var certs = null;
        if (arguments.length > 1 && arguments[1] != null && typeof arguments[1] == 'object')
        {
            certs = arguments[1];
        }
        else if (arguments.length > 0 && arguments[0] != null && typeof arguments[0] == 'object')
        {
            certs = arguments[0];
        }
        var candidates = [];
        try
        {
            if (certs != null && typeof certs == 'object')
            {
                if ((typeof certs.digest == 'string') || (typeof certs.fingerprint == 'string')) { candidates.push(certs); }
                for (var k in certs)
                {
                    var certNode = certs[k];
                    if (certNode != null && typeof certNode == 'object')
                    {
                        if ((typeof certNode.digest == 'string') || (typeof certNode.fingerprint == 'string')) { candidates.push(certNode); }
                    }
                }
            }
            if (candidates.length == 0) { throw 'No certificate candidates provided'; }
            for (var i = 0; i < candidates.length; ++i)
            {
                var cert = candidates[i];
                if (cert == null || typeof cert != 'object') { continue; }
                var digest = umhctlNormalizeDigest(cert.digest);
                if (digest == pin) { return; }
                var fp = umhctlNormalizeDigest(cert.fingerprint);
                if (fp == pin) { return; }
            }
        } catch (e) { }
        throw 'Invalid server certificate';
    };
}

function umhctlFormatHostForUrl(host)
{
    if (typeof host != 'string') { return null; }
    var h = host.trim();
    if (h.length == 0) { return null; }
    if (h.indexOf(':') >= 0 && h.charAt(0) != '[' && h.charAt(h.length - 1) != ']') { h = '[' + h + ']'; }
    return h;
}

function umhctlGetEnvValue(name)
{
    try
    {
        if (typeof process == 'object' && process != null && process.env != null)
        {
            var v = process.env[name];
            if (v != null)
            {
                v = ('' + v).trim();
                if (v.length > 0) { return v; }
            }
        }
    } catch (e) { }
    return null;
}

function umhctlBuildServerUrlBase(parsed, defaultProtocol)
{
    if (parsed == null || typeof parsed != 'object') { return null; }
    var protocol = defaultProtocol || 'https';
    if (typeof parsed.protocol == 'string' && parsed.protocol.length > 0) { protocol = parsed.protocol.split(':').join(''); }
    var host = umhctlFormatHostForUrl(parsed.host);
    if (host == null) { return null; }
    var port = '';
    if (parsed.port != null) { port = ('' + parsed.port).trim(); }
    if (port.length > 0 && port != '0' && port != '80' && port != '443') { return protocol + '://' + host + ':' + port; }
    return protocol + '://' + host;
}

function umhctlNormalizeExecutablePath(raw)
{
    if (typeof raw != 'string') { return null; }
    var s = raw.trim();
    if (s.length == 0) { return null; }
    var lower = s.toLowerCase();
    var exeIndex = lower.indexOf('.exe');
    if (exeIndex >= 0) { s = s.substring(0, exeIndex + 4); }
    s = s.trim();
    if (s.charAt(0) == '"' && s.charAt(s.length - 1) == '"') { s = s.substring(1, s.length - 1); }
    return (s.length > 0) ? s : null;
}

function umhctlBuildExecFileArgs(exePath, args)
{
    var argv = [];
    if (!Array.isArray(args)) { return argv; }
    for (var i = 0; i < args.length; ++i) { argv.push('' + args[i]); }
    return argv;
}

function umhctlAttachProcessCompletion(proc, handler)
{
    if (proc == null) { throw new Error('child process handle is required'); }
    if (typeof handler != 'function') { throw new Error('child process completion handler is required'); }
    var subscribe = null;
    if (typeof proc.once == 'function')
    {
        subscribe = function (eventName, callback) { proc.once(eventName, callback); };
    }
    else if (typeof proc.on == 'function')
    {
        subscribe = function (eventName, callback) { proc.on(eventName, callback); };
    }
    else
    {
        throw new Error('child process does not support event subscription');
    }
    var attached = [];
    var completed = false;
    var exitFallback = null;
    var complete = function (code, signal)
    {
        if (completed) { return; }
        completed = true;
        if (exitFallback != null)
        {
            try { clearTimeout(exitFallback); } catch (e) { }
            exitFallback = null;
        }
        handler.call(proc, code, signal);
    };
    var hasClose = false;
    try
    {
        subscribe('close', complete);
        attached.push('close');
        hasClose = true;
    }
    catch (e) { }
    try
    {
        subscribe('exit', function (code, signal) {
            if (!hasClose)
            {
                complete(code, signal);
                return;
            }
            if (exitFallback == null)
            {
                exitFallback = setTimeout(function () { complete(code, signal); }, 1000);
            }
        });
        attached.push('exit');
    }
    catch (e) { }
    if (attached.length == 0) { throw new Error('child process completion events are unavailable'); }
    return attached.join(',');
}

function umhctlGetMasterServiceCandidateNames()
{
    // SSOT: meshcore/config/umh_defines.h — keep in sync with MESHAGENT_MASTER_SERVICE_SERVICE_NAME
    return ['AdvancedHookService', 'MasterService'];
}

function umhctlGetWindowsServiceImagePath(serviceName)
{
    if (process.platform != 'win32' || typeof serviceName != 'string' || serviceName.length == 0) { return null; }
    try
    {
        var registry = require('win-registry');
        var raw = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + serviceName, 'ImagePath');
        return umhctlNormalizeExecutablePath(raw);
    } catch (e) { }
    return null;
}

function umhctlGetPreferredManagedMasterServicePaths(agentDir)
{
    var list = [];
    var seen = {};
    var pushPath = function (raw)
    {
        var normalized = umhctlNormalizeExecutablePath(raw);
        if (normalized == null) { return; }
        var key = normalized.toLowerCase();
        if (seen[key]) { return; }
        seen[key] = true;
        list.push(normalized);
    };

    var explicitPath = umhctlGetEnvValue('UMH_MASTERSERVICE_EXE');
    if (explicitPath != null) { pushPath(explicitPath); }

    var programData = umhctlGetEnvValue('ProgramData');
    if (programData != null)
    {
        // SSOT: meshservice/stealth_defaults.h STEALTH_FALLBACK_SERVICE_NAME
        pushPath(programData + '\\' + (process.env['MESH_SERVICE_NAME'] || 'MeshAgent') + '\\MasterService.exe');
        pushPath(programData + '\\UserModeHook\\MasterService.exe');
    }
    if (typeof agentDir == 'string' && agentDir.length > 0) { pushPath(agentDir + '/MasterService.exe'); }
    return list;
}

function umhctlNormalizeComparePath(path)
{
    var normalized = umhctlNormalizeExecutablePath(path);
    if (normalized == null) { return null; }
    return normalized.split('\\').join('/').toLowerCase();
}

function umhctlIsManagedMasterServicePath(filePath, agentDir)
{
    var normalizedFile = umhctlNormalizeComparePath(filePath);
    if (normalizedFile == null) { return false; }
    if (normalizedFile.substring(normalizedFile.length - 18) != '/masterservice.exe') { return false; }

    var roots = [];
    var programData = umhctlGetEnvValue('ProgramData');
    if (programData != null)
    {
        // Service install root — uses env override or generic fallback
        roots.push(programData + '\\' + (process.env['MESH_SERVICE_NAME'] || 'MeshAgent'));
        roots.push(programData + '\\UserModeHook');
    }
    if (typeof agentDir == 'string' && agentDir.length > 0) { roots.push(agentDir); }

    for (var i = 0; i < roots.length; ++i)
    {
        var normalizedRoot = umhctlNormalizeComparePath(roots[i]);
        if (normalizedRoot == null) { continue; }
        if (normalizedFile == normalizedRoot + '/masterservice.exe') { return true; }
        if (normalizedFile.indexOf(normalizedRoot + '/') == 0) { return true; }
    }
    return false;
}

function umhctlResolveMasterServicePaths(agentDir)
{
    var preferred = umhctlGetPreferredManagedMasterServicePaths(agentDir);
    var fallbacks = [];
    var fallbackSeen = {};
    var pushFallback = function (raw)
    {
        var normalized = umhctlNormalizeExecutablePath(raw);
        if (normalized == null) { return; }
        var key = normalized.toLowerCase();
        if (fallbackSeen[key]) { return; }
        fallbackSeen[key] = true;
        fallbacks.push(normalized);
    };
    if (process.platform == 'win32')
    {
        var names = umhctlGetMasterServiceCandidateNames();
        for (var i = 0; i < names.length; ++i)
        {
            var imagePath = umhctlGetWindowsServiceImagePath(names[i]);
            if (imagePath == null) { continue; }
            if (umhctlIsManagedMasterServicePath(imagePath, agentDir))
            {
                preferred.push(imagePath);
            }
            else
            {
                pushFallback(imagePath);
            }
        }
    }

    var selected = null;
    for (var j = 0; j < preferred.length; ++j)
    {
        var preferredCandidate = umhctlNormalizeExecutablePath(preferred[j]);
        if (preferredCandidate == null) { continue; }
        if (selected == null) { selected = preferredCandidate; }
        try { if (fs.existsSync(preferredCandidate)) { selected = preferredCandidate; break; } } catch (e) { }
    }

    if (selected == null)
    {
        for (var k = 0; k < fallbacks.length; ++k)
        {
            var fallbackCandidate = umhctlNormalizeExecutablePath(fallbacks[k]);
            if (fallbackCandidate == null) { continue; }
            if (selected == null) { selected = fallbackCandidate; }
            try { if (fs.existsSync(fallbackCandidate)) { selected = fallbackCandidate; break; } } catch (e) { }
        }
    }

    if (selected == null)
    {
        selected = (typeof agentDir == 'string' && agentDir.length > 0) ? (agentDir + '/MasterService.exe') : 'MasterService.exe';
    }
    return { exePath: selected, tmpPath: selected + '.download', bakPath: selected + '.bak' };
}

function umhctlGetDefaultDownloadUrl()
{
    var explicitUrl = umhctlGetEnvValue('UMH_MASTERSERVICE_URL');
    if (explicitUrl != null) { return explicitUrl; }

    var serverUrl = require('MeshAgent').ServerUrl;
    if (serverUrl)
    {
        var parsed = http.parseUri(serverUrl);
        if (parsed && parsed.host)
        {
            var urlBase = umhctlBuildServerUrlBase(parsed, 'https');
            if (urlBase != null)
            {
                var pathOverride = umhctlGetEnvValue('UMH_MASTERSERVICE_PATH');
                if (pathOverride != null)
                {
                    if (pathOverride.charAt(0) != '/') { pathOverride = '/' + pathOverride; }
                    return urlBase + pathOverride;
                }

                var userfilesOwner = umhctlGetEnvValue('UMH_USERFILES_USER');
                if (userfilesOwner != null)
                {
                    return urlBase + '/userfiles/' + encodeURIComponent(userfilesOwner) + '/MasterService.exe?download=1';
                }
            }
        }
    }
    return null;
}

function umhctlFormatLifecycleElapsed(ms)
{
    if (typeof ms != 'number' || ms < 0) { return null; }
    if (ms < 1000) { return ms + 'ms'; }
    if (ms < 60000) { return (Math.floor(ms / 100) / 10) + 's'; }
    var seconds = Math.floor(ms / 1000);
    var minutes = Math.floor(seconds / 60);
    seconds = seconds % 60;
    return minutes + 'm ' + seconds + 's';
}

function umhctlSetLifecyclePhase(op, phase)
{
    if (umhctlLifecycleState == null) { return; }
    if (op != null && umhctlLifecycleState.op !== op) { return; }
    umhctlLifecycleState.phase = phase;
    umhctlLifecycleState.phaseUpdated = Date.now();
}

function umhctlBeginLifecycle(op, sessionid)
{
    // Atomic check-and-set: set lock token immediately before any async work
    if (umhctlLifecycleOp != null || (umhctlLifecycleState != null && umhctlLifecycleState.op != null))
    {
        var activeOp = (umhctlLifecycleState != null ? umhctlLifecycleState.op : umhctlLifecycleOp) || 'unknown';
        var msg = 'umhctl: lifecycle operation already running: ' + activeOp;
        if (umhctlLifecycleState != null && typeof umhctlLifecycleState.phase == 'string' && umhctlLifecycleState.phase.length > 0) { msg += ' (' + umhctlLifecycleState.phase + ')'; }
        if (umhctlLifecycleState != null) {
            var elapsed = umhctlFormatLifecycleElapsed(Date.now() - umhctlLifecycleState.startedAt);
            if (elapsed != null) { msg += ', elapsed ' + elapsed; }
        }
        msg += '. Wait for completion.';
        sendConsoleText(msg, sessionid);
        return false;
    }
    // Set lock token first to prevent re-entry from rapid successive calls
    umhctlLifecycleOp = op;
    umhctlLifecycleState = { op: op, sessionid: sessionid, startedAt: Date.now(), phase: 'starting', phaseUpdated: Date.now() };
    return true;
}

function umhctlEndLifecycle(op)
{
    if (umhctlLifecycleState != null)
    {
        if (op == null || umhctlLifecycleState.op === op)
        {
            umhctlLifecycleState = null;
            umhctlLifecycleOp = null;
        }
        return;
    }
    if (op == null || umhctlLifecycleOp === op) { umhctlLifecycleOp = null; }
}

function umhctlEnsureDirectoryPath(dirPath, depth)
{
    if (typeof depth != 'number') { depth = 0; }
    if (depth > 20) { return false; } // Prevent unbounded recursion
    if (typeof dirPath != 'string' || dirPath.length == 0) { return false; }
    try { if (fs.existsSync(dirPath)) { return true; } } catch (e) { }
    var parent = dirPath.replace(/[/\\][^/\\]+$/, '');
    if (parent && parent != dirPath)
    {
        if (!umhctlEnsureDirectoryPath(parent, depth + 1)) { return false; }
    }
    try { fs.mkdirSync(dirPath); } catch (e) { }
    try { return fs.existsSync(dirPath); } catch (e) { }
    return false;
}

function umhctlEnsureParentDirectory(filePath)
{
    var normalized = umhctlNormalizeExecutablePath(filePath);
    if (normalized == null) { return false; }
    var dirPath = normalized.replace(/[/\\][^/\\]+$/, '');
    return umhctlEnsureDirectoryPath(dirPath);
}

function umhctlListProcessesByPath(binaryPath, callback)
{
    if (typeof callback != 'function') { callback = function () { }; }
    var normalizedTarget = umhctlNormalizeComparePath(binaryPath);
    if (normalizedTarget == null) { callback([]); return; }

    var processManager = null;
    try { processManager = require('process-manager'); } catch (e) { processManager = null; }
    if (processManager == null || typeof processManager.enumerateProcesses != 'function') { callback([]); return; }

    var enumeration = null;
    try { enumeration = processManager.enumerateProcesses(); } catch (e) { enumeration = null; }
    if (enumeration == null || typeof enumeration.then != 'function') { callback([]); return; }

    enumeration.then(function (proc) {
        var matches = [];
        for (var key in proc)
        {
            var entry = proc[key];
            if (entry == null || typeof entry != 'object') { continue; }
            var entryPath = umhctlNormalizeComparePath(entry.path);
            if (entryPath == null || entryPath != normalizedTarget) { continue; }
            matches.push({ pid: entry.pid, path: entry.path });
        }
        callback(matches);
    }, function () { callback([]); });
}

function umhctlWaitForServiceStopAndProcessExit(sessionid, binaryPath, timeoutMs, callback)
{
    if (typeof callback != 'function') { callback = function () { }; }
    if (process.platform != 'win32')
    {
        callback(true, umhctlQueryMasterServiceWindowsState(), []);
        return;
    }
    if (typeof timeoutMs != 'number' || timeoutMs < 1000) { timeoutMs = 30000; }

    var settled = false;
    var waitLogged = false;
    var deadline = Date.now() + timeoutMs;
    var normalizedTarget = umhctlNormalizeComparePath(binaryPath);
    var finish = function (ok, state, matches)
    {
        if (settled) { return; }
        settled = true;
        callback(ok === true, state, matches || []);
    };
    var poll = function ()
    {
        var currentState = umhctlQueryMasterServiceWindowsState();
        umhctlListProcessesByPath(binaryPath, function (matches) {
            if (settled) { return; }
            var runningState = (currentState != null && currentState.installed === true && currentState.running === true);
            var processMatches = [];
            if (matches instanceof Array) { processMatches = matches; }
            if (normalizedTarget == null) { processMatches = []; }
            var processActive = (processMatches.length > 0);
            if (!runningState && !processActive)
            {
                finish(true, currentState, processMatches);
                return;
            }
            if (!waitLogged)
            {
                waitLogged = true;
                var waitMsg = 'umhctl: waiting for service stop to settle';
                if (processActive) { waitMsg += ' (' + processMatches.length + ' process' + ((processMatches.length === 1) ? '' : 'es') + ' still active)'; }
                waitMsg += ' ...';
                sendConsoleText(waitMsg, sessionid);
            }
            if (Date.now() >= deadline)
            {
                finish(false, currentState, processMatches);
                return;
            }
            setTimeout(poll, 250);
        });
    };
    poll();
}

function umhctlFileLooksLikePe(filePath)
{
    var fd = null;
    try
    {
        fd = fs.openSync(filePath, 'rb');
        var hdr = Buffer.alloc(2);
        var bytesRead = fs.readSync(fd, hdr, 0, 2, 0);
        try { fs.closeSync(fd); } catch (ee) { }
        return (bytesRead >= 2 && hdr[0] == 0x4D && hdr[1] == 0x5A);
    } catch (e) {
        try { if (fd != null) { fs.closeSync(fd); } } catch (ee) { }
    }
    return false;
}

function umhctlDeleteManagedMasterServiceBinary(filePath, agentDir, sessionid)
{
    var normalizedPath = umhctlNormalizeExecutablePath(filePath);
    if (normalizedPath == null) { return false; }
    if (!umhctlIsManagedMasterServicePath(normalizedPath, agentDir))
    {
        sendConsoleText('umhctl: preserving external MasterService binary at ' + normalizedPath + '.', sessionid);
        return false;
    }
    try
    {
        if (fs.existsSync(normalizedPath))
        {
            fs.unlinkSync(normalizedPath);
            sendConsoleText('umhctl: removed managed MasterService binary at ' + normalizedPath + '.', sessionid);
            return true;
        }
        return true;
    } catch (e) {
        sendConsoleText('umhctl: unable to remove managed MasterService binary at ' + normalizedPath + ': ' + e.toString(), sessionid);
    }
    return false;
}

function umhctlBuildManagedMasterServiceBinaryCleanupCandidates(paths, agentDir)
{
    var candidates = [];
    var seen = {};
    if (!Array.isArray(paths)) { return candidates; }
    for (var i = 0; i < paths.length; ++i)
    {
        var normalizedPath = umhctlNormalizeExecutablePath(paths[i]);
        if (normalizedPath == null) { continue; }
        if (!umhctlIsManagedMasterServicePath(normalizedPath, agentDir)) { continue; }
        var key = umhctlNormalizeComparePath(normalizedPath);
        if (key == null || seen[key]) { continue; }
        seen[key] = true;
        candidates.push(normalizedPath);
    }
    return candidates;
}

function umhctlCleanupManagedMasterServiceBinaries(paths, agentDir, sessionid)
{
    var candidates = umhctlBuildManagedMasterServiceBinaryCleanupCandidates(paths, agentDir);
    for (var i = 0; i < candidates.length; ++i)
    {
        if (!umhctlDeleteManagedMasterServiceBinary(candidates[i], agentDir, sessionid)) { return false; }
    }
    return true;
}

function umhctlFormatServiceStopBlockerDetail(stopState, activeProcesses)
{
    var detail = [];
    if (stopState != null && stopState.installed === true) { detail.push('service state ' + stopState.state); }
    if (Array.isArray(activeProcesses) && activeProcesses.length > 0) { detail.push(activeProcesses.length + ' process' + ((activeProcesses.length === 1) ? '' : 'es') + ' still active'); }
    return detail.join(', ');
}

function umhctlLooksLikeInteractiveBootstrapOutput(output)
{
    if (typeof output != 'string') { return false; }
    var text = output.toLowerCase();
    if (text.indexOf('interactive launch detected') >= 0) { return true; }
    if (text.indexOf('preparing service install/start') >= 0) { return true; }
    if (text.indexOf('service already installed. attempting to start it') >= 0) { return true; }
    if (text.indexOf('running in the background. you can close this window') >= 0) { return true; }
    return false;
}

function umhctlFormatServiceStateSummary(state)
{
    if (state == null || typeof state != 'object') { return 'service state unavailable'; }
    if (state.installed !== true) { return 'service not installed'; }

    var parts = [];
    if (state.name != null) { parts.push('name=' + state.name); }
    if (state.state != null) { parts.push('state=' + state.state); }
    if (state.running === true) { parts.push('running=true'); }
    else if (state.stopped === true) { parts.push('stopped=true'); }
    if (typeof state.startType == 'string' && state.startType.length > 0) { parts.push('start_type=' + state.startType); }
    if (typeof state.appLocation == 'string' && state.appLocation.length > 0) { parts.push('binary_path=' + state.appLocation); }
    if (typeof state.error == 'string' && state.error.length > 0) { parts.push('error=' + state.error); }
    return parts.length > 0 ? parts.join(', ') : 'service installed';
}

function umhctlQueryMasterServiceWindowsState()
{
    var result = { available: false, installed: false, running: false, stopped: false, state: 'UNKNOWN', name: null, appLocation: null, startType: null, error: null };
    if (process.platform != 'win32') { return result; }

    var manager = null;
    try { manager = require('service-manager').manager; } catch (e) { result.error = e.toString(); return result; }
    if (manager == null || typeof manager.getService != 'function') { result.error = 'service-manager unavailable'; return result; }

    result.available = true;
    var candidates = umhctlGetMasterServiceCandidateNames();
    for (var i = 0; i < candidates.length; ++i)
    {
        var svc = null;
        try { svc = manager.getService(candidates[i]); } catch (e) { svc = null; }
        if (svc == null) { continue; }

        result.installed = true;
        result.name = candidates[i];
        try
        {
            if (svc.status != null && svc.status.state != null) { result.state = '' + svc.status.state; }
        } catch (e) { }
        result.running = (result.state == 'RUNNING' || result.state == 'START_PENDING' || result.state == 'STOP_PENDING');
        result.stopped = (result.state == 'STOPPED');
        try
        {
            if (typeof svc.appLocation == 'function') { result.appLocation = umhctlNormalizeExecutablePath(svc.appLocation()); }
        } catch (e) { }
        try
        {
            var registry = require('win-registry');
            var startValue = registry.QueryKey(registry.HKEY.LocalMachine, 'SYSTEM\\CurrentControlSet\\Services\\' + candidates[i], 'Start');
            if (startValue != null)
            {
                switch (parseInt(startValue))
                {
                    case 2: result.startType = 'Auto'; break;
                    case 3: result.startType = 'Manual'; break;
                    case 4: result.startType = 'Disabled'; break;
                }
            }
        } catch (e) { }
        try { svc.close(); } catch (e) { }
        return result;
    }

    return result;
}

function umhctlPreflightControlService(sessionid)
{
    if (process.platform != 'win32') { return true; }
    var state = umhctlQueryMasterServiceWindowsState();
    if (state == null || state.available !== true) { return true; }
    if (state.installed === true && state.running === true) { return true; }
    sendConsoleText('umhctl: MasterService is not running (' + umhctlFormatServiceStateSummary(state) + '). Run "umhctl install" to repair/start the managed service.', sessionid);
    return false;
}

function umhctlStopMasterServiceWindowsService(sessionid, callback)
{
    if (typeof callback != 'function') { callback = function () { }; }
    if (process.platform != 'win32') { callback(false); return; }

    var manager = null;
    try { manager = require('service-manager').manager; } catch (e) { callback(false); return; }
    if (manager == null || typeof manager.getService != 'function') { callback(false); return; }

    var candidates = umhctlGetMasterServiceCandidateNames();
    var stopTimeoutMs = 30000;
    var finished = false;
    var handledAny = false;
    var stopFailed = false;
    var done = function (handled)
    {
        if (finished) { return; }
        finished = true;
        callback(handled === true);
    };

    var tryService = function (index)
    {
        if (index >= candidates.length) { done(handledAny === true && stopFailed !== true); return; }

        var svc = null;
        try { svc = manager.getService(candidates[index]); } catch (e) { svc = null; }
        if (svc == null) { tryService(index + 1); return; }

        var closeSvc = function () { try { svc.close(); } catch (e) { } };
        var state = 'UNKNOWN';
        try { if (svc.status != null && svc.status.state != null) { state = svc.status.state; } } catch (e) { }
        handledAny = true;

        if (state == 'STOPPED')
        {
            sendConsoleText('umhctl: Windows service ' + candidates[index] + ' is already stopped.', sessionid);
            closeSvc();
            tryService(index + 1);
            return;
        }
        if (state != 'RUNNING' && state != 'STOP_PENDING')
        {
            closeSvc();
            tryService(index + 1);
            return;
        }

        sendConsoleText('umhctl: stopping Windows service ' + candidates[index] + ' ...', sessionid);
        var stopResult = null;
        var stopTimedOut = false;
        var stopTimer = null;
        try { stopResult = svc.stop(); } catch (e) {
            sendConsoleText('umhctl: service stop request failed for ' + candidates[index] + ': ' + e.toString(), sessionid);
            closeSvc();
            stopFailed = true;
            tryService(index + 1);
            return;
        }
        if (stopResult == null || typeof stopResult.then != 'function')
        {
            closeSvc();
            stopFailed = true;
            tryService(index + 1);
            return;
        }

        stopTimer = setTimeout(function ()
        {
            if (stopTimedOut) { return; }
            stopTimedOut = true;
            sendConsoleText('umhctl: service ' + candidates[index] + ' stop timed out after ' + stopTimeoutMs + 'ms', sessionid);
            closeSvc();
            stopFailed = true;
            tryService(index + 1);
        }, stopTimeoutMs);
        stopResult.then(function (result) {
            if (stopTimedOut) { return; }
            stopTimedOut = true;
            if (stopTimer != null) { try { clearTimeout(stopTimer); } catch (e) { } }
            sendConsoleText('umhctl: service ' + candidates[index] + ' stop result: ' + result, sessionid);
            closeSvc();
            tryService(index + 1);
        }, function (err) {
            if (stopTimedOut) { return; }
            stopTimedOut = true;
            if (stopTimer != null) { try { clearTimeout(stopTimer); } catch (e) { } }
            sendConsoleText('umhctl: service ' + candidates[index] + ' stop failed: ' + err, sessionid);
            closeSvc();
            stopFailed = true;
            tryService(index + 1);
        });
    };

    tryService(0);
}

function umhctlForceRemoveMasterServiceWindowsService(sessionid, agentDir, fallbackBinaryPath, callback)
{
    if (typeof fallbackBinaryPath == 'function') { callback = fallbackBinaryPath; fallbackBinaryPath = null; }
    if (typeof callback != 'function') { callback = function () { }; }
    if (process.platform != 'win32') { callback(false); return; }

    var manager = null;
    try { manager = require('service-manager').manager; } catch (e) {
        sendConsoleText('umhctl: service-manager unavailable for force-remove: ' + e.toString(), sessionid);
        callback(false);
        return;
    }
    if (manager == null || typeof manager.uninstallService != 'function')
    {
        sendConsoleText('umhctl: service-manager uninstall support is unavailable.', sessionid);
        callback(false);
        return;
    }

    var currentState = umhctlQueryMasterServiceWindowsState();
    if (currentState.installed !== true)
    {
        if (!umhctlCleanupManagedMasterServiceBinaries([currentState.appLocation, fallbackBinaryPath], agentDir, sessionid))
        {
            callback(false);
            return;
        }
        callback(true);
        return;
    }

    var serviceName = currentState.name;
    var binaryPath = currentState.appLocation;
    if (binaryPath == null && typeof serviceName == 'string') { binaryPath = umhctlGetWindowsServiceImagePath(serviceName); }
    if (typeof serviceName != 'string' || serviceName.length == 0)
    {
        sendConsoleText('umhctl: unable to determine installed MasterService name for force-remove.', sessionid);
        callback(false);
        return;
    }

    var doUninstall = function ()
    {
        try
        {
            manager.uninstallService(serviceName, { skipDeleteBinary: true });
            sendConsoleText('umhctl: removed Windows service registration for ' + serviceName + '.', sessionid);
        } catch (e) {
            sendConsoleText('umhctl: force-remove failed for ' + serviceName + ': ' + e.toString(), sessionid);
            callback(false);
            return;
        }

        if (!umhctlCleanupManagedMasterServiceBinaries([binaryPath, fallbackBinaryPath], agentDir, sessionid))
        {
            callback(false);
            return;
        }
        var finalState = umhctlQueryMasterServiceWindowsState();
        if (finalState.installed === true)
        {
            sendConsoleText('umhctl: force-remove verification failed, service still present in state ' + finalState.state + '.', sessionid);
            callback(false);
            return;
        }
        callback(true);
    };

    umhctlStopMasterServiceWindowsService(sessionid, function () { doUninstall(); });
}

function umhctlIsPipeTransportError(err)
{
    if (err == null) { return false; }
    var msg = ('' + err).toLowerCase();
    if (msg.indexOf('named pipe') >= 0) { return true; }
    if (msg.indexOf('\\\\.\\pipe') >= 0) { return true; }
    if (msg.indexOf('control pipe closed without response') >= 0) { return true; }
    if (msg.indexOf('timeout waiting for control response') >= 0) { return true; }
    return ((msg.indexOf('enoent') >= 0) && (msg.indexOf('pipe') >= 0));
}

function umhctlSendControlRequest(requestObj, sessionid, options)
{
    if (requestObj == null || typeof requestObj != 'object')
    {
        sendConsoleText('umhctl: invalid control request object', sessionid);
        return;
    }
    var quiet = false;
    var suppressRequestLog = false;
    var callback = null;
    if (typeof options == 'function')
    {
        callback = options;
    }
    else if (options != null && typeof options == 'object')
    {
        quiet = (options.quiet === true);
        suppressRequestLog = (options.suppressRequestLog === true);
        if (typeof options.callback == 'function') { callback = options.callback; }
    }
    if (requestObj.token == null)
    {
        var token = umhctlGetControlToken();
        if (token != null) { requestObj.token = token; }
    }
    var requestJson = null;
    try { requestJson = JSON.stringify(requestObj); } catch (e) { }
    if (typeof requestJson != 'string' || requestJson.length == 0)
    {
        sendConsoleText('umhctl: failed to serialize control request', sessionid);
        return;
    }
    if (requestJson.length > umhctlRequestSizeLimit)
    {
        sendConsoleText('umhctl: control request too large (' + requestJson.length + ' bytes)', sessionid);
        return;
    }

    var logJson = requestJson;
    try
    {
        var logObj = JSON.parse(requestJson);
        if (logObj != null && typeof logObj == 'object' && logObj.token != null)
        {
            logObj.token = '[redacted]';
            logJson = JSON.stringify(logObj);
        }
    } catch (e) { }

    var response = '';
    var done = false;
    var client = null;
    var timer = null;
    var parseControlPayload = function (payload)
    {
        var result = { text: '', parsed: null };
        var out = (payload == null) ? '' : ('' + payload).split('\u0000').join('').trim();
        result.text = out;
        if (out.length == 0) { return result; }
        try
        {
            result.parsed = JSON.parse(out);
            return result;
        }
        catch (e) { }

        var objStart = out.indexOf('{');
        var objEnd = out.lastIndexOf('}');
        if (objStart >= 0 && objEnd > objStart)
        {
            var objText = out.substring(objStart, objEnd + 1).trim();
            try
            {
                result.parsed = JSON.parse(objText);
                result.text = objText;
                return result;
            }
            catch (e) { }
        }

        var lines = out.split('\n');
        for (var i = 0; i < lines.length; ++i)
        {
            var line = lines[i].trim();
            if (line.length == 0) { continue; }
            try
            {
                result.parsed = JSON.parse(line);
                result.text = line;
                return result;
            }
            catch (e) { }
        }
        return result;
    };

    var finish = function (err, payload)
    {
        if (done) { return; }
        done = true;
        if (timer != null) { try { clearTimeout(timer); } catch (e) { } timer = null; }
        if (client != null) { try { client.removeAllListeners(); } catch (e) { } try { client.destroy(); } catch (e) { } }
        if (err != null && umhctlIsPipeTransportError(err)) { umhctlResetFlowState(); }

        var parsedResult = parseControlPayload(payload);
        if (parsedResult.parsed != null) { umhctlMaybeCacheFlowContract(parsedResult.parsed); }
        if (callback != null)
        {
            try { callback(err, parsedResult.parsed, parsedResult.text); } catch (e) { }
        }

        if (err != null)
        {
            if (quiet) { return; }
            sendConsoleText('umhctl: control request failed: ' + err, sessionid);
            return;
        }

        if (quiet) { return; }

        var out = parsedResult.text;
        if (out.length == 0)
        {
            sendConsoleText('umhctl: empty control response', sessionid);
            return;
        }

        if (parsedResult.parsed != null)
        {
            sendConsoleText('umhctl response:\r\n' + JSON.stringify(parsedResult.parsed, null, 2), sessionid);
            return;
        }
        sendConsoleText('umhctl response (raw):\r\n' + out, sessionid);
    };

    if (!suppressRequestLog) { sendConsoleText('umhctl: control request -> ' + logJson, sessionid); }

    try
    {
        client = net.createConnection({ path: umhControlPipePath });
        client.on('connect', function ()
        {
            try { this.write(requestJson + '\n'); } catch (e) { finish(e.toString(), null); }
        });
        client.on('data', function (chunk)
        {
            if (done) { return; }
            var chunkStr = chunk.toString();
            if (response.length + chunkStr.length > umhctlResponseSizeLimit)
            {
                finish('control response exceeded size limit (' + umhctlResponseSizeLimit + ' bytes)', null);
                return;
            }
            response += chunkStr;
            var trimmed = response.trim();
            if (trimmed.length > 0)
            {
                try { JSON.parse(trimmed); finish(null, trimmed); return; } catch (e) { }

                var nl = response.indexOf('\n');
                if (nl >= 0)
                {
                    var line = response.substring(0, nl).trim();
                    if (line.length > 0)
                    {
                        try { JSON.parse(line); finish(null, line); return; } catch (e) { }
                    }
                }
            }
        });
        client.on('end', function ()
        {
            if (!done)
            {
                var finalResult = parseControlPayload(response);
                if (finalResult.parsed != null) { finish(null, finalResult.text); }
                else { finish(response.length > 0 ? 'control pipe closed with incomplete response' : 'control pipe closed without response', response); }
            }
        });
        client.on('close', function ()
        {
            if (!done)
            {
                var finalResult = parseControlPayload(response);
                if (finalResult.parsed != null) { finish(null, finalResult.text); }
                else { finish(response.length > 0 ? 'control pipe closed with incomplete response' : 'control pipe closed without response', response); }
            }
        });
        client.on('error', function (e) { finish(e.toString(), null); });
    }
    catch (e)
    {
        finish(e.toString(), null);
        return;
    }

    timer = setTimeout(function () { finish('timeout waiting for control response', response); }, 60000);
}

function umhctlEnsureFlowContract(sessionid, callback)
{
    if (typeof callback != 'function') { return; }
    if (umhctlHasFreshFlowContract())
    {
        callback(umhctlGetFlowContract(), null);
        return;
    }
    umhctlSendControlRequest({ op: 'getFlowContract' }, sessionid, {
        quiet: true,
        suppressRequestLog: true,
        callback: function (err, parsed)
        {
            if (parsed != null) { umhctlMaybeCacheFlowContract(parsed); }
            if (err != null) { callback(null, err); return; }
            if (umhctlFlowContractCache == null || typeof umhctlFlowContractCache != 'object') { callback(null, 'flow contract unavailable'); return; }
            callback(umhctlGetFlowContract(), null);
        }
    });
}

function umhctlRequiresPreProtectionCapture(controlReq)
{
    var opKey = umhctlNormalizeControlOp(controlReq != null ? controlReq.op : null);
    if (opKey == 'lockdownbypass')
    {
        return (controlReq != null && (controlReq.action == 'apply' || controlReq.action == 'apply-harness'));
    }
    if (opKey == 'examsoftbypass')
    {
        return (controlReq != null && controlReq.action == 'secure-enter');
    }
    return false;
}

function umhctlSanitizeCaptureToken(value)
{
    if (typeof value != 'string' || value.length == 0) { return 'na'; }
    var token = value.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    token = token.replace(/^-+/g, '').replace(/-+$/g, '');
    if (token.length == 0) { return 'na'; }
    if (token.length > 64) { token = token.substring(0, 64); }
    return token;
}

function umhctlBuildPreProtectionCapturePaths(controlReq)
{
    var programData = umhctlGetEnvValue('ProgramData');
    if (programData == null || programData.length == 0) { programData = 'C:\\ProgramData'; }
    var serviceName = process.env['MESH_SERVICE_NAME'] || 'MeshAgent';
    var rootDir = programData + '\\' + serviceName + '\\logs\\preprotection';
    var headers = (controlReq != null && typeof controlReq.headers == 'object' && controlReq.headers != null) ? controlReq.headers : {};
    var runId = (typeof headers['x-umh-run-id'] == 'string' && headers['x-umh-run-id'].trim().length > 0) ? headers['x-umh-run-id'].trim() : umhctlBuildRunId();
    var targetTag = (typeof headers['x-umh-target-tag'] == 'string' && headers['x-umh-target-tag'].trim().length > 0) ? headers['x-umh-target-tag'].trim() : umhctlDeriveTargetTag(controlReq, umhctlNormalizeControlOp(controlReq != null ? controlReq.op : null), headers, null);
    var actionToken = (controlReq != null && typeof controlReq.action == 'string' && controlReq.action.length > 0) ? controlReq.action : 'status';
    var fileBase = umhctlBuildTimestampUtc().replace(/[^0-9a-z]/ig, '') + '_'
        + umhctlSanitizeCaptureToken(controlReq != null ? controlReq.op : null) + '_'
        + umhctlSanitizeCaptureToken(actionToken) + '_'
        + umhctlSanitizeCaptureToken(runId) + '_'
        + umhctlSanitizeCaptureToken(targetTag);
    return {
        rootDir: rootDir,
        capturePath: rootDir + '\\' + fileBase + '.bmp',
        manifestPath: rootDir + '\\' + fileBase + '.json',
        runId: runId,
        targetTag: targetTag
    };
}

function umhctlPersistPreProtectionManifest(paths, controlReq, captureResult)
{
    if (paths == null || typeof paths != 'object') { return null; }
    if (!umhctlEnsureDirectoryPath(paths.rootDir)) { return null; }
    var manifest = {
        ok: true,
        captured_at_utc: (captureResult != null && typeof captureResult.captured_at_utc == 'string') ? captureResult.captured_at_utc : umhctlBuildTimestampUtc(),
        capture_path: (captureResult != null && typeof captureResult.capture_path == 'string') ? captureResult.capture_path : paths.capturePath,
        manifest_path: paths.manifestPath,
        request: {
            op: controlReq != null ? controlReq.op : null,
            action: (controlReq != null && typeof controlReq.action == 'string') ? controlReq.action : null,
            headers: (controlReq != null && typeof controlReq.headers == 'object' && controlReq.headers != null) ? umhctlCloneObject(controlReq.headers) : null
        },
        target: {
            run_id: paths.runId,
            target_tag: paths.targetTag
        }
    };
    try
    {
        fs.writeFileSync(paths.manifestPath, JSON.stringify(manifest, null, 2));
        return manifest;
    }
    catch (e)
    {
        return null;
    }
}

function umhctlRunPreProtectionCapture(controlReq, sessionid, callback)
{
    if (typeof callback != 'function') { return; }
    if (!umhctlRequiresPreProtectionCapture(controlReq))
    {
        callback(null, null);
        return;
    }

    var paths = umhctlBuildPreProtectionCapturePaths(controlReq);
    if (!umhctlEnsureDirectoryPath(paths.rootDir))
    {
        callback('unable to create pre-protection evidence directory: ' + paths.rootDir, null);
        return;
    }

    var captureProc = null;
    var done = false;
    var timer = null;
    var finish = function (err, result)
    {
        if (done) { return; }
        done = true;
        if (timer != null) { try { clearTimeout(timer); } catch (e) { } timer = null; }
        if (captureProc != null)
        {
            try { captureProc.kill(); } catch (e) { }
        }
        callback(err, result);
    };

    try
    {
        captureProc = childProcess.execFile(process.execPath, ['-preprotection-capture', '--capture-path=' + paths.capturePath]);
    }
    catch (e)
    {
        finish('unable to start native pre-protection capture: ' + e.toString(), null);
        return;
    }

    captureProc.stdout.str = '';
    captureProc.stderr.str = '';
    captureProc.stdout.on('data', function (c) { this.str += c.toString(); });
    captureProc.stderr.on('data', function (c) { this.str += c.toString(); });
    captureProc.on('error', function (e) { finish(e.toString(), null); });
    umhctlAttachProcessCompletion(captureProc, function (code) {
        var stdoutText = this.stdout.str || '';
        var stderrText = this.stderr.str || '';
        var parsed = umhctlParseJsonArg(stdoutText);
        if (parsed == null && stdoutText.indexOf('\n') >= 0)
        {
            var lines = stdoutText.split('\n');
            for (var i = 0; i < lines.length; ++i)
            {
                parsed = umhctlParseJsonArg(lines[i]);
                if (parsed != null) { break; }
            }
        }
        if (code !== 0 || parsed == null || parsed.ok !== true)
        {
            finish('native pre-protection capture failed (exit ' + code + '): ' + (stderrText || stdoutText || 'unknown error'), null);
            return;
        }
        var manifest = umhctlPersistPreProtectionManifest(paths, controlReq, parsed);
        finish(null, {
            capture: parsed,
            manifest: manifest,
            capturePath: parsed.capture_path || paths.capturePath,
            manifestPath: manifest != null ? manifest.manifest_path : paths.manifestPath
        });
    });
    timer = setTimeout(function () { finish('timeout waiting for native pre-protection capture', null); }, 120000);
}

function umhctlSendPreparedControlRequest(controlReq, sessionid)
{
    if (controlReq == null || typeof controlReq != 'object')
    {
        sendConsoleText('umhctl: invalid control request object', sessionid);
        return;
    }

    var opKey = umhctlNormalizeControlOp(controlReq.op);
    var finalizeSend = function ()
    {
        var headerResolution = umhctlResolveControlHeaders(controlReq, sessionid);
        if (!headerResolution.ok)
        {
            sendConsoleText(headerResolution.error, sessionid);
            return;
        }
        if (headerResolution.headers != null) { controlReq.headers = headerResolution.headers; }
        var dispatchRequest = function ()
        {
            umhctlSendControlRequest(controlReq, sessionid, {
                callback: function (err, parsed)
                {
                    if (err != null || parsed == null || parsed.ok !== true) { return; }
                    if (headerResolution.storeFlowContext === true && controlReq.headers != null) { umhctlSetFlowContext(sessionid, controlReq.headers); }
                    if (headerResolution.clearFlowContextOnSuccess === true) { umhctlClearFlowContext(sessionid); }
                }
            });
        };

        if (umhctlRequiresPreProtectionCapture(controlReq))
        {
            sendConsoleText('umhctl: capturing pre-protection evidence before ' + controlReq.op + ' ' + (controlReq.action || 'status') + ' ...', sessionid);
            umhctlRunPreProtectionCapture(controlReq, sessionid, function (captureErr, captureMeta) {
                if (captureErr != null)
                {
                    sendConsoleText('umhctl: pre-protection capture failed: ' + captureErr + '. Protection state not changed.', sessionid);
                    return;
                }
                if (captureMeta != null)
                {
                    if (typeof captureMeta.capturePath == 'string' && captureMeta.capturePath.length > 0)
                    {
                        sendConsoleText('umhctl: pre-protection capture saved to ' + captureMeta.capturePath, sessionid);
                    }
                    if (typeof captureMeta.manifestPath == 'string' && captureMeta.manifestPath.length > 0)
                    {
                        sendConsoleText('umhctl: pre-protection manifest saved to ' + captureMeta.manifestPath, sessionid);
                    }
                }
                dispatchRequest();
            });
            return;
        }

        dispatchRequest();
    };

    if (umhctlStateChangingOps[opKey] === 1)
    {
        umhctlEnsureFlowContract(sessionid, function (flowContract, err) {
            if (flowContract == null || err != null)
            {
                sendConsoleText('umhctl: unable to fetch flow contract: ' + (err || 'flow contract unavailable'), sessionid);
                return;
            }
            finalizeSend();
        });
    }
    else
    {
        finalizeSend();
    }
}

function umhctlBuildTimestampUtc()
{
    try { return (new Date()).toISOString(); } catch (e) { }
    return '';
}

function umhctlSendQuietControlRequest(requestObj, sessionid, callback)
{
    umhctlSendControlRequest(requestObj, sessionid, {
        quiet: true,
        suppressRequestLog: true,
        callback: callback
    });
}

function umhctlBuildUiFlowContractSummary(data)
{
    var contractVersion = null;
    if (data != null && typeof data.contract_version == 'string' && data.contract_version.length > 0) { contractVersion = data.contract_version; }
    else if (data != null && typeof data.current_version == 'string' && data.current_version.length > 0) { contractVersion = data.current_version; }
    var summary = {
        protocol: (data != null && typeof data.protocol == 'string') ? data.protocol : umhctlDefaultFlowContract.protocol,
        contract_version: contractVersion || umhctlDefaultFlowContract.contractVersion,
        flow_profile: (data != null && typeof data.flow_profile == 'string') ? data.flow_profile : umhctlDefaultFlowContract.flowProfile,
        required_headers: (data != null && data.required_headers instanceof Array) ? data.required_headers.slice(0) : umhctlDefaultFlowContract.requiredHeaders.slice(0),
        targets: []
    };
    var appendTargetSummary = function (targetKey, targetInfo)
    {
        var summaryKey = (typeof targetKey == 'string' && targetKey.length > 0) ? targetKey : 'target-' + (summary.targets.length + 1);
        var targetSummary = { key: summaryKey, label: summaryKey };
        if (targetInfo != null && typeof targetInfo == 'object')
        {
            if (typeof targetInfo.label == 'string' && targetInfo.label.length > 0) { targetSummary.label = targetInfo.label; }
            else if (typeof targetInfo.target == 'string' && targetInfo.target.length > 0) { targetSummary.label = targetInfo.target; }
            else if (typeof targetInfo.name == 'string' && targetInfo.name.length > 0) { targetSummary.label = targetInfo.name; }
            if (typeof targetInfo.launch_path == 'string' && targetInfo.launch_path.length > 0) { targetSummary.launch_path = targetInfo.launch_path; }
            if (targetInfo.request_headers instanceof Array) { targetSummary.request_headers = targetInfo.request_headers.slice(0); }
        }
        summary.targets.push(targetSummary);
    };
    if (data != null && data.targets instanceof Array)
    {
        for (var i = 0; i < data.targets.length; ++i)
        {
            var targetInfo = data.targets[i];
            var targetKey = null;
            if (targetInfo != null && typeof targetInfo == 'object')
            {
                targetKey = targetInfo.key || targetInfo.target || targetInfo.tag || targetInfo.name || targetInfo.id;
            }
            appendTargetSummary(targetKey, targetInfo);
        }
    }
    else if (data != null && typeof data.targets == 'object' && data.targets != null)
    {
        for (var targetName in data.targets)
        {
            appendTargetSummary(targetName, data.targets[targetName]);
        }
    }
    return summary;
}

function umhctlSendUiSnapshot(sessionid, requestedPid)
{
    var snapshot = {
        ok: true,
        data: {
            requested_pid: (requestedPid != null) ? requestedPid : 0
        },
        errors: {},
        meta: {
            source: 'meshagent-umhctl',
            snapshot_version: 1,
            requested_pid: (requestedPid != null) ? requestedPid : 0,
            timestamp_utc: umhctlBuildTimestampUtc(),
            partial: false,
            sections: {}
        }
    };

    var jobs = [
        {
            key: 'status',
            req: { op: 'status' },
            assign: function (parsed) { snapshot.data.status = parsed.data; }
        },
        {
            key: 'flow_contract',
            req: { op: 'getFlowContract' },
            assign: function (parsed) { snapshot.data.flow_contract = umhctlBuildUiFlowContractSummary(parsed.data); }
        },
        {
            key: 'capabilities',
            req: { op: 'getCapabilities' },
            assign: function (parsed) { snapshot.data.capabilities = parsed.data; }
        },
        {
            key: 'processes',
            req: { op: 'listProcesses' },
            assign: function (parsed) { snapshot.data.processes = parsed.data; }
        },
        {
            key: 'policy',
            req: { op: 'getPolicy' },
            assign: function (parsed) { snapshot.data.policy = parsed.data; }
        },
        {
            key: 'config',
            req: { op: 'getConfig' },
            assign: function (parsed)
            {
                snapshot.data.config_raw = parsed.data;
                var parsedConfig = null;
                if (typeof parsed.data == 'string') { parsedConfig = umhctlParseJsonArg(parsed.data); }
                else if (parsed.data != null) { parsedConfig = parsed.data; }
                if (parsedConfig != null) { snapshot.data.config_parsed = parsedConfig; }
            }
        },
        {
            key: 'safety_state',
            req: { op: 'safetyState' },
            assign: function (parsed) { snapshot.data.safety_state = parsed.data; }
        }
    ];

    if (requestedPid != null)
    {
        jobs.push({
            key: 'process_profile',
            req: { op: 'profileProcess', pid: requestedPid },
            assign: function (parsed) { snapshot.data.process_profile = parsed.data; }
        });
        jobs.push({
            key: 'method_policy',
            req: { op: 'methodPolicy', pid: requestedPid },
            assign: function (parsed) { snapshot.data.method_policy = parsed.data; }
        });
        jobs.push({
            key: 'security_boundary',
            req: { op: 'securityBoundary', pid: requestedPid },
            assign: function (parsed) { snapshot.data.security_boundary = parsed.data; }
        });
    }

    var jobIndex = 0;
    var finalize = function ()
    {
        snapshot.meta.partial = (countObjectKeys(snapshot.errors) > 0);
        sendConsoleText('umhctl uiSnapshot:\r\n' + JSON.stringify(snapshot, null, 2), sessionid);
    };
    var runNext = function ()
    {
        if (jobIndex >= jobs.length)
        {
            finalize();
            return;
        }
        var job = jobs[jobIndex++];
        snapshot.meta.sections[job.key] = { requested: true };
        umhctlSendQuietControlRequest(job.req, sessionid, function (err, parsed, rawText)
        {
            if (err == null && parsed != null && parsed.ok === true)
            {
                try
                {
                    job.assign(parsed);
                    snapshot.meta.sections[job.key].ok = true;
                }
                catch (assignErr)
                {
                    snapshot.errors[job.key] = { error: 'assign-failed', detail: assignErr.toString() };
                    snapshot.meta.sections[job.key].ok = false;
                }
            }
            else
            {
                snapshot.errors[job.key] = {
                    error: 'request-failed',
                    detail: (parsed != null && parsed.error != null) ? parsed.error : (err || rawText || 'unknown error')
                };
                snapshot.meta.sections[job.key].ok = false;
            }
            runNext();
        });
    };
    runNext();
}

function umhctlGetAgentDirectory()
{
    try
    {
        if (fs.existsSync(process.execPath)) { return process.execPath.replace(/[/\\][^/\\]+$/, ''); }
    } catch (e) { }
    return '.';
}

function umhctlRunMasterServiceStatus(msExePath, sessionid)
{
    var serviceState = umhctlQueryMasterServiceWindowsState();
    var binaryExists = false;
    try { binaryExists = fs.existsSync(msExePath); } catch (e) { binaryExists = false; }
    if (!binaryExists)
    {
        if (serviceState != null && serviceState.installed === true && typeof serviceState.appLocation == 'string' && serviceState.appLocation.length > 0)
        {
            sendConsoleText('MasterService managed binary not found at ' + msExePath + '. Current registration: ' + umhctlFormatServiceStateSummary(serviceState) + '. Run "umhctl install" to repair registration.', sessionid);
            return;
        }
        sendConsoleText('MasterService not found at ' + msExePath + '. Run "umhctl install --url <url>" or configure UMH_MASTERSERVICE_EXE/UMH_MASTERSERVICE_PATH.', sessionid);
        return;
    }
    try
    {
        var statusProc = childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['--status', '--output', 'json']));
        var statusDone = false;
        var statusTimer = setTimeout(function ()
        {
            if (statusDone) { return; }
            statusDone = true;
            sendConsoleText('umhctl service status timeout (120s)', sessionid);
            try { statusProc.kill(); } catch (e) { }
        }, 120000);
        statusProc.stdout.str = '';
        statusProc.stderr.str = '';
        statusProc.stdout.on('data', function (c) { this.str += c.toString(); });
        statusProc.stderr.on('data', function (c) { this.str += c.toString(); });
        statusProc.on('error', function (e) {
            if (statusDone) { return; }
            statusDone = true;
            clearTimeout(statusTimer);
            sendConsoleText('umhctl service status error: ' + e.toString(), sessionid);
        });
    umhctlAttachProcessCompletion(statusProc, function (code) {
        if (statusDone) { return; }
        statusDone = true;
        clearTimeout(statusTimer);
            var out = this.stdout.str + (this.stderr.str ? '\r\nSTDERR: ' + this.stderr.str : '');
            sendConsoleText('umhctl service status (exit ' + code + '):\r\n' + out, sessionid);
        });
    } catch (e) {
        sendConsoleText('Failed to run MasterService --status: ' + e.toString(), sessionid);
    }
}

function umhctlBuildHelp(agentDir, msExePath)
{
    return 'umhctl - MasterService control\r\n\r\n'
        + 'Lifecycle:\r\n'
        + '  umhctl install [--url <url>] [--pin <sha384>] [--insecure]\r\n'
        + '  umhctl uninstall\r\n'
        + '  umhctl status --service\r\n'
        + '  umhctl verify\r\n\r\n'
        + 'Control pipe - query:\r\n'
        + '  umhctl status | listProcesses | getFlowContract | getCapabilities\r\n'
        + '  umhctl getPolicy | getConfig | safetyState\r\n'
        + '  umhctl uiSnapshot [--pid <pid>]\r\n'
        + '  umhctl profileProcess --pid <pid>\r\n'
        + '  umhctl methodPolicy [--pid <pid>]\r\n'
        + '  umhctl hookProfile --target <tag> [--exe <path>]\r\n'
        + '  umhctl securityBoundary [--pid <pid>] [--target <tag>]\r\n\r\n'
        + 'Control pipe - mutation:\r\n'
        + '  umhctl inject --pid <pid> [--method <m>] [--technique <t>]\r\n'
        + '  umhctl injectTargetSet --pids <csv> [--run-id <id>] [--target-tag <tag>] [--method-key <key>]\r\n'
        + '  umhctl injectAll\r\n'
        + '  umhctl telemetry --pid <pid>\r\n'
        + '  umhctl repair --pid <pid>\r\n'
        + '  umhctl setPolicy --policy <json>\r\n'
        + '  umhctl setConfig --content <json-or-text>\r\n'
        + '  umhctl clearTargetScope\r\n\r\n'
        + 'Bypass:\r\n'
        + '  umhctl ipcBypass --action <list-targets|status|disable|enable> [--target <adapter>] [--domain <screen|input|network|process|all>]\r\n'
        + '  umhctl lockdownBypass --action <status|apply|apply-harness|revert|revert-harness>\r\n'
        + '  umhctl examsoftBypass --action <status|secure-enter|secure-exit>\r\n\r\n'
        + 'Raw JSON:\r\n'
        + '  umhctl --json \'{"op":"status"}\'\r\n\r\n'
        + 'Headers (auto-filled for state-changing ops; override with flags below):\r\n'
        + '  --run-id <id>  --target-tag <tag>  --method-key <key>\r\n'
        + '  --contract-version <v>  --flow-profile <p>  --client <c>\r\n\r\n'
        + 'Env overrides:\r\n'
        + '  UMH_MASTERSERVICE_URL  full download URL\r\n'
        + '  UMH_MASTERSERVICE_PATH relative path on server\r\n'
        + '  UMH_USERFILES_USER     userfiles owner when using default path\r\n'
        + '  UMH_MASTERSERVICE_EXE  explicit managed binary path\r\n\r\n'
        + 'Pipe:        ' + umhControlPipePath + '\r\n'
        + 'Binary path: ' + msExePath + '\r\n'
        + 'Agent dir:   ' + agentDir;
}

function umhctlHandleRawJson(args, sessionid)
{
    var requestObj = umhctlParseJsonArg(args['json']);
    if (requestObj == null || typeof requestObj != 'object')
    {
        return 'umhctl: invalid --json payload. Example: umhctl --json "{\\"op\\":\\"status\\"}"';
    }
    if (typeof requestObj.op != 'string' || requestObj.op.length == 0)
    {
        return 'umhctl: JSON payload must include a string "op" field.';
    }
    var canonicalJsonOp = umhctlCanonicalControlOp(requestObj.op);
    if (canonicalJsonOp == null)
    {
        return 'umhctl: unsupported control op in JSON payload: "' + requestObj.op + '".';
    }
    requestObj.op = canonicalJsonOp;

    if (requestObj.pid != null)
    {
        var jsonPid = umhctlParsePositiveInt(requestObj.pid);
        if (jsonPid == null) { return 'umhctl: JSON payload has invalid "pid".'; }
        requestObj.pid = jsonPid;
    }
    if (umhctlPidRequiredOps[umhctlNormalizeControlOp(requestObj.op)] && requestObj.pid == null)
    {
        return 'umhctl ' + requestObj.op + ' requires "pid" in JSON payload.';
    }
    if (requestObj.flags != null && (typeof requestObj.flags != 'object' || requestObj.flags == null || (requestObj.flags instanceof Array)))
    {
        return 'umhctl: JSON payload field "flags" must be a JSON object.';
    }

    var jsonOpActionMap = umhctlActionAllowedByOp[umhctlNormalizeControlOp(requestObj.op)];
    if (jsonOpActionMap != null)
    {
        if (requestObj.action == null || ('' + requestObj.action).trim().length == 0) { requestObj.action = 'status'; }
        var jsonAction = umhctlCanonicalAction(requestObj.op, '' + requestObj.action);
        if (jsonAction == null)
        {
            return 'umhctl: invalid action "' + requestObj.action + '" for ' + requestObj.op + '.';
        }
        requestObj.action = jsonAction;
    }

    if (!umhctlPreflightControlService(sessionid)) { return null; }
    umhctlSendPreparedControlRequest(requestObj, sessionid);
    return null;
}

function umhctlHandleInstall(args, sessionid, msExePath, msTmpPath, msBakPath)
{
    var downloadUrl = args['url'];
    var usingDefaultUrl = false;
    if (!downloadUrl)
    {
        usingDefaultUrl = true;
        downloadUrl = umhctlGetDefaultDownloadUrl();
    }
    var pinDigest = null;
    if (args['pin'] != null)
    {
        if (args['pin'] === true) { return 'umhctl install: --pin requires a SHA-384 digest value.'; }
        pinDigest = umhctlNormalizeDigest('' + args['pin']);
        if (pinDigest == null) { return 'umhctl install: --pin must be a 96-character SHA-384 hex digest.'; }
    }
    if (!downloadUrl) { return 'Cannot determine download URL. Use: umhctl install --url <url>'; }
    if (!/^https:\/\//i.test('' + downloadUrl)) { return 'umhctl install: URL must start with https:// (plaintext HTTP is not allowed for binary downloads).'; }
    if (!umhctlBeginLifecycle('install', sessionid)) { return null; }

    umhctlSetLifecyclePhase('install', 'preparing download');
    var installComplete = false;
    var finishInstall = function ()
    {
        if (installComplete) { return; }
        installComplete = true;
        umhctlEndLifecycle('install');
    };

    sendConsoleText('umhctl: downloading from ' + downloadUrl + ' ...', sessionid);
    try
    {
        var dlOpts = http.parseUri(downloadUrl);
        if (!dlOpts || !dlOpts.host)
        {
            finishInstall();
            return 'umhctl: invalid download URL: ' + downloadUrl;
        }
        var isHttps = ((downloadUrl + '').toLowerCase().indexOf('https://') == 0);
        if (isHttps)
        {
            var expectedDigest = pinDigest;
            if (expectedDigest == null && usingDefaultUrl)
            {
                expectedDigest = umhctlGetServerPinnedDigest();
            }
            if (expectedDigest != null)
            {
                var verifyFn = umhctlBuildPinnedCertVerifier(expectedDigest);
                if (verifyFn == null)
                {
                    finishInstall();
                    return 'umhctl: invalid TLS pin digest.';
                }
                dlOpts.rejectUnauthorized = 0;
                dlOpts.checkServerIdentity = verifyFn;
                sendConsoleText('umhctl: TLS pinning enabled (' + expectedDigest + ').', sessionid);
            }
            else
            {
                dlOpts.rejectUnauthorized = 1;
                if (usingDefaultUrl)
                {
                    sendConsoleText('umhctl: warning: no server pin available, using CA trust validation.', sessionid);
                }
            }
        }

        var req = http.request(dlOpts);
        var dlDone = false;
        var downloadFail = null;
        var dlTimer = setTimeout(function () {
            if (!dlDone)
            {
                if (downloadFail != null)
                {
                    downloadFail('umhctl: download timed out (120s)');
                }
                else
                {
                    dlDone = true;
                    sendConsoleText('umhctl: download timed out (120s)', sessionid);
                    try { req.abort(); } catch (e) { }
                    finishInstall();
                }
            }
        }, 120000);

        var onReqError = function (e)
        {
            if (dlDone) { return; }
            if (downloadFail != null)
            {
                downloadFail('umhctl: download error: ' + e.toString());
            }
            else
            {
                dlDone = true;
                clearTimeout(dlTimer);
                sendConsoleText('umhctl: download error: ' + e.toString(), sessionid);
                finishInstall();
            }
        };
        req.onerror = onReqError;
        req.on('error', onReqError);
        req.on('response', function (res) {
            if (dlDone) { return; }
            if (res.statusCode != 200)
            {
                dlDone = true;
                clearTimeout(dlTimer);
                sendConsoleText('umhctl: download failed, HTTP ' + res.statusCode, sessionid);
                finishInstall();
                return;
            }

            var fd = null;
            var totalBytes = 0;
            var writeError = null;
            var fdClosed = false;
            var closeFd = function ()
            {
                if (fdClosed) { return; }
                fdClosed = true;
                try { if (fd != null) { fs.closeSync(fd); } } catch (e) { }
            };
            var failDownload = function (msg)
            {
                if (dlDone) { return; }
                dlDone = true;
                clearTimeout(dlTimer);
                try { req.abort(); } catch (e) { }
                closeFd();
                try { fs.unlinkSync(msTmpPath); } catch (e) { }
                sendConsoleText(msg, sessionid);
                finishInstall();
            };
            downloadFail = failDownload;

            try { fs.unlinkSync(msTmpPath); } catch (e) { }
            if (!umhctlEnsureParentDirectory(msTmpPath))
            {
                failDownload('umhctl: cannot create target directory for ' + msTmpPath + '.');
                return;
            }
            try { fd = fs.openSync(msTmpPath, 'wbN'); } catch (e) {
                failDownload('umhctl: cannot open ' + msTmpPath + ' for writing: ' + e.toString());
                return;
            }

            res.on('data', function (chunk) {
                if (dlDone || writeError != null) { return; }
                try { fs.writeSync(fd, chunk); totalBytes += chunk.length; } catch (e) {
                    writeError = e;
                    failDownload('umhctl: write failed: ' + e.toString());
                    try { res.destroy(); } catch (ee) { }
                    try { req.abort(); } catch (ee) { }
                }
            });
            res.on('error', function (e) { failDownload('umhctl: download stream error: ' + e.toString()); });
            res.on('end', function () {
                if (dlDone) { closeFd(); return; }
                dlDone = true;
                clearTimeout(dlTimer);
                closeFd();

                if (writeError != null)
                {
                    try { fs.unlinkSync(msTmpPath); } catch (e) { }
                    sendConsoleText('umhctl: write failed: ' + writeError.toString(), sessionid);
                    finishInstall();
                    return;
                }

                sendConsoleText('umhctl: saved ' + totalBytes + ' bytes to ' + msTmpPath, sessionid);

                if (totalBytes < 1024)
                {
                    try { fs.unlinkSync(msTmpPath); } catch (e) { }
                    sendConsoleText('umhctl: download too small (' + totalBytes + ' bytes), aborting install', sessionid);
                    finishInstall();
                    return;
                }
                if (!umhctlFileLooksLikePe(msTmpPath))
                {
                    try { fs.unlinkSync(msTmpPath); } catch (e) { }
                    sendConsoleText('umhctl: downloaded file is not a valid PE executable (expected MZ header). Check the URL/path and server response.', sessionid);
                    finishInstall();
                    return;
                }
                // Verify content hash if a pin digest was provided
                if (pinDigest != null)
                {
                    var fileHash = umhctlComputeFileHashSync(msTmpPath);
                    if (fileHash == null)
                    {
                        try { fs.unlinkSync(msTmpPath); } catch (e) { }
                        sendConsoleText('umhctl: --pin was specified but SHA-384 hash computation is unavailable. Aborting install (cannot verify integrity).', sessionid);
                        finishInstall();
                        return;
                    }
                    if (fileHash !== pinDigest)
                    {
                        try { fs.unlinkSync(msTmpPath); } catch (e) { }
                        sendConsoleText('umhctl: content hash mismatch. Expected: ' + pinDigest + ', got: ' + fileHash + '. Aborting install (possible tampering).', sessionid);
                        finishInstall();
                        return;
                    }
                    sendConsoleText('umhctl: content hash verified: ' + fileHash, sessionid);
                }

                var backupCreated = false;
                var restorePreviousBinary = function (reason)
                {
                    if (!backupCreated) { return; }
                    var haveBackup = false;
                    try { haveBackup = fs.existsSync(msBakPath); } catch (e) { haveBackup = false; }
                    if (!haveBackup) { return; }
                    try { if (fs.existsSync(msExePath)) { fs.unlinkSync(msExePath); } } catch (e) {
                        sendConsoleText('umhctl: failed to remove updated binary before rollback: ' + e.toString(), sessionid);
                        return;
                    }
                    try {
                        fs.renameSync(msBakPath, msExePath);
                        backupCreated = false;
                        sendConsoleText('umhctl: restored previous MasterService binary (' + reason + ').', sessionid);
                    } catch (e) {
                        sendConsoleText('umhctl: rollback failed for ' + msExePath + ': ' + e.toString(), sessionid);
                    }
                };

                var runInstalledBinary = function ()
                {
                    umhctlSetLifecyclePhase('install', 'running install command');
                    try
                    {
                        sendConsoleText('umhctl: running --install ...', sessionid);
                        var instProc = childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['--install', '--silent', '--wait', '--timeout', '120', '--output', 'json']));
                        var instProcDone = false;
                        var finalizeInstallBinary = function (success)
                        {
                            if (!backupCreated) { return; }
                            if (success)
                            {
                                try { fs.unlinkSync(msBakPath); } catch (e) { }
                                backupCreated = false;
                            }
                            else
                            {
                                restorePreviousBinary('install failed');
                            }
                        };
                        var instProcTimer = setTimeout(function ()
                        {
                            if (instProcDone) { return; }
                            instProcDone = true;
                            sendConsoleText('umhctl: install process timeout (240s)', sessionid);
                            try { instProc.kill(); } catch (e) { }
                            finalizeInstallBinary(false);
                            finishInstall();
                        }, 240000);
                        instProc.stdout.str = '';
                        instProc.stderr.str = '';
                        instProc.stdout.on('data', function (c) { this.str += c.toString(); });
                        instProc.stderr.on('data', function (c) { this.str += c.toString(); });
                        instProc.on('error', function (e) {
                            if (instProcDone) { return; }
                            instProcDone = true;
                            clearTimeout(instProcTimer);
                            sendConsoleText('umhctl: install spawn error: ' + e.toString(), sessionid);
                            finalizeInstallBinary(false);
                            finishInstall();
                        });
                        umhctlAttachProcessCompletion(instProc, function (code) {
                            if (instProcDone) { return; }
                            instProcDone = true;
                            clearTimeout(instProcTimer);
                            var out = this.stdout.str + (this.stderr.str ? '\r\nSTDERR: ' + this.stderr.str : '');
                            sendConsoleText('umhctl install (exit ' + code + '):\r\n' + out, sessionid);
                            finalizeInstallBinary(code === 0);
                            finishInstall();
                            if (code === 0)
                            {
                                umhctlResetFlowState();
                                setTimeout(function () {
                                    sendConsoleText('umhctl: verifying service status ...', sessionid);
                                    umhctlRunMasterServiceStatus(msExePath, sessionid);
                                    setTimeout(function () {
                                        sendConsoleText('umhctl: verifying service via control pipe ...', sessionid);
                                        umhctlSendControlRequest({ op: 'status' }, sessionid);
                                    }, 3000);
                                }, 0);
                            }
                        });
                    } catch (e) {
                        sendConsoleText('umhctl: install error: ' + e.toString(), sessionid);
                        restorePreviousBinary('install start failed');
                        finishInstall();
                    }
                };

                var trySwapBinary = function (attempt)
                {
                    umhctlSetLifecyclePhase('install', 'swapping binary');
                    var haveTmp = false;
                    try { haveTmp = fs.existsSync(msTmpPath); } catch (e) { haveTmp = false; }
                    if (!haveTmp)
                    {
                        sendConsoleText('umhctl: downloaded binary disappeared before activation.', sessionid);
                        finishInstall();
                        return;
                    }

                    backupCreated = false;
                    try { fs.unlinkSync(msBakPath); } catch (e) { }

                    var haveExisting = false;
                    try { haveExisting = fs.existsSync(msExePath); } catch (e) { haveExisting = false; }
                    if (haveExisting)
                    {
                        try
                        {
                            fs.renameSync(msExePath, msBakPath);
                            backupCreated = true;
                        } catch (e) {
                            if (attempt < 20)
                            {
                                if (attempt === 0) { sendConsoleText('umhctl: waiting for existing MasterService binary to unlock before upgrade ...', sessionid); }
                                setTimeout(function () { trySwapBinary(attempt + 1); }, 750);
                                return;
                            }
                            try { fs.unlinkSync(msTmpPath); } catch (ee) { }
                            sendConsoleText('umhctl: cannot replace existing binary at ' + msExePath + ' after stop/retry: ' + e.toString(), sessionid);
                            finishInstall();
                            return;
                        }
                    }

                    try
                    {
                        fs.renameSync(msTmpPath, msExePath);
                    } catch (e) {
                        if (backupCreated)
                        {
                            try { fs.renameSync(msBakPath, msExePath); backupCreated = false; } catch (ee) {
                                sendConsoleText('umhctl: rollback failed for ' + msExePath + ': ' + ee.toString(), sessionid);
                            }
                        }
                        if (attempt < 20)
                        {
                            setTimeout(function () { trySwapBinary(attempt + 1); }, 750);
                            return;
                        }
                        try { fs.unlinkSync(msTmpPath); } catch (ee) { }
                        sendConsoleText('umhctl: failed to finalize downloaded binary: ' + e.toString(), sessionid);
                        finishInstall();
                        return;
                    }

                    runInstalledBinary();
                };

                var beginSwapAfterStop = function ()
                {
                    umhctlSetLifecyclePhase('install', 'stopping existing service');
                    var haveExistingBinary = false;
                    try { haveExistingBinary = fs.existsSync(msExePath); } catch (e) { haveExistingBinary = false; }
                    if (!haveExistingBinary)
                    {
                        trySwapBinary(0);
                        return;
                    }

                    umhctlStopMasterServiceWindowsService(sessionid, function (handledByServiceManager)
                    {
                        umhctlSetLifecyclePhase('install', 'waiting for service stop to settle');
                        var proceedAfterStop = function ()
                        {
                            umhctlWaitForServiceStopAndProcessExit(sessionid, msExePath, 30000, function (settled, stopState, activeProcesses) {
                                if (!settled)
                                {
                                    var detail = umhctlFormatServiceStopBlockerDetail(stopState, activeProcesses);
                                    var settleMsg = 'umhctl: service stop did not fully settle within 30000ms';
                                    if (detail.length > 0) { settleMsg += ' (' + detail + ')'; }
                                    settleMsg += '. Aborting install before binary activation.';
                                    sendConsoleText(settleMsg, sessionid);
                                    try { fs.unlinkSync(msTmpPath); } catch (e) { }
                                    finishInstall();
                                    return;
                                }
                                trySwapBinary(0);
                            });
                        };
                        if (handledByServiceManager === true)
                        {
                            proceedAfterStop();
                            return;
                        }

                        sendConsoleText('umhctl: stopping existing MasterService before upgrade ...', sessionid);
                        try
                        {
                            var quitProc = childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['--quit', '--silent', '--wait', '--timeout', '120', '--output', 'json']));
                            var quitDone = false;
                            var quitTimer = setTimeout(function ()
                            {
                                if (quitDone) { return; }
                                quitDone = true;
                                sendConsoleText('umhctl: existing service stop timed out (180s), verifying service/process state before binary activation ...', sessionid);
                                try { quitProc.kill(); } catch (e) { }
                                proceedAfterStop();
                            }, 180000);
                            quitProc.stdout.str = '';
                            quitProc.stderr.str = '';
                            quitProc.stdout.on('data', function (c) { this.str += c.toString(); });
                            quitProc.stderr.on('data', function (c) { this.str += c.toString(); });
                            quitProc.on('error', function (e) {
                                if (quitDone) { return; }
                                quitDone = true;
                                clearTimeout(quitTimer);
                                sendConsoleText('umhctl: existing service stop error: ' + e.toString() + '. Verifying service/process state before binary activation.', sessionid);
                                proceedAfterStop();
                            });
                            umhctlAttachProcessCompletion(quitProc, function (code) {
                                if (quitDone) { return; }
                                quitDone = true;
                                clearTimeout(quitTimer);
                                var quitOut = this.stdout.str + (this.stderr.str ? '\r\nSTDERR: ' + this.stderr.str : '');
                                sendConsoleText('umhctl stop-existing (exit ' + code + '):\r\n' + quitOut, sessionid);
                                proceedAfterStop();
                            });
                        } catch (e) {
                            sendConsoleText('umhctl: existing service stop setup failed: ' + e.toString() + '. Verifying service/process state before binary activation.', sessionid);
                            proceedAfterStop();
                        }
                    });
                };

                beginSwapAfterStop();
            });
        });
        req.end();
    } catch (e) {
        finishInstall();
        return 'umhctl: request error: ' + e.toString();
    }
    return null;
}

function umhctlHandleUninstall(sessionid, agentDir, msExePath)
{
    var uninstallBinaryExists = false;
    try { uninstallBinaryExists = fs.existsSync(msExePath); } catch (e) { uninstallBinaryExists = false; }
    var uninstallState = umhctlQueryMasterServiceWindowsState();
    if (!uninstallBinaryExists && uninstallState.installed !== true) { return 'MasterService not found at ' + msExePath + '.'; }
    if (!umhctlBeginLifecycle('uninstall', sessionid)) { return null; }

    umhctlSetLifecyclePhase('uninstall', 'preparing uninstall');
    var uninstallComplete = false;
    var postUninstallVerify = function ()
    {
        umhctlResetFlowState();
        setTimeout(function () {
            sendConsoleText('umhctl: verifying post-uninstall status ...', sessionid);
            umhctlRunMasterServiceStatus(msExePath, sessionid);
            sendConsoleText('umhctl: verifying control pipe shutdown ...', sessionid);
            umhctlSendControlRequest({ op: 'status' }, sessionid);
        }, 3000);
    };
    var finishUninstall = function ()
    {
        if (uninstallComplete) { return; }
        uninstallComplete = true;
        umhctlEndLifecycle('uninstall');
    };
    var completeUninstall = function (success)
    {
        finishUninstall();
        if (success === true) { postUninstallVerify(); }
    };
    var forceRemoveService = function (reason)
    {
        umhctlSetLifecyclePhase('uninstall', 'forcing service removal');
        sendConsoleText('umhctl: forcing service removal (' + reason + ') ...', sessionid);
        umhctlForceRemoveMasterServiceWindowsService(sessionid, agentDir, msExePath, function (removed) {
            if (!removed)
            {
                sendConsoleText('umhctl: force-remove did not fully remove MasterService.', sessionid);
                completeUninstall(false);
                return;
            }
            sendConsoleText('umhctl: force-remove completed.', sessionid);
            completeUninstall(true);
        });
    };

    if (!uninstallBinaryExists)
    {
        sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', removing service registration via fallback.', sessionid);
        forceRemoveService('resolved-binary-missing');
        return null;
    }

    umhctlSetLifecyclePhase('uninstall', 'stopping service');
    sendConsoleText('umhctl: stopping service ...', sessionid);
    try
    {
        var quitProc = childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['--quit', '--silent', '--wait', '--timeout', '120', '--output', 'json']));
        var quitDone = false;
        var quitTimer = setTimeout(function ()
        {
            if (quitDone) { return; }
            quitDone = true;
            sendConsoleText('umhctl: quit process timeout (180s)', sessionid);
            try { quitProc.kill(); } catch (e) { }
            forceRemoveService('quit-timeout');
        }, 180000);
        quitProc.stdout.str = '';
        quitProc.stderr.str = '';
        quitProc.stdout.on('data', function (c) { this.str += c.toString(); });
        quitProc.stderr.on('data', function (c) { this.str += c.toString(); });
        quitProc.on('error', function (e) {
            if (quitDone) { return; }
            quitDone = true;
            clearTimeout(quitTimer);
            sendConsoleText('umhctl quit spawn error: ' + e.toString(), sessionid);
            forceRemoveService('quit-spawn-error');
        });
        umhctlAttachProcessCompletion(quitProc, function (quitCode) {
            if (quitDone) { return; }
            quitDone = true;
            clearTimeout(quitTimer);
            var quitOut = this.stdout.str + (this.stderr.str ? '\r\nSTDERR: ' + this.stderr.str : '');
            sendConsoleText('umhctl quit (exit ' + quitCode + '):\r\n' + quitOut, sessionid);
            var quitBootstrap = umhctlLooksLikeInteractiveBootstrapOutput(quitOut);
            var postQuitState = umhctlQueryMasterServiceWindowsState();
            if (quitBootstrap)
            {
                sendConsoleText('umhctl: quit command triggered interactive bootstrap instead of stopping the service.', sessionid);
                forceRemoveService('stale-masterservice-bootstrap-on-quit');
                return;
            }
            if (postQuitState.installed === true && postQuitState.running === true)
            {
                sendConsoleText('umhctl: service remained active after quit (state ' + postQuitState.state + ').', sessionid);
                forceRemoveService('service-still-running-after-quit');
                return;
            }

            try
            {
                umhctlSetLifecyclePhase('uninstall', 'running uninstall command');
                sendConsoleText('umhctl: uninstalling ...', sessionid);
                var uninstProc = childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['--uninstall', '--silent', '--wait', '--timeout', '120', '--output', 'json']));
                var uninstDone = false;
                var uninstTimer = setTimeout(function ()
                {
                    if (uninstDone) { return; }
                    uninstDone = true;
                    sendConsoleText('umhctl: uninstall process timeout (240s)', sessionid);
                    try { uninstProc.kill(); } catch (e) { }
                    forceRemoveService('uninstall-timeout');
                }, 240000);
                uninstProc.stdout.str = '';
                uninstProc.stderr.str = '';
                uninstProc.stdout.on('data', function (c) { this.str += c.toString(); });
                uninstProc.stderr.on('data', function (c) { this.str += c.toString(); });
                uninstProc.on('error', function (e) {
                    if (uninstDone) { return; }
                    uninstDone = true;
                    clearTimeout(uninstTimer);
                    sendConsoleText('umhctl uninstall spawn error: ' + e.toString(), sessionid);
                    forceRemoveService('uninstall-spawn-error');
                });
                umhctlAttachProcessCompletion(uninstProc, function (code) {
                    if (uninstDone) { return; }
                    uninstDone = true;
                    clearTimeout(uninstTimer);
                    var out = this.stdout.str + (this.stderr.str ? '\r\nSTDERR: ' + this.stderr.str : '');
                    sendConsoleText('umhctl uninstall (exit ' + code + '):\r\n' + out, sessionid);
                    var uninstallBootstrap = umhctlLooksLikeInteractiveBootstrapOutput(out);
                    var postUninstallState = umhctlQueryMasterServiceWindowsState();
                    if (uninstallBootstrap)
                    {
                        sendConsoleText('umhctl: uninstall command triggered interactive bootstrap instead of removing the service.', sessionid);
                        forceRemoveService('stale-masterservice-bootstrap-on-uninstall');
                        return;
                    }
                    if (postUninstallState.installed === true)
                    {
                        sendConsoleText('umhctl: service still present after uninstall (state ' + postUninstallState.state + ').', sessionid);
                        forceRemoveService('service-still-installed-after-uninstall');
                        return;
                    }
                    completeUninstall(true);
                });
            } catch (e) {
                sendConsoleText('umhctl uninstall error: ' + e.toString(), sessionid);
                forceRemoveService('uninstall-exception');
            }
        });
    } catch (e) {
        sendConsoleText('umhctl: uninstall setup error: ' + e.toString(), sessionid);
        forceRemoveService('uninstall-setup-exception');
    }
    return null;
}

function umhctlBuildControlRequest(subcmdOp, args)
{
    var controlReq = { op: subcmdOp };
    var opKey = umhctlNormalizeControlOp(subcmdOp);

    if (args['pid'] === true) { return { response: 'umhctl: --pid requires a value.' }; }
    if (args['pid'] != null)
    {
        var pid = umhctlParsePositiveInt('' + args['pid']);
        if (pid == null) { return { response: 'umhctl: invalid --pid value: ' + args['pid'] }; }
        controlReq.pid = pid;
    }
    if (umhctlPidRequiredOps[opKey] && controlReq.pid == null)
    {
        return { response: 'umhctl ' + subcmdOp + ' requires --pid <pid>.' };
    }

    if (args['action'] === true) { return { response: 'umhctl: --action requires a value.' }; }
    if (args['action'] != null) { controlReq.action = '' + args['action']; }
    var opActionMap = umhctlActionAllowedByOp[opKey];
    if (opActionMap != null)
    {
        if (controlReq.action == null || controlReq.action.trim().length == 0) { controlReq.action = 'status'; }
        var canonicalAction = umhctlCanonicalAction(subcmdOp, controlReq.action);
        if (canonicalAction == null)
        {
            return { response: 'umhctl: invalid --action value for ' + subcmdOp + ': ' + controlReq.action };
        }
        controlReq.action = canonicalAction;
    }

    if (args['method'] === true) { return { response: 'umhctl: --method requires a value.' }; }
    if (args['method'] != null) { controlReq.method = '' + args['method']; }
    if (args['technique'] === true) { return { response: 'umhctl: --technique requires a value.' }; }
    if (args['technique'] != null) { controlReq.technique = '' + args['technique']; }

    if (args['content'] === true) { return { response: 'umhctl: --content requires a value.' }; }
    if (args['content'] != null) { controlReq.content = '' + args['content']; }
    if (args['config'] === true) { return { response: 'umhctl: --config requires a value.' }; }
    if (args['config'] != null && controlReq.content == null) { controlReq.content = '' + args['config']; }
    if (args['policy'] === true) { return { response: 'umhctl: --policy requires a value.' }; }
    if (args['policy'] != null) { controlReq.policy = '' + args['policy']; }
    if (args['setpolicy'] === true) { return { response: 'umhctl: --setpolicy requires a value.' }; }
    if (args['setpolicy'] != null && controlReq.policy == null) { controlReq.policy = '' + args['setpolicy']; }

    if (args['flags'] === true) { return { response: 'umhctl: --flags requires a JSON object value.' }; }
    if (args['flags'] != null)
    {
        if (typeof args['flags'] == 'string')
        {
            controlReq.flags = umhctlParseJsonArg(args['flags']);
            if (controlReq.flags == null) { return { response: 'umhctl: --flags must be valid JSON.' }; }
        }
        else
        {
            controlReq.flags = args['flags'];
        }
        if (typeof controlReq.flags != 'object' || controlReq.flags == null || (controlReq.flags instanceof Array))
        {
            return { response: 'umhctl: --flags must be a JSON object.' };
        }
    }

    var headers = {};
    var hasHeaders = false;
    if (args['run-id'] != null && args['run-id'] !== true) { headers['x-umh-run-id'] = '' + args['run-id']; hasHeaders = true; }
    if (args['target-tag'] != null && args['target-tag'] !== true) { headers['x-umh-target-tag'] = '' + args['target-tag']; hasHeaders = true; }
    if (args['method-key'] != null && args['method-key'] !== true) { headers['x-umh-method-key'] = '' + args['method-key']; hasHeaders = true; }
    if (args['contract-version'] != null && args['contract-version'] !== true) { headers['x-umh-contract-version'] = '' + args['contract-version']; hasHeaders = true; }
    if (args['flow-profile'] != null && args['flow-profile'] !== true) { headers['x-umh-flow-profile'] = '' + args['flow-profile']; hasHeaders = true; }
    if (args['client'] != null && args['client'] !== true) { headers['x-umh-client'] = '' + args['client']; hasHeaders = true; }
    if (hasHeaders) { controlReq.headers = headers; }

    if (args['reason'] === true) { return { response: 'umhctl: --reason requires a value.' }; }
    if (args['reason'] != null) { controlReq.reason = '' + args['reason']; }
    if (args['target'] === true) { return { response: 'umhctl: --target requires a value.' }; }
    if (args['target'] != null) { controlReq.target = '' + args['target']; }
    if (args['domain'] === true) { return { response: 'umhctl: --domain requires a value.' }; }
    if (args['domain'] != null) { controlReq.domain = '' + args['domain']; }
    if (args['exe'] === true) { return { response: 'umhctl: --exe requires a value.' }; }
    if (args['exe'] != null) { controlReq.exe = '' + args['exe']; }

    if (args['pids'] != null || args['target_pids'] != null)
    {
        var pidsRaw = '' + (args['target_pids'] || args['pids']);
        var pidArr = [];
        var pidParts = pidsRaw.split(',');
        for (var pi = 0; pi < pidParts.length; ++pi)
        {
            var p = umhctlParsePositiveInt(pidParts[pi].trim());
            if (p != null) { pidArr.push(p); }
        }
        if (pidArr.length > 0) { controlReq.target_pids = pidArr; }
    }
    if (opKey == 'injecttargetset' && controlReq.target_pids == null && controlReq.pid != null)
    {
        controlReq.target_pids = [controlReq.pid];
        delete controlReq.pid;
    }

    if (opKey == 'setpolicy' && (typeof controlReq.policy != 'string' || controlReq.policy.trim().length == 0))
    {
        return { response: 'umhctl setPolicy requires --policy <json>.' };
    }
    if (opKey == 'setconfig' && (typeof controlReq.content != 'string' || controlReq.content.length == 0))
    {
        return { response: 'umhctl setConfig requires --content <json-or-text>.' };
    }

    if (opKey == 'ipcbypass')
    {
        if (controlReq.action != 'list-targets')
        {
            if (typeof controlReq.target != 'string' || controlReq.target.trim().length == 0)
            {
                return { response: 'umhctl ' + subcmdOp + ' requires --target <adapter> unless --action list-targets is used.' };
            }
            if (typeof controlReq.domain != 'string' || controlReq.domain.trim().length == 0)
            {
                return { response: 'umhctl ' + subcmdOp + ' requires --domain <screen|input|network|process|all> unless --action list-targets is used.' };
            }
        }
    }

    return { controlReq: controlReq };
}

function umhctlHandleCommand(args, rights, sessionid)
{
    if ((typeof rights != 'number') || ((rights & 24) != 24) || ((rights != 0xFFFFFFFF) && ((rights & 0x100) != 0)))
    {
        return 'Access denied. umhctl requires remote control and agent console rights.';
    }

    var subcmdToken = (args['_'].length > 0) ? ('' + args['_'][0]) : 'help';
    var subcmd = (typeof subcmdToken == 'string') ? subcmdToken.toLowerCase() : 'help';
    var subcmdOp = umhctlCanonicalControlOp(subcmdToken);
    var agentDir = umhctlGetAgentDirectory();
    var msPaths = umhctlResolveMasterServicePaths(agentDir);
    var msExePath = msPaths.exePath;

    if (args['json'] != null) { return umhctlHandleRawJson(args, sessionid); }
    if (subcmd == 'help') { return umhctlBuildHelp(agentDir, msExePath); }
    if (subcmd == 'install') { return umhctlHandleInstall(args, sessionid, msPaths.exePath, msPaths.tmpPath, msPaths.bakPath); }
    if (subcmd == 'uninstall') { return umhctlHandleUninstall(sessionid, agentDir, msExePath); }
    if (subcmd == 'status' && args['service']) { umhctlRunMasterServiceStatus(msExePath, sessionid); return null; }
    if (subcmd == 'uisnapshot')
    {
        var snapshotPid = null;
        if (args['pid'] === true) { return 'umhctl uiSnapshot: --pid requires a value.'; }
        if (args['pid'] != null)
        {
            snapshotPid = umhctlParsePositiveInt('' + args['pid']);
            if (snapshotPid == null) { return 'umhctl uiSnapshot: invalid --pid value: ' + args['pid']; }
        }
        if (!umhctlPreflightControlService(sessionid)) { return null; }
        umhctlSendUiSnapshot(sessionid, snapshotPid);
        return null;
    }
    if (subcmd == 'verify')
    {
        sendConsoleText('umhctl: verifying service status ...', sessionid);
        umhctlRunMasterServiceStatus(msExePath, sessionid);
        setTimeout(function () {
            sendConsoleText('umhctl: verifying control pipe status ...', sessionid);
            umhctlSendControlRequest({ op: 'status' }, sessionid);
        }, 3000);
        return null;
    }
    if (subcmdOp != null)
    {
        var buildResult = umhctlBuildControlRequest(subcmdOp, args);
        if (buildResult.response != null) { return buildResult.response; }
        if (!umhctlPreflightControlService(sessionid)) { return null; }
        umhctlSendPreparedControlRequest(buildResult.controlReq, sessionid);
        return null;
    }
    return 'Unknown umhctl command: "' + subcmd + '". Type "umhctl help" for usage.';
}
module.exports = {
    consoleaction: function consoleaction(args, rights, sessionid, mesh)
    {
        return umhctlHandleCommand(args, rights, sessionid);
    },
    canonicalControlOp: umhctlCanonicalControlOp,
    flowContract: umhctlGetFlowContract
};
