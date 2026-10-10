#!/usr/bin/env node
'use strict';

// Operator-only bootstrap for an identity-verified legacy agent. This launches a
// staged updater; the updater still owns every migration/pre-stop safety gate.
// No package transfer, service change, wait, retry, or arbitrary command support.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function absoluteFile(value) {
    if (typeof value !== 'string' || !/^[A-Za-z]:\\/.test(value) || /[\x00-\x1f"/]/.test(value)) throw Error('source-exe must be an absolute local Windows path');
    const parts = value.slice(3).split('\\');
    if (parts.length < 2 || parts.some(p => !p || p === '.' || p === '..' || /[:*?<>|]/.test(p) || /[ .]$/.test(p) || /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p))) throw Error('Unsafe source-exe path');
    if (!/\.exe$/i.test(value)) throw Error('source-exe must end in .exe');
    return value;
}
function validate(config) {
    const c = { ...config };
    let url; try { url = new URL(c.controlUrl); } catch (_) { throw Error('Invalid control-url'); }
    if (url.protocol !== 'wss:' || url.pathname !== '/control.ashx' || url.username || url.password || url.search || url.hash) throw Error('control-url must be wss://host/control.ashx without credentials or query');
    if (!/^user\/[^/]*\/[^/]+$/.test(c.loginUser || '')) throw Error('login-user must be a full user ID');
    if (!/^node\/[^/]*\/[^/]+$/.test(c.nodeId || '')) throw Error('node-id must be a full node ID');
    for (const field of ['expectedNodeIdentity', 'sourceSha384', 'dllSha384', 'mshSha384']) {
        if (!/^[a-fA-F0-9]{96}$/.test(c[field] || '')) throw Error(field + ' must contain 96 hexadecimal characters');
        c[field] = c[field].toLowerCase();
    }
    c.sourceExe = absoluteFile(c.sourceExe);
    c.timeoutMs = c.timeoutMs === undefined ? 45000 : Number(c.timeoutMs);
    if (!Number.isInteger(c.timeoutMs) || c.timeoutMs < 1000 || c.timeoutMs > 180000) throw Error('timeout-ms must be 1000..180000');
    return c;
}

// Kept self-contained so fixtures execute precisely the expression sent to the
// endpoint. Use the legacy runtime's ES5 syntax and its native buffer API.
function remoteBootstrap(c, state) {
    var g = require('_GenericMarshal'), k = g.CreateNativeProxy('kernel32.dll');
    var a = g.CreateNativeProxy('advapi32.dll'), f = require('fs'), sep = String.fromCharCode(92);
    function fail(message) { throw new Error(message); }
    if (String(require('_agentNodeId')()).toLowerCase() !== c.expectedNodeIdentity) fail('Endpoint identity mismatch');
    if (g.PointerSize !== 4 && g.PointerSize !== 8) fail('Unsupported pointer size');
    ['GetModuleFileNameW', 'GetFileAttributesW', 'GetDriveTypeW', 'CreateFileW', 'GetFinalPathNameByHandleW', 'CreateProcessW', 'CloseHandle', 'LocalFree', 'GetLastError'].forEach(function (n) { k.CreateMethod(n); });
    ['GetNamedSecurityInfoW', 'GetSecurityDescriptorDacl', 'GetSecurityDescriptorControl', 'ConvertSecurityDescriptorToStringSecurityDescriptorW'].forEach(function (n) { a.CreateMethod(n); });
    function wide(s) { return g.CreateVariable(s, { wide: true }); }
    function pointerPresent(p) {
        var b = p.toBuffer(); for (var i = 0; i < g.PointerSize; ++i) { if (b[i] !== 0) return true; }
        return false;
    }
    function parent(p) { return p.substring(0, p.lastIndexOf(sep)); }
    function inside(p, root) { p = p.toLowerCase(); root = root.toLowerCase(); return p === root || p.indexOf(root + sep) === 0; }
    var stage = parent(c.sourceExe), host = g.CreateVariable(8192);
    var hostLength = k.GetModuleFileNameW(0, host, 4096).Val;
    if (!hostLength || hostLength >= 4096) fail('Cannot resolve current process image');
    var installed = process.execPath;
    if (typeof installed !== 'string' || !/^[A-Za-z]:\\/.test(installed) || !/^[A-Za-z]:\\/.test(host.Wide2UTF8)) fail('Cannot resolve installed paths');
    if (inside(stage, parent(installed)) || inside(stage, parent(host.Wide2UTF8))) fail('Staging must be outside the installed agent and process directories');
    if (k.GetDriveTypeW(wide(c.sourceExe.substring(0, 3))).Val !== 3) fail('Staging must use a fixed local drive');
    function attributes(p, directory) {
        var value = k.GetFileAttributesW(wide(p)).Val >>> 0;
        if (value === 4294967295 || (value & 1024) !== 0 || Boolean(value & 16) !== directory) fail('Unsafe or unavailable staging path');
    }
    var components = stage.slice(3).split(sep), ancestor = stage.substring(0, 3);
    attributes(ancestor, true);
    for (var n = 0; n < components.length; ++n) {
        ancestor += (ancestor.charAt(ancestor.length - 1) === sep ? '' : sep) + components[n];
        attributes(ancestor, true);
    }
    function finalPath(p) {
        // Resolve drive aliases/short names by handle. This does not classify or
        // authorize the installed host; it only prevents staging inside it.
        var handle = k.CreateFileW(wide(p), 0, 7, 0, 3, 35651584, 0);
        if (handle.Val === 0 || handle.Val === -1 || handle.Val === 4294967295) fail('Cannot resolve staging boundary');
        try {
            var buffer = g.CreateVariable(8192);
            var length = k.GetFinalPathNameByHandleW(handle, buffer, 4096, 1).Val;
            if (!length || length >= 4096 || !/^\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\/.test(buffer.Wide2UTF8)) fail('Cannot resolve staging volume path');
            return buffer.Wide2UTF8;
        } finally { k.CloseHandle(handle); }
    }
    var resolvedStage = finalPath(stage);
    if (inside(resolvedStage, parent(finalPath(installed))) || inside(resolvedStage, parent(finalPath(host.Wide2UTF8)))) fail('Staging aliases an installed directory');
    function security(p, directory) {
        var sd = g.CreatePointer(), dacl = g.CreatePointer(), output = g.CreatePointer();
        var present = g.CreateVariable(4), defaulted = g.CreateVariable(4), control = g.CreateVariable(2), revision = g.CreateVariable(4);
        sd.toBuffer().fill(0); output.toBuffer().fill(0); dacl.toBuffer().fill(0);
        // OWNER + DACL: an unprivileged owner could otherwise replace the DACL.
        var error = a.GetNamedSecurityInfoW(wide(p), 1, 5, 0, 0, 0, 0, sd).Val;
        if (error !== 0 || !pointerPresent(sd)) fail('Staging security descriptor unavailable: ' + p);
        try {
            if (!a.GetSecurityDescriptorDacl(sd.Deref(), present, dacl, defaulted).Val || !present.toBuffer().readUInt32LE(0) || !pointerPresent(dacl)) fail('Staging requires a non-null DACL: ' + p);
            if (!a.GetSecurityDescriptorControl(sd.Deref(), control, revision).Val) fail('Cannot inspect staging DACL protection: ' + p);
            if (directory && !(control.toBuffer().readUInt16LE(0) & 4096)) fail('Staging DACL must be protected: ' + p);
            if (!a.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd.Deref(), 1, 5, output, 0).Val || !pointerPresent(output)) fail('Cannot inspect staging ACL: ' + p);
            var sddl = output.Deref().Wide2UTF8;
            function aclFail() { fail('Staging ACL must grant only SYSTEM and Administrators full access: ' + p + '; observedSDDL=' + String(sddl).slice(0, 1024)); }
            // Compare ACE meaning rather than serialization order or optional
            // auto-inheritance flags. Nonprotected files are safe here only
            // with exactly these two effective grants in the protected stage.
            var descriptor = /^O:(SY|BA|S-1-5-18|S-1-5-32-544)D:((?:P|AI|AR)*)(.*)$/.exec(sddl);
            if (!descriptor || (directory && descriptor[2].indexOf('P') < 0)) aclFail();
            var aces = descriptor[3].match(/\([^()]*\)/g), seen = {};
            if (!aces || aces.length !== 2 || aces.join('') !== descriptor[3]) aclFail();
            for (var x = 0; x < aces.length; ++x) {
                var ace = aces[x].slice(1, -1).split(';');
                if (ace.length !== 6 || ace[0] !== 'A' || ace[3] || ace[4]) aclFail();
                if (ace[2] !== 'FA' && !(/^0x[0-9a-f]+$/i.test(ace[2]) && parseInt(ace[2], 16) === 2032127)) aclFail();
                var flags = ace[1].match(/OI|CI|ID/g) || [], flagSet = {};
                if (flags.join('') !== ace[1]) aclFail();
                for (var y = 0; y < flags.length; ++y) { if (flagSet[flags[y]]) aclFail(); flagSet[flags[y]] = true; }
                if (directory ? (!flagSet.OI || !flagSet.CI) : (flagSet.OI || flagSet.CI)) aclFail();
                var trustee = ace[5] === 'SY' || ace[5] === 'S-1-5-18' ? 'SY' : ace[5] === 'BA' || ace[5] === 'S-1-5-32-544' ? 'BA' : '';
                if (!trustee || seen[trustee]) aclFail();
                seen[trustee] = true;
            }
        } finally {
            if (pointerPresent(output)) k.LocalFree(output.Deref());
            k.LocalFree(sd.Deref());
        }
    }
    security(stage, true);
    var files = [c.sourceExe, c.sourceExe.slice(0, -4) + '.dll', c.sourceExe.slice(0, -4) + '.msh'];
    var hashes = [c.sourceSha384, c.dllSha384, c.mshSha384];
    for (var j = 0; j < files.length; ++j) {
        attributes(files[j], false); security(files[j], false);
        var bytes = f.readFileSync(files[j]);
        if (!bytes.length || require('SHA384Stream').create().syncHash(bytes).toString('hex').toLowerCase() !== hashes[j]) fail('Staged package hash mismatch');
    }
    // Recheck pathname security after reading all package members. Privileged
    // administrators remain trusted; these checks do not claim atomic locking.
    security(stage, true);
    for (var q = 0; q < files.length; ++q) attributes(files[q], false);
    var si = g.CreateVariable(g.PointerSize === 8 ? 104 : 68), pi = g.CreateVariable(g.PointerSize === 8 ? 24 : 16);
    si.toBuffer().fill(0); si.toBuffer().writeUInt32LE(si._size, 0); pi.toBuffer().fill(0);
    var command = '"' + c.sourceExe + '" -update --quiet';
    state.launchAttempted = true;
    if (!k.CreateProcessW(wide(c.sourceExe), wide(command), 0, 0, 0, 134217728, 0, wide(stage), si, pi).Val) {
        state.launchAttempted = false;
        fail('Updater process creation failed: ' + k.GetLastError().Val);
    }
    var pid = pi.toBuffer().readUInt32LE(g.PointerSize * 2);
    k.CloseHandle(pi.Deref(g.PointerSize, g.PointerSize).Deref());
    k.CloseHandle(pi.Deref(0, g.PointerSize).Deref());
    return { launched: true, updated: false, pid: pid, waitedForChild: false, sourceExe: c.sourceExe };
}

function buildExpression(config, marker) {
    const c = validate(config);
    const payload = { expectedNodeIdentity: c.expectedNodeIdentity, sourceExe: c.sourceExe, sourceSha384: c.sourceSha384, dllSha384: c.dllSha384, mshSha384: c.mshSha384 };
    const body = '(' + remoteBootstrap.toString() + ')(' + JSON.stringify(payload) + ',state)';
    // Legacy console tokenization does not reliably decode escaped paths/quotes.
    const encoded = Buffer.from(body).toString('base64');
    return "(function(){var state={launchAttempted:false};try{return {marker:'" + marker + "',ok:true,result:eval(Buffer.from('" + encoded + "','base64').toString())};}catch(e){return {marker:'" + marker + "',ok:false,error:String(e),launchAttempted:state.launchAttempted};}})()";
}
function cookie(key, user) {
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key.subarray(0, 32), iv);
    const payload = { userid: user, domainid: user.split('/')[1], time: Math.floor(Date.now() / 1000) };
    const data = Buffer.concat([cipher.update(JSON.stringify(payload)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64').replace(/\+/g, '@').replace(/\//g, '$');
}
function launch(config, key, WebSocket) {
    const c = validate(config);
    if (!Buffer.isBuffer(key) || key.length !== 80) throw Error('Key must contain 80 bytes');
    const marker = 'LEGACY_BOOTSTRAP_' + crypto.randomBytes(16).toString('hex');
    const expression = buildExpression(c, marker), url = new URL(c.controlUrl);
    url.searchParams.set('auth', cookie(key, c.loginUser));
    return new Promise((resolve, reject) => {
        let ws, done = false, submitted = false;
        const timer = setTimeout(() => finish(Error('Timed out awaiting correlated launch result')), c.timeoutMs);
        function finish(error, result, knownState) {
            if (done) return; done = true; clearTimeout(timer);
            if (ws) { try { ws.terminate(); } catch (_) {} }
            if (error) { error.submitted = submitted; error.launchState = knownState || (submitted ? 'unknown' : 'not-submitted'); reject(error); }
            else resolve({ ...result, nodeId: c.nodeId, submitted: true });
        }
        try { ws = new WebSocket(url.toString(), { rejectUnauthorized: true, handshakeTimeout: 15000 }); }
        catch (_) { finish(Error('Control transport could not be opened')); return; }
        ws.on('open', () => {
            submitted = true;
            try { ws.send(JSON.stringify({ action: 'msg', nodeid: c.nodeId, type: 'console', value: 'eval ' + JSON.stringify(expression) }), error => { if (error) finish(Error('Control send failed')); }); }
            catch (_) { finish(Error('Control send failed')); }
        });
        ws.on('error', () => finish(Error('Control connection or TLS verification failed')));
        ws.on('close', () => finish(Error('Control connection closed before correlated result')));
        ws.on('message', raw => {
            if (done) return;
            let message, value;
            try { message = JSON.parse(raw.toString()); } catch (_) { return; }
            if (message.action === 'close') { finish(Error('Server rejected control session')); return; }
            if (message.action !== 'msg' || message.type !== 'console' || message.nodeid !== c.nodeId || typeof message.value !== 'string') return;
            try { value = JSON.parse(message.value); } catch (_) { return; }
            if (!value || value.marker !== marker) return;
            if (value.ok !== true) { finish(Error('Endpoint rejected bootstrap: ' + String(value.error).slice(0, 2048)), null, value.launchAttempted === false ? 'not-launched' : undefined); return; }
            const result = value.result;
            if (!result || result.launched !== true || result.updated !== false || result.waitedForChild !== false || !Number.isInteger(result.pid) || result.pid <= 0 || result.sourceExe !== c.sourceExe) { finish(Error('Invalid correlated launch result')); return; }
            finish(null, result);
        });
    });
}
function parseArgs(argv) {
    const fields = { 'control-url':'controlUrl', 'login-user':'loginUser', 'keyfile':'keyfile', 'node-id':'nodeId', 'expected-node-identity':'expectedNodeIdentity', 'source-exe':'sourceExe', 'source-sha384':'sourceSha384', 'dll-sha384':'dllSha384', 'msh-sha384':'mshSha384', 'timeout-ms':'timeoutMs' }, out = {};
    for (let i = 0; i < argv.length; i += 2) {
        const name = argv[i].slice(2), field = fields[name];
        if (!argv[i].startsWith('--') || !field || out[field] !== undefined || !argv[i + 1] || argv[i + 1].startsWith('--')) throw Error('Unknown, duplicate, or missing CLI option');
        out[field] = argv[i + 1];
    }
    if (!out.keyfile) throw Error('--keyfile is required');
    return validate(out);
}
async function main() {
    const c = parseArgs(process.argv.slice(2));
    const keyText = fs.readFileSync(c.keyfile, 'utf8').trim();
    if (!/^[a-fA-F0-9]{160}$/.test(keyText)) throw Error('keyfile must contain 160 hexadecimal characters');
    const WebSocket = require(require.resolve('ws', { paths: [process.cwd(), path.resolve(__dirname, '../../MeshCentral')] }));
    console.log(JSON.stringify(await launch(c, Buffer.from(keyText, 'hex'), WebSocket)));
}
if (require.main === module) main().catch(error => { console.error(JSON.stringify({ ok: false, error: error.message, submitted: error.submitted || false, launchState: error.launchState || 'not-submitted' })); process.exitCode = 1; });
module.exports = { validate, parseArgs, buildExpression, launch };
