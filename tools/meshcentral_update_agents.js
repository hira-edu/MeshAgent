#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const meshCentralRepo = path.resolve(__dirname, '..', '..', 'MeshCentral');
const minimist = require(path.join(meshCentralRepo, 'node_modules', 'minimist'));
const WebSocket = require(path.join(meshCentralRepo, 'node_modules', 'ws'));
const args = minimist(process.argv.slice(2));

function fail(message) {
    console.error(message);
    process.exit(1);
}

function normalizeUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
        fail('Missing --url');
    }
    let url = rawUrl.trim();
    if (url.endsWith('/')) { url = url.slice(0, -1); }
    if (url.endsWith('/control.ashx') === false) { url += '/control.ashx'; }
    return url;
}

function encodeCookie(payload, key) {
    payload.time = Math.floor(Date.now() / 1000);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
    const crypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), crypted]).toString('base64').replace(/\+/g, '@').replace(/\//g, '$');
}

function loadNodeIds() {
    if (typeof args['nodeids-file'] === 'string') {
        const raw = fs.readFileSync(args['nodeids-file'], 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) === false || parsed.length === 0) {
            fail('nodeids file must contain a non-empty JSON array');
        }
        return parsed;
    }
    if (typeof args.nodeids === 'string') {
        const nodeids = args.nodeids.split(',').map((value) => value.trim()).filter(Boolean);
        if (nodeids.length === 0) { fail('No node IDs supplied'); }
        return nodeids;
    }
    fail('Missing --nodeids-file or --nodeids');
}

function loadLoginKey() {
    if (typeof args.loginkeyfile !== 'string') {
        fail('Missing --loginkeyfile');
    }
    const hex = fs.readFileSync(args.loginkeyfile, 'utf8').replace(/\s+/g, '');
    const key = Buffer.from(hex, 'hex');
    if (key.length !== 80) {
        fail('Invalid login key length');
    }
    return key;
}

const url = normalizeUrl(args.url);
const loginUser = typeof args.loginuser === 'string' ? args.loginuser : 'hsadmin';
const loginDomain = typeof args.logindomain === 'string' ? args.logindomain : '';
const nodeids = loadNodeIds();
const loginKey = loadLoginKey();
const authCookie = encodeCookie({ userid: `user/${loginDomain}/${loginUser}`, domainid: loginDomain }, loginKey);
const controlUrl = `${url}${url.includes('?') ? '&' : '?'}auth=${authCookie}`;

let completed = false;
const ws = new WebSocket(controlUrl);

function succeed() {
    if (completed) { return; }
    completed = true;
    console.log(JSON.stringify({ ok: true, count: nodeids.length, nodeids }));
    ws.close();
    setTimeout(() => process.exit(0), 50);
}

ws.on('open', function onOpen() {
    ws.send(JSON.stringify({ action: 'updateAgents', nodeids, responseid: 'meshagent-update' }));
    setTimeout(succeed, 500);
});

ws.on('message', function onMessage(data) {
    let msg = null;
    try { msg = JSON.parse(data); } catch (ex) { return; }
    if (msg && msg.action === 'close' && msg.cause === 'noauth') {
        fail(`MeshCentral authentication failed: ${msg.msg || 'noauth'}`);
    }
});

ws.on('error', function onError(err) {
    fail(err.message || 'WebSocket error');
});

ws.on('close', function onClose() {
    if (completed === false) {
        fail('MeshCentral control channel closed before updateAgents completed');
    }
});
