#!/usr/bin/env node

const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function requiredEnv(name) {
    const value = process.env[name];
    if (value == null || value.length === 0) {
        throw new Error(`${name} is required`);
    }
    return value;
}

function encodeCookie(payload, key) {
    payload.time = Math.floor(Date.now() / 1000);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
    const crypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), crypted]).toString('base64').replace(/\+/g, '@').replace(/\//g, '$');
}

function compressionPacket() {
    const packet = Buffer.alloc(10);
    packet.writeUInt16BE(5, 0);
    packet.writeUInt16BE(10, 2);
    packet[4] = 1; // JPEG
    packet[5] = 50;
    packet.writeUInt16BE(1024, 6);
    packet.writeUInt16BE(100, 8);
    return packet;
}

function parseCommand(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 4) { return null; }
    let command = buffer.readUInt16BE(0);
    let size = buffer.readUInt16BE(2);
    let offset = 0;
    if (command === 27 && size === 8 && buffer.length >= 10) {
        size = (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
        command = buffer.readUInt16BE(8);
        offset = 8;
    }
    return { command, size, offset };
}

function rawMessageBuffer(message) {
    if (Buffer.isBuffer(message)) { return message; }
    if (message instanceof ArrayBuffer) { return Buffer.from(message); }
    if (ArrayBuffer.isView(message)) { return Buffer.from(message.buffer, message.byteOffset, message.byteLength); }
    if (typeof message === 'string') { return Buffer.from(message, 'latin1'); }
    return Buffer.from(String(message), 'latin1');
}

function snapshotLocalBridgeHelpers() {
    if (process.platform !== 'win32') { return { supported: false, helpers: [] }; }
    return {
        supported: false,
        error: 'Local bridge-helper snapshot requires a native probe; script-host process enumeration is disabled by the rundll32-only contract.',
        helpers: []
    };
}

function helperPidSet(snapshot) {
    const pids = new Set();
    for (const helper of (snapshot && Array.isArray(snapshot.helpers) ? snapshot.helpers : [])) {
        const pid = Number(helper.ProcessId);
        if (Number.isFinite(pid) && pid > 0) { pids.add(pid); }
    }
    return pids;
}

function diffHelperSnapshots(before, after) {
    const beforePids = helperPidSet(before);
    const afterPids = helperPidSet(after);
    const started = [];
    const exited = [];
    for (const pid of afterPids) {
        if (!beforePids.has(pid)) { started.push(pid); }
    }
    for (const pid of beforePids) {
        if (!afterPids.has(pid)) { exited.push(pid); }
    }
    return { started, exited };
}

function safeArtifactDirectory() {
    const artifactDir = process.env.MESH_KVM_PROBE_ARTIFACT_DIR;
    if (artifactDir == null || artifactDir.length === 0) { return null; }
    const resolved = path.resolve(artifactDir);
    fs.mkdirSync(resolved, { recursive: true });
    return resolved;
}

function picturePayload(buffer, parsed) {
    const payloadOffset = parsed.offset + 8;
    if (buffer.length <= payloadOffset) { return null; }
    return buffer.subarray(payloadOffset);
}

function picturePayloadEvidence(buffer, parsed, ordinal, artifactDir) {
    const payload = picturePayload(buffer, parsed);
    if (payload == null) {
        return { ordinal, payloadBytes: 0, jpegStart: false, jpegEnd: false };
    }

    const sample = {
        ordinal,
        payloadOffset: parsed.offset + 8,
        payloadBytes: payload.length,
        sha256: crypto.createHash('sha256').update(payload).digest('hex'),
        jpegStart: payload.length >= 2 && payload[0] === 0xFF && payload[1] === 0xD8,
        jpegEnd: payload.length >= 2 && payload[payload.length - 2] === 0xFF && payload[payload.length - 1] === 0xD9
    };

    if (artifactDir != null) {
        const fileName = `picture-${String(ordinal).padStart(4, '0')}.jpg`;
        fs.writeFileSync(path.join(artifactDir, fileName), payload);
        sample.file = fileName;
    }
    return sample;
}

function main() {
    const serverUrl = process.env.MESH_SERVER_URL || 'wss://high.support';
    const nodeid = requiredEnv('MESH_NODEID');
    const loginKey = Buffer.from(requiredEnv('MESH_LOGIN_KEY'), 'hex');
    const username = process.env.MESH_LOGIN_USER || 'hsadmin';
    const domainid = process.env.MESH_LOGIN_DOMAIN || '';
    const durationMs = Number(process.env.MESH_KVM_PROBE_MS || 20000);
    const artifactDir = safeArtifactDirectory();
    const maxPictureSamples = Number(process.env.MESH_KVM_PROBE_PICTURE_SAMPLES || 3);
    const options = { rejectUnauthorized: false };
    const auth = encodeCookie({ userid: `user/${domainid}/${username}`, domainid }, loginKey);
    const tunnelId = crypto.randomBytes(6).toString('hex');
    const result = {
        startedUtc: new Date().toISOString(),
        serverUrl,
        nodeid,
        tunnelId,
        controlOpen: false,
        relayOpen: false,
        receivedConnectMarker: false,
        state3AtUtc: null,
        screenPackets: 0,
        screenSizes: [],
        picturePackets: 0,
        pictureBytes: 0,
        picturePayloadJpegPackets: 0,
        picturePayloadNonJpegPackets: 0,
        picturePayloadSamples: [],
        copyPackets: 0,
        displayPackets: 0,
        cursorPackets: 0,
        binaryPackets: 0,
        binaryBytes: 0,
        textFramedBinaryPackets: 0,
        textFramedBinaryBytes: 0,
        textMessages: [],
        errors: [],
        closeEvents: [],
        localBridgeHelpersBefore: snapshotLocalBridgeHelpers(),
        localBridgeHelpersAfter: null,
        localBridgeHelperDelta: null
    };

    let control = null;
    let relay = null;
    let finished = false;
    let refreshSent = false;

    function closeSocketsAfterViewerClose(code) {
        try { if (relay != null && relay.readyState === WebSocket.OPEN) { relay.close(); } } catch (e) { }
        try { if (control != null && control.readyState === WebSocket.OPEN) { control.close(); } } catch (e) { }
        setTimeout(() => {
            result.localBridgeHelpersAfter = snapshotLocalBridgeHelpers();
            result.localBridgeHelperDelta = diffHelperSnapshots(result.localBridgeHelpersBefore, result.localBridgeHelpersAfter);
            process.stdout.write(JSON.stringify(result, null, 2) + '\n');
            process.exit(result.success ? 0 : (code || 2));
        }, Number(process.env.MESH_KVM_PROBE_CLEANUP_SETTLE_MS || 1500));
    }

    function finish(code) {
        if (finished) { return; }
        finished = true;
        result.endedUtc = new Date().toISOString();
        result.durationMs = Date.parse(result.endedUtc) - Date.parse(result.startedUtc);
        result.success = result.relayOpen &&
            result.receivedConnectMarker &&
            result.screenPackets > 0 &&
            result.picturePackets > 0 &&
            result.durationMs >= Math.min(durationMs, 12000);
        if (process.env.MESH_KVM_PROBE_VIEWER_CLOSE === '1' && relay != null && relay.readyState === WebSocket.OPEN) {
            try {
                result.sentViewerClose = true;
                relay.send(JSON.stringify({ ctrlChannel: '102938', type: 'close' }));
            } catch (e) {
                result.errors.push(`viewer-close:${e.message}`);
            }
            setTimeout(() => closeSocketsAfterViewerClose(code), Number(process.env.MESH_KVM_PROBE_VIEWER_CLOSE_SETTLE_MS || 250));
        } else {
            closeSocketsAfterViewerClose(code);
        }
    }

    control = new WebSocket(`${serverUrl}/control.ashx?auth=${encodeURIComponent(auth)}`, options);
    control.on('open', () => {
        result.controlOpen = true;
        control.send(JSON.stringify({ action: 'authcookie' }));
    });
    control.on('error', (error) => {
        result.errors.push(`control:${error.message}`);
        finish(3);
    });
    control.on('close', (code, reason) => {
        result.closeEvents.push({ side: 'control', code, reason: reason.toString() });
    });
    control.on('message', (raw) => {
        let data = null;
        try { data = JSON.parse(raw.toString()); } catch (e) { return; }
        if (data.action === 'authcookie') {
            const relayValue = `*/meshrelay.ashx?p=2&nodeid=${nodeid}&id=${tunnelId}&rauth=${data.rcookie}`;
            control.send(JSON.stringify({
                action: 'msg',
                nodeid,
                type: 'tunnel',
                usage: 2,
                value: relayValue,
                responseid: 'kvm-live-test'
            }));

            const relayUrl = `${serverUrl}/meshrelay.ashx?browser=1&p=2&nodeid=${encodeURIComponent(nodeid)}&id=${tunnelId}&auth=${encodeURIComponent(data.cookie)}`;
            relay = new WebSocket(relayUrl, options);
            relay.on('open', () => { result.relayOpen = true; });
            relay.on('error', (error) => {
                result.errors.push(`relay:${error.message}`);
                finish(4);
            });
            relay.on('close', (code, reason) => {
                result.closeEvents.push({ side: 'relay', code, reason: reason.toString() });
                if (!finished) { finish(5); }
            });
            relay.on('message', (message, isBinary) => {
                const buffer = rawMessageBuffer(message);
                if (!isBinary) {
                    const text = Buffer.isBuffer(message) ? message.toString('latin1') : String(message);
                    if (text === 'c' || text === 'cr') {
                        result.receivedConnectMarker = true;
                        result.state3AtUtc = new Date().toISOString();
                        relay.send('2');
                        return;
                    }
                    try {
                        const controlMessage = JSON.parse(text);
                        if (controlMessage != null && controlMessage.ctrlChannel == '102938' && controlMessage.type === 'ping') {
                            relay.send('{"ctrlChannel":"102938","type":"pong"}');
                        } else if (controlMessage != null && controlMessage.ctrlChannel == '102938' && controlMessage.type === 'rtt') {
                            relay.send(text);
                        }
                    } catch (e) { }

                    const parsedTextFrame = parseCommand(buffer);
                    if (parsedTextFrame != null) {
                        result.textFramedBinaryPackets++;
                        result.textFramedBinaryBytes += buffer.length;
                        handleKvmPacket(buffer, parsedTextFrame);
                        return;
                    }

                    result.textMessages.push(text.slice(0, 160));
                    return;
                }

                result.binaryPackets++;
                result.binaryBytes += buffer.length;
                const parsed = parseCommand(buffer);
                if (parsed == null) { return; }
                handleKvmPacket(buffer, parsed);
            });
        } else if (data.responseid === 'kvm-live-test') {
            result.controlResponse = data;
        } else if (data.action === 'close') {
            result.errors.push(`control-close:${JSON.stringify(data)}`);
            finish(6);
        }
    });
    setTimeout(() => finish(0), durationMs);

    function handleKvmPacket(buffer, parsed) {
        if (parsed.command === 7 && buffer.length >= parsed.offset + 8) {
            result.screenPackets++;
            result.screenSizes.push({
                width: buffer.readUInt16BE(parsed.offset + 4),
                height: buffer.readUInt16BE(parsed.offset + 6)
            });
            if (!refreshSent) {
                refreshSent = true;
                relay.send(compressionPacket());
                relay.send(Buffer.from([0, 8, 0, 5, 0])); // unpause
                relay.send(Buffer.from([0, 6, 0, 4])); // refresh
            }
        } else if (parsed.command === 3) {
            result.picturePackets++;
            result.pictureBytes += buffer.length;
            const retainSample = result.picturePayloadSamples.length < maxPictureSamples;
            const sample = picturePayloadEvidence(buffer, parsed, result.picturePackets, retainSample ? artifactDir : null);
            if (sample.jpegStart) {
                result.picturePayloadJpegPackets++;
            } else {
                result.picturePayloadNonJpegPackets++;
            }
            if (retainSample) {
                result.picturePayloadSamples.push(sample);
            }
        } else if (parsed.command === 4) {
            result.copyPackets++;
        } else if (parsed.command === 11 || parsed.command === 82) {
            result.displayPackets++;
        } else if (parsed.command === 88 || parsed.command === 89) {
            result.cursorPackets++;
        }
    }
}

try {
    main();
} catch (error) {
    process.stderr.write((error && error.stack ? error.stack : String(error)) + '\n');
    process.exit(1);
}
