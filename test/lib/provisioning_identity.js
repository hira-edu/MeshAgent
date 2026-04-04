const fs = require('fs');

const EMBEDDED_MSH_GUID = Buffer.from('b996015880544a19b7f7e9be44914c19', 'hex');

function parseKvText(text) {
    const result = {};
    for (const rawLine of String(text || '').split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) { continue; }

        const idx = line.indexOf('=');
        if (idx <= 0) { continue; }

        const key = line.substring(0, idx).trim();
        const value = line.substring(idx + 1).trim();
        result[key] = value;
    }
    return result;
}

function extractEmbeddedMsh(exePath) {
    const buffer = fs.readFileSync(exePath);
    if (buffer.length < 20) {
        throw new Error(`File too small to contain embedded provisioning: ${exePath}`);
    }

    const guidOffset = buffer.length - 16;
    const embeddedGuid = buffer.subarray(guidOffset);
    if (!embeddedGuid.equals(EMBEDDED_MSH_GUID)) {
        throw new Error(`Embedded provisioning GUID not found in ${exePath}`);
    }

    const lengthOffset = buffer.length - 20;
    const mshLength = buffer.readUInt32BE(lengthOffset);
    if (mshLength <= 0 || (lengthOffset - mshLength) < 0) {
        throw new Error(`Invalid embedded provisioning length in ${exePath}`);
    }

    const start = lengthOffset - mshLength;
    return buffer.subarray(start, lengthOffset).toString('utf8');
}

function normalizeUrl(value) {
    return value ? String(value).trim() : null;
}

function normalizeHex(value) {
    return value ? String(value).replace(/^0x/i, '').trim().toLowerCase() : null;
}

function normalizeFallback(value) {
    if (!value) { return []; }
    return String(value)
        .split('|')
        .map((item) => item.trim())
        .filter(Boolean);
}

function buildIdentityFromKv(label, kv) {
    return {
        label,
        meshName: kv.MeshName || kv.meshName || null,
        meshServer: normalizeUrl(kv.MeshServer || kv.serverUrl || null),
        serverId: normalizeHex(kv.ServerID || kv.serverId || null),
        meshId: normalizeHex(kv.MeshID || kv.meshId || null),
        fallbackEndpoints: normalizeFallback(kv.fallbackEndpoints || kv.FallbackEndpoints || null)
    };
}

function buildIdentityFromBranding(label, config) {
    const provisioning = config.provisioning || {};
    const network = config.network || {};
    const primary = network.primaryEndpoint || (typeof provisioning.serverUrl === 'string' ? provisioning.serverUrl.split(/\s+/)[0] : null);
    const fallbackEndpoints = Array.isArray(network.fallbackEndpoints)
        ? network.fallbackEndpoints.map((item) => item && item.url).filter(Boolean)
        : [];
    return {
        label,
        meshName: provisioning.meshName || null,
        meshServer: normalizeUrl(primary),
        serverId: normalizeHex(provisioning.serverId || (config.security && config.security.serverCertHash) || null),
        meshId: normalizeHex(provisioning.meshId || null),
        fallbackEndpoints
    };
}

function compareIdentity(left, right) {
    const mismatches = [];
    if ((left.meshName || null) !== (right.meshName || null)) {
        mismatches.push({ field: 'MeshName', left: left.meshName, right: right.meshName });
    }
    if ((left.meshServer || null) !== (right.meshServer || null)) {
        mismatches.push({ field: 'MeshServer', left: left.meshServer, right: right.meshServer });
    }
    if ((left.serverId || null) !== (right.serverId || null)) {
        mismatches.push({ field: 'ServerID', left: left.serverId, right: right.serverId });
    }
    if ((left.meshId || null) !== (right.meshId || null)) {
        mismatches.push({ field: 'MeshID', left: left.meshId, right: right.meshId });
    }

    const leftFallback = JSON.stringify(left.fallbackEndpoints || []);
    const rightFallback = JSON.stringify(right.fallbackEndpoints || []);
    if (leftFallback !== rightFallback) {
        mismatches.push({ field: 'fallbackEndpoints', left: left.fallbackEndpoints || [], right: right.fallbackEndpoints || [] });
    }

    return {
        left: left.label,
        right: right.label,
        match: mismatches.length === 0,
        mismatches
    };
}

function loadIdentityFromKvFile(filePath, label) {
    return buildIdentityFromKv(label, parseKvText(fs.readFileSync(filePath, 'utf8')));
}

function loadIdentityFromEmbeddedExe(exePath, label) {
    const text = extractEmbeddedMsh(exePath);
    return {
        text,
        identity: buildIdentityFromKv(label, parseKvText(text))
    };
}

module.exports = {
    EMBEDDED_MSH_GUID,
    parseKvText,
    extractEmbeddedMsh,
    normalizeUrl,
    normalizeHex,
    normalizeFallback,
    buildIdentityFromKv,
    buildIdentityFromBranding,
    compareIdentity,
    loadIdentityFromKvFile,
    loadIdentityFromEmbeddedExe
};
