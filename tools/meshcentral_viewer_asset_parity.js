#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function sha256(text) {
    return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function desktopAssetChecks(text) {
    return {
        oldStandardSameSizeGuardAbsent: !text.includes('if ((obj.ScreenWidth == width) && (obj.ScreenHeight == height)) return;'),
        oldMinifiedSameSizeGuardAbsent: !text.includes('n.ScreenWidth!=e||n.ScreenHeight!=t'),
        remoteInputRefreshPresent: text.includes('SendRemoteInputLock')
    };
}

function redirAssetChecks(text) {
    return {
        omitsCustomDesktopSyncHelper: !text.includes('xxSendInitialDesktopSync'),
        kvmConnectDefersConnectedState:
            text.includes('if (obj.protocol != 2) { obj.xxStateChange(3); }') ||
            text.includes('2!=r.protocol&&r.xxStateChange(3)'),
        transportHandshakeStillSendsProtocol:
            text.includes('obj.socket.send(obj.protocol);') ||
            text.includes('r.socket.send(r.protocol)')
    };
}

function allChecksPass(checks) {
    return Object.values(checks).every(Boolean);
}

async function fetchText(url) {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) {
        throw new Error(`${url} returned HTTP ${response.status}`);
    }
    return response.text();
}

async function main() {
    const args = parseArgs(process.argv);
    const server = String(args.server || process.env.MESH_SERVER_HTTP_URL || 'https://high.support').replace(/\/+$/, '');
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const localRoot = path.resolve('..', 'MeshCentral');
    const assets = [
        {
            name: 'agent-desktop-0.0.2.js',
            localPath: path.join(localRoot, 'public', 'scripts', 'agent-desktop-0.0.2.js'),
            url: `${server}/scripts/agent-desktop-0.0.2.js`,
            check: desktopAssetChecks
        },
        {
            name: 'agent-desktop-0.0.2-min.js',
            localPath: path.join(localRoot, 'public', 'scripts', 'agent-desktop-0.0.2-min.js'),
            url: `${server}/scripts/agent-desktop-0.0.2-min.js`,
            check: desktopAssetChecks
        },
        {
            name: 'agent-redir-ws-0.1.1.js',
            localPath: path.join(localRoot, 'public', 'scripts', 'agent-redir-ws-0.1.1.js'),
            url: `${server}/scripts/agent-redir-ws-0.1.1.js`,
            check: redirAssetChecks
        },
        {
            name: 'agent-redir-ws-0.1.1-min.js',
            localPath: path.join(localRoot, 'public', 'scripts', 'agent-redir-ws-0.1.1-min.js'),
            url: `${server}/scripts/agent-redir-ws-0.1.1-min.js`,
            check: redirAssetChecks
        }
    ];

    const report = {
        generatedUtc: new Date().toISOString(),
        server,
        assets: []
    };

    for (const asset of assets) {
        const localText = fs.readFileSync(asset.localPath, 'utf8');
        const servedText = await fetchText(asset.url);
        const localHash = sha256(localText);
        const servedHash = sha256(servedText);
        const checks = asset.check(servedText);
        report.assets.push({
            name: asset.name,
            localPath: asset.localPath,
            url: asset.url,
            localHash,
            servedHash,
            hashMatch: localHash === servedHash,
            servedLength: servedText.length,
            checks
        });
    }

    report.success = report.assets.every((asset) => asset.hashMatch && allChecksPass(asset.checks));

    if (evidenceDir) {
        ensureDir(evidenceDir);
        fs.writeFileSync(path.join(evidenceDir, 'meshcentral_viewer_asset_parity.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SERVER=${report.server}`,
            `SUCCESS=${report.success}`,
            ...report.assets.map((asset) => [
                `ASSET=${asset.name}`,
                `LOCAL_SHA256=${asset.localHash}`,
                `SERVED_SHA256=${asset.servedHash}`,
                `HASH_MATCH=${asset.hashMatch}`,
                `CHECKS=${Object.entries(asset.checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
            ].join('\n'))
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }

    process.exit(report.success ? 0 : 2);
}

main().catch((error) => {
    process.stderr.write((error && error.stack) ? error.stack : String(error));
    process.stderr.write('\n');
    process.exit(1);
});
