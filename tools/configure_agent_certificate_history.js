'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');

const refreshState = new WeakMap();

function certificateHashes(pem) {
    if (typeof pem === 'string' && /PRIVATE KEY/.test(pem)) throw Error('Public certificate input contains a private key');
    const cert = new crypto.X509Certificate(pem);
    const hashes = [crypto.createHash('sha384').update(cert.raw).digest('hex')];
    if (cert.publicKey.asymmetricKeyType === 'rsa') {
        hashes.push(crypto.createHash('sha384').update(cert.publicKey.export({type: 'pkcs1', format: 'der'})).digest('hex'));
    }
    return hashes;
}

function endpointCertificate(address) {
    const url = new URL(address);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw Error('Expected an operator-designated HTTPS endpoint');
    return new Promise((resolve, reject) => {
        let timer;
        const socket = tls.connect({host: url.hostname, servername: url.hostname, port: Number(url.port || 443), rejectUnauthorized: true}, () => {
            clearTimeout(timer);
            try {
                if (!socket.authorized) throw Error('Unverified endpoint certificate');
                const raw = socket.getPeerCertificate().raw;
                if (!raw) throw Error('Missing endpoint certificate');
                const hashes = certificateHashes(raw);
                socket.end();
                resolve(hashes);
            } catch (error) { socket.destroy(); reject(error); }
        });
        timer = setTimeout(() => socket.destroy(Error('Endpoint certificate request timed out')), 15000);
        socket.setTimeout(15000, () => socket.destroy(Error('Endpoint certificate request timed out')));
        socket.on('error', error => { clearTimeout(timer); reject(error); });
    });
}

async function refreshDomain(domain) {
    if (!domain || !Array.isArray(domain.agentwebcerturls) || !domain.agentwebcerturls.length || domain.agentwebcerturls.length > 16) return false;
    const now = Date.now(), state = refreshState.get(domain);
    if (state && (state.busy || now - state.lastAttempt < 120000)) return false;
    const nextState = {busy: true, lastAttempt: now};
    refreshState.set(domain, nextState);
    try {
        const pins = new Set(Array.isArray(domain.agentwebcerthashes) ? domain.agentwebcerthashes.filter(pin => typeof pin === 'string' && /^[a-f0-9]{96}$/i.test(pin) && !/^0+$/.test(pin)).map(pin => pin.toLowerCase()) : []);
        const before = pins.size;
        const results = await Promise.all(domain.agentwebcerturls.map(async endpoint => {
            try { return await endpointCertificate(endpoint); }
            catch (error) { console.log('[AGENT_CERT_HISTORY_REFRESH_FAILURE] domain=' + domain.id + ' error=' + (error.code || 'invalid_endpoint')); return []; }
        }));
        for (const hashes of results) for (const hash of hashes) {
            if (pins.size < 4096) pins.add(hash);
        }
        if (pins.size === before) return false;
        domain.agentwebcerthashes = [...pins];
        return true;
    } finally { nextState.busy = false; }
}

async function main(argv) {
    const args = {certificates: [], endpoints: [], domain: ''};
    for (let i = 0; i < argv.length; i += 2) {
        const value = argv[i + 1];
        if (value === undefined) throw Error('Missing argument value');
        if (argv[i] === '--config') args.config = value;
        else if (argv[i] === '--history-dir') args.historyDir = value;
        else if (argv[i] === '--domain') args.domain = value;
        else if (argv[i] === '--certificate') args.certificates.push(value);
        else if (argv[i] === '--endpoint') args.endpoints.push(value);
        else throw Error('Unknown argument: ' + argv[i]);
    }
    if (!args.config || (!args.historyDir && !args.certificates.length && !args.endpoints.length)) throw Error('Specify --config and trusted public certificate sources');
    const configPath = path.resolve(args.config);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const domain = config.domains && config.domains[args.domain];
    if (!domain || typeof domain !== 'object') throw Error('Domain not found');
    for (const section of [config.settings, domain]) {
        for (const [key, value] of Object.entries(section || {})) {
            if (key.toLowerCase() === 'ignoreagenthashcheck' && value !== false) throw Error('Certificate/signature checks must remain enabled');
        }
    }
    const pins = new Set();
    const existing = domain.agentwebcerthashes || domain.agentWebCertHashes || [];
    if (!Array.isArray(existing)) throw Error('Historical certificate pins must be an array');
    for (const pin of existing) {
        if (typeof pin !== 'string' || !/^[a-f0-9]{96}$/i.test(pin) || /^0+$/.test(pin)) throw Error('Invalid historical certificate pin');
        pins.add(pin.toLowerCase());
    }
    if (args.historyDir) {
        for (const name of fs.readdirSync(args.historyDir).sort()) {
            if (/^webserver-cert-public\.crt(?:$|[.-])/.test(name)) args.certificates.push(path.join(args.historyDir, name));
        }
    }
    const sources = [];
    for (const filename of args.certificates) {
        const stat = fs.lstatSync(filename);
        if (!stat.isFile() || stat.isSymbolicLink()) throw Error('Expected a regular public certificate file');
        const hashes = certificateHashes(fs.readFileSync(filename, 'utf8'));
        hashes.forEach(hash => pins.add(hash));
        sources.push({certificate: path.basename(filename), hashes});
    }
    for (const endpoint of args.endpoints) {
        const hashes = await endpointCertificate(endpoint);
        hashes.forEach(hash => pins.add(hash));
        sources.push({endpoint, hashes});
    }
    if (!pins.size) throw Error('No trusted certificate hashes collected');
    const sorted = [...pins].sort();
    const existingUrls = domain.agentwebcerturls || [];
    if (!Array.isArray(existingUrls)) throw Error('Historical certificate URLs must be an array');
    const urls = [...new Set([...existingUrls, ...args.endpoints])].sort();
    if (urls.length > 16) throw Error('At most 16 historical certificate endpoints are supported');
    for (const endpoint of urls) {
        const url = new URL(endpoint);
        if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw Error('Invalid historical certificate URL');
    }
    if (JSON.stringify(existing) === JSON.stringify(sorted) && JSON.stringify(existingUrls) === JSON.stringify(urls)) {
        console.log(JSON.stringify({changed: false, domain: args.domain, pins: sorted.length, sources}));
        return;
    }
    const stat = fs.lstatSync(configPath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw Error('Expected a regular config file');
    const backupDir = path.join(path.dirname(configPath), 'certificate-history-backups');
    fs.mkdirSync(backupDir, {recursive: true, mode: 0o700});
    const backupStat = fs.lstatSync(backupDir);
    if (!backupStat.isDirectory() || backupStat.isSymbolicLink()) throw Error('Expected a private backup directory');
    if (process.platform !== 'win32') fs.chmodSync(backupDir, 0o700);
    const backup = path.join(backupDir, 'config-' + Date.now() + '-' + process.pid + '.json');
    fs.writeFileSync(backup, fs.readFileSync(configPath), {flag: 'wx', mode: 0o600});
    delete domain.agentWebCertHashes;
    domain.agentwebcerthashes = sorted;
    domain.agentwebcerturls = urls;
    const temporary = configPath + '.certificate-history-' + process.pid;
    try {
        fs.writeFileSync(temporary, JSON.stringify(config, null, 2) + '\n', {flag: 'wx', mode: 0o600});
        if (process.platform !== 'win32') fs.chownSync(temporary, stat.uid, stat.gid);
        fs.chmodSync(temporary, stat.mode & 0o777);
        fs.renameSync(temporary, configPath);
    } finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
    console.log(JSON.stringify({changed: true, domain: args.domain, pins: sorted.length, backup, sources}));
}

if (require.main === module) main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = {certificateHashes, endpointCertificate, refreshDomain};
