'use strict';
// One phase of the D27 database compatibility run (dup_dbcompat.py drives the phases).
//
//   node dbcompat.js <secretsFile> <reportFile> <dbjsDir> <phase> [--seed n,days,eventsPerDay,powerPerDay,statsMinutes]
//                    [--drop-list] [--filter] [--write131field] [--mongolog <mongod.log>]
//
// Opens a layout's own db.js (MeshCentral 1.2.5 from layout A, the 1.3.1 fork from layout B) against the
// scratch database meshcentral_dupcompat on the duplicate's mongod, exactly as the server does (CreateDB,
// SetupDatabase), and records: the time until the index set settles (db.js creates and drops indexes
// without callbacks, so the set is read until no index build runs and it stops changing), the index set,
// the "Resetting ..." lines, reads that every version must answer the same way, the device-list plan, and
// mongod's own index-build log lines for this phase. --seed writes synthetic data sized like production
// (no production data). --drop-list drops exactly the indexes 1.3.1 adds (docs/DEPLOYMENT.md) before
// CreateDB. Refuses any database other than meshcentral_dupcompat on 127.0.0.1:27018.
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const [secretsFile, reportFile, dbjsDirArg, phase] = process.argv.slice(2, 6);
const flags = process.argv.slice(6);
function flag(name) { const i = flags.indexOf('--' + name); return i < 0 ? null : (flags[i + 1] || ''); }
const has = name => flags.includes('--' + name);
function fail(message) { process.stderr.write('dbcompat: ' + message + '\n'); process.exit(1); }
if (!secretsFile || !reportFile || !dbjsDirArg || !phase) { fail('usage: dbcompat.js <secretsFile> <reportFile> <dbjsDir> <phase> [options]'); }

const DBNAME = 'meshcentral_dupcompat';
const secrets = JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
if (secrets.host !== '127.0.0.1' || secrets.port !== 27018) { fail('the duplicate mongod must be 127.0.0.1:27018'); }
const uri = 'mongodb://' + encodeURIComponent(secrets.appUser) + ':' + encodeURIComponent(secrets.appPassword) +
    '@127.0.0.1:27018/' + DBNAME + '?authSource=admin';
const dbjsDir = path.resolve(dbjsDirArg);
const { MongoClient } = require(require.resolve('mongodb', { paths: [dbjsDir] }));

// 1.3.1 adds these (deploy/tests/db-mongodb-indexes.test.js pins the same set); docs/DEPLOYMENT.md lists them
// as the rollback drop list. plugins.TypeAndName1 is optional there; it is dropped too so 1.2.5 sees no 1.3.1 index.
const DROP_LIST = { meshcentral: ['TypeDomainMeshNameCollation1', 'TypeDomainIdNameCollation1', 'Domain1', 'TypeDomainNode1'],
    events: ['DomainIdsTime1', 'DomainUserTime1', 'DomainUserActionTime1'], power: ['Domain1'], plugins: ['TypeAndName1'] };

const logs = [];
const origLog = console.log;
console.log = function () { logs.push(Array.from(arguments).join(' ')); };
console.error = function () { logs.push('ERR ' + Array.from(arguments).join(' ')); };
process.on('unhandledRejection', e => { logs.push('UNHANDLED REJECTION ' + (e && e.message)); });
const warnings = [];
const wait = ms => new Promise(r => setTimeout(r, ms));
const cb = fn => new Promise(resolve => fn((err, v) => resolve({ err: err ? String(err) : null, v })));
const now = Date.now();

// Deterministic synthetic data (a seeded PRNG), so every run seeds the same database.
let seed = 0x5eed1234;
function rand() { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) / 4294967296; }
function pick(list) { return list[Math.floor(rand() * list.length)]; }
const MESHES = Array.from({ length: 8 }, (_, i) => 'mesh//' + crypto.createHash('sha256').update('mesh' + i).digest('hex').slice(0, 64));
const USERS = ['admin', 'support1', 'support2', 'support3', 'auditor'].map(u => 'user//' + u);
function nodeId(i) { return 'node//' + crypto.createHash('sha384').update('node' + i).digest('base64').replace(/\+/g, '@').replace(/\//g, '$').slice(0, 64); }

async function seedRaw(db, spec) {
    const [nodes, days, eventsPerDay, powerPerDay, statsMinutes] = spec;
    const out = {};
    const events = db.collection('events'), power = db.collection('power'), stats = db.collection('serverstats');
    const actions = ['agentconnect', 'agentdisconnect', 'wssessioncount', 'relaylog', 'nodechange', 'login', 'runcommands', 'chat'];
    let batch = [], total = 0;
    const span = days * 86400000 - 3600000; // inside the 20-day events TTL
    for (let i = 0; i < days * eventsPerDay; i++) {
        const n = Math.floor(rand() * nodes), userid = pick(USERS), action = pick(actions);
        batch.push({ etype: (action === 'login') ? 'user' : 'node', action, domain: '', nodeid: nodeId(n), userid, username: userid.slice(6),
            ids: [nodeId(n), MESHES[n % MESHES.length], userid], time: new Date(now - Math.floor(rand() * span)),
            msg: 'synthetic ' + action + ' event ' + i, msgid: 10 + Math.floor(rand() * 120), h: crypto.createHash('md5').update(String(i)).digest('hex') });
        if (batch.length === 5000) { await events.insertMany(batch, { ordered: false }); total += batch.length; batch = []; }
    }
    if (batch.length) { await events.insertMany(batch, { ordered: false }); total += batch.length; }
    out.events = total;
    batch = []; total = 0;
    const powerDays = Math.min(days, 9); // inside the 10-day power TTL
    for (let i = 0; i < powerDays * powerPerDay; i++) {
        batch.push({ time: new Date(now - Math.floor(rand() * powerDays * 86400000)), nodeid: nodeId(Math.floor(rand() * nodes)), power: pick([0, 1, 1, 1]), oldPower: pick([0, 1]) });
        if (batch.length === 5000) { await power.insertMany(batch, { ordered: false }); total += batch.length; batch = []; }
    }
    if (batch.length) { await power.insertMany(batch, { ordered: false }); total += batch.length; }
    out.power = total;
    batch = []; total = 0;
    for (let t = now - 29 * 86400000; t < now; t += statsMinutes * 60000) {
        batch.push({ time: new Date(t), expire: new Date(t + 30 * 86400000), mem: { rss: 200000000 + Math.floor(rand() * 1e8), heapTotal: 1e8, heapUsed: 8e7 },
            conn: { ca: Math.floor(rand() * 50), cu: 1, us: 2, rs: 0 }, cpu: [rand(), rand(), rand()], s: 'synthetic' });
        if (batch.length === 5000) { await stats.insertMany(batch, { ordered: false }); total += batch.length; batch = []; }
    }
    if (batch.length) { await stats.insertMany(batch, { ordered: false }); total += batch.length; }
    out.serverstats = total;
    return out;
}

async function seedRecords(mc, nodes) {
    const names = ['alpha', 'Bravo', 'charlie', 'DELTA', 'echo', 'Foxtrot', 'golf', 'Golf', 'hotel', 'India_X', 'juliet', 'KILO'];
    for (const u of USERS) {
        await cb(f => mc.Set({ _id: u, type: 'user', domain: '', name: u.slice(6), email: u.slice(6) + '@dup.invalid', creation: 1,
            links: Object.fromEntries(MESHES.map(m => [m, { rights: 0xFFFFFFFF }])) }, f));
    }
    for (const m of MESHES) { await cb(f => mc.Set({ _id: m, type: 'mesh', domain: '', name: 'group ' + m.slice(6, 12), mtype: 2, links: { 'user//admin': { rights: 0xFFFFFFFF } } }, f)); }
    for (let i = 0; i < nodes; i++) {
        await cb(f => mc.Set({ _id: nodeId(i), type: 'node', domain: '', meshid: MESHES[i % MESHES.length], name: names[i % names.length] + '-' + i,
            host: '10.' + (i >> 8) + '.' + (i & 255) + '.1', icon: 1, agent: { id: 4, ver: 0, caps: 31, core: 'MeshCore v6' }, osdesc: 'Windows 11' }, f));
    }
    return { users: USERS.length, meshes: MESHES.length, nodes };
}

async function indexSnapshot(db) {
    const out = {};
    for (const col of (await db.listCollections().toArray()).map(x => x.name).sort()) {
        out[col] = (await db.collection(col).indexes()).map(ix => ix.name + (ix.expireAfterSeconds != null ? '(ttl ' + ix.expireAfterSeconds + ')' : '') +
            (ix.collation ? '(' + ix.collation.locale + '/' + ix.collation.strength + ')' : '')).sort();
    }
    return out;
}

// The app user may see only its own operations; db.js's createIndexes and dropIndexes run on its connections
// and stay in progress until their index builds finish.
async function buildsInProgress(admin) {
    const ops = await admin.command({ currentOp: 1, $ownOps: true });
    return (ops.inprog || []).filter(op => (op.ns || '').startsWith(DBNAME + '.') &&
        /createIndexes|dropIndexes/.test(JSON.stringify(op.command || {}))).length;
}

// db.js issues createIndex/dropIndexes without callbacks. The set has settled when no build runs and two reads
// 250 ms apart agree; the time is measured from just before CreateDB.
async function settle(client, t0) {
    const db = client.db(DBNAME), admin = client.db('admin');
    let last = null, same = 0, snap = null, polls = 0;
    const deadline = Date.now() + 600000;
    while (Date.now() < deadline) {
        polls++;
        snap = await indexSnapshot(db);
        const busy = await buildsInProgress(admin);
        const key = JSON.stringify(snap);
        if (busy === 0 && key === last) { if (++same >= 2) break; } else { same = 0; last = key; }
        await wait(250);
    }
    return { indexes: snap, settledMs: Date.now() - t0 - 500, polls };
}

function mongodIndexLines(logFile, offset) {
    if (!logFile || !fs.existsSync(logFile)) return null;
    const fd = fs.openSync(logFile, 'r');
    const size = fs.fstatSync(fd).size;
    const buffer = Buffer.alloc(Math.max(0, size - offset));
    fs.readSync(fd, buffer, 0, buffer.length, offset);
    fs.closeSync(fd);
    const lines = [];
    for (const line of buffer.toString('utf8').split('\n')) {
        if (!line.includes(DBNAME) || !/Index build|dropIndexes|Dropping index|createIndexes/i.test(line)) continue;
        try {
            const entry = JSON.parse(line);
            lines.push({ t: entry.t && entry.t.$date, msg: entry.msg, ns: entry.attr && (entry.attr.namespace || entry.attr.ns || (entry.attr.collectionName)),
                index: entry.attr && (entry.attr.index || entry.attr.indexName || (entry.attr.indexes && JSON.stringify(entry.attr.indexes)) || (entry.attr.spec && entry.attr.spec.name)),
                durationMillis: entry.attr && entry.attr.durationMillis });
        } catch (ex) { lines.push({ raw: line.slice(0, 300) }); }
    }
    return lines;
}

(async function main() {
    const report = { phase, node: process.version, dbjs: dbjsDir, version: JSON.parse(fs.readFileSync(path.join(dbjsDir, 'package.json'), 'utf8')).version };
    const logFile = flag('mongolog');
    const logOffset = (logFile && fs.existsSync(logFile)) ? fs.statSync(logFile).size : 0;
    const client = await MongoClient.connect(uri, { directConnection: true });
    const db = client.db(DBNAME);
    if (has('seed')) {
        const t = Date.now();
        report.seededRaw = await seedRaw(db, flag('seed').split(',').map(Number));
        report.seedRawMs = Date.now() - t;
    }
    if (has('drop-list')) {
        report.dropped = [];
        const t = Date.now();
        for (const [col, names] of Object.entries(DROP_LIST)) {
            const existing = (await db.listCollections({ name: col }).toArray()).length ? (await db.collection(col).indexes()).map(ix => ix.name) : [];
            for (const name of names) {
                if (!existing.includes(name)) { report.dropped.push({ col, name, present: false }); continue; }
                const t1 = Date.now();
                await db.collection(col).dropIndex(name);
                report.dropped.push({ col, name, present: true, ms: Date.now() - t1 });
            }
        }
        report.dropListMs = Date.now() - t;
    }
    report.indexesBefore = await indexSnapshot(db);

    const datapath = path.join(path.dirname(reportFile), 'dbcompat-datapath');
    fs.mkdirSync(datapath, { recursive: true });
    const parent = {
        args: { mongodb: uri, mongodbname: DBNAME, dbrecordsencryptkey: 'duplicate-scratch-records-key' },
        config: { settings: { mongodb: uri, mongodbname: DBNAME, plugins: { enabled: true, list: ['nativeruntime'] } }, domains: { '': {} } },
        datapath, parentpath: datapath, platform: process.platform, crypto,
        debug: function () { }, addServerWarning: m => warnings.push(String(m)), getConfigFilePath: f => path.join(datapath, f),
        webserver: { meshes: {}, users: {}, userGroups: {} }, DispatchEvent: function () { }
    };
    const t0 = Date.now();
    const mc = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('CreateDB did not call back within 120 s')), 120000);
        require(path.join(dbjsDir, 'db.js')).CreateDB(parent, function (d) { clearTimeout(timer); resolve(d); });
    });
    report.createDbMs = Date.now() - t0;
    report.schemaVersion = await new Promise(r => mc.SetupDatabase(r));
    const settled = await settle(client, t0);
    report.indexSettleMs = settled.settledMs;
    report.indexes = settled.indexes;
    report.resetLines = logs.filter(l => /Resetting/.test(l));
    if (has('seed')) {
        const t = Date.now();
        report.seededRecords = await seedRecords(mc, flag('seed').split(',').map(Number)[0]);
        report.seedRecordsMs = Date.now() - t;
    }

    // Reads every version must answer the same way.
    const users = await cb(f => mc.GetAllType('user', f));
    report.users = users.err || users.v.map(u => u._id + ':' + u.email).sort();
    const nodes = await cb(f => mc.GetAllType('node', f));
    report.nodeCount = nodes.err || nodes.v.length;
    report.nodeDigest = nodes.err ? null : crypto.createHash('sha256').update(JSON.stringify(nodes.v.map(n => [n._id, n.name, n.meshid, n.host]).sort())).digest('hex');
    const page = await cb(f => mc.GetAllTypeNoTypeFieldMeshFiltered(MESHES, null, '', 'node', null, 0, 10, f));
    report.deviceListPage1 = page.err || page.v.map(x => x.name);
    const count = await cb(f => mc.CountAllTypeNoTypeFieldMeshFiltered(MESHES, null, '', 'node', null, f));
    report.deviceCount = count.err || count.v;
    if (has('filter')) {
        const golf = await cb(f => mc.GetAllTypeNoTypeFieldMeshFiltered(MESHES, null, '', 'node', null, 0, 500, 'GOLF', f));
        report.filterGolf = golf.err || golf.v.length;
        const meta = await cb(f => mc.GetAllTypeNoTypeFieldMeshFiltered(MESHES, null, '', 'node', null, 0, 500, '.*(', f));
        report.filterRegexMeta = meta.err || meta.v.length;
    }
    const events = await cb(f => mc.GetEventsWithLimit([MESHES[0]], '', 10000, null, f));
    report.meshEventsLimited = events.err || events.v.length;
    const userEvents = await cb(f => mc.GetUserEventsWithLimit([MESHES[1]], '', 'user//support1', 1000, null, f));
    report.userEventsLimited = userEvents.err || (userEvents.v && userEvents.v.length);
    const nodeEvents = await cb(f => mc.GetNodeEventsWithLimit(nodeId(7), '', 500, null, f));
    report.nodeEventsLimited = nodeEvents.err || nodeEvents.v.length;
    const powerline = await cb(f => mc.getPowerTimeline(nodeId(3), f));
    report.powerNode3 = powerline.err || powerline.v.length;
    report.counts = {};
    for (const col of ['meshcentral', 'events', 'power', 'serverstats', 'plugins']) { report.counts[col] = await db.collection(col).countDocuments(); }
    if (has('write131field')) {
        const one = nodes.v[0];
        one.defaultRouteIp = '10.9.9.9';
        await cb(f => mc.Set(one, f));
    }
    const back = await cb(f => mc.Get(nodes.v[0]._id, f));
    report.firstNodeDefaultRouteIp = back.err || (back.v[0] && back.v[0].defaultRouteIp) || null;
    // The device list query #8158's collation index serves, and the event query 1.3.1's DomainIdsTime1 serves.
    const plan = async (cursor) => {
        const explain = await cursor.explain('executionStats');
        const text = JSON.stringify(explain.queryPlanner.winningPlan);
        return { stages: Array.from(new Set((text.match(/"stage":"[A-Z_]+"/g) || []).map(s => s.slice(9, -1)))),
            index: (text.match(/"indexName":"([^"]+)"/) || [])[1] || null, docsExamined: explain.executionStats.totalDocsExamined,
            ms: explain.executionStats.executionTimeMillis };
    };
    report.deviceListPlan = await plan(db.collection('meshcentral').find({ type: 'node', domain: '', meshid: { $in: MESHES } }).collation({ locale: 'en', strength: 2 }).sort({ name: 1 }).limit(10));
    report.eventListPlan = await plan(db.collection('events').find({ domain: '', ids: { $in: [MESHES[0]] } }).sort({ time: -1 }).limit(1000));
    await wait(500);
    report.mongodIndexLog = mongodIndexLines(logFile, logOffset);
    // mongod's own clock: from the first index drop or build of this phase to the last completed build.
    const stamps = (report.mongodIndexLog || []).filter(l => l.t && /^(CMD: dropIndexes|Index build: registering|Index build: completed successfully)$/.test(l.msg));
    const builds = stamps.filter(l => l.msg === 'Index build: completed successfully');
    report.mongodIndexWindowMs = (stamps.length && builds.length) ? (Date.parse(builds[builds.length - 1].t) - Date.parse(stamps[0].t)) : 0;
    report.mongodIndexBuilds = builds.length;
    report.logs = logs.filter(l => !/^\s*$/.test(l)).slice(0, 200);
    report.warnings = warnings;
    await client.close();
    fs.writeFileSync(reportFile, JSON.stringify(report, null, 2) + '\n');
    origLog(JSON.stringify({ phase, version: report.version, node: report.node, indexSettleMs: report.indexSettleMs, resetLines: report.resetLines }));
    process.exit(0);
})().catch(e => { fail((e && e.stack) || String(e)); });
