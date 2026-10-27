// MongoDB administration for the duplicate server, using the wrapper's own driver
// (mongodb@4.17.2, the version production runs). Secrets are read from a file,
// never from the command line.
//
// node mongo_admin.js <driverDir> <secretsFile> <command> [args...]
//   init <db>...   create the admin user (localhost exception) and the app user
//   dropdb <db>    drop one duplicate database
//   ping           authenticate as admin and print the server version
//   shutdown       shut mongod down cleanly
'use strict';

const fs = require('fs');
const path = require('path');

function fail(message) {
    console.error('mongo_admin: ' + message);
    process.exit(1);
}

const [driverDir, secretsFile, command, ...rest] = process.argv.slice(2);
if (!driverDir || !secretsFile || !command) { fail('usage: mongo_admin.js <driverDir> <secretsFile> <command> [args...]'); }
const { MongoClient } = require(path.join(driverDir, 'mongodb'));
const secrets = JSON.parse(fs.readFileSync(secretsFile, 'utf8'));
for (const key of ['host', 'port', 'adminUser', 'adminPassword', 'appUser', 'appPassword']) {
    if (secrets[key] == null || secrets[key] === '') { fail('secrets file lacks ' + key); }
}
const base = 'mongodb://' + secrets.host + ':' + secrets.port + '/';
const adminUrl = 'mongodb://' + encodeURIComponent(secrets.adminUser) + ':' + encodeURIComponent(secrets.adminPassword) +
    '@' + secrets.host + ':' + secrets.port + '/?authSource=admin&directConnection=true';
const allowedDb = /^meshcentral_dup[AB]$/;

async function withClient(url, fn) {
    const client = new MongoClient(url, { serverSelectionTimeoutMS: 15000, directConnection: true });
    await client.connect();
    try { return await fn(client); } finally { await client.close(); }
}

async function init(dbs) {
    if (dbs.length === 0) { fail('init needs at least one database name'); }
    for (const db of dbs) { if (!allowedDb.test(db)) { fail('refusing database name ' + db); } }
    // The localhost exception allows exactly one thing: creating the first user.
    await withClient(base + '?directConnection=true', async (client) => {
        await client.db('admin').command({ createUser: secrets.adminUser, pwd: secrets.adminPassword, roles: [{ role: 'root', db: 'admin' }] });
    });
    await withClient(adminUrl, async (client) => {
        const roles = [];
        for (const db of dbs) { roles.push({ role: 'readWrite', db }, { role: 'dbAdmin', db }); }
        await client.db('admin').command({ createUser: secrets.appUser, pwd: secrets.appPassword, roles });
        const info = await client.db('admin').command({ usersInfo: 1 });
        console.log('users: ' + info.users.map((u) => u.user).sort().join(', '));
    });
}

async function main() {
    if (command === 'init') { return init(rest); }
    if (command === 'ping') {
        return withClient(adminUrl, async (client) => {
            const info = await client.db('admin').command({ buildInfo: 1 });
            console.log('mongod version ' + info.version);
        });
    }
    if (command === 'dropdb') {
        if (rest.length !== 1 || !allowedDb.test(rest[0])) { fail('dropdb needs one duplicate database name'); }
        return withClient(adminUrl, async (client) => {
            const dropped = await client.db(rest[0]).dropDatabase();
            console.log('dropped ' + rest[0] + ': ' + dropped);
        });
    }
    if (command === 'shutdown') {
        const client = new MongoClient(adminUrl, { serverSelectionTimeoutMS: 15000, directConnection: true });
        await client.connect();
        try {
            await client.db('admin').command({ shutdown: 1 });
        } catch (ex) {
            // mongod closes the socket while answering shutdown; anything else is a failure.
            if (!/closed|ECONNRESET|interrupted|connection/i.test(String(ex && ex.message))) { throw ex; }
            console.log('shutdown acknowledged by connection close: ' + ex.message);
        }
        await client.close(true).catch((ex) => console.log('client close after shutdown: ' + ex.message));
        return;
    }
    fail('unknown command ' + command);
}

main().catch((ex) => fail(ex && ex.stack ? ex.stack : String(ex)));
