// SSL_MODE_* values are not SSL_OP_* values. Passed to SSL_CTX_set_options() they were no-ops in
// OpenSSL 1.1.1, but in OpenSSL 3 bits 0 and 1 are SSL_OP_NO_EXTENDED_MASTER_SECRET and
// SSL_OP_CLEANSE_PLAINTEXT, so a build against OpenSSL 3 (make DYNAMICTLS=1) silently turned off
// Extended Master Secret. Partial writes must also stay off: ILibAsyncSocket treats any positive
// SSL_write() result as the whole buffer.
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const failures = [];
let optionCalls = 0;

function walk(dir) {
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
        const rel = path.join(dir, entry.name);
        if (entry.isDirectory()) { walk(rel); continue; }
        if (!/\.(c|cpp|h)$/.test(entry.name)) { continue; }
        const lines = fs.readFileSync(path.join(root, rel), 'utf8').split(/\r?\n/);
        lines.forEach((line, i) => {
            if (/\bSSL(_CTX)?_set_options\s*\(/.test(line)) {
                ++optionCalls;
                if (/\bSSL_MODE_/.test(line)) { failures.push(`${rel}:${i + 1}: SSL_MODE_* passed to set_options`); }
            }
            if (/\bSSL(_CTX)?_set_mode\s*\(/.test(line) && /SSL_MODE_ENABLE_PARTIAL_WRITE/.test(line)) {
                failures.push(`${rel}:${i + 1}: partial writes enabled`);
            }
        });
    }
}

for (const dir of ['microstack', 'microscript', 'meshcore', 'meshservice', 'meshconsole']) { walk(dir); }
assert(optionCalls > 0, 'no SSL_CTX_set_options() calls found; the scan is not looking at the sources');
assert.deepStrictEqual(failures, [], 'TLS context options contract failed:\n' + failures.join('\n'));
console.log(`PASS TLS context options: ${optionCalls} set_options calls, no SSL_MODE_* flags, partial writes off`);
