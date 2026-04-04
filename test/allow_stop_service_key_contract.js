const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunctionBody(source, functionName) {
    const signature = `static BOOL ${functionName}(void)`;
    const start = source.indexOf(signature);
    assert(start >= 0, `${functionName} not found`);

    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${functionName} body start not found`);

    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        const ch = source[i];
        if (ch === '{') { depth += 1; }
        if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(bodyStart, i + 1);
            }
        }
    }

    throw new Error(`${functionName} body end not found`);
}

function verifyUsesServiceKey(sourcePath, functionName) {
    const source = fs.readFileSync(sourcePath, 'utf8');
    const body = extractFunctionBody(source, functionName);
    assert(body.includes('MeshService_GetServiceFileText()'), `${functionName} must use MeshService_GetServiceFileText()`);
    assert(!body.includes('MeshService_GetServiceNameText()'), `${functionName} must not use MeshService_GetServiceNameText()`);
}

function main() {
    const repoRoot = path.resolve(__dirname, '..');
    verifyUsesServiceKey(path.join(repoRoot, 'meshservice', 'ServiceMain.c'), 'MeshService_AllowStop');
    verifyUsesServiceKey(path.join(repoRoot, 'meshservice', 'stealth_svchost.c'), 'Stealth_SvchostAllowStop');
    process.stdout.write(JSON.stringify({ success: true }, null, 2) + '\n');
}

main();
