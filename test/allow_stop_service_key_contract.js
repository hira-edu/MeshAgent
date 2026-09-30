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
    assert(body.includes('const wchar_t* serviceKeyName = g_ServiceHostServiceName;'), `${functionName} must use the actual SCM service key`);
    assert(source.includes('StringCchCopyW(g_ServiceHostServiceName, _countof(g_ServiceHostServiceName), argv[0]);'), 'Service key must come from the SCM callback arguments');
    assert(body.includes('if (!serviceKeyName[0]) { return FALSE; }'), 'Missing SCM name must fail closed');
    assert(!body.includes('MeshService_GetServiceNameText()'), `${functionName} must not use MeshService_GetServiceNameText()`);
}

function main() {
    const repoRoot = path.resolve(__dirname, '..');
    const launcher = fs.readFileSync(path.join(repoRoot, 'meshservice', 'ServiceMain.c'), 'utf8');
    assert(!launcher.includes('MeshService_AllowStop('), 'Launcher must not retain a separate SCM stop policy');
    assert(!launcher.includes('StartServiceCtrlDispatcher'), 'Launcher must not register an alternate SCM dispatcher');
    verifyUsesServiceKey(path.join(repoRoot, 'meshservice', 'service_host.c'), 'ServiceHost_AllowStop');
    process.stdout.write(JSON.stringify({ success: true }, null, 2) + '\n');
}

main();
