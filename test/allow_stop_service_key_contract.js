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
    assert(body.includes('g_ServiceHostServiceName'), `${functionName} must use the SCM-provided service key`);
    assert(source.includes('ServiceHost_AcceptScmName(dwArgc, lpszArgv)'), 'SCM name must be populated from service-main arguments');
    assert(!body.includes('MeshService_GetServiceNameText()'), `${functionName} must not use MeshService_GetServiceNameText()`);
}

function main() {
    const repoRoot = path.resolve(__dirname, '..');
    const deliveryExe = fs.readFileSync(path.join(repoRoot, 'meshservice', 'ServiceMain.c'), 'utf8');
    assert(!deliveryExe.includes('MeshService_AllowStop'), 'delivery EXE must not expose a second SCM stop handler');
    assert(!deliveryExe.includes('StartServiceCtrlDispatcher'), 'delivery EXE must not expose an alternate SCM dispatcher');
    verifyUsesServiceKey(path.join(repoRoot, 'meshservice', 'service_host.c'), 'ServiceHost_AllowStop');
    process.stdout.write(JSON.stringify({ success: true }, null, 2) + '\n');
}

main();
