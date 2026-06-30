const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

function extractFunction(source, signature) {
    let start = source.indexOf(signature);
    assert(start >= 0, `missing function: ${signature}`);

    let bodyStart = source.indexOf('{', start);
    let prototypeEnd = source.indexOf(';', start);
    while (prototypeEnd >= 0 && prototypeEnd < bodyStart) {
        start = source.indexOf(signature, prototypeEnd + 1);
        assert(start >= 0, `missing function body: ${signature}`);
        bodyStart = source.indexOf('{', start);
        prototypeEnd = source.indexOf(';', start);
    }
    assert(bodyStart > start, `missing function body: ${signature}`);

    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`unterminated function body: ${signature}`);
}

function main() {
    const installer = read('meshservice/stealth_installer.c');
    const commit = extractFunction(installer, 'static BOOL Stealth_CommitUpdateTransaction(');
    const rollback = extractFunction(installer, 'static BOOL Stealth_RollbackUpdateTransaction(');

    const dllCommitIndex = commit.indexOf('tx->stagedDllReady');
    const exeCommitIndex = commit.indexOf('tx->stagedExeReady');
    assert(dllCommitIndex >= 0, 'update commit must explicitly handle staged DLL');
    assert(exeCommitIndex >= 0, 'update commit must explicitly handle staged EXE');
    assert(dllCommitIndex < exeCommitIndex, 'update commit must replace ServiceDll before host EXE');

    const dllInstallIndex = commit.indexOf('Stealth_InstallFiles(tx->stagedDllPath, paths->dllPath)');
    const exeInstallIndex = commit.indexOf('Stealth_InstallFiles(tx->stagedExePath, paths->exePath)');
    assert(dllInstallIndex >= 0 && exeInstallIndex >= 0, 'update commit must install both staged binaries');
    assert(dllInstallIndex < exeInstallIndex, 'staged ServiceDll install must precede staged EXE install');
    assert(
        commit.indexOf('Stealth_ValidateSvchostPayloadDll(paths->dllPath)') < exeInstallIndex,
        'committed ServiceDll must validate before host EXE replacement'
    );

    const dllRollbackIndex = rollback.indexOf('tx->liveDllExists');
    const exeRollbackIndex = rollback.indexOf('tx->liveExeExists');
    assert(dllRollbackIndex >= 0, 'rollback must explicitly restore live DLL backup');
    assert(exeRollbackIndex >= 0, 'rollback must explicitly restore live EXE backup');
    assert(dllRollbackIndex < exeRollbackIndex, 'rollback must restore ServiceDll before host EXE');
    assert(
        installer.includes('Stealth_RecordUpdateActivationFailureHold(&paths);') &&
        installer.includes('Stealth_ClearUpdateActivationHolds(&paths, L"[UPDATE]");'),
        'update transaction must clear activation holds on success and promote the target hold on failure'
    );

    console.log(JSON.stringify({
        success: true,
        checks: {
            serviceDllCommittedBeforeExe: true,
            serviceDllValidatedBeforeExe: true,
            serviceDllRolledBackBeforeExe: true,
            updateActivationHoldConvergesWithTransaction: true
        }
    }, null, 2));
}

main();
