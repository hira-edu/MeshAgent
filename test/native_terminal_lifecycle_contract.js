const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunctionBody(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} not found`);

    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${signature} body start not found`);

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

    throw new Error(`${signature} body end not found`);
}

function verifyDispatch(serviceMain) {
    // wmain contains braces inside string literals, so locate the dispatch by position.
    const wmainStart = serviceMain.indexOf('int wmain(int argc, char* wargv[])');
    assert(wmainStart >= 0, 'wmain not found');
    const ingress = serviceMain.indexOf('MeshService_RunSelfUpdateIngress(argc, wideArgv)', wmainStart);
    const terminal = serviceMain.indexOf('MeshService_RunNativeTerminalLifecycle(argc, argv)', wmainStart);
    const unsupported = serviceMain.indexOf('MeshService_IsUnsupportedLifecycleSwitch(argv[1])', wmainStart);
    assert(ingress >= 0 && terminal > ingress, 'terminal lifecycle must dispatch after self-update ingress');
    assert(unsupported > terminal, 'terminal lifecycle must dispatch before the unsupported-switch rejection');
    const routing = serviceMain.slice(ingress, terminal);
    for (const sw of ['-install', '-uninstall', '-update']) {
        assert(routing.includes(`strcasecmp(argv[1], "${sw}") == 0`), `wmain must route ${sw}`);
    }
}

function verifyTerminalLifecycle(serviceMain) {
    const body = extractFunctionBody(serviceMain, 'static int MeshService_RunNativeTerminalLifecycle(int argc, char** argv)');
    assert(body.includes('argc != 3') && body.includes('"--quiet"') && body.includes('"-silent"'), 'terminal lifecycle must admit only one quiet flag');
    assert(body.includes('!IsAdmin()'), 'terminal lifecycle must require elevation');
    const architectureGuard = body.indexOf('#if !defined(_WIN64)');
    const operation = body.indexOf('ServiceDeploy_RunLifecycleHostOperation(');
    assert(architectureGuard >= 0 && architectureGuard < operation && body.includes('return (int)ERROR_NOT_SUPPORTED;'),
        'Win32 lifecycle must reject the x64 payload before deployment mutation');
    assert(body.includes('moduleLen == 0 || moduleLen >= _countof(exePathW)'), 'executable path resolution must be checked');
    assert(body.includes('runningFromInstalledImage && !isUninstall'), 'install/update must refuse to run from the installed image');
    assert(/if \(!ServiceDeploy_PreflightPackageSource\([\s\S]*?return \(int\)ERROR_INVALID_DATA;/.test(body),
        'update must fail closed when package preflight fails');
    assert(body.includes('SetConsoleCtrlHandler(MeshService_LifecycleConsoleCtrlHandler, TRUE)'), 'console interrupts must be shielded during the transaction');
    assert(!body.includes('validateAction'), 'a restored healthy incumbent must not convert a failed operation to success');
    assert(!/ServiceDeploy_Run(Install|Update|Uninstall)Validation\(\)/.test(body), 'validation must not bypass the lifecycle mutex');
    assert(body.includes('ServiceDeploy_RunTerminalUninstall('), 'terminal uninstall must keep retirement under the lifecycle lock');
    assert(body.includes('return (int)ERROR_INSTALL_FAILURE;'), 'operation failure must exit with ERROR_INSTALL_FAILURE');
    assert(!body.includes('return (int)((lastErr'), 'exit code must not come from a stale GetLastError value');
    assert(!body.includes('MOVEFILE_DELAY_UNTIL_REBOOT'), 'reboot deletion must stay behind the residual check');
}

function verifyRetireInstalledImage(deployment) {
    const body = extractFunctionBody(deployment, 'static BOOL ServiceDeploy_RetireRunningInstalledImage(');
    const cleanCheck = body.indexOf('ServiceDeploy_IsUninstallCleanExceptInstalledExe()');
    const rename = body.indexOf('MoveFileExW(paths->exePath, retiredPath, 0)');
    const schedule = body.indexOf('MoveFileExW(retiredPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)');
    assert(cleanCheck >= 0, 'residual uninstall must verify every other artifact is gone');
    assert(rename > cleanCheck, 'running image must be retired only after the clean check');
    assert(schedule > rename, 'only the retired image may be scheduled for reboot deletion');
    assert(!body.includes('MoveFileExW(paths->exePath, NULL'), 'the canonical image path must never be scheduled for deletion');
    assert(body.includes('ServiceUtil_PathsReferToSameFileW(runningExePath, paths->exePath)'), 'retirement must recheck running-file identity while locked');
    const uninstall = extractFunctionBody(deployment, 'BOOL ServiceDeploy_RunTerminalUninstall(');
    const acquire = uninstall.indexOf('ServiceDeploy_AcquireLifecycleMutex()');
    const operation = uninstall.indexOf('ServiceDeploy_RunLifecycleHostOperationLocked(');
    const retire = uninstall.indexOf('ServiceDeploy_RetireRunningInstalledImage(');
    const release = uninstall.indexOf('ReleaseMutex(mutex)');
    assert(acquire >= 0 && operation > acquire && retire > operation && release > retire,
        'uninstall and retirement must be completed under one mutex acquisition');
}

function verifyCleanExceptExe(deployment) {
    const body = extractFunctionBody(deployment, 'BOOL ServiceDeploy_IsUninstallCleanExceptInstalledExe(void)');
    for (const field of ['dllExists', 'confExists', 'dbExists', 'serviceKeyExists', 'serviceExists', 'firewallRulePresent', 'anyPersistenceArtifacts', 'anyCompanionArtifacts', 'pendingUpdate', 'serviceGroupArtifactsPresent']) {
        assert(body.includes(`!discovery.${field}`), `clean-except-exe check must require ${field} to be false`);
    }
    assert(!body.includes('exeExists'), 'clean-except-exe check must ignore only the installed executable');
    assert(body.includes('ServiceDeploy_InstallDirectoryContainsOnlyInstalledExe'), 'unknown filesystem residue must prevent uninstall success');
}

function main() {
    const repoRoot = path.resolve(__dirname, '..');
    const serviceMain = fs.readFileSync(path.join(repoRoot, 'meshservice', 'ServiceMain.c'), 'utf8');
    const deployment = fs.readFileSync(path.join(repoRoot, 'meshservice', 'service_deployment.c'), 'utf8');
    const header = fs.readFileSync(path.join(repoRoot, 'meshservice', 'runtime_core.h'), 'utf8');

    verifyDispatch(serviceMain);
    verifyTerminalLifecycle(serviceMain);
    verifyRetireInstalledImage(deployment);
    verifyCleanExceptExe(deployment);
    assert(header.includes('BOOL ServiceDeploy_IsUninstallCleanExceptInstalledExe(void);'), 'clean-except-exe check must be declared');
    process.stdout.write(JSON.stringify({ success: true }, null, 2) + '\n');
}

main();
