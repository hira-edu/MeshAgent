const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const installerPath = path.join(repoRoot, 'meshservice', 'service_deployment.c');
const source = fs.readFileSync(installerPath, 'utf8');

const checks = {
    helperDefined: source.includes('static BOOL ServiceDeploy_WaitForUpdateTargetQuiesced('),
    helperSweepsLoadedServiceDll: source.includes('ServiceDeploy_TerminateProcessesByLoadedModulePath(paths->dllPath);'),
    helperSweepsAgentProcess: source.includes('ServiceDeploy_TerminateProcessesByPath(paths->exePath);'),
    helperDoesNotKillSharedServiceHostByPath: !source.includes('ServiceDeploy_TerminateProcessesByPath(hostExePath);'),
    sharedHostsExcludedFromModuleSweep: source.includes('if (pid == 0 || pid == currentPid || !_wcsicmp(processEntry.szExeFile, L"svchost.exe")) { continue; }'),
        forcedSharedServiceStopRequiresExclusiveBinding: source.includes('ServiceHost_ValidateServiceBinding(serviceName, serviceDll)') &&
        source.includes('if (!stopped && forceTerminate && processIsExclusivelyOurs && ssp.dwProcessId != 0)'),
    executableSweepRequiresExactImage: source.includes('if (_wcsicmp(imagePath, exePath) == 0 && entry.th32ProcessID != currentPid)'),
    helperOpensExclusiveHandle: source.includes('CreateFileW(targetPath, DELETE | GENERIC_WRITE, 0, NULL, OPEN_EXISTING'),
    commitQuiescesExe: source.includes('ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE]")'),
    commitQuiescesDll: source.includes('ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE]")'),
    rollbackQuiescesExe: source.includes('ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE][ROLLBACK]")'),
    rollbackQuiescesDll: source.includes('ServiceDeploy_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE][ROLLBACK]")')
};

const success = Object.values(checks).every(Boolean);
const result = {
    generatedUtc: new Date().toISOString(),
    success,
    files: { installerPath },
    checks
};

console.log(JSON.stringify(result, null, 2));
if (!success) {
    process.exit(1);
}
