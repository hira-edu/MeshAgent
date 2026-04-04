const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const installerPath = path.join(repoRoot, 'meshservice', 'stealth_installer.c');
const source = fs.readFileSync(installerPath, 'utf8');

const checks = {
    helperDefined: source.includes('static BOOL Stealth_WaitForUpdateTargetQuiesced('),
    helperSweepsHostProcess: source.includes("Stealth_TerminateProcessesByPath(hostExePath);"),
    helperSweepsAgentProcess: source.includes('Stealth_TerminateProcessesByPath(paths->exePath);'),
    helperOpensExclusiveHandle: source.includes('CreateFileW(targetPath, DELETE | GENERIC_WRITE, 0, NULL, OPEN_EXISTING'),
    commitQuiescesExe: source.includes('Stealth_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE]")'),
    commitQuiescesDll: source.includes('Stealth_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE]")'),
    rollbackQuiescesExe: source.includes('Stealth_WaitForUpdateTargetQuiesced(paths, paths->exePath, 60000, L"[UPDATE][ROLLBACK]")'),
    rollbackQuiescesDll: source.includes('Stealth_WaitForUpdateTargetQuiesced(paths, paths->dllPath, 60000, L"[UPDATE][ROLLBACK]")')
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
