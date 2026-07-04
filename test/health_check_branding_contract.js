const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

const repoRoot = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(repoRoot, 'tools', 'health_check.ps1'), 'utf8');

assert(source.includes('$branding.branding.binaryName'), 'health check must use branding.binaryName for branded installs');
assert(source.includes('$binaryNames.Add("MeshService64.exe")'), 'health check must retain MeshService64.exe fallback');
assert(source.includes('$binaryNames.Add("MeshService.exe")'), 'health check must retain MeshService.exe fallback');
assert(source.includes('foreach ($binaryName in ($binaryNames | Select-Object -Unique))'), 'health check must probe each unique candidate name');
assert(source.includes('function Resolve-ServiceDllPath'), 'health check must infer svchost install path from ServiceDll');
assert(source.includes('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$Name\\Parameters'), 'health check must read the service Parameters registry key');
assert(source.includes('Resolve-ServiceExecutablePath -PathName $service.PathName'), 'health check must retain executable path inference fallback');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Pass\' }).Count'), 'pass count must be array-wrapped for single-object PowerShell results');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Fail\' }).Count'), 'fail count must be array-wrapped for single-object PowerShell results');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Warning\' }).Count'), 'warning count must be array-wrapped for single-object PowerShell results');

process.stdout.write(JSON.stringify({
    ok: true,
    checks: {
        brandedBinaryName: true,
        legacyFallbacks: true,
        svchostServiceDllInference: true,
        robustPowerShellCounts: true
    }
}, null, 2) + '\n');
