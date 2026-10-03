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
assert(!source.includes('$binaryNames.Add("MeshService64.exe")'), 'health check must not infer obsolete binary aliases');
assert(!source.includes('$binaryNames.Add("MeshService.exe")'), 'health check must not infer obsolete binary aliases');
assert(source.includes('function Resolve-ServiceRuntimeDllPath'), 'health check must parse the canonical service-host binding');
assert(source.includes('ServiceHost_ServiceMain'), 'health check must require the service-host ServiceMain export');
assert(source.includes("'svchost.exe'"), 'health check must require the actual System32 service-host executable');
assert(source.includes('ServiceDllUnloadOnStop'), 'health check must validate the service-host unload contract');
assert(source.includes('Resolve-ServiceRuntimeDllPath -PathName $service.PathName'), 'health check must infer the install directory from the canonical runtime DLL');
assert(!source.includes('Resolve-ServiceExecutablePath'), 'health check must not fall back to a host executable directory');
assert(source.includes('CurrentControlSet\\Services\\$Name\\Parameters'), 'health check must read the canonical ServiceDll parameters');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Pass\' }).Count'), 'pass count must be array-wrapped for single-object PowerShell results');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Fail\' }).Count'), 'fail count must be array-wrapped for single-object PowerShell results');
assert(source.includes('@($results | Where-Object { $_.Status -eq \'Warning\' }).Count'), 'warning count must be array-wrapped for single-object PowerShell results');

process.stdout.write(JSON.stringify({
    ok: true,
    checks: {
        brandedBinaryName: true,
        canonicalRuntimeBinding: true,
        robustPowerShellCounts: true
    }
}, null, 2) + '\n');
