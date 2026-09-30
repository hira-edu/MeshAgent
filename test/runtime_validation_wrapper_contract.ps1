#Requires -Version 5.1
<# Execute the production runtime dispatcher with process fixtures only. No services are changed. #>
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'test.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "test.ps1 failed parsing: $parseErrors" }
$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-GroupedRuntimeValidation' }, $true)
if (-not $function) { throw 'Missing runtime dispatcher' }
Invoke-Expression $function.Extent.Text

function Write-TestResult {
    param($TestName, $Status, $Message)
    $script:result = @{ Name = $TestName; Status = $Status; Message = $Message }
}
function Test-IsAdmin { return $script:admin }
function Get-Command {
    param($Name, $CommandType, $ErrorAction)
    if ($script:mode -eq 'missing-node') { throw 'Node unavailable' }
    if ($Name -ne 'node' -or $CommandType -ne 'Application') { throw 'Wrong runtime interpreter requested' }
    return [pscustomobject]@{ Source = 'Invoke-FakeNode' }
}
function Invoke-FakeNode {
    $script:launches++
    if ($args.Count -ne 7 -or $args[0] -ne (Join-Path $repoRoot 'test/run_grouped_regression.js') -or
        $args[1] -ne '--source-exe' -or $args[2] -ne $script:package -or
        $args[3] -ne '--source-dll' -or $args[4] -ne $script:dll -or $args[5] -ne '--evidence') {
        throw 'Runtime dispatcher did not forward the explicit package/DLL/evidence inputs'
    }
    if ($env:BRANDING_CONFIG_PATH -ne $script:config) { throw 'Resolved branding config not forwarded' }
    $global:LASTEXITCODE = 0
    if ($script:mode -eq 'exit-failure') { $global:LASTEXITCODE = 7; return }
    if ($script:mode -eq 'missing-results') { return }
    $phases = @('package_preflight', 'js_local_tests', 'meshcentral_same_size_contracts', 'native_cli', 'gui_lifecycle')
    if ($script:mode -eq 'incomplete') { $phases = @('package_preflight') }
    $phaseResults = @($phases | ForEach-Object { @{ name = $_; passed = $script:mode -ne 'phase-failure' } })
    @{
        allOk = $script:mode -ne 'reported-failure'
        fatal = $(if ($script:mode -eq 'fatal') { 'Fixture failure' } else { $null })
        phaseResults = $phaseResults
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $args[6] 'results.json')
}

$originalOS = $env:OS
$originalBranding = $env:BRANDING_CONFIG_PATH
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('meshagent-runtime-wrapper-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $script:package = Join-Path $fixtureRoot 'package.exe'
    $script:dll = Join-Path $fixtureRoot 'bundle.dll'
    $script:config = Join-Path $fixtureRoot 'branding.json'
    foreach ($path in @($script:package, $script:dll, $script:config)) { Set-Content -LiteralPath $path -Value '{}' }
    $env:BRANDING_CONFIG_PATH = 'previous-config'
    $cases = @('not-windows', 'not-admin', 'missing-package', 'missing-dll', 'missing-config', 'missing-node', 'exit-failure', 'missing-results', 'incomplete', 'phase-failure', 'reported-failure', 'fatal', 'pass')
    foreach ($case in $cases) {
        $script:mode = $case
        $script:admin = $case -ne 'not-admin'
        $env:OS = $(if ($case -eq 'not-windows') { 'Unix' } else { 'Windows_NT' })
        $script:launches = 0
        $script:result = $null
        $packageArg = $(if ($case -eq 'missing-package') { '' } else { $script:package })
        $dllArg = $(if ($case -eq 'missing-dll') { '' } else { $script:dll })
        $configArg = $(if ($case -eq 'missing-config') { '' } else { $script:config })
        Invoke-GroupedRuntimeValidation -PackagePath $packageArg -DllPath $dllArg -ConfigPath $configArg -EvidencePath $fixtureRoot
        $expected = $(if ($case -eq 'pass') { 'Pass' } else { 'Fail' })
        if (-not $script:result -or $script:result.Status -ne $expected) { throw "Unexpected result for ${case}: $($script:result | ConvertTo-Json)" }
        if ($case -in @('not-windows', 'not-admin', 'missing-package', 'missing-dll', 'missing-config', 'missing-node') -and $script:launches -ne 0) { throw "Prerequisite failure launched runtime: $case" }
        if ($env:BRANDING_CONFIG_PATH -ne 'previous-config') { throw "Branding environment was not restored: $case" }
    }
    Write-Output 'PASS: 13 runtime dispatcher outcomes; missing prerequisites and skipped/failed phases cannot pass'
} finally {
    $env:OS = $originalOS
    $env:BRANDING_CONFIG_PATH = $originalBranding
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
