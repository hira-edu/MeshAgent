$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '..\test.ps1') -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in @('Resolve-BinaryPath', 'Get-MeshCentralAgentDownload')) {
    $functionAst = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    Invoke-Expression $functionAst.Extent.Text
}
$agentTypeAssignment = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -eq '$downloadAgentType'
}, $true).Extent.Text
if (-not $agentTypeAssignment) { throw 'Missing download architecture selection' }
$downloadCheck = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
    $node.Body.Extent.Text.Contains('$downloadAgentType =')
}, $true).Extent.Text
if (-not $downloadCheck) { throw 'Missing download verification block' }
$inventoryStart = $source.IndexOf('#region Test Suite 1:')
$inventoryEnd = $source.IndexOf('# Test 1.3:', $inventoryStart)
$inventory = [scriptblock]::Create($source.Substring($inventoryStart, $inventoryEnd - $inventoryStart))
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = Join-Path $tempBase ('architecture-contract-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $repoRoot = $fixtureRoot
    $BinaryPath = $fixtureRoot
    function Write-TestResult {
        param($TestName, $Status, $Message, $Details)
        $script:results.Add(@{ Name = $TestName; Status = $Status })
    }
    foreach ($RuntimeArchitecture in @('x64', 'ARM64')) {
        $selectedName = if ($RuntimeArchitecture -eq 'ARM64') { 'MeshServiceARM64.exe' } else { 'MeshService64.exe' }
        $selectedPath = Join-Path $fixtureRoot $selectedName
        [IO.File]::WriteAllBytes($selectedPath, [byte[]]@(0))
        $FullRelease = $false
        $script:results = [Collections.Generic.List[object]]::new()
        . $inventory
        if ($results.Count -ne 1 -or $results[0].Status -ne 'Pass') {
            throw "Single-architecture inventory failed: $RuntimeArchitecture"
        }
        Remove-Item -LiteralPath $selectedPath
        $script:results.Clear()
        . $inventory
        if ($results.Count -ne 1 -or $results[0].Status -ne 'Fail') { throw 'Missing selected binary was accepted' }

        # Execute the production selector and download function against a local CLI fixture.
        Invoke-Expression $agentTypeAssignment
        $meshctrl = Join-Path $fixtureRoot 'meshctrl.js'
        @'
const fs = require('fs');
const type = process.argv[process.argv.indexOf('--type') + 1];
fs.writeFileSync('download.exe', type);
console.log('Downloaded agent to "download.exe"');
'@ | Set-Content -LiteralPath $meshctrl -Encoding utf8
        $download = Get-MeshCentralAgentDownload -MeshCtrlPath $meshctrl -MeshCentralMeshId fixture `
            -MeshCentralLoginUser fixture -MeshCentralLoginPass fixture -MeshCentralControlUrl wss://fixture.invalid `
            -AgentType $downloadAgentType
        $expectedType = if ($RuntimeArchitecture -eq 'ARM64') { '43' } else { '4' }
        if ([Text.Encoding]::UTF8.GetString($download.Bytes) -ne $expectedType) { throw 'Wrong downloaded architecture' }
    }
    $FullRelease = $true
    foreach ($name in @('MeshService64.exe', 'MeshServiceARM64.exe', 'MeshService.exe')) {
        [IO.File]::WriteAllBytes((Join-Path $fixtureRoot $name), [byte[]]@(0))
    }
    $script:results.Clear()
    . $inventory
    if ($results.Count -ne 3 -or @($results | Where-Object Status -ne 'Pass').Count) { throw 'Full release rejected complete set' }
    Remove-Item -LiteralPath (Join-Path $fixtureRoot 'MeshService.exe')
    $script:results.Clear()
    . $inventory
    if (@($results | Where-Object Status -eq 'Fail').Count -ne 1) { throw 'Full release accepted incomplete set' }

    # A failing CLI that prints a success line must still fail runtime validation.
    Add-Content -LiteralPath $meshctrl -Value 'process.exit(1);'
    $MeshCtrlPath = $meshctrl
    $MeshCentralMeshId = $MeshCentralLoginUser = $MeshCentralLoginPass = 'fixture'
    $MeshCentralControlUrl = 'wss://fixture.invalid'
    $effectiveMeshCentralUrl = $null
    foreach ($RuntimeValidation in @($true, $false)) {
        $script:results.Clear()
        Invoke-Expression $downloadCheck
        $expectedStatus = if ($RuntimeValidation) { 'Fail' } else { 'Warning' }
        if ($results.Count -ne 1 -or $results[0].Status -ne $expectedStatus) { throw 'Download failure was not reported correctly' }
    }
    Write-Host 'PASS: architecture inventory, agent download type, and runtime download failure handling'
} finally {
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
    if (-not $resolvedFixture.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
