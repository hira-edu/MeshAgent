$ErrorActionPreference = 'Stop'
$source = Get-Content (Join-Path $PSScriptRoot '..\test.ps1') -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($name in @(
    'Convert-MshTextToDictionary',
    'Get-ByteArrayHash',
    'Get-PeCertificateTableInfo',
    'Normalize-AgentCertificateTable',
    'Invoke-MeshCentralDownloadValidation'
)) {
    $functionAst = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $functionAst) { throw "Missing function: $name" }
    Invoke-Expression $functionAst.Extent.Text
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = Join-Path $tempBase ('meshcentral-generic-contract-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
try {
    $reference = Join-Path $fixtureRoot 'agent.exe'
    $referenceBytes = [byte[]](0..255)
    [IO.File]::WriteAllBytes($reference, $referenceBytes)
    $trailer = [Text.Encoding]::UTF8.GetBytes('0123456789abcdef0123456789abcdef01234567')
    $footer = [byte[]]::new(20)
    $length = [BitConverter]::GetBytes([uint32]$trailer.Length)
    [Array]::Reverse($length)
    [Array]::Copy($length, 0, $footer, 0, 4)
    $download = [byte[]]::new($referenceBytes.Length + $trailer.Length + $footer.Length)
    [Array]::Copy($referenceBytes, 0, $download, 0, $referenceBytes.Length)
    [Array]::Copy($trailer, 0, $download, $referenceBytes.Length, $trailer.Length)
    [Array]::Copy($footer, 0, $download, $referenceBytes.Length + $trailer.Length, $footer.Length)

    $script:results = [Collections.Generic.List[object]]::new()
    $RuntimeValidation = $true
    function Write-TestResult {
        param($TestName, $Status, $Message, $Details)
        $script:results.Add([pscustomobject]@{ Name = $TestName; Status = $Status; Message = $Message })
    }

    Invoke-MeshCentralDownloadValidation -DownloadedBytes $download -ReferenceBinary $reference `
        -LocalMshPath (Join-Path $fixtureRoot 'missing.msh') -GenericDownload
    if (@($results | Where-Object Status -ne 'Pass').Count -ne 0) { throw 'Valid generic package was rejected' }
    if (@($results | Where-Object Name -eq 'MeshCentral Generic Server Trailer Valid').Count -ne 1) {
        throw 'Generic trailer result missing'
    }

    $download[$referenceBytes.Length] = [byte][char]'g'
    $results.Clear()
    Invoke-MeshCentralDownloadValidation -DownloadedBytes $download -ReferenceBinary $reference `
        -LocalMshPath (Join-Path $fixtureRoot 'missing.msh') -GenericDownload
    if (@($results | Where-Object { $_.Name -eq 'MeshCentral Generic Server Trailer Valid' -and $_.Status -eq 'Fail' }).Count -ne 1) {
        throw 'Malformed generic trailer was accepted'
    }
    Write-Host 'PASS: generic MeshCentral downloads require binary parity and a valid server trailer'
} finally {
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
    if (-not $resolvedFixture.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
