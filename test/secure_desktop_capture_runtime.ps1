param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$OutputDir = (Join-Path $env:TEMP ('meshagent-secure-desktop-runtime-' + [guid]::NewGuid().ToString('N'))),
    [int]$WaitSeconds = 45,
    [int]$SampleIntervalSeconds = 2
)

$ErrorActionPreference = 'Stop'

if ($WaitSeconds -lt 1) { throw 'WaitSeconds must be at least 1.' }
if ($SampleIntervalSeconds -lt 1) { throw 'SampleIntervalSeconds must be at least 1.' }

$exe = Join-Path $RepoRoot 'meshservice\\x64\\StealthLab\\MeshService-2022.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Missing executable: $exe" }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$outputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$probeStdoutPath = Join-Path $outputDir 'probe_stdout.json'
$probeStderrPath = Join-Path $outputDir 'probe_stderr.txt'
$taskQueryPath = Join-Path $outputDir 'task_query.txt'
$samplesPath = Join-Path $outputDir 'runtime_samples.json'
$metaPath = Join-Path $outputDir 'secure_desktop_capture_runtime.json'
$cmdPath = Join-Path $outputDir 'run_probe.cmd'
$taskName = 'MeshAgentSecureDesktopRuntime_' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$cmdText = "@echo off`r`n`"$exe`" -kvm-secure-desktop-probe > `"$probeStdoutPath`" 2> `"$probeStderrPath`"`r`n"
[System.IO.File]::WriteAllText($cmdPath, $cmdText, [System.Text.Encoding]::ASCII)

$taskDate = (Get-Date).ToString('MM/dd/yyyy')
$samples = New-Object System.Collections.Generic.List[object]
$probeJson = $null

try {
    & schtasks /Create /TN $taskName /SC ONCE /SD $taskDate /ST 23:59 /RU SYSTEM /RL HIGHEST /TR $cmdPath /F | Out-Null
    & schtasks /Run /TN $taskName | Out-Null

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $samples.Add([pscustomobject]@{
            ts = (Get-Date).ToString('o')
            mesh = ((tasklist /FI 'IMAGENAME eq MeshService-2022.exe') -join "`n")
            consent = ((tasklist /FI 'IMAGENAME eq consent.exe') -join "`n")
            cred = ((tasklist /FI 'IMAGENAME eq CredentialUIBroker.exe') -join "`n")
            logonui = ((tasklist /FI 'IMAGENAME eq LogonUI.exe') -join "`n")
            wscript = ((tasklist /FI 'IMAGENAME eq wscript.exe') -join "`n")
        }) | Out-Null
        Start-Sleep -Seconds $SampleIntervalSeconds
    }

    $taskQuery = (& schtasks /Query /TN $taskName /V /FO LIST) -join "`n"
    [System.IO.File]::WriteAllText($taskQueryPath, $taskQuery, [System.Text.Encoding]::UTF8)
    ($samples | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $samplesPath -Encoding UTF8

    if (Test-Path -LiteralPath $probeStdoutPath) {
        try {
            $probeJson = Get-Content -LiteralPath $probeStdoutPath -Raw | ConvertFrom-Json
        }
        catch {
            $probeJson = $null
        }
    }

    $result = [pscustomobject]@{
        success = ($probeJson -ne $null -and $probeJson.success -eq $true)
        outputDir = $outputDir
        exe = $exe
        taskName = $taskName
        waitSeconds = $WaitSeconds
        sampleIntervalSeconds = $SampleIntervalSeconds
        probeStdoutPath = $probeStdoutPath
        probeStderrPath = $probeStderrPath
        taskQueryPath = $taskQueryPath
        runtimeSamplesPath = $samplesPath
        probe = $probeJson
    }

    ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $metaPath -Encoding UTF8
    $result | ConvertTo-Json -Depth 8
}
finally {
    try { & schtasks /Delete /TN $taskName /F | Out-Null } catch {}
}
