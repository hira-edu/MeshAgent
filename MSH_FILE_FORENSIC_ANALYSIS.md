# MeshCentral .MSH File Creation & Embedding - Complete Forensic Analysis

> **Last Updated:** October 24, 2024
> **Based on:** Line-by-line code analysis of MeshCentral source
> **Status:** COMPLETE TECHNICAL DOCUMENTATION

---

## Executive Summary

`.MSH` files are MeshCentral's configuration embedding system that allows agents to carry their complete configuration within the executable binary. This document provides a complete technical breakdown of how these files are created, embedded, and used.

---

## Table of Contents

1. [What is a .MSH File?](#1-what-is-a-msh-file)
2. [Binary Structure and Embedding](#2-binary-structure-and-embedding)
3. [Server/Mesh/Group ID Generation](#3-servermeshgroup-id-generation)
4. [Configuration Compilation Process](#4-configuration-compilation-process)
5. [PE Header Modification for Signed Executables](#5-pe-header-modification-for-signed-executables)
6. [Installation Flags and Runtime Behavior](#6-installation-flags-and-runtime-behavior)
7. [Agent Customization Options](#7-agent-customization-options)
8. [Code Flow and Key Functions](#8-code-flow-and-key-functions)
9. [Practical Examples](#9-practical-examples)
10. [Troubleshooting Guide](#10-troubleshooting-guide)

---

## 1. What is a .MSH File?

### Definition
A `.msh` file is a plain-text configuration file containing key-value pairs (format: `key=value\r\n`) that gets embedded into MeshCentral agent executables.

### Example .MSH Content
```
MeshName=Production Servers
MeshType=2
MeshID=0x1A2B3C4D5E6F7890ABCDEF1234567890
ServerID=283DE2DD8539007F64853D3CE7C7D4C0562A8AD9DD100FDB31D08B3DCB4FB05815596C62A10A5459C84B14B4171252DF
MeshServer=wss://meshcentral.company.com:443/agent.ashx
meshServiceName=CompanyRemoteAgent
displayName=Company Remote Support Agent
InstallFlags=3
Tag=Server
```

### File Locations
- **Standalone .msh file:** Written beside agent executable after installation
- **Embedded in binary:** Appended to agent executable during download
- **Example path:** `C:\Program Files\Company\Agent\MeshService64.exe.msh`

---

## 2. Binary Structure and Embedding

### 2.1 Unsigned Executables

**Structure:**
```
[Original Binary][MSH Data][MSH Length (4 bytes, LE)][GUID (16 bytes)]
```

**Code Reference:** `exeHandler.js` lines 96-109
```javascript
// Stream original binary
sourceStream.pipe(destinationStream);
// Append MSH data
destinationStream.write(mshbuf);
// Append length (little-endian)
sz.writeUInt32LE(mshbuf.length, 0);
destinationStream.write(sz);
// Append GUID
destinationStream.end(Buffer.from(exeMeshPolicyGuid, 'hex'));
```

### 2.2 Signed Executables

**Structure:**
```
[Modified PE Headers]
[Certificate Table with Updated Size]
[Original Certificate Data]
[Padding (0-7 bytes for 8-byte alignment)]
[MSH Data]
[MSH Length (4 bytes, LE)]
[GUID (16 bytes)]
```

**Key Modifications:**
1. **CertificateTableSize:** Updated at PE offset to include MSH + 20 bytes
2. **Certificate dwLength:** Updated in certificate entry to include MSH + 20 bytes
3. **Quad-alignment:** Padding added to maintain 8-byte boundary

**Code Reference:** `exeHandler.js` lines 110-155

### 2.3 GUID System

| GUID | Value | Purpose |
|------|-------|---------|
| `exeJavaScriptGuid` | B996015880544A19B7F7E9BE44914C18 | Embedded JavaScript/MeshCmd |
| `exeMeshPolicyGuid` | B996015880544A19B7F7E9BE44914C19 | Real MSH configuration |
| `exeNullPolicyGuid` | B996015880544A19B7F7E9BE44914C20 | Random/placeholder MSH |

---

## 3. Server/Mesh/Group ID Generation

### 3.1 ServerID

**Generation:** `webserver.js` line 5770
```javascript
var serveridhex = Buffer.from(
    obj.agentCertificateHashBase64
        .replace(/\@/g, '+')
        .replace(/\$/g, '/'),
    'base64'
).toString('hex').toUpperCase();
```

**Source:** Server's agent certificate hash
**Format:** Uppercase hexadecimal (64 characters)
**Example:** `283DE2DD8539007F64853D3CE7C7D4C0562A8AD9DD100FDB31D08B3DCB4FB05815596C62A10A5459C84B14B4171252DF`

### 3.2 MeshID (Group ID)

**Generation:** `webserver.js` line 5769
```javascript
var meshidhex = Buffer.from(
    req.query.meshid
        .replace(/\@/g, '+')
        .replace(/\$/g, '/'),
    'base64'
).toString('hex').toUpperCase();
```

**Source:** Device group identifier from database
**Format:** Uppercase hexadecimal with `0x` prefix
**Example:** `0x1A2B3C4D5E6F7890ABCDEF1234567890`

**Note:** MeshID and GroupID are the same value - there is no separate GroupID.

### 3.3 MeshName

**Source:** `mesh.name` from database
**Sanitization:** Special characters removed
**Example:** `Production Servers`

---

## 4. Configuration Compilation Process

### 4.1 Three-Level Configuration Cascade

**Priority Order (highest to lowest):**

1. **Query Parameters** (highest priority)
   ```
   ?tag=Server&installflags=3&ac=1
   ```

2. **Domain Configuration**
   ```json
   {
     "domains": {
       "": {
         "agentconfig": ["LogLevel=2", "MaxLogSize=5000000"],
         "agentcustomization": {
           "displayname": "Company Agent",
           "servicename": "CompanyRemoteAgent"
         }
       }
     }
   }
   ```

3. **Global Configuration** (lowest priority)
   ```json
   {
     "settings": {
       "agentconfig": ["DefaultSetting=value"]
     }
   }
   ```

### 4.2 getMshFromRequest Function Flow

**Location:** `webserver.js` lines 6356-6407

```javascript
function getMshFromRequest(req, res, domain) {
    // 1. Verify permissions
    // 2. Decode cookie/authentication
    // 3. Fetch mesh object from database
    // 4. Generate ServerID and MeshID (hex format)
    // 5. Build base configuration
    meshsettings = 'MeshName=' + mesh.name + '\r\n';
    meshsettings += 'MeshType=' + mesh.mtype + '\r\n';
    meshsettings += 'MeshID=0x' + meshidhex + '\r\n';
    meshsettings += 'ServerID=' + serveridhex + '\r\n';

    // 6. Add server connection
    if (obj.args.lanonly != true) {
        meshsettings += 'MeshServer=wss://' + serverName + ':' + httpsPort + '/agent.ashx\r\n';
    } else {
        meshsettings += 'MeshServer=local\r\n';
        if (obj.args.localdiscovery?.key) {
            meshsettings += 'DiscoveryKey=' + obj.args.localdiscovery.key + '\r\n';
        }
    }

    // 7. Add query parameters
    if (req.query.tag && obj.common.isAlphaNumeric(req.query.tag)) {
        meshsettings += 'Tag=' + req.query.tag + '\r\n';
    }
    if (req.query.installflags) {
        meshsettings += 'InstallFlags=' + req.query.installflags + '\r\n';
    }

    // 8. Apply global agentconfig
    if (obj.args.agentconfig) {
        for (var i in obj.args.agentconfig) {
            meshsettings += obj.args.agentconfig[i] + '\r\n';
        }
    }

    // 9. Apply domain agentconfig
    if (domain.agentconfig) {
        for (var i in domain.agentconfig) {
            meshsettings += domain.agentconfig[i] + '\r\n';
        }
    }

    // 10. Apply domain customization
    if (domain.agentcustomization) {
        if (domain.agentcustomization.displayname) {
            meshsettings += 'displayName=' + domain.agentcustomization.displayname + '\r\n';
        }
        if (domain.agentcustomization.servicename) {
            meshsettings += 'meshServiceName=' + domain.agentcustomization.servicename + '\r\n';
        }
        // ... other customizations
    }

    return meshsettings;
}
```

---

## 5. PE Header Modification for Signed Executables

### 5.1 PE Structure Overview

```
DOS Header (64 bytes)
├─ Magic: "MZ" (0x5A4D) at offset 0
└─ PE Offset: at offset 0x3C (points to PE header)

PE Header
├─ Signature: "PE\0\0" (0x50450000)
├─ Machine Type: 0x14C (x86) or 0x8664 (x64)
└─ Optional Header
    ├─ Certificate Table Address (x86: +128, x64: +144)
    └─ Certificate Table Size (x86: +132, x64: +148)

Certificate Table
├─ dwLength (4 bytes): Total entry size
├─ wRevision (2 bytes): Usually 0x0200
├─ wCertificateType (2 bytes): Usually 0x0002 (PKCS#7)
└─ bCertificate[]: Actual certificate data
```

### 5.2 Modification Process

**Step 1:** Calculate padding for 8-byte alignment
```javascript
mshPadding = (8 - ((certificateDwLength + mshbuf.length + 20) % 8)) % 8;
```

**Step 2:** Update Certificate Table Size in PE header
```javascript
newCertTableSize = originalCertTableSize + mshbuf.length + 20 + mshPadding;
```

**Step 3:** Update Certificate Entry dwLength
```javascript
newDwLength = originalDwLength + mshbuf.length + 20 + mshPadding;
```

**Step 4:** Append MSH data after certificate with padding

---

## 6. Installation Flags and Runtime Behavior

### 6.1 InstallFlags Values

| Value | Binary | Meaning |
|-------|--------|---------|
| 0 | 0b00 | No options (silent) |
| 1 | 0b01 | Enable "Connect" mode only |
| 2 | 0b10 | Enable "Install" mode only |
| 3 | 0b11 | Both Connect and Install (default) |

**Usage:** `?installflags=3`

### 6.2 Runtime Checking

**Code:** `meshinstall-linux.js` lines 161-165
```javascript
if ((msh.InstallFlags & 1) == 1) {
    // Show "Connect" button/option
}
if ((msh.InstallFlags & 2) == 2) {
    // Show "Install" button/option
}
```

### 6.3 AutoConnect Flags (Assistant Only)

| Value | Meaning |
|-------|---------|
| 0x01 | Always Connected |
| 0x02 | Not System Tray |

**Usage:** `?ac=1` (for MeshCentral Assistant)

---

## 7. Agent Customization Options

### 7.1 Complete Customization Properties

| Property | MSH Key | Sanitization | Example |
|----------|---------|--------------|---------|
| `displayname` | `displayName` | Remove `\r\n` | "Company Remote Agent" |
| `description` | `description` | Remove `\r\n` | "Remote support software" |
| `companyname` | `companyName` | Remove `\r\n` | "ACME Corporation" |
| `servicename` | `meshServiceName` | Remove special chars | "ACMERemoteAgent" |
| `filename` | `fileName` | None | "acmeagent" |
| `image` | `image` | Base64 PNG | "data:image/png;base64,..." |
| `foregroundcolor` | `foreground` | RGB validation | "255,0,0" or "#FF0000" |
| `backgroundcolor` | `background` | RGB validation | "255,255,255" or "#FFFFFF" |

### 7.2 Color Validation

**Function:** `checkAgentColorString()` in `webserver.js` lines 10146-10160

**Accepted Formats:**
- Hex: `#RRGGBB` (e.g., `#FF0000`)
- Decimal: `R,G,B` (e.g., `255,0,0`)

**Validation:**
- Each RGB component must be 0-255
- Hex format must be exactly 7 characters
- Decimal format must have exactly 3 components

### 7.3 Configuration Example

```json
{
  "domains": {
    "": {
      "agentcustomization": {
        "displayname": "ACME Remote Support",
        "description": "ACME Corporation Remote Support Agent",
        "companyname": "ACME Corporation",
        "servicename": "ACMERemoteAgent",
        "filename": "acmeagent",
        "foregroundcolor": "#0066CC",
        "backgroundcolor": "#FFFFFF"
      },
      "agentconfig": [
        "LogLevel=2",
        "MaxLogSize=5000000",
        "CustomSetting=value"
      ]
    }
  }
}
```

---

## 8. Code Flow and Key Functions

### 8.1 Agent Download Request Flow

```
User Request: /meshagents?id=4&meshid=xyz&tag=Server
                    │
                    ▼
    webserver.js:handleMeshAgentRequest() [line 5715]
                    │
                    ├─> Validate permissions
                    ├─> Get mesh object from DB
                    ├─> getMshFromRequest() [line 6356]
                    │       │
                    │       ├─> Generate ServerID/MeshID
                    │       ├─> Build base config
                    │       ├─> Add query params
                    │       ├─> Merge agentconfig
                    │       └─> Apply customization
                    │
                    └─> exeHandler.streamExeWithMeshPolicy() [line 84]
                            │
                            ├─> Check if signed
                            ├─> Calculate padding
                            ├─> Modify PE headers (if signed)
                            └─> Append MSH + metadata
```

### 8.2 Key Functions Reference

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `handleMeshAgentRequest` | webserver.js | 5715 | Main agent download handler |
| `getMshFromRequest` | webserver.js | 6356 | Generate MSH configuration |
| `streamExeWithMeshPolicy` | exeHandler.js | 84 | Embed MSH into binary |
| `parseWindowsExecutable` | exeHandler.js | 161 | Parse PE headers |
| `updateMeshAgentsTable` | meshcentral.js | 3540 | Load agent binaries |
| `signMeshAgents` | meshcentral.js | 3243 | Code-sign agents |
| `checkAgentColorString` | webserver.js | 10146 | Validate color values |

### 8.3 Agent Architecture IDs

| ID | Platform | Binary Name | Signed |
|----|----------|-------------|--------|
| 3 | Windows x86-32 | MeshService.exe | Yes |
| 4 | Windows x86-64 | MeshService64.exe | Yes |
| 5 | Linux x86-32 | meshagent_x86 | No |
| 6 | Linux x86-64 | meshagent_x86-64 | No |
| 11 | macOS x86-64 | meshosx_x86-64 | No |
| 16 | macOS ARM64 | meshosx_arm64 | No |
| 43 | Windows ARM64 | MeshServiceARM64.exe | Yes |
| 10003 | Windows x86-32 Unsigned | MeshService.exe | No |
| 10004 | Windows x86-64 Unsigned | MeshService64.exe | No |

---

## 9. Practical Examples

### 9.1 Basic Agent Download URL

```
https://meshcentral.company.com/meshagents?id=4&meshid=abcd1234
```

**Result:** Windows x64 agent with embedded mesh configuration

### 9.2 Customized Agent with Tag

```
https://meshcentral.company.com/meshagents?id=4&meshid=abcd1234&tag=WebServer&installflags=2
```

**Embedded MSH:**
```
MeshName=Production Servers
MeshType=2
MeshID=0xABCD1234...
ServerID=283DE2DD...
MeshServer=wss://meshcentral.company.com:443/agent.ashx
Tag=WebServer
InstallFlags=2
```

### 9.3 LAN-Only Mode Configuration

**Config.json:**
```json
{
  "settings": {
    "lanonly": true
  },
  "localdiscovery": {
    "key": "secret123"
  }
}
```

**Resulting MSH:**
```
MeshName=Local Network
MeshType=2
MeshID=0x...
ServerID=...
MeshServer=local
DiscoveryKey=secret123
```

### 9.4 Fully Customized Enterprise Agent

**Config.json:**
```json
{
  "domains": {
    "": {
      "agentcustomization": {
        "displayname": "Enterprise IT Support",
        "description": "Corporate remote support agent",
        "companyname": "MegaCorp Inc.",
        "servicename": "MegaCorpAgent",
        "filename": "megacorp_agent",
        "foregroundcolor": "#003366",
        "backgroundcolor": "#FFFFFF",
        "image": "/path/to/logo.png"
      },
      "agentconfig": [
        "LogLevel=3",
        "MaxLogSize=10000000",
        "ProxyURL=http://proxy.megacorp.com:8080",
        "Department=IT"
      ]
    }
  }
}
```

---

## 10. Troubleshooting Guide

### 10.1 Common Issues

**Issue:** Agent doesn't connect after download
**Solution:** Check ServerID and MeshID generation, verify certificate hash

**Issue:** Custom settings not appearing
**Solution:** Verify agentcustomization is at domain level, not global

**Issue:** Signed agent fails to run
**Solution:** Check PE header modifications, verify certificate table updates

**Issue:** MSH file not created beside agent
**Solution:** Agent may not have write permissions, check InstallFlags

### 10.2 Debug Verification

**Enable Debug Logging:**
```json
{
  "settings": {
    "debug": "agent,web"
  }
}
```

**Check Binary for MSH:**
```bash
# Linux/Mac
tail -c 1000 MeshService64.exe | xxd | grep -A5 "B996"

# Windows PowerShell
Get-Content MeshService64.exe -Tail 100 -Encoding Byte | Format-Hex
```

**Extract MSH from Binary:**
```python
import struct

def extract_msh(filename):
    with open(filename, 'rb') as f:
        # Read last 20 bytes (4 byte length + 16 byte GUID)
        f.seek(-20, 2)
        data = f.read(20)

        # Parse length (little-endian)
        length = struct.unpack('<I', data[:4])[0]

        # Read MSH data
        f.seek(-(20 + length), 2)
        msh_data = f.read(length)

        return msh_data.decode('utf-8')

print(extract_msh('MeshService64.exe'))
```

### 10.3 Validation Checklist

- [ ] ServerID is 64-character hexadecimal
- [ ] MeshID starts with `0x` and is hexadecimal
- [ ] MeshServer URL uses `wss://` protocol
- [ ] InstallFlags is between 0-3
- [ ] Service name has no special characters
- [ ] Colors are valid RGB or hex format
- [ ] Tag is alphanumeric only
- [ ] Certificate table size updated correctly (signed agents)
- [ ] Padding maintains 8-byte alignment

---

## Conclusion

The MeshCentral .MSH file system is a sophisticated configuration embedding mechanism that:

1. **Preserves digital signatures** while embedding configuration
2. **Supports multi-level configuration** inheritance
3. **Validates and sanitizes** all input data
4. **Maintains backward compatibility** with various agent versions
5. **Enables complete customization** without recompiling agents

This system allows enterprises to deploy fully customized agents while maintaining the security benefits of code signing and centralized configuration management.

---

*This forensic analysis is based on MeshCentral source code as of October 24, 2024*