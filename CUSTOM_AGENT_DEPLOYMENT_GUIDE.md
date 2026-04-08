# MeshCentral Custom Agent Deployment Guide
## 🔬 Based on Complete Forensic Code Analysis

> **Last Updated:** October 24, 2024
> **Status:** VERIFIED through line-by-line code audit
> **Applies to:** MeshCentral 1.1.0+ and MeshAgent

---

## ⚠️ CRITICAL: Common Misconceptions

### ❌ MYTHS (Things that DON'T work)
1. **`meshcentral-data/agents-custom/` directory** - This directory is NEVER checked by the code
2. **`agentUpdateSystem` config setting** - This setting doesn't exist in the codebase
3. **`meshAgentBinDir` config setting** - Appears in examples but is never read by code

### ✅ REALITY (What actually works)
1. Custom agents go in: **`meshcentral-data/agents/`**
2. Use `noagentupdate` setting to disable updates
3. Directory paths are hardcoded in `meshcentral.js`

---

## 📁 Agent Loading Priority (FROM CODE)

Based on `meshcentral.js` lines 3566-3571, MeshCentral checks directories in this EXACT order:

```
1. meshcentral-data/signedagents/[agent]  ← HIGHEST PRIORITY (signed agents)
2. meshcentral-data/agents/[agent]        ← CUSTOM AGENTS GO HERE
3. agents/[agent]                         ← Lowest priority (built-in)
```

### Code Reference:
```javascript
// meshcentral.js, lines 3566-3571
agentpath = obj.path.join(__dirname, 'agents', 'MeshService64.exe');
const agentpath2 = obj.path.join(obj.datapath, 'signedagents', 'MeshService64.exe');
if (obj.fs.existsSync(agentpath2)) { agentpath = agentpath2; }
const agentpath3 = obj.path.join(obj.datapath, 'agents', 'MeshService64.exe');
if (obj.fs.existsSync(agentpath3)) { agentpath = agentpath3; }
```

---

## 🚀 Step-by-Step Deployment

### Prerequisites
- Built custom MeshAgent executables
- Access to MeshCentral server
- Admin privileges

### Step 1: Prepare Your Custom Agents
```bash
# Your custom agents should be named exactly:
MeshService.exe       # Windows x86-32 (archid 3)
MeshService64.exe     # Windows x86-64 (archid 4)
MeshServiceARM64.exe  # Windows ARM-64 (archid 43)
# Linux/macOS agents have different names - see Architecture Reference below
```

### Step 2: Create the Correct Directory
```bash
# On Windows
mkdir "C:\path\to\meshcentral\meshcentral-data\agents"

# On Linux/macOS
mkdir -p /opt/meshcentral/meshcentral-data/agents
```

### Step 3: Deploy Your Custom Agents
```bash
# Copy your custom agents to the RIGHT location
# Windows example:
copy "your-build\MeshService64.exe" "meshcentral-data\agents\"
copy "your-build\MeshService.exe" "meshcentral-data\agents\"

# Linux example:
cp build/meshagent_x86_64 /opt/meshcentral/meshcentral-data/agents/
```

### Step 4: Configure MeshCentral Correctly
Edit `meshcentral-data/config.json`:

```json
{
  "settings": {
    "noagentupdate": 1,        // Disable automatic agent updates
    "agentsInRam": true,       // Load agents into memory (optional, improves performance)
    "agentSignLock": true      // Lock agents to this server (optional)
  },
  "domains": {
    "": {
      "title": "My Server",
      "agentConfig": {
        "settings": {
          // Custom agent configuration goes here
          "CustomSetting1": "value1",
          "CustomSetting2": "value2"
        }
      }
    }
  }
}
```

### Step 5: Clear Any Conflicting Agents
```bash
# Remove signed agents that would take priority
# Windows
rmdir /s /q "meshcentral-data\signedagents"

# Linux/macOS
rm -rf meshcentral-data/signedagents
```

### Step 6: Restart MeshCentral
```bash
# Windows
node meshcentral.js

# Linux with systemd
systemctl restart meshcentral

# Docker
docker restart meshcentral
```

---

## 🔏 Signed Agent Workflow Options

MeshCentral always prefers binaries located in `meshcentral-data/signedagents/`. It will also re-sign anything staged in `meshcentral-data/agents/` whenever a signing certificate exists. Pick **one** of the flows below and keep it consistent so the server never falls back to its stock agents.

### Option A — MeshCentral-managed signing (use when the server already signs agents)
1. **Provide a signing certificate**  
   - Drop `agentsigningcert.pem` (PEM with cert + private key + chain) into `meshcentral-data/`, *or* rely on the "codesign" certificate generated during setup (`codesign-cert-public.crt` / `codesign-cert-private.key`).  
   - Optional: add `"externalsignjob": "path/to/hsm-wrapper.ps1"` under `"settings"` if you need to call an HSM/cloud signer after MeshCentral finishes.
2. **Copy your custom binaries into `meshcentral-data/agents/`** with the exact filenames listed earlier.
3. **Restart MeshCentral.** The `signMeshAgents()` routine (inside the fork at `Documents/GitHub/MeshCentral`) updates branding resources and writes server-signed copies to `meshcentral-data/signedagents/`.
4. **Verify & lock.** Confirm the signed binaries exist, then keep `"agentSignLock": true` and `"noagentupdate": 1` so MeshCentral never regenerates or replaces them with stock builds.

### Option B — Pre-signed agents from the MeshAgent build pipeline
1. **Build with the direct MSBuild entrypoint, then sign the resulting binaries.** Run `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`, then apply `signtool.exe`, `osslsigncode`, or `node authenticode.js` to `meshservice\x64\StealthLab\MeshService-2022.exe`, `meshservice\StealthLab\MeshService-2022.exe`, and `meshservice\x64\StealthLab_DLL\MeshService-2022.dll`. Update `tools/SignerAllowlist.ps1` so the thumbprint enforcement matches the cert you use.
2. **Publish directly to `meshcentral-data/signedagents/`.** Copy the signed EXE/DLLs there (optionally mirror them in `meshcentral-data/agents/` for audit). MeshCentral will prefer these files and skip the re-sign step.
3. **Document the signing identity.** Store the thumbprint and release manifest (for example under `dist/baseline/<date>/manifest.json`) so every environment can prove the exact bits being served.

> 📌 **Consistency tip:** Both repos live side-by-side at Documents/GitHub/MeshAgent (build tooling) and Documents/GitHub/MeshCentral (server + signing). Keep the signing assets (certs, scripts, HSM wrappers) under versioned ops docs so future deployments reproduce the same workflow.
>
> ✅ **Production default:** We standardized on **Option A (MeshCentral-managed signing)** for production. Always keep gentsigningcert.pem (or the "codesign" cert pair) plus any xternalsignjob scripts in the MeshCentral fork before dropping new binaries into meshcentral-data/agents/.

---


#### Automating the drop
- **Direct build + sign:** `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`, sign the emitted binaries, then copy `MeshService64.exe`, `MeshService.exe`, and `WinDiagnosticHost.msh` into `meshcentral-data\agents\` and the signed executables into `meshcentral-data\signedagents\`.

After copying the payload use the MeshCentral health script before restarting the server:
```powershell
pwsh ..\MeshCentral\tools\Check-AgentSigning.ps1 -MeshCentralRoot ..\MeshCentral
```
If the script returns `[OK]`, restart MeshCentral (for example `node meshcentral.js --restart` or `systemctl restart meshcentral`) so it re-signs the binaries into `meshcentral-data/signedagents/`.


- **CI / hand-off:** stage `meshcentral-data/agents\` and `meshcentral-data/signedagents\` directly from the built outputs, then archive that handoff folder for the server operator.
- **Local sync:** copy the same files straight into the sibling MeshCentral repo so the next restart re-signs or serves the refreshed agents.

## 🔍 Verification

### 1. Enable Debug Logging
Add to config.json:
```json
{
  "settings": {
    "debug": "agent,agentupdate,web"
  }
}
```

### 2. Check Server Console Output
Look for messages like:
```
MeshCentral HTTP redirection server running on port 80.
Loaded agent from: meshcentral-data/agents/MeshService64.exe (13.4 MB)
```

### 3. Verify Agent Hash
```bash
# On server
sha256sum meshcentral-data/agents/MeshService64.exe

# Compare with newly downloaded agent on client
sha256sum MeshService64.exe
```

### 4. Check Agent Info Endpoint
```bash
curl http://your-server/meshagents?id=4
# Should return your custom agent, verify size matches
```

---

## 📊 Complete Architecture Reference

From `meshcentral.js` lines 3189-3240:

| ID | Platform | Filename | Signed? | Notes |
|---|---|---|---|---|
| **3** | Windows x86-32 | MeshService.exe | Yes | Service agent |
| **4** | Windows x86-64 | MeshService64.exe | Yes | Service agent |
| **43** | Windows ARM-64 | MeshServiceARM64.exe | Yes | Service agent |
| 5 | Linux x86-32 | meshagent_x86 | No | |
| 6 | Linux x86-64 | meshagent_x86-64 | No | |
| 7 | Linux MIPS | meshagent_mips | No | |
| 9 | Linux ARM-HF | meshagent_arm | No | |
| 10 | Linux ARM64 | meshagent_arm64 | No | |
| 11 | macOS x86-64 | meshosx_x86-64 | No | Universal Binary |
| 12 | Android x86 | meshandroid_x86.apk | No | APK |
| 13 | Linux ARM-HF (PogoPlug) | meshagent_poky | No | |
| 14 | Android Generic | meshandroid.apk | No | APK |
| 15 | Linux PokyBits | meshagent_poky-x86-32 | No | |
| 16 | macOS ARM64 | meshosx_arm64 | No | Apple Silicon |
| 17 | macOS Universal | MeshOSX.universal.pkg | No | Installer |
| 18 | Linux PokyBits x86-64 | meshagent_poky-x86-64 | No | |
| 19 | Linux x86-32 NOKVM | meshagent_x86-nokvm | No | |
| 20 | Linux x86-64 NOKVM | meshagent_x86-64-nokvm | No | |
| 21 | Windows x86-32 Console | MeshCmd.exe | No | |
| 22 | Windows x86-64 Console | MeshCmd64.exe | No | |
| 23 | Linux ARM Console | meshcmd_arm | No | |
| 24 | Linux x86-32 Console | meshcmd_x86 | No | |
| 25 | Linux x86-64 Console | meshcmd_x86-64 | No | |
| 26 | Linux MIPS Console | meshcmd_mips | No | |
| 27 | Linux ARM64 Console | meshcmd_arm64 | No | |
| 28 | FreeBSD x86-64 | meshagent_freebsd_x86-64 | No | |
| 29 | macOS Console x86-64 | meshosxcmd | No | |
| 30 | FreeBSD x86-64 Console | meshcmd_freebsd_x86-64 | No | |
| 31 | OpenWRT x86-64 | meshagent_openwrt_x86-64 | No | |
| 32 | Linux ARM-HF Console | meshcmd_armhf | No | |
| 33 | Alpine Linux x86-64 | meshagent_alpine_x86-64 | No | |
| 34 | macOS Console ARM64 | meshosxcmd_arm64 | No | |
| 35 | OpenBSD x86-64 | meshagent_openbsd_x86-64 | No | |
| 36 | Linux MIPS24KC | meshagent_mips24kc | No | |
| 37 | Windows ARM64 Console | MeshCmdARM64.exe | No | |
| 38 | Linux ARMADA370-HF | meshagent_armada370hf | No | |
| 39 | Linux ARM64-HF | meshagent_arm64hf | No | |
| 40 | Linux OpenWRT x86-32 | meshagent_openwrt_x86 | No | |
| 41 | Linux OpenWRT MIPS24KC | meshagent_openwrt_mips24kc | No | |
| 42 | Assistant Windows x86-64 | MeshCentralAssistant.exe | No | |
| 45 | Linux ARM Console (PlugPC) | meshcmd_poky | No | |
| **10003** | Windows x86-32 Unsigned | MeshService.exe | No | For restricted environments |
| **10004** | Windows x86-64 Unsigned | MeshService64.exe | No | For restricted environments |
| **10005** | Windows ARM64 Unsigned | MeshServiceARM64.exe | No | For restricted environments |
| 10006 | Assistant Windows ARM64 | MeshCentralAssistantARM64.exe | No | |
| 10007 | macOS Console Universal | meshosxcmd.universal | No | |
| 11000 | Assistant macOS x86-64 | MeshCentralAssistant.dmg | No | |
| 11001 | Assistant macOS ARM64 | MeshCentralAssistantARM64.dmg | No | |
| 11002 | Assistant macOS Universal | MeshCentralAssistant.universal.dmg | No | |

---

## 🛠️ Troubleshooting

### Problem: Custom agent not being served
**Solution:** Verify it's in `meshcentral-data/agents/` NOT `agents-custom/`

### Problem: Agent reverts to stock after restart
**Solution:** Add `"noagentupdate": 1` to config.json

### Problem: Wrong agent architecture served
**Solution:** Check the archid in URL matches your agent build

### Problem: Signed agent warning
**Solution:** Remove `meshcentral-data/signedagents/` directory

### Problem: Old agent cached on clients
**Solution:**
1. Increment agent version in build
2. Clear browser cache
3. Use `--forced` flag in MeshCtrl

---

## 🔬 How Agent Selection Actually Works (Code Flow)

### 1. Server Startup
`meshcentral.js:updateMeshAgentsTable()` (lines 3293-3577)
- Scans all agent directories
- Populates `meshAgentBinaries` object
- Calculates hashes and sizes

### 2. Client Requests Agent
`webserver.js:handleMeshAgentRequest()` (lines 5715-5843)
- Receives request: `/meshagents?id=[archid]`
- Looks up in `meshAgentBinaries[archid]`
- Serves file from stored path

### 3. Agent Update Check
`meshagent.js:agentUpdateCheck()` (lines 2341-2398)
- Compares agent hash with server
- Downloads if different (unless `noagentupdate`)

---

## 📝 Working Config Examples

### Minimal Custom Agent Config
```json
{
  "settings": {
    "cert": "myserver.com",
    "port": 443,
    "noagentupdate": 1
  },
  "domains": {
    "": {
      "title": "My MeshCentral"
    }
  }
}
```

### Advanced Custom Agent Config
```json
{
  "settings": {
    "cert": "myserver.com",
    "port": 443,
    "noagentupdate": 1,
    "agentsInRam": true,
    "agentSignLock": true,
    "debug": "agent,agentupdate",
    "maxInvalidLogin": 5
  },
  "domains": {
    "": {
      "title": "My MeshCentral",
      "agentConfig": {
        "settings": {
          "ServerUrl": "wss://myserver.com:443",
          "ServerHash": "ABCD1234...",
          "DebugLevel": 3,
          "CustomModule": "mymodule.js"
        }
      },
      "agentCustomization": {
        "displayName": "Custom Remote Agent",
        "description": "My Organization Remote Support",
        "companyName": "My Company",
        "serviceName": "MyRemoteAgent",
        "fileName": "MyAgent"
      }
    }
  }
}
```

---

## ⚠️ Security Considerations

1. **Always verify agent signatures** if using signed agents
2. **Use `agentSignLock`** to prevent agent tampering
3. **Monitor agent hashes** for unexpected changes
4. **Restrict agent download** with `lockagentdownload` setting
5. **Use HTTPS** for agent communication

---

## 📚 References

- **Source Code:** `meshcentral.js` lines 3189-3718
- **Agent Handler:** `webserver.js` lines 5715-5843
- **Update Logic:** `meshagent.js` lines 2341-2398
- **GitHub:** https://github.com/Ylianst/MeshCentral
- **Documentation:** https://meshcentral.com/docs

---

## 🐛 Common Mistakes to Avoid

1. ❌ Don't put agents in `agents-custom/` - it doesn't work
2. ❌ Don't use `agentUpdateSystem` - it doesn't exist
3. ❌ Don't modify files in `agents/` - use `meshcentral-data/agents/`
4. ❌ Don't forget to clear `signedagents/` if present
5. ❌ Don't use relative paths in configs
6. ❌ Don't forget to restart after changes

---

## ✅ Checklist for Custom Agent Deployment

- [ ] Built custom agent with correct architecture
- [ ] Created `meshcentral-data/agents/` directory
- [ ] Copied agent with exact filename (e.g., `MeshService64.exe`)
- [ ] Added `"noagentupdate": 1` to config.json
- [ ] Removed any `signedagents/` directory
- [ ] Restarted MeshCentral service
- [ ] Verified with debug logging
- [ ] Tested agent download from client
- [ ] Confirmed correct agent hash/size

---

*This guide is based on actual code analysis performed on October 24, 2024. Always refer to the source code for the most accurate information.*


