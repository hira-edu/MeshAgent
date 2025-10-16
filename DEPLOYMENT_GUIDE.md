# MeshAgent Custom Build & Deployment Guide

## Overview

This repository now has automated CI/CD for building custom-branded MeshAgent binaries with the following features:

- **Custom Branding**: "Acme Telemetry Core" service name and branding
- **Automated Builds**: GitHub Actions builds both x64 and x86 binaries
- **Release Management**: Automatic publication of binaries to GitHub Releases
- **Optional Auto-Deploy**: Can automatically deploy to MeshCentral server

## Current Status

### ✅ Completed
- [x] CI workflow created and pushed to `.github/workflows/build-release.yml`
- [x] Branding configuration (`branding_config.json`) added to repository
- [x] Branding headers generated at `meshcore/generated/meshagent_branding.h`
- [x] MeshCentral server is running (root@72.60.233.29)
- [x] Nginx proxy configuration fixed for relay endpoint (port 4450)

### ⚠️ Pending Actions Required

1. **Configure GitHub Secrets** (see below)
2. **Run the CI build** (will trigger automatically on next push or manually)
3. **Test agent connectivity** after deployment
4. **Troubleshoot firewall/DNS** for relay.high.support:4450 if needed

---

## GitHub Actions Workflow

### Build Triggers

The workflow triggers on:
- **Push to master/main branch** - Automatic build
- **New tags** (v*) - Build + create GitHub Release
- **Manual dispatch** - Run workflow manually with optional deployment

### Build Process

1. Checks out repository with submodules
2. Sets up MSBuild and Python
3. Generates branding headers from `branding_config.json`
4. Builds both architectures:
   - `MeshService64.exe` (x64)
   - `MeshService.exe` (x86)
5. Uploads artifacts with 90-day retention
6. Creates GitHub Release (on tags)
7. Deploys to server (if enabled)

---

## Required GitHub Secrets

To enable full functionality, add these secrets to your repository:

### Settings → Secrets and variables → Actions → New repository secret

#### 1. `SSH_PRIVATE_KEY` (Required for deployment)
```
Your SSH private key for root@72.60.233.29
```

**How to create:**
```bash
# On your local machine or the server
ssh-keygen -t ed25519 -C "github-actions-meshagent" -f ~/.ssh/github_meshagent_deploy
cat ~/.ssh/github_meshagent_deploy  # Copy this as the secret value

# Add public key to server
ssh-copy-id -i ~/.ssh/github_meshagent_deploy.pub root@72.60.233.29
```

#### 2. `BRANDING_CONFIG_JSON` (Optional)
```json
{
  "branding": {
    "companyName": "Acme Corp",
    "serviceName": "AcmeTelemetryCore",
    "displayName": "Acme Telemetry Core Service",
    "binaryName": "AcmeTelemetryCore.exe",
    "productName": "Acme Telemetry Core",
    "description": "Acme Telemetry Core Service",
    "installRoot": "C:/ProgramData/Acme/TelemetryCore",
    "logPath": "C:/ProgramData/Acme/TelemetryCore/logs"
  },
  "network": {
    "primaryEndpoint": "wss://72.60.233.29:443/agent.ashx",
    "userAgent": "AcmeAgent/1.0",
    "useIpOnly": true
  }
}
```

**Note**: If not provided, the workflow will use `branding_config.json` from the repository.

---

## How to Build & Deploy

### Option 1: Automatic Build (on push)

Simply push changes to master:
```bash
git push origin master
```

The workflow will:
- ✅ Build both x64 and x86 binaries
- ✅ Upload as GitHub Actions artifacts
- ❌ NOT deploy to server (requires tag or manual trigger)

### Option 2: Create a Release

Push a version tag to trigger a full release:
```bash
git tag -a v1.0.0 -m "Release v1.0.0 - Custom Acme branding"
git push origin v1.0.0
```

The workflow will:
- ✅ Build both binaries
- ✅ Create GitHub Release with binaries
- ✅ Deploy to server (if SSH_PRIVATE_KEY is configured)

### Option 3: Manual Workflow Dispatch

1. Go to: https://github.com/hira-edu/MeshAgent/actions
2. Select "Build and Release Custom MeshAgent"
3. Click "Run workflow"
4. Choose:
   - Branch: `master`
   - Deploy to server: `true` or `false`
5. Click "Run workflow"

---

## Deployment Details

When deployment is enabled, the workflow:

1. **Downloads artifacts**: Gets both MeshService64.exe and MeshService.exe
2. **Uploads to server**:
   ```bash
   /opt/meshcentral/meshcentral-data/agents/MeshService64.exe
   /opt/meshcentral/meshcentral-data/agents/MeshService.exe
   ```
3. **Restarts MeshCentral**: `systemctl restart meshcentral`
4. **Verifies deployment**: Checks service status

### Server Information
- **Host**: 72.60.233.29 (high.support)
- **MeshCentral Port**: 443 (HTTPS)
- **Agent Port**: 4445 (agents.high.support)
- **Relay Port**: 4450 (relay.high.support)

---

## Testing After Deployment

### 1. Check Agent Download Page
Visit: https://high.support (or https://72.60.233.29)
- Login to MeshCentral
- Go to "My Server" → "Installation"
- Download Windows 64-bit agent
- Verify filename and properties match branding

### 2. Install Agent on Test Machine
```powershell
# Run as Administrator
.\MeshService64.exe -install

# Check service
Get-Service "Acme Telemetry Core Service"

# Check logs
Get-Content "C:\ProgramData\Acme\TelemetryCore\logs\telemetry.log"
```

### 3. Verify Agent Connection
- Check MeshCentral web UI for new device
- Verify device appears in correct mesh
- Test remote desktop/terminal functionality

---

## Troubleshooting

### Build Fails

#### Error: "Could not find MSBuild"
- Workflow uses `windows-latest` runner (includes VS 2022)
- Should not occur on GitHub-hosted runners
- If using self-hosted runner, install Visual Studio 2022 Build Tools

#### Error: "Could not find branding_config.json"
- Ensure file exists in repository root
- Or provide `BRANDING_CONFIG_JSON` secret

### Deployment Fails

#### Error: "Permission denied (publickey)"
- Ensure `SSH_PRIVATE_KEY` secret is configured
- Verify public key is in server's `~/.ssh/authorized_keys`
- Test manually: `ssh -i /path/to/key root@72.60.233.29`

#### Error: "Could not restart meshcentral"
- Check service status: `systemctl status meshcentral`
- Check logs: `journalctl -u meshcentral -n 50`

### Agent Won't Connect

#### Check 1: Endpoint Configuration
```bash
# On server
curl http://127.0.0.1:4449/agent.ashx
# Should return HTML page
```

#### Check 2: Nginx Proxy
```bash
# On server
curl -k https://agents.high.support:4445/agent.ashx
# Should return HTML page, not 404/502
```

#### Check 3: Firewall Rules
```bash
# On server
ufw status
iptables -L -n | grep 4445
```

#### Check 4: Agent Logs (Client)
```powershell
# On Windows client
Get-Content "C:\ProgramData\Acme\TelemetryCore\logs\telemetry.log" -Tail 50
```

### Known Issues

1. **relay.high.support:4450 timeout**
   - Relay endpoint may have firewall/DNS issues
   - Nginx configuration fixed (now listens on all interfaces)
   - May need firewall rule: `ufw allow 4450/tcp`

2. **agents.high.support:4445 returns 404**
   - Nginx is proxying but endpoint may need WebSocket headers
   - Backend (127.0.0.1:4449) responds correctly
   - Check Nginx logs: `tail -f /var/log/nginx/error.log`

---

## Branding Details

### Service Information
- **Service Name**: `AcmeTelemetryCore`
- **Display Name**: `Acme Telemetry Core Service`
- **Company**: `Acme Corp`
- **Binary**: `AcmeTelemetryCore.exe`
- **Install Path**: `C:\ProgramData\Acme\TelemetryCore`
- **Log Path**: `C:\ProgramData\Acme\TelemetryCore\logs`

### Network Configuration
- **Primary Endpoint**: `wss://72.60.233.29:443/agent.ashx`
- **User Agent**: `AcmeAgent/1.0`
- **IP-Only Mode**: Enabled (bypasses DNS)

### Persistence
- **Registry Run Key**: Disabled
- **Scheduled Task**: Disabled
- **WMI**: Disabled
- **Watchdog**: Enabled (checks every 600 seconds)

---

## Next Steps

1. **Configure GitHub Secrets** (if not done):
   ```
   Settings → Secrets → Actions → New secret
   - SSH_PRIVATE_KEY: [Your SSH private key]
   ```

2. **Trigger First Build**:
   ```bash
   cd MeshAgent
   git tag -a v1.0.0 -m "Initial custom build"
   git push origin v1.0.0
   ```

3. **Monitor Build**:
   - Visit: https://github.com/hira-edu/MeshAgent/actions
   - Watch build progress
   - Download artifacts when complete

4. **Test Deployment**:
   - SSH to server: `ssh root@72.60.233.29`
   - Check files: `ls -lh /opt/meshcentral/meshcentral-data/agents/MeshService*.exe`
   - Check service: `systemctl status meshcentral`

5. **Install & Test Agent**:
   - Download from MeshCentral web UI
   - Install on test Windows machine
   - Verify connection in MeshCentral

6. **Fix Remaining Issues**:
   - Test relay endpoint connectivity
   - Add firewall rules if needed
   - Update DNS if using domain names

---

## Support & References

- **MeshAgent GitHub**: https://github.com/Ylianst/MeshAgent
- **MeshCentral GitHub**: https://github.com/Ylianst/MeshCentral
- **GitHub Actions Docs**: https://docs.github.com/en/actions
- **Nginx WebSocket Proxy**: https://nginx.org/en/docs/http/websocket.html

For issues with this deployment, check:
1. GitHub Actions logs: https://github.com/hira-edu/MeshAgent/actions
2. MeshCentral logs: `ssh root@72.60.233.29 journalctl -u meshcentral -f`
3. Nginx logs: `ssh root@72.60.233.29 tail -f /var/log/nginx/error.log`
