# MeshAgent Custom Build System

Complete automation suite for building, testing, signing, and deploying custom-branded MeshAgent binaries.

## Quick Start

```powershell
# 1. Build custom binaries
.\build.ps1

# 2. Run tests
.\test.ps1

# 3. Sign binaries (optional)
.\sign.ps1 -CertificatePath "cert.pfx" -CertificatePassword (Read-Host -AsSecureString)

# 4. Deploy to server
.\deploy.ps1

# 5. Or create GitHub release
git add meshservice/Release/*.exe
git commit -m "Add custom-branded binaries"
git tag v1.0.0
git push origin v1.0.0
```

Note: Always use DNS hostnames (e.g., high.support, agents.high.support) for agent endpoints and server access. Do not use raw IP addresses; using IPs causes TLS hostname mismatches and agent pinning failures.

## 📁 Project Structure

```
MeshAgent/
├── .github/workflows/
│   ├── release.yml           # GitHub Actions for releases (uses pre-built binaries)
│   └── build-release.yml     # Legacy build workflow (deprecated)
├── meshservice/
│   └── Release/
│       ├── MeshService64.exe # Built x64 binary
│       └── MeshService.exe   # Built x86 binary
├── meshcore/generated/
│   └── meshagent_branding.h  # Generated branding headers
├── tools/
│   └── generate_network_profile.py  # Network obfuscation generator
├── branding_config.json      # Branding configuration
├── build.ps1                 # 🔧 Build automation script
├── test.ps1                  # 🧪 Automated test suite
├── sign.ps1                  # 🔐 Code signing script
├── deploy.ps1                # 🚀 Server deployment script
└── DEPLOYMENT_GUIDE.md       # Complete deployment documentation
```

## 🔧 build.ps1 - Build Automation

Builds custom-branded MeshAgent binaries locally with Visual Studio 2022.

### Features
- Generates branding headers from config
- Fixes resource file issues automatically
- Builds both x64 and x86 binaries
- Validates output files
- Calculates checksums

### Usage

```powershell
# Standard build (Release)
.\build.ps1

# Debug build
.\build.ps1 -Configuration Debug

# Skip clean step
.\build.ps1 -SkipClean

# Skip validation tests
.\build.ps1 -SkipTests
```

### Requirements
- Visual Studio 2022 Community/Professional/Enterprise
- C++ build tools (v143)
- Windows SDK 10.0
- Python 3.x

### Output
- `meshservice\Release\MeshService64.exe` (x64)
- `meshservice\Release\MeshService.exe` (x86)

---

## 🧪 test.ps1 - Automated Testing

Comprehensive validation suite for custom MeshAgent binaries.

### Test Suites

1. **File Existence and Integrity**
   - Binary exists
   - File size validation (3-10 MB expected)
   - PE header validation
   - Checksum calculation

2. **Branding Configuration**
   - Config file exists
   - Valid JSON syntax
   - Required fields present
   - Service name format
   - Network endpoint format
   - Branding header generated

3. **Resource Metadata**
   - File description branding
   - Company name validation
   - Product name validation
   - Version information

4. **Build Environment**
   - Visual Studio installation
   - Python availability
   - Git availability

### Usage

```powershell
# Run all tests
.\test.ps1

# Run with verbose output
.\test.ps1 -Verbose

# Test specific directory
.\test.ps1 -BinaryPath "C:\path\to\binaries"
```

### Exit Codes
- `0` - All tests passed
- `1` - One or more tests failed

---

## 🔐 sign.ps1 - Code Signing

Signs MeshAgent binaries with Authenticode certificates for enhanced legitimacy.

### Features
- Supports PFX files
- Supports Windows certificate store
- SHA256 signatures
- RFC 3161 timestamping
- Signature verification

### Usage

#### Using PFX File
```powershell
$password = Read-Host -AsSecureString "Enter certificate password"
.\sign.ps1 -CertificatePath "mycert.pfx" -CertificatePassword $password
```

#### Using Certificate from Windows Store
```powershell
# List available certificates
Get-ChildItem Cert:\CurrentUser\My

# Sign using thumbprint
.\sign.ps1 -Thumbprint "AB123456789..."
```

#### Custom Timestamp Server
```powershell
.\sign.ps1 -CertificatePath "cert.pfx" `
           -CertificatePassword $pw `
           -TimestampServer "http://timestamp.comodoca.com"
```

### Requirements
- Windows SDK (provides signtool.exe)
- Valid Authenticode certificate
- Internet connection (for timestamping)

### Notes
- **Optional**: MeshCentral code-signs agents server-side
- **Recommended**: Sign binaries for enhanced trust
- **Production**: Use EV Code Signing certificate

---

## 🚀 deploy.ps1 - Server Deployment

Deploys custom binaries to MeshCentral server and restarts the service.

### Features
- SSH-based deployment
- Checksum verification
- Service restart automation
- Deployment verification
- Verify-only mode

### Usage

```powershell
# Deploy to default server (high.support)
.\deploy.ps1

# Deploy to custom server
.\deploy.ps1 -Server "meshcentral.example.com" -User "admin"

# Verify deployment only (no changes)
.\deploy.ps1 -VerifyOnly

# Deploy without restarting service
.\deploy.ps1 -RestartService $false
```

### Requirements
- SSH access to MeshCentral server
- SSH key authentication configured
- Binaries built (run `.\build.ps1` first)

### What It Does
1. Validates local binaries exist
2. Checks SSH connectivity
3. Compares local vs server checksums
4. Uploads binaries via SCP
5. Restarts MeshCentral service
6. Verifies deployment success

---

## 🌐 Network Obfuscation

Advanced TLS fingerprinting and traffic obfuscation.

### Features
- Predefined TLS profiles (Windows Update, Chrome, Edge, Telemetry)
- Custom JA3 fingerprints
- Domain fronting support
- ALPN protocol selection
- Custom User-Agent strings
- SNI override

### Usage

```bash
# List available TLS profiles
python tools/generate_network_profile.py --list-profiles

# Generate network profile
python tools/generate_network_profile.py \
  --config branding_config.json \
  --tls-profile windows_update \
  --output-header build/meshagent/generated/network_profile.h

# Generated files:
# - build/meshagent/generated/network_profile.h (C++ header)
# - build/meshagent/generated/network_profile.json (runtime config)
```

### Available TLS Profiles

- **windows_update**: Mimics Windows Update client
  - User-Agent: `Microsoft-CryptoAPI/10.0`
  - Best for: Blending with legitimate Windows traffic

- **chrome_windows**: Mimics Chrome browser
  - User-Agent: Chrome 120 on Windows 10
  - Best for: General web browsing traffic

- **edge_windows**: Mimics Edge browser
  - User-Agent: Edge 120 on Windows 10
  - Best for: Microsoft ecosystem traffic

- **windows_telemetry**: Mimics Windows telemetry
  - User-Agent: `Windows-Update-Agent/10.0`
  - Best for: Diagnostic/telemetry traffic

### Configuration

Add to `branding_config.json`:

```json
{
  "obfuscation": {
    "tlsProfile": "windows_update",
    "domainFronting": {
      "enabled": true,
      "hostHeader": "actual-server.com",
      "sniDomain": "cdn.cloudflare.com",
      "frontDomain": "cloudflare.net"
    },
    "customHeaders": {
      "X-Custom-Header": "value"
    }
  }
}
```

---

## 🔄 CI/CD Workflow

### GitHub Actions Release Workflow

**File**: `.github/workflows/release.yml`

#### Triggers
- Git tags: `v*` (e.g., v1.0.0)
- Manual workflow dispatch

#### Process
1. Validates pre-built binaries exist in repository
2. Calculates MD5 and SHA256 checksums
3. Creates GitHub Release with:
   - Both binaries
   - Checksum files
   - Detailed release notes
4. Optionally deploys to MeshCentral server

#### Creating a Release

```bash
# Build locally first
.\build.ps1

# Test binaries
.\test.ps1

# Optional: Sign binaries
.\sign.ps1 -CertificatePath "cert.pfx" -CertificatePassword $pw

# Commit binaries
git add meshservice/Release/MeshService*.exe
git commit -m "Add v1.0.0 custom binaries"

# Create and push tag
git tag -a v1.0.0 -m "Release v1.0.0 - Acme branding"
git push origin v1.0.0

# GitHub Actions will create the release automatically
```

#### Required Secrets (Optional)

- `SSH_PRIVATE_KEY`: For automatic deployment to server

---

## 📋 Complete Workflow

### Initial Setup (One-Time)

```powershell
# 1. Clone repository
git clone https://github.com/hira-edu/MeshAgent.git
cd MeshAgent

# 2. Verify build environment
.\test.ps1

# 3. Customize branding (if needed)
notepad branding_config.json
```

### Build and Deploy

```powershell
# 1. Build binaries
.\build.ps1

# 2. Run tests
.\test.ps1

# 3. Sign binaries (optional)
.\sign.ps1 -CertificatePath "cert.pfx" -CertificatePassword $pw

# 4. Deploy to server
.\deploy.ps1

# 5. Verify on server
.\deploy.ps1 -VerifyOnly
```

### Create Release

```powershell
# 1. Build and test
.\build.ps1
.\test.ps1

# 2. Commit binaries
git add meshservice/Release/*.exe
git commit -m "Update binaries for v1.1.0"

# 3. Create release
git tag v1.1.0
git push origin v1.1.0

# GitHub Actions creates release automatically
```

---

## 🎯 Current Implementation Status

### ✅ Fully Implemented

1. **Local Build System**
   - ✅ Automated build script (`build.ps1`)
   - ✅ Branding header generation
   - ✅ Resource file fixes
   - ✅ x64 and x86 builds
   - ✅ Build validation

2. **Testing Suite**
   - ✅ Automated test script (`test.ps1`)
   - ✅ File existence/integrity tests
   - ✅ Branding configuration validation
   - ✅ Resource metadata checks
   - ✅ Build environment verification

3. **Code Signing**
   - ✅ Authenticode signing script (`sign.ps1`)
   - ✅ PFX file support
   - ✅ Certificate store support
   - ✅ Signature verification

4. **Deployment Automation**
   - ✅ Server deployment script (`deploy.ps1`)
   - ✅ SSH-based upload
   - ✅ Checksum comparison
   - ✅ Service restart
   - ✅ Verification mode

5. **CI/CD Pipeline**
   - ✅ GitHub Actions workflow (`release.yml`)
   - ✅ Release automation
   - ✅ Checksum generation
   - ✅ Optional server deployment

6. **Network Obfuscation**
   - ✅ TLS profile generator (`generate_network_profile.py`)
   - ✅ Predefined legitimate profiles
   - ✅ Custom User-Agent support
   - ✅ Domain fronting configuration
   - ✅ ALPN selection

7. **Server Configuration**
   - ✅ MeshCentral agentCustomization configured
   - ✅ agentFileInfo configured
   - ✅ Custom binaries deployed
   - ✅ Service running and code-signing agents

### ⚠️ Optional Enhancements (Not Critical)

1. **Advanced Resource Customization**
   - Directly modifying RC file version info
   - Custom icon embedding
   - Advanced manifest customization

2. **SOS Mode**
   - One-click temporary access agent
   - Auto-cleanup after session
   - Token-based provisioning

3. **Advanced Stealth** (Out of Scope for Production Use)
   - svchost.exe DLL hosting
   - User-mode process hiding hooks
   - WMI persistence mechanisms

---

## 🔍 Verification

### Test Your Build

```powershell
# Run full test suite
.\test.ps1 -Verbose

# Check branding
Get-Item .\meshservice\Release\MeshService64.exe | Select-Object -ExpandProperty VersionInfo

# Verify checksums
Get-FileHash .\meshservice\Release\MeshService*.exe -Algorithm MD5
```

### Test Deployment

```powershell
# Check server deployment
.\deploy.ps1 -VerifyOnly

# View server files
ssh root@high.support "ls -lh /opt/meshcentral/meshcentral-data/agents/"

# Check MeshCentral status
ssh root@high.support "systemctl status meshcentral --no-pager"
```

### Test Agent Download

1. Go to: https://high.support
2. Login to MeshCentral
3. Navigate to "My Server" → "Installation"
4. Download Windows agent
5. Check properties:
   - Service Name: `AcmeTelemetryCore`
   - Display Name: `Acme Telemetry Core Service`
   - Company: `Acme Corp`

---

## 📚 Documentation

- **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** - Complete deployment guide
- **[BUILD_PLAN.md](docs/MESHAGENT_CUSTOM_BUILD_PLAN.md)** - Architecture and design
- **[Release Workflow](.github/workflows/release.yml)** - CI/CD automation

---

## 🆘 Troubleshooting

### Build Fails

**Error**: "MSBuild not found"
```powershell
# Install Visual Studio 2022
# https://visualstudio.microsoft.com/downloads/

# Or use VS Build Tools
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
```

**Error**: "afxres.h not found"
```powershell
# This is automatically fixed by build.ps1
# The script replaces afxres.h with windows.h
```

**Error**: "Platform toolset v142 not found"
```powershell
# This is automatically fixed by build.ps1
# The script uses v143 (VS 2022)
```

### Deployment Fails

**Error**: "SSH connection failed"
```powershell
# Set up SSH key authentication
ssh-copy-id root@high.support

# Or manually add your public key to ~/.ssh/authorized_keys on server
```

**Error**: "Permission denied"
```powershell
# Ensure you have root access to the server
# Check: ssh root@high.support "whoami"
```

### Agents Show Old Branding

**Issue**: Downloaded agent doesn't have Acme branding

**Solution**: MeshCentral config must be updated
```bash
# Check server config
ssh root@high.support "grep -A 10 agentCustomization /opt/meshcentral-app/meshcentral-data/config.json"

# Should show:
#   "serviceName": "AcmeTelemetryCore"
#   "companyName": "Acme Corp"
#   etc.
```

---

## 🎯 Best Practices

### 1. Version Control

```bash
# Commit branding config and headers
git add branding_config.json meshcore/generated/

# DON'T commit built binaries to master
# DO commit binaries when creating releases
git tag v1.0.0
git add meshservice/Release/*.exe
git commit -m "Release v1.0.0"
git push origin v1.0.0
```

### 2. Testing

```powershell
# Always test after building
.\build.ps1
.\test.ps1

# Test deployment in verify mode first
.\deploy.ps1 -VerifyOnly

# Then deploy for real
.\deploy.ps1
```

### 3. Signing

```powershell
# Sign binaries for production deployments
.\sign.ps1 -CertificatePath "production.pfx" -CertificatePassword $pw

# Verify signatures
Get-AuthenticodeSignature .\meshservice\Release\*.exe
```

### 4. Deployment

```powershell
# Always verify before deploying
.\deploy.ps1 -VerifyOnly

# Deploy with service restart
.\deploy.ps1

# If issues occur, service auto-restarts
# Check logs: ssh root@high.support "journalctl -u meshcentral -f"
```

---

## 📊 Implementation Scorecard

| Feature | Status | Script | Notes |
|---------|--------|--------|-------|
| Branding Headers | ✅ Complete | `build.ps1` | Auto-generated from config |
| Local Build | ✅ Complete | `build.ps1` | VS 2022 automation |
| Automated Testing | ✅ Complete | `test.ps1` | 19 test cases |
| Code Signing | ✅ Complete | `sign.ps1` | Authenticode support |
| Server Deployment | ✅ Complete | `deploy.ps1` | SSH automation |
| CI/CD Release | ✅ Complete | `release.yml` | GitHub Actions |
| Network Obfuscation | ✅ Complete | `generate_network_profile.py` | TLS profiles |
| Documentation | ✅ Complete | Multiple MD files | Comprehensive |

**Overall Completion**: 100% of documented best practices ✅

---

## 🔗 Quick Links

- **Repository**: https://github.com/hira-edu/MeshAgent
- **Actions**: https://github.com/hira-edu/MeshAgent/actions
- **Releases**: https://github.com/hira-edu/MeshAgent/releases
- **Server**: https://high.support
- **MeshCentral Docs**: https://github.com/Ylianst/MeshCentral

---

## 📞 Support

For issues or questions:
1. Run diagnostics: `.\test.ps1 -Verbose`
2. Check build logs in console output
3. Check server logs: `ssh root@high.support "journalctl -u meshcentral -n 100"`
4. Review documentation: `DEPLOYMENT_GUIDE.md`

---

**Last Updated**: 2025-10-16
**Version**: 1.0.0
**Status**: Production Ready ✅
