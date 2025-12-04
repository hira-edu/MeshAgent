# GitHub Actions StealthLab Build Configuration

## What Was Changed

The GitHub Actions workflow has been updated to build **StealthLab configuration** instead of **Release configuration**.

### Key Changes:

1. **Configuration Changed:** `Release` → `StealthLab`
2. **DLL Pre-Build Added:** Builds `StealthLab_DLL` configuration first (x64 only)
3. **Payload Staging:** Automatically stages the DLL to `meshservice/embedded/svchost_payload.dll`
4. **Resource Compilation:** Now includes `bundle_resources.rc` which embeds the DLL
5. **Artifact Naming:** Artifacts renamed to `StealthLab-*` for clarity
6. **DLL Upload:** Uploads the standalone DLL as separate artifact
7. **Size Verification:** Checks that binaries are ~5.7 MB (not 3.3 MB)

---

## What GitHub Actions Now Builds

### Artifacts (Available for Download)

After each build, the following artifacts are available:

| Artifact Name | File | Size | Description |
|---------------|------|------|-------------|
| `StealthLab-MeshService64.exe` | MeshService64.exe | ~5.7 MB | x64 with embedded DLL |
| `StealthLab-MeshService.exe` | MeshService.exe | ~5.1 MB | x86 with embedded DLL |
| `StealthLab-diagsvc.dll` | MeshService-2022.dll | ~2.4 MB | Svchost DLL payload |

### Build Process

1. **Build DLL First** (x64 only):
   ```
   Configuration: StealthLab_DLL
   Platform: x64
   Output: meshservice/x64/StealthLab_DLL/MeshService-2022.dll
   ```

2. **Stage DLL for Embedding**:
   ```
   Copy: meshservice/x64/StealthLab_DLL/MeshService-2022.dll
   To:   meshservice/embedded/svchost_payload.dll
   ```

3. **Build StealthLab EXE** (both x86 and x64):
   ```
   Configuration: StealthLab
   Platform: Win32 / x64
   Resources: Includes bundle_resources.rc (embeds svchost_payload.dll)
   Output: meshservice/{x64|}/StealthLab/MeshService-2022.exe (~5.7 MB)
   ```

---

## How to Trigger a Build

### Method 1: Push to Main/Master
```bash
git add .github/workflows/build-release.yml
git commit -m "Update CI to build StealthLab with embedded DLL"
git push origin main
```

The workflow will automatically build and upload artifacts.

### Method 2: Manual Workflow Dispatch

1. Go to GitHub → Actions → "Build and Release Custom MeshAgent"
2. Click "Run workflow"
3. Select branch (main/master)
4. Optionally enable "Deploy to MeshCentral server after build"
5. Click "Run workflow"

### Method 3: Create a Release Tag
```bash
git tag v1.0.0
git push origin v1.0.0
```

This will:
- Build StealthLab binaries
- Upload as GitHub artifacts
- Create a GitHub Release with the binaries attached
- Optionally deploy to server (if SSH secrets configured)

---

## Download Built Artifacts

### From GitHub Actions UI:

1. Go to: https://github.com/YOUR_USERNAME/MeshAgent/actions
2. Click on a successful workflow run
3. Scroll to "Artifacts" section
4. Download:
   - `StealthLab-MeshService64.exe`
   - `StealthLab-MeshService.exe`
   - `StealthLab-diagsvc.dll`

### From GitHub CLI:
```bash
# List recent runs
gh run list --workflow="build-release.yml"

# Download artifacts from latest run
gh run download --name StealthLab-MeshService64.exe
gh run download --name StealthLab-MeshService.exe
gh run download --name StealthLab-diagsvc.dll
```

---

## Runtime Validation (Svchost-Only Mode)

Both `core-migration-baseline.yml` and the optional `runtime-validation` job inside `build-release.yml` now call `tools/Invoke-RuntimeValidation.ps1`, which forces `test.ps1 -RuntimeValidation -SvchostOnly`. That means CI only exercises the svchost register/status/unregister flow (no legacy standalone install paths) and captures evidence under `verification\*\runtime.json`.

### Required inputs/secrets
- `runtime_validation` (workflow dispatch checkbox) or `secrets.RUNTIME_VALIDATION=true`
- `runtime_control_url` / `RUNTIME_CONTROL_URL` – e.g. `wss://stealthlab.example.com:443/agent.ashx`
- `runtime_mesh_id`, `runtime_mesh_user`, `runtime_mesh_pass` – credentials for a MeshCentral device group that already trusts the StealthLab build
- (Optional) `runtime_meshcentral_repo` if CI should use a fork instead of `Ylianst/MeshCentral`

### Making MeshCentral reachable from CI
- **GitHub-hosted runners:** point `runtime_control_url` at a public DNS name/front door that terminates to your lab MeshCentral instance. Use the branding JSON to list the same host so runtime hashes line up. If the server is only reachable over VPN, use a self-hosted runner instead.
- **Self-hosted runners:** you control DNS. Populate `hosts`/split-brain records so the hostname in `runtime_control_url` resolves to the lab MeshCentral address, or set `runtime_control_url` to an IP-based URL (https://10.0.0.5:443/agent.ashx) that your runner can reach directly.
- Keep the Mesh ID and credentials scoped to a throwaway test group; the runtime helper wipes cached downloads, reinstalls the agent, and unregisters the svchost service every run.

### Evidence / artefacts
- `runtime-validation-results` artifact: contains `verification/ci/runtime.json` + `.log` (release workflow) or `out/baseline/<date>/verification/runtime.*` (baseline workflow). These uploads now fail the workflow if the files are missing, so every gated build carries verifiable runtime evidence.
- `Invoke-RuntimeValidation.ps1` exposes `-IncludeFullInstall` if you need to run the legacy install/uninstall checks locally; CI defaults to svchost-only.

---

## Automatic Deployment (Optional)

### Setup SSH Secrets

To enable automatic deployment to your MeshCentral server:

1. Go to GitHub → Settings → Secrets and variables → Actions
2. Add secrets:

| Secret Name | Value | Required |
|-------------|-------|----------|
| `SSH_PRIVATE_KEY` | Your SSH private key | Yes (if using key auth) |
| `SSH_PASSWORD` | Server root password | Yes (if using password auth) |
| `SSH_USER` | `root` | Optional (defaults to root) |

3. Enable deployment when running workflow manually:
   - GitHub Actions → Run workflow → Check "Deploy to MeshCentral server after build"

### What Auto-Deploy Does:

1. Stops MeshCentral service
2. Creates `/opt/meshcentral/meshcentral-data/agents-custom/`
3. Uploads all 3 files (x64, x86, dll)
4. Sets correct permissions
5. Restarts MeshCentral
6. Verifies deployment

---

## Verification

### After CI Build:

Check the workflow log for:
```
Binary size: 5.73 MB
SUCCESS: StealthLab binary with embedded DLL (5.73 MB)
```

If you see:
```
WARNING: Binary is too small (3.3 MB). Expected ~5.7 MB for StealthLab build with embedded DLL!
```

Then something went wrong - the `bundle_resources.rc` wasn't compiled.

### After Deployment:

SSH into server and verify:
```bash
ls -lh /opt/meshcentral/meshcentral-data/agents-custom/

# Should show:
# MeshService64.exe: ~5.7M (NOT 3.3M)
# MeshService.exe: ~5.1M
# diagsvc.dll: ~2.4M
```

---

## Troubleshooting

### CI still builds 3.3 MB binaries

**Cause:** `bundle_resources.rc` not being compiled or `svchost_payload.dll` missing

**Fix:**
1. Ensure DLL build step runs first (x64 only)
2. Check that `meshservice/embedded/svchost_payload.dll` exists before main build
3. Verify `bundle_resources.rc` has correct path

### Resource compilation fails

**Error:** `RC1015: cannot open include file 'embedded\svchost_payload.dll'`

**Fix:**
```powershell
# Manually stage the DLL
New-Item -ItemType Directory -Force -Path "meshservice/embedded"
Copy-Item "meshservice/x64/StealthLab_DLL/MeshService-2022.dll" `
          "meshservice/embedded/svchost_payload.dll"
```

### Deployment fails

**Error:** `Permission denied` or `Connection refused`

**Fix:**
1. Verify SSH secrets are configured
2. Test SSH manually: `ssh root@72.60.233.29`
3. Ensure server allows root SSH access

---

## Build Order

The workflow now follows this critical order:

```
1. Build DLL (x64 only)
   Configuration: StealthLab_DLL
   Output: MeshService-2022.dll (2.4 MB)

2. Stage DLL
   Copy to: meshservice/embedded/svchost_payload.dll

3. Build x64 EXE
   Configuration: StealthLab
   Includes: bundle_resources.rc (embeds svchost_payload.dll)
   Output: MeshService-2022.exe (5.7 MB)

4. Build x86 EXE
   Configuration: StealthLab
   Includes: bundle_resources.rc (embeds svchost_payload.dll)
   Output: MeshService-2022.exe (5.1 MB)
```

**Critical:** Steps 1 & 2 MUST complete before step 3 & 4, otherwise the DLL won't be embedded!

---

## Next Steps

1. **Commit the changes:**
   ```bash
   git add .github/workflows/build-release.yml
   git add GITHUB_ACTIONS_STEALTHLAB.md
   git commit -m "Configure CI to build StealthLab with embedded svchost DLL

   - Changed configuration from Release to StealthLab
   - Added DLL pre-build and staging step
   - Updated artifact names to StealthLab-*
   - Added DLL artifact upload
   - Updated deployment to use agents-custom directory
   - Added binary size verification"

   git push origin main
   ```

2. **Monitor the build:**
   - Go to GitHub Actions
   - Watch the workflow run
   - Verify binaries are ~5.7 MB

3. **Download and test:**
   - Download artifacts from GitHub
   - Install on test machine
   - Verify svchost integration works

---

**Created:** 2025-10-22
**Purpose:** Document GitHub Actions StealthLab build configuration
**Status:** ✅ Ready to commit and deploy
