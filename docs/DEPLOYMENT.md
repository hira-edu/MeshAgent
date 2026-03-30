# Deployment — Single Source of Truth

> Authoritative reference for deploying MeshAgent binaries AND MeshCentral server code to the production server.

Related operational SSOT:

- `docs/REPO_SYNC_AND_DEPLOYMENT_PLAN.md` for cross-repo keep-set, sync hygiene, branch policy, and combined release order across `MeshAgent`, `MeshCentral`, and `UserModeHook`.

## Server Infrastructure

| Property | Value |
|---|---|
| **Host** | `167.88.44.65` (`srv1057130.hstgr.cloud`) |
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
| Standalone EXE | `meshservice/x64/StealthLab/MeshService-2022.exe` | **`MeshService64.exe`** |
| Svchost DLL | `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | `MeshService64.dll` |
| Embedded Payload | `meshservice/embedded/svchost_payload.dll` | `svchost_payload.dll` |
| MasterService | `../UserModeHook/build-fresh/bin/Release/MasterService.exe` | `MasterService.exe` |

**Important:** The Visual Studio build output is named `MeshService-2022.exe`. During staging/deploy it is **renamed** to `MeshService64.exe` to match the filename MeshCentral expects when serving agents to endpoints.

## hashagents.json

After deploying new binaries, `hashagents.json` must be regenerated from the actual published bytes. MeshCentral reads `node_modules/meshcentral/agents/hashagents.json` at startup, then prefers `meshcentral-data/signedagents/` binaries when they exist. The signed-agent manifest is maintained for observability and post-restart verification, but the module-side manifest is the authoritative runtime input. Each entry contains:

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
1. Verifies staging has files
2. Creates timestamped backup of current agents in both paths
3. Copies staged agent binaries → `/opt/meshcentral/meshcentral-data/signedagents/`
4. Copies staged agent binaries → `/opt/meshcentral/node_modules/meshcentral/agents/`
5. Copies `MasterService.exe` → `/opt/meshcentral/meshcentral-files/domain/user-hsadmin/Public/` (for agent download)
6. Regenerates `hashagents.json` for both publish directories from the actual remote files
7. Restarts `meshcentral` systemd service
8. Re-runs post-restart publish verification so `node_modules/meshcentral/agents/` and its manifest still match the local build while `signedagents/` remains self-consistent if MeshCentral repacks/signs the EXEs
9. Writes local release manifest with repo SHAs + artifact hashes under `docs/testing/artifacts/`
10. Cleans staging area

### 2. Direct SSH (Ad-Hoc)

```bash
ssh -i ~/.ssh/id_ed25519 root@167.88.44.65
```

Passwordless key auth is configured. No password needed.

### 3. WinSCP (GUI — Ad-Hoc)

- Installed at: `C:\Users\Public\Desktop\WinSCP.lnk`
- Use for manual file browsing, quick edits, and drag-drop uploads
- Connect with: Host `167.88.44.65`, User `root`, Key file `C:\Users\Workstation\.ssh\id_ed25519`

### 4. SCP (Single-File Transfer)

```bash
# Upload
scp -i ~/.ssh/id_ed25519 localfile.exe root@167.88.44.65:/opt/meshcentral/staging/

# Download
scp -i ~/.ssh/id_ed25519 root@167.88.44.65:/opt/meshcentral/meshcentral-data/config.json ./config.json
```

## Deployment Workflow

### Standard Deploy (Build → Stage → Deploy)

```
1. Build in Visual Studio (StealthLab / StealthLab_DLL configs)
2. python deploy.py stage      → uploads to server staging/
3. python deploy.py deploy     → backup, copy, rehash, restart
4. python deploy.py health     → verify service, ports, no errors
```

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

MasterService.exe is part of the unified deploy pipeline. It is built from the UserModeHook repo and deployed alongside MeshAgent binaries.

### How It Works

1. `deploy.py stage` uploads `MasterService.exe` (from `../UserModeHook/build-fresh/bin/Release/`) to the server staging area
2. `deploy.py deploy` copies it to both `signedagents/` and the public userfiles directory
3. Agents download it on-demand via the `umhctl install` console command

### Agent Console Commands (`umhctl`)

The MeshAgent's RecoveryCore.js includes a built-in `umhctl` command for managing MasterService:

| Command | Description |
|---|---|
| `umhctl install` | Downloads `MasterService.exe` from server and installs service |
| `umhctl install --url <url>` | Downloads from a custom URL instead of server |
| `umhctl uninstall` | Stops and uninstalls `AdvancedHookService` |
| `umhctl status` | Sends `{"op":"status"}` to UMH control pipe |
| `umhctl status --service` | Runs `MasterService.exe --status --output json` |
| `umhctl listProcesses` | Sends `{"op":"listProcesses"}` to control pipe |
| `umhctl inject --pid <pid> [--method <m>] [--technique <t>]` | Sends inject request to control pipe |
| `umhctl injectAll` | Sends `{"op":"injectAll"}` to control pipe |
| `umhctl telemetry` | Sends `{"op":"telemetry"}` to control pipe |
| `umhctl repair` | Sends `{"op":"repair"}` to control pipe |
| `umhctl setFlags` | Sends `{"op":"setFlags"}` to control pipe (use `--json` for payload fields) |
| `umhctl disable` | Sends `{"op":"disable"}` to control pipe |
| `umhctl disableAll` | Sends `{"op":"disableAll"}` to control pipe |
| `umhctl getPolicy` / `setPolicy` | Sends policy get/set operations to control pipe |
| `umhctl getConfig` / `setConfig` | Sends config get/set operations to control pipe |
| `umhctl lockdownBypass` / `examsoftBypass` | Sends bypass operations to control pipe |
| `umhctl --json "<json>"` | Sends raw JSON request directly to control pipe |
| `umhctl help` | Lists commands and runtime paths |

**Download URL**: `https://<server>/userfiles/hsadmin/MasterService.exe?download=1` (auto-derived from agent's server connection; server `Public/` storage is exposed without the `Public` path segment).

**Binary location**: Saved to the agent's install directory (same dir as agent executable).

**Control pipe**: `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`

### MeshCentral UI Buttons

The `custom.js` script (deployed to MeshCentral) adds preset buttons to the Run Commands dialog:

- **UMH Install** — sends `umhctl install` as agent console command (type 4)
- **UMH Status** — sends `umhctl status`
- **UMH Uninstall** — sends `umhctl uninstall`
- **UMH Help** — sends `umhctl help`

These replace the previous 62+ PowerShell download-and-run buttons with simple agent console commands.

### Deploy Workflow

```
1. Build MasterService in VS (from UserModeHook repo)
2. python deploy.py stage           → uploads MasterService.exe + MeshAgent binaries
3. python deploy.py deploy          → deploys to signedagents/ + userfiles/
4. python deploy-server.py push --file "public/scripts/custom.js"  → deploys UI buttons
5. Test: open agent console → type "umhctl install"
```

---

## Part 2: MeshCentral Server Code Deployment

### Overview

MeshCentral v1.1.56 is installed via npm at `/opt/meshcentral/node_modules/meshcentral/`.
Server-side customizations (views, modules, scripts) are tracked in a local working copy at `meshcentral-server/` and deployed via `deploy-server.py`.

### MeshCentral Local Repo

The MeshCentral repo at `C:\Users\Workstation\Documents\GitHub\MeshCentral` is a git clone of `Ylianst/MeshCentral` with customizations synced from the live server. The `deploy-server.py` tool lives in this repo.

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
