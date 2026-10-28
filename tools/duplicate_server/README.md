# Local duplicate MeshCentral server

A local copy of the production MeshCentral server that runs on this workstation with no production
secrets or data. Layout A is production as it runs until the Stage 4 cutover (stock MeshCentral 1.2.5
on Node 20.20.2). Layout B is the fork package as Stage 6 landed it (MeshCentral 1.3.1 plus the fork,
on Node 24.22.1). Everything lives under `C:\mc-dup` (override with `MC_DUP_ROOT`). The tooling
installs no services, makes no `PATH` changes and has no production access.

## Commands

```powershell
python tools\duplicate_server\dupserver.py setup [--bind <ip>]                 # runtimes, layout A, config, users
python tools\duplicate_server\dupserver.py layout-b [--agents <dir> | --tarball <tgz>] [--bind <ip>]
python tools\duplicate_server\dupserver.py start [--layout A|B]               # A on 4431, B on 4432
python tools\duplicate_server\dupserver.py checklist [--layout A|B] [--label <name>]
python tools\duplicate_server\dupserver.py pin-check                          # B must refuse a changed agent pin
python tools\duplicate_server\dupserver.py dbcompat [--events-per-day <n> ...] # D27 database compatibility
python tools\duplicate_server\dupserver.py status
python tools\duplicate_server\dupserver.py stop [--layout A|B|all]            # all also stops mongod
python tools\duplicate_server\dupserver.py reset [--layout A|B|all]           # drop DBs, delete layout trees
python tools\duplicate_server\dupserver.py teardown                           # stop everything, delete C:\mc-dup
```

`setup` and `layout-b` need network access to nodejs.org, fastdl.mongodb.org, downloads.mongodb.org and
registry.npmjs.org. A MeshAgent worktree must set `MESHCENTRAL_ROOT` to its MeshCentral checkout.
Reports go to `C:\mc-dup\reports`: install checksums, manifests, the comparison against production,
config differences, probe output, checklist, pin-check and dbcompat results.

## Runtimes

Each runtime zip must match both its publisher's checksum and the pin in `dup_common.py`:

| Runtime | Used by | Checksum source |
|---|---|---|
| Node 20.20.2 `win-x64` | layout A (production until the cutover) | nodejs.org `SHASUMS256.txt` |
| Node 24.22.1 `win-x64` | layout B (the 1.3.1 fork; 1.3.1's autobackup needs Node 22+) | nodejs.org `SHASUMS256.txt` |
| MongoDB Community 7.0.31 | both (production's version) | fastdl.mongodb.org `.sha256` |
| MongoDB Database Tools 100.20.0 | `mongodump` for both layouts' autobackup | downloads.mongodb.org `tools/db/release.json` |

The Node version is a property of the layout (`LAYOUTS[...]["node"]`): each layout installs, starts,
probes and runs `npm` with its own Node. `mongod` runs as a user process on `127.0.0.1:27018` with
`--auth` and data in `C:\mc-dup\mongo`. Setup creates a fresh admin user (localhost exception) and an
app user that owns only `meshcentral_dupA`, `meshcentral_dupB` and the dbcompat scratch database.
Credentials are in `C:\mc-dup\secrets`.

## Layout A (production until the cutover)

`C:\mc-dup\A` has the same relative layout as `/opt/meshcentral`:

- `npm ci --omit=dev` of the deployment wrapper (`MeshCentral/deploy`: `package.json`, lockfile and the
  packed fork tarball it pins), with the integrity checked against the lock. `node_modules/meshcentral`
  is then replaced by the stock npm `meshcentral@1.2.5` production runs, checked against
  `test/lib/meshcentral_production_reference.json`, and the installed tree must equal that tarball.
- `deploy.py`'s own publish map, imported read-only. Agent binaries come from the main MeshAgent
  checkout's build outputs (or `MC_DUP_SOURCE_REPO`). Since Stage 6 the MeshCentral checkout holds the
  1.3.1 fork, so no MeshCentral file is read from it: every MeshCentral file the map publishes is taken
  from the checkout's git history at production's sha256 from `evidence/live/hashes.tsv` (the Stage 1
  import committed production's files). A target production does not have is left out and recorded.
  `meshcentral.js` is production's loader rebuilt from the stock copy with `deploy.py`'s transform
  helpers; the CRLF that production's first versioned deploy left on three lines is restored and the
  result must equal production's sha256.
- `evidence/production-layout-a/layout-a.tar` extracted over the tree with its mtimes, then
  `layout-a-modules-posix.tar` applied to `meshcentral-data/meshcore*.js` and `modules_meshcore*`, which
  sets their nanosecond mtimes. Those mtimes are the module versions agents compare.
- `bin/harden-image-size.js`: production's image-size preload, from the tracked
  `tools/deployment/harden-image-size.js` that `install_controller.py` installs. `start` loads it with
  `NODE_OPTIONS=--require`, like production's systemd drop-in. `refresh-signed-hashagents.py` is not
  reproduced (D16 retires it).
- `node_modules/meshcentral/daemon` and `domains[''].myServer` with `upgrade: false`: the D6 safeguards
  production has had since 2026-10-28.
- A manifest (path, sha256, mtime) and a file-by-file comparison with `evidence/live/hashes.tsv`.

## Layout B (the 1.3.1 fork)

`C:\mc-dup\B` is the fork as production will run it after the Stage 4 cutover:

- `npm ci --omit=dev` of the wrapper against its lockfile, which pins the fork tarball made by
  `node deploy/scripts/pack.js --agents <folder with the pinned agent builds>`. `--agents <dir>` packs it
  first in the MeshCentral checkout with layout B's Node; `--tarball <tgz>` uses an already packed file;
  without either the wrapper's own `deploy/dist` tarball is used. Any tarball whose sha512 is not the
  locked one is refused before `npm ci`.
- The installed package must equal the tarball (plus the D6 `daemon` marker), and every agent binary
  `agents/agent-defaults.json` pins must be in the package with its size and SHA384.
- Only the files the fork release keeps outside the package, from the MeshCentral checkout's HEAD:
  `deploy/meshcentral-web/**` (`custom.js`) and `plugins/nativeruntime/**` (the package does not ship
  plugins yet). No data-dir cores, no `meshcentral-data/agents` or `signedagents`, no `agentbuilds/`, no
  view overrides, no `bin/`.
- No image-size preload: the fork retires image-size with its preload (D4, DEP-21). The duplicate
  never installs it for layout B, whatever the package still lists.
- The config is production's (below) without `customFiles`, which holds only the r0 canary entry (D16).

`pin-check` proves the fork's start-up pin check: it changes the last byte of one pinned binary
(size unchanged), starts layout B as `start` does, requires MeshCentral's own
`ERROR: fork agent binaries: ... does not match its pin (SHA384 ...)` and that the port never opens,
then restores the file and checks it against the pin. The serving process exits with code 1, and
MeshCentral's launcher (`launchChildServer`) restarts it every 5 seconds, so the parent process keeps
running while nothing listens.

## Config

`config.json` starts from the wrapper's `config.json.template` and is reduced to the key set production
has (`summary.txt`). Production's non-secret values come from `production_flags.json` and, for
`agentConfig`, `auth`, `ciphers`, `cookieIpCheck`, `customFiles` and
`autobackup.backupskipfoldersglob`, from the read-only capture `evidence/live/config-extra-values.json`.
`after_inventory` in `production_flags.json` holds production settings applied after the inventory
(the D6 `myServer` safeguard). Hosts, ports and paths get duplicate values,
`autobackup.mongodumppath` names the pinned `mongodump`, and every secret is freshly random.
MeshCentral generates its own certificates, including a local code-signing certificate, at first
start. Generation fails if the config contains any production host, IP, ServerID or MeshID from
`C:\mc-dup\denylist.json`. That denylist is built from `evidence/live/*.txt`, the MeshAgent docs, the
plan, and the `.msh` that `deploy.py` publishes. Every difference from production is listed in
`reports\config-<layout>-differences.json`. A duplicate-only site admin (`--createaccount`) is created
for the checklist.

## Checklist

`checklist` writes `reports\checklist-<layout>-<label>-<time>.json` and `checklist-<layout>-latest.json`.
Every item is PASS, FAIL, INFO or PENDING-VM:

| Item | Layout A | Layout B |
|---|---|---|
| 0 | runs on Node 20.20.2 | runs on Node 24.22.1 |
| 1a, 1b | no runtime install; wrapper files unchanged | same |
| 1c | tree vs production inventory (INFO) | package equals the locked fork tarball |
| 1d | | no data-dir cores, agent folders, `agentbuilds/`, view overrides or `bin/` |
| 2a, 2b, 2d, 2e | no runtime npm install; clean start; `GET /` 200; `agent.ashx` 101 | same |
| 2c | the preload printed `disabled unpatched parsers: icns, jxl, jxl-stream, heif` | no preload and no preload output |
| 2f | `selfUpdate` false, `daemon` marker, `myServer.upgrade` false (D6) | same |
| 2g | the server console's `autobackup` (MeshCentral's own `db.performBackup`) writes a zip holding the `mongodump` archive, with no backup error | same, on Node 24 |
| 7a, 7b, 7d | core and module versions = production's data-dir capture | core from the package; versions = `agents/module-versions.json` |
| bin | arch 3/4/43 = production's selection and hash | arch 3/4/43 = the pinned fork builds (size, SHA384), unsigned |
| views | `default3` = production's overrides | `default3` = the package page |
| d16 | | no override, r0 canary or `customFiles` |
| 10a | `nativeruntime` loaded | same |
| 3-10b | PENDING-VM | PENDING-VM |

The core composition, the agent binary selection (for 1.3.1 through the fork's `agentbuilds.js`, as
the server does at start) and the plugin state are read through MeshCentral's own objects by
`probe_meshcentral.js`. View selection is read over HTTPS from the running server, logged in, with
`?sitestyle=3&lang=<l>&minify=<0|1>`. Items that need an agent are PENDING-VM.

## Database compatibility (D27)

`dbcompat` runs MeshCentral's own `db.js` of each layout, on that layout's Node, against the scratch
database `meshcentral_dupcompat` (dropped before and after): 1.2.5 seeds synthetic data sized like
production (312 nodes, 20 days of events, power, server stats; `--events-per-day` and
`--power-per-day` scale it), then 1.3.1, 1.2.5 (rollback), 1.3.1 (re-upgrade), and finally the
`docs/DEPLOYMENT.md` drop list followed by 1.2.5. Each phase records the time until the index set
settles, mongod's own index-build log lines, the index set, the `Resetting ...` lines, reads that every
version must answer the same way and the device-list plan. The run fails unless the s6-c expectations
hold. Layouts A and B must be installed and stopped.

## Known differences from production

| Area | Duplicate | Production |
|---|---|---|
| OS, service manager | Windows 11, user processes | Ubuntu 24.04, systemd |
| TLS | MeshCentral terminates TLS itself on 4431/4432 | Caddy and cloudflared in front, `tlsOffload`, `certurl`, `aliasPort 443` |
| `bin/harden-image-size.js` (A) | the tracked, path-portable copy | an older copy that requires `/opt/meshcentral/node_modules/image-size` |
| Windows-only modules | `node-windows@0.1.14` and `loadavg-windows@1.1.1` installed with `--no-save`, because MeshCentral's `mainStart` requires them on win32 | not needed |
| `.msh` files | not copied (production identity, D8; MeshCentral does not serve them) | in `agents`, `signedagents`, `meshcentral-data/agents` |
| `signedagents/*.exe` (A) | signed with the duplicate's code-signing certificate | signed with the production certificate |
| `mongodump` | named in `autobackup.mongodumppath` | found on `PATH` |
| Production identifiers | `cert`, `url`, `certurl`, `agentAliasDNS` and the cert hash/URL lists stay local or are left out, and stay on the denylist | production hosts |
| Not captured (A) | favicons, unmanaged extras (`diaghost.exe`, `diagsvc.dll`, `upgrade.bat`, `install-*.ps1`, `svchost_payload.dll`, `meshagent_osx-arm-64`), `hashagents.json` | present |
| `customFiles.r0UmairReconnectCanary` | layout A only, from the capture; layout B drops it (D16) | present |

## Test agent (VM)

Build the test agent only with explicit, duplicate-only inputs kept outside the repository:

1. Create `Dup.msh` from the duplicate's Add Agent flow and a second branding config, for example
   `C:\mc-dup\agent\branding.dup.json`. Give the branding config its own `serviceName`, `installRoot`,
   `binaryName`, `databaseName` and task names. The MeshServer host must be reachable from the VM: a
   host-only or private IP, or a `*.localhost` / `*.test` name.
2. Run the preflight. It fails if either file names a production host, IP, ServerID or MeshID. It
   also fails if either file is missing, is inside the repository, or is one of the build's implicit
   defaults (`branding_config.local.json`, `WinDiagnosticHost.msh`; see `docs/CONFIGURATION.md`,
   "Provisioning manifest selection"):

   ```powershell
   python tools\duplicate_server\preflight_agent.py --branding C:\mc-dup\agent\branding.dup.json --msh C:\mc-dup\agent\Dup.msh
   ```

3. Build with both properties explicit, exactly as the preflight prints:

   ```powershell
   msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal "/p:MeshAgentBrandingConfig=C:\mc-dup\agent\branding.dup.json" "/p:MeshAgentProvisioningManifest=C:\mc-dup\agent\Dup.msh"
   ```

MeshCentral listens on the `--bind` address given to `setup` or `layout-b`. It is written into
`portBind` and `mpsPortBind`, and added to `allowedorigin`. The default is `127.0.0.1`. For the VM,
build the layout with the host-only adapter address, for example `setup --bind 192.168.211.1`. Only
loopback, private and link-local addresses are accepted; `0.0.0.0` and public addresses are refused.
mongod always stays on `127.0.0.1`. `start`, `status` and `checklist` read the address back from the
layout's `config.json`. A layout rebuilt after `reset` has new certificates, so an agent provisioned
for the old layout needs a new `.msh` (its ServerID changes).

## Tests

```powershell
python test\duplicate_server_tools_contract.py
```
