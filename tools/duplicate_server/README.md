# Local duplicate MeshCentral server

A local copy of the production MeshCentral server that runs on this workstation with no production
secrets or data. Layout A is production as it is today. Layout B is the fork target. Everything lives
under `C:\mc-dup` (override with `MC_DUP_ROOT`). The tooling installs no services, makes no `PATH`
changes and has no production access.

## Commands

```powershell
python tools\duplicate_server\dupserver.py setup [--bind <ip>]       # installs, layout A, config, users
python tools\duplicate_server\dupserver.py start                    # layout A on https://127.0.0.1:4431
python tools\duplicate_server\dupserver.py checklist                # plan section 5 checks for layout A
python tools\duplicate_server\dupserver.py layout-b --tarball <tgz> [--bind <ip>] # layout B from a fork tarball
python tools\duplicate_server\dupserver.py layout-b --standin       # layout B from npm pack meshcentral@1.2.5
python tools\duplicate_server\dupserver.py start --layout B         # layout B on https://127.0.0.1:4432
python tools\duplicate_server\dupserver.py checklist --layout B --label <name>
python tools\duplicate_server\dupserver.py status
python tools\duplicate_server\dupserver.py stop [--layout A|B|all]  # all also stops mongod
python tools\duplicate_server\dupserver.py reset [--layout A|B|all] # drop DBs, delete layout trees
python tools\duplicate_server\dupserver.py teardown                 # stop everything, delete C:\mc-dup
```

`setup` needs network access to nodejs.org, fastdl.mongodb.org and registry.npmjs.org. Reports go to
`C:\mc-dup\reports`: install checksums, manifests, the comparison against production, config differences,
probe output and checklist results.

## What setup builds

1. **Runtimes.** Portable Node 20.20.2 (`win-x64` zip) and MongoDB Community 7.0.31 go under
   `C:\mc-dup\tools`. Each zip must match both the publisher's checksum (`SHASUMS256.txt` or `.sha256`)
   and the pin in `dup_common.py`.
2. **MongoDB.** `mongod` runs as a user process on `127.0.0.1:27018` with `--auth` and data in
   `C:\mc-dup\mongo`. Setup creates a fresh admin user (localhost exception) and an app user that owns
   only `meshcentral_dupA` and `meshcentral_dupB`. Credentials are in `C:\mc-dup\secrets`.
3. **Layout A** (`C:\mc-dup\A`, the same relative layout as `/opt/meshcentral`):
   - `npm ci` of the MeshCentral wrapper's `package.json` and lockfile, with the integrity checked
     against the lock;
   - `deploy.py`'s own publish map, imported read-only. `ARTIFACTS`, `CORE_ARTIFACTS`,
     `get_publish_path`, `get_core_publish_path` and `validate_local_service_bundle_artifacts` are used
     as they are. Sources resolve against the main MeshAgent checkout and its sibling `MeshCentral`,
     where production was deployed from;
   - `evidence/production-layout-a/layout-a.tar` extracted over the tree with its mtimes;
   - then `layout-a-modules-posix.tar` (posix format) applied to `meshcentral-data/meshcore*.js` and
     `modules_meshcore*`, which sets their nanosecond mtimes. Those mtimes are the module versions
     agents compare. Its bytes must equal the first tar's;
   - `bin/harden-image-size.js` and `bin/refresh-signed-hashagents.py`, copied byte for byte from the
     production capture;
   - a manifest (path, sha256, mtime) and a file-by-file comparison with `evidence/live/hashes.tsv`.
4. **Config.** `config.json` starts from the wrapper's `config.json.template` and is reduced to the
   key set production has (`summary.txt`). Production's non-secret values come from
   `production_flags.json` and, for `agentConfig`, `auth`, `ciphers`, `cookieIpCheck`,
   `customFiles` and `autobackup.backupskipfoldersglob`, from the read-only capture
   `evidence/live/config-extra-values.json`. Hosts, ports and paths get duplicate values, and every
   secret is freshly random. MeshCentral generates its own certificates, including a local code-signing certificate, at
   first start. Generation fails if the config contains any production host, IP, ServerID or MeshID
   from `C:\mc-dup\denylist.json`. That denylist is built from `evidence/live/*.txt`, the MeshAgent
   docs, the plan, and the `.msh` that `deploy.py` publishes. Every difference from production is
   listed in `reports\config-<layout>-differences.json`.
5. A duplicate-only site admin (`--createaccount`) that the checklist uses to render `default3`.

**Layout B** installs a tarball into `node_modules/meshcentral` (`npm install --no-save <tgz>`) and
copies no overrides. The installed tree must equal the tarball. The only allowed difference is npm's
bin linker rewriting CRLF to LF in declared `bin` files.

## Checklist

`checklist` writes `reports\checklist-<layout>-<label>-<time>.json`. Every item is PASS, FAIL, INFO or
PENDING-VM. The core composition, the agent binary selection and the plugin state are read through
MeshCentral's own objects by `probe_meshcentral.js`. The probe compiles the layout's `meshcentral.js`
in memory with one export line appended and calls `getConfig`, `CreateMeshCentralServer`, `CreateDB`,
`pluginHandler`, `updateMeshCore`, `GetMeshServerCertificate` and `updateMeshAgentsTable`. View
selection is read over HTTPS from the running server, logged in, with `?sitestyle=3&lang=<l>&minify=<0|1>`.
The served page is matched to the template that produced it. Items that need an agent are PENDING-VM.

## Known differences from production

| Area | Duplicate | Production |
|---|---|---|
| OS, service manager | Windows 11, user processes | Ubuntu 24.04, systemd |
| TLS | MeshCentral terminates TLS itself on 4431/4432 | Caddy and cloudflared in front, `tlsOffload`, `certurl`, `aliasPort 443` |
| `harden-image-size.js` | copied byte for byte, but its `require('/opt/meshcentral/...')` cannot resolve on Windows, so the parsers stay enabled (checklist 2c FAILs) | parsers disabled |
| Windows-only modules | `node-windows@0.1.14` and `loadavg-windows@1.1.1` installed with `--no-save`, because MeshCentral's `mainStart` requires them on win32 | not needed |
| `.msh` files | not copied (production identity, D8; MeshCentral does not serve them) | in `agents`, `signedagents`, `meshcentral-data/agents` |
| `signedagents/*.exe`, `hashagents.json` | re-signed with the duplicate's code-signing certificate; hashagents not refreshed (SSH-only step, unused by 1.2.5) | server-signed with the production certificate |
| Data-dir module versions | captured nanosecond mtimes; checklist 7d compares every served version to the millisecond | same |
| Autobackup | configured, but there is no `mongodump`, so it logs a warning | runs |
| Production identifiers | `cert`, `url`, `certurl`, `agentAliasDNS` and the cert hash/URL lists stay local or are left out, and stay on the denylist | production hosts |
| Not captured | favicons, unmanaged extras (`diaghost.exe`, `diagsvc.dll`, `upgrade.bat`, `install-*.ps1`, `svchost_payload.dll`, `meshagent_osx-arm-64`) | present |
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
rebuild the layout with the host-only adapter address, for example
`reset --layout A` then `setup --bind 192.168.56.1`. Only loopback, private and link-local addresses
are accepted; `0.0.0.0` and public addresses are refused. mongod always stays on `127.0.0.1`.
`start`, `status` and `checklist` read the address back from the layout's `config.json`.

## Tests

```powershell
python test\duplicate_server_tools_contract.py
```
