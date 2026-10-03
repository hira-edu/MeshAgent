# Deployment

`deploy.py` is the repository's deployment interface for publishing reviewed
MeshAgent builds and configured MeshCentral support files to the VPS. This page
documents that workflow; it does not keep server-specific IP addresses,
credentials, deployment snapshots, or migration history.

## Before staging

Build the package on Windows using the ordered build entry point:

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

Configure `MESHCENTRAL_SERVER` for the target host and make sure the selected
SSH host and user can connect. The script defaults to SSH host alias
`meshcentral` and user `root`; `MESHCENTRAL_SSH_HOST`, `MESHCENTRAL_USER`, and
`MESHCENTRAL_SSH_CONFIG` can select the operator's SSH configuration.

The active branding configuration must provide `branding.installRoot` and
`branding.serviceDllName`, either through `MESHCENTRAL_BRANDING_CONFIG`, the
ignored `branding_config.local.json`, or the explicit
`MESHCENTRAL_INSTALL_ROOT` and `MESHCENTRAL_LIFECYCLE_DLL` overrides. The
deployment tool uses these Windows paths when it performs remote native update
activation. Keep local identity and credential files out of version control.

`stage` validates required local MeshAgent artifacts, checks embedded service
bundle parity and the DLL's `ServiceHost_ServiceMain` export, selects configured
MeshCentral and optional UserModeHook files, creates a digest manifest, uploads
the bundle, and verifies the staged bytes.
The script's artifact mappings in `deploy.py` are the source of truth for
staging names and destinations.

When TLS terminates at a proxy, the domain's `certUrl` must identify the HTTPS
endpoint used by agents. Staging aligns the certificate loader's TLS SNI with
that URL's hostname, including when the console and agent endpoints differ.
Enable agent hash checking by setting `ignoreAgentHashCheck` to `false` and
removing any domain or IP exceptions that skip the check.

The installed native service is a `SERVICE_WIN32_SHARE_PROCESS` DLL service in
a deterministic, agent-only service-host group. Its image path resolves the actual
`%SystemRoot%\System32\svchost.exe`; `Parameters\ServiceDll` names the installed
DLL and `Parameters\ServiceMain` is `ServiceHost_ServiceMain`. The group contains
only the configured service. `ServiceDll` uses `REG_EXPAND_SZ`, as required by
the Windows loader, even when its value is an absolute path. This keeps
process protection and service-scoped firewall rules scoped to this service.
Existing callback-based bindings are
accepted only long enough for update, server-driven update, rollback, or
uninstall to migrate or remove them; they are never accepted as healthy final
state.

Tracked files in the MeshAgent and configured sibling checkouts are the local
release authorities. Ignored npm copies, cached downloads, and historical
verification output must not be selected as deployment sources.

## Standard release

Set the server value in PowerShell:

```powershell
$env:MESHCENTRAL_SERVER = "<vps-host>"
python .\deploy.py status
python .\deploy.py stage
```

Review the staged artifact list and digest verification before publishing. The
interactive deploy command asks for confirmation; avoid `--yes` for a live
release.

```powershell
python .\deploy.py deploy
python .\deploy.py health
```

Before copying files, `deploy.py deploy` verifies the staged manifest against
the current local artifacts. It backs up the configured publish roles, deploys
the staged agent and server-support files, refreshes MeshCentral's
`hashagents.json`, verifies published bytes, and restarts MeshCentral. A
verified content mismatch triggers restoration from the backup. If SSH fails
during verification, the tool reports the incomplete state and does not
restart based on an unverified publish.

Publishing a changed agent binary makes it eligible for MeshCentral's native
automatic update on **every connected agent**. A later `update-online --filter`
only scopes the explicit update command; it does not make the preceding
publication a canary deployment. To isolate a canary, disable automatic native
updates in the server's settings (`noagentupdate: true`) before publishing,
then verify the setting is active and explicitly update the selected agent.
Keep automatic updates disabled until the selected agent reconnects with the
expected binary and service health. `deploy.py deploy` checks this setting and
stops before publishing if it cannot confirm it; `--allow-fleet-update` is the
explicit override for a planned fleet rollout.

## Endpoint install, update, and uninstall

The x64 service EXE supports native lifecycle operations from an elevated terminal.
The current service migration targets 64-bit Windows and an x64 service DLL.
Win32 EXE terminal lifecycle commands return `ERROR_NOT_SUPPORTED` (50) before
deployment changes; use `MeshService64.exe`, including for unattended operations.
All commands below require an elevated (Run as Administrator) PowerShell
prompt. The URL single-quotes protect the `$` and `@` characters in the
MeshCentral mesh ID encoding.

### Download the binary

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4' -OutFile "$env:TEMP\MeshService64.exe"
```

### Run the lifecycle operation

Use a staged package outside the installed directory. A configured package
carries provisioning in its embedded data or adjacent `.msh` file. Run exactly
one lifecycle switch, optionally followed by `--quiet` (alias `-silent`):

```powershell
& "$env:TEMP\MeshService64.exe" -install
& "$env:TEMP\MeshService64.exe" -update
& "$env:TEMP\MeshService64.exe" -uninstall
```

For unattended use, append `--quiet` to any of these three commands. It
suppresses stdout and stderr, preserves installer file logs, and returns the
same exit code as a normal terminal operation. Already-elevated automation is
required; quiet mode does not suppress Windows UAC. No other terminal lifecycle
options or combinations are accepted. Check `$LASTEXITCODE`: zero means success;
a failed transaction remains a failure even when rollback restores a healthy
incumbent service.

Install and update reject execution from the installed image, including a
hard-link alias. Uninstall from that image retires the running binary only after
all other service, group, persistence, update, and filesystem residue is absent,
under the same lifecycle lock. The retired copy is removed at reboot; a failed
rename or deletion scheduling returns a failure and records the cleanup path in
the installer log. Uninstall from a staged copy avoids deferred image cleanup.

Install and update perform native validation before returning success. Update
preserves the installed NodeID and migrates a legacy service binding to the
scoped DLL host. Failed activation restores the original binding and files
through the transaction journal. A provisioning package can update the mesh
and server configuration; a raw automatic update preserves installed
provisioning.

When a historical package used a different service key, filename, database
name, or installation directory, the lifecycle discovers its actual SCM
binding and validates the datastore beside that payload. The migration retains
the existing SCM key while installing the current payload paths and display
branding. Multiple matching identities, an unreadable identity, an unsupported
service account, or a conflicting identity at the destination stop the
operation before files are replaced.

Migration copies the old database after stopping its service and publishing
the durable backup checkpoint. Activation verifies the preserved NodeID.
Rollback and interrupted-update recovery use the original binding and
database, including for failed-package hash holds. After a committed update,
cleanup removes the verified old payload, its sidecars, and recovery-state
file before deleting the old database. A companion EXE belongs to a DLL
installation only when its embedded DLL exactly matches that installed DLL.
Historical directories are removed only when empty; unrelated files are
retained.

Windows certificate identity survives a service or product rename. Existing
CNG and legacy CAPI identities are selected by the saved NodeID; older databases without that
field use the issuer and signature of their stored TLS certificate. Selection
only opens an existing, accessible private key in the user or machine store. TLS renewal retains the signing
certificate's actual issuer name. Missing keys, corrupt persisted certificates,
and mismatched NodeIDs stop startup instead of replacing the endpoint identity.
Exported PKCS12 identities in the database remain supported. An explicit
administrator-requested NodeID reset still creates a fresh identity.
TLS renewal uses a unique temporary key container and deletes it after export;
an export without the private key fails. Renewal and database-write failures
stop startup while preserving the endpoint's root identity.

The x64 service EXE's `-fullupdate` ingress remains supported and launches the approved
`MeshLifecycleHostW` callback. Direct `-fullinstall`, `-fulluninstall`, and
`-validate-*` EXE switches are disabled; automated validation uses that callback
with a lifecycle manifest. Repository tests use
`test/lib/runtime_host_lifecycle.js` to construct the manifest and command.

```powershell
powershell -NoProfile -File .\tools\health_check.ps1
```
