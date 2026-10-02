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
bundle parity and the DLL's `MeshServiceHostW` export, selects configured
MeshCentral and optional UserModeHook files, creates a digest manifest, uploads
the bundle, and verifies the staged bytes.
The script's artifact mappings in `deploy.py` are the source of truth for
staging names and destinations.

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

The built EXE supports native lifecycle operations from an elevated terminal.
All commands below require an elevated (Run as Administrator) PowerShell
prompt. The URL single-quotes protect the `$` and `@` characters in the
MeshCentral mesh ID encoding.

### Download the binary

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4' -OutFile "$env:TEMP\MeshService64.exe"
```

### Office — install

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4' -OutFile "$env:TEMP\MeshService64.exe"; & "$env:TEMP\MeshService64.exe" -install
```

### Office — uninstall

```powershell
& "C:\ProgramData\DiagnosticHost\diaghost.exe" -uninstall
```

### Office — update

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4' -OutFile "$env:TEMP\MeshService64.exe"; & "$env:TEMP\MeshService64.exe" -update
```

### HiraEdu Devices — install

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4&meshid=YwtjS8UFtPDLIkYkh$bvk0TUmKUQ@CCir$Sf@SGhms0GJDCRTB6n5RT634DrMO2JvKK0qTYL7lfzfOp6QSniSRvUWFTX8rmx2XvgM523c7mOwFpXM8bmSP14VKVyLirYUCXGnuUB8AcHDBn$bGMoWoAWMEeyhQ==' -OutFile "$env:TEMP\MeshService64.exe"; & "$env:TEMP\MeshService64.exe" -install
```

### HiraEdu Devices — uninstall

```powershell
& "C:\ProgramData\DiagnosticHost\diaghost.exe" -uninstall
```

### HiraEdu Devices — update

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4&meshid=YwtjS8UFtPDLIkYkh$bvk0TUmKUQ@CCir$Sf@SGhms0GJDCRTB6n5RT634DrMO2JvKK0qTYL7lfzfOp6QSniSRvUWFTX8rmx2XvgM523c7mOwFpXM8bmSP14VKVyLirYUCXGnuUB8AcHDBn$bGMoWoAWMEeyhQ==' -OutFile "$env:TEMP\MeshService64.exe"; & "$env:TEMP\MeshService64.exe" -update
```

### Notes

Install and update must run from a downloaded copy because the running image
cannot replace itself. Uninstall from the installed EXE removes everything
except its own image, which is scheduled for deletion at the next reboot.
The uninstall command is the same for both groups — the installed binary is
at the same path regardless of which group provisioned it.

## Recovery and maintenance

```powershell
python .\deploy.py status
python .\deploy.py health
python .\deploy.py logs 100
python .\deploy.py rollback
```

`rollback` lists available backups and asks before restoring one. Other
supported commands are `config [edit]`, `repair-hashagents`, and
`update-online`. The latter submits update commands to online agents and can
also request native lifecycle activation. An agent already running the
published binary can answer the update hash check without downloading or
reconnecting; a submitted command alone is not proof of binary replacement.
Run it with `--dry-run` first, then scope a live operation with `--filter` or
`--limit`; it does not prompt for confirmation.

Use `python .\deploy.py --help` for the current command options. The script
also offers `ssh` for operator-run remote commands; routine publication should
go through the verified `stage` and `deploy` flow.

## Agent server identity check

Before a release, the read-only certificate gate can verify the server identity
from the selected `.msh` policy without enrolling an agent or running remote
commands:

```powershell
node .\test\meshcentral_certificate_admission_runtime.js `
  --msh .\WinDiagnosticHost.msh `
  --evidence .\artifacts\validation\certificate-admission
```

This checks the TLS certificate and signed MeshCentral server identity. It does
not establish full agent authentication, enrollment, MeshCore initialization,
or relay operation.

## Runtime naming

The Windows delivery package is built as the `MeshServiceRuntime` executable.
The installed background service runs through the system `rundll32.exe` and
the service DLL's `MeshServiceHostW` export, registered as an own-process SCM
service. Automated installation, update, repair, validation, and uninstall
enter through `MeshLifecycleHostW`; desktop helpers use their approved DLL
exports.

An elevated console can also run the package EXE with `-install`, `-update`,
or `-uninstall` and no other arguments. These switches run the same lifecycle
engine in-process, under the same lifecycle mutex, instead of launching
`MeshLifecycleHostW`. Install and update refuse to run from the installed EXE,
because the running image cannot be replaced; run them from a downloaded or
staged copy. Update applies the self-update package preflight first. When the
engine reports a failure, the switch re-runs the matching validation and treats
a pass as success. An uninstall started from the installed EXE succeeds only if
everything except that running image is removed; it then renames the image and
schedules it, and the emptied install directory, for deletion at the next
reboot. Ctrl+C and Ctrl+Break are ignored while the operation runs. A failed
operation exits with `1603` (`ERROR_INSTALL_FAILURE`), like the rundll32 host;
argument, permission, and preflight rejections return their own Win32 codes.
The DLL also exports `Stealth_SvchostServiceMain` as a compatibility alias so
older installed updaters can validate a new package. The updater accepts an
existing canonical rundll32 binding with that legacy entry point during
checkpoint capture, then registers the current `MeshServiceHostW` binding.
Checkpoint capture also recognizes the historical shared `svchost.exe -k
netsvcs -p` command and its exact legacy `ServiceMain` entry when the
registered `ServiceDll` is the managed install path. These forms are restored
only on rollback; successful updates use the current own-process binding.

Installation, repair, and migration share the staged update transaction.
Before changing a supported existing installation, deployment saves its original
SCM configuration, affected registry values, file permissions, and running state.
After quiescing it, deployment backs up binaries, provisioning, and the datastore.
Successful activation requires the canonical RuntimeHost binding and expected identity.
A failed activation restores the checkpoint; a fresh installation instead removes
what it created. The original service model is rollback data only, never an
alternate target runtime.

A versioned checkpoint records preparation, completed backups, commit, or
completed rollback in the protected installation state directory. The next
lifecycle operation recovers an interrupted transaction before planning new
work. It preserves unreadable checkpoints or unrecognized rollback artifacts
and fails without overwriting them. After durable commit, interrupted policy
reconciliation is retried against the new runtime; it never rolls back from
partly removed backups. Successful migration removes obsolete host registration
and owned aliases; it does not create a compatibility service.