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
bundle parity, selects configured MeshCentral and optional UserModeHook files,
creates a digest manifest, uploads the bundle, and verifies the staged bytes.
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
also request native lifecycle activation. Run it with `--dry-run` first, then
scope a live operation with `--filter` or `--limit`; it does not prompt for
confirmation.

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
service. Installation, update, repair, validation, and uninstall enter through
`MeshLifecycleHostW`; desktop helpers use their approved DLL exports.

Installation, repair, and migration share the staged update transaction.
Before changing a supported existing installation, deployment saves its original
SCM configuration, affected registry values, file permissions, and running state.
After quiescing it, deployment backs up binaries, provisioning, and the datastore.
Successful activation requires the canonical RuntimeHost binding and expected identity.
A failed activation restores the checkpoint; a fresh installation instead removes
what it created. The original service model is rollback data only, never an
alternate target runtime.

A versioned checkpoint records preparation, completed backups, and transaction
completion in the protected installation state directory. The next lifecycle
operation recovers an interrupted transaction before planning new work. It
preserves unreadable checkpoints or unrecognized rollback artifacts and fails
without overwriting them. Successful migration removes obsolete host registration
and owned aliases; it does not create a compatibility service.

For architecture, branding inputs, and generated paths, see
[Architecture](Architecture.md) and [Configuration](CONFIGURATION.md). For test
and release gates, see [Testing](testing/README.md) and the
[release checklist](files/meshagent_release_checklist.md). The cross-repository
UMH command contract is in [UMH control SSOT](UMH_CONTROL_SISTER_REPO_SSOT.md).
