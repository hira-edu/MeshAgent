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

