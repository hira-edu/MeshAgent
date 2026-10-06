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

### Historical web certificates

The tracked MeshCentral `meshagent.js` supports domain-scoped
`agentwebcerthashes`: an explicit array of 96-character SHA384 certificate or
RSA public-key hashes. These pins extend only web-certificate admission. The
agent's nonce signature, NodeID, mesh authorization, and pinned server identity
are still required. Unknown, malformed, wildcard, and all-zero pins are rejected;
reported agent hashes are never automatically trusted. Successful historical
connections emit `[AGENT_CERT_COMPAT]` after signature verification.

On the VPS, `tools/configure_agent_certificate_history.js` can collect pins from
saved public web certificates and operator-designated HTTPS endpoints. Endpoint
collection requires CA and hostname validation. For example:

```sh
node configure_agent_certificate_history.js \
  --config /opt/meshcentral/meshcentral-data/config.json \
  --history-dir /opt/meshcentral/meshcentral-data \
  --endpoint https://old-agent.example/ \
  --endpoint https://agents.example/
```

`--certificate <public-crt>` adds a specific historical listener certificate.
The default domain is selected unless `--domain <id>` is supplied. The tool
preserves existing valid pins, rejects private-key inputs, saves a private config
backup, and replaces the configuration atomically. Deploy the server change and
restart MeshCentral to apply the pins. Configured endpoints are retained as
`agentwebcerturls`. A rejected certificate triggers a CA/hostname-validated
refresh of these endpoints, at most once per domain every two minutes, with
15-second timeouts. New validated hashes extend the in-memory history and held
connections restart with fresh nonces; failed fetches never grant trust.
Re-run the inventory tool to persist newly observed certificates across server
restarts. Remove retired pins and endpoints after migration is verified.

This does not replace agent identities or rewrite the agent's server public-key
pin. A changed server identity needs proof from the previously trusted private
key or separately authorized endpoint reprovisioning. Missing historical
certificates must be recovered from operator backups, not inferred from rejected
connection logs.

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
operation before files are replaced. A service already bound to the current
payload path skips this discovery, so uninstall, repair, and update of an
ordinary installation do not depend on its database. An existing service whose
database lacks a NodeID is not updated; a registration without a database
remains repairable.

Identity discovery opens databases without repair, conversion, compaction, or
file creation, including legacy 32-bit and 64-bit datastore formats. Identical
`.bak` or `.backup` copies of an existing file do not count as another identity;
different database contents still require operator selection. Historical
callback bindings accept quoted or unquoted system loaders and expandable
paths, require a canonical absolute `.dll` path, and retain the exact original
SCM settings for rollback. Interrupted copies (`mcu*.tmp`) and datastore
compaction files (`*.db.tmp`) are ignored as identities and left in place.

Migration copies the old database after stopping its service and publishing
the durable backup checkpoint. Activation verifies the preserved NodeID.
Rollback and interrupted-update recovery use the original binding and
database. The service host records no failed-package hold, and recovery does
not depend on an update activation target key. A successful update deletes
hold keys written by earlier builds; a key that cannot be deleted is logged and
does not fail the update. When verified incumbent paths must be preserved, the
journal is written as version 2, so recovery and retirement also work when old
and new databases share a directory. Otherwise the journal keeps the version 1
layout, which an older installed service DLL can still recover after a crash.
Both versions are readable. Database replacement copies and flushes a
temporary sibling before replacing the destination; a failed copy does not
first delete the live database. After a committed update, cleanup removes the
verified old payload, its sidecars, and recovery-state file before deleting
the old database. A companion EXE belongs to a DLL installation only when its
embedded DLL exactly matches that installed DLL. Multiple matching companion
EXEs are retained instead of blocking migration. Historical directories are
removed only when empty; unrelated files are retained.

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

## macOS privacy permissions

Agent and helper startup do not request Screen Recording, Accessibility, or
Full Disk Access and do not open System Settings. During a desktop session,
KVM queries existing Screen Recording and Accessibility authorization without
prompting. Missing Screen Recording authorization pauses capture; missing
Accessibility authorization blocks remote keyboard and mouse input. A desktop
protocol message explains the missing permission. Grant access to the installed
MeshAgent executable in System Settings > Privacy & Security, then reconnect
or restart the helper if required by macOS.

Removing automatic requests does not grant access or suppress macOS-controlled
notifications. Full Disk Access is not inferred by opening protected user files;
file operations remain subject to macOS authorization.

For managed Macs, deploy Apple's Privacy Preferences Policy Control (PPPC)
payload through MDM using the installed binary's path and designated code signing
requirement. PPPC can preapprove Accessibility and System Policy All Files.
Screen Recording follows Apple's separate approval rules; do not treat it as a
silent allow grant. Keep the installed path and signing identity consistent
across updates so the deployment policy continues to identify the same agent.
See [Apple's PPPC deployment settings](https://support.apple.com/guide/deployment/dep38df53c2a/web)
and [payload examples](https://support.apple.com/guide/deployment/dep9ddb7e0b5/web).

On supervised Macs running macOS 15.1 or later, an MDM Restrictions payload can
set `forceBypassScreenCaptureAlert` to suppress recurring capture alerts. This
does not grant initial Screen Recording access. Apple's Persistent Content
Capture entitlement is available for eligible VNC-style applications, but
requires approval from Apple and the corresponding signing profile; adding an
entitlement key to an unprovisioned build does not enable it. See Apple's
[Restrictions reference](https://developer.apple.com/documentation/devicemanagement/restrictions)
and [Persistent Content Capture entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.persistent-content-capture).

## macOS service installation and user sessions

The daemon and LoginWindow LaunchAgent use the same installed executable.
Installation writes the executable and provisioning before publishing the daemon
plist, installs the LoginWindow job, then starts the daemon. A failed setup removes
files created by that installation and preserves preexisting provisioning. This
cleanup covers handled failures; it is not crash recovery for an interrupted
installation or restoration of a previously uninstalled version.

LoginWindow job cleanup addresses its actual launchd login domain and any
historical system-domain binding. It does not select the logged-in Aqua user's
domain. When no LoginWindow session exists, launchd loads the installed job at
the next applicable session.

Interactive operations select the foreground user from `/dev/console` ownership.
SSH login order does not determine the desktop user. The login window and Setup
Assistant are not treated as ordinary user desktops. Account lookups use checked,
bounded processes with literal arguments; home-directory records are decoded as
plists to preserve spaces and special characters. Session enumeration reports
live logins with each user's resolved UID.

KVM launches the same executable through `launchctl asuser` to select the user's
GUI bootstrap and audit context. That command preserves credentials. The KVM
entry point therefore checks that the selected UID still owns `/dev/console`,
initializes supplementary groups, sets the primary GID and UID, and verifies the
result before accessing desktop APIs. It sets the user's home/account environment
and clears an inherited temporary-directory override. A failed transition exits
the helper and closes the desktop stream. A non-root process outside the GUI
audit session may be unable to make this transition; the system service retains
root until the helper has entered the selected context.

Dialogs, clipboard operations, notifications and lock requests launch the same
installed executable as a temporary Aqua LaunchAgent for the foreground user.
The parent creates a private directory and authenticates the helper over a Unix
socket using a per-request secret stored in a private configuration file. The
secret is not placed in the LaunchAgent arguments. Root retains ownership of the
directory when serving another user. Setup, command, disconnect and timeout
failures reject the request and remove owned resources after unloading the job.
An unload failure is reported and retains its files for recovery. This cleanup
does not cover a parent process crash or power loss.

Helper messages use bounded, length-prefixed JSON. The
length is the encoded byte length; JSON Unicode escapes keep supplementary
characters interoperable with the embedded JavaScript runtime. Receivers retain
partial frames and process all complete frames in a read. The frame limit is
16 MiB including the four-byte header.

Clipboard commands receive UTF-8 bytes, and dialogs/notifications receive data
as a literal argument to a fixed JavaScript for Automation program. Text is not
interpolated into a shell command. Lock requests require Accessibility access
and post the standard Control-Command-Q shortcut; a changed system shortcut can
prevent locking. Live UI, clipboard and lock behavior must be validated on each
supported macOS version before release.

## macOS server-driven update recovery

The macOS native agent validates a staged executable with its bounded
`-updaterversion` probe before stopping the agent chain. A failed probe leaves
the incumbent online and reports update failure. A symlinked executable is
rejected for replacement without changing the launch path used for identity files.
Package extraction owns the
staged file until its completion or failure callback; additional transfers cannot
truncate it during extraction.

After closing the datastore, the agent keeps a hard-link backup of the incumbent,
publishes a durable transaction record, atomically replaces the executable, and
uses `execv` at the same installed path. The hand-off preserves the process ID,
launchd job, working directory, and original argument values. It removes the
one-shot `--fakeUpdate` and `--resetnodeid` arguments. It does not move or replace
the datastore or provisioning files. An execution failure restores the incumbent
before attempting to restart it.

The installed executable owns `<executable>.update-backup`,
`<executable>.update-state`, and a persistent `<executable>.update-lock` file.
The first normal writable agent startup marks a trial; scripts, KVM helpers and
read-only probes do not consume it. Authentication to the server commits the
trial and retires the backup. Startup failure, a subsequent uncommitted startup,
or failure to authenticate within 120 seconds restores the incumbent. A network
outage during the trial can therefore cause a valid update to roll back. A
malformed journal or a backup whose file identity no longer matches the record
is reported as a recovery error; the agent does not delete unrelated files.

A stored certificate that is corrupt, lacks its private key, or disagrees with a
stored NodeID is an identity error on macOS. Startup exits nonzero instead of
creating a replacement node. Historical databases with a valid private PKCS12
certificate and no separate NodeID record remain supported.
