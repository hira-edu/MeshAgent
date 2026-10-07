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

Agent and helper startup do not request Accessibility or Full Disk Access and do
not open System Settings. Remote desktop uses Apple Screen Sharing (see below),
so the agent itself needs neither Screen Recording nor Accessibility for it.
Removing automatic requests does not grant access or suppress macOS-controlled
notifications. Full Disk Access is not inferred by opening protected user files;
file operations remain subject to macOS authorization.

Lock requests post a keyboard shortcut and need Accessibility access. For managed
Macs, deploy Apple's Privacy Preferences Policy Control (PPPC) payload through MDM
using the installed binary's path and designated code signing requirement. Keep
the installed path and signing identity consistent across updates so the
deployment policy continues to identify the same agent. See
[Apple's PPPC deployment settings](https://support.apple.com/guide/deployment/dep38df53c2a/web)
and [payload examples](https://support.apple.com/guide/deployment/dep9ddb7e0b5/web).

## macOS remote desktop

Remote desktop relays Apple Screen Sharing (`screensharingd`). For each session
the daemon starts its own executable with `-kvm0`, keeping root credentials. That
helper connects to `127.0.0.1:5900` as an RFB client and translates between RFB
and the MeshCentral tile protocol on its standard input and output. Screen
Sharing captures the screen, applies input, and serves the login window and
every user session, so one helper covers all of them, including user switching.
macOS shows its own Screen Sharing indicator while a session is connected. There
is no other capture or input path.

Before authenticating, the helper requires:

- the agent to run as root;
- the VNC password in `vncrelay.secret` beside the installed executable. The
  directory must be root-owned and not writable by group or others. The file must
  be a root-owned regular file with no group or other permissions, not a symlink,
  with one hard link, holding 1 to 8 printable ASCII characters and an optional
  trailing newline;
- every process holding a TCP listener on port 5900 to run as root, which is
  launchd or `screensharingd` while Screen Sharing is on. Otherwise, while
  Screen Sharing is off, any account could listen on the port and collect the
  VNC authentication exchange.

Before connecting, the root helper ensures the system-wide boolean
`VNCAlwaysStartOnConsole` in `com.apple.RemoteManagement` is true. Password-based
VNC otherwise can start in a separate login-window session while the physical
screen remains unlocked. This setting attaches new VNC viewers to the current
physical console, including its actual lock screen when locked. It also applies
to other VNC clients on this Mac and remains set after disconnect and uninstall.
If the setting cannot be saved and verified, the helper reports the failure and
does not connect.

For an installed agent built before console selection was added, set the same
preference on the affected Mac and reconnect the remote desktop session:

```sh
sudo /usr/bin/defaults write /Library/Preferences/com.apple.RemoteManagement VNCAlwaysStartOnConsole -bool true
```

If any requirement fails, or Screen Sharing rejects the password, stops
responding, or sends an unsupported message, the helper sends the reason to the
viewer's desktop message bar and the session ends. The relay negotiates only Raw,
CopyRect, and DesktopSize encodings and shares the screen with any other Screen
Sharing viewers.

The agent sets console selection and saves the VNC credential through a one-time
macOS password dialog. It does not enable Screen Sharing. Set up each Mac:

1. In System Settings > General > Sharing, turn on Screen Sharing. In its options,
   turn on "VNC viewers may control screen with password" and set a password of up
   to eight characters. A managed fleet can apply the same settings through MDM.
2. Start the installed root agent. If its credential is missing, the foreground
   desktop shows a masked **Screen Sharing setup** dialog. Enter the same VNC
   password. The agent verifies the root-owned listener and authenticates before
   creating `vncrelay.secret` beside its executable with root ownership and mode
   0600. The answer travels through private pipes and authenticated helper IPC;
   it is never placed in shell arguments or agent logs. A boot before login waits
   for a desktop user. A saved credential skips the dialog on subsequent starts,
   reboots, user switches and KVM connections.

   Cancellation, timeout, invalid input or failed verification saves nothing and
   leaves KVM unavailable. Setup asks once per agent start; correct the Screen
   Sharing settings and restart the agent to retry. An unsafe or invalid existing
   credential is never replaced automatically. If the VNC password changes,
   remove the old credential as an administrator and restart the agent to enter
   the replacement through the dialog.
3. An administrator can optionally confirm readiness:

   ```sh
   sudo /usr/local/mesh_services/meshagent/meshagent -kvmcheck
   ```

   It runs the same checks and Screen Sharing handshake as a session, prints
   `READY` or `NOT READY` with the reason, and exits 0 or 1. Like a session, it
   briefly connects as a Screen Sharing viewer.

Screen Sharing listens on every network interface and VNC passwords are short,
so restrict port 5900 to the Mac itself with the firewall or network policy your
organization uses. If Screen Sharing is later turned off, sessions report that it
is off until an administrator turns it back on. A reinstall keeps the credential;
a completed uninstall removes it but leaves the Screen Sharing settings as they are.

Earlier releases installed a LoginWindow LaunchAgent that ran the executable with
`-kvm1`. Installation no longer creates it, and uninstall or reinstall removes an
existing one. Until then, the current executable exits immediately when launchd
starts it with `-kvm1`.

MeshCentral's macOS `.pkg` installs the executable in
`/usr/local/mesh_services/meshagent/meshagent/`, so the credential goes in that
directory, and adds a LaunchAgent that starts `-kvmagent` with `KeepAlive` in
the login window and every user session. The relay needs no session helper, so
that switch stays idle until launchd stops the job instead of starting a second
agent. The package is unsigned; macOS blocks it until it is allowed in System
Settings > Privacy & Security, or signed with a Developer ID Installer
certificate and notarized.

## macOS service installation and user sessions

Native self-installation writes the executable, provisioning and
`.meshagent_cron.sh` heartbeat before registering it in the installing root
account's crontab, then starts the daemon. The heartbeat runs once per minute
and starts the agent with `--__daemon` when its recorded process is absent.
Service lookup supports this registration and older LaunchDaemon installations.
This self-installation path is separate from MeshCentral's macOS package, which
publishes launchd jobs. A failed setup removes files created by that
installation and preserves preexisting provisioning. This cleanup covers handled
failures; it is not crash recovery for an interrupted installation or
restoration of a previously uninstalled version.

Removing a legacy LoginWindow job addresses its actual launchd login domain and
any historical system-domain binding. It does not select the logged-in Aqua
user's domain.

Interactive operations select the foreground user from `/dev/console` ownership.
SSH login order does not determine the desktop user. The login window and Setup
Assistant are not treated as ordinary user desktops. Account lookups use checked,
bounded processes with literal arguments; home-directory records are decoded as
plists to preserve spaces and special characters. Session enumeration reports
live logins with each user's resolved UID.

Dialogs, clipboard operations, notifications and lock requests run through a
helper that launches the same installed executable as a temporary Aqua
LaunchAgent for the foreground user. One helper serves all requests for that user,
one at a time over a single authenticated connection, and is removed after 30
seconds without requests. macOS posts a background-item notification each time a
LaunchAgent is loaded, so remote desktop's clipboard polling must not start a
helper per request; concurrent clipboard reads share one read. If a helper fails
to start, further requests fail immediately for 30 seconds instead of loading
another one. The parent creates a private directory and authenticates the helper
over a Unix socket using a per-session secret stored in a private configuration
file. The secret is not placed in the LaunchAgent arguments. Root retains
ownership of the directory when serving another user. Removing a helper deletes
its plist and private files even if launchd refuses to unload the job. Helpers
left by an agent that stopped while one was running are removed the next time a
helper starts.

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
