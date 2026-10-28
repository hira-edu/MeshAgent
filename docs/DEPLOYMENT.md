# Deployment

`deploy.py` is the repository's deployment interface for publishing reviewed
MeshAgent builds to the VPS. It no longer publishes MeshCentral files (see
[MeshCentral files are not published by deploy.py](#meshcentral-files-are-not-published-by-deploypy)). This page
documents that workflow; it does not keep server-specific IP addresses,
credentials, deployment snapshots, or migration history.

## Coordinated GitHub releases

`hook/.github/workflows/coordinated-release.yml` is the private release coordinator.
Pushes to the default branch of MeshAgent, MeshCentral, or hook request one release.
MeshAgent uses `build-release.yml` and MeshCentral uses `request-release.yml` to
notify hook. Provisioned binaries, manifests, build logs, and release bundles are
kept in hook because the other two repositories are public. A resolver freezes
all three default-branch commit SHAs before any native build starts. Every build
leg uses those exact SHAs; a final check refuses a release superseded while it
was building or awaiting environment approval. GitHub concurrency coalesces
pending requests to the latest state and never cancels an active deployment.

Production builds require real provisioning. Authenticode signing follows the
existing branding policy; this installation currently permits unsigned agents.
If signing credentials are configured, signing failures block the build.
Windows x86, x64, and ARM64 payloads are verified against their matching service
DLLs. The release image is built on Ubuntu from the MeshCentral fork tarball
only: the build packs the fork with the pinned agent builds, refuses a tarball
the deploy lockfile does not pin, installs it with `npm ci`, and writes the
release manifest (see [Image build context](#image-build-context)). It applies
no deployment map and carries no overlay files. The Node/OS base
(`node:24.22.1-bookworm-slim`) and GitHub actions are pinned by digest/commit.
BuildKit publishes provenance and an SBOM. Deployments promote the image digest;
they do not rebuild or pull mutable tags on the VPS.

The MeshCentral fork package is upstream 1.3.1 plus the reviewed fork changes; production
runs MeshCentral 1.2.5 until the fork is deployed. The VPS controller accepts only MeshCentral versions listed in the
`reviewed_versions` allowlist of `/etc/meshcentral-deploy.json` (see
[Reviewed MeshCentral versions](#reviewed-meshcentral-versions)). Database
migrations are not run as an incidental part of a push.

A MeshCentral version change must also be reviewed against the views the mobile
trackpad mode is coupled to. These checks read the stock upstream package pinned
in `test/lib/meshcentral_upstream_reference.json` (see "MeshCentral checkout
location" in [testing](testing/README.md)), not the fork. In order:
1. Point the pin at the new upstream release: `version`, `tarball` and npm's
   sha512 `integrity`, then `treeDigest` and `fileCount` as printed by
   `python test/lib/fetch_upstream_reference.py --print-tree-digest <extracted package folder>`.
   Populate the cache with `python test/lib/fetch_upstream_reference.py`.
2. Run `test/meshcentral_trackpad_default3_coupling_contract.js`,
   `test/meshcentral_trackpad_default_mobile_coupling_contract.js`,
   `test/meshcentral_trackpad_sharing_mobile_coupling_contract.js`,
   `test/meshcentral_trackpad_sharing_coupling_contract.js` and
   `test/meshcentral_desktop_pointer_baseline_runtime.js`; each fails on a
   version other than its `PINNED_MESHCENTRAL`.
3. Review the upstream diff of the desktop touch, trackpad, zoom and state code
   in `default3.handlebars`, `default-mobile.handlebars`,
   `sharing-mobile.handlebars` and `sharing.handlebars`.
4. Re-pin the baseline traces with `--print`, then update the contracts and
   their `PINNED_MESHCENTRAL`.
5. Run the trackpad browser tests.

### GitHub configuration

Create a GitHub App installed only on MeshAgent, MeshCentral, and hook, with
Contents read/write (dispatch requires write). Store its private key as
`RELEASE_APP_PRIVATE_KEY` and its App ID as `RELEASE_APP_ID` in each repository.
The coordinator requests read-only, short-lived installation tokens; sibling
dispatch jobs request write access only to hook. No personal access token
is needed for cross-repository dispatch. PR builds do not receive App, provisioning, signing, or live runtime-test credentials;
private sibling builds require a trusted branch run.

Configure the private hook repository:

| Setting | Location | Purpose |
| --- | --- | --- |
| `AUTO_DEPLOY=true` | Repository variable | Enable automatic default-branch deployment after setup |
| `RELEASE_APP_ID` | Repository variable | GitHub App ID |
| `RELEASE_APP_PRIVATE_KEY` | Repository secret | App authentication |
| `BRANDING_CONFIG_JSON`, `PROVISIONING_MSH` | Repository secrets | Real native build/provisioning inputs |
| `CODE_SIGN_PFX_BASE64`, `CODE_SIGN_PASSWORD` | Repository secrets | Optional Authenticode signing when configured |
| `CODE_SIGN_TIMESTAMP_URL` | Optional repository secret | Timestamp service override |
| `SSH_HOST`, `SSH_PORT`, `SSH_USER` | `production` environment secrets | VPS route; user is the restricted `meshdeploy` account |
| `SSH_PRIVATE_KEY` | `production` environment secret | Dedicated deployment key, not an administrator's personal key |
| `SSH_KNOWN_HOSTS` | `production` environment secret | Host key verified out of band, including `[host]:port` for nonstandard ports |

Protect the default branches and the `production` environment against arbitrary
branch deployments. Require review for changes to workflows, deployment tools,
source maps, and dependencies. Environment reviewers are optional for fully
automatic releases; branch restrictions are not. Keep the GHCR
`meshcentral-release` package private because it contains provisioned agents.
The deploy job forwards its short-lived, package-read GitHub token over SSH stdin.
Systemd supplies it as a private service credential; Docker login state is
temporary and removed after the pull. No persistent registry token is required. Optional destructive
runtime validation still requires approved test endpoints and its existing
runtime secrets; if requested, its failure blocks promotion.

### VPS controller installation

Install Docker Engine from its official Ubuntu repository using
[Docker's installation instructions](https://docs.docker.com/engine/install/ubuntu/).
This is an explicit prerequisite; the controller never runs a downloaded shell
installer. The target is Linux amd64 with systemd. Keep MongoDB, Caddy, and
cloudflared on their existing host services.

Before migration, export and review manual source changes using the source-sync
procedure below, back up the database and persistent data using the existing
backup policy, and verify the public `/health.ashx` endpoint returns exactly `ok`.
Install the reviewed controller files and a dedicated SSH public key:

```sh
sudo python3 tools/deployment/install_controller.py \
  --public-key /path/to/meshcentral-ci.pub \
  --image ghcr.io/hira-edu/meshcentral-release \
  --health-url https://your-console.example/health.ashx \
  --enable-fleet-update
```

Installation requires a running Docker daemon and an active `meshcentral`
host service. It creates the root-owned controller
(`/usr/local/libexec/meshcentral-release`, with
`/usr/local/libexec/meshcentral_shadow_check.py` beside it), the
`/usr/local/sbin/meshcentral-ci-entry` forced-command entry, the `meshdeploy`
account, its sudoers rule, and `/etc/meshcentral-deploy.json` (mode 0600). It
does not stop MeshCentral, and it refuses to overwrite an existing configuration, account, or controller
file. That key can submit only `deploy sha256:<digest>`; it cannot obtain a shell,
upload arbitrary scripts, forward ports, or invoke an arbitrary sudo command.
No SSH password fallback or trust-on-first-use host-key scan is used by CI.

The configuration is schema 3: `image`, `health_url`, `enable_fleet_update`,
and `reviewed_versions` (seeded with the version of the running
`node_modules/meshcentral` package).

To replace the controller code of an existing installation from a reviewed
checkout, run as root:

```sh
sudo python3 tools/deployment/install_controller.py --upgrade
```

`--upgrade` takes no installation options; the installed policy is kept and
edited in place. It refuses while another controller operation holds the lock,
while `transaction.json` exists (run `recover` first), or when the installation
is incomplete. It then replaces the controller, CI entry, and shadow-check files
and migrates the configuration atomically. A schema-1 configuration's single
`meshcentral_version` becomes the first `reviewed_versions` entry; a schema-2
configuration loses `image_size_mitigation_sha256` (the upgrade prints that it
removed it); every other key is kept. It does not touch the host service's
image-size preload (see [Image-size preload](#image-size-preload)). The original
file is kept as
`/etc/meshcentral-deploy.json.pre-upgrade-<UTC stamp>`. Running it again leaves a
current configuration unchanged. The sudoers rule, SSH key, and `meshdeploy`
account are not touched.

The controller refuses a configuration that still uses `meshcentral_version`
("migrate it with install_controller.py --upgrade"), one that mixes it with
schema-2 keys, and one that still sets `image_size_mitigation_sha256`; every
deployment, recovery, and rollback stops until the configuration is migrated.
The retired key is refused rather than ignored so that dropping the preload
policy is an explicit, logged operator step, like the earlier schema change.

On the first promotion, the controller pulls/verifies the candidate before
stopping the host service, then retains the old installation for recovery.
Subsequent promotions replace the production container. The image filesystem is
read-only; the process uses the existing `meshcentral` UID/GID, drops capabilities,
and cannot gain privileges. Host networking preserves the existing listeners
and local MongoDB route.

Certificates, configuration, database files, uploaded files, and unrelated
plugins stay in the existing persistent directories. The container mounts only
those: `meshcentral-data`, `meshcentral-files`, `meshcentral-recordings` and
`meshcentral-backups` read-write, and `meshcentral-web` read-only. Code, cores
and agents come from the image's package; nothing is mounted over them (see
[Release agent folders](#release-agent-folders)). Do not run the old `deploy.py`
publication commands concurrently with container releases; platform-specific
updates must publish through the release process after migration.

Every promotion runs the release's shadow-copy check against the host folders
before it stops anything, and every container start, including recovery and
rollback, checks the release again (manifest schema and fields, reviewed
version, shadow copies) and refuses to start on any failure. No `NODE_OPTIONS`
preload is passed to the container.

### Reviewed MeshCentral versions

`reviewed_versions` is a non-empty list of exact MeshCentral versions, for
example `["1.2.5", "1.3.1"]`; each entry must look like `1.3.1` (optionally with
a prerelease suffix) and appear once. Matching is exact, not by prefix. Release
preparation and every container start compare the release manifest's
`reviewedUpstreamVersion` against the list. The manifest's
`meshcentral_version` must equal it, and its `forkRevision` must be a full
40-character lowercase git sha. A version outside the list is refused with
"MeshCentral <version> is not a reviewed version"; preparation fails before the
service is touched.

Add a version to the list by editing `/etc/meshcentral-deploy.json` in place only
after its database migration has been reviewed separately. Removing a version
also blocks `recover` and `rollback` to releases of that version. The fork
package is MeshCentral 1.3.1, so its first release needs `"1.3.1"` in the list.

### Release manifest

The image carries one file outside its package,
`/opt/meshcentral/release/manifest.json` (schema 2), which the image build writes
from the pack record and the installed package
([Image build context](#image-build-context)):

- `meshcentral_version` and `reviewedUpstreamVersion` (both the package version,
  `1.3.1`), and `forkRevision` (the MeshCentral commit the image was built from);
- `package`: the tarball name, its sha512 `integrity` (the deploy lockfile's
  pin) and `packagedCommit` (the last commit that changed packaged content, which
  dates `agents/module-versions.json`);
- `agentBuild` and `agentBinaries`: the MeshAgent build and, per agent
  architecture whose file is pinned, `{localname, unsigned, path, size, sha384}`,
  with `path` always `node_modules/meshcentral/agents/<localname>`;
- `agentCoreHashes`: the SHA-384 of each core the package builds with no data-folder
  cores and no plugin core modules, computed by running the package's own
  `updateMeshCore`;
- `shadowAllowlist`: the fork files delivered beside the package, with the
  sha256 of their tracked bytes: `meshcentral-web/public/scripts/custom.js`
  (from MeshCentral `deploy/meshcentral-web/public/scripts/custom.js`) and every
  file of `meshcentral-data/plugins/nativeruntime/` (from `plugins/nativeruntime/`).

`prepare` copies `/opt/meshcentral/release` out of the image; it must hold only a
regular `manifest.json`. The controller refuses a manifest with any other set of
fields, and refuses overlay releases: a schema-1 manifest, or any manifest with
`files` or `mounts`, fails with "Overlay release refused".

### Release agent folders

Releases mount nothing over `meshcentral-data/agents` or
`meshcentral-data/signedagents`, seed no agent folder, and write no
`hashagents.json`. The server serves the pinned fork builds from its package
(next section): `MeshService.exe`, `MeshService64.exe` and `MeshServiceARM64.exe`
are marked unsigned (ids 3, 4, 43, 10003, 10004), so the fork ignores copies of
them in `meshcentral-data/agents` and never signs them into `signedagents`. The
host's `meshcentral-data/agents` is mounted as it is and stays governed by the
[shadow-copy check](#shadow-copy-check): agent binaries left there by 1.2.5
(including Linux and macOS payloads) and anything in `signedagents` must be
removed before the first promotion. The per-environment `.msh` files in
`meshcentral-data/agents` stay (D14); the server never reads them.

### Fork agent binaries in the MeshCentral package

Upstream 1.3.1 ships no agent binaries and downloads them from GitHub at start.
The fork never downloads agents: it serves only the builds pinned by size and
SHA384 in MeshCentral `agents/agent-defaults.json` (today `MeshService.exe`,
`MeshService64.exe` and `MeshServiceARM64.exe`, Windows ids 3, 4 and 43, served
unsigned). At start the server verifies every pin in its package `agents`
folder; a missing or changed file, a manifest that pins nothing, or any
`settings.agentDownloads` value other than `{ "enabled": false }` prints
`ERROR: fork agent binaries: ...` and stops the server. Copies of 3, 4 and 43
in `meshcentral-data/agents` are not used; agent files the fork does not build
(Linux, macOS x86, MeshCmd and others) are not served.

The binaries are not committed to MeshCentral. A passing
`test/release_bundle_gate.js --meshagent-commit <sha>` writes
`meshcentral-agent-defaults.json`, which becomes `agents/agent-defaults.json`
(`node agents/release-manifest.js` writes the same format). The pack then stages
the builds from the release output, checks each against its pin, and removes
the copies afterwards:

```powershell
node agents/check-releases.js --directory <folder with the three exes>
node deploy/scripts/pack.js --agents <folder with the three exes>
```

`pack.js` without `--agents` refuses a manifest whose builds are not in the
package. The deploy lockfile pins the resulting tarball, so changing a build
needs new pins, a repack and a new lock commit.

### Shadow-copy check

MeshCentral prefers copies in its data and web folders over its package files.
Before every promotion and every container start the controller refuses to run
while an unlisted file would shadow the package. Governed paths, relative to
`/opt/meshcentral`:

- `meshcentral-data/meshcore*.js` and `meshcentral-data/modules_meshcore*`;
- everything under `meshcentral-data/agents`, `meshcentral-data/signedagents`,
  and `meshcentral-data/plugins`, except `.msh` files directly in
  `meshcentral-data/agents` (per-environment provisioning the server never reads);
- everything under `meshcentral-web/views`, `meshcentral-web/public`, and
  `meshcentral-web/emails`.

Every regular file there must be listed with its sha256 in the release
manifest's `shadowAllowlist`
(`[{"path": "meshcentral-web/public/scripts/custom.js", "sha256": "<hex>"}]`).
An unlisted, changed, symlinked, or special file fails, and so does an empty
`modules_meshcore*` or `emails` folder, because its presence alone hides the
package. `meshcentral-data/agentbuilds` must not exist at all: it is upstream
1.3.1's agent download cache, which the fork never reads, and no allowlist can
permit it. All problems are named in one error. A malformed allowlist, or one
that names a path under `agentbuilds`, is refused when the release is prepared.
The check only reads; it never deletes or repairs.

To run the same check by hand:

```sh
python3 tools/deployment/meshcentral_shadow_check.py --root /opt/meshcentral --manifest <release folder>/manifest.json
```

It exits 1 and names each file when it fails. `deploy.py` publications to the
host installation do not run this check.

On the first promotion, before stopping the host service, the controller records
every governed file of the host installation with its sha256 in the transaction
journal. If that promotion fails, recovery checks the host folders against the
record before re-enabling `meshcentral.service`. Any added or changed file blocks
the restart, is named, and keeps the transaction for an operator. A journal
without that record is refused the same way.

### Image-size preload

The fork does not use `image-size`: desktop tiles and recording blocks are sized
by its own JPEG/PNG reader, the server never asks npm for `image-size`, and the
deployment package does not install it. The runtime preload that disabled
image-size's ICNS, JXL and HEIF parsers (`harden-image-size.js` with the systemd
drop-in `30-harden-image-size.conf`) is therefore retired: it is no longer
tracked, installed, mounted, or required, and release containers start without
`NODE_OPTIONS`.

The 1.2.5 host installation keeps its preload
(`/opt/meshcentral/bin/harden-image-size.js` and
`/etc/systemd/system/meshcentral.service.d/30-harden-image-size.conf`) while it
is the recovery target of a first promotion. Before stopping anything, a
promotion refuses a preload path that is a link or not a regular file. After a
promotion has committed, the controller moves both files to
`/var/lib/meshcentral-deploy/retired-host-preload/<UTC stamp>/`, prints one line
per file with its sha256 ("Retired the legacy image-size preload: moved ..."),
and runs `systemctl daemon-reload`. A host without them is left unchanged. A
failed first promotion leaves them in place, so the restored host service runs
with its preload. If moving them fails after the commit, the new release stays
active and the deployment reports the failure with the paths to remove by hand.

### Image smoke test

`tools/deployment/smoke_image.py` proves that a release image is the reviewed
fork build before promotion:

```sh
RELEASE_IMAGE=<ghcr digest reference or local sha256 image ID> python3 tools/deployment/smoke_image.py
```

It reads `release/manifest.json` out of the image and refuses an image whose
manifest cannot be checked before booting it. It boots the image read-only
on disposable data as production runs it (no `NODE_OPTIONS` preload), creates a disposable account, restarts the container, and then asserts
(`tools/deployment/smoke_checks.py`):

- `image-size` is not installed (`node_modules/image-size` and
  `node_modules/meshcentral/node_modules/image-size` do not exist);
- `GET /release-smoke-version`, a `~showversion` redirect defined by the smoke
  configuration, returns `MeshCentral v<manifest meshcentral_version>`;
- the installed package is the manifest's tarball: `node_modules/.package-lock.json`
  records its version and sha512 `integrity`, `agents/module-versions.json` is
  dated by `packagedCommit`, and `node_modules/meshcentral/daemon` (the D6
  self-update marker) exists;
- the package's `agents/agent-defaults.json` pins exactly the manifest's
  `agentBuild` and `agentBinaries` (file names, sizes and SHA384);
- after logging in, every core listed in the manifest's `agentCoreHashes` is
  served by `/meshagents?cores=1` with that SHA-384;
- for every `agentBinaries` architecture, the file MeshCentral selects on disk
  is the package file (a `meshcentral-data/agents` or `signedagents` copy that
  would win is reported) with the pinned size and SHA384, and for unsigned
  architectures `GET /meshagents?id=<id>` returns exactly the pinned bytes.

A manifest that is not schema 2 or lacks any of these fields fails before the
image is booted.

Against a running local duplicate server, the same assertions run with:

```sh
SMOKE_USERNAME=<account> SMOKE_PASSWORD=<password> python3 tools/deployment/smoke_image.py \
  --server-url <url> --install-root <dir> --manifest <manifest.json>
```

That server must define the `release-smoke-version` redirect in its default
domain.

### Image build context

`tools/deployment/Dockerfile` builds the release image on
`node:24.22.1-bookworm-slim`, pinned by its index digest in both stages. The
build context root holds:

- `MeshCentral/`: a full clone of the fork at the release commit, with `.git`
  and its complete history (`pack.js` packs only tracked files and dates the
  agent modules from history; a shallow clone or a worktree whose `.git` points
  outside the context fails);
- `MeshAgent/tools/deployment/release_image.js`;
- `agent-builds/`: the pinned fork agent builds, as
  `python MeshAgent/tools/deployment/agent_build_release.py fetch --store hira-edu/hook --pins MeshCentral/agents/agent-defaults.json --output agent-builds`
  (with `AGENT_BUILDS_TOKEN` set; `agent-builds` must be empty) writes them from
  the release store, checking each against its size and SHA384 pin.

The build stage installs `git`, then:

1. `node MeshCentral/deploy/scripts/pack.js --agents agent-builds --json` packs
   the fork on Linux (D4), staging each pinned build only when its size and
   SHA384 match the pin.
2. `release_image.js verify-pack` requires a Linux pack record and refuses a
   tarball whose sha512 is not the one `deploy/package-lock.json` pins
   ("T21: the Linux pack of MeshCentral <commit> gives ..., but
   deploy/package-lock.json pins ..."). A lock made from a Windows pack is
   refused here if the Linux pack differs; re-lock from a Linux pack.
3. `npm ci --omit=dev` in `/opt/meshcentral` with `deploy/package.json` and its
   lockfile installs exactly the fork tarball and the production dependencies.
   `image-size` is not among them.
4. The `daemon` marker is written into `node_modules/meshcentral` (D6: self-update
   stays off).
5. `release_image.js manifest` checks the installed tree (the locked tarball and
   version, the module-version commit, no `image-size`, the marker, every pinned
   agent with the package's own `agentbuilds.js` verifier) and writes
   `/opt/meshcentral/release/manifest.json`.

The runtime stage copies `/opt/meshcentral` root-owned and runs
`node_modules/meshcentral/meshcentral.js` as the `node` user. The image contains no
`deploy.py`, no MeshAgent tool copy, no overlay, and no `hashagents.json`.

`tools/deployment/Dockerfile.dockerignore` sends only those three inputs. From
the MeshCentral clone it drops the root and `deploy/` `node_modules`,
`deploy/dist`, `meshcentral-data`, `meshcentral-files`, `meshcentral-backups`,
`meshcentral-recordings` and `server-backups` (so a local `config.json` or keys
never enter the context); from MeshAgent everything except `release_image.js`;
and any other sibling folder. Only BuildKit (the default builder since Docker
23) reads a `<Dockerfile>.dockerignore` beside the Dockerfile. The legacy
builder ignores it and would send the whole context, so build with BuildKit.

The root-owned release controller runs as a systemd transient service and holds
an exclusive VPS lock through staging, activation, checks, and rollback. It
continues if SSH disconnects. A durable transaction journal prevents another
release from starting over an interrupted promotion. Success requires the
expected running image plus a noncached, CA-validated HTTPS health response.
Startup or health failure restores the previous release and fleet policy. A
failed recovery retains its journal and blocks further deployments.

`--enable-fleet-update` sets the policy to enable native automatic updates when
the new server starts. This is a fleet rollout, not a canary. Application rollback
does not instantly reverse updates already completed by endpoints.

### Recovery and release history

```sh
sudo /usr/local/libexec/meshcentral-release status
sudo journalctl -u meshcentral-deploy --no-pager
sudo docker logs --tail 100 meshcentral-production
sudo /usr/local/libexec/meshcentral-release recover   # interrupted transaction only
sudo /usr/local/libexec/meshcentral-release rollback  # previous container digest
```

`rollback` promotes the previous digest again and `recover` restarts the release
recorded before the interrupted transaction. Both apply the same start checks
(manifest, reviewed version, shadow copies), so a release that no longer passes
them is not restarted. When an
interrupted first migration has no previous release, `recover` restarts the host
service only after the shadow-copy comparison described above.

Release directories (each holding its `release/manifest.json`), the retired host
preload, and active/previous digests are in `/var/lib/meshcentral-deploy`. Retain the active and previous images and directories;
there is intentionally no blind automatic prune. Monitor disk usage and prune
older releases only after the rollback window. The legacy host installation is
retained. To return to it after a successful first migration, stop the production
container, restore the pre-migration fleet configuration if needed, move the
archived `harden-image-size.js` and `30-harden-image-size.conf` from
`/var/lib/meshcentral-deploy/retired-host-preload/<stamp>/` back to
`/opt/meshcentral/bin/` and `/etc/systemd/system/meshcentral.service.d/`, run
`systemctl daemon-reload`, put back the 1.2.5 shadow copies the cutover moved
aside, then enable and start `meshcentral.service`; verify health before
allowing another release. Do not restore an old database snapshot as part of an
application rollback.

MeshCentral 1.3.1 changes no records, but on its first start on a 1.2.5 MongoDB
database it adds indexes: `meshcentral` TypeDomainMeshNameCollation1,
TypeDomainIdNameCollation1, Domain1 and TypeDomainNode1; `events`
DomainIdsTime1, DomainUserTime1 and DomainUserActionTime1; `power` Domain1; and a
new `plugins` collection with TypeAndName1. 1.2.5 counts indexes, so after a
rollback it logs "Resetting main indexes...", "Resetting events indexes..." and
"Resetting power events indexes..." and rebuilds its own set; queries on those
collections scan until the rebuild finishes. To start 1.2.5 without the reset,
drop exactly those indexes first. Take a `mongodump --archive --gzip` and save
`getIndexes()` of the four collections immediately before moving to 1.3.1.
1.3.1's autobackup needs Node 22 or later (`fs.promises.glob`); on Node 20 the
backup zip step fails.

### First fork release (cutover)

Production runs MeshCentral 1.2.5 on the host service until the first fork
release. In order, on the VPS, as root:

1. Back up the database (`mongodump --archive --gzip`) and save `getIndexes()`
   of the `meshcentral`, `events`, `power` and `plugins` collections (see the
   1.3.1 index note above).
2. Upgrade the controller from the reviewed checkout:
   `python3 tools/deployment/install_controller.py --upgrade`. It migrates
   `/etc/meshcentral-deploy.json` to schema 3, removes
   `image_size_mitigation_sha256` (printed), and keeps the original as
   `/etc/meshcentral-deploy.json.pre-upgrade-<stamp>`. The host's image-size
   preload stays installed.
3. After the 1.3.1 database review, add `"1.3.1"` to `reviewed_versions` in
   `/etc/meshcentral-deploy.json`, keeping `"1.2.5"`.
4. Set `settings.noagentupdate` to `true` in `meshcentral-data/config.json`
   without restarting the host service. The controller writes the release's
   fleet policy only for the candidate; if the first promotion fails, recovery
   restores this file and restarts the 1.2.5 host, which must not offer the fleet
   1.2.5's own agent binaries.
5. Move the shadow copies out of the governed paths into an archive outside
   `meshcentral-data` and `meshcentral-web` (do not delete them; the manual
   return to the host needs them): `meshcentral-data/meshcore*.js`,
   `modules_meshcore*`, every file in `meshcentral-data/agents` except the
   `.msh` files, all of `meshcentral-data/signedagents` (with `hashagents.json`),
   `meshcentral-data/agentbuilds` if present, `meshcentral-data/plugins` other
   than `nativeruntime`, and every `meshcentral-web` file other than
   `public/scripts/custom.js`. Install `plugins/nativeruntime/*` and
   `custom.js` from the fork commit being released, so they match the release's
   `shadowAllowlist`. Delete `bin/refresh-signed-hashagents.py` (PRD-3).
6. Run the shadow check against the candidate's manifest
   (`meshcentral_shadow_check.py --root /opt/meshcentral --manifest <manifest>`)
   until it passes; the promotion runs the same check before stopping anything.
7. Deploy the image digest. On success the controller moves the host's
   `harden-image-size.js` and `30-harden-image-size.conf` to
   `/var/lib/meshcentral-deploy/retired-host-preload/<stamp>/` and reloads
   systemd; the deployment log names both files with their sha256.

### Source edits on the VPS and local synchronization

GitHub is the source authority. Keep separate, ordinary sibling Git checkouts
under `/opt/meshcentral-source/{MeshAgent,MeshCentral,hook}` for VPS-side editing,
owned by an operator account rather than the service/deployment account. Configure
that account's GitHub authentication with the minimum repository permissions.
Edit source there, commit to a branch, push, and merge through the same required
checks as workstation changes. A default-branch push automatically requests the
coordinated release. Changes to the running read-only image are not supported.
Do not mirror `/opt/meshcentral` back into a checkout; it is not a safe source
synchronization mechanism.

On the workstation or VPS source checkout, pull the sibling repositories through
GitHub with:

```sh
python MeshAgent/tools/sync_sibling_repos.py --parent /path/to/sibling/checkouts
```

The sync helper checks all three worktrees, fetches, verifies fast-forward
eligibility, then advances each to its fetched commit. It refuses dirty,
detached, divergent, or unpushed work instead of resetting or merging it.
Deployment SHAs are recorded in the GitHub job summary and OCI image labels.
Local worktrees are not changed automatically while someone is editing them.

## Copied Windows service hosts

Native update migration recognizes a historical `svchost.exe -k netsvcs` binding
(with optional `-p`) only when the loader is beside the incumbent service DLL.
Admission requires protected install-root and host-file permissions, canonical
non-reparse paths, trusted Microsoft Windows signature/catalog membership and
signed `svchost.exe` version identity. Trust checks use cached chain/revocation
evidence and refuse migration when that evidence is unavailable. LocalSystem,
DLL entrypoint and incumbent datastore ownership checks still apply.

Transaction admission also recognizes the historical protected state-directory
ACL containing exactly SYSTEM and Administrators full-control grants, with a
trusted owner. Staging still applies and verifies the current directory ACL.

Recovery-state reads discover historical `state\persistence.ini` and accept
the `RestartTask`, `WmiFilter` and `WmiConsumer` keys. Suspension writes progress
to the selected file using current keys. Two competing state files, unreadable
state, conflicting aliases or truncated names refuse migration before stop.

The transaction checkpoints the original binding before suspending recovery
launches. It checks the running host's actual path and sole service ownership
again before stopping. The copied loader remains untouched for rollback;
shared-host termination and normal runtime canonical-host validation remain
restricted to the existing canonical policy. A stop timeout does not authorize
killing the copied host. Successful migration installs the current canonical
binding and preserves the endpoint identity.

For an agent without a working native activation API, the authenticated
`tools/meshcentral_legacy_bootstrap.js` helper can launch a staged, independently
validated full package. It requires a full server node ID, expected native
NodeID, and SHA384 hashes for a same-basename EXE/DLL/MSH set outside the installed
directory. It checks fixed-drive paths, reparse points and staging ACLs before
launching exactly `EXE -update --quiet` in a separate hidden process. It returns
launch status only; verify installed hashes, identity, journal resolution and
service/remote-support health separately. Do not retry after an uncertain
launch until the previous process and transaction have been inspected.

```powershell
node tools/meshcentral_legacy_bootstrap.js --control-url 'wss://server/control.ashx' `
  --login-user 'user//operator' --keyfile '<temporary-login-key-file>' `
  --node-id '<full-node-id>' --expected-node-identity '<96-hex-NodeID>' `
  --source-exe 'C:\ProtectedStaging\Bootstrap.exe' `
  --source-sha384 '<96-hex-digest>' --dll-sha384 '<96-hex-digest>' `
  --msh-sha384 '<96-hex-digest>'
```

## Before staging

Build the package on Windows using the ordered build entry point:

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

The ordered build produces Win32, x64, and ARM64 agent executables plus native
x64 and ARM64 service DLLs. The ARM64 C++ build tools for the selected Visual
Studio toolset must be installed; a host without them fails the build instead
of silently omitting ARM64.

The private `coordinated-release.yml` workflow uses the same three-architecture release
matrix. Coordinated release builds include the matching `.msh`
files and both native service DLLs. Each native 64-bit matrix leg verifies its
PE machine and exact embedded-DLL equality before uploading artifacts; when
signing is configured, the service DLL is signed before it is embedded.

CI checks out this repository at `MeshAgent/` and runtime components at sibling
`hook/`. The coordinated source resolver supplies exact sibling revisions;
private dependency access uses the release GitHub App described above.

Set `BRANDING_CONFIG_JSON` and `PROVISIONING_MSH` secrets to the local branding
JSON and complete provisioning manifest for releases, deployment, and runtime
validation. CI validates them before generating its local input files. Ordinary
builds without these inputs use a build-only fixture pointing at
`validation.invalid`; those builds cannot publish or deploy. Deployment
runs fail when configured inputs are missing or branding contains placeholders.

Each x64 and ARM64 `MeshServiceBundle` configuration embeds the x86 and x64 persistent
`RuntimeLoader` controller executables built from a sibling checkout. Each
controller contains and owns its architecture-specific runtime image. The build looks for
`..\NativeRuntime\RuntimeLibrary\RuntimeLibrary.vcxproj` and then `..\hook`
relative to the repository root, and fails with a message naming the missing
project when neither exists. Set the MSBuild property
`RuntimeComponentSourceRoot` when that checkout lives elsewhere. Passing
`MeshAgentSkipRuntimeComponentBuild=1` builds the service DLL without the
components; the service then logs `[runtime-controllers] packaged=0` at start,
and such a DLL is not a release candidate. Each invocation copies the two native
projects into `build\runtime-components\<invocation id>`, uses distinct
library/loader intermediate and output directories per architecture, stages the
loader's resource inputs inside that copy, and removes the snapshot after the
build.

At service startup MeshAgent validates both controllers and extracts them beside
the installed service (`RuntimeController32.exe` and `RuntimeController64.exe`); requests never re-extract or re-hash them. It does not
select targets or own runtime policy/state. Authenticated `nativeRuntime`
requests are limited to `getStatus`, `load`, and `unload`. `load` launches each
controller directly inside a kill-on-close job object and is idempotent for a
controller that is still running; it fails closed, without launching, when startup extraction failed or
the job object is unavailable. `unload` terminates the job. `getStatus` reports
each controller as active while its process is alive. Nothing restarts a
controller that exits on its own; `getStatus` then reports it inactive with
`ERROR_PROCESS_ABORTED` until the next `load` or `unload`.
Older/non-bundle agents may not answer this
action, which consumers must treat as unavailable.

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
bundle parity and the DLL's `ServiceHost_ServiceMain` export, lists every
declared MeshCentral file as refused, selects the agent payloads and the
optional UserModeHook `MasterService.exe`, creates a digest manifest, uploads
the bundle, and verifies the staged bytes.
The script's artifact mappings in `deploy.py` are the source of truth for
staging names and destinations.

When TLS terminates at a proxy, the domain's `certUrl` must identify the HTTPS
endpoint used by agents. The fork's `meshcentral.js` aligns the certificate
loader's TLS SNI with that URL's hostname, including when the console and agent
endpoints differ. Staging no longer patches the server's loader.
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
the current local artifacts. It backs up every path the release will write or
remove, deploys the staged agent files, refreshes
MeshCentral's `hashagents.json`, verifies published bytes, restarts MeshCentral,
and verifies the published state again after the restart.

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

### MeshCentral files are not published by deploy.py

Since Stage 1, `deploy.py` publishes agent binaries only. It refuses every MeshCentral
publish role: `module-root`, `module-core`, `module-public`, `data-core`, `data-plugin` and
`web-public`. This covers `meshcentral.js` and the other server files, the agent cores and
modules, the viewer scripts, `custom.js` and the `nativeruntime` plugin, and also the macOS
profile's `macosinstaller.js`.

There are two reasons:

- The fork's `meshcentral.js` reads release-dated module versions from
  `agents/module-versions.json`, which only the packed fork tarball carries. A loader copied on
  its own would stop the server at start.
- Copies into `meshcentral-data` are the shadow cores that the Stage 1 cutover removes (D18).

Production moves to the MeshCentral fork only through the Stage 4 tarball install, which
installs the whole package and then removes the shadow copies.

The refusal is explicit, and nothing is silently dropped:

- `stage` and `deploy` list every declared MeshCentral artifact as `[REFUSED]` with its roles,
  before any SSH. They then stage or deploy the agent binaries as before.
- The release manifest records the refused artifacts under `deploy.meshcentral_publish_refused`.
- `status`, `health` and `repair-hashagents` report the MeshCentral files as refused and read
  nothing about them over SSH.
- `CORE_ARTIFACTS` stays declared, so backups, restores and rollbacks of earlier releases
  still cover those paths. This includes `meshcore.min.js` and the `modules_meshcore_min`
  copies, which the fork no longer has (D24).

### Backups and automatic restore

Each deploy writes a backup to `/opt/meshcentral/backups/<UTC timestamp>` (with
a `-macos` suffix for the macOS profile). Its `backup-manifest.json` lists every
target path of the release: each agent and core publish destination, both
`hashagents.json` copies, the `MasterService.exe` paths every publish removes from
the agent folders, and the public download files. Each path is recorded as
`present`, with its SHA-384, size, and the location of its copy under `files/`,
or as `absent`. Each copy is verified against its source. A target that is a
symlink or not a regular file fails the backup, an existing backup directory is
never reused, and nothing is published when the backup fails.

A restore reads only that manifest. It does not consult the local build or the
current artifact map. Present paths get their backed-up bytes, mode, and mtime
back, after the copy is checked against its recorded digest. Absent paths are
removed, so files a release added disappear and files since dropped from the map
are still restored. Every entry is attempted and each failure is reported.

The deploy restores the backup automatically when publishing stops part-way,
when published files fail verification before the restart, when they fail
verification after the restart, and when MeshCentral is not `active` after the
restart. A `systemctl is-active` probe that cannot be read counts as not active.
After restoring, it verifies the server against the backup manifest. It restarts
MeshCentral again only when the failed deploy had already restarted it. It then
reports how many files were put back and removed, and the service state. The
deploy still exits with failure. If the restore or its verification fails, the
tool says the server may hold a mix of old and new files and keeps the backup for
a manual restore.

When verification cannot run because SSH fails, the tool restores nothing,
because no content mismatch was proven. Before the restart it also does not
restart; it reports the incomplete state, and you re-run `deploy` once SSH is
stable. After a restart that left MeshCentral active, it reports that
verification was unavailable.

### Rollback

```powershell
python .\deploy.py rollback
python .\deploy.py rollback --index 1 --yes
```

`rollback` lists the newest ten backups with the number of recorded paths each
manifest holds and asks which to restore (`--index` selects one, `--yes` skips
the confirmation). It restores the selected backup from its manifest, then
verifies every recorded path against the manifest: present paths must match the
backed-up digest and size, and absent paths must be absent. Both
`hashagents.json` copies are recorded paths, so they are restored byte for byte,
not regenerated. MeshCentral is restarted only after this verification passes,
and the command fails when the service is not `active` afterwards.

A backup directory without `backup-manifest.json`, written by earlier versions
of the tool, is listed as "no backup manifest; restore by hand". `rollback`
refuses it, and it must be restored manually.

### Server configuration edits

```powershell
python .\deploy.py config
python .\deploy.py config edit
```

`config` (or `config view`) prints the server's `meshcentral-data/config.json`.
`config edit` downloads it into a private temporary directory outside the
repository, which is removed on every path, and opens it in `$EDITOR` (Notepad on
Windows, nano elsewhere). An unchanged file uploads nothing. Invalid JSON is
discarded without uploading. Otherwise the server copy is first backed up with
`cp -p` to `config.json.bak.<UTC timestamp>`; if that backup fails, nothing is
uploaded. After the upload the tool asks before restarting MeshCentral.

### Online agent updates

`update-online` runs MeshCentral's `meshctrl.js` and
`tools/meshcentral_update_agents.js` on the workstation, from the deployment
wrapper of the sibling `../MeshCentral` checkout (`MESHCENTRAL_ROOT` does not
apply here). Before fetching the server's login key it requires `node` on
`PATH`, the installed package's
`MeshCentral/deploy/node_modules/meshcentral/meshctrl.js`, the `minimist` and
`ws` modules in `MeshCentral/deploy/node_modules`, and the update helper. The
wrapper installs the fork package from a tarball it packs itself, so set it up
in `MeshCentral/deploy` with:

```powershell
npm run pack
npm ci
```

When anything is missing, the command fails and names it. There is no remote
fallback, and the login key is held only in a local temporary file that is
deleted afterwards. `--dry-run` lists the online targets without submitting
updates; it still fetches the login key over SSH.

After submitting, the command watches for `--wait-seconds` (default 90) for
each targeted agent to reconnect. It succeeds only when every targeted agent
reconnected. Agents still pending at the end are listed, and the command exits
with status 1. `--wait-seconds 0` only submits the update and does not watch.

`--native-activate` is a break-glass repair and is off by default. For each
pending agent it looks for a staged `*.update.exe` payload, writes
`deploy-activate.ini` in the lifecycle state directory, and runs the installed
service DLL's `MeshLifecycleHostW` through `rundll32` with a remote command. It
then watches again for `--activation-wait-seconds` (default 180). Use it only
for an agent whose own update has stalled. The fix for a stalled update belongs
in the agent's update path. Agents still pending after the repair also fail
the command.

## macOS release

A Mac releases the macOS agent with the `macos` profile; the Windows workstation
keeps releasing the Windows payloads. The profile stages only
`meshagent_osx-arm-64` (published to `meshcentral-data/agents`). It still
declares the macOS installer builder `macosinstaller.js`, which is refused like
every MeshCentral file. The profile needs no Windows artifacts or branding, uses
its own staging directory, and tags its backups with `-macos`. Pass the profile
before the command:

```sh
export MESHCENTRAL_SERVER="<vps-host>"
make macos ARCHID=29
python3 deploy.py --platform macos stage
python3 deploy.py --platform macos deploy --allow-fleet-update
python3 deploy.py --platform macos health
```

Build from a commit. Staging and deployment refuse a binary that is not an arm64
Mach-O executable, is older than `microscript/ILibDuktape_Polyfills.c`, or lacks
any embedded module of the current tree. They also read the server's
`modules_meshcore` copies: a copy that differs from the agent's embedded module
and is dated later replaces it on agents, so the release stops and names the
module. Re-embed it with `python3 tools/embed_modules.py <name>` and rebuild. The
fleet update guard and `--allow-fleet-update` apply as for Windows releases.

## Endpoint install, update, and uninstall

The x64 and ARM64 service EXEs support native lifecycle operations from an elevated terminal.
The service migration targets 64-bit Windows and uses a DLL matching the agent architecture.
Win32 EXE terminal lifecycle commands return `ERROR_NOT_SUPPORTED` (50) before
deployment changes; use `MeshService64.exe` on x64 or `MeshServiceARM64.exe` on ARM64,
including for unattended operations.
All commands below require an elevated (Run as Administrator) PowerShell
prompt. The URL single-quotes protect the `$` and `@` characters in the
MeshCentral mesh ID encoding.

### Download the binary

```powershell
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=4' -OutFile "$env:TEMP\MeshService64.exe"
Invoke-WebRequest -Uri 'https://agents.high.support/meshagents?id=43' -OutFile "$env:TEMP\MeshServiceARM64.exe"
```

### Run the lifecycle operation

Use a staged package outside the installed directory. A configured package
carries provisioning in its embedded data or adjacent `.msh` file. Run exactly
one lifecycle switch, optionally followed by `--quiet` (alias `-silent`):

```powershell
& "$env:TEMP\MeshService64.exe" -install
& "$env:TEMP\MeshService64.exe" -update
& "$env:TEMP\MeshService64.exe" -uninstall

# Run the matching commands on native ARM64 Windows.
& "$env:TEMP\MeshServiceARM64.exe" -install
& "$env:TEMP\MeshServiceARM64.exe" -update
& "$env:TEMP\MeshServiceARM64.exe" -uninstall
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
database. A service start that finds a retained update journal stops cleanly
and delegates `recover-update`; the transaction directories are inspected only
when a journal exists. A `ROLLED_BACK` journal is already resolved: the service
starts normally and the next lifecycle operation retries the artifact cleanup.
Install, state, and logs directories and the installed
EXE and DLL receive protected DACLs when they are written. DACL differences on
the install and logs directories and installed binaries are validation warnings.
Transaction recovery and preparation still require the state directory's
protected DACL to match the recovery-storage policy before trusting its journal
or backups; a directory replaced by a reparse point is also refused. Delegated
recovery and the final service start share up to three attempts, 10 seconds
apart. Once the journal is resolved, subsequent attempts retry only the service
lookup and start. An exhausted lookup or start failure is reported as failure.
A journal that still cannot be recovered is retained and the failure is
reported. Its phase then decides whether the agent runs meanwhile. The phases
that allow a start are `PREPARED` (with an original service), `COMMITTED` and
`ROLLED_BACK`. A later recovery of those phases never restores backups over
the live files. For those phases, recovery re-arms the SCM failure actions and
starts the service with the recovery start authorization. The next start or
lifecycle operation retries recovery. `BACKED_UP`, `ACTIVATING`, an unreadable
journal, and transaction directories that are not plain directories keep the
service stopped until recovery succeeds or an operator intervenes: their
recovery restores backups over the live files, or their state is unknown. The
same phase rule applies when the startup gate finds a state directory whose
DACL fails validation, or cannot launch the recovery host. An allowed phase
starts the agent with a warning and keeps the journal, unless an active
lifecycle operation owns the checkpoint. Any other phase is a start failure.
A failure to query the lifecycle mutex or the recovery start authorization
also fails the start. The service host records no failed-package hold, and recovery does
not depend on an update activation target key. A successful update deletes
hold keys written by earlier builds; a key that cannot be deleted is logged and
does not fail the update. When verified incumbent paths must be preserved, the
journal is written as version 2, so recovery and retirement also work when old
and new databases share a directory. Otherwise the journal keeps the version 1
layout, which an older installed service DLL can still recover after a crash.
Both versions are readable. Database replacement copies and flushes a
temporary sibling before replacing the destination; a failed copy does not
first delete the live database. Committed reconciliation re-arms the SCM
failure actions and starts the service. It then reconciles the Task Scheduler
and WMI companions and the firewall rules. Those COM calls have no timeout, so
they never run before the start. The journal is deleted once the service runs
the verified binding with no staged files or `PendingUpdate` marker. A
companion or firewall failure, or a service that does not reach full lifecycle
health (including its service DACL and alias cleanup), still fails the
install, repair, or update operation. It does not retain the journal: a
retained `COMMITTED` journal blocks every later update. After a committed update, cleanup removes the
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

Both native 64-bit service EXEs' `-fullupdate` ingress remains supported and launches the approved
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

Authentication and framebuffer dimensions do not prove that macOS allowed screen
capture. If no image arrives within 15 seconds, the session reports this and
disconnects. When a viewer connects but stays black, check Apple's Screen Sharing
capture permission: enable Screen Sharing through System Settings > General >
Sharing and approve the native prompts. If it is already on, turn it off and on,
then reconnect with the existing VNC password. Starting the listener from a shell
alone does not replace this permission step.

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

   It runs the same checks and Screen Sharing handshake as a session and waits
   up to 15 seconds for an actual image before reporting readiness. It prints
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
