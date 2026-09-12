# Configuration

## Sources of truth

MeshAgent's Windows package build consumes two independent inputs:

1. a branding JSON document for product identity, paths, signing policy,
   supported runtime options, and explicit hardcoded-lab network metadata;
2. a MeshCentral provisioning manifest (`.msh`) for server and mesh identity.

Local credentials and environment-specific identities must stay in ignored
files.

## Branding selection

`MeshAgent.Build.proj` and the project targets use this precedence:

1. the explicit MSBuild property `MeshAgentBrandingConfig`;
2. `branding_config.local.json` when it exists;
3. the checked-in `branding_config.json` fallback.

Start a local configuration with:

```powershell
Copy-Item .\branding_config.template.json .\branding_config.local.json
```

Replace every `REPLACE_WITH_*` placeholder before building. Do not commit the
local file, certificate paths, private keys, passwords, or production tokens.

The schema is `schema/meshagent.schema.json`. Major sections are:

| Section | Purpose |
|---|---|
| `branding` | Company/product names, service identity, install/log paths, and version resources |
| `network` | Lab-build network metadata; production connection authority remains the `.msh`/datastore |
| `artifacts` | Database, log, and configuration filenames |
| `security` | Certificate validation, signing enforcement, and signer allow-list |
| `provisioning` | Mesh name/type, mesh ID, server ID, URL, and install flags |
| `advanced` | Logging, keepalive, idle timeout, compression, and local power-action policy |
| compatibility sections | Windows service packaging options retained by the current project schema |

Only enable administrative behavior that is approved for the target
environment. Configuration cannot override consent, audit, or fail-closed
requirements.

## Provisioning manifest selection

The package orchestrator uses this precedence:

1. the explicit MSBuild property `MeshAgentProvisioningManifest`;
2. `WinDiagnosticHost.msh` when present;
3. `MeshAgent.msh` as the generic fallback.

The executable, sidecar `.msh`, database identity, service DLL, and embedded
DLL payload must belong to the same build/package set. Deployment validation
rejects mismatched package identities.

For `StealthLab` service EXEs, both direct project builds and the package
orchestrator copy the selected manifest to `$(TargetDir)$(TargetName).msh`.
A missing manifest fails the build before compilation. Every successful build
refreshes the sidecar, including when the selected manifest is older than an
existing sidecar. This prevents a previous deployment's endpoint from surviving
a rebuild. The shared manifest and branding URL must describe the intended
deployment; matching local files alone does not prove server admission.

MSBuild produces raw EXEs and sidecars; it does not append a group enrollment
policy to the EXE. MeshCentral appends that policy to group-specific downloads.
Use `--package-msh` for raw build validation and `--package-exe` for a downloaded
EXE containing a policy. Requested files that are missing or whose embedded
policy cannot be extracted fail the provisioning check.

## Windows installer elevation

Both `StealthLab` service EXEs embed `requestedExecutionLevel=requireAdministrator`
with `uiAccess=false`. Installation needs administrative service-manager and
installation-directory access. A normal non-elevated interactive launch uses
Windows consent/administrator credentials before either architecture starts;
cancellation leaves the installer unstarted. Already-elevated callers retain
their existing privileges. This is the standard Windows manifest boundary.

The Win32 project previously omitted this setting and inherited `asInvoker`.
Its lifecycle launcher inherits the caller's token, so a normal desktop launch
could reach protected staging/service operations and fail with error 5. The
x64 project already required administrator privileges. Check the manifest in
the actual downloaded EXE when diagnosing this distinction. An x64 access-denied
report still requires the failing operation and endpoint logs; it is not
explained by the Win32 manifest defect or by a MeshCentral certificate counter.

## Windows lifecycle manifest encoding and errors

Every lifecycle INI writer uses UTF-16LE with a BOM. `WritePrivateProfileStringW`
otherwise creates an ANSI file, even though its arguments are wide strings.
On an incompatible code page, a source path such as `OneDrive\桌面\agent.exe`
becomes `OneDrive\??\agent.exe`; the elevated host then fails package preflight.
The native writer initializes the BOM before writing fields. The JavaScript
installer (including its embedded copy), deployment helper, and test harnesses
use the same encoding. Existing ASCII manifests remain readable.

`MeshRundll32_LaunchLifecycleHostW` preserves API failures before logging and
cleanup. A completed child that fails returns `FALSE` with `GetLastError()==0`
and its actual status in `exitCodeOut`. The GUI therefore reports an install
failure with the child status instead of an unrelated last-error value from
cleanup. Genuine launch/write/wait failures retain their Windows error code.

## Native update transport

Native command 13 verifies `GenerateSHA384FileHash`: Windows EXEs normalize PE
checksum/signature fields and appended provisioning; ZIP files use their full
byte hash. Raw native transfers must end with MeshCentral's `agentExeInfo.hash`,
and compressed transfers with `zhash`. `fileHash` is the complete HTTP download
hash used by the JavaScript HTTP updater and cannot substitute for the native
EXE hash. The two download mechanisms have different verification contracts.

Capability `0x100` retains its existing compression meaning. Native streaming
ZIP updates additionally require `0x200`, advertised by the corrected decoder.
Older agents receive raw native updates so they can install that decoder.
The stream accepts exhausted-input `Z_BUF_ERROR` as needing more input, keeps
zlib status separate from output backpressure, and retains input ownership
until deferred output has resumed. Once updated, an agent can receive ZIP
updates again. Hash verification remains mandatory for both formats.

## Generated outputs

The build invokes `tools/generate_branding_assets.py` and related MSBuild
targets to produce generated headers/resources. Common generated outputs
include:

- `meshcore/generated/meshagent_branding.h`
- `meshcore/generated/network_profile.h`
- `build/meshagent/generated/network_profile.json`
- service version/resource inputs
- `meshservice/embedded/svchost_payload.dll`

The generated network profile header currently has no production include or
consumer. Network values in the branding header are guarded by
`MESH_PROVISIONING_HARDCODED`, which is not defined by the production project
configurations. Do not treat either generated file as a production connection
authority or edit it as a substitute for the `.msh` manifest.

To validate and regenerate the branding header explicitly:

```powershell
python .\tools\generate_branding_assets.py --repo-root . --config .\branding_config.local.json
```

Then run the normal MSBuild command so every consumer is refreshed in the
correct order.

## Network and proxy policy

Production reads `MeshServer` from the provisioning `.msh` into the datastore,
parses one configured URL, performs one OS resolution, and issues one request.
Keep a single URL in the deployment manifests unless a separately validated
contract requires otherwise. The branding JSON must mirror that URL for build
and package validation, but its fallback/SNI/Host fields are not an alternate
production route.

If a proxy is required, provide an explicit MeshCentral `WebProxy` value.
Ambient proxy discovery is not used by the active agent path; do not rely on
WPAD, per-user browser settings, or heuristic proxy fallback. Stock reconnect
handling remains part of MeshAgent and is not an endpoint-selection fallback.

## Deployment environment

`.env.template` is operator documentation and is separate from production
provisioning. Its endpoint value is not consumed by the current build or deploy
path. Copy it to an ignored `.env` only when a local wrapper explicitly consumes
it, and keep secrets out of shell history and source control.
