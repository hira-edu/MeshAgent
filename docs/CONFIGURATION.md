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
