# UMH + MeshAgent + MeshCentral Integration Master Plan

## Objective

- Keep UMH control-server operations reachable from MeshCentral console and UI through the agent control pipeline.
- Keep MeshAgent native install, update, uninstall, GUI buttons, and server auto-update aligned with upstream dynamic `.msh` behavior.
- Remove `MasterService.exe` from the native agent package shape and lifecycle gates.

## Control Path

1. MeshCentral Device Console UI builds a UMH request command.
2. Agent console command `umhctl` validates and sends JSON to `\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control`.
3. MasterService ControlServer executes the operation and returns JSON response.
4. Agent console prints the structured response back to MeshCentral.

## Lifecycle Authority Split

### MeshAgent native lifecycle

- `-fullinstall`
- `-fullupdate`
- `-fulluninstall`
- GUI install/update button
- GUI uninstall button
- server-driven MeshCentral auto-update

These flows manage only the downloaded agent payload and its dynamic sidecars:

- agent executable
- svchost DLL
- embedded or staged `.msh`
- `.conf`
- optional `.db`

Provisioning identity remains dynamic in all of these paths. MeshID, MeshServer, group identity, and related values are taken from the staged or embedded provisioning payload and are never hardcoded into the native lifecycle.

They do not:

- accept or require `--masterservice-source`
- accept or require `--masterservice=0|1`
- stage `MasterService.exe` beside the agent
- treat an external UMH install as an agent lifecycle failure

### UMH lifecycle

- install: `umhctl install --url "https://high.support/userfiles/hsadmin/MasterService.exe?download=1"`
- uninstall: `umhctl uninstall`
- status and control: `umhctl status`, `umhctl listProcesses`, `umhctl --json ...`

`MasterService.exe` is published separately for this operator path. It is not part of the MeshAgent package contract.

## Regression Focus

### Agent lifecycle regression

- dynamic `.msh` survives direct download, GUI install/update, and server auto-update
- launcher self-delete behavior remains intact after GUI install/update
- SCM delete-pending service objects are treated as busy until the service name and registry key are actually reusable
- no `MasterService.exe` sidecar is required or staged beside the agent
- stray legacy `MasterService.exe` files under the agent install root are cleaned without touching valid external UMH installs

### UMH operator regression

- `umhctl install --url ...` downloads and installs UMH from MeshCentral userfiles
- `umhctl uninstall` removes UMH through the operator path
- control-pipe commands keep working after install

## Evidence Requirements

- native lifecycle evidence under `docs/testing/evidence/advanced/`
- grouped regression artifacts
- stress and churn artifacts
- MeshCentral operator-path evidence for `umhctl`
