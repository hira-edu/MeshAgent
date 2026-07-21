# GitHub Actions

## Active workflows

| Workflow | Purpose |
|---|---|
| `.github/workflows/build-release.yml` | Windows StealthLab DLL/EXE build, artifact upload, optional runtime validation, optional deployment, and tagged release |
| `.github/workflows/codeql-analysis.yml` | JavaScript and C/C++ CodeQL analysis |

The workflow YAML is the source of truth for triggers, runner versions,
secrets, and individual steps.

## Build and release workflow

`Build and Release Custom MeshAgent` runs for pushes and pull requests to
`main`/`master`, version tags, and manual dispatch. Its Windows build order is:

1. restore the Visual Studio solution;
2. build `StealthLab_DLL|x64`;
3. stage the service DLL as the embedded payload;
4. build `StealthLab|x64` and `StealthLab|Win32`;
5. verify and upload the expected artifacts.

Published GitHub artifact names are:

- `StealthLab-MeshService64.exe`
- `StealthLab-MeshService.exe`
- `StealthLab-diagsvc.dll`

Reproduce the package locally with:

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
```

## Manual dispatch

From GitHub Actions, select `Build and Release Custom MeshAgent` and use **Run
workflow**. Runtime validation and deployment inputs are optional. Deployment
is a live, disruptive action: review the selected ref, target host, staged
hashes, secrets, and rollback availability before enabling it.

## Runtime validation

The optional runtime job uses `tools/Invoke-RuntimeValidation.ps1` and uploads
its report as `runtime-validation-results`. It requires a reachable authorized
MeshCentral test environment and the workflow inputs/secrets declared in
`build-release.yml`. Use a dedicated canary group; do not point CI lifecycle
tests at general production endpoints.

## Releases and deployment

Version tags create a GitHub release from the built artifacts. The workflow can
also publish to a configured MeshCentral host when the deployment condition and
credentials are present. The repository's authoritative server paths, backup,
rollback, and post-publish checks remain in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Use the GitHub CLI for inspection:

```powershell
gh run list --workflow build-release.yml
gh run view --log
gh run download --name StealthLab-MeshService64.exe
```
