# Deployment Guide

The authoritative deployment runbook is
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). This root file is retained as a stable
entry point for operators and external links.

## Normal flow

```powershell
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
python .\deploy.py status
python .\deploy.py stage
python .\deploy.py deploy
python .\deploy.py health
```

`stage` is preparation. `deploy` replaces published files, creates a backup,
regenerates the MeshCentral hash manifest, and may restart the remote service;
obtain explicit approval before running it against a live host.

Rollback, remote directory layout, artifact renaming, signed-agent behavior,
MeshCentral server-code publication, MasterService publication, and health
targets are maintained only in the canonical runbook.

Related active contracts:

- [Release checklist](docs/files/meshagent_release_checklist.md)
- [UMH sister-repository SSOT](docs/UMH_CONTROL_SISTER_REPO_SSOT.md)
- [UMH deployment ledger](docs/UMH_CONTROL_DEPLOYMENT_LEDGER.md)
