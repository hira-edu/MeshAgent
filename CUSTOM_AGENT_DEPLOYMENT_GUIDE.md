# Custom Agent Publishing

Custom MeshAgent publishing is part of the canonical
[deployment runbook](docs/DEPLOYMENT.md). This file provides a stable root link
without duplicating server paths, hashes, or live-state claims.

The package build produces Visual Studio filenames; staging maps them to the
filenames MeshCentral serves:

| Build output | Published role |
|---|---|
| `meshservice/x64/StealthLab/MeshService-2022.exe` | `MeshService64.exe` |
| `meshservice/StealthLab/MeshService-2022.exe` | `MeshService.exe` |
| `meshservice/x64/StealthLab_DLL/MeshService-2022.dll` | service DLL and embedded-payload parity source |
| `WinDiagnosticHost.msh` and generated sidecars | provisioning identity |

Use `python deploy.py stage` to validate the complete package before upload.
Use `python deploy.py deploy` only after reviewing the target and backup plan,
then use `python deploy.py health` to verify the published bytes and service.

Do not manually mix executables, DLLs, databases, or `.msh` files from
different builds. The exact publish directories, backup layout, rollback
commands, and MeshCentral hash rules live in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
