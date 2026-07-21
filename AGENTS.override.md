# Repository Execution Guidance

This file takes priority over `AGENTS.md` for agent discovery.

## Authorization and safety

- Work only on systems the user owns or is explicitly authorized to manage.
- Preserve user consent, operator visibility, audit logging, and fail-closed
  checks for remote desktop, service lifecycle, updates, and command execution.
- Do not add hidden execution paths, credential collection, unauthorized
  persistence, security-control evasion, or behavior intended to impair
  third-party monitoring.
- Treat Windows service, firewall, desktop, input, and process APIs as
  documented administrative interfaces and keep their use scoped to the
  requested support behavior.
- Ask before reboot, shutdown, live endpoint replacement, destructive cleanup,
  service restart on a live host, or broad deployment.

## Execution rules

1. Inspect the relevant implementation and current SSOT before editing.
2. Complete the requested scope end to end; do not revive retired project plans
   or create a parallel status ledger.
3. After native code, resource, project, or generated-header changes, run:

   ```powershell
   msbuild .\meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m
   ```

4. Run the relevant tests from `test/`. Use the full package build when the
   change affects executable packaging, embedding, or both architectures.
5. Put generated validation output under an ignored path such as
   `artifacts/validation/<run>/`; do not commit logs, dumps, screenshots, or
   per-run reports.
6. Keep deployment details in `docs/DEPLOYMENT.md` and cross-repo UMH contract
   changes synchronized with the two sister-repository SSOT documents.

## Quality requirements

- Handle every failure path.
- Check every Windows API return value.
- Release handles, allocations, COM objects, and temporary resources on every
  exit path.
- Do not suppress warnings without a documented, narrowly scoped reason.
- Avoid behavior or documentation that claims validation not actually run.

Work is complete when the requested behavior is implemented, relevant builds
and tests pass, current documentation agrees with the code, and no required
live action remains implicit.
