# Documentation

This directory contains current operating and engineering references. Git
history and the issue tracker carry historical context; dated plans, work
queues, completed-project reports, and generated test evidence are not kept in
the documentation tree.

## Start here

| Subject | Document |
|---|---|
| System and component boundaries | [Architecture](Architecture.md) |
| Repository path map | [Repository layout](Files.md) |
| Branding and provisioning inputs | [Configuration](CONFIGURATION.md) |
| Build-to-server deployment, backup, rollback, and health | [Deployment SSOT](DEPLOYMENT.md) |
| Test suites and runtime artifact policy | [Testing](testing/README.md) |
| Release preparation | [Release checklist](files/meshagent_release_checklist.md) |
| Deep Windows diagnostics | [Advanced debug toolchain](testing/ADVANCED_DEBUG_TOOLCHAIN.md) |

## Cross-repository contracts

- [UMH control sister-repository SSOT](UMH_CONTROL_SISTER_REPO_SSOT.md)
- [UMH control deployment ledger](UMH_CONTROL_DEPLOYMENT_LEDGER.md)
- [UMH operator panel SSOT](testing/UMH_OPERATOR_PANEL_SSOT.md)

These files are retained because they define active ownership and deployment
contracts shared with MeshCentral and UserModeHook.

## Upstream technical references

- [Self-update behavior and test harness](testing/SelfUpdate.md)
- [Embedded JavaScript unit-test harness](testing/UnitTests.md)
- `files/ILib*.md` for selected Microstack APIs

When code changes, update the smallest authoritative document above. Avoid a
second README or status file that restates the same contract.
