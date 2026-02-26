# Remote Desktop Always-Ready Master Plan

## Scope
This plan defines the production target for service-only remote desktop readiness with:
- Primary in-memory session startup path.
- `RAMAS` fallback path when primary session startup is degraded or unavailable.
- End-to-end validation and regression gates that block release on any readiness gap.

`RAMAS` in this document means `Resilient Agent Managed Alternate Session` (fallback session path).

## Non-Negotiable Outcomes
1. Remote desktop session path is always pre-initialized while service is running.
2. Service restart and update never leave the runtime without a working session path.
3. Any primary-path failure must auto-failover to `RAMAS` with deterministic recovery.
4. No silent degradation. Every failover, timeout, and recovery decision is logged and test-verifiable.

## Reliability Targets (SLO/SLI)
- `Readiness SLI`: time from service `RUNNING` to remote session ready.
- `Failover SLI`: time from primary failure detection to `RAMAS` availability.
- `Continuity SLI`: percentage of restart/update cycles that retain at least one ready session path.

Release targets:
- Readiness p95 <= 8s, p99 <= 15s.
- Failover p95 <= 3s, p99 <= 7s.
- Continuity >= 99.95% across stress cycles.
- Zero hangs in `restart`, `-fullupdate`, or session initialization.

## Architecture
### 1. Session Orchestrator (service process)
- Single authority state machine for session lifecycle.
- Owns path selection: `PRIMARY_INMEM` -> `RAMAS` fallback -> recovery back to primary.
- Enforces bounded timeouts and idempotent retries.

### 2. Primary In-Memory Path
- Session pipeline is initialized in-process with no runtime dependency on ad-hoc disk staging.
- Pre-warm channel and capability probes at service startup.
- Keep hot standby structures allocated while service remains `RUNNING`.

### 3. RAMAS Fallback Path
- Independent fallback startup flow with isolated error domain.
- Activated only when primary probe/startup crosses timeout or reports hard failure.
- Must support control continuity even under transport limits.
- Must auto-deactivate after confirmed primary recovery and hysteresis window.

### 4. Health and Policy Layer
- Health monitor tracks heartbeat, tunnel status, capability probes, and session liveness.
- Policy guardrails:
  - service-only enforcement,
  - deterministic spawn governance,
  - explicit log markers for denied/allowed transitions.

### 5. Recovery Manager
- Performs bounded restart of failed session path without restarting whole service.
- Escalation ladder:
  1. local session component reset,
  2. path switch to `RAMAS`,
  3. full service restart only if both paths fail.

## State Machine (Required)
1. `BOOTSTRAP`
2. `PRIMARY_WARMING`
3. `PRIMARY_READY`
4. `FAILOVER_ARMED`
5. `RAMAS_READY`
6. `RECOVERING_PRIMARY`
7. `DEGRADED_BLOCKED` (hard fault, release-blocking)

Required transitions:
- `PRIMARY_WARMING -> PRIMARY_READY` on successful probe.
- `PRIMARY_WARMING -> RAMAS_READY` on timeout/failure.
- `PRIMARY_READY -> RAMAS_READY` on runtime failure detection.
- `RAMAS_READY -> PRIMARY_READY` only after primary passes full readiness checks.

## Observability and Evidence
Every transition must emit:
- timestamp (UTC),
- state_from/state_to,
- reason_code,
- timeout_ms,
- operation_id,
- service_pid,
- channel/session identifiers.

Artifacts per run:
- `docs/testing/evidence/advanced/<timestamp>_<run_name>/commands.txt`
- `<run_name>.log` and `<run_name>.err`
- `summary.txt` with exit codes and key readiness metrics
- `C:\ProgramData\DiagnosticHost\logs\installer.log`

## End-to-End Test Program
### A. Mandatory Per-Change Validation
1. `-validate-install`
2. `-svchost-status`
3. `restart`
4. `--selfTest=1 --serviceName=WinDiagnosticHost --majorBug=1`

Pass conditions:
- restart exits 0,
- service PID changes when restart is requested,
- major-bug self-test exits 0 with KVM readiness reported.

### B. Full Regression Gate
Run `-fullregression` and require:
- install/update/uninstall validations all pass,
- network persistence remains active,
- service returns to expected final state per run plan.

### C. Session Continuity Gate
Run sequence:
1. install/validate/svchost status,
2. restart,
3. major-bug self-test,
4. update,
5. major-bug self-test,
6. uninstall/validate.

Block release if any step fails or if readiness exceeds SLO budgets.

### D. Stress and Chaos Gate
- Restart churn: >= 200 restart cycles.
- Update churn: >= 50 update cycles.
- Network fault injection during active sessions.
- Resource pressure (CPU/memory) while verifying failover latency.

Required outcome: no deadlocks, no hung control paths, no persistent readiness loss.

## Regression Matrix (Must Stay Green)
1. Fresh install + first-session readiness
2. Restart + readiness
3. Update + readiness
4. Post-update restart + readiness
5. Service crash recovery + readiness
6. Primary failure simulation -> `RAMAS` activation
7. Primary recovery -> fallback exit
8. Uninstall cleanup integrity

## Release Gates
Release is blocked unless all are true:
1. Full regression exit codes are all zero.
2. Major-bug session path exits zero in baseline and post-restart sequences.
3. Readiness/failover SLO targets are met in stress runs.
4. Evidence bundle is complete and reproducible.
5. No unresolved high-severity bugs in remote desktop/session state machine.

## Implementation Phases
1. Consolidate session state machine and timeout constants in native code.
2. Separate primary and `RAMAS` startup code paths with explicit interfaces.
3. Add structured readiness/failover telemetry fields to logs and summaries.
4. Extend native validation to assert state-machine transitions.
5. Add stress harness cases for restart/update churn and forced failover.
6. Add release-time gate checker for evidence completeness and SLO thresholds.

## Immediate Backlog (Execution Order)
1. Add readiness and failover counters to native validation output.
2. Add post-restart major-bug check to standard advanced regression sequence.
3. Add dedicated `RAMAS` failover simulation flag for deterministic testing.
4. Add 24h soak profile to `docs/testing/evidence/advanced/` artifact workflow.

