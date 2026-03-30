# 2026-03-31 Realignment Guardrails

## Purpose

This document captures the non-negotiable implementation guardrails for the clean realignment branch. It turns external design guidance into concrete rules for the MeshAgent lifecycle, svchost service packaging, localhost relay transport, Session 1 remote-desktop bridge, and evidence model.

These guardrails apply to all code and test work on `realignment-origin-main`.

## External Design References

The following sources informed the rules below:

- Microsoft Learn: `Service host grouping in Windows 10`
- Microsoft Learn: `CreateServiceA function`
- Microsoft Learn: `Service User Accounts`
- Microsoft Learn: `Session Zero Guidelines for UMDF Drivers`
- Microsoft Learn: `User Accounts with Fast User Switching and Remote Desktop`
- Microsoft Learn: `WTSQueryUserToken function`
- Microsoft Learn: `Guidelines for Authoring Secure Installations`
- Microsoft Learn: `Administrator protection`
- OWASP Cheat Sheet Series: `Logging Cheat Sheet`

## Derived Rules

### Clean baseline and porting discipline

- New implementation work lands only on the clean branch created from `origin/main`.
- Archived drift refs and the preserved working branch are patch sources only.
- No broad cherry-picks are allowed from the preserved branch line.
- Every retained hunk must map to a ledger item, a TODO, and a regression gate.

### svchost installation and service registration

- The shipped Windows runtime remains svchost-only.
- Standalone agent execution remains blocked in the shipped service build.
- svchost registration must use a quoted local binary path and explicit local staging roots; remote-share service binaries are prohibited.
- Service account choice must be explicit and justified; privileged service context may exist only where required by the lifecycle engine or the trusted session broker boundary.
- Service registration, `ServiceDll`, failure actions, dependencies, and ACLs must be validated after install and update and validated absent after uninstall.

### Session 0, Session 1, and remote-desktop bridge

- Session 0 remains the authoritative runtime for lifecycle, policy, networking, and companion-service orchestration.
- Session 0 code may not depend on interactive UI or user input.
- Session crossing is allowed only through an explicit, service-owned desktop bridge for remote desktop readiness.
- The only approved Session 1 bridge shape is a narrowly scoped `rundll32` bridge owned by the service.
- PowerShell, terminal, file operations, installer/update logic, helper monitors, and arbitrary child-process launch may not use the Session 1 bridge.
- Service-to-bridge communication must use authenticated local IPC such as named pipes or RPC, with explicit session targeting, correlation IDs, and deterministic teardown.
- Token handling for session launch is a high-trust operation. Token acquisition, duplication, use, and release must be bounded, audited, and leak-free.

### Localhost relay transport

- Production connectivity follows `agent -> localhost relay -> configured server endpoint`.
- Staged provisioning remains the source of truth for upstream endpoint identity, `ServerID`, and trust/hash material.
- The localhost relay may not silently retarget traffic, weaken trust validation, or become a general-purpose proxy.
- The loopback listener and relay control plane must be ACL-restricted, explicitly logged, and validated for restart/update continuity.

### Elevation and privileged operations

- No ambient or persistent "full elevation mode" is allowed for arbitrary child processes.
- Privileged operations must be explicit, minimal, and auditable.
- If elevated execution is required, it must be scoped to the service or trusted broker boundary and not reused as a generic launch context.
- The implementation must prefer least privilege and just-in-time privileged transitions over always-elevated control paths.

### Capture, input, and protection boundaries

- Supported workflows may require capture to occur before application-managed protections or blackout behavior are applied.
- This contract does not authorize bypassing Windows security boundaries such as protected desktop, protected content, DRM-enforced restrictions, or OS security prompts.
- If a Windows security boundary blocks capture or input, the flow must fail explicitly, record the boundary and reason, and avoid any bypass attempt.
- Input injection or operator control may only occur through the approved remote-desktop path and may not be generalized into a bypass surface for unrelated protections.

### Installation hardening

- Package preflight must reject incomplete or untrusted packages before mutating system state.
- Signer validation and local staging integrity are mandatory before install or update activation.
- Install/update logic must fail securely when access is denied or prerequisites are missing.
- Installer logging may not leak credentials, secrets, or trust material.

### Logging and evidence

- Security logs, operational logs, and transaction/evidence logs must remain logically separated.
- Each security-relevant action must record actor, target, requested action, policy decision, outcome, error code, and correlation ID.
- Log transport or export over untrusted networks must use protected transport.
- Evidence must be sufficient to reconstruct lifecycle state transitions, session-bridge activation, relay decisions, and explicit protection-boundary failures.

## Prohibited Patterns

- Treating the preserved branch as the new baseline.
- Turning the Session 1 bridge into a generic launcher.
- Bypassing OS or DRM security boundaries for capture or input.
- Reusing privileged service context as a permanent operator shell.
- Using remote-share binaries or unquoted service paths for service installation.
- Logging secrets, passwords, or raw trust material.
- Silent fallback from trusted relay or trusted broker failures into weaker behavior.
