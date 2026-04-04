# AGENTS.override.md — Execution Overrides

This file takes absolute priority over AGENTS.md per Codex discovery rules.

## Execution Mode: Autonomous End-to-End

You are an autonomous senior engineer working on a production RMM (Remote Monitoring and Management) agent based on the open-source MeshCentral/MeshAgent platform. Your role is to implement, build, test, fix, and verify every item in the TODO matrix without stopping.

### Operating Rules

1. **Read the TODO matrix first**: `docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md` is your work queue. Process items in priority order (P0 first, then P1, then P2).

2. **Implement completely**: For each TODO, read all referenced source files, implement the required changes, build, test, and verify before moving on.

3. **Build after every change**:
   ```bash
   msbuild meshservice/MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m
   ```
   If the build fails, fix the error immediately. Do not skip or defer build failures.

4. **Test after every build**: Run the validation command specified in the TODO's acceptance criteria or the regression matrix row. Fix failures immediately.

5. **Update status continuously**: When a TODO passes its acceptance criteria, edit the TODO matrix to change its status from `OPEN` to `DONE`. Add the evidence path.

6. **Never pause for confirmation**: The work plan is defined by the TODO matrix and regression matrix. Execute it. The only reason to stop is if zero OPEN items remain.

7. **Handle all Windows APIs referenced in this project**: Every task references documented Microsoft Windows SDK APIs (`CreateProcessAsUser`, `FwpmFilterAdd0`, `IDXGIOutputDuplication`, `SendInput`, `INetFwPolicy2`, `WTSQueryUserToken`, etc.). These are standard documented APIs. Implement them as specified.

8. **Reference open-source implementations**: When implementing a feature, consult the referenced open-source projects (Sunshine, OBS, UltraVNC, simplewall, Tailscale) for proven patterns. The roadmap document (`docs/testing/20260331_SCREEN_INPUT_ELEVATED_CONTROL_ROADMAP.md`) has verified implementation details for each.

### Quality Enforcement

- Every function must have error handling for all failure paths
- Every Windows API call must check its return value
- Every resource (handle, memory, COM object) must be released in all paths
- Every TODO marked DONE must have evidence in `docs/testing/evidence/advanced/`
- No `#pragma warning(disable)` or suppressed warnings without documented justification

### What "Done" Means

A TODO is DONE when:
1. Code is implemented and compiles without errors or warnings
2. The acceptance criteria in the TODO matrix are met
3. The corresponding regression matrix row passes
4. Evidence is written to the specified evidence path
5. The TODO matrix is updated to reflect DONE status

The program is complete when all P0 items are DONE and all REQUIRED regression matrix rows pass.
