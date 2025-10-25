# Core Migration â€“ Phase 2 Plan (Native Resource Embedding)

| Field | Value |
| --- | --- |
| **Owner** | Codex automation thread |
| **Last Updated** | 2025-10-26 |
| **Status** | 🚧 In progress (header embed + native loader landed; runtime/packaging tasks ongoing) |
| **Related Docs** | `CORE_MIGRATION_MASTER_PLAN.md` (Phase 2 section), `branding_build_overhaul.md` |

## 1. Objectives
1. Embed the svchost payload directly into MeshService via native headers so no `.rc`/RCDATA staging is required.
2. Provide deterministic hashing + signer metadata for the embedded payload and refuse to run if validation fails.
3. Remove PowerShell/RC dependencies from the build chain while keeping StealthLab/CI workflows green.
4. Update docs, tests, and packaging so operators know how to regenerate + verify the embedded payload.

### Success Criteria
- No `.rc` files reference `svchost_payload.dll`; MSBuild/MinGW builds do not require resource compilation to stage the DLL.
- `MeshSvchostPayload_*` helpers read from a generated header (or PE section) and enforce SHA-256 + signer checks before writing to disk.
- `test.ps1 -RuntimeValidation` exercises the native extraction codepaths (x64 mandatory, Win32 best-effort until compiler bug resolved).
- `build.ps1`/`build_all.ps1` automatically regenerate the payload header only when `MeshService-2022.dll` changes, and `build_complete.ps1` surfaces any validation failures.
- Packaging docs list the exact regeneration commands/operators must run after touching the svchost payload.

## 2. Workstreams & Tasks

### WS1 â€“ Tooling & Header Generation
1. **Finalize `tools/bin2h`** â€“ ensure it emits deterministic headers + metadata JSON (size, SHA256, generation timestamp). Add switch to skip emitting the byte array (for metadata-only consumers) but *default* to emitting the data array for Phase 2.
2. **Pipeline integration:** `build.ps1` should:
   - Rebuild `MeshService-2022.dll` (StealthLab_DLL) when requested.
   - Invoke `bin2h` to produce `meshcore/embedded/generated/svchost_payload.h` (or `payload_data.h`) containing:
     - `constexpr uint8_t g_SvchostPayload[]`
     - `constexpr size_t g_SvchostPayload_SIZE`
     - `constexpr char g_SvchostPayload_SHA256[]`
   - Emit metadata (`svchost_payload.json`) for provenance + signing audit.
3. **Cache invalidation:** Skip header regeneration when DLL timestamp/sha matches metadata. Provide `-ForcePayloadRefresh`/`-SkipPayloadEmbed` switches for CI + diagnostics.

### WS2 â€“ Runtime Extraction & Integrity
1. **Native loader module** (`meshservice/svchost_payload.c` or new `meshcore/embedded/payload_extract.cpp`):
   - Expose `MeshSvchostPayload_GetData`, `MeshSvchostPayload_WriteToPath`, and `MeshSvchostPayload_VerifyIntegrity` helpers.
   - Perform SHA-256 comparison against `g_SvchostPayload_SHA256` before writing to disk.
   - After writing, re-hash the written file + set hidden/system attributes.
   - (Stretch) Verify Authenticode signer thumbprint recorded in metadata before allowing install.
2. **Service integration:** `stealth_installer.c`, `stealth_init.c`, and `ServiceMain.c` should call the native helper instead of relying on staged files. Remove dead code paths that copied `meshservice/embedded/svchost_payload.dll`.
3. **Error reporting:** bubble rich error messages (context + Win32 code) into the installer logs and `Stealth_DebugLastErrorW` helpers.

### WS3 â€“ Build, Test, Packaging & Docs
1. **MSBuild cleanup:**
   - Delete `meshservice/bundle_resources.rc` and associated `.res` artifacts.
   - Remove `ResourceCompile` entries from `MeshService-2022.vcxproj`; add the generated header as a forced include where needed.
   - Ensure Win32/x64 targets both compile the new helper (watch for compiler C1001 on Win32; if blocking, gate with `#if !defined(_M_IX86)` until workaround is in place and document the limitation).
2. **Validation scripts:**
   - Extend `test.ps1` with `-RuntimeValidation` to call the new helper (drop + hash-check) and fail when SHA mismatch occurs.
   - Update `build_complete.ps1` and `tools/prepare_meshcentral_agent.ps1` to consume the metadata JSON instead of scanning `.res` files.
3. **Documentation updates:**
   - `DEPLOYMENT_GUIDE.md`: add â€œRegenerating Embedded Payloadsâ€ appendix with commands + verification steps.
   - `branding_build_overhaul.md`: reflect that Phase 2 became the active workstream (Phase 1 is complete) and link back to this plan.
   - `CORE_MIGRATION_MASTER_PLAN.md`: mark Phase 2 tasks as â€œin progressâ€ with references to the TODO table below.

## 3. Detailed TODO Board

| ID | Task | Artifact / Evidence | Status |
| --- | --- | --- | --- |
| P2-T01 | Harden `tools/bin2h` (byte array emission, metadata JSON, deterministic guard) | Updated `tools/bin2h/*.cpp`, README, metadata samples | ✅ Completed |
| P2-T02 | Wire `build.ps1` to regenerate `meshcore/embedded/generated/svchost_payload.h` & `.json` when DLL changes | `build.ps1`, `build_all.ps1`, `build_complete.ps1` diffs + CI log snippet | ✅ Completed |
| P2-T03 | Implement native loader (`meshservice/svchost_payload.h`) w/ SHA-256 verification | ServiceMain/installer diffs + runtime logs | ✅ Completed (thumbprint validation deferred) |
| P2-T04 | Delete RC resource pipeline + stop staging `meshservice/embedded/svchost_payload.dll` | Removed files, updated `.vcxproj`, clean build log | ✅ Completed |
| P2-T05 | Extend regression scripts (`test.ps1`, packaging helpers) to read metadata + run runtime validation | Script diffs + `test.ps1 -RuntimeValidation` output | 🚧 In progress (runtime suite added; CI gating TBD) |
| P2-T06 | Update docs (branding overhaul, deployment guide, master plan) to describe the new process & operator commands | Doc diffs + PR references | ✅ Completed (will evolve with runtime gating) |
| P2-T07 | MeshCentral packaging: ensure deliverables include payload metadata and signer hooks | Packaging log + sample manifest snippet | 🚧 In progress (metadata shipped via `svchost_payload.json`; signer hook TBD) |
| P2-T08 | Risk mitigation for Win32 compiler crash (document gating, optional fallback) | README note + tracker issue link | ⏳ Pending |

## 4. Execution Order & Checkpoints
1. **Tooling (T01)** â†’ validate locally with sample DLLs.
2. **Build orchestration (T02)** â†’ ensure StealthLab_DLL + bin2h flow works end-to-end; gate on x64 first.
3. **Runtime loader (T03)** â†’ unit-test via `stealth_init` lab command to drop payload to temp path.
4. **RC removal (T04)** â†’ once native loader passes tests, remove old files + clean up MSBuild targets.
5. **Automation & docs (T05-T07)** â†’ update test scripts, packaging, and documentation.
6. **Win32 health check (T08)** â†’ if compiler bug persists, document waiver + create follow-up issue.

Each checkpoint should end with `test.ps1 -RuntimeValidation` and `build_complete.ps1 -Configuration StealthLab -AllowNonAdmin` so CI parity is maintained.

## 5. Validation Plan
- `build.ps1 -Configuration StealthLab -SkipTests:$false` (x64) â€“ ensures embedder + loader coexist.
- `build.ps1 -Configuration StealthLab -Platforms Win32 -SkipTests` â€“ best-effort build; log known compiler crash if it persists.
- `test.ps1 -BinaryPath meshservice\x64\StealthLab -RuntimeValidation -ReportPath verification/phase2` â€“ proves runtime extraction works and SHA mismatches fail.
- `build_complete.ps1 -Configuration StealthLab -AllowNonAdmin -SkipTests:$false -RunHealthCheck` â€“ packages payload metadata + verification reports.
- (Optional) `tools/prepare_meshcentral_agent.ps1 -SkipBuild -OutputDir handoff/phase2-smoke` â€“ confirms packaging copies new metadata for MeshCentral uploads.

## 6. Dependencies & Risks
- **MSVC Win32 internal compiler error (C1001)** â€“ recurring when compiling massive payload arrays. Mitigation: prioritize x64 path, add build gate + documentation; investigate chunked headers/compression as stretch goal.
- **Signer validation** â€“ if Authenticode info must be validated, we may need access to signing cert data or allowlist; coordinate with ops before blocking builds.
- **CI artifacts** â€“ workflows must cache/regenerate payload headers deterministically; ensure `core-migration-baseline.yml` mirrors local script changes.
- **MeshCentral deployment** â€“ once payload is embedded, server-side scripts should no longer expect `svchost_payload.dll` to exist on disk; update those automation hooks in Phase 3.

## 7. Immediate Next Steps
1. Land this plan in the repo (docs) and update `branding_build_overhaul.md`/`CORE_MIGRATION_MASTER_PLAN.md` references (current task).
2. Start WS1 (T01/T02) to get the header generator + build flow in place.
3. Schedule a follow-up checkpoint to review the tooling changes before touching runtime code.

> **Reminder:** keep Phase 2 changes behind a short-lived feature flag (`MESH_AGENT_EMBEDDED_PAYLOAD_V2`) until both x64 build + runtime tests pass. This allows incremental merges without destabilizing release packaging.

