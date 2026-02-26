# UMH + MeshAgent + MeshCentral Integration Master Plan

## Objective
- Run MeshAgent and UserModeHook MasterService as a unified service deployment.
- Drive UMH control-server operations from MeshCentral console/UI through agent control pipeline.
- Enforce install/update/uninstall and control-pipe readiness gates in native regression.

## Control Path
1. MeshCentral Device Console UI builds UMH request command.
2. Agent console command `umhctl` validates and sends JSON to:
- `\\.\pipe\{95c1a2e0-f84e-4c8a-9c32}-control`
3. MasterService ControlServer executes operation and returns JSON response.
4. Agent console prints structured response to MeshCentral.

## Native Lifecycle Gates
- Install/update:
1. Stage `MasterService.exe` into install root.
2. Run `--install --silent --wait --timeout 120 --output json`.
3. Verify `AdvancedHookService` is `RUNNING`.
4. Probe control pipe with `{"op":"status"}` and require `"ok":true`.
- Uninstall:
1. Run `--quit --silent ...`.
2. Run `--uninstall --silent ...`.
3. Verify `AdvancedHookService` no longer exists.

## Runtime Inputs
- Optional source override:
- `--masterservice-source="C:\path\MasterService.exe"`
- Optional gate toggle:
- `--masterservice=0|1` (default `1`)

## End-to-End Regression Command Set
1. Build svchost payload:
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab_DLL /p:Platform=x64 /m`
2. Build standalone entrypoint:
- `msbuild meshservice\MeshService-2022.vcxproj /p:Configuration=StealthLab /p:Platform=x64 /m`
3. Run full regression:
- `meshservice\x64\StealthLab\MeshService-2022.exe -fullregression --masterservice-source="C:\Users\Workstation\Documents\GitHub\UserModeHook\bin\x64\MasterService.exe"`
4. Post-checks:
- `meshservice\x64\StealthLab\MeshService-2022.exe -validate-install`
- `meshservice\x64\StealthLab\MeshService-2022.exe -svchost-status`

## MeshCentral Console Validation
- Baseline status:
- `umhctl status`
- Enumerate candidates:
- `umhctl listProcesses`
- Direct JSON request:
- `umhctl --json "{\"op\":\"getPolicy\"}"`

## Evidence Requirements
- Capture:
- `docs/testing/native-install.log`
- `docs/testing/native-regression.log`
- `docs/testing/evidence/advanced/*`
- `C:\ProgramData\DiagnosticHost\logs\installer.log`
