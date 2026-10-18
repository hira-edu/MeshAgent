# Trackpad Mode Handover

> **Temporary document. Delete this file once the trackpad work (including
> P1b) is deployed to production.** It is a deliberate, short-lived exception
> to the AGENTS.md rule against status files in the repository. Current
> behaviour lives in `docs/CONFIGURATION.md`, `docs/DEPLOYMENT.md` and
> `docs/testing/README.md`. Validation reports go in `artifacts/validation/`,
> not in this file.

This is a Windows-RDP-style "mouse pointer" trackpad for the mobile remote
desktop viewer.

- Phases 1–5 and the server-side button release (P1a) are on `main` in both
  hira-edu/MeshAgent and hira-edu/MeshCentral.
- The agent-side button release (P1b) is on its own branch, waiting to be
  built and tested on Windows.
- The page flags default to off, so users see no change until a flag is
  turned on.
- None of this is deployed yet. The release coordinator has
  `AUTO_DEPLOY=false`.

## Where everything is

| Repo / ref | Commit | What it holds |
|---|---|---|
| MeshCentral `main` | `5646fea5` | 6 commits on `94f5d70d`:<br>• reproducible viewer min build<br>• gesture engine<br>• remote-pixel pointer API in `agent-desktop-0.0.2.js`<br>• controller and adapters<br>• `custom.js` loader<br>• multiplexer viewer-departure release (P1a) |
| MeshAgent `main` | `12553cb9` (plus this file) | 6 commits on `25401cb2`: tests for each phase, `test/package.json` (Playwright 1.63.0), `deploy.py` publish entries, docs |
| MeshAgent `trackpad/p1b-agent-release` | `c94bbf57` | P1b, one commit on top of `12553cb9`. **Not merged.** |
| Both repos: `trackpad/phase1-safety-net` … `phase5-loader`, `p1a-viewer-release` | — | The stack from before the rebase, pushed for history. `main` has rebased copies of these commits. **Do not merge these branches into `main`.** |
| MeshCentral `deps/meshcentral-1.2.6` | `471ff267` | The version bump branch. Only on the Mac, not pushed. On hold until 1.2.6 is published to npm. |

## What was built

- **Gesture engine** (`public/scripts/agent-desktop-trackpad-0.0.1.js` in
  MeshCentral).
  - DOM-free. Ported from Apache Guacamole's Touchpad/Touchscreen and
    Chromium's SwipePinchDetector.
  - Apache-2.0 and BSD-3 notices are in `THIRD_PARTY_NOTICES.txt` and in the
    file header.
  - Ships unminified so the licence header survives.
- **Viewer API** in `agent-desktop-0.0.2.js` and its rebuilt `-min`.
  - Adds `GetRemoteGeometry`, `SendRemotePointer`, `SendRemoteWheel`,
    `ReleaseAllPointerButtons`, `remoteScreenKnown`,
    `addStateListener`/`removeStateListener` and
    `window.MeshDesktopModuleObservers`.
  - Additive only: the existing mouse paths and their packet traces are
    unchanged.
- **Controller and adapters**: one shared controller
  (`agent-desktop-trackpad-controller-0.0.1.js`), plus one adapter for Modern
  UI (`-default3-0.0.1.js`), one for the classic mobile UI
  (`-mobile-0.0.1.js`) and one for the guest share page for phones
  (`-sharing-mobile-0.0.1.js`), which adds the trackpad button that page lacks,
  and one for the desktop guest share page iPadOS gets (`-sharing-0.0.1.js`),
  which adds a Trackpad checkbox beside Input.
  - A capture-phase touch listener on `#DeskParent` owns the touch, so the
    page's own handlers and compatibility clicks never run.
  - Buttons are released on: mode off, Input off, dialogs, a hidden page,
    blur, a screen change, a module switch and disconnect.
- **Loader** in `custom.js`, placed before the audio block. Each page has its
  own flag, and all four default to off.
- **P1a** (`meshdesktopmultiplex.js`):
  - When a viewer leaves, the multiplexer sends a button-up for each button
    that viewer held and no other viewer holds, at the viewer's last position.
  - The queue drains before the agent is closed.
- **P1b** (branch only): the Windows and Linux KVM masters track the buttons
  they injected and release them when the session ends. The physical button
  state is never read.
- **Docs**:
  - `docs/CONFIGURATION.md`: "Mobile trackpad mode" and "Viewer departure".
  - `docs/DEPLOYMENT.md`: the upgrade gate.
  - `docs/testing/README.md`: "Viewer pointer input".
- **Review**: Fable did an adversarial review of every phase. Every major
  finding was reproduced and fixed, and the tests were mutation-checked.

### Turning it on

- **Per browser:** add `?trackpadengine=on` (or `off` / `default`) to the
  page URL. This sets the localStorage key `meshTrackpadEngine.default3` or
  `meshTrackpadEngine.defaultMobile`.
- **As the default for a UI:** change that UI's entry in `DEFAULT_ON` in
  `custom.js`. That is Stage 2 of the rollout.

## Next on Windows: build and probe P1b

**Changed files:**

- `meshcore/KVM/kvm_pointer_release.h` (new tracker)
- `meshcore/KVM/Windows/kvm.c`
- `meshcore/KVM/Linux/linux_kvm.c`
- four tests
- two doc paragraphs

**What it does on Windows:**

- Tracking runs only after a successful bridge write.
- The release runs first in `kvm_cleanup`, and only over a live bridge in the
  Windows session that received the press.
- It skips buttons that another live viewer in the same session still holds.
- It stops at the first failed write.

**Steps:**

```powershell
git fetch origin
git checkout trackpad/p1b-agent-release
msbuild .\meshservice\MeshService-2022.vcxproj /p:Configuration=MeshServiceBundle /p:Platform=x64 /m
msbuild .\MeshAgent.Build.proj /m /nologo /verbosity:minimal
node test\kvm_pointer_release_contract.js
python test\kvm_pointer_release_native.py
python test\windows_kvm_pointer_release_native.py
python test\linux_kvm_pointer_release_native.py
```

- The Python harnesses need clang. Set `CC` if it isn't on PATH.
- Expect no new warnings in `kvm.c`.
- A MinGW syntax check on the Mac gave exactly the same diagnostics as the
  base: 8 MSVC-only errors and 14 warnings, all pre-existing.

### Probes on an approved test endpoint

| Scenario | Expected |
|---|---|
| Hold left (drag a window or select text), then kill the viewer tab or cut its network | The drag ends on the endpoint. Repeat with the right button. |
| Viewers A and B connected; A holds left; B leaves | Still held. When A then leaves, it is released. |
| Normal clicks, then close the session | No extra click. |
| A local user holds the physical button while the remote session ends | The local user's button is left alone. |
| Press in one Windows session, switch sessions (lock and unlock, or switch user), then end the viewer | Nothing is released into the new session. |
| `test/run_grouped_regression.js` (elevated, approved host) | Install, update and uninstall still pass. |

When everything passes, merge `trackpad/p1b-agent-release` into `main` with a
fast-forward or rebase. A push to `main` starts the release workflow, but
nothing deploys while `AUTO_DEPLOY` is `false`. If a probe fails, fix it on the
branch first.

## Everything still pending

1. **[Blocker] P1b Windows build, probes and grouped regression.** See above.
   This is gate G5. Until it passes, trackpad mode stays opt-in only, because
   production runs with `desktopmultiplex = true`.
2. **[Blocker] P1b Linux probe under X.**
   - `linux_kvm.c` writes the button-ups before it sends SIGTERM, then waits
     up to 250 ms for the slave to read them. It checks the pipe with
     `FIONREAD`.
   - The harness covers this with a real pipe, but it has never run against
     an X session.
3. **Merge P1b into `main`**, after both probes pass.
4. **Deploy to production.** Not done. Deploying is a separate, deliberate step
   while `AUTO_DEPLOY=false`. With the flags off, a deploy changes nothing users
   see. **Then delete this file.**
5. **Real-device testing and tuning.**
   - Devices:
     - iPhone Safari (iOS 18 and 26);
     - iPad with and without a trackpad;
     - an Android phone and tablet;
     - a Windows touchscreen laptop, which must stay on the direct path.
   - Cover both UIs and the guest share page on each device.
   - Check that the view pans after the pointer with the browser itself
     pinch-zoomed on iOS Safari; the browser tests cover only Chromium.
   - Check the arrow size against the remote pointer at fit, 1:1 and zoomed in.
   - Agents:
     - Windows 10/11 with a single monitor, multiple monitors, mixed DPI, and
       a monitor at negative coordinates;
     - Linux X11;
     - macOS.
   - Run with multiplexing on and off.
   - Settle the acceleration curve and the slow-precision floor, and choose
     between a 150 and a 250 ms release delay.
   - Record the measured values in the change description, not in the
     repository.
6. **Stage 1 opt-in soak, then Stage 2.**
   - Each adapter goes through this on its own.
   - Run a 14-day opt-in soak.
   - Move to default-on only with zero confirmed stuck buttons, zero desktop or
     direct-touch regressions, and no open device blockers.
   - Roll back by turning that adapter's flag off.
7. **MeshCentral 1.2.6 bump and re-pin.** When 1.2.6 is on npm, follow the
   `docs/DEPLOYMENT.md` upgrade gate:
   1. Run both coupling contracts.
   2. Review the upstream diff of the views' touch, trackpad, zoom and state
      code.
   3. Rerun the pointer baseline (`--print` re-pins it after review) and the
      browser suites.
   4. Then change the pin.

   The coupling tests currently pin 1.2.5.
8. **Small independent fixes.**
   - `tools/meshcentral_viewer_asset_parity.js` reports a failure when files
     differ only in CRLF line endings. Normalise line endings before hashing
     (P7).
   - Linux should reject combined or unknown button bytes (P2).
   - Optional: a negative wheel step is one unit off in `SendMouseMsg` (P4).
   - Two MeshCentral tests already failed before this work:
     `tests/desktop-audio-relay.test.js` expects 1.2.1, and
     `tests/native-runtime.test.js:660` also fails.
9. **v1.1 (deferred):**
   - remote cursor shapes (needs agent change P3);
   - right-button drag;
   - modifier-plus-gesture combinations;
   - pen handling;
   - pinch zoom on the classic and guest mobile pages (their zoom is a 1x / 0.5x
     button);
   - remembering trackpad mode between sessions.

## Known limitations

- Held keyboard keys are not released when a viewer leaves, in either P1a or
  P1b. Only mouse buttons are.
- If a remote user presses the same button again soon after, P1a's release can
  end that new press.
- When the agent drops, a leaving viewer still triggers an image-settings write
  to the closed agent. This happened before this work.
- Every click's button-up arrives late by `clickReleaseDelayMs`.
- The overlay is always an arrow. Agent-drawn and overlay cursors can both show.
- The classic mobile UI only offers trackpad mode in fullscreen, as upstream
  does, and has no pinch there. The guest share page for phones follows it.
- A pinch that switched Modern UI fit mode to native zoom stays in native zoom;
  "Scale to Fit" in the menu returns to fit mode. Upstream resets native zoom
  to 1:1 on any window resize or rotation (including the on-screen keyboard),
  on entering fullscreen and on a remote resolution change.
- iPadOS gets the classic desktop UI by default, which has no touch support.
  iPad users need Modern UI. iPad guests get the desktop share page, which now
  offers the Trackpad checkbox.

## Running the tests

Clone MeshAgent and MeshCentral side by side. The viewer tests read
`../MeshCentral` from the MeshAgent root.

One-time setup for the browser tests:

```bash
cd test
npm ci
npx playwright install chromium webkit
```

| Test (MeshAgent `test/`) | Covers | Size |
|---|---|---|
| `meshcentral_trackpad_engine_runtime.js` | Gesture table and the randomized property test | 40 + 100,000 runs |
| `meshcentral_desktop_remote_pointer_runtime.js` | Viewer API packets, on both the full and min assets | 50 |
| `meshcentral_trackpad_adapter_runtime.js` | All four adapters in Chromium and WebKit, including follow and arrow size | 112 |
| `meshcentral_trackpad_loader_runtime.js` | The `custom.js` loader and flags | 20 |
| `meshcentral_trackpad_default3_coupling_contract.js` | Upstream coupling, Modern UI | 40 checks |
| `meshcentral_trackpad_default_mobile_coupling_contract.js` | Upstream coupling, classic mobile | 37 checks |
| `meshcentral_trackpad_sharing_mobile_coupling_contract.js` | Upstream coupling, guest share for phones | 34 checks |
| `meshcentral_trackpad_sharing_coupling_contract.js` | Upstream coupling, guest share for desktop browsers and iPad | 31 checks |
| `meshcentral_desktop_pointer_baseline_runtime.js` | Packet traces of the unchanged mouse paths | 47 scenarios |
| `meshcentral_multiplex_button_release_runtime.js` | P1a. Run it with no arguments: the first argument is read as a source path. | 12 |
| `meshcentral_trackpad_licence_contract.js`, `meshcentral_viewer_min_build_contract.js`, `meshcentral_viewer_touch_harness_runtime.js`, `deploy_publish_paths_contract.js` | Licences, min-file rebuild, touch event order, deploy manifest | — |
| `kvm_pointer_release_*` (P1b branch only) | Tracker unit test, extracted Windows and Linux functions, wiring contract | 3 + 15 checks |

MeshCentral wrapper: `node --test tests/*.test.js` gives 142/145. The 2
failures already existed before this work.

## Rules

- Never commit `branding_config.local.json` or any generated credentials.
- The working plan, with records §12a–12i, is only on the Mac:
  `MeshAgent/.claude/worktrees/trackpad/TRACKPAD-PLAN.md`, outside both
  repositories.
- Once nobody needs the history, the pre-rebase `trackpad/*` branches can be
  deleted. `main` already has their content.
