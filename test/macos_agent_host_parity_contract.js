// Static contract: the macOS agent mirrors the Windows two-host split.
//
//   Windows                         macOS
//   -------                         -----
//   svchost service (SYSTEM)   <->  LaunchDaemon in /Library/LaunchDaemons (root, no GUI)
//   rundll32 helper (session)  <->  per-session child spawned into the console user's Aqua session
//
// The two invariants the user asked for:
//   1. "Run-in-service doesn't ask for permissions": no macOS/agent source calls a *prompting*
//      TCC/permission API. Permission state is read with the SILENT preflight only; the daemon
//      never raises a system dialog. (kvm_check_permission, which prompted at startup, is gone.)
//   2. "Interactive session as rundll": desktop/KVM work is delegated to a child spawned INTO the
//      logged-in user's session (uid != 0). The root daemon (uid == 0) never captures directly.
//
// This is a source-shape guard, not proof of GUI-domain or permission behavior.
// Run the native session tests and a managed-host desktop smoke test as well.
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error('Unexpected argument: ' + token); }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) { args[key] = true; } else { args[key] = value; i += 1; }
    }
    return args;
}

function read(relPath) { return fs.readFileSync(path.resolve(relPath), 'utf8'); }

function count(haystack, needle) { return haystack.split(needle).length - 1; }

// Reads the body of the first function whose signature contains `marker` (brace-matched).
function functionBody(source, marker) {
    const at = source.indexOf(marker);
    if (at < 0) { return null; }
    let i = source.indexOf('{', at);
    if (i < 0) { return null; }
    let depth = 0;
    const start = i;
    for (; i < source.length; ++i) {
        if (source[i] === '{') { depth++; }
        else if (source[i] === '}') { depth--; if (depth === 0) { return source.substring(start, i + 1); } }
    }
    return null;
}

// APIs that raise a user-facing permission dialog (or open Settings). The daemon must never call
// these; use the silent preflight instead.
const PROMPTING_APIS = [
    'CGRequestScreenCaptureAccess',          // prompts for Screen Recording
    'kAXTrustedCheckOptionPrompt',           // AX trust check WITH prompt
    'LSOpenCFURLRef',                        // opening System Settings panes
    'LSOpenCFURLSpecRef',
    'TCCAccessRequest',
    'requestAuthorization'
];

function main() {
    const args = parseArgs(process.argv);

    const macSources = [
        'meshcore/KVM/MacOS/mac_kvm.c',
        'meshcore/KVM/MacOS/mac_events.c',
        'meshcore/KVM/MacOS/mac_tile.c',
        'meshcore/macos_update.c',
        'meshcore/agentcore.c'
    ].filter(p => fs.existsSync(path.resolve(p)));
    const macKvm = read('meshcore/KVM/MacOS/mac_kvm.c');
    const agentCore = read('meshcore/agentcore.c');
    const serviceManager = read('modules/service-manager.js');

    // Invariant 1: no prompting API anywhere, and no AXIsProcessTrustedWithOptions with a non-NULL
    // (prompting) options dictionary.
    const promptingHits = [];
    for (const rel of macSources) {
        const text = read(rel);
        for (const api of PROMPTING_APIS) { if (text.includes(api)) { promptingHits.push(rel + ':' + api); } }
        const axMatch = text.match(/AXIsProcessTrustedWithOptions\(\s*([^)]*)\)/);
        if (axMatch && axMatch[1].trim() !== 'NULL') { promptingHits.push(rel + ':AXIsProcessTrustedWithOptions(' + axMatch[1].trim() + ')'); }
    }

    const setupBody = functionBody(macKvm, 'kvm_relay_setup(char *exePath');
    const mainloopBody = functionBody(macKvm, 'kvm_server_mainloop(void* param');
    const canCaptureBody = functionBody(macKvm, 'MacKvm_CanCaptureScreen(void');
    // Tokens that cause macOS to register the binary in a Privacy & Security category.
    const TCC_TOKENS = ['CGPreflightScreenCaptureAccess', 'AXIsProcessTrustedWithOptions', 'CGDisplayCreateImage', 'CGEventPost', 'MacKvm_CanCaptureScreen'];

    const checks = {
        noPromptingPermissionApi: promptingHits.length === 0,
        // The permission read is the silent preflight.
        usesSilentScreenPreflight: macKvm.includes('CGPreflightScreenCaptureAccess'),
        usesSilentAccessibilityCheck: macKvm.includes('AXIsProcessTrustedWithOptions(NULL)'),
        // The prompting startup check must not come back.
        noStartupPermissionPrompt: !agentCore.includes('kvm_check_permission') && !macKvm.includes('kvm_check_permission'),
        // The root daemon does not capture the desktop directly...
        daemonDoesNotCaptureDirectly: setupBody != null && /if \(uid == 0\)\s*\{\s*return \(void\*\)KVM_Listener_Path;/.test(setupBody),
        // The root launcher enters the GUI context, then the same executable
        // establishes the user's credentials. Merely passing a UID to the
        // generic pipe spawn does not establish the macOS bootstrap context.
        interactiveDelegatedToSessionChild: setupBody != null &&
            setupBody.includes('"asuser"') && setupBody.includes('"--session-uid"') &&
            setupBody.includes('SpawnProcessEx3(processPipeMgr, "/bin/launchctl"'),
        helperVerifiesCredentials: macKvm.includes('MacKvm_InitializeSessionUser') &&
            macKvm.includes('initgroups(account.pw_name, account.pw_gid)') &&
            macKvm.includes('console.st_uid != uid'),
        // The installer keeps the LaunchDaemon (system) + Aqua session LaunchAgent split.
        launchDaemonHostPresent: serviceManager.includes("'/Library/LaunchDaemons'") || serviceManager.includes("'/Library/LaunchDaemons/'"),
        aquaSessionAgentSupported: serviceManager.includes("'Aqua'") && serviceManager.includes('/Library/LaunchAgents'),

        // --- No sticky/early TCC registration: the agent must touch capture/permission APIs ONLY
        // on demand, inside the session child's capture loop. A Mac that never runs remote desktop
        // then never gets listed in Privacy & Security (the entry is only ever created on real use).
        // The core/daemon translation unit never references any TCC-registering API.
        coreNeverTouchesTcc: TCC_TOKENS.every(t => !agentCore.includes(t)),
        // Session SETUP (reachable by the root daemon with uid==0) never captures or preflights.
        setupNeverTouchesTcc: setupBody != null &&
            ['CGDisplayCreateImage', 'CGPreflightScreenCaptureAccess', 'CGEventPost', 'MacKvm_CanCaptureScreen'].every(t => !setupBody.includes(t)),
        // Screen capture is confined to the capture loop (the on-demand child), nowhere else.
        captureConfinedToCaptureLoop: mainloopBody != null && count(macKvm, 'CGDisplayCreateImage(') === 1 && mainloopBody.includes('CGDisplayCreateImage('),
        // The silent screen preflight exists only inside MacKvm_CanCaptureScreen (not scattered / not proactive).
        preflightConfinedToCanCapture: canCaptureBody != null && count(macKvm, 'CGPreflightScreenCaptureAccess') === 1 && canCaptureBody.includes('CGPreflightScreenCaptureAccess'),
        // Permission is only ever checked while actively capturing: the single call site is the loop.
        permissionCheckedOnlyWhileCapturing: mainloopBody != null && mainloopBody.includes('MacKvm_CanCaptureScreen()') && count(macKvm, 'MacKvm_CanCaptureScreen(') === 2
    };

    const report = { promptingHits, checks };
    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('macOS agent host parity contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'macos_agent_host_parity_contract.txt'),
            'SUCCESS=true\nSCANNED=' + macSources.join(',') + '\nPROMPTING_HITS=' + promptingHits.join(',') + '\n');
    }

    process.stdout.write('macOS host source guard: silent checks, explicit GUI launcher, credential checks, daemon/Aqua-agent declarations present\n');
}

main();
