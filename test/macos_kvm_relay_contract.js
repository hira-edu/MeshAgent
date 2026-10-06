// Static contract: macOS remote desktop runs only through the Apple Screen Sharing relay.
//
//   agent (root LaunchDaemon) --stdin/stdout--> exePath -kvm0 (root) --RFB, 127.0.0.1:5900--> screensharingd
//
// Invariants:
//   1. No native capture, input or privacy-permission API remains in the macOS KVM or core
//      sources, so there is no second code path and nothing registers in Privacy & Security.
//   2. The agent starts one helper with its own credentials, for the login window and users alike;
//      there is no launchctl/asuser hop, no LoginWindow socket and no LaunchAgent for KVM.
//   3. The helper reads the credential, verifies root owns the port, then authenticates; it
//      wipes the password and connects to loopback only.
//   4. Installation no longer publishes the LoginWindow -kvm1 job but still removes an old one.
//
// This is a source-shape guard. test/macos_kvm_session_native.py and
// test/macos_vnc_relay_native.py exercise the behavior.
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

const root = path.resolve(__dirname, '..');
function read(relPath) { return fs.readFileSync(path.join(root, relPath), 'utf8'); }

// Returns the brace-matched body of the first function whose signature contains `marker`.
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

function macBlock(source, start, end) {
    const at = source.indexOf(start);
    return at < 0 ? null : source.substring(at, source.indexOf(end, at + start.length));
}

// Capture, input injection and TCC APIs that the relay replaces.
const NATIVE_DESKTOP_APIS = [
    'CGDisplayCreateImage', 'CGWindowListCreateImage', 'CGDisplayStream', 'SCStream', 'SCShareableContent',
    'CGEventPost', 'CGEventCreate', 'CGWarpMouseCursorPosition', 'IOHIDPostEvent', 'IOHIDUserDevice',
    'IOHIDSetModifierLockState', 'IOHIDGetModifierLockState',
    'CGPreflightScreenCaptureAccess', 'CGRequestScreenCaptureAccess', 'AXIsProcessTrusted', 'kAXTrustedCheckOptionPrompt',
    'TCCAccessRequest', 'LSOpenCFURLRef'
];
const REMOVED_FILES = [
    'meshcore/KVM/MacOS/mac_events.c', 'meshcore/KVM/MacOS/mac_events.h',
    'meshcore/KVM/MacOS/mac_hid.c', 'meshcore/KVM/MacOS/mac_hid.h',
    'meshcore/KVM/MacOS/mac_kvm_ipc.c', 'meshcore/KVM/MacOS/mac_kvm_ipc.h'
];

function main() {
    const args = parseArgs(process.argv);
    const scanned = ['meshcore/KVM/MacOS/mac_kvm.c', 'meshcore/KVM/MacOS/mac_kvm.h', 'meshcore/KVM/MacOS/mac_tile.c',
        'meshcore/KVM/MacOS/mac_tile.h', 'meshcore/KVM/MacOS/mac_vnc_relay.c', 'meshcore/agentcore.c', 'meshconsole/main.c'];
    const nativeHits = [];
    for (const rel of scanned) {
        const text = read(rel);
        for (const api of NATIVE_DESKTOP_APIS) { if (text.includes(api)) { nativeHits.push(rel + ':' + api); } }
    }

    const kvm = read('meshcore/KVM/MacOS/mac_kvm.c');
    const relay = read('meshcore/KVM/MacOS/mac_vnc_relay.c');
    const core = read('meshcore/agentcore.c');
    const consoleMain = read('meshconsole/main.c');
    const installer = read('modules/agent-installer.js');
    const makefile = read('makefile');

    const setup = functionBody(kvm, 'void* kvm_relay_setup(');
    const open = functionBody(kvm, 'static vnc_relay* MacKvm_OpenRelay(');
    const input = functionBody(kvm, 'int kvm_server_inputdata(');
    const mainloop = functionBody(kvm, 'void* kvm_server_mainloop(');
    const listener = functionBody(kvm, 'int MacKvm_RelayListener(');
    const coreApple = macBlock(core, '#elif defined(__APPLE__)\n\t// One root relay helper', '#else');
    const entry = macBlock(consoleMain, 'if (argc > 1 && strcasecmp(argv[1], "-kvm0") == 0)', '#endif');
    const install = functionBody(installer, 'function installService(params)');
    const uninstall = functionBody(installer, 'function uninstallService2(params, msh)');
    const sourcesLine = (makefile.match(/^MACOSKVMSOURCES = (.*)$/gm) || []).map(l => l.substring('MACOSKVMSOURCES = '.length).trim());

    const checks = {
        noNativeDesktopApi: nativeHits.length === 0,
        replacedSourcesRemoved: REMOVED_FILES.every(f => !fs.existsSync(path.join(root, f))),
        buildsOnlyRelaySources: sourcesLine.length > 0 && sourcesLine.every(l => l ===
            'meshcore/KVM/MacOS/mac_kvm.c meshcore/KVM/MacOS/mac_tile.c meshcore/KVM/MacOS/mac_vnc_relay.c meshcore/KVM/Linux/linux_compression.c'),

        // One helper, spawned directly with the agent's credentials and no session selection.
        setupSpawnsRootHelper: setup != null && setup.includes('char *args[] = { exePath, "-kvm0", NULL };') &&
            setup.includes('SpawnProcessEx3(processPipeMgr, exePath, args, ILibProcessPipe_SpawnTypes_DEFAULT, NULL, 0)'),
        noSessionHop: !kvm.includes('launchctl') && !kvm.includes('asuser') && !kvm.includes('setuid(') &&
            !kvm.includes('--session-uid') && !kvm.includes('KVM_Listener_Path') && !kvm.includes('AF_UNIX'),
        coreUsesHelperPipeOnly: coreApple != null &&
            coreApple.includes('ptrs->kvmPipe = kvm_relay_setup(agent->exePath, agent->pipeManager, ILibDuktape_MeshAgent_RemoteDesktop_KVM_WriteSink, ptrs);') &&
            !core.includes('KVM_IPC_SOCKET') && !core.includes('DomainIPC') && !core.includes('kvmDomainSocket'),
        entryPointsBounded: entry != null && entry.includes('if (argc != 2)') && entry.includes('kvm_server_mainloop(NULL)') &&
            /"-kvm1"\) == 0\)\s*\{[^}]*return 0;\s*\}/.test(entry) && !consoleMain.includes('MacKvm_InitializeSessionUser'),

        // Credential, then port ownership, then authentication; the password is wiped.
        openOrdered: open != null && open.indexOf('geteuid() != 0') >= 0 &&
            open.indexOf('geteuid() != 0') < open.indexOf('MacKvm_ReadRelaySecret(') &&
            open.indexOf('MacKvm_ReadRelaySecret(') < open.indexOf('MacKvm_RelayListener(') &&
            open.indexOf('MacKvm_RelayListener(') < open.indexOf('vnc_relay_open(') &&
            open.includes('case MAC_KVM_LISTENER_ROOT:') && open.includes('memset_s(password'),
        relayOpenedOnlyThroughCheck: (kvm.match(/vnc_relay_open\(/g) || []).length === 1 && mainloop != null &&
            mainloop.includes('MacKvm_OpenRelay(') && !mainloop.includes('vnc_relay_open('),
        listenerUsesProcessCredentials: listener != null && listener.includes('PROC_PIDTBSDINFO') &&
            listener.includes('owner.pbi_uid == 0 && owner.pbi_ruid == 0 && owner.pbi_svuid == 0') && !listener.includes('vst_uid'),
        secretRules: kvm.includes('O_NOFOLLOW') && kvm.includes('info.st_nlink != 1') && kvm.includes('S_IRWXG | S_IRWXO') &&
            kvm.includes('S_IWGRP | S_IWOTH') && kvm.includes('#define MAC_KVM_RELAY_SECRET\t\t"vncrelay.secret"'),
        relayLoopbackOnly: relay.includes('htonl(INADDR_LOOPBACK)') && !relay.includes('INADDR_ANY') && !relay.includes('getaddrinfo') &&
            !relay.includes('inet_pton'),

        // Input reaches the desktop only as RFB messages.
        inputOnlyThroughRelay: input != null && input.includes('vnc_relay_key(') && input.includes('vnc_relay_mouse(') &&
            !/\b(KeyAction|MouseAction|KeyActionUnicode)\(/.test(kvm),

        // Installation stops publishing the LoginWindow job; uninstall still removes an existing one.
        installerHasNoKvmLaunchAgent: install != null && !install.includes('installLaunchAgent') && !installer.includes("'-kvm1'"),
        uninstallRemovesLegacyAgent: uninstall != null && uninstall.includes("if (process.platform == 'darwin') { uninstallMacLaunchAgent(serviceName); }")
    };

    const report = { nativeHits, checks };
    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('macOS KVM relay contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'macos_kvm_relay_contract.json'), JSON.stringify(report, null, 2) + '\n');
    }
    process.stdout.write('PASS: macOS KVM is relay-only: no native desktop APIs, one root helper, ordered credential and port checks, loopback RFB, no KVM LaunchAgent\n');
}

main();
