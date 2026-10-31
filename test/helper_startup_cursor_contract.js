// Static contract: hidden helpers started on the user's desktop must not trigger the Windows
// "app starting" cursor. Without STARTF_FORCEOFFFEEDBACK, Windows shows the busy cursor for up to
// ~7 seconds per launch because these helpers never pump messages on their first GUI thread.
// KVM start launches the KVM bridge (through ILibProcessPipe) and may launch the clipboard and
// audio helpers, so the spinner stacked to 10-15 seconds.
//
// SCOPE/LIMITS: reads source text only. It does not build or run the helpers.
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

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

// The flag must be set on the startup struct before the matching CreateProcess call.
function flagSetBefore(source, flagLine, callText) {
    const flagIndex = source.indexOf(flagLine);
    const callIndex = source.indexOf(callText);
    return flagIndex >= 0 && callIndex >= 0 && flagIndex < callIndex;
}

function main() {
    const args = parseArgs(process.argv);
    const sources = {
        processPipe: read('microstack/ILibProcessPipe.c'),
        clipboardBridge: read('meshservice/clipboard_bridge.h'),
        audioBridge: read('meshservice/audio_bridge.h')
    };

    const checks = {
        processPipeSpawnDisablesStartupCursor:
            flagSetBefore(sources.processPipe, 'info.dwFlags |= STARTF_FORCEOFFFEEDBACK;',
                'createOk = CreateProcessAsUserW(userToken, tmp1, tmp2'),
        clipboardUserHelperDisablesStartupCursor:
            flagSetBefore(sources.clipboardBridge, 'startup.dwFlags = STARTF_FORCEOFFFEEDBACK;',
                'CreateProcessAsUserW(token, host, command'),
        audioUserHelperDisablesStartupCursor:
            flagSetBefore(sources.audioBridge, 'startup.dwFlags = STARTF_FORCEOFFFEEDBACK;',
                'CreateProcessAsUserW(token, host, command'),
        noForcedStartupCursor:
            !sources.processPipe.includes('STARTF_FORCEONFEEDBACK') &&
            !sources.clipboardBridge.includes('STARTF_FORCEONFEEDBACK') &&
            !sources.audioBridge.includes('STARTF_FORCEONFEEDBACK')
    };

    const report = { checks };
    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('helper startup cursor contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'helper_startup_cursor_contract.txt'),
            'SUCCESS=true\nCHECKS=' + Object.keys(checks).join(',') + '\n');
    }

    process.stdout.write('Helper startup cursor contract: user-session helper launches disable the busy cursor\n');
}

main();
