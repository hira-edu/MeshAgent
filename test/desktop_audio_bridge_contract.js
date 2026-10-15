// Static contract for the native desktop-audio loopback helper (MeshAudioBridgeW). It asserts
// the helper is registered on the same runtime-host surface as the clipboard bridge (export
// declaration, implementation include, both architecture .def files, entry-name constants), that
// ILibProcessPipe approves only the agent-reachable "local"/"tsid=" launch forms, that the wire
// framing constants in audio_bridge.h match AUDIO_SPEC sections 3 and 4, that the capture path is
// WASAPI shared-mode loopback with libopus, and that the owned files never spill audio to disk or
// logs. It also guards that the KVM/agentcore/meshdefines/ServiceMain surfaces are untouched.
//
// SCOPE/LIMITS: this reads source TEXT only. It does not compile the DLL, run the helper, or
// inspect the linked export table; an MSVC build and a Windows runtime probe
// (test/desktop_audio_bridge_runtime.js) are strictly stronger and cover what this cannot.
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

function main() {
    const args = parseArgs(process.argv);
    const sources = {
        audioBridge: read('meshservice/audio_bridge.h'),
        clipboardBridge: read('meshservice/clipboard_bridge.h'),
        runtimeHostContract: read('meshservice/runtime_host_contract.h'),
        runtimeHostContractImpl: read('meshservice/runtime_host_contract.c'),
        serviceHostDef: read('meshservice/MeshServiceHost.def'),
        serviceHostArm64Def: read('meshservice/MeshServiceHost_ARM64.def'),
        processPipe: read('microstack/ILibProcessPipe.c'),
        kvm: read('meshcore/KVM/Windows/kvm.c'),
        agentcore: read('meshcore/agentcore.c'),
        meshdefines: read('meshcore/meshdefines.h'),
        serviceMain: read('meshservice/ServiceMain.c')
    };

    const checks = {
        // --- Registration surface (mirrors the clipboard bridge). ---
        entryNameConstantsDefined:
            sources.runtimeHostContract.includes('#define MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_W   L"MeshAudioBridgeW"') &&
            sources.runtimeHostContract.includes('#define MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_A   "MeshAudioBridgeW"') &&
            sources.runtimeHostContract.includes('void CALLBACK MeshAudioBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow);'),
        implementationIncludesHeaderAndDispatches:
            sources.runtimeHostContractImpl.includes('#include "audio_bridge.h"') &&
            sources.runtimeHostContractImpl.includes('void CALLBACK MeshAudioBridgeW(HWND hwnd, HINSTANCE hinstDLL, LPWSTR lpCmdLine, int nCmdShow)') &&
            sources.runtimeHostContractImpl.includes('MeshRuntimeHost_GetEntryTailW(MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_W, lpCmdLine, tail, _countof(tail))') &&
            sources.runtimeHostContractImpl.includes('MeshAudio_Run(tail, module)'),
        // rundll32's hinstDLL is rundll32 itself; the broker must relaunch the DLL containing the export.
        brokerRelaunchesOwningDll:
            sources.runtimeHostContractImpl.includes('(LPCWSTR)&MeshAudioBridgeW, &module)') &&
            !sources.runtimeHostContractImpl.includes('MeshAudio_Run(tail, hinstDLL)'),
        exportedFromBothArchitectures:
            sources.serviceHostDef.includes('MeshAudioBridgeW') &&
            sources.serviceHostArm64Def.includes('MeshAudioBridgeW'),

        // --- ILibProcessPipe launch validator + consultation (mirrors the clipboard validator). ---
        launchValidatorPresent:
            sources.processPipe.includes('static int ILibProcessPipe_IsApprovedAudioBridgeLaunchA(char* target, char* const* parameters)') &&
            sources.processPipe.includes('MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_A') &&
            sources.processPipe.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_A)') &&
            sources.processPipe.includes('strcmp(parameters[1], "local") == 0') &&
            sources.processPipe.includes('strncmp(parameters[1], "tsid=", 5)') &&
            sources.processPipe.includes('ILibProcessPipe_SetBridgePolicyRejectReasonA("ok-audio")'),
        launchValidatorConsulted:
            sources.processPipe.includes('!ILibProcessPipe_IsUserSessionSpawnType(spawnType) && ILibProcessPipe_IsApprovedAudioBridgeLaunchA(target, parameters)') &&
            sources.processPipe.includes('allow-runtime-host-audio') &&
            sources.processPipe.includes('ILibProcessPipe_FormatRuntimeHostModuleEntryForCommandLineA(value, MESH_RUNTIME_HOST_ENTRY_AUDIO_BRIDGE_A, output, outputLen)'),

        // --- Command-line grammar is documented for the agent module (agent C) to match. ---
        commandLineGrammarDocumented:
            sources.audioBridge.includes('MeshAudioBridgeW local') &&
            sources.audioBridge.includes('MeshAudioBridgeW tsid=<sessionId>') &&
            sources.audioBridge.includes('MeshAudioBridgeW user <pipeName> <brokerPid> <sessionId>') &&
            sources.audioBridge.includes('\\\\.\\pipe\\MeshAudio_<brokerPid>'),

        // --- Packet framing constants match AUDIO_SPEC section 3. ---
        framingConstantsMatchSpec:
            sources.audioBridge.includes('#define MESH_AUDIO_VERSION              1') &&
            sources.audioBridge.includes('#define MESH_AUDIO_HEADER_SIZE          16') &&
            sources.audioBridge.includes('#define MESH_AUDIO_MAX_PAYLOAD          4096') &&
            sources.audioBridge.includes('#define MESH_AUDIO_TYPE_CONFIG          1') &&
            sources.audioBridge.includes('#define MESH_AUDIO_TYPE_AUDIO           2') &&
            sources.audioBridge.includes('#define MESH_AUDIO_TYPE_SILENCE         3') &&
            sources.audioBridge.includes('#define MESH_AUDIO_TYPE_STATUS          4') &&
            sources.audioBridge.includes('#define MESH_AUDIO_FLAG_DISCONTINUITY   0x0001') &&
            sources.audioBridge.includes('#define MESH_AUDIO_SAMPLE_RATE          48000') &&
            sources.audioBridge.includes('#define MESH_AUDIO_CHANNELS             2') &&
            sources.audioBridge.includes('#define MESH_AUDIO_FRAME_MS             20') &&
            sources.audioBridge.includes('#define MESH_AUDIO_FRAME_SAMPLES        960') &&
            sources.audioBridge.includes('#define MESH_AUDIO_BITRATE              64000') &&
            sources.audioBridge.includes('#define MESH_AUDIO_SILENCE_MS           250UL') &&
            sources.audioBridge.includes('#define MESH_AUDIO_CODEC_OPUS           1'),
        configPayloadMatchesSpec:
            sources.audioBridge.includes('MESH_AUDIO_CODEC_OPUS') &&
            sources.audioBridge.includes('MeshAudio_PutLE32(payload + 0, MESH_AUDIO_CODEC_OPUS)') &&
            sources.audioBridge.includes('MeshAudio_PutLE32(payload + 4, MESH_AUDIO_SAMPLE_RATE)') &&
            sources.audioBridge.includes('MeshAudio_PutLE16(payload + 8, MESH_AUDIO_CHANNELS)') &&
            sources.audioBridge.includes('MeshAudio_PutLE16(payload + 10, MESH_AUDIO_FRAME_MS)') &&
            sources.audioBridge.includes('MeshAudio_PutLE32(payload + 12, MESH_AUDIO_BITRATE)'),

        // --- Capture path: WASAPI shared-mode loopback, libopus, device-change re-init. ---
        wasapiLoopbackOpusCapture:
            sources.audioBridge.includes('#include <opus.h>') &&
            sources.audioBridge.includes('#include <mmdeviceapi.h>') &&
            sources.audioBridge.includes('#include <audioclient.h>') &&
            sources.audioBridge.includes('AUDCLNT_SHAREMODE_SHARED') &&
            sources.audioBridge.includes('AUDCLNT_STREAMFLAGS_LOOPBACK') &&
            sources.audioBridge.includes('AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM') &&
            sources.audioBridge.includes('eRender, eConsole') &&
            sources.audioBridge.includes('opus_encoder_create(MESH_AUDIO_SAMPLE_RATE, MESH_AUDIO_CHANNELS, OPUS_APPLICATION_RESTRICTED_LOWDELAY') &&
            sources.audioBridge.includes('OPUS_SET_BITRATE(MESH_AUDIO_BITRATE)') &&
            sources.audioBridge.includes('OPUS_SET_VBR(0)') &&
            sources.audioBridge.includes('IMMNotificationClientVtbl'),
        deviceChangeAndUnrecoverableHandling:
            sources.audioBridge.includes('OnDefaultDeviceChanged') &&
            sources.audioBridge.includes('AUDCLNT_E_DEVICE_INVALIDATED') &&
            sources.audioBridge.includes('MeshAudio_Reinit') &&
            sources.audioBridge.includes('MeshAudio_EmitStatus') &&
            sources.audioBridge.includes('MeshAudio_EmitSilence'),

        // --- Broker/user split with a kill-on-close job object (mirrors the clipboard broker). ---
        brokerUserSplitWithKillOnCloseJob:
            sources.audioBridge.includes('CreateProcessAsUserW(token, host, command') &&
            sources.audioBridge.includes('MeshProcessToken_Open(MeshProcessToken_SessionUser, sessionId, &token)') &&
            sources.audioBridge.includes('JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE') &&
            sources.audioBridge.includes('AssignProcessToJobObject(job, child.hProcess)') &&
            sources.audioBridge.includes('GetNamedPipeClientProcessId(pipe, &clientPid)') &&
            sources.audioBridge.includes('GetNamedPipeServerProcessId(pipe, &serverPid)'),
        exitsOnStdinEofAndBrokenStdout:
            sources.audioBridge.includes('MeshAudio_StdinWatch') &&
            sources.audioBridge.includes('ReadFile(input, scratch, sizeof(scratch), &read, NULL) || read == 0') &&
            sources.audioBridge.includes('return ERROR_BROKEN_PIPE;'),
        // The broker launches the capture child without inherited handles, so the child has no
        // stdin: watching it would read EOF at once and stop capture right after CONFIG.
        userChildDoesNotWatchMissingStdin:
            /static DWORD MeshAudio_User\([\s\S]*?\n\}/.test(sources.audioBridge) &&
            !/static DWORD MeshAudio_User\([\s\S]*?\n\}/.exec(sources.audioBridge)[0].includes('MeshAudio_StdinWatch'),
        // A child that writes STATUS and exits leaves those bytes in the pipe; the relay must read
        // until the broken pipe instead of quitting on child exit before the read.
        // A persistent GetBuffer / GetNextPacketSize failure must end capture with STATUS instead of
        // retrying immediately in a tight loop.
        captureFailuresEndWithStatus:
            !sources.audioBridge.includes('if (FAILED(IAudioCaptureClient_GetNextPacketSize(capture.capture, &packetFrames))) { break; }') &&
            sources.audioBridge.split('"audio-capture-failed"').length - 1 >= 2,
        relayDrainsBeforeChildExit:
            /static DWORD MeshAudio_Relay\([\s\S]*?\n\}/.test(sources.audioBridge) &&
            !/static DWORD MeshAudio_Relay\([\s\S]*?\n\}/.exec(sources.audioBridge)[0].includes('WaitForSingleObject(child, 0)'),

        // --- No audio content on disk or in logs. ---
        noAudioToDiskOrLog:
            sources.audioBridge.includes('no audio content is logged') &&
            !sources.audioBridge.includes('fopen') &&
            !sources.audioBridge.includes('_wfopen') &&
            !sources.audioBridge.includes('ServiceDeploy_LogInstallEvent') &&
            !/CreateFileW\([^)]*GENERIC_WRITE[^)]*CREATE/.test(sources.audioBridge),

        // --- Ownership guard: the spec forbids edits to these surfaces for the audio feature. ---
        protectedSurfacesUntouched:
            !sources.kvm.includes('MeshAudioBridgeW') && !sources.kvm.includes('audio_bridge') &&
            !sources.agentcore.includes('MeshAudioBridgeW') && !sources.agentcore.includes('audio_bridge') &&
            !sources.meshdefines.includes('MeshAudioBridgeW') &&
            !sources.serviceMain.includes('MeshAudioBridgeW') && !sources.serviceMain.includes('audio_bridge')
    };

    const report = { checks };
    for (const [name, passed] of Object.entries(checks)) {
        if (!passed) {
            process.stderr.write(JSON.stringify(report, null, 2) + '\n');
            throw new Error('desktop audio bridge contract failed: ' + name);
        }
    }

    if (args.evidence) {
        const evidenceDir = path.resolve(args.evidence);
        fs.mkdirSync(evidenceDir, { recursive: true });
        fs.writeFileSync(path.join(evidenceDir, 'desktop_audio_bridge_contract.txt'),
            'SUCCESS=true\nCHECKS=' + Object.keys(checks).join(',') + '\n');
    }

    process.stdout.write('Desktop audio bridge contract: registration, validator, framing and privacy checks passed\n');
}

main();
