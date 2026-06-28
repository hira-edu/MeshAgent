const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const rundll32ContractPath = path.resolve('meshservice', 'rundll32_contract.h');
    const kvmRuntimeHelpersPath = path.resolve('test', 'lib', 'kvm_runtime_helpers.js');
    const processPipeSource = fs.readFileSync(processPipePath, 'utf8');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const rundll32ContractSource = fs.readFileSync(rundll32ContractPath, 'utf8');
    const kvmRuntimeHelpersSource = fs.readFileSync(kvmRuntimeHelpersPath, 'utf8');

    const checks = {
        policyAllowsBridgeEntryPoint: processPipeSource.includes('allow-kvm-bridge') &&
            processPipeSource.includes('MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A') &&
            rundll32ContractSource.includes('#define MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A     "KvmSessionBridgeW"') &&
            processPipeSource.includes('ILibProcessPipe_IsApprovedBridgeModuleArgumentA') &&
            processPipeSource.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[1], "_in")') &&
            processPipeSource.includes('ILibProcessPipe_IsApprovedBridgePipeNameA(parameters[2], "_out")') &&
            processPipeSource.includes('ILibProcessPipe_IsApprovedBridgeModeA(parameters[3])') &&
            !processPipeSource.includes('ILibProcessPipe_HasKvmBridgeEntryPointA') &&
            !processPipeSource.includes('ILibString_IndexOf(value, (int)strnlen_s(value, 4096), MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A'),
        policyDeniesInternalHelperReentry:
            !processPipeSource.includes('allow-helper-reentry') &&
            !processPipeSource.includes('ILibProcessPipe_IsApprovedInternalHelperLaunchA') &&
            !processPipeSource.includes('ILibProcessPipe_HasExactParameterA(parameters, "--slave")') &&
            !processPipeSource.includes('ILibProcessPipe_HasExactParameterA(parameters, "-b64exec")') &&
            processPipeSource.includes('blocked-windows-spawn') &&
            processPipeSource.includes('ILibProcessPipe_IsWindowsSpawnAllowed(spawnType, target, parameters)'),
        policyDoesNotAllowGenericUserSessionByEnv:
            !processPipeSource.includes('ILibProcessPipe_LogPolicyDecisionA("allow", "generic"') &&
            !processPipeSource.includes('strictServiceOnly == 0 || allowDesktopBridge != 0'),
        policyBlocksStandaloneAgentSelfSpawnInUserSessions:
            !processPipeSource.includes('allow-agent-self') &&
            !processPipeSource.includes('ILibProcessPipe_IsApprovedAgentSelfSpawnLaunchA') &&
            !processPipeSource.includes('MESHAGENT_SELF_SPAWN_PATH'),
        relayResolvesRundll32: kvmSource.includes('kvm_relay_resolve_rundll32_pathW'),
        relayResolvesBridgeDll: kvmSource.includes('kvm_relay_resolve_bridge_dll_pathW') &&
            !kvmSource.includes('STEALTH_KVM_BRIDGE_DLL') &&
            !serviceMainSource.includes('STEALTH_KVM_BRIDGE_DLL') &&
            !kvmRuntimeHelpersSource.includes('STEALTH_KVM_BRIDGE_DLL'),
        relaySpawnsRundll32First: kvmSource.includes('Spawning rundll32 KVM attempt=') && kvmSource.includes('rundll32PathA'),
        relayUsesNamedPipeBridgeTransport: kvmSource.includes('ILibProcessPipe_Manager_SpawnProcessEx5(') &&
            kvmSource.includes('&kvm_relay_bridge_pre_start_handler') &&
            kvmSource.includes('char* bridgeParms0[8] = { bridgeCommandArg, bridgeInputPipeNameA, bridgeOutputPipeNameA, "-kvm0", NULL, NULL, NULL, NULL };') &&
            kvmSource.includes('char* bridgeParms1[8] = { bridgeCommandArg, bridgeInputPipeNameA, bridgeOutputPipeNameA, "-kvm1", NULL, NULL, NULL, NULL };') &&
            kvmSource.includes('bridgeParms0[bridgeOptionalArgCount] = "-coredump";') &&
            kvmSource.includes('bridgeParms0[bridgeOptionalArgCount] = "-remotecursor";') &&
            !kvmSource.includes('bridgeParms0[3] = "-coredump";') &&
            kvmSource.includes('kvm_relay_build_bridge_pipe_namesW(bridgeInputPipeNameW') &&
            kvmSource.includes('kvm_relay_create_bridge_server_pipeW(bridgeInputPipeNameW, PIPE_ACCESS_OUTBOUND, &ctx->bridgeInputPipeHandle)') &&
            kvmSource.includes('kvm_relay_create_bridge_server_pipeW(bridgeOutputPipeNameW, PIPE_ACCESS_INBOUND, &ctx->bridgeOutputPipeHandle)') &&
            kvmSource.includes('kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeInputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange)') &&
            kvmSource.includes('kvm_relay_wait_for_bridge_client(ctx, ctx->bridgeOutputPipeHandle, KVM_BRIDGE_CONNECT_TIMEOUT_MS, restartSessionGeneration, &lastError, &connectAbortedBySessionChange)') &&
            kvmSource.includes('kvm_relay_attach_bridge_transport(ctx, ctx->bridgeInputPipeHandle, ctx->bridgeOutputPipeHandle)') &&
            kvmSource.includes('WriteFile(ctx->bridgeInputPipeHandle, buffer, (DWORD)bufferLen, NULL, &overlapped)') &&
            kvmSource.includes('transport=named-pipe input=%s output=%s') &&
            !kvmSource.includes('transport=stdio'),
        relayUsesUpstreamKvmSwitches: kvmSource.includes('"-kvm0"') &&
            kvmSource.includes('"-kvm1"') &&
            !kvmSource.includes('char * parms0[] = { " -kvm0"') &&
            !kvmSource.includes('char * parms1[] = { " -kvm1"'),
        relayPrefersBridgeByDefault: kvmSource.includes('static int kvm_should_prefer_bridge(char* exePath)') &&
            kvmSource.includes('return 1;'),
        relaySelectionIgnoresExePresence: !kvmSource.includes('kvm_legacy_helper_available('),
        relayDisablesLegacyFallbackByDefault: !kvmSource.includes('STEALTH_KVM_ALLOW_LEGACY_FALLBACK') &&
            !kvmSource.includes('Falling back to legacy self-exe KVM spawn') &&
            kvmSource.includes('rundll32 KVM path required; legacy self-exe fallback is disabled'),
        relayKeepsStdoutHandlerForRundll32Bridge: kvmSource.includes('&kvm_relay_StdOutHandler') &&
            !kvmSource.includes('InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0) ? NULL : &kvm_relay_StdOutHandler'),
        serviceMainRejectsDirectKvmExeModes: serviceMainSource.includes('direct KVM slave execution is disabled') &&
            serviceMainSource.includes('MeshService_IsRunningUnderRundll32()') &&
            serviceMainSource.includes('kvm_server_mainloop((void*)parm);'),
        serviceMainRejectsDirectHelperReentry: serviceMainSource.includes('MeshService_HasUnsupportedDirectScriptSwitch(argc, argv)') &&
            serviceMainSource.includes('direct -exec/-b64exec/--slave helper re-entry is disabled') &&
            serviceMainSource.includes('Use an approved rundll32 contract export') &&
            !serviceMainSource.includes('ILibBase64Decode((unsigned char *)argv[2]') &&
            !serviceMainSource.includes('ILibString_Copy(argv[2], 0)'),
        probesDoNotForceBridgePreference: !serviceMainSource.includes('SetEnvironmentVariableW(L"STEALTH_KVM_PREFER_BRIDGE", L"1");')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `selection contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            processPipePath,
            kvmPath,
            serviceMainPath,
            rundll32ContractPath,
            kvmRuntimeHelpersPath
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_bridge_selection_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
