const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const bridgePath = path.resolve('meshservice', 'stealth_svchost.c');
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const inputPath = path.resolve('meshcore', 'KVM', 'Windows', 'input.c');

    const bridge = fs.readFileSync(bridgePath, 'utf8');
    const processPipe = fs.readFileSync(processPipePath, 'utf8');
    const kvm = fs.readFileSync(kvmPath, 'utf8');
    const input = fs.readFileSync(inputPath, 'utf8');

    const checks = {
        kvmInvalidParameterFailFastIsBridgeScoped:
            bridge.includes('Stealth_SvchostIsKvmBridgeInvocation') &&
            bridge.includes('KvmSessionBridgeW') &&
            bridge.includes('RaiseFailFastException(NULL, NULL, 0)') &&
            bridge.includes('CRT invalid parameter in KvmSessionBridgeW; terminating helper for WER capture'),
        helperLogsTransportAndFirstPackets:
            bridge.includes('KvmSessionBridgeW transport attached after') &&
            bridge.includes('KvmSessionBridgeW first output packet after') &&
            bridge.includes('KvmSessionBridgeW first screen packet after') &&
            bridge.includes('firstOutputLogged') &&
            bridge.includes('firstScreenLogged'),
        processPipeValidatesReadWindowBeforeBufferArithmetic:
            processPipe.includes('ILibProcessPipe_ReadWindowIsValid') &&
            processPipe.includes('ILibProcessPipe_ReadWindowCanAppend') &&
            processPipe.includes('ILibProcessPipe_FailInvalidReadWindow') &&
            processPipe.includes('ReadExHandler.Append') &&
            processPipe.includes('ReadExHandler.Consumed') &&
            processPipe.includes('ReadExHandler.Compact') &&
            processPipe.includes('ScheduleRead'),
        processPipeFailsPipesInsteadOfCallingInvalidMemmove:
            processPipe.includes('ILibProcessPipe invalid read window') &&
            processPipe.includes('pipeObject->brokenPipeHandler(pipeObject)') &&
            processPipe.includes('ILibProcessPipe_FreePipe(pipeObject)'),
        processPipeMergesWideEnvironmentBlocksInBytes:
            processPipe.includes('mergedBytes = totalChars * sizeof(WCHAR)') &&
            processPipe.includes('remainingBytes = ILibMemory_Size(merged) - ((size_t)(writePtr - merged) * sizeof(WCHAR))') &&
            processPipe.includes('memcpy_s(writePtr, remainingBytes, current, copyLen * sizeof(WCHAR))') &&
            processPipe.includes('ILibMemory_Free(merged);') &&
            processPipe.includes('return NULL;'),
        kvmTelemetryUsesExistingActivityState:
            kvm.includes('bridge first input packet after') &&
            kvm.includes('bridge first output packet after') &&
            kvm.includes('bridge first screen packet after') &&
            kvm.includes('gKvmLastInputTickMs == 0') &&
            kvm.includes('gKvmLastOutputTickMs == 0') &&
            kvm.includes('gKvmLastScreenTickMs == 0'),
        kvmTelemetryWritesToModuleLocalDiagnosticLog:
            kvm.includes('GetModuleHandleExW') &&
            kvm.includes('GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS') &&
            kvm.includes('svchost-debug.log') &&
            kvm.includes('FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE'),
        kvmInputTelemetryClosesSendInputBlindSpot:
            kvm.includes('bridge input packet after') &&
            kvm.includes('KVM input packet: stage=') &&
            kvm.includes('KVM input loop: starting') &&
            input.includes('KVM input send: action=') &&
            input.includes('GetForegroundWindow') &&
            input.includes('foregroundPid=') &&
            input.includes('KVM_GetThreadDesktopName') &&
            input.includes('KVM_TraceStartupF'),
        kvmInputLoopCompactsPartialPackets:
            kvm.includes('memmove(pchRequest2, pchRequest2 + ptr') &&
            kvm.includes('len -= ptr') &&
            kvm.includes('KVM input loop: dropping full unconsumed buffer'),
        kvmLogsDisconnectAndChildExitReasons:
            kvm.includes('bridge child exit pid=') &&
            kvm.includes('ILibProcessPipe_Process_GetPID(sender)') &&
            kvm.includes('ctx->childPid') &&
            kvm.includes('exitCode=%d restartSuppressed=%d shutdown=%d restartCount=%d') &&
            kvm.includes('bridge disconnect cleanup requested'),
        svchostLogsBrandedProvisioningArtifacts:
            bridge.includes('executable sibling provisioning file') &&
            bridge.includes('configuration file %ls') &&
            bridge.includes('MeshService_GetBinaryNameText') &&
            bridge.includes('MeshService_GetConfigFileNameText')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({ bridgePath, processPipePath, kvmPath, checks }, null, 2) + '\n');
}

main();
