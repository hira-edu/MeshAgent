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

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} not found`);
    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${signature} body start not found`);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        const ch = source[i];
        if (ch === '{') {
            depth += 1;
        } else if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`${signature} body end not found`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const genericMarshalPath = path.resolve('microscript', 'ILibDuktape_GenericMarshal.c');
    const helpersPath = path.resolve('microscript', 'ILibDuktape_Helpers.c');
    const genericMarshal = fs.readFileSync(genericMarshalPath, 'utf8');
    const helpers = fs.readFileSync(helpersPath, 'utf8');

    const workerBody = extractFunction(genericMarshal, 'void ILibDuktape_GenericMarshal_MethodInvokeAsync_WorkerRunLoop(void *arg)');
    const abortBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_abort(duk_context *ctx)');
    const finalizerBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_dataFinalizer(duk_context *ctx)');
    const dispatchBody = extractFunction(genericMarshal, 'void ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatch(void *chain, void *user)');
    const requestStopBody = extractFunction(genericMarshal, 'void ILibDuktape_GenericMarshal_MethodInvokeAsync_RequestStop(ILibDuktape_FFI_AsyncData *data)');
    const destroyBody = extractFunction(helpers, 'void Duktape_SafeDestroyHeap(duk_context *ctx)');
    const nativeCallIndex = workerBody.indexOf('ILibDuktape_GenericMarshal_MethodInvoke_Native');
    const postNativeAbortIndex = workerBody.indexOf('if (data->abort != 0)', nativeCallIndex);
    const dispatchIndex = workerBody.indexOf('Duktape_RunOnEventLoop', nativeCallIndex);

    const checks = {
        shutdownRequestsWakeIdleWorkers: requestStopBody.includes('data->abort = 1;') && requestStopBody.includes('sem_post(&(data->workAvailable));'),
        shutdownRequestsWakeWindowsMessageWaits: requestStopBody.includes('PostThreadMessageW(data->workerThreadId, WM_QUIT, 0, 0);'),
        promiseAbortSignalsWorker: abortBody.includes('ILibDuktape_GenericMarshal_MethodInvokeAsync_RequestStop(data);'),
        promiseFinalizerSignalsWorker: finalizerBody.includes('ILibDuktape_GenericMarshal_MethodInvokeAsync_RequestStop(data);'),
        shutdownTracksPromiseWorkerForJoin: finalizerBody.includes('ILibLinkedList_AddTail(duk_ctx_context_data(ctx)->threads, data->workerThread);'),
        workerDoesNotDispatchAfterAbort: nativeCallIndex >= 0 && postNativeAbortIndex > nativeCallIndex && dispatchIndex > postNativeAbortIndex,
        dispatchRejectsShutdownContext: dispatchBody.includes('duk_ctx_shutting_down(data->ctx)') && dispatchBody.includes('data->abort != 0') && dispatchBody.includes('return;'),
        shutdownDoesNotFreeNativeReturnPointer: !workerBody.includes('ILibMemory_Free(data->vars)') && !dispatchBody.includes('ILibMemory_Free(data->vars)'),
        dispatchDoesNotRaceWorkerFree: !dispatchBody.includes('ILibMemory_Free(data);'),
        duktapeDestroyJoinsRecordedThreads: destroyBody.includes('ILibThread_Join(thr);'),
        duktapeDestroyHasNoTimedThreadSkip: !destroyBody.includes('WaitForMultipleObjectsEx') && !destroyBody.includes('ILibThread_TimedJoinEx') && !destroyBody.includes('WAIT_TIMEOUT'),
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `GenericMarshal async shutdown contract failed: ${name}`);
    }

    const result = {
        success: true,
        genericMarshalPath,
        helpersPath,
        checks,
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'genericmarshal_async_shutdown_contract.json'), result);
    }
    console.log(JSON.stringify(result, null, 2));
}

main();
