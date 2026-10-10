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
    source = source.replace(/\r\n/g, '\n');
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
    const stopWorkersBody = extractFunction(genericMarshal, 'int ILibDuktape_GenericMarshal_StopAsyncWorkers(duk_context *ctx)');
    const releaseBody = extractFunction(genericMarshal, 'static void ILibDuktape_GenericMarshal_AsyncData_Release(ILibDuktape_FFI_AsyncData *data, int fromWorker)');
    const startWorkerBody = extractFunction(genericMarshal, 'static void ILibDuktape_GenericMarshal_MethodInvokeAsync_StartWorker(duk_context *ctx, ILibDuktape_FFI_AsyncData *data)');
    const variableFinalizerBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_Variable_Finalizer(duk_context *ctx)');
    const proxyFinalizerBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_NativeProxy_Finalizer(duk_context *ctx)');
    const globalCallbackBody = extractFunction(genericMarshal, 'void* ILibDuktape_GlobalGenericCallback_Process(int numParms, ...)');
    const invokeAsyncBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync(duk_context *ctx)');
    const waitBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_wait(duk_context *ctx)');
    const scriptContainer = fs.readFileSync(path.resolve('microscript', 'ILibDuktape_ScriptContainer.c'), 'utf8');
    const engineFreeBody = extractFunction(scriptContainer, 'void ILibDuktape_ScriptContainer_Engine_free(void *udata, void *ptr)\n{');
    const engineReallocBody = extractFunction(scriptContainer, 'void *ILibDuktape_ScriptContainer_Engine_realloc(void *udata, void *ptr, duk_size_t size)');
    const trackedPromiseFinalizerBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvokeAsync_promfinTracked(duk_context *ctx)');
    const dispatcherDoneBody = extractFunction(genericMarshal, 'void ILibDuktape_GenericMarshal_MethodInvokeAsync_Done_chain(void *chain, void* u)');
    const sanityCheckBody = extractFunction(helpers, 'void __stdcall Duktape_RunOnEventLoop_SanityCheck(ULONG_PTR u)');
    const callbackExBody = extractFunction(genericMarshal, 'PTRSIZE ILibDuktape_GlobalGenericCallbackEx_Process(PTRSIZE arg1, int index, va_list args)');
    const threadSinkBody = extractFunction(genericMarshal, 'void ILibDuktape_GenericMarshal_MethodInvoke_ThreadSink(void *args)');
    const methodInvokeBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_MethodInvoke(duk_context *ctx)');
    const marshalFinalizerBody = extractFunction(genericMarshal, 'duk_ret_t ILibDuktape_GenericMarshal_Finalizer(duk_context *ctx)');
    const stopTimeoutMatch = genericMarshal.match(/#define ILibDuktape_GenericMarshal_AsyncStopTimeoutMS\s+(\d+)/);
    const stopWorkersIndex = destroyBody.indexOf('ILibDuktape_GenericMarshal_StopAsyncWorkers(ctx)');
    const heapFreeIndex = destroyBody.indexOf('duk_destroy_heap(ctx);');
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
        duktapeDestroyStopsWorkersBeforeFreeingHeap: stopWorkersIndex >= 0 && heapFreeIndex > stopWorkersIndex,
        duktapeDestroyPinsNativeMemoryForUnconfirmedWorkers: destroyBody.includes('ctxd->flags |= duk_native_memory_pinned;'),
        duktapeDestroyKeepsWorkerListWhilePinned: destroyBody.includes('if ((ctxd->flags & duk_native_memory_pinned) == 0) { ILibLinkedList_Destroy(ctxd->asyncWorkers); }'),
        stopWaitsForWorkersToUnregister: stopWorkersBody.includes('ILibDuktape_GenericMarshal_MethodInvokeAsync_RequestStop(') && stopWorkersBody.includes('ILibLinkedList_GetCount(ctxd->asyncWorkers)') && stopWorkersBody.includes('return(running == 0);'),
        stopRequestIsIdempotent: requestStopBody.includes('data->stopRequested == 0') && requestStopBody.includes('data->stopRequested = 1;'),
        shutdownWakesWindowFilteredMessageWaits: requestStopBody.includes('EnumThreadWindows(data->workerThreadId, ILibDuktape_GenericMarshal_PostQuitToWindow, 0);'),
        workerReleasesInsteadOfFreeing: workerBody.includes('ILibDuktape_GenericMarshal_AsyncData_Release(data, 1);') && !workerBody.includes('ILibMemory_Free(data);'),
        workerUnregistersUnderTrackerLock: releaseBody.indexOf('ILibLinkedList_Lock(data->tracker);') >= 0 && releaseBody.indexOf('ILibLinkedList_Remove(data->trackerNode);') > releaseBody.indexOf('ILibLinkedList_Lock(data->tracker);'),
        ownerPathsReleaseData: abortBody.includes('ILibDuktape_GenericMarshal_AsyncData_Release(data, 0);') && finalizerBody.includes('ILibDuktape_GenericMarshal_AsyncData_Release(data, 0);'),
        finalizerDoesNotJoinUnconfirmedWorker: finalizerBody.includes('duk_ctx_shutting_down(ctx) && !ILibDuktape_GenericMarshal_AsyncData_IsRunning(data)'),
        workerThatNeverStartedIsReleased: startWorkerBody.includes('if (data->workerThread == NULL)') && startWorkerBody.includes('ILibDuktape_GenericMarshal_AsyncData_Release(data, 1);'),
        stoppedWorkerRejectsNewWork: invokeAsyncBody.includes('if (data->stopRequested != 0) { return(ILibDuktape_Error(ctx, "Async worker has been stopped")); }'),
        shutdownRefusesNewWorkers: invokeAsyncBody.includes('Cannot start an async worker during shutdown') && waitBody.includes('Cannot start an async worker during shutdown'),
        pinnedVariablesAreNotFreed: variableFinalizerBody.includes('if (!ILibDuktape_GenericMarshal_NativeMemoryPinned(ctx)) { free(ptr); }'),
        pinnedModulesAreNotUnloaded: (proxyFinalizerBody.match(/!ILibDuktape_GenericMarshal_NativeMemoryPinned\(ctx\)/g) || []).length === 2,
        pinnedHeapBlocksAreKept: engineFreeBody.includes('duk_native_memory_pinned') && engineFreeBody.indexOf('return;') < engineFreeBody.indexOf('ILibMemory_Free(ptr);'),
        pinnedHeapBlocksStopLookingAlive: engineFreeBody.includes('ILibMemory_SecureZero(ILibMemory_RawPtr(ptr), sizeof(ILibMemory_Header));'),
        pinnedHeapBlocksAreNotMoved: engineReallocBody.includes('duk_native_memory_pinned') && engineReallocBody.includes('ILibDuktape_ScriptContainer_Engine_free(udata, ptr);'),
        asyncPromiseHoldsDataReference: invokeAsyncBody.includes('ILibDuktape_GenericMarshal_AsyncData_AddRef(data);') && invokeAsyncBody.includes('ILibDuktape_CreateFinalizer(ctx, ILibDuktape_GenericMarshal_MethodInvokeAsync_promfinTracked);'),
        asyncPromiseFinalizerReleasesReference: trackedPromiseFinalizerBody.includes('ILibDuktape_GenericMarshal_AsyncData_Release(data, 0);') && !trackedPromiseFinalizerBody.includes('ILibMemory_CanaryOK'),
        dispatcherDetachesPromiseBeforeFree: dispatcherDoneBody.indexOf('duk_del_prop_string(data->ctx, -1, "_data");') >= 0 && dispatcherDoneBody.indexOf('duk_del_prop_string(data->ctx, -1, "_data");') < dispatcherDoneBody.indexOf('ILibMemory_Free(data);'),
        dispatchNeverPushesCollectedPromise: dispatchBody.includes('if (data->promise == ILibDuktape_GenericMarshal_INVALID_PROMISE) { data->promise = NULL; return; }'),
        waitModeReturnsWithoutPromise: invokeAsyncBody.includes('if (data->promise == NULL) { return(0); }'),
        waitResetsAfterFailedCall: waitBody.includes('if (duk_pcall_method(ctx, 2) != 0)') && waitBody.includes('data->waitingForResult = 0;'),
        stopWaitFitsServiceStopHint: stopTimeoutMatch != null && Number(stopTimeoutMatch[1]) < 5000,
        stopWakesWindowsBeforeIdleWorker: requestStopBody.indexOf('EnumThreadWindows(') >= 0 && requestStopBody.indexOf('sem_post(&(data->workAvailable));') > requestStopBody.indexOf('EnumThreadWindows('),
        callbackExUsesNonceCheckedDispatch: callbackExBody.includes('Duktape_RunOnEventLoop(user->chain, ILibDuktape_GlobalGenericCallbackEx_nonce[index], target, ILibDuktape_GlobalGenericCallbackEx_Process_ChainEx, ILibDuktape_GlobalGenericCallback_ProcessEx_Abort, user);') && !callbackExBody.includes('ILibChain_RunOnMicrostackThread('),
        callbackExSkipsTornDownHeap: callbackExBody.includes('(targetData->flags & duk_destroy_heap_in_progress) == duk_destroy_heap_in_progress'),
        sanityCheckAbortsOnceAndSkipsFreeMarker: sanityCheckBody.includes('d->abortHandler = NULL;') && sanityCheckBody.includes('d->abortHandler != (Duktape_EventLoopDispatch)(uintptr_t)0x01'),
        asyncReferencesAreAtomic: releaseBody.includes('ILibDuktape_GenericMarshal_AtomicDecrement(&(data->refs)) == 0'),
        queuedDispatchHoldsReference: workerBody.includes('ILibDuktape_GenericMarshal_AsyncData_AddRef(data);') && workerBody.includes('ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatchRef, ILibDuktape_GenericMarshal_MethodInvokeAsync_ChainDispatchAbort, data);'),
        threadedInvokeIsWaitedFor: methodInvokeBody.includes('args[7] = ILibLinkedList_AddTail(args[6], NULL);') && threadSinkBody.lastIndexOf('ILibLinkedList_Remove(trackerNode);') > threadSinkBody.indexOf('Duktape_RunOnEventLoop('),
        rejectedArgumentReleasesCallSlot: invokeAsyncBody.includes('if (data->waitingForResult == 0) { data->promise = NULL; }'),
        teardownClearsExCallbackSlots: marshalFinalizerBody.includes('ILibDuktape_GlobalGenericCallbackEx_ctx[exIndex] = NULL;'),
        crossThreadCallbacksSkipTornDownHeap: globalCallbackBody.includes('if (crossThread && (targetData == NULL || (targetData->flags & duk_destroy_heap_in_progress) == duk_destroy_heap_in_progress))'),
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
