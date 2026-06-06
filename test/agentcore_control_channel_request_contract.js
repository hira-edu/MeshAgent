const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractSpan(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    if (start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span: ${startMarker}`);
    }
    return source.slice(start, end);
}

function extractSpanAfter(source, afterMarker, startMarker, endMarker) {
    const after = source.indexOf(afterMarker);
    const start = after >= 0 ? source.indexOf(startMarker, after) : -1;
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    if (after < 0 || start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span after: ${afterMarker}`);
    }
    return source.slice(start, end);
}

function main() {
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const processPipePath = path.resolve('microstack', 'ILibProcessPipe.c');
    const agentcore = fs.readFileSync(agentcorePath, 'utf8');
    const processPipe = fs.readFileSync(processPipePath, 'utf8');

    const stateType = extractSpan(
        agentcore,
        'typedef struct MeshServer_ControlChannelRequestState',
        'typedef struct RemoteDesktop_Ptrs'
    );
    const markComplete = extractSpan(
        agentcore,
        'static void MeshServer_ControlChannelRequest_MarkConnectComplete',
        'static void MeshServer_ControlChannelRequest_Finalize'
    );
    const finalize = extractSpan(
        agentcore,
        'static void MeshServer_ControlChannelRequest_Finalize',
        'void MeshServer_OnResponse'
    );
    const pongTimeout = extractSpan(
        agentcore,
        'void MeshServer_ControlChannel_IdleTimeout_PongTimeout',
        'void MeshServer_ControlChannel_IdleTimeout('
    );
    const onResponse = extractSpan(
        agentcore,
        'void MeshServer_OnResponse',
        'void MeshServer_ConnectEx_NetworkError'
    );
    const networkError = extractSpan(
        agentcore,
        'void MeshServer_ConnectEx_NetworkError',
        'void MeshServer_ConnectEx_Lockout_Retry'
    );
    const connectEx = extractSpan(
        agentcore,
        'void MeshServer_ConnectEx(MeshAgentHostContainer *agent)',
        'void MeshServer_DbWarning'
    );
    const agentMode = extractSpanAfter(
        agentcore,
        'void MeshAgent_AgentMode_Core_ServerTimeout',
        'int MeshAgent_AgentMode(MeshAgentHostContainer *agentHost, int paramLen, char **param, int parseCommands)',
        'int MeshAgent_Start('
    );

    const checks = {
        requestStateCarriesRequestAndWebSocketLifetime:
            stateType.includes('ILibWebClient_RequestToken requestToken;') &&
            stateType.includes('ILibWebClient_StateObject webStateObject;') &&
            stateType.includes('int established;') &&
            stateType.includes('int timeoutFired;') &&
            stateType.includes('int finalized;'),
        connectTimerRemovalNoLongerDestroysTracker:
            markComplete.includes('agent->controlChannelRequest = NULL;') &&
            markComplete.includes('ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), requestState);') &&
            !markComplete.includes('ILibMemory_Free('),
        finalizeIsSingleOwnerOfTrackerFree:
            finalize.includes('requestState->finalized = 1;') &&
            finalize.includes('ILibMemory_Free(requestState);'),
        onResponseDoesNotFreeControlChannelRequestDirectly:
            !onResponse.includes('ILibMemory_Free(agent->controlChannelRequest)') &&
            !onResponse.includes('ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), agent->controlChannelRequest)'),
        staleTimedOutConnectCompletionCannotResetNewChannel:
            onResponse.includes('requestState->timeoutFired != 0 && requestState->established == 0') &&
            onResponse.includes('stale timed-out connect completion ignored') &&
            onResponse.includes('MeshServer_ControlChannelRequest_Finalize(agent, requestState);') &&
            onResponse.indexOf('stale timed-out connect completion ignored') < onResponse.indexOf('switch (recvStatus)'),
        requestOwnershipCapturedBeforeTimerRemoval:
            onResponse.indexOf('int isTrackedControlChannelRequest = (requestState != NULL && agent->controlChannelRequest == requestState);') <
            onResponse.indexOf('MeshServer_ControlChannelRequest_MarkConnectComplete(agent, requestState);'),
        disconnectOnlyResetsAuthoritativeWebSocket:
            onResponse.includes('int isActiveControlChannel = (agent->controlChannel == WebStateObject);') &&
            onResponse.includes('int isTrackedControlChannelRequest = (requestState != NULL && agent->controlChannelRequest == requestState);') &&
            onResponse.includes('int isPreClearedEstablishedChannel = (agent->controlChannel == NULL && agent->controlChannelRequest == NULL && requestState != NULL && requestState->established != 0 && requestState->webStateObject == WebStateObject);') &&
            onResponse.includes('int isAuthoritativeDisconnect = (isActiveControlChannel != 0 || isTrackedControlChannelRequest != 0 || isPreClearedEstablishedChannel != 0);') &&
            onResponse.includes('if (isAuthoritativeDisconnect != 0') &&
            onResponse.includes('agent->controlChannel = NULL;') &&
            onResponse.includes('stale disconnect ignored'),
        connectionEstablishedClearsPriorPongTimer:
            onResponse.includes('ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));') &&
            onResponse.indexOf('ILibLifeTime_Remove(ILibGetBaseTimer(agent->chain), Agent2PingData(agent));') <
                onResponse.indexOf('agent->controlChannel = WebStateObject;'),
        headerlessCurrentRequestResetsStateBeforeRetry:
            onResponse.includes('if (isTrackedControlChannelRequest != 0 || agent->controlChannel == WebStateObject || (agent->controlChannel == NULL && agent->controlChannelRequest == NULL && requestState != NULL && requestState->established != 0 && requestState->webStateObject == WebStateObject))') &&
            onResponse.includes('MeshServer_OnResponse: header=NULL reset serverConnectionState to 0 before retry') &&
            onResponse.indexOf('agent->serverConnectionState = 0;') < onResponse.indexOf('MeshServer_Connect(agent);'),
        pongTimeoutResetsStateBeforeReconnect:
            pongTimeout.includes('timedOutChannel = agent->controlChannel;') &&
            pongTimeout.includes('if (timedOutChannel == NULL || agent->serverConnectionState != 2)') &&
            pongTimeout.includes('agent->serverConnectionState = 0;') &&
            pongTimeout.includes('ILibWebClient_Disconnect(timedOutChannel);') &&
            pongTimeout.includes('MeshServer_Connect(agent);') &&
            pongTimeout.indexOf('agent->serverConnectionState = 0;') < pongTimeout.indexOf('MeshServer_Connect(agent);'),
        timeoutCancelsWithoutFreeingStateBeforeCancelResponse:
            networkError.includes('requestState->timeoutFired = 1;') &&
            networkError.includes('agent->controlChannelRequest = NULL;') &&
            networkError.includes('ILibWebClient_CancelRequest(request);') &&
            !networkError.includes('ILibMemory_Free(j)') &&
            !networkError.includes('ILibMemory_Free(requestState);'),
        pipelinePassesRequestStateAsResponseUserData:
            connectEx.includes('MeshServer_ControlChannelRequestState *requestState') &&
            connectEx.includes('agent->controlChannelRequest = requestState;') &&
            connectEx.includes('MeshServer_OnResponse, agent, requestState') &&
            connectEx.includes('ILibLifeTime_Add(ILibGetBaseTimer(agent->chain), requestState, 60, MeshServer_ConnectEx_NetworkError, NULL);'),
        serviceNamesRemainHeapOwned:
            agentMode.includes('ILibMemory_Free(agentHost->meshServiceName); agentHost->meshServiceName = NULL;') &&
            agentMode.includes('agentHost->displayName = ILibString_Copy("MeshCentral", 0);'),
        stderrMetadataAssignedToStderrPipe:
            processPipe.includes('if (j->stdErr->metadata == NULL) { j->stdErr->metadata = "process_handle_stderr"; }')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({
        success: true,
        agentcorePath,
        processPipePath,
        checks
    }, null, 2) + '\n');
}

main();
