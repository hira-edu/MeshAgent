#!/usr/bin/env python3
"""Run the production pong-timeout handler against a scripted clock and socket.

A missed pong disconnects at once unless the timer itself fired more than
CONTROLCHANNEL_PONG_STALL_SLACK_MS late (the event thread was stalled). Then it
re-pings exactly once. Recent or buffered input extends the deadline instead.
The failure log reports how many re-pings were spent (pongProbes).
"""
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def extract(source, name):
    match = re.search(r"(?m)^[^\n;]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source)
    if not match:
        raise AssertionError("Missing production function: " + name)
    depth = 1
    for token in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[match.end():]):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():match.end() + token.end()]
    raise AssertionError("Unclosed function: " + name)


def define(source, name):
    match = re.search(r"(?m)^#define " + name + r"\s+(\d+)\s*$", source)
    if not match:
        raise AssertionError("Missing production constant: " + name)
    return "#define %s %s\n" % (name, match.group(1))


PRELUDE = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef void *ILibWebClient_StateObject;
typedef struct MeshAgentHostContainer {
    void *chain;
    ILibWebClient_StateObject controlChannel;
    int controlChannelDebug, serverConnectionState, serverAuthState, controlChannel_pongGraceUsed;
    long long controlChannel_pingSentTick, controlChannel_lastDataTick;
} MeshAgentHostContainer;
#define Agent2PingData(ptr) ((void*)((char*)(ptr)+1))
#define PingData2Agent(data) ((MeshAgentHostContainer*)((char*)(data)-1))
#define MeshAgent_ControlChannelDebugLog(...) ((void)0)
#define ILIBLOGMESSAGEX(...) ((void)0)
#define ILibRemoteLogging_printf(...) ((void)0)
#define ILibChainGetLogger(chain) NULL
#define ILibGetBaseTimer(chain) (chain)
static long long now;
static int pendingInput, pingResult, pings, timers, removals, disconnects, reconnects, failures, failureProbes;
static long long ILibGetUptime(void) { return now; }
static int ILibWebClient_GetDescriptorValue_FromStateObject(ILibWebClient_StateObject s) { (void)s; return 7; }
static int MeshServer_ControlChannel_HasPendingInput(ILibWebClient_StateObject s) { (void)s; return pendingInput; }
static void ILibLifeTime_Add(void *timer, void *data, int seconds, void (*callback)(void*), void *destroy) { (void)timer; (void)data; (void)seconds; (void)callback; (void)destroy; ++timers; }
static void ILibLifeTime_Remove(void *timer, void *data) { (void)timer; (void)data; ++removals; }
static int ILibWebClient_WebSocket_Ping(ILibWebClient_StateObject s) { (void)s; ++pings; return pingResult; }
static void MeshAgent_ControlChannelFailureLog(MeshAgentHostContainer *agent, ILibWebClient_StateObject channel, const char *reason, int interrupt, int status) {
    (void)channel; (void)interrupt; assert(strcmp(reason, "pong_timeout") == 0 && status == 101); ++failures; failureProbes = agent->controlChannel_pongGraceUsed;
}
static void MeshServer_ControlChannel_EmitDisconnected(MeshAgentHostContainer *agent) { (void)agent; }
static void ILibWebClient_Disconnect(ILibWebClient_StateObject s) { (void)s; ++disconnects; }
static void MeshServer_Connect(MeshAgentHostContainer *agent) { (void)agent; ++reconnects; }
void MeshServer_ControlChannel_IdleTimeout_PongTimeout(void *object);
'''

MAIN = r'''
static MeshAgentHostContainer agent;
static int channel;
static void ping_sent(long long at) {
    memset(&agent, 0, sizeof(agent)); agent.controlChannel = &channel; agent.serverConnectionState = 2; agent.serverAuthState = 1;
    agent.controlChannel_pingSentTick = at; pendingInput = 0; pingResult = 0;
    pings = timers = removals = disconnects = reconnects = failures = 0; failureProbes = -1;
}
static void fire(long long lateMs) {
    now = agent.controlChannel_pingSentTick + CONTROLCHANNEL_PONG_TIMEOUT_SECONDS * 1000LL + lateMs;
    MeshServer_ControlChannel_IdleTimeout_PongTimeout(Agent2PingData(&agent));
}
static void assert_dropped(int probes) {
    assert(failures == 1 && failureProbes == probes && disconnects == 1 && reconnects == 1);
    assert(agent.controlChannel == NULL && agent.serverConnectionState == 0 && agent.serverAuthState == 0);
}
int main(void) {
    /* On-time miss: the peer is gone; detect it in one pong timeout. */
    ping_sent(1000); fire(100); assert(pings == 0); assert_dropped(0);
    ping_sent(1000); fire(CONTROLCHANNEL_PONG_STALL_SLACK_MS); assert(pings == 0); assert_dropped(0);

    /* Stalled event thread: exactly one re-ping, then a second miss disconnects. */
    ping_sent(1000); fire(CONTROLCHANNEL_PONG_STALL_SLACK_MS + 1);
    assert(pings == 1 && timers == 1 && failures == 0 && disconnects == 0 && agent.controlChannel_pongGraceUsed == 1);
    assert(agent.controlChannel_pingSentTick == now);
    fire(CONTROLCHANNEL_PONG_STALL_SLACK_MS + 5000); assert(pings == 1); assert_dropped(1);

    /* A re-ping that cannot be queued disconnects now and cancels the re-armed timer. */
    ping_sent(1000); pingResult = -1; fire(8000); assert(pings == 1 && removals == 1); assert_dropped(1);

    /* Recent or buffered input extends the deadline and clears the probe count. */
    ping_sent(1000); agent.controlChannel_pongGraceUsed = 1; agent.controlChannel_lastDataTick = 1000 + CONTROLCHANNEL_PONG_TIMEOUT_SECONDS * 1000LL;
    fire(100); assert(pings == 0 && timers == 1 && failures == 0 && agent.controlChannel_pongGraceUsed == 0 && agent.controlChannel_pingSentTick == now);
    ping_sent(1000); pendingInput = 1; fire(100); assert(timers == 1 && failures == 0 && disconnects == 0);

    /* A timer for a channel that is already gone changes nothing. */
    ping_sent(1000); agent.controlChannel = NULL; fire(100); assert(failures == 0 && disconnects == 0 && reconnects == 0 && timers == 0);
    ping_sent(1000); agent.serverConnectionState = 1; fire(100); assert(failures == 0 && disconnects == 0 && reconnects == 0);

    puts("PASS: on-time pong miss disconnects; a stalled timer re-pings once; input extends the deadline; pongProbes is logged");
    return 0;
}
'''


def main():
    source = (ROOT / 'meshcore/agentcore.c').read_text(encoding='utf-8')
    constants = define(source, 'CONTROLCHANNEL_PONG_TIMEOUT_SECONDS') + define(source, 'CONTROLCHANNEL_PONG_STALL_SLACK_MS')
    body = extract(source, 'MeshServer_ControlChannel_IdleTimeout_PongTimeout')
    with tempfile.TemporaryDirectory(prefix='mesh-pong-probe-') as folder:
        path = pathlib.Path(folder)
        (path / 'probe.c').write_text(PRELUDE + constants + body + MAIN)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable', '-Wno-unused-but-set-variable',
                        '-fsanitize=address,undefined', str(path / 'probe.c'), '-o', str(path / 'probe')], check=True)
        subprocess.run([str(path / 'probe')], check=True, timeout=15)


if __name__ == '__main__':
    main()
