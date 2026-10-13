#!/usr/bin/env python3
"""Compile the production Windows update readiness and retry-backoff block against
Win32 fakes, then drive the readiness gate, the per-package attempt record and the
one-shot renegotiation after a deferral clears."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshcore/agentcore.c').read_text(encoding='utf-8-sig').replace('\r\n', '\n')
defines = (ROOT / 'meshcore/config/update_defines.h').read_text(encoding='utf-8-sig')

start = source.index('#ifdef WIN32\n// Server-pushed update readiness and retry backoff')
end = source.index('#if defined(WIN32) && defined(MESHAGENT_ENABLE_RUNTIME_FEATURES)\ntypedef struct MeshServer_UpdateActivation', start)
block = source[start:end]

prelude = r'''
#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wchar.h>
#define WIN32 1
#define MESHAGENT_ENABLE_RUNTIME_FEATURES 1
#define UTIL_SHA384_HASHSIZE 48
#define FALSE 0
#define SYNCHRONIZE 0x100000UL
#define SM_SHUTTINGDOWN 0x2000
#define _stricmp strcasecmp
#define sprintf_s snprintf
typedef int BOOL; typedef unsigned long DWORD; typedef void* HANDLE; typedef unsigned long long ULONGLONG;
/* Log calls evaluate their arguments, as in production, but print nothing. */
static void logFixture(const char *format, ...) { (void)format; }
#define ILIBLOGMESSSAGE logFixture
#define ILIBLOGMESSAGEX logFixture

typedef struct MeshAgentHostContainer {
    void *masterDb; void *chain; char agentHash[UTIL_SHA384_HASHSIZE];
    int serverSupportsUpdateFailureStatus, disableUpdate, updateDownloadActive, transferBlocked, forceUpdate, fakeUpdate;
    int controlChannelIntentionalDisconnect;
    void *controlChannel; int updateRenegotiateArmed; void *updateRenegotiateChannel;
} MeshAgentHostContainer;
static MeshAgentHostContainer *current;

static int shuttingDown, msiBusy, handlesOpen; static ULONGLONG tickMs;
static int GetSystemMetrics(int index) { assert(index == SM_SHUTTINGDOWN); return shuttingDown; }
static HANDLE OpenMutexW(DWORD access, BOOL inherit, const wchar_t *name) {
    assert(access == SYNCHRONIZE && !inherit && !wcscmp(name, L"Global\\_MSIExecute"));
    if (!msiBusy) return NULL; ++handlesOpen; return (HANDLE)7;
}
static BOOL CloseHandle(HANDLE h) { assert(h == (HANDLE)7); --handlesOpen; return 1; }
static ULONGLONG GetTickCount64(void) { return tickMs; }

/* The production reader returns the stored length without copying when the buffer is too small. */
static char dbValue[400]; static int dbLen, puts_, deletes; static int minUptimeKey = -1;
static int ILibSimpleDataStore_Get(void *db, const char *key, char *out, int len) {
    (void)db; assert(!strcmp(key, "UpdateRetryState")); if (dbLen && dbLen <= len) memcpy(out, dbValue, (size_t)dbLen); return dbLen;
}
static int ILibSimpleDataStore_GetInt(void *db, const char *key, int def) {
    (void)db;
    if (!strcmp(key, "updateMinUptimeSeconds")) return minUptimeKey != -1 ? minUptimeKey : def;
    abort();
}
static int ILibSimpleDataStore_Delete(void *db, const char *key) { (void)db; assert(!strcmp(key, "UpdateRetryState")); ++deletes; dbLen = 0; dbValue[0] = 0; return 0; }
static int ILibSimpleDataStore_PutEx(void *db, const char *key, size_t keyLen, const char *value, size_t valueLen) {
    (void)db; assert(keyLen == strlen(key) && !strcmp(key, "UpdateRetryState") && valueLen < sizeof(dbValue));
    memcpy(dbValue, value, valueLen); dbValue[valueLen] = 0; dbLen = (int)valueLen; ++puts_; return 0;
}
static void dbSet(const char *value) { strcpy(dbValue, value); dbLen = (int)strlen(value); }
static char *util_tohex(char *data, size_t len, char *out) {
    static const char table[] = "0123456789ABCDEF"; size_t i;
    for (i = 0; i < len; ++i) { out[2 * i] = table[(unsigned char)data[i] >> 4]; out[2 * i + 1] = table[(unsigned char)data[i] & 15]; }
    out[2 * len] = 0; return out;
}
static char sent[8][256]; static int sentCount, disconnects;
static void MeshServer_SendJSON(MeshAgentHostContainer *a, void *channel, char *json, int len) {
    assert(a && channel == a->controlChannel && len == (int)strlen(json) && sentCount < 8); strcpy(sent[sentCount++], json);
}
/* A deliberate reconnect must not be logged as a control-channel failure. */
static void ILibWebClient_Disconnect(void *channel) { assert(channel && current->controlChannelIntentionalDisconnect == 1); ++disconnects; }
static void *timerData; static int timerSeconds, timerAdds; static void (*timerCallback)(void*);
static void *ILibGetBaseTimer(void *chain) { assert(chain == (void*)9); return (void*)8; }
#define ILibLifeTime_Add(timer, data, seconds, callback, destroy) do { assert((timer) == (void*)8 && (destroy) == NULL); timerData = (data); timerSeconds = (seconds); timerCallback = (callback); ++timerAdds; } while (0)
static int MeshServer_UpdateTransferBlocked(MeshAgentHostContainer *a) { return a->transferBlocked; }
'''

cases = r'''
#define HASH_A "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1"
#define HASH_B "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"
static MeshAgentHostContainer agent;
static char pkgA[48], pkgB[48];

static void reset(void) {
    shuttingDown = msiBusy = 0; tickMs = 60ULL * 1000; minUptimeKey = -1;
    dbLen = 0; dbValue[0] = 0; puts_ = deletes = sentCount = disconnects = timerAdds = timerSeconds = 0; timerData = NULL; timerCallback = NULL;
    memset(&agent, 0, sizeof(agent)); agent.masterDb = (void*)1; agent.chain = (void*)9; agent.controlChannel = (void*)5; agent.serverSupportsUpdateFailureStatus = 1;
    current = &agent;
}
static const char *notReady(void) {
    static char r[96]; r[0] = 0;
    if (!MeshServer_UpdateNotReady(&agent, r, sizeof(r))) return NULL;
    assert(handlesOpen == 0); return r;
}
static void record(int attempts, long long last, const char *hash) { char t[160]; snprintf(t, sizeof(t), "1 %d %lld %s", attempts, last, hash); dbSet(t); }
static int waiting(int attempts, long long last, long long now) {
    MeshServer_UpdateRetryState s; memset(&s, 0, sizeof(s)); s.attempts = attempts; s.lastAttempt = last;
    return MeshServer_UpdateRetry_Waiting(&s, now);
}

static void readiness(void) {
    /* The uptime minimum is opt-in: a freshly booted system is ready by default. */
    reset(); tickMs = 0; assert(notReady() == NULL);
    reset(); shuttingDown = 1; msiBusy = 1; assert(!strcmp(notReady(), "system shutdown in progress"));
    reset(); msiBusy = 1; assert(!strcmp(notReady(), "Windows Installer transaction in progress"));
    reset(); minUptimeKey = 600; tickMs = 599ULL * 1000; assert(!strcmp(notReady(), "system uptime 599s is below the 600s minimum"));
    reset(); minUptimeKey = 600; tickMs = 600ULL * 1000; assert(notReady() == NULL);
    reset(); minUptimeKey = -5; tickMs = 0; assert(notReady() == NULL);
}

static void retry(void) {
    MeshServer_UpdateRetryState s;
    reset(); assert(!MeshServer_UpdateRetry_Load(&agent, &s) && deletes == 0);
    record(2, 1700000000LL, HASH_A);
    assert(MeshServer_UpdateRetry_Load(&agent, &s) && s.attempts == 2 && s.lastAttempt == 1700000000LL && !strcmp(s.hashHex, HASH_A));
    {
        const char *bad[] = { "x", "2 2 1700000000 " HASH_A, "1 0 1700000000 " HASH_A, "1 -1 1700000000 " HASH_A,
            "1  2 1700000000 " HASH_A, "1 2  1700000000 " HASH_A, "1 2 -5 " HASH_A, "1 2 1700000000 " HASH_A "0",
            "1 2 1700000000 A1", "1 2 1700000000 G1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
            "1 2 1700000000 " HASH_A HASH_A };
        size_t i;
        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) { reset(); dbSet(bad[i]); assert(!MeshServer_UpdateRetry_Load(&agent, &s) && deletes == 1 && dbLen == 0); }
    }
    assert(waiting(1, 100000, 100000 + 3599) && !waiting(1, 100000, 100000 + 3600));
    assert(waiting(2, 100000, 100000 + 7199) && !waiting(2, 100000, 100000 + 7200));
    assert(waiting(5, 100000, 100000 + 57599) && !waiting(5, 100000, 100000 + 57600));
    assert(waiting(6, 100000, 100000 + 86399) && !waiting(6, 100000, 100000 + 86400));
    /* No attempt limit: a long-failing package is still retried daily. */
    assert(waiting(1000000, 100000, 100000 + 86399) && !waiting(1000000, 100000, 100000 + 86400));
    /* A record further ahead than the longest wait is not trusted; a smaller skew still waits. */
    assert(!waiting(1, 100000 + 86401, 100000) && waiting(1, 100000 + 600, 100000));
    /* Forced and fake updates never wait. */
    reset(); record(1, (long long)time(NULL), HASH_A); assert(MeshServer_UpdateRetry_Pending(&agent, (long long)time(NULL), &s));
    agent.forceUpdate = 1; assert(!MeshServer_UpdateRetry_Pending(&agent, (long long)time(NULL), &s));
    agent.forceUpdate = 0; agent.fakeUpdate = 1; assert(!MeshServer_UpdateRetry_Pending(&agent, (long long)time(NULL), &s));

    /* The record is cleared once the running image is the handed-off package. */
    reset(); record(2, 1000, HASH_A); memcpy(agent.agentHash, pkgB, 48); MeshServer_UpdateRetry_Reconcile(&agent); assert(dbLen > 0);
    memcpy(agent.agentHash, pkgA, 48); MeshServer_UpdateRetry_Reconcile(&agent); assert(dbLen == 0 && deletes == 1);
    reset(); record(2, 1000, "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");
    memcpy(agent.agentHash, pkgA, 48); MeshServer_UpdateRetry_Reconcile(&agent); assert(dbLen == 0);
    reset(); MeshServer_UpdateRetry_Reconcile(&agent); assert(deletes == 0);
}

static void negotiation(void) {
    long long now = 2000000000LL; char r[96];
    /* Readiness defers on every server, arms one recheck, and sends no device event. */
    reset(); msiBusy = 1; assert(MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)) && strstr(r, "Installer") && timerAdds == 1 && sentCount == 0);
    reset(); agent.forceUpdate = 1; shuttingDown = 1; assert(MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)));
    MeshServer_ReportUpdateDeferral(&agent, "reboot");
    assert(sentCount == 1 && !strcmp(sent[0], "{\"action\":\"log\",\"msg\":\"Agent update deferred: reboot\"}"));
    agent.controlChannel = NULL; MeshServer_ReportUpdateDeferral(&agent, "reboot"); assert(sentCount == 1);

    /* A capable server is told the hash before the hash reply; negotiation proceeds. */
    reset(); record(1, now - 60, HASH_A);
    assert(!MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)) && timerAdds == 0);
    MeshServer_SendUpdateRetrySuppression(&agent, now);
    assert(sentCount == 1 && !strcmp(sent[0], "{\"action\":\"agentupdatefailure\",\"hash\":\"" HASH_A "\"}") && timerAdds == 1);
    MeshServer_SendUpdateRetrySuppression(&agent, now + 3600); assert(sentCount == 1);
    reset(); MeshServer_SendUpdateRetrySuppression(&agent, now); assert(sentCount == 0 && timerAdds == 0);
    reset(); agent.fakeUpdate = 1; record(1, now - 60, HASH_A); MeshServer_SendUpdateRetrySuppression(&agent, now); assert(sentCount == 0);

    /* A server without failure status gets an all-zero hash until the retry is due. */
    reset(); agent.serverSupportsUpdateFailureStatus = 0; record(1, now - 60, HASH_A);
    MeshServer_SendUpdateRetrySuppression(&agent, now); assert(sentCount == 0);
    assert(MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)) && !strcmp(r, "retry of the last failed package is not due") && timerAdds == 1);
    assert(!MeshServer_UpdateNegotiationDeferred(&agent, now + 3600, r, sizeof(r)));
    agent.forceUpdate = 1; assert(!MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)));
    reset(); agent.serverSupportsUpdateFailureStatus = 0; assert(!MeshServer_UpdateNegotiationDeferred(&agent, now, r, sizeof(r)));
}

static void renegotiation(void) {
    long long now = (long long)time(NULL);
    /* Armed once; while still deferred it re-arms and never reconnects. */
    reset(); msiBusy = 1;
    MeshServer_UpdateRenegotiate_Arm(&agent); MeshServer_UpdateRenegotiate_Arm(&agent);
    assert(timerAdds == 1 && timerSeconds == MESHAGENT_UPDATE_RENEGOTIATE_RECHECK_SECONDS && timerData == &agent.updateRenegotiateArmed);
    timerCallback(timerData); assert(timerAdds == 2 && agent.updateRenegotiateArmed && disconnects == 0);
    /* Cleared: reconnect exactly once, flagged as intentional, and do not re-arm. */
    msiBusy = 0; timerCallback(timerData);
    assert(timerAdds == 2 && !agent.updateRenegotiateArmed && disconnects == 1 && sentCount == 0 && agent.controlChannelIntentionalDisconnect == 0);

    /* The connection that armed the check is gone: a new one negotiates by itself. */
    reset(); MeshServer_UpdateRenegotiate_Arm(&agent); agent.controlChannel = (void*)6; timerCallback(timerData); assert(disconnects == 0 && timerAdds == 1);
    reset(); agent.controlChannel = NULL; MeshServer_UpdateRenegotiate_Arm(&agent); assert(timerAdds == 0);
    /* A check pending from a dropped connection serves the next one that defers. */
    reset(); MeshServer_UpdateRenegotiate_Arm(&agent); agent.controlChannel = (void*)6; MeshServer_UpdateRenegotiate_Arm(&agent);
    assert(timerAdds == 1); timerCallback(timerData); assert(disconnects == 1);
    /* A transfer that started anyway owns the outcome. */
    reset(); MeshServer_UpdateRenegotiate_Arm(&agent); agent.transferBlocked = 1; timerCallback(timerData); assert(disconnects == 0 && timerAdds == 1);
    reset(); MeshServer_UpdateRenegotiate_Arm(&agent); agent.updateDownloadActive = 1; timerCallback(timerData); assert(disconnects == 0 && timerAdds == 1);
    reset(); MeshServer_UpdateRenegotiate_Arm(&agent); agent.disableUpdate = 1; timerCallback(timerData); assert(disconnects == 0 && timerAdds == 1);
    /* Backoff: wait it out, then reconnect once; a forced update does not wait. */
    reset(); record(1, now, HASH_A); MeshServer_UpdateRenegotiate_Arm(&agent); timerCallback(timerData); assert(timerAdds == 2 && disconnects == 0);
    record(1, now - 3600, HASH_A); timerCallback(timerData); assert(timerAdds == 2 && disconnects == 1);
    reset(); agent.forceUpdate = 1; record(1, now, HASH_A); MeshServer_UpdateRenegotiate_Arm(&agent); timerCallback(timerData); assert(timerAdds == 1 && disconnects == 1);
}

static void activation(void) {
    long long now = (long long)time(NULL);
    int i;
    /* Not ready: reported as a device event and rechecked, nothing counted. */
    reset(); msiBusy = 1; assert(!MeshServer_UpdateActivationAllowed(&agent, pkgA));
    assert(puts_ == 0 && dbLen == 0 && sentCount == 1 && !strcmp(sent[0], "{\"action\":\"log\",\"msg\":\"Agent update deferred: Windows Installer transaction in progress\"}") && timerAdds == 1);
    /* Ready: the handoff is counted before it starts; a different package starts at one. */
    reset(); assert(MeshServer_UpdateActivationAllowed(&agent, pkgA) && !strncmp(dbValue, "1 1 ", 4) && strstr(dbValue, HASH_A) && sentCount == 0);
    assert(MeshServer_UpdateActivationAllowed(&agent, pkgA) && !strncmp(dbValue, "1 2 ", 4));
    assert(MeshServer_UpdateActivationAllowed(&agent, pkgB) && !strncmp(dbValue, "1 1 ", 4) && strstr(dbValue, HASH_B));
    /* A package that reached the handoff is accepted on every server (negotiation already
     * withheld it while it waited) and counted. */
    record(5, now, HASH_A); assert(MeshServer_UpdateActivationAllowed(&agent, pkgA) && !strncmp(dbValue, "1 6 ", 4));
    reset(); agent.serverSupportsUpdateFailureStatus = 0; record(2, now, HASH_A);
    assert(MeshServer_UpdateActivationAllowed(&agent, pkgA) && !strncmp(dbValue, "1 3 ", 4));
    /* Repeated failures only lengthen the wait (capped at 24 hours); they never stop retries. */
    reset();
    for (i = 1; i <= 8; ++i) {
        MeshServer_UpdateRetryState s;
        assert(MeshServer_UpdateActivationAllowed(&agent, pkgA));
        assert(MeshServer_UpdateRetry_Load(&agent, &s) && s.attempts == i);
        assert(MeshServer_UpdateRetry_Waiting(&s, s.lastAttempt) && !MeshServer_UpdateRetry_Waiting(&s, s.lastAttempt + 86400));
    }
}

int main(void) {
    memset(pkgA, 0xA1, sizeof(pkgA)); memset(pkgB, 0xB2, sizeof(pkgB));
    readiness(); retry(); negotiation(); renegotiation(); activation();
    puts("Update readiness gate, retry backoff and renegotiation passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='mesh-update-readiness-') as tmp:
    c, exe = Path(tmp) / 'readiness.c', Path(tmp) / 'readiness'
    c.write_text(prelude + defines + block + cases)
    cmd = [os.environ.get('CC', 'clang'), '-std=c11', '-D_DEFAULT_SOURCE', '-D_DARWIN_C_SOURCE', '-Wall', '-Wextra', '-Werror']
    if os.name != 'nt':
        cmd += ['-fsanitize=address,undefined']
    subprocess.run(cmd + [str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

# Integration points: the deferral sits beside the transfer-blocked gate, and the
# failed-package status precedes the hash reply.
hash_case = source[source.index('case MeshCommand_AgentHash:'):source.index('case MeshCommand_AgentUpdate:')]
order = [hash_case.index(marker) for marker in (
    'MeshServer_UpdateTransferBlocked(agent)',
    'MeshServer_UpdateNegotiationDeferred(agent,',
    'agent->forceUpdate != 0 || agent->fakeUpdate != 0',
    'MeshServer_SendUpdateRetrySuppression(agent,',
    '// Update when necessary',
    'ILibWebClient_WebSocket_Send(WebStateObject')]
assert order == sorted(order)
deferred = hash_case[order[1]:order[2]]
assert 'memset(rcm->coreModuleHash, 0, UTIL_SHA384_HASHSIZE)' in deferred
# Negotiation logs locally only; the device event is reserved for activation-time deferrals.
assert 'MeshServer_ReportUpdateDeferral' not in hash_case
continue_fn = source[source.index('void MeshServer_selfupdate_continue(MeshAgentHostContainer *agent)'):]
gate = continue_fn.index('MeshServer_UpdateActivationAllowed(agent, packageHash)')
launch = continue_fn.index('MeshServer_StartUpdateActivation(agent, w_updatefile)')
assert continue_fn.index('GenerateSHA384FileHash(updatefile, packageHash)') < gate < launch
assert 'MeshServer_FailUpdateActivation(agent, 1);' in continue_fn[gate:launch]
connect = source[source.index('agent->serverSupportsUpdateFailureStatus = 0;'):]
assert connect.index('MeshServer_UpdateRetry_Reconcile(agent);') < connect.index('Attempting to connect to Server...')
# The lifecycle host's PendingUpdate marker keeps its startup semantics.
assert 'ILibSimpleDataStore_Delete(agentHost->masterDb, "PendingUpdate");' in source
