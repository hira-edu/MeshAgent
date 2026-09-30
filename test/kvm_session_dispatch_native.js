const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// Compile the actual notifier and its event classifier with controlled Win32/chain boundaries.
// Requires a C compiler (CC, or cc/clang); no services, sessions, or helpers are launched.
const sourcePath = process.argv[2] || path.join(__dirname, '..', 'meshcore', 'KVM', 'Windows', 'kvm.c');
const source = fs.readFileSync(sourcePath, 'utf8');
function extract(signature) {
    let start = source.indexOf(signature);
    while (start >= 0 && !/^\s*\{/.test(source.slice(start + signature.length))) {
        start = source.indexOf(signature, start + signature.length);
    }
    assert(start >= 0, `Missing definition: ${signature}`);
    const body = source.indexOf('{', start);
    let depth = 0;
    for (let i = body; i < source.length; ++i) {
        if (source[i] === '{') ++depth;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`Unterminated definition: ${signature}`);
}

const classifiers = [
    'static int kvm_session_id_is_valid(DWORD sessionId)',
    'static int kvm_session_event_is_stop(DWORD eventType)',
    'static int kvm_session_event_is_start(DWORD eventType)',
    'static int kvm_relay_session_matches_context(const KvmRelayContext* ctx, DWORD sessionId)',
    'static int kvm_relay_session_change_aborts_launch(const KvmRelayContext* ctx, DWORD eventType, DWORD sessionId, int startSessionUsable)'
].map(extract).join('\n');
const notifier = extract('void kvm_notify_session_change(DWORD eventType, DWORD sessionId)');
const harness = `
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _WINSERVICE
typedef uint32_t DWORD;
typedef void* PVOID;
enum { WTS_CONSOLE_CONNECT = 1, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_CONNECT,
    WTS_REMOTE_DISCONNECT, WTS_SESSION_LOGON, WTS_SESSION_LOGOFF, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK };
typedef struct { DWORD processSessionId; int processTSID, processTSIDExplicit, generation; } KvmRelayContext;
typedef struct { DWORD eventType, sessionId; } KvmSessionChangeRequest;
#define KVM_MAX_RELAY_CONTEXTS 2
static KvmRelayContext context, unrelated;
static KvmRelayContext* gKvmRelayContexts[KVM_MAX_RELAY_CONTEXTS];
static void* gKvmDispatchChain;
static int allocationFails, allocationBalance, lockHeld, signals, queued, drops;
static KvmSessionChangeRequest* queuedRequest;
static void* request_allocate(size_t size) {
    if (allocationFails) return NULL;
    void* result = malloc(size);
    assert(result != NULL);
    ++allocationBalance;
    return result;
}
static void request_free(void* value) {
    if (value != NULL) --allocationBalance;
    free(value);
}
static void kvm_relay_signal_lock(void) { assert(!lockHeld); lockHeld = 1; }
static void kvm_relay_signal_unlock(void) { assert(lockHeld); lockHeld = 0; }
static PVOID InterlockedCompareExchangePointer(PVOID volatile* slot, PVOID replacement, PVOID expected) {
    assert(lockHeld); assert(replacement == NULL && expected == NULL); return *slot;
}
static int kvm_session_id_exists(DWORD sessionId) { assert(!lockHeld); return sessionId != 999; }
static int kvm_relay_signal_session_change(KvmRelayContext* ctx, DWORD eventType, DWORD sessionId) {
    (void)eventType; (void)sessionId; assert(lockHeld); ++signals; return ++ctx->generation;
}
static void kvm_relay_dispatch_session_change_on_chain(void* chain, void* user) { (void)chain; (void)user; }
static void ILibChain_RunOnMicrostackThreadEx2(void* chain, void (*handler)(void*, void*), void* request, int freeOnShutdown) {
    assert(lockHeld && chain != NULL && chain == gKvmDispatchChain);
    assert(handler == kvm_relay_dispatch_session_change_on_chain && request != NULL && freeOnShutdown == 1);
    assert(queuedRequest == NULL); queuedRequest = request; ++queued;
}
static void kvm_trace_startupf(const char* format, ...) { (void)format; ++drops; }
${classifiers}
#define malloc request_allocate
#define free request_free
${notifier}
#undef malloc
#undef free

static void run_case(const char* label, DWORD eventType, DWORD sessionId, int oom, int chainPresent,
    int explicitSession, int expectedSignals, int expectedQueued) {
    assert(allocationBalance == 0 && !lockHeld);
    memset(&context, 0, sizeof(context));
    context.processSessionId = 10; context.processTSID = 10; context.processTSIDExplicit = explicitSession;
    unrelated = context; unrelated.processSessionId = 30; unrelated.processTSID = 30; unrelated.processTSIDExplicit = 1;
    gKvmRelayContexts[0] = &context; gKvmRelayContexts[1] = &unrelated;
    gKvmDispatchChain = chainPresent ? &context : NULL;
    allocationFails = oom; signals = queued = drops = 0; queuedRequest = NULL;
    kvm_notify_session_change(eventType, sessionId);
    if (signals != expectedSignals || queued != expectedQueued) {
        fprintf(stderr, "%s: signals=%d expected=%d queued=%d expected=%d\\n",
            label, signals, expectedSignals, queued, expectedQueued);
        exit(1);
    }
    assert(!lockHeld && unrelated.generation == 0);
    assert(context.generation == expectedSignals);
    assert(drops == (expectedQueued ? 0 : 1));
    if (queuedRequest != NULL) {
        assert(queuedRequest->eventType == eventType && queuedRequest->sessionId == sessionId);
        request_free(queuedRequest); queuedRequest = NULL;
    }
    assert(allocationBalance == 0);
}
int main(void) {
    run_case("OOM start cannot orphan launch", WTS_REMOTE_CONNECT, 20, 1, 1, 0, 0, 0);
    run_case("OOM stop does not abort without dispatch", WTS_REMOTE_DISCONNECT, 10, 1, 1, 0, 0, 0);
    run_case("destroyed chain start", WTS_REMOTE_CONNECT, 20, 0, 0, 0, 0, 0);
    run_case("destroyed chain stop", WTS_REMOTE_DISCONNECT, 10, 0, 0, 0, 0, 0);
    run_case("normal start aborts and queues", WTS_REMOTE_CONNECT, 20, 0, 1, 0, 1, 1);
    run_case("normal stop aborts and queues", WTS_REMOTE_DISCONNECT, 10, 0, 1, 0, 1, 1);
    run_case("lock retains helper", WTS_SESSION_LOCK, 10, 0, 1, 0, 0, 1);
    run_case("same-session start retains launch", WTS_SESSION_UNLOCK, 10, 0, 1, 0, 0, 1);
    run_case("explicit target ignores unrelated start", WTS_REMOTE_CONNECT, 20, 0, 1, 1, 0, 1);
    run_case("missing target retains launch", WTS_REMOTE_CONNECT, 999, 0, 1, 0, 0, 1);
    puts("KVM native session dispatch: 10 cases passed");
    return 0;
}
`;

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'meshagent-kvm-dispatch-'));
try {
    const input = path.join(temporary, 'dispatch.c');
    const output = path.join(temporary, process.platform === 'win32' ? 'dispatch.exe' : 'dispatch');
    fs.writeFileSync(input, harness);
    const compiler = process.env.CC || (process.platform === 'win32' ? 'clang' : 'cc');
    const build = spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', input, '-o', output], { encoding: 'utf8' });
    assert.strictEqual(build.status, 0, `Native test compilation failed (${compiler}): ${build.error || build.stderr}`);
    const result = spawnSync(output, [], { encoding: 'utf8' });
    assert.strictEqual(result.status, 0, `Native test failed: ${result.error || result.stderr}`);
    process.stdout.write(result.stdout);
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}
