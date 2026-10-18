// Pin how the Windows and Linux KVM masters use the pointer-release tracker
// (meshcore/KVM/kvm_pointer_release.h): only input actually delivered to the injector is tracked,
// the release happens when the session ends and before the injector is stopped, only over a live
// bridge in the session that received the presses, and the physical button state is never read.
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const read = f => fs.readFileSync(path.join(root, f), 'utf8').replace(/\r\n/g, '\n');
const win = read('meshcore/KVM/Windows/kvm.c');
const linux = read('meshcore/KVM/Linux/linux_kvm.c');
const header = read('meshcore/KVM/kvm_pointer_release.h');

function body(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing ${signature}`);
    let i = source.indexOf('{', start) + 1, depth = 1;
    while (depth) { depth += (source[i] === '{') - (source[i] === '}'); i++; }
    return source.slice(start, i);
}

const feed = body(win, 'int kvm_relay_feeddata(char* buf, int len, ILibKVM_WriteHandler writeHandler, void *reserved)');
const cleanup = body(win, 'void kvm_cleanup(void *reserved)');
const release = body(win, 'static void kvm_relay_release_injected_pointer(KvmRelayContext* ctx)');
const linuxFeed = body(linux, 'int kvm_relay_feeddata(char* buf, int len)');
const linuxCleanup = body(linux, 'void kvm_cleanup()');

const checks = {
    windowsIncludesTracker: win.includes('#include "meshcore/KVM/kvm_pointer_release.h"'),
    windowsContextFields: win.includes('KvmPointerTrack injectedPointer;') && win.includes('DWORD injectedPointerSessionId;'),
    // Tracked only right after a successful bridge write: dropped, cached or failed input never counts.
    windowsTracksDeliveredInputOnly: (feed.match(/kvm_relay_note_injected_pointer\(/g) || []).length === 1 &&
        /if \(!kvm_relay_write_bridge_input\(ctx, buf, len\)\)\n\t\t\t\t\{[\s\S]*?goto finish;\n\t\t\t\t\}\n\t\t\t\tkvm_relay_note_injected_pointer\(ctx, buf, len\);/.test(feed),
    windowsReleasesFirstInCleanup: (() => { const a = cleanup.indexOf('kvm_relay_release_injected_pointer(ctx);'), b = cleanup.indexOf('lingerSeconds = kvm_get_helper_linger_seconds();'); return a > 0 && b > a && cleanup.indexOf('kvm_relay_unlock();\n\t\treturn;\n\t}') < a; })(),
    windowsReleaseGated: release.includes('InterlockedCompareExchange(&ctx->childUsesBridge, 0, 0) != 0') && release.includes('InterlockedCompareExchange(&ctx->bridgeTransportAttached, 0, 0) != 0') && release.includes('ctx->processSessionId == ctx->injectedPointerSessionId'),
    windowsReleaseRespectsOtherSessions: release.includes('other->injectedPointerSessionId == ctx->injectedPointerSessionId') && release.includes('elsewhere |= other->injectedPointer.held'),
    windowsReleaseStopsAtFirstFailure: /if \(!kvm_relay_write_bridge_input\(ctx, packets\[i\], KVM_POINTER_RELEASE_PACKET_SIZE\)\)\n\t\t\t\{[\s\S]*?break;/.test(release),
    windowsReleaseResets: release.includes('kvm_pointer_track_reset(&ctx->injectedPointer);'),
    linuxIncludesTracker: linux.includes('#include "meshcore/KVM/kvm_pointer_release.h"'),
    linuxTracksCompleteWritesOnly: /if \(len != \(int\)written\) return written;\n\tkvm_pointer_track_packet\(&g_injectedPointer, buf, len\);/.test(linuxFeed),
    linuxReleasesBeforeSignal: (() => { const a = linuxCleanup.indexOf('kvm_pointer_track_release_packets('), b = linuxCleanup.indexOf('kill(g_slavekvm, SIGTERM);'); return a > 0 && b > a; })(),
    linuxResets: linuxCleanup.includes('kvm_pointer_track_reset(&g_injectedPointer);'),
    // The master waits until the slave has read the releases, bounded, instead of a fixed sleep.
    linuxBoundedDrainWait: linuxCleanup.includes('waitedMs < 250') && linuxCleanup.includes('ioctl(master2slave[1], FIONREAD, &queued) == 0 && queued > 0') && !/usleep\(100000\)/.test(linuxCleanup),
    // The Windows session is stamped when a press starts; a press from another session is dropped.
    windowsStampsOnPressOnly: body(win, 'static void kvm_relay_note_injected_pointer(KvmRelayContext* ctx, char* buf, int len)').includes('before == 0 && ctx->injectedPointer.held != 0') && body(win, 'static void kvm_relay_note_injected_pointer(KvmRelayContext* ctx, char* buf, int len)').includes('ctx->injectedPointerSessionId != ctx->processSessionId'),
    // Never the physical state: that would release a button the local user is holding.
    noPhysicalStateRead: ![header, release, linuxCleanup].some(t => /GetAsyncKeyState|GetKeyState|XQueryPointer/.test(t))
};

const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([name]) => name);
for (const name of failed) console.log(`FAIL ${name}`);
console.log(`${failed.length ? 'FAIL' : 'PASS'} KVM pointer release wiring (${Object.keys(checks).length} checks)`);
if (failed.length) process.exitCode = 1;
