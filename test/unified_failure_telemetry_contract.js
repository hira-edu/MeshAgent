const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

const sink = read('meshcore/diagnostic_log.h');
assert(sink.includes('LockFileEx(') && sink.includes('UnlockFileEx('));
assert(sink.includes('FlushFileBuffers(file)') && sink.includes('SetEndOfFile(file)'));
assert(sink.includes('FILE_FLAG_OPEN_REPARSE_POINT') && sink.includes('SERVICE_SECURE_DIR_DACL_SDDL'));
assert(!sink.includes('MoveFile') && !sink.includes('.bak') && !sink.includes('GetTempPath'));
for (const name of ['microstack/ILibParsers.c', 'meshservice/service_host.c', 'meshservice/service_deployment.c',
    'meshservice/runtime_policy.c', 'meshservice/service_integration.c', 'meshservice/service_monitor.c',
    'meshcore/KVM/Windows/kvm.c', 'meshcore/agentcore.c', 'meshservice/ServiceMain.c']) {
    assert(read(name).includes('MeshDiagnosticLog_'), name + ' must use the shared sink');
}
const host = read('meshservice/service_host.c');
const telemetry = read('meshservice/service_telemetry.h');
assert(host.includes('[START_FAILURE]') && host.includes('[UNEXPECTED_EXIT]'));
assert(host.includes('SetUnhandledExceptionFilter(ServiceHost_UnhandledException)'));
assert(host.includes('SetUnhandledExceptionFilter(g_ServiceHostPreviousExceptionFilter)'));
assert(host.includes('guarantee < 128 * 1024') && host.includes('__finally'));
assert(host.includes('reason=scm_stop') && host.includes('reason=os_shutdown'));
assert(telemetry.includes('EXCEPTION_CONTINUE_SEARCH') && !telemetry.includes('EXCEPTION_CONTINUE_EXECUTION'));
assert(telemetry.includes('unknown_crash_external_termination_power_loss_or_interrupted_shutdown'));
assert(telemetry.includes('CompareFileTime(&created, &previous.processCreated)'));
assert(read('meshcore/KVM/Windows/kvm.c').includes('[KVM_FAILURE]'));
assert(read('meshcore/KVM/Windows/kvm.c').includes('[HELPER_EXIT]'));
assert(read('meshcore/agentcore.c').includes('MeshAgent_LogKvmFailurePacket(buffer, bufferLen)'));
assert(read('meshcore/agentcore.c').includes('"%.*s", messageLen, buffer + 4'));

let requestedPath;
let input = '[2026-10-03 07:48:55.123] [pid=123 tid=456] [core] [] core.c:123 (1,2) [CONTROLCHANNEL_FAILURE] reason=receive\n' +
    '[2026-10-03 12:00:01 AM] [] old.c:42 (1,2) midnight\n' +
    '[2026-10-03 12:00:01 PM] [] old.c:43 (1,2) noon\n';
const context = {
    module: { exports: {} }, Buffer, process: { execPath: 'C:\\Agent\\helper.exe' },
    require(name) {
        if (name === 'MeshAgent') { return { logPath: 'C:\\Agent\\logs\\diagnostics.log' }; }
        if (name === 'fs') {
            return { createReadStream(file) {
                requestedPath = file;
                return { on(event, callback) { this.callback = callback; },
                    resume() { this.callback.call(this, Buffer.from(input)); }, removeAllListeners() {} };
            } };
        }
        throw new Error(name);
    }
};
vm.runInNewContext(read('modules/util-agentlog.js'), context);
const entries = context.module.exports.read();
assert.strictEqual(requestedPath, 'C:\\Agent\\logs\\diagnostics.log');
assert.strictEqual(entries.length, 3);
assert.strictEqual(entries[0].t, Math.floor(Date.parse('2026-10-03T07:48:55.123') / 1000));
assert(entries[0].m.includes('[CONTROLCHANNEL_FAILURE]'));
assert.strictEqual(entries[0].pid, 123);
assert.strictEqual(entries[0].tid, 456);
assert.strictEqual(entries[0].component, 'core');
assert.strictEqual(entries[0].f, 'core.c');
assert.strictEqual(entries[1].t, Math.floor(Date.parse('2026-10-03T00:00:01') / 1000));
assert.strictEqual(entries[2].t, Math.floor(Date.parse('2026-10-03T12:00:01') / 1000));
assert.strictEqual(entries[1].f, 'old.c');
context.module.exports.read(1, 'explicit.log');
assert.strictEqual(requestedPath, 'explicit.log');
console.log('PASS: unified writer routing, lifecycle/crash honesty, handler cleanup, log path and legacy/new timestamps');
