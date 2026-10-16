// Mock only command execution: exercise the production probe plan without services.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { resolveProbeInputs, runMeshCentralSameSizeContracts } = require('./run_grouped_regression');

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'grouped-architecture-'));
function pe(name, machine) {
    const file = path.join(temp, name);
    const bytes = Buffer.alloc(256);
    bytes.write('MZ'); bytes.writeUInt32LE(128, 60); bytes.write('PE\0\0', 128);
    bytes.writeUInt16LE(machine, 132);
    fs.writeFileSync(file, bytes);
    return file;
}
try {
    for (const [architecture, machine] of [['x64', 0x8664], ['arm64', 0xaa64]]) {
        const exe = pe(`${architecture}.exe`, machine);
        const dll = pe(`${architecture}.dll`, machine);
        const runner = pe(`${architecture}-console.exe`, machine);
        const inputs = resolveProbeInputs({ exe, dll }, runner);
        assert.strictEqual(inputs.architecture, architecture);
        const commands = new Map();
        runMeshCentralSameSizeContracts((name, file, args) => {
            commands.set(name, args);
            return { exitCode: 0, stdout: '', stderr: '' };
        }, path.join(temp, architecture), inputs);
        function option(name, key, value) {
            const args = commands.get(name);
            assert(args.includes(key), `${name} missing ${key}`);
            assert.strictEqual(args[args.indexOf(key) + 1], value);
        }
        option('http-request-alignment-runtime', '--runner', runner);
        option('rundll32-bridge-smoke', '--dll', dll);
        for (const name of ['kvm-initial-frame-runtime', 'kvm-system-picture-runtime', 'service-bundle-embedding-contract']) {
            option(name, '--exe', exe);
            option(name, '--dll', dll);
        }
        option('service-bundle-embedding-contract', '--architecture', architecture);
        const other = pe('wrong.dll', machine === 0x8664 ? 0xaa64 : 0x8664);
        assert.throws(() => resolveProbeInputs({ exe, dll: other }, runner), /architecture mismatch/);
        assert.throws(() => resolveProbeInputs({ exe, dll }, other), /architecture mismatch/);
    }
    console.log('PASS: both native probe plans propagate matching inputs and reject mixed architectures');
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
