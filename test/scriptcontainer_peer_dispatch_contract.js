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

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const scriptContainerPath = path.resolve('microscript', 'ILibDuktape_ScriptContainer.c');
    const source = fs.readFileSync(scriptContainerPath, 'utf8');

    const checks = {
        masterTracksPeerNonce: source.includes('uintptr_t PeerCTXNonce;'),
        masterTracksPeerSlave: source.includes('ILibDuktape_ScriptContainer_Slave *PeerSlave;'),
        masterTracksPeerLock: source.includes('ILibSpinLock PeerLock;'),
        helperSetsPeerState: source.includes('static void ILibDuktape_ScriptContainer_SetPeerState('),
        helperClearsPeerState: source.includes('static void ILibDuktape_ScriptContainer_ClearPeerState('),
        helperDispatchesPeerSafely: source.includes('static int ILibDuktape_ScriptContainer_DispatchToPeer(') &&
            source.includes('ILibSpinLock_Lock(&(master->PeerLock));') &&
            source.includes('Duktape_RunOnEventLoopEx(master->PeerChain, master->PeerCTXNonce, master->PeerCTX, ILibDuktape_ScriptContainer_NonIsolatedWorker_ProcessAsSlave, cmd, 1);'),
        heapDestroyClearsPeerStateEarly: source.includes('ILibDuktape_ScriptContainer_ClearPeerState(master, ctx, slave);'),
        workerSetsPeerStateOnCreation: source.includes('ILibDuktape_ScriptContainer_SetPeerState(master, slave->chain, slave->ctx, slave);'),
        exitProcessingClearsPeerState: source.includes('ILibDuktape_ScriptContainer_ClearPeerState(master, NULL, NULL);'),
        noDirectPeerNonceDereference: !source.includes('duk_ctx_nonce(master->PeerCTX)'),
        noDirectPeerChainExtraMemoryLookup: !source.includes('ILibMemory_GetExtraMemory(master->PeerChain')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `script container peer dispatch contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        file: scriptContainerPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'scriptcontainer_peer_dispatch_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
