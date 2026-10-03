const fs = require('fs');
const path = require('path');
const vm = require('vm');

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    if (start < 0) throw new Error(`Missing function: ${signature}`);
    const brace = source.indexOf('{', start);
    let depth = 0;
    for (let i = brace; i < source.length; ++i) {
        if (source[i] === '{') depth += 1;
        if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) return source.substring(start, i + 1);
        }
    }
    throw new Error(`Unterminated function: ${signature}`);
}

function exerciseRecoveryCommandError(source) {
    const messages = [];
    const handlers = {};
    const terminal = {
        _meshTerminalReadyMarkerProtocol: true,
        onBridgeData(fn) { handlers.data = fn; },
        onBridgeReady(fn) { handlers.ready = fn; },
        on(name, fn) { handlers[name] = fn; },
        closeBridge() { this._meshTerminalClosed = true; }
    };
    const sandbox = {
        process: { platform: 'win32' },
        sendConsoleText(text) { messages.push(String(text)); },
        setTimeout() { return 1; },
        clearTimeout() { },
        require(name) {
            if (name === 'win-terminal') {
                return {
                    RunPowerShellCommand() { return terminal; },
                    RunPowerShellCommandAsUser() { return terminal; }
                };
            }
            if (name === 'user-sessions') return { consoleUid() { return 5; } };
            if (name === 'MeshAgent') return { SendCommand() { } };
            throw new Error(`Unexpected module: ${name}`);
        }
    };
    vm.runInNewContext(`var recoveryRunCommandChild = null;\n${extractFunction(source, 'function recoveryRunCommands(')}`, sandbox);
    sandbox.recoveryRunCommands({ runAsUser: 0, type: 2, cmds: 'Write-Output ok', reply: false, sessionid: 'session-1' });
    assert(typeof handlers.error === 'function', 'recovery command must register an error handler');
    handlers.error(new Error('ERROR_ELEVATION_REQUIRED'));
    assert(messages.some((text) => text.includes('ERROR_ELEVATION_REQUIRED')), 'recovery command errors must be visible to the operator');
    assert(messages.includes('Run commands failed.'), 'recovery command must report a failed terminal outcome');
    assert(!messages.includes('Run commands completed.'), 'recovery command errors must not report success');
}

function makeElement(tagName, registry) {
    return {
        tagName: String(tagName).toUpperCase(), id: '', name: '', type: '', value: '', textContent: '', disabled: false,
        style: {}, attributes: {}, children: [], parentNode: null, _listeners: {},
        appendChild(child) { child.parentNode = this; this.children.push(child); if (child.id) registry[child.id] = child; return child; },
        insertBefore(child) { return this.appendChild(child); },
        addEventListener(name, fn) { this._listeners[name] = fn; },
        getAttribute() { return null; }, setAttribute() { }, querySelector() { return null; },
        click() { if (this._listeners.click) this._listeners.click({ preventDefault() { }, target: this }); }
    };
}

function runOverlay(customSource, options) {
    const registry = {};
    const host = makeElement('div', registry);
    host.id = 'p13rightOfButtons';
    registry[host.id] = host;
    const checkbox = { checked: true, value: '0', name: 'fd', attributes: { file: { value: '3' } } };
    const sends = [];
    const intervalCallbacks = [];
    const document = {
        readyState: 'complete',
        createElement(tag) { return makeElement(tag, registry); },
        getElementById(id) { return registry[id] || null; },
        getElementsByName(name) { return name === 'fd' ? [checkbox] : []; },
        addEventListener() { }
    };
    const window = {
        document,
        location: { origin: 'https://example.invalid' },
        p13filetree: { dir: [{ n: options.name || 'Tool.exe' }] },
        p13filetreelocation: ['C:', 'Program Files', "Vendor's Tool"],
        filesNode: { _id: 'node/domain/id', agent: { id: 4 } },
        currentNode: { _id: 'node/domain/id', agent: { id: 4 } },
        files: { State: 3, sendText(message) { sends.push(message); }, m: { ProcessData() { } } },
        isWindowsNode() { return true; },
        GetNodeRights() { return options.rights; },
        meshserver: { send(message) { sends.push(message); } },
        confirm() { return true; },
        btoa(value) { return Buffer.from(value, 'binary').toString('base64'); },
        setInterval(fn) { intervalCallbacks.push(fn); return intervalCallbacks.length; },
        setTimeout(fn) { return 1; },
        clearTimeout() { }
    };
    window.window = window;
    const sandbox = { window, document, Buffer, console };
    vm.runInNewContext(customSource, sandbox, { filename: 'custom.js' });
    for (const callback of intervalCallbacks) callback();
    return { window, registry, sends };
}

function main() {
    const meshCentralRoot = path.resolve(process.argv[2] || path.join('..', 'MeshCentral'));
    const customSource = fs.readFileSync(path.join(meshCentralRoot, 'public', 'scripts', 'custom.js'), 'utf8');
    const corePaths = ['agents/meshcore.js', 'agents/meshcore.min.js', 'agents/recoverycore.js'];
    const cores = corePaths.map((relativePath) => ({ relativePath, source: fs.readFileSync(path.join(meshCentralRoot, relativePath), 'utf8') }));
    const recoverySource = cores.find(({ relativePath }) => relativePath === 'agents/recoverycore.js').source;

    const authorized = runOverlay(customSource, { rights: 131072 | 8 });
    const userButton = authorized.registry['mc-files-run-user'];
    const privilegedButton = authorized.registry['mc-files-run-privileged'];
    assert(userButton && privilegedButton, 'both Files execution buttons must be installed');
    assert(userButton.disabled === false && privilegedButton.disabled === false, 'valid selected executable must enable both actions');
    userButton.click();
    privilegedButton.click();
    assert(authorized.sends.length === 2, 'each Files action must dispatch exactly once');
    assert(authorized.sends[0].action === 'execute' && authorized.sends[0].privileged === false, 'Run must request the native user identity');
    assert(authorized.sends[1].action === 'execute' && authorized.sends[1].privileged === true, 'Run privileged must request the native agent identity');
    assert(authorized.sends.every((message) => message.path === "C:\\Program Files\\Vendor's Tool\\Tool.exe" && !message.cmds && !message.type && !message.nodeids), 'literal paths must travel through the connected Files tunnel');
    authorized.window.files.m.ProcessData(JSON.stringify({ action: 'fileaction', operation: 'execute', ok: false, error: 740 }));
    assert(authorized.registry['mc-files-exec-status'].textContent.includes('failed: 740'), 'native errors must be visible in Files');
    authorized.window.files.m.ProcessData(JSON.stringify({ action: 'fileaction', operation: 'execute', ok: true, pid: 123 }));
    assert(authorized.registry['mc-files-exec-status'].textContent.includes('PID 123'), 'native success must show the actual PID');

    const unauthorized = runOverlay(customSource, { rights: 8 });
    assert(unauthorized.registry['mc-files-run-user'].style.display === 'none', 'Run must be hidden without Remote Commands permission');
    assert(unauthorized.registry['mc-files-run-privileged'].style.display === 'none', 'Run privileged must be hidden without Remote Commands permission');
    const wrongType = runOverlay(customSource, { rights: 131072, name: 'Tool.txt' });
    assert(wrongType.registry['mc-files-run-user'].disabled === true && wrongType.registry['mc-files-run-privileged'].disabled === true, 'non-EXE selections must stay disabled');
    exerciseRecoveryCommandError(recoverySource);

    for (const core of cores) {
        const calls = [], replies = [];
        const sandbox = { process: { platform: 'win32' }, Buffer, sendConsoleText() { },
            require(name) { assert(name === 'MeshAgent', 'native handler must not load helpers'); return { fileAction(...args) { calls.push(args); return { ok: true, pid: 42 }; } }; } };
        vm.runInNewContext(extractFunction(core.source, 'function nativeFileAction('), sandbox);
        const invoke = (rights, action, extra) => sandbox.nativeFileAction({ httprequest: { rights }, write(data) { replies.push(JSON.parse(data)); } }, Object.assign({ action, path: 'C:\\literal & name.exe', reqid: 'owned' }, extra));
        invoke(8, 'execute', { privileged: true });
        invoke(131072, 'execute', { privileged: false });
        invoke(8 | 131072 | 1024, 'execute', { privileged: false });
        invoke(8 | 131072, 'execute', { privileged: 'true' });
        assert(calls.length === 0 && replies.every((r) => !r.ok), `${core.relativePath}: malformed/unauthorized execution must fail before native entry`);
        invoke(8 | 131072, 'execute', { privileged: false });
        invoke(0xFFFFFFFF, 'execute', { privileged: true });
        invoke(8 | 131072, 'open', { privileged: true });
        invoke(8, 'delete', { rec: true });
        assert(calls.length === 4 && calls[0][2] === false && calls[1][2] === true && calls[2][2] === false && calls[3][2] === true, `${core.relativePath}: native identity and delete mode must be explicit`);
        assert(calls.every((c) => c[1] === 'C:\\literal & name.exe'), 'paths must remain literal');
        assert(replies.every((r) => r.reqid === 'owned' && r.action === 'fileaction'), 'every outcome must retain correlation');
        sandbox.require = () => ({});
        const missing = invoke(8 | 131072, 'execute', { privileged: false });
        assert(!missing.ok && missing.error.includes('Update the agent'), 'old agents must fail visibly without a helper fallback');
    }

    const native = fs.readFileSync(path.resolve('meshcore/native_file_actions.h'), 'utf8');
    const checks = {
        uiUsesNativeFilesRoute: customSource.includes("window.files.sendText({ action: 'execute'") && customSource.includes('FILE_EXECUTE_RIGHT = 131072'),
        uiRevalidatesConnectedNode: customSource.includes('node._id !== current._id') && customSource.includes('getLaunchState()'),
        uiValidatesOneAbsoluteExe: customSource.includes("String(box.attributes.file.value) !== '3'") && customSource.includes('test(entry.n)'),
        uiHasNoLaunchCommandBuilder: !customSource.includes('buildWindowsFileLaunchCommand') && !customSource.includes('MESH_FILE_EXEC_OK'),
        uiRequiresExplicitConfirmation: customSource.includes('window.confirm(promptText)'),
        allFilesCoresHandleNativeExecution: cores.every(({ source }) => source.includes("case 'execute':") && source.includes("case 'open':") && source.includes("action: 'delete'")),
        nativeLaunchVerifiesTokenBeforeResume: native.includes('CREATE_SUSPENDED') && native.includes('MeshProcessToken_VerifyChildAndResume'),
        nativeDeleteDoesNotTraverseReparsePoints: native.includes('FILE_FLAG_OPEN_REPARSE_POINT') && native.includes('FILE_ATTRIBUTE_REPARSE_POINT'),
        nativeCodeHasNoHelperCommands: !/powershell|schtasks|rundll32|cmd\.exe/i.test(native),
        allFilesCoresHandleRunCommands: cores.every(({ source }) => source.includes("case 'runcommands':")),
        allFilesCoresUseApprovedTokenBridge: cores.every(({ source }) => source.includes("'RunPowerShellCommandAsUser'") && source.includes("'RunPowerShellCommand'")),
        allFilesCoresReportTerminalFailure: cores.every(({ source }) => source.includes('Run commands failed.')),
        recoveryRejectsInvalidIdentity: recoverySource.includes("sendResult('Invalid runAsUser value.')"),
        recoveryHasBoundedCommandLifetime: recoverySource.includes('}, 300000);'),
        recoveryInjectedErrorReportsFailure: true
    };
    for (const [name, passed] of Object.entries(checks)) assert(passed, `file execution actions contract failed: ${name}`);
    process.stdout.write(JSON.stringify({ generatedUtc: new Date().toISOString(), success: true, meshCentralRoot, checks }, null, 2) + '\n');
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
