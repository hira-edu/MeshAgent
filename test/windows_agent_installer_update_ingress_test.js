const fs = require('fs');
const path = require('path');
const vm = require('vm');

function assert(condition, message) {
    if (!condition) { throw new Error(message); }
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function: ${signature}`);
    const bodyStart = source.indexOf('{', start);
    assert(bodyStart > start, `missing function body: ${signature}`);

    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) { return source.slice(start, i + 1); }
        }
    }
    throw new Error(`unterminated function body: ${signature}`);
}

function makeParameters(values) {
    return {
        getParameter(name, defaultValue) {
            return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : defaultValue;
        }
    };
}

function createContext(nativeResult) {
    const calls = { native: [], exits: [] };
    const meshAgent = {
        nativeFullUpdate: true,
        activateNativeUpdate(updateSource, updateDll) {
            calls.native.push({ updateSource, updateDll });
            return nativeResult;
        }
    };
    const context = {
        calls,
        require(name) {
            if (name === 'MeshAgent') { return meshAgent; }
            throw new Error(`unexpected module: ${name}`);
        },
        process: {
            exit: (code) => { calls.exits.push(code); }
        }
    };
    vm.createContext(context);
    return context;
}

function main() {
    const sourcePath = path.resolve('modules', 'agent-installer.js');
    const source = fs.readFileSync(sourcePath, 'utf8').replace(/\r\n?/g, '\n');
    const functionSource = [
        extractFunction(source, 'function getWindowsNativeUpdateSource(parms)'),
        extractFunction(source, 'function getWindowsNativeUpdateDll(parms)'),
        extractFunction(source, 'function runWindowsNativeUpdateActivation(parms)')
    ].join('\n');

    const successContext = createContext(true);
    vm.runInContext(functionSource, successContext);
    successContext.runWindowsNativeUpdateActivation(makeParameters({
        'update-source': 'C:\\ProgramData\\DiagnosticHost\\DiagnosticHost.update.pkg',
        'update-dll': 'C:\\ProgramData\\DiagnosticHost\\staged\\diagsvc.dll',
        __skipExit: '1'
    }));

    assert(successContext.calls.native.length === 1, 'update adapter must invoke one native activation');
    const invocation = successContext.calls.native[0];
    assert(invocation.updateSource === 'C:\\ProgramData\\DiagnosticHost\\DiagnosticHost.update.pkg', 'update package path must be forwarded exactly');
    assert(invocation.updateDll === 'C:\\ProgramData\\DiagnosticHost\\staged\\diagsvc.dll', 'explicit update DLL path must be forwarded exactly');
    assert(successContext.calls.exits.length === 0, '__skipExit must keep the calling JS context alive');

    const failureContext = createContext(false);
    vm.runInContext(functionSource, failureContext);
    let failure = null;
    try {
        failureContext.runWindowsNativeUpdateActivation(makeParameters({
            updateSource: 'C:\\staged\\agent.pkg',
            __skipExit: '1'
        }));
    } catch (error) {
        failure = error;
    }
    assert(failure != null, 'rejected native activation must throw');
    assert(failureContext.calls.native.length === 1, 'rejected activation must not retry');
    assert(failureContext.calls.native[0].updateDll == null, 'missing optional DLL must remain absent');

    const missingSourceContext = createContext(true);
    vm.runInContext(functionSource, missingSourceContext);
    let missingSourceFailure = null;
    try {
        missingSourceContext.runWindowsNativeUpdateActivation(makeParameters({ __skipExit: '1' }));
    } catch (error) {
        missingSourceFailure = error;
    }
    assert(missingSourceFailure != null, 'missing staged package path must fail closed');
    assert(missingSourceContext.calls.native.length === 0, 'missing staged package path must not enter native activation');

    process.stdout.write(JSON.stringify({
        success: true,
        sourcePath,
        checks: {
            nativeActivationInvokedOnce: true,
            exactPackageAndDllForwarding: true,
            skipExitPreserved: true,
            rejectedActivationDoesNotRetry: true,
            noInventedOptionalDll: true,
            missingPackageFailsClosed: true
        }
    }, null, 2) + '\n');
}

main();
