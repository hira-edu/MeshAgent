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
    const parameters = {
        length: 0,
        getParameter(name, defaultValue) {
            return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : defaultValue;
        },
        push(value) {
            const match = /^--([^=]+)=(.*)$/.exec(value);
            if (match != null) {
                let parameterValue = match[2];
                if (parameterValue.startsWith('"') && parameterValue.endsWith('"')) {
                    parameterValue = parameterValue.substring(1, parameterValue.length - 1);
                }
                values[match[1]] = parameterValue;
            }
            this[this.length++] = value;
        }
    };
    return parameters;
}

function makeMsh(values) {
    return function () {
        return values;
    };
}

function createContext(nativeResult, mshValues) {
    const calls = { native: [], exits: [] };
    const meshAgent = {
        nativeFullUpdate: true,
        activateNativeUpdate(updateSource, updateDll, displayName, description) {
            calls.native.push({ updateSource, updateDll, displayName, description });
            return nativeResult;
        }
    };
    const context = {
        calls,
        _MSH: makeMsh(mshValues || {}),
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
        extractFunction(source, 'function hasWindowsUnsupportedStandaloneParameter(parms)'),
        extractFunction(source, 'function prepareWindowsNativeLifecycleParameters(parms)'),
        extractFunction(source, 'function getWindowsNativeUpdateSource(parms)'),
        extractFunction(source, 'function getWindowsNativeUpdateDll(parms)'),
        extractFunction(source, 'function runWindowsNativeUpdateActivation(parms)')
    ].join('\n');

    const successContext = createContext(true, {
        displayName: 'Server Supplied Agent',
        description: 'Server supplied runtime description'
    });
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
    assert(invocation.displayName === 'Server Supplied Agent', 'runtime .msh displayName must be forwarded exactly');
    assert(invocation.description === 'Server supplied runtime description', 'runtime .msh description must be forwarded exactly');
    assert(successContext.calls.exits.length === 0, '__skipExit must keep the calling JS context alive');

    const explicitBrandingContext = createContext(true, {
        displayName: 'Package Branding',
        description: 'Package description'
    });
    vm.runInContext(functionSource, explicitBrandingContext);
    explicitBrandingContext.runWindowsNativeUpdateActivation(makeParameters({
        'update-source': 'C:\\staged\\agent.pkg',
        displayName: 'Explicit Runtime Branding',
        description: 'Explicit runtime description',
        __skipExit: '1'
    }));
    assert(explicitBrandingContext.calls.native[0].displayName === 'Explicit Runtime Branding', 'explicit runtime displayName must override .msh branding');
    assert(explicitBrandingContext.calls.native[0].description === 'Explicit runtime description', 'explicit runtime description must override .msh branding');

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
    assert(failureContext.calls.native[0].displayName == null, 'missing runtime displayName must remain absent');
    assert(failureContext.calls.native[0].description == null, 'missing runtime description must remain absent');

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
            dynamicMshBrandingForwarded: true,
            explicitBrandingPrecedencePreserved: true,
            absentBrandingRemainsAbsent: true,
            skipExitPreserved: true,
            rejectedActivationDoesNotRetry: true,
            noInventedOptionalDll: true,
            missingPackageFailsClosed: true
        }
    }, null, 2) + '\n');
}

main();
