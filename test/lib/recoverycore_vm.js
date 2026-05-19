const fs = require('fs');
const path = require('path');
const vm = require('vm');

const RECOVERYCORE_PATH = path.resolve(__dirname, '..', '..', 'modules', 'RecoveryCore.js');
const UMHCTL_PATH = path.resolve(__dirname, '..', '..', 'modules', 'umhctl.js');

function createMeshAgentStub() {
    return {
        connectedHandlers: [],
        commandHandlers: [],
        sentCommands: [],
        SendCommand(command) {
            this.sentCommands.push(command);
        },
        AddCommandHandler(handler) {
            this.commandHandlers.push(handler);
        },
        on(eventName, handler) {
            this.connectedHandlers.push({ eventName, handler });
        }
    };
}

function loadRecoveryCoreVm() {
    const code = fs.readFileSync(RECOVERYCORE_PATH, 'utf8');
    const meshAgentStub = createMeshAgentStub();

    function mirrorUmhctlOverrides(sandbox, umhSandbox) {
        [
            'childProcess',
            'sendConsoleText',
            'umhctlPreflightControlService',
            'umhctlSendControlRequest',
            'umhctlRunPreProtectionCapture',
            'umhctlEnsureFlowContract'
        ].forEach((name) => {
            if (Object.prototype.hasOwnProperty.call(sandbox, name)) {
                umhSandbox[name] = sandbox[name];
            }
        });
    }

    const sandbox = {
        Buffer,
        console,
        process,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        require(moduleName) {
            if (moduleName === 'MeshAgent') { return meshAgentStub; }
            if (moduleName === 'umhctl') {
                if (sandbox.__umhctlModule != null) {
                    mirrorUmhctlOverrides(sandbox, sandbox.__umhctlSandbox);
                    return sandbox.__umhctlModule;
                }
                const umhSandbox = {
                    Buffer,
                    console,
                    process,
                    setTimeout,
                    clearTimeout,
                    setInterval,
                    clearInterval,
                    module: { exports: {} },
                    exports: {},
                    require: sandbox.require
                };
                vm.createContext(umhSandbox);
                vm.runInContext(fs.readFileSync(UMHCTL_PATH, 'utf8'), umhSandbox, { filename: UMHCTL_PATH });
                mirrorUmhctlOverrides(sandbox, umhSandbox);
                sandbox.__umhctlSandbox = umhSandbox;
                sandbox.__umhctlModule = umhSandbox.module.exports;
                return sandbox.__umhctlModule;
            }
            return require(moduleName);
        }
    };

    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, { filename: RECOVERYCORE_PATH });
    return { sandbox, meshAgentStub, recoveryCorePath: RECOVERYCORE_PATH };
}

function getConsoleMessages(meshAgentStub) {
    return meshAgentStub.sentCommands
        .filter((entry) => entry && entry.type === 'console')
        .map((entry) => entry.value);
}

module.exports = {
    RECOVERYCORE_PATH,
    UMHCTL_PATH,
    loadRecoveryCoreVm,
    getConsoleMessages
};
