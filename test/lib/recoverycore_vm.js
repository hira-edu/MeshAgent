const fs = require('fs');
const path = require('path');
const vm = require('vm');

const RECOVERYCORE_PATH = path.resolve(__dirname, '..', '..', 'modules', 'RecoveryCore.js');

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
    loadRecoveryCoreVm,
    getConsoleMessages
};
