const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

function sourceSection(source, startToken, endToken) {
    const start = source.indexOf(startToken);
    if (start < 0) {
        throw new Error(`Missing source section start: ${startToken}`);
    }
    const end = endToken ? source.indexOf(endToken, start + startToken.length) : -1;
    return end < 0 ? source.substring(start) : source.substring(start, end);
}

const processPipe = read('microstack/ILibProcessPipe.c');
const parser = sourceSection(
    processPipe,
    'static int ILibProcessPipe_TryParseRundll32ModuleEntryA(',
    'static int ILibProcessPipe_IsApprovedRundll32ModuleEntryA('
);
const kvmModule = sourceSection(
    processPipe,
    'static int ILibProcessPipe_IsApprovedBridgeModuleArgumentA(',
    'static int ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA('
);
const consoleModule = sourceSection(
    processPipe,
    'static int ILibProcessPipe_IsApprovedConsoleBridgeModuleArgumentA(',
    'static int ILibProcessPipe_IsApprovedBridgePipeNameA('
);

assert(parser.includes("if (*cursor == '\"')"), 'rundll32 module parser must accept the quoted module form');
assert(parser.includes("while (*cursor != 0 && *cursor != ',')"), 'rundll32 module parser must accept the unquoted module form up to the export comma');
assert(parser.includes("_strnicmp(cursor, expectedEntry, entryLen)"), 'rundll32 module parser must verify the requested export');
assert(parser.includes('ILibProcessPipe_NormalizePathA(rawModulePath, modulePath, modulePathLen)'), 'rundll32 module parser must normalize the requested module path');

assert(kvmModule.includes('ILibProcessPipe_TryParseRundll32ModuleEntryA(value, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A'), 'KVM bridge validator must use the shared rundll32 module parser');
assert(kvmModule.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNDLL32_ENTRY_KVM_BRIDGE_A)'), 'KVM bridge validator must keep exact DLL file-identity enforcement');
assert(!kvmModule.includes("if (*cursor != '\"')"), 'KVM bridge validator must not reject the valid unquoted rundll32 module form');

assert(consoleModule.includes('ILibProcessPipe_TryParseRundll32ModuleEntryA(value, MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_A'), 'console bridge validator must use the shared rundll32 module parser');
assert(consoleModule.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNDLL32_ENTRY_CONSOLE_BRIDGE_A)'), 'console bridge validator must keep exact DLL file-identity enforcement');
assert(!consoleModule.includes("if (*cursor != '\"')"), 'console bridge validator must not reject the valid unquoted rundll32 module form');

console.log(JSON.stringify({
    success: true,
    checked: [
        'quoted rundll32 module form',
        'unquoted rundll32 module form',
        'exact export',
        'exact bridge DLL file identity'
    ]
}, null, 2));
