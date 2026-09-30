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
    'static int ILibProcessPipe_TryParseRuntimeHostModuleEntryA(',
    'static int ILibProcessPipe_IsApprovedRuntimeHostModuleEntryA('
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
const commandLineFormatting = sourceSection(
    processPipe,
    'static int ILibProcessPipe_FormatRuntimeHostModuleEntryForCommandLineA(',
    'static int ILibProcessPipe_IsApprovedBridgeModeA('
);
const processSpawn = sourceSection(
    processPipe,
    'ILibProcessPipe_Process ILibProcessPipe_Manager_SpawnProcessEx5(',
    '#else\n\tpid_t pid;'
);

assert(parser.includes("if (*cursor == '\"')"), 'RuntimeHost module parser must accept the quoted module form');
assert(parser.includes("while (*cursor != 0 && *cursor != ',')"), 'RuntimeHost module parser must accept the unquoted module form up to the export comma');
assert(parser.includes("_strnicmp(cursor, expectedEntry, entryLen)"), 'RuntimeHost module parser must verify the requested export');
assert(parser.includes('ILibProcessPipe_NormalizePathA(rawModulePath, modulePath, modulePathLen)'), 'RuntimeHost module parser must normalize the requested module path');

assert(kvmModule.includes('ILibProcessPipe_TryParseRuntimeHostModuleEntryA(value, MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A'), 'KVM bridge validator must use the shared RuntimeHost module parser');
assert(kvmModule.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNTIME_HOST_ENTRY_KVM_BRIDGE_A)'), 'KVM bridge validator must keep exact DLL file-identity enforcement');
assert(!kvmModule.includes("if (*cursor != '\"')"), 'KVM bridge validator must not reject the valid unquoted RuntimeHost module form');

assert(consoleModule.includes('ILibProcessPipe_TryParseRuntimeHostModuleEntryA(value, MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A'), 'console bridge validator must use the shared RuntimeHost module parser');
assert(consoleModule.includes('ILibProcessPipe_IsExactBridgeModuleDllPathA(modulePath, MESH_RUNTIME_HOST_ENTRY_CONSOLE_BRIDGE_A)'), 'console bridge validator must keep exact DLL file-identity enforcement');
assert(!consoleModule.includes("if (*cursor != '\"')"), 'console bridge validator must not reject the valid unquoted RuntimeHost module form');

assert(commandLineFormatting.includes('ILibProcessPipe_FormatKnownRuntimeHostModuleEntryForCommandLineA'), 'process pipe must use a shared RuntimeHost module-entry command-line formatter');
assert(commandLineFormatting.includes('"\\"%s\\",%s"'), 'RuntimeHost command-line formatter must emit "<dll>",Export instead of quoting the comma/export as part of the DLL path');
assert(commandLineFormatting.includes('ILibProcessPipe_AppendQuotedCommandLineArgumentA'), 'process pipe must quote ordinary Windows argv arguments safely');
assert(commandLineFormatting.includes('ILibProcessPipe_AppendWindowsCommandLineArgumentA'), 'process pipe must route argv serialization through the Windows-safe appender');
assert(processSpawn.includes('ILibProcessPipe_AppendWindowsCommandLineArgumentA(target, parameters, i, parms, sz, &offset)'), 'spawn process must not flatten argv with a raw whitespace join');
assert(!processSpawn.includes('"%s%s", (i == 0) ? "" : " ", parameters[i]'), 'spawn process must not use the historical raw whitespace argv join');

console.log(JSON.stringify({
    success: true,
    checked: [
        'quoted RuntimeHost module form',
        'unquoted RuntimeHost module form',
        'exact export',
        'exact bridge DLL file identity',
        'RuntimeHost command-line module-entry serialization'
    ]
}, null, 2));
