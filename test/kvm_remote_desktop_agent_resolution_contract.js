const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function extractBlock(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    if (start < 0) { return ''; }
    const end = nextMarker ? source.indexOf(nextMarker, start) : -1;
    return end > start ? source.slice(start, end) : source.slice(start);
}

function main() {
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const source = fs.readFileSync(agentcorePath, 'utf8');
    const helperBlock = extractBlock(
        source,
        'static MeshAgentHostContainer* ILibDuktape_MeshAgent_ResolveRemoteDesktopAgent(duk_context *ctx)',
        'duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop(duk_context *ctx)'
    );
    const getRemoteDesktopBlock = extractBlock(
        source,
        'duk_ret_t ILibDuktape_MeshAgent_getRemoteDesktop(duk_context *ctx)',
        'duk_ret_t ILibDuktape_MeshAgent_ConnectedServer(duk_context *ctx)'
    );

    const checks = {
        helperExists: helperBlock.length > 0,
        helperChecksThisMeshAgentPtr: helperBlock.includes('Duktape_GetPointerProperty(ctx, -1, MESH_AGENT_PTR)'),
        helperFallsBackToHeapStashMeshAgentPtr: helperBlock.includes('Duktape_GetPointerProperty(ctx, -1, "MeshAgentPtr")'),
        helperFallsBackToMeshDesktopStashPtr: helperBlock.includes('Duktape_GetPointerProperty(ctx, -1, "\\xFF_MeshDesktop_AgentPtr")'),
        getRemoteDesktopUsesResolver: getRemoteDesktopBlock.includes('agent = ILibDuktape_MeshAgent_ResolveRemoteDesktopAgent(ctx);'),
        getRemoteDesktopNoLongerReadsRawThisPointer:
            !/duk_get_prop_string\(ctx,\s*-1,\s*MESH_AGENT_PTR\);\s*agent\s*=\s*\(MeshAgentHostContainer\*\)duk_get_pointer\(ctx,\s*-1\);/m.test(getRemoteDesktopBlock)
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify({
        generatedUtc: new Date().toISOString(),
        success: true,
        agentcorePath,
        checks
    }, null, 2) + '\n');
}

main();
