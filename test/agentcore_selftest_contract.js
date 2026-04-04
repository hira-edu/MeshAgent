const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function main() {
    const agentcorePath = path.resolve('meshcore', 'agentcore.c');
    const source = fs.readFileSync(agentcorePath, 'utf8');
    const startMarker = 'void MeshServer_Agent_SelfTest(MeshAgentHostContainer *agent)';
    const endMarker = 'void MeshServer_Connect(MeshAgentHostContainer *agent)';
    const start = source.indexOf(startMarker);
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    const functionSource = start >= 0 && end > start ? source.slice(start, end) : '';

    const okIndex = functionSource.indexOf('printf("[OK]\\n");');
    const executeIndex = functionSource.indexOf('ILibDuktape_ScriptContainer_ExecuteByteCode');
    const missingCoreIndex = functionSource.indexOf('if (CoreModuleLen <= 4)');
    const missingCoreWindow = missingCoreIndex >= 0 ? functionSource.slice(missingCoreIndex, missingCoreIndex + 512) : '';
    const report = {
        agentcorePath,
        checks: {
            missingCoreIgnoresCachedServiceName: !/CoreModuleLen\s*<=\s*4[\s\S]{0,160}serviceName/.test(functionSource),
            missingCoreFailsFast: missingCoreWindow.includes('CoreModule missing from datastore') &&
                missingCoreWindow.includes('exit(1);'),
            readFailureFailsFast: /failed to read CoreModule from datastore[\s\S]*?exit\(1\);/.test(functionSource),
            compileFailureFailsFast: /Error Executing MeshCore: %s[\s\S]*?exit\(1\);/.test(functionSource),
            printsOkAfterSuccessfulCoreLoad: okIndex > executeIndex && executeIndex >= 0
        }
    };

    for (const [name, passed] of Object.entries(report.checks)) {
        assert(passed, `${name} failed`);
    }

    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}

main();
