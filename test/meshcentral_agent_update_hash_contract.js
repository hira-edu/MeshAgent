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

function main() {
    const source = read('../MeshCentral/meshagent.js');
    const packageSource = read('../MeshCentral/node_modules/meshcentral/meshagent.js');
    const compareStart = source.indexOf('function compareAgentBinaryHash(agentExeInfo, agentHash)');
    assert(compareStart >= 0, 'compareAgentBinaryHash is missing');
    const compareEnd = source.indexOf('// Request that the core dump file', compareStart);
    assert(compareEnd > compareStart, 'compareAgentBinaryHash section end marker missing');
    const compareSection = source.substring(compareStart, compareEnd);

    const ramUpdateStart = source.indexOf('// Send uncompressed data');
    assert(ramUpdateStart >= 0, 'uncompressed RAM update section missing');
    const ramUpdateSection = source.substring(ramUpdateStart, source.indexOf('const len = Math.min', ramUpdateStart));

    assert(
        compareSection.includes('(agentExeInfo.fileHash != null && agentExeInfo.fileHash == agentHash)'),
        'agent binary compare must accept served/appended fileHash'
    );
    assert(
        ramUpdateSection.includes('obj.agentUpdate.agentUpdateHash = (obj.agentExeInfo.fileHash != null) ? obj.agentExeInfo.fileHash : obj.agentExeInfo.hash;'),
        'RAM binary update must end with served/appended fileHash when present'
    );
    assert(
        source.includes('if (obj.agentExeInfo.fileHash != null) { cmd.hash = obj.agentExeInfo.fileHashHex; } else { cmd.hash = obj.agentExeInfo.hashhex; }'),
        'HTTP agent update command must advertise served/appended fileHashHex when present'
    );
    assert(
        compareSection.includes("if ((agentExeInfo.id == 4) && (agentExeInfo.fileHash != null)) return 1;"),
        'Windows x64 svchost agents with fileHash metadata must use native update routing'
    );
    assert(
        packageSource.includes('(agentExeInfo.fileHash != null && agentExeInfo.fileHash == agentHash)') &&
        packageSource.includes("if ((agentExeInfo.id == 4) && (agentExeInfo.fileHash != null)) return 1;") &&
        packageSource.includes('obj.agentUpdate.agentUpdateHash = (obj.agentExeInfo.fileHash != null) ? obj.agentExeInfo.fileHash : obj.agentExeInfo.hash;'),
        'installed MeshCentral package copy must match agent update hash/native routing contract'
    );

    console.log(JSON.stringify({
        success: true,
        checks: {
            compareAcceptsFileHash: true,
            ramUpdateUsesFileHash: true,
            httpUpdateUsesFileHashHex: true,
            win64SvchostUsesNativeUpdate: true,
            installedPackageCopyAligned: true
        }
    }, null, 2));
}

main();
