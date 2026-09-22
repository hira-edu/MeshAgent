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

function readOptional(relPath) {
    try { return read(relPath); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function main() {
    const source = read('../MeshCentral/meshagent.js');
    const packageSource = readOptional('../MeshCentral/node_modules/meshcentral/meshagent.js');
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
        ramUpdateSection.includes('obj.agentUpdate.agentUpdateHash = obj.agentExeInfo.hash;'),
        'Native RAM update must end with the normalized executable hash'
    );
    assert(
        source.includes('if (obj.agentExeInfo.fileHash != null) { cmd.hash = obj.agentExeInfo.fileHashHex; } else { cmd.hash = obj.agentExeInfo.hashhex; }'),
        'HTTP agent update command must advertise served/appended fileHashHex when present'
    );
    assert(
        packageSource == null || (packageSource.includes('(agentExeInfo.fileHash != null && agentExeInfo.fileHash == agentHash)') &&
        packageSource.includes('obj.agentUpdate.agentUpdateHash = obj.agentExeInfo.hash;')),
        'installed MeshCentral package copy must match agent update hash contract'
    );

    console.log(JSON.stringify({
        success: true,
        checks: {
            compareAcceptsFileHash: true,
            ramUpdateUsesNativeNormalizedHash: true,
            httpUpdateUsesFileHashHex: true,
            installedPackageCopyAligned: packageSource != null,
            installedPackageCopyPresent: packageSource != null
        }
    }, null, 2));
}

main();
