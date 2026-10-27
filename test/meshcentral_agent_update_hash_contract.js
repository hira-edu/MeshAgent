const fs = require('fs');
const path = require('path');
const { forkFile, installedPackageDir } = require('./lib/meshcentral_paths');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

// Every input is required: a missing or empty file fails the contract and says what it was for.
function read(relPath, purpose) {
    const fullPath = path.resolve(relPath);
    let text;
    try {
        text = fs.readFileSync(fullPath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`required input missing: ${fullPath} (${purpose})`, { cause: error });
        }
        throw error;
    }
    assert(text.trim().length > 0, `required input is empty: ${fullPath} (${purpose})`);
    return text.replace(/\r\n?/g, '\n');
}

function main() {
    const source = read(forkFile('meshagent.js'), 'tracked MeshCentral meshagent.js whose agent update hash handling is checked');
    const packageSource = read(path.join(installedPackageDir().dir, 'meshagent.js'), 'installed MeshCentral package copy of meshagent.js, which the server runs');
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
        packageSource.includes('(agentExeInfo.fileHash != null && agentExeInfo.fileHash == agentHash)') &&
        packageSource.includes('obj.agentUpdate.agentUpdateHash = obj.agentExeInfo.hash;'),
        'installed MeshCentral package copy must match agent update hash contract'
    );

    console.log(JSON.stringify({
        success: true,
        checks: {
            compareAcceptsFileHash: true,
            ramUpdateUsesNativeNormalizedHash: true,
            httpUpdateUsesFileHashHex: true,
            installedPackageCopyAligned: true,
            installedPackageCopyPresent: true
        }
    }, null, 2));
}

main();
