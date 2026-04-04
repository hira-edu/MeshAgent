const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function evaluateStandard(source) {
    return {
        usesStockAccumulatorState:
            source.includes('var cmdAccCmd = 0, cmdAccCmdSize = 0, cmdAccLen = 0, cmdAcc = [];'),
        ignoresShortFramesWithoutAccumulator:
            source.includes('if ((cmdAccLen == 0) && (e.data.byteLength < 4)) return;'),
        accumulatesFragmentsUntilCmdSize:
            source.includes('if (cmdAccCmdSize <= cmdAccLen)') &&
            source.includes('obj.m.ProcessBinaryCommand(cmdAccCmd, cmdAccCmdSize, tmp);'),
        unwrapsJumboFramesInline:
            source.includes('if ((cmd == 27) && (cmdsize == 8)) { cmd = (view[8] << 8) + view[9]; cmdsize = (view[5] << 16) + (view[6] << 8) + view[7]; view = view.slice(8); }'),
        omitsCustomBinaryReassemblyHelpers:
            !source.includes('xxAppendBinaryAccumulator') &&
            !source.includes('xxStoreBinaryAccumulator') &&
            !source.includes('xxProcessBinaryData')
    };
}

function evaluateMinified(source) {
    return {
        usesStockAccumulatorState:
            source.includes('var s=0,i=0,d=0,g=[];') ||
            source.includes('var c=0,t=0,s=0,i=[];'),
        ignoresShortFramesWithoutAccumulator:
            source.includes('0==d&&e.data.byteLength<4') ||
            source.includes('0==s&&e.data.byteLength<4'),
        accumulatesFragmentsUntilCmdSize:
            (source.includes('i<=d') && source.includes('ProcessBinaryCommand(s,i,a)')) ||
            (source.includes('c<=s') && source.includes('ProcessBinaryCommand(c,t,')),
        unwrapsJumboFramesInline:
            source.includes('27==u&&8==f') ||
            source.includes('27==a&&8==c'),
        omitsCustomBinaryReassemblyHelpers:
            !source.includes('xxAppendBinaryAccumulator') &&
            !source.includes('xxStoreBinaryAccumulator') &&
            !source.includes('xxProcessBinaryData')
    };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const redirPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1.js');
    const redirMinPath = path.resolve('..', 'MeshCentral', 'public', 'scripts', 'agent-redir-ws-0.1.1-min.js');
    const source = fs.readFileSync(redirPath, 'utf8');
    const sourceMin = fs.readFileSync(redirMinPath, 'utf8');

    const checks = {
        standard: evaluateStandard(source),
        minified: evaluateMinified(sourceMin)
    };

    for (const [assetName, assetChecks] of Object.entries(checks)) {
        for (const [name, passed] of Object.entries(assetChecks)) {
            assert(passed, `${assetName}.${name} failed`);
        }
    }

    const report = {
        redirPath,
        redirMinPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_agent_redir_binary_frame_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `REDIR_PATH=${redirPath}`,
            `REDIR_MIN_PATH=${redirMinPath}`,
            'SUCCESS=true',
            `STANDARD_CHECKS=${Object.entries(checks.standard).map(([name, passed]) => `${name}:${passed}`).join(',')}`,
            `MINIFIED_CHECKS=${Object.entries(checks.minified).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
