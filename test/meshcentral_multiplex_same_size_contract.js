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

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const multiplexPath = path.resolve('..', 'MeshCentral', 'meshdesktopmultiplex.js');
    const source = fs.readFileSync(multiplexPath, 'utf8');
    const startMarker = '            case 7: // Screen Size, clear the screen state and compute the tile count';
    const endMarker = '            case 11: // GetDisplays';
    const start = source.indexOf(startMarker);
    const end = start >= 0 ? source.indexOf(endMarker, start) : -1;
    const block = start >= 0 && end > start ? source.slice(start, end) : '';

    const checks = {
        screenCaseLocated: block.length > 0,
        dropsSameSizeScreenPackets: block.includes('if ((obj.width === data.readUInt16BE(4)) && (obj.height === data.readUInt16BE(6))) break;'),
        updatesScreenDimensions: block.includes('obj.width = data.readUInt16BE(4);') &&
            block.includes('obj.height = data.readUInt16BE(6);'),
        resetsImageCache: block.includes('obj.screen = new Array(obj.swidth * obj.sheight);') &&
            block.includes('obj.imagesCount = 0;') &&
            block.includes('obj.imagesCounters = {};') &&
            block.includes('obj.images = {};'),
        reanchorsStreamAtScreenPacket: block.includes('obj.firstData = obj.counter;') &&
            block.includes('obj.lastData = obj.counter;'),
        replaysResetToExistingViewers: block.includes('v.dataPtr = obj.counter;') &&
            block.includes('if (v.sending == false) { sendViewerNext(v); }')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        multiplexPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'meshcentral_multiplex_same_size_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `MULTIPLEX_PATH=${multiplexPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
