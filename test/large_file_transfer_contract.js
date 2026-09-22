const fs = require('fs');
const path = require('path');
const vm = require('vm');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const key = argv[i];
        if (!key.startsWith('--')) throw new Error(`Unexpected argument: ${key}`);
        if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) { args[key.substring(2)] = true; continue; }
        args[key.substring(2)] = argv[++i];
    }
    return args;
}

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    if (start < 0) throw new Error(`Missing function: ${signature}`);
    const brace = source.indexOf('{', start);
    let depth = 0;
    for (let i = brace; i < source.length; ++i) {
        if (source[i] === '{') depth += 1;
        if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) return source.substring(start, i + 1);
        }
    }
    throw new Error(`Unterminated function: ${signature}`);
}

function exerciseCleanupHelpers(source) {
    const closed = [];
    const removed = [];
    const sandbox = {
        fs: {
            closeSync(fd) { closed.push(fd); if (fd === 99) throw new Error('injected close failure'); },
            unlinkSync(file) { removed.push(file); }
        }
    };
    vm.runInNewContext([
        extractFunction(source, 'function closeFileUpload('),
        extractFunction(source, 'function closeFileDownload('),
        extractFunction(source, 'function closeBasicFileDownload(')
    ].join('\n'), sandbox);

    const normalSocket = { filedownload: { id: 1, f: 7 } };
    sandbox.closeFileDownload(normalSocket);
    assert(normalSocket.filedownload == null, 'download state must be deleted after close');
    assert(closed.includes(7), 'download descriptor must be closed');

    const throwingSocket = { filedownload: { id: 2, f: 99 } };
    sandbox.closeFileDownload(throwingSocket);
    assert(throwingSocket.filedownload == null, 'download state must be deleted when close throws');

    const upload = { uploadFile: 8, uploadFileid: 3, uploadFilePath: 'partial.bin', uploadFileSize: 20 };
    assert(sandbox.closeFileUpload(upload, true) === true, 'successful upload close must be reported');
    assert(upload.uploadFile == null && upload.uploadFileid == null && upload.uploadFilePath == null && upload.uploadFileSize == null, 'upload metadata must be cleared');
    assert(closed.includes(8) && removed.includes('partial.bin'), 'canceled partial upload must be closed and removed');

    const stream = { paused: false, unpiped: false, pause() { this.paused = true; }, unpipe() { this.unpiped = true; } };
    const request = { downloadFile: stream };
    sandbox.closeBasicFileDownload(request, {});
    assert(stream.paused && stream.unpiped && request.downloadFile == null, 'protocol 10 stream must be paused, unpiped, and cleared');
}

function main() {
    const args = parseArgs(process.argv);
    const meshCentralRoot = path.resolve(args.meshcentral || path.join('..', 'MeshCentral'));
    const fsSource = fs.readFileSync(path.resolve('microscript', 'ILibDuktape_fs.c'), 'utf8');
    const corePaths = ['agents/meshcore.js', 'agents/meshcore.min.js', 'agents/recoverycore.js'];
    const coreSources = corePaths.map((relativePath) => ({ relativePath, source: fs.readFileSync(path.join(meshCentralRoot, relativePath), 'utf8') }));

    const checks = {
        readStreamHasPerTurnBudget:
            fsSource.includes('#define FS_READSTREAM_MAX_BYTES_PER_TURN (256 * 1024)') &&
            fsSource.includes('bytesReadThisTurn < FS_READSTREAM_MAX_BYTES_PER_TURN') &&
            fsSource.includes('bytesReadThisTurn += data->bytesRead;'),
        readStreamSchedulesCooperativeContinuation:
            fsSource.includes('ILibDuktape_fs_readStream_ScheduleResume(data, sender);') &&
            fsSource.includes('ILibDuktape_Immediate(data->ctx, (void*[]) { data, sender, NULL }, 2, ILibDuktape_fs_readStream_ResumeLater)') &&
            fsSource.includes('duk_put_prop_string(data->ctx, -2, "self");'),
        pausedReadStreamDoesNotSelfSchedule:
            fsSource.includes('if (sender->paused == 0 && data->bytesRead > 0 && (data->bytesLeft < 0 || data->bytesLeft > 0))'),
        allCoresCloseEveryFileTransferSurface: coreSources.every(({ source }) =>
            source.includes('function closeFileUpload(') &&
            source.includes('function closeFileDownload(') &&
            source.includes('function closeBasicFileDownload(') &&
            source.includes('closeFileUpload(this.httprequest, false);') &&
            source.includes('closeFileDownload(this);') &&
            source.includes('closeBasicFileDownload(this.httprequest, this);')),
        allCoresCloseReplacementAndStoppedDownloads: coreSources.every(({ source }) =>
            source.includes('closeFileDownload(this); this.write({ action: \'download\', sub: \'cancel\'') &&
            source.includes("(cmd.sub == 'stop') || (cmd.sub == 'cancel')") &&
            source.includes("(cmd.sub == 'cancel')) { closeFileDownload(this);")),
        allCoresCloseReadFailures: coreSources.every(({ source }) =>
            source.includes('catch (') &&
            source.includes('closeFileDownload(this); this.write({ action: \'download\', sub: \'cancel\'')),
        allCoresBoundInitialDownloadWork: coreSources.every(({ source }) => !source.includes('while (sendNextBlock > 0)')),
        allCoresCloseUploadFailures: coreSources.every(({ source }) =>
            source.includes("closeFileUpload(this.httprequest, false); sendConsoleText('FileUpload Error')") &&
            source.includes("action: 'uploaderror'")),
        allCoresRemoveCanceledPartials: coreSources.every(({ source }) => source.includes('closeFileUpload(this.httprequest, true);')),
        allCoresAcceptDescriptorZero: coreSources.every(({ source }) =>
            source.includes('if (request.uploadFile != null)') &&
            source.includes('if (this.httprequest.uploadFile != null)'))
    };

    for (const { relativePath, source } of coreSources) {
        exerciseCleanupHelpers(source);
        checks[`cleanupHelpersExecute:${relativePath}`] = true;
    }
    for (const [name, passed] of Object.entries(checks)) assert(passed, `large-file transfer contract failed: ${name}`);

    process.stdout.write(JSON.stringify({
        generatedUtc: new Date().toISOString(),
        success: true,
        meshCentralRoot,
        checks
    }, null, 2) + '\n');
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
