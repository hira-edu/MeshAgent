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

function extractSpan(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    if (start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span: ${startMarker}`);
    }
    return source.substring(start, end);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const sourcePath = path.resolve('microscript', 'ILibDuktape_HttpStream.c');
    const source = fs.readFileSync(sourcePath, 'utf8');

    const writePacket = extractSpan(
        source,
        'ILibTransport_DoneState ILibDuktape_httpStream_webSocket_WriteWebSocketPacket',
        'void ILibDuktape_httpStream_webSocket_EncodedEndSink'
    );
    const encodedPauseSink = extractSpan(
        source,
        'void ILibDuktape_httpStream_webSocket_EncodedPauseSink(',
        'void ILibDuktape_httpStream_webSocket_EncodedResumeSink_Chain'
    );
    const encodedResumeSink = extractSpan(
        source,
        'void ILibDuktape_httpStream_webSocket_EncodedResumeSink(',
        'int ILibDuktape_httpStream_webSocket_EncodedUnshiftSink'
    );
    const decodedPauseSink = extractSpan(
        source,
        'void ILibDuktape_httpStream_webSocket_DecodedPauseSink(',
        'void ILibDuktape_httpStream_webSocket_DecodedResumeSink_Chain'
    );
    const decodedResumeSink = extractSpan(
        source,
        'void ILibDuktape_httpStream_webSocket_DecodedResumeSink(',
        'int ILibDuktape_httpStream_webSocket_DecodedUnshiftSink'
    );

    const checks = {
        hasStateGuardHelper: source.includes('static ILibDuktape_WebSocket_State* ILibDuktape_httpStream_webSocket_GetState('),
        hasContextGuardHelper: source.includes('static int ILibDuktape_httpStream_webSocket_HasLiveContext('),
        hasEncodedWritableGuardHelper: source.includes('static int ILibDuktape_httpStream_webSocket_HasEncodedWritable('),
        hasDecodedWritableGuardHelper: source.includes('static int ILibDuktape_httpStream_webSocket_HasDecodedWritable('),
        writePathGuardsStateBeforeNoMasking:
            writePacket.indexOf('ILibDuktape_httpStream_webSocket_GetState(state)') >= 0 &&
            writePacket.indexOf('if (liveState == NULL) { return(ILibTransport_DoneState_ERROR); }') >= 0 &&
            writePacket.indexOf('state = liveState;') >= 0 &&
            writePacket.indexOf('flags = state->noMasking == 0 ? WEBSOCKET_MASK : 0;') >
                writePacket.indexOf('state = liveState;'),
        encodedPauseGuardsDecodedStream:
            encodedPauseSink.includes('ILibDuktape_httpStream_webSocket_GetState(user)') &&
            encodedPauseSink.includes('ILibDuktape_httpStream_webSocket_HasDecodedWritable(state)') &&
            encodedPauseSink.includes('if (state->chain == NULL || !ILibDuktape_httpStream_webSocket_HasLiveContext(state)) { return; }'),
        encodedResumeGuardsDecodedStream:
            encodedResumeSink.includes('ILibDuktape_httpStream_webSocket_GetState(user)') &&
            encodedResumeSink.includes('ILibDuktape_httpStream_webSocket_HasDecodedWritable(state)') &&
            encodedResumeSink.includes('if (state->chain == NULL || !ILibDuktape_httpStream_webSocket_HasLiveContext(state)) { return; }'),
        decodedPauseGuardsEncodedStream:
            decodedPauseSink.includes('ILibDuktape_httpStream_webSocket_GetState(user)') &&
            decodedPauseSink.includes('ILibDuktape_httpStream_webSocket_HasEncodedWritable(state)') &&
            decodedPauseSink.includes('if (state->chain == NULL || !ILibDuktape_httpStream_webSocket_HasLiveContext(state)) { return; }'),
        decodedResumeGuardsEncodedStream:
            decodedResumeSink.includes('ILibDuktape_httpStream_webSocket_GetState(user)') &&
            decodedResumeSink.includes('ILibDuktape_httpStream_webSocket_HasEncodedWritable(state)') &&
            decodedResumeSink.includes('if (state->chain == NULL || !ILibDuktape_httpStream_webSocket_HasLiveContext(state)) { return; }'),
        chainCallbacksValidateContext:
            source.includes('if (ctx == NULL || !duk_ctx_is_alive(ctx) || duk_ctx_shutting_down(ctx)) { return; }')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `websocket lifecycle contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        file: sourcePath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'websocket_state_lifecycle_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
