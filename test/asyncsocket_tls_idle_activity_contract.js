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
    const end = start >= 0 ? source.indexOf(endMarker, start + startMarker.length) : -1;
    if (start < 0 || end < 0 || end <= start) {
        throw new Error(`Unable to extract source span: ${startMarker}`);
    }
    return source.slice(start, end);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const sourcePath = path.resolve('microstack', 'ILibAsyncSocket.c');
    const source = fs.readFileSync(sourcePath, 'utf8');

    const helper = extractSpan(
        source,
        'static void ILibAsyncSocket_RecordSendActivity',
        'void ILibAsyncSocket_PostSelect'
    );
    const sendToMultiWrite = extractSpan(
        source,
        'ILibAsyncSocket_SendStatus ILibAsyncSocket_SendTo_MultiWrite',
        '/*! \\fn ILibAsyncSocket_Disconnect'
    );
    const tlsImmediateSend = extractSpan(
        sendToMultiWrite,
        '#ifndef MICROSTACK_NOTLS',
        '// If we got here, we aren\'t doing TLS'
    );
    const nonTlsImmediateSend = extractSpan(
        sendToMultiWrite,
        '// If we got here, we aren\'t doing TLS',
        'return (retVal);'
    );
    const tlsPartialSend = extractSpan(
        tlsImmediateSend,
        'if (bytesSent > 0)',
        'else if (bytesSent < 0)'
    );
    const tlsCompleteSend = extractSpan(
        tlsImmediateSend,
        'else if (bytesSent == module->writeBioBuffer->length)',
        'else'
    );
    const nonTlsSendActivity = extractSpan(
        nonTlsImmediateSend,
        '// BUGFIX: Reset idle timeout when sending data',
        '}'
    );

    const checks = {
        hasSharedActivityHelper:
            helper.includes('bytesSent > 0') &&
            helper.includes('module->timeout_milliSeconds != 0') &&
            helper.includes('module->timeout_lastActivity = ILibGetUptime();'),
        tlsPartialImmediateSendRefreshesIdle:
            tlsPartialSend.includes('module->TotalBytesSent += bytesSent;') &&
            tlsPartialSend.includes('ILibAsyncSocket_RecordSendActivity(module, bytesSent);'),
        tlsCompleteImmediateSendRefreshesIdle:
            tlsCompleteSend.includes('module->TotalBytesSent += bytesSent;') &&
            tlsCompleteSend.includes('ILibAsyncSocket_RecordSendActivity(module, bytesSent);'),
        tlsWouldBlockDoesNotFakeActivity:
            !extractSpan(tlsImmediateSend, 'else if (bytesSent < 0)', 'retVal = ILibAsyncSocket_NOT_ALL_DATA_SENT_YET;')
                .includes('ILibAsyncSocket_RecordSendActivity(module, bytesSent);'),
        nonTlsImmediateSendUsesSameHelper:
            nonTlsSendActivity.includes('ILibAsyncSocket_RecordSendActivity(module, bytesSent);'),
        helperUsedByBothTlsAndNonTlsImmediatePaths:
            (sendToMultiWrite.match(/ILibAsyncSocket_RecordSendActivity\(module, bytesSent\);/g) || []).length >= 3
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `${name} failed`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        file: sourcePath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'asyncsocket_tls_idle_activity_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `SOURCE=${sourcePath}`,
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
