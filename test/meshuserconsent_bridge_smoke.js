const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error(`Unexpected argument: ${token}`); }
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

function system32Path(fileName) {
    const root = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    return path.join(root, 'System32', fileName);
}

function activeSessionId() {
    const attempts = [
        { file: system32Path('quser.exe'), args: [] },
        { file: system32Path('query.exe'), args: ['session'] },
        { file: system32Path('query.exe'), args: ['user'] }
    ];
    const outputs = [];
    for (const attempt of attempts) {
        const result = childProcess.spawnSync(attempt.file, attempt.args, { encoding: 'utf8' });
        const output = `${result.stdout || ''}\n${result.stderr || ''}`;
        outputs.push(output);
        const lines = output.split(/\r?\n/);
        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || /^SESSIONNAME\s+/i.test(line) || /^USERNAME\s+/i.test(line)) { continue; }
            if (!/\sActive\s/i.test(` ${line} `)) { continue; }
            const normalized = line.replace(/^>/, '').trim().split(/\s+/);
            for (let i = 0; i < normalized.length; ++i) {
                if (/^\d+$/.test(normalized[i])) { return parseInt(normalized[i], 10); }
            }
        }
    }
    throw new Error(`Unable to identify active session from session-tool output:\n${outputs.join('\n---\n')}`);
}

function hexByte(value) {
    const text = value.toString(16);
    return text.length < 2 ? `0${text}` : text;
}

function utf16Hex(value) {
    let ret = '';
    const text = `${value}`;
    for (let i = 0; i < text.length; ++i) {
        const code = text.charCodeAt(i);
        ret += hexByte(code & 0xff) + hexByte((code >> 8) & 0xff);
    }
    return ret;
}

function writeManifest(manifestPath, sessionId) {
    const lines = [
        '[Consent]',
        `SessionId=${sessionId}`,
        'TimeoutMs=1000',
        'TimeoutAutoAccept=1',
        `TitleHex=${utf16Hex('MeshUserConsentW smoke')}`,
        `CaptionHex=${utf16Hex('This automated test prompt will close after one second.')}`
    ];
    fs.writeFileSync(manifestPath, `${lines.join('\r\n')}\r\n`);
}

function runSmoke(options) {
    return new Promise((resolve, reject) => {
        const dllPath = path.resolve(options.dll);
        const evidenceDir = options.evidence ? path.resolve(options.evidence) : null;
        const sessionId = options.session ? parseInt(options.session, 10) : activeSessionId();
        const suffix = `${process.pid}_${Date.now()}`;
        const resultPipeName = `\\\\.\\pipe\\MeshUserConsent_${suffix}_result`;
        const manifestPath = path.join(os.tmpdir(), `MeshUserConsent_${suffix}.ini`);
        const chunks = [];
        let child = null;
        let exitCode = null;
        let nativeResult = null;
        let completed = false;
        let watchdog = null;

        function finish(error, result) {
            if (completed) { return; }
            completed = true;
            if (watchdog != null) { clearTimeout(watchdog); }
            try { server.close(); } catch (ex) { }
            try { fs.unlinkSync(manifestPath); } catch (ex) { }
            if (evidenceDir != null) {
                writeJson(path.join(evidenceDir, 'meshuserconsent_bridge_smoke.json'), {
                    success: error == null,
                    error: error ? String(error.message || error) : null,
                    dllPath,
                    sessionId,
                    resultPipeName,
                    exitCode,
                    result
                });
            }
            if (error) { reject(error); } else { resolve(result); }
        }

        function maybeFinish() {
            if (nativeResult == null || exitCode == null || completed) { return; }
            if (nativeResult.status !== 'ALLOW_TIMEOUT') {
                finish(new Error(`Unexpected consent status: ${nativeResult.status}`), nativeResult);
                return;
            }
            if (exitCode !== 0) {
                finish(new Error(`Unexpected rundll32 exit code: ${exitCode}`), nativeResult);
                return;
            }
            finish(null, nativeResult);
        }

        if (!Number.isInteger(sessionId) || sessionId <= 0) {
            reject(new Error(`Invalid active session id: ${sessionId}`));
            return;
        }

        const server = net.createServer((socket) => {
            socket.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
            socket.on('error', finish);
            socket.on('close', () => {
                try { nativeResult = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (ex) { finish(ex); return; }
                maybeFinish();
            });
        });

        server.on('error', finish);
        server.listen(resultPipeName, () => {
            writeManifest(manifestPath, sessionId);
            child = childProcess.spawn(system32Path('rundll32.exe'), [`${dllPath},MeshUserConsentW`, resultPipeName, manifestPath], {
                windowsHide: true,
                stdio: ['ignore', 'pipe', 'pipe']
            });
            child.on('error', finish);
            child.on('exit', (code) => {
                exitCode = code;
                maybeFinish();
            });
        });

        watchdog = setTimeout(() => {
            try { if (child != null) { child.kill(); } } catch (ex) { }
            finish(new Error('Timed out waiting for MeshUserConsentW result.'));
        }, 30000);
    });
}

async function main() {
    const args = parseArgs(process.argv);
    if (!args.dll) { throw new Error('--dll is required'); }
    const result = await runSmoke(args);
    console.log(JSON.stringify({ success: true, result }));
}

if (require.main === module) {
    main().catch((error) => {
        console.error(error && error.stack ? error.stack : String(error));
        process.exit(1);
    });
}
