const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

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

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function runCommand(file, args, options = {}) {
    const result = childProcess.spawnSync(file, args, {
        cwd: options.cwd || process.cwd(),
        windowsHide: true,
        encoding: 'utf8',
        timeout: options.timeoutMs || 0
    });
    if (result.error) {
        throw result.error;
    }
    return result;
}

async function waitForReadableFile(filePath, timeoutMs) {
    const start = Date.now();
    while ((Date.now() - start) < timeoutMs) {
        if (fs.existsSync(filePath)) {
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                if (content.trim().length > 0) {
                    return content;
                }
            } catch (error) {
                const message = String(error && error.message ? error.message : error);
                if (!(/being used by another process/i.test(message) || /resource busy or locked/i.test(message) || /EBUSY/i.test(message))) {
                    throw error;
                }
            }
        }
        await sleep(500);
    }
    throw new Error(`Timed out waiting for probe report: ${filePath}`);
}

function readJsonText(label, text) {
    const raw = String(text || '');
    const trimmed = raw.trim();

    try {
        return JSON.parse(trimmed);
    } catch (error) {
        const lines = trimmed
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter((line) => line.length > 0);

        for (let i = lines.length - 1; i >= 0; --i) {
            const line = lines[i];
            if (!line.startsWith('{') && !line.startsWith('[')) {
                continue;
            }
            try {
                return JSON.parse(line);
            } catch (lineError) {
                // Ignore non-JSON trace lines and keep walking backward toward the final JSON payload.
            }
        }

        throw new Error(`Failed to parse ${label} JSON\ncontent:\n${text}\nparse error: ${error.message}`);
    }
}

function queryServiceName(exePath) {
    const result = runCommand(exePath, ['-name'], {
        cwd: path.dirname(exePath),
        timeoutMs: 60000
    });
    if (result.status !== 0) {
        throw new Error(`Failed to query service name\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    }
    const serviceName = String(result.stdout || '').trim();
    if (!serviceName) {
        throw new Error(`Service name probe returned an empty value for ${exePath}`);
    }
    return serviceName;
}

function resolvePsExecPath() {
    const candidates = [];
    if (process.env.PSEXEC_PATH) {
        candidates.push(process.env.PSEXEC_PATH);
    }
    if (process.env.LOCALAPPDATA) {
        candidates.push(path.join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Links', 'PsExec.exe'));
    }
    if (process.env.USERPROFILE) {
        candidates.push(path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links', 'PsExec.exe'));
    }

    for (const candidate of candidates) {
        if (candidate && fs.existsSync(candidate)) {
            return path.resolve(candidate);
        }
    }

    const whereResult = runCommand('where.exe', ['PsExec.exe'], { timeoutMs: 15000 });
    if (whereResult.status === 0) {
        const first = String(whereResult.stdout || '')
            .split(/\r?\n/)
            .map((line) => line.trim())
            .find((line) => line.length > 0);
        if (first) {
            return first;
        }
    }

    throw new Error('PsExec.exe not found. Set PSEXEC_PATH or install PsExec into PATH/WinGet Links.');
}

function resolveRundll32Path() {
    const systemRoot = process.env.SystemRoot || 'C:\\Windows';
    const candidate = path.join(systemRoot, 'System32', 'rundll32.exe');
    if (!fs.existsSync(candidate)) {
        throw new Error(`rundll32.exe not found at ${candidate}`);
    }
    return candidate;
}

function resolveBridgeDllPath(exePath, explicitDllPath) {
    const candidates = [];
    const normalizedExePath = exePath ? path.resolve(exePath) : '';
    let brandedDllName = '';

    if (explicitDllPath) {
        candidates.push(path.resolve(explicitDllPath));
    }
    if (process.env.STEALTH_KVM_BRIDGE_DLL) {
        candidates.push(path.resolve(process.env.STEALTH_KVM_BRIDGE_DLL));
    }
    if (normalizedExePath) {
        const exeDir = path.dirname(normalizedExePath);
        const exeName = path.basename(normalizedExePath, path.extname(normalizedExePath));
        const parentDir = path.dirname(exeDir);
        const brandingHeaderPath = path.resolve('meshcore', 'config', 'branding_profile.local.h');
        if (fs.existsSync(brandingHeaderPath)) {
            const brandingHeader = fs.readFileSync(brandingHeaderPath, 'utf8');
            const match = brandingHeader.match(/MESH_AGENT_SVCHOST_DLL\s+TEXT\(\"([^\"]+)\"\)/);
            if (match) {
                brandedDllName = match[1];
            }
        }

        if (brandedDllName) {
            candidates.push(path.join(exeDir, brandedDllName));
        }
        candidates.push(path.join(exeDir, 'svchost_payload.dll'));
        candidates.push(path.join(exeDir, `${exeName}.dll`));
        candidates.push(path.join(exeDir, 'MeshService-2022.dll'));
        candidates.push(path.join(parentDir, 'StealthLab_DLL', `${exeName}.dll`));
        candidates.push(path.join(parentDir, 'StealthLab_DLL', 'MeshService-2022.dll'));
    }

    for (const candidate of candidates) {
        if (candidate && fs.existsSync(candidate)) {
            return candidate;
        }
    }

    throw new Error(`Unable to resolve KVM bridge DLL for ${normalizedExePath || '(no exe)'}${explicitDllPath ? ` (explicit=${path.resolve(explicitDllPath)})` : ''}`);
}

function buildKvmPacket(type, payload) {
    const body = Buffer.isBuffer(payload) ? payload : Buffer.alloc(0);
    const packet = Buffer.alloc(4 + body.length);
    packet.writeUInt16BE(type, 0);
    packet.writeUInt16BE(packet.length, 2);
    body.copy(packet, 4);
    return packet;
}

function buildSystemProbeScript(scriptPath, exePath, probeArgument, reportPath) {
    const lines = [
        '@echo off',
        `"${exePath}" ${probeArgument} > "${reportPath}" 2>&1`
    ];
    fs.writeFileSync(scriptPath, `${lines.join('\r\n')}\r\n`, 'ascii');
}

async function runSystemProbeWithPsExec(exePath, probeArgument, options = {}) {
    const prefix = options.prefix || `meshagent_kvm_probe_${process.pid}_${Date.now()}`;
    const psexecPath = options.psexecPath || resolvePsExecPath();
    const scriptPath = options.scriptPath || path.join(os.tmpdir(), `${prefix}.cmd`);
    const reportPath = options.reportPath || path.join(os.tmpdir(), `${prefix}.json`);
    const timeoutMs = options.timeoutMs || 180000;

    buildSystemProbeScript(scriptPath, exePath, probeArgument, reportPath);
    const psexec = runCommand(psexecPath, ['-accepteula', '-nobanner', '-s', scriptPath], {
        timeoutMs,
        cwd: path.dirname(exePath)
    });
    const reportContent = await waitForReadableFile(reportPath, timeoutMs);

    return {
        psexecPath,
        scriptPath,
        reportPath,
        reportContent,
        psexec
    };
}

function decodeXmlText(value) {
    return String(value || '')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, '\'')
        .replace(/&amp;/g, '&');
}

function parseUInt(value, fallback = 0) {
    const parsed = Number.parseInt(String(value || ''), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function parseEventXml(xmlText) {
    const events = [];
    const matches = String(xmlText || '').match(/<Event\b[\s\S]*?<\/Event>/g) || [];

    for (const xml of matches) {
        const data = Array.from(xml.matchAll(/<Data(?: [^>]*)?>([\s\S]*?)<\/Data>/g), (match) => decodeXmlText(match[1]));
        const providerMatch = xml.match(/<Provider Name=(['"])(.*?)\1\/>/);
        const eventIdMatch = xml.match(/<EventID(?: [^>]*)?>(\d+)<\/EventID>/);
        const recordIdMatch = xml.match(/<EventRecordID>(\d+)<\/EventRecordID>/);
        const timeMatch = xml.match(/<TimeCreated SystemTime=(['"])(.*?)\1\/>/);
        const processMatch = xml.match(/<Execution ProcessID=(['"])(\d+)\1 ThreadID=(['"])(\d+)\3\/>/);
        const levelMatch = xml.match(/<Level>(\d+)<\/Level>/);

        events.push({
            providerName: providerMatch ? providerMatch[2] : '',
            eventId: eventIdMatch ? parseUInt(eventIdMatch[1]) : 0,
            recordId: recordIdMatch ? parseUInt(recordIdMatch[1]) : 0,
            systemTime: timeMatch ? timeMatch[2] : '',
            processId: processMatch ? parseUInt(processMatch[2]) : 0,
            threadId: processMatch ? parseUInt(processMatch[4]) : 0,
            level: levelMatch ? parseUInt(levelMatch[1]) : 0,
            data,
            outcome: data[0] || '',
            pid: parseUInt(data[1]),
            sessionId: parseUInt(data[2]),
            dllPath: data[3] || '',
            tokenType: data[4] || '',
            spawnType: data[5] || '',
            errorCode: parseUInt(data[6]),
            eventTimestamp: data[7] || '',
            xml
        });
    }

    return events;
}

function buildEventQuery(providerName, eventIds, minRecordId) {
    const clauses = [
        `Provider[@Name='${providerName}']`,
        `(${eventIds.map((eventId) => `EventID=${eventId}`).join(' or ')})`
    ];
    if (minRecordId > 0) {
        clauses.push(`EventRecordID > ${minRecordId}`);
    }
    return `*[System[${clauses.join(' and ')}]]`;
}

function queryEventLog(providerName, eventIds, minRecordId, options = {}) {
    const query = buildEventQuery(providerName, eventIds, minRecordId || 0);
    const args = [
        'qe',
        'Application',
        options.reverse === false ? '/rd:false' : '/rd:true',
        `/c:${options.count || 128}`,
        '/f:xml',
        `/q:${query}`
    ];
    const result = runCommand('wevtutil', args, { timeoutMs: options.timeoutMs || 30000 });
    if (result.status !== 0) {
        throw new Error(`Event Log query failed\nquery:\n${query}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    }
    return {
        query,
        result,
        events: parseEventXml(result.stdout || '')
    };
}

function readLatestEventRecordId(providerName, eventIds) {
    const query = queryEventLog(providerName, eventIds, 0, {
        count: 1,
        reverse: true,
        timeoutMs: 30000
    });
    return query.events.length > 0 ? query.events[0].recordId : 0;
}

async function waitForEventLog(providerName, eventIds, minRecordId, predicate, options = {}) {
    const start = Date.now();
    const timeoutMs = options.timeoutMs || 30000;
    let lastQuery = null;

    while ((Date.now() - start) < timeoutMs) {
        lastQuery = queryEventLog(providerName, eventIds, minRecordId, {
            count: options.count || 256,
            reverse: false,
            timeoutMs: options.queryTimeoutMs || 30000
        });
        if (predicate(lastQuery.events)) {
            return {
                waitedMs: Date.now() - start,
                query: lastQuery.query,
                stdout: lastQuery.result.stdout || '',
                stderr: lastQuery.result.stderr || '',
                events: lastQuery.events
            };
        }
        await sleep(options.pollIntervalMs || 500);
    }

    throw new Error(`Timed out waiting for Event Log entries\nquery:\n${lastQuery ? lastQuery.query : '(not-run)'}\nstdout:\n${lastQuery ? lastQuery.result.stdout : ''}\nstderr:\n${lastQuery ? lastQuery.result.stderr : ''}`);
}

module.exports = {
    assert,
    buildKvmPacket,
    parseArgs,
    queryServiceName,
    readJsonText,
    readLatestEventRecordId,
    resolveBridgeDllPath,
    resolvePsExecPath,
    resolveRundll32Path,
    runCommand,
    runSystemProbeWithPsExec,
    sleep,
    waitForEventLog,
    waitForReadableFile,
    writeJson,
    writeText
};
