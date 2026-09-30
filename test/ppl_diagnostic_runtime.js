const fs = require('fs');
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

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    assert(process.platform === 'win32', 'process protection diagnostics require Windows');
    assert(process.env.SystemRoot, 'SystemRoot is unavailable');
    const powershell = path.win32.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    // Read the same native protection class as Monitor_QueryProcessProtectionByPid.
    // This is a diagnostic probe, not an agent runtime or a removed EXE status mode.
    const script = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ProtectionProbe {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr handle, int infoClass, out byte value, int size, IntPtr returned);
    public static int Query(int pid) {
        IntPtr handle = OpenProcess(0x1000, false, pid);
        if (handle == IntPtr.Zero) return -1;
        try { byte value; return NtQueryInformationProcess(handle, 61, out value, 1, IntPtr.Zero) >= 0 ? value : -1; }
        finally { CloseHandle(handle); }
    }
}
'@
$processes = @(Get-Process)
$queried = 0
$entries = @($processes | ForEach-Object {
    $level = [ProtectionProbe]::Query($_.Id)
    if ($level -ge 0) {
        $queried++
        $kind = $level -band 7
        if ($kind -ne 0) {
            [pscustomobject]@{ processId=$_.Id; imageName=$_.ProcessName; protectionLevel=$level; isProtectedLight=($kind -eq 1); type=$(if ($kind -eq 1) { 'ProtectedLight' } elseif ($kind -eq 2) { 'Protected' } else { 'Unknown' }) }
        }
    }
})
[pscustomobject]@{ phase='process-protection'; processProtection=[pscustomobject]@{ collected=($queried -gt 0); scannedProcessCount=$processes.Count; queriedProcessCount=$queried; protectedProcessCount=$entries.Count; protectedLightCount=@($entries | Where-Object isProtectedLight).Count; entries=$entries } } | ConvertTo-Json -Depth 6 -Compress
`;
    const result = childProcess.spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
        windowsHide: true, encoding: 'utf8', timeout: 60000
    });
    if (result.error) {
        throw result.error;
    }

    assert(result.status === 0, `Native diagnostic failed: exit=${result.status} ${result.stderr || ''}`);
    const stdout = (result.stdout || '').trim();
    const stderr = result.stderr || '';
    let json = null;

    try {
        json = JSON.parse(stdout);
    } catch (error) {
        throw new Error(`Failed to parse native process-protection JSON\nstdout:\n${stdout}\nstderr:\n${stderr}\nparse error: ${error.message}`);
    }

    assert(json.phase === 'process-protection', `unexpected phase ${json.phase}`);
    assert(json.processProtection && json.processProtection.collected === true, 'processProtection diagnostics were not collected');
    assert(Array.isArray(json.processProtection.entries), 'processProtection.entries is not an array');
    assert(json.processProtection.protectedProcessCount > 0, 'no protected processes were reported');
    assert(json.processProtection.protectedLightCount > 0, 'no ProtectedLight processes were reported');

    const protectedLightEntries = json.processProtection.entries.filter((entry) => entry && entry.isProtectedLight === true);
    assert(protectedLightEntries.length > 0, 'no ProtectedLight entries were present in the diagnostics array');
    assert(protectedLightEntries.every((entry) => entry.type === 'ProtectedLight'), 'ProtectedLight entries did not report the expected type');

    const report = {
        generatedUtc: new Date().toISOString(),
        diagnosticProvider: "NtQueryInformationProcess(ProcessProtectionInformation)",
        exitCode: result.status,
        success: true,
        diagnostics: json,
        protectedLightImageNames: protectedLightEntries.map((entry) => entry.imageName)
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'ppl_diagnostic_runtime.json'), report);
        writeText(path.join(evidenceDir, 'process_protection.json'), stdout + '\n');
        writeText(path.join(evidenceDir, 'stderr.txt'), stderr);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `EXIT_CODE=${report.exitCode}`,
            `PROTECTED_PROCESS_COUNT=${json.processProtection.protectedProcessCount}`,
            `PROTECTED_LIGHT_COUNT=${json.processProtection.protectedLightCount}`,
            `PROTECTED_LIGHT_IMAGES=${report.protectedLightImageNames.join(',')}`
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
