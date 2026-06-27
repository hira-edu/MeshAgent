#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

function usage() {
    console.error('Usage: node test/release_signing_bundle_gate.js --timestamp <stamp> --evidence-root <path> [--include-evidence <path> ...]');
}

function parseArgs(argv) {
    const args = { includes: [] };
    for (let i = 2; i < argv.length; ++i) {
        const arg = argv[i];
        if (arg === '--timestamp') {
            args.timestamp = argv[++i];
        } else if (arg === '--evidence-root') {
            args.evidenceRoot = argv[++i];
        } else if (arg === '--include-evidence') {
            args.includes.push(argv[++i]);
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }
    if (!args.timestamp || !args.evidenceRoot) {
        usage();
        process.exit(2);
    }
    return args;
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function toRepoRelative(repoRoot, filePath) {
    return path.relative(repoRoot, filePath).replace(/\\/g, '/');
}

function sha(filePath, algorithm) {
    const hash = crypto.createHash(algorithm);
    const data = fs.readFileSync(filePath);
    hash.update(data);
    return hash.digest('hex');
}

function copyFile(src, dest) {
    ensureDir(path.dirname(dest));
    fs.copyFileSync(src, dest);
}

function copyDir(src, dest) {
    ensureDir(dest);
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath);
        } else if (entry.isFile()) {
            copyFile(srcPath, destPath);
        }
    }
}

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function readUInt32(buffer, offset) {
    if (offset < 0 || offset + 4 > buffer.length) {
        return 0;
    }
    return buffer.readUInt32LE(offset);
}

function getPeCertificateTable(filePath) {
    const buffer = fs.readFileSync(filePath);
    if (buffer.length < 0x40 || buffer.toString('ascii', 0, 2) !== 'MZ') {
        return { pe: false, hasCertificateTable: false, certificateTableOffset: 0, certificateTableSize: 0 };
    }
    const peOffset = readUInt32(buffer, 0x3c);
    if (peOffset <= 0 || peOffset + 0x18 >= buffer.length || buffer.toString('ascii', peOffset, peOffset + 4) !== 'PE\u0000\u0000') {
        return { pe: false, hasCertificateTable: false, certificateTableOffset: 0, certificateTableSize: 0 };
    }
    const optionalHeaderOffset = peOffset + 0x18;
    const magic = buffer.readUInt16LE(optionalHeaderOffset);
    const dataDirectoryOffset = optionalHeaderOffset + (magic === 0x20b ? 0x70 : 0x60);
    const securityDirectoryOffset = dataDirectoryOffset + (4 * 8);
    const certificateTableOffset = readUInt32(buffer, securityDirectoryOffset);
    const certificateTableSize = readUInt32(buffer, securityDirectoryOffset + 4);
    return {
        pe: true,
        hasCertificateTable: certificateTableOffset !== 0 && certificateTableSize !== 0,
        certificateTableOffset,
        certificateTableSize,
    };
}

function run(command, cwd) {
    const result = childProcess.spawnSync(command[0], command.slice(1), {
        cwd,
        encoding: 'utf8',
        windowsHide: true,
    });
    return {
        command: command.join(' '),
        status: result.status,
        signal: result.signal,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        ok: result.status === 0,
    };
}

function compressDirectory(sourceDir, zipPath) {
    if (fs.existsSync(zipPath)) {
        fs.rmSync(zipPath, { force: true });
    }
    const tarResult = run(['tar.exe', '-a', '-cf', zipPath, '-C', sourceDir, '.'], path.dirname(sourceDir));
    if (tarResult.ok && fs.existsSync(zipPath)) {
        return tarResult;
    }
    const script = [
        '$ErrorActionPreference = "Stop"',
        `$source = ${JSON.stringify(path.join(sourceDir, '*'))}`,
        `$dest = ${JSON.stringify(zipPath)}`,
        'Compress-Archive -Path $source -DestinationPath $dest -Force',
    ].join('; ');
    const result = run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], path.dirname(sourceDir));
    if (!result.ok) {
        throw new Error(`Archive creation failed. tar: ${tarResult.stderr || tarResult.stdout}; Compress-Archive: ${result.stderr || result.stdout}`);
    }
    return result;
}

function main() {
    const args = parseArgs(process.argv);
    const repoRoot = path.resolve(__dirname, '..');
    const brandingPath = path.join(repoRoot, 'branding_config.local.json');
    const branding = readJson(brandingPath);
    const evidenceRoot = path.resolve(repoRoot, args.evidenceRoot);
    const stagingRoot = path.join(evidenceRoot, 'release-staging');
    const releaseDir = path.join(stagingRoot, 'release');
    const reportsDir = path.join(stagingRoot, 'reports');
    const evidenceDir = path.join(stagingRoot, 'evidence');
    const artifactsDir = path.join(repoRoot, 'docs', 'testing', 'artifacts');
    const bundlePath = path.join(artifactsDir, `${args.timestamp}_realignment_bundle.zip`);

    if (fs.existsSync(stagingRoot)) {
        fs.rmSync(stagingRoot, { recursive: true, force: true });
    }
    ensureDir(releaseDir);
    ensureDir(reportsDir);
    ensureDir(evidenceDir);
    ensureDir(artifactsDir);

    const stagedDefinitions = [
        ['x64-agent-exe', 'meshservice/x64/StealthLab/MeshService-2022.exe', 'MeshService64.exe'],
        ['x64-agent-exe', 'meshservice/x64/StealthLab/MeshService-2022.exe', 'MeshService-2022.exe'],
        ['x64-agent-exe', 'meshservice/x64/StealthLab/MeshService-2022.exe', branding.branding.binaryName || 'diaghost.exe'],
        ['win32-agent-exe', 'meshservice/StealthLab/MeshService-2022.exe', 'MeshService.exe'],
        ['service-dll', 'meshservice/x64/StealthLab_DLL/MeshService-2022.dll', 'MeshService-2022.dll'],
        ['service-dll', 'meshservice/x64/StealthLab_DLL/MeshService-2022.dll', branding.branding.serviceDllName || 'diagsvc.dll'],
        ['provisioning-manifest', 'meshservice/x64/StealthLab/MeshService-2022.msh', 'MeshService-2022.msh'],
        ['provisioning-manifest', 'meshservice/x64/StealthLab/MeshService-2022.msh', `${branding.branding.serviceName || 'WinDiagnosticHost'}.msh`],
        ['agent-database', 'meshservice/x64/StealthLab/MeshService-2022.db', 'MeshService-2022.db'],
        ['agent-database', 'meshservice/x64/StealthLab/MeshService-2022.db', branding.artifacts.databaseName || 'diaghost.db'],
    ];

    const stagedFiles = [];
    for (const [role, sourceRel, stagedName] of stagedDefinitions) {
        const source = path.join(repoRoot, sourceRel);
        if (!fs.existsSync(source)) {
            throw new Error(`Required release input missing: ${sourceRel}`);
        }
        const dest = path.join(releaseDir, stagedName);
        copyFile(source, dest);
        const stat = fs.statSync(dest);
        stagedFiles.push({
            role,
            source: sourceRel.replace(/\\/g, '/'),
            stagedAs: `release/${stagedName}`,
            path: toRepoRelative(repoRoot, dest),
            size: stat.size,
            modifiedUtc: stat.mtime.toISOString(),
            sha256: sha(dest, 'sha256'),
            sha384: sha(dest, 'sha384'),
        });
    }

    const enforceSigning = Boolean(branding.security && branding.security.enforceSigning);
    const allowedThumbprints = ((branding.security && branding.security.allowedSigners) || [])
        .map((signer) => String(signer.thumbprint || '').replace(/\s+/g, '').toUpperCase())
        .filter(Boolean);
    const signingReport = stagedFiles
        .filter((entry) => entry.role.endsWith('exe') || entry.role === 'service-dll')
        .map((entry) => {
            const fullPath = path.join(stagingRoot, entry.stagedAs);
            const peCertificateTable = getPeCertificateTable(fullPath);
            let status = 'unsigned-allowed-by-branding-policy';
            let ok = !enforceSigning;
            if (peCertificateTable.hasCertificateTable) {
                status = enforceSigning ? 'certificate-table-present-needs-signer-validation' : 'certificate-table-present-signing-not-enforced';
                ok = !enforceSigning;
            } else if (enforceSigning) {
                status = 'unsigned-blocked-by-branding-policy';
            }
            return {
                stagedAs: entry.stagedAs,
                role: entry.role,
                sha256: entry.sha256,
                signingRequired: enforceSigning,
                allowedThumbprints,
                status,
                ok,
                peCertificateTable,
            };
        });

    const checksums = [];
    for (const entry of stagedFiles) {
        checksums.push(`${entry.sha256}  ${entry.stagedAs}`);
        checksums.push(`${entry.sha384}  ${entry.stagedAs}.sha384`);
    }
    fs.writeFileSync(path.join(releaseDir, 'checksums.txt'), `${checksums.join('\n')}\n`);

    const reports = [
        'docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md',
        'docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md',
        'docs/testing/20260507_DIAGNOSTICHOST_KVM_AUDIT_REMEDIATION.md',
        'docs/files/meshagent_release_checklist.md',
    ];
    for (const report of reports) {
        const source = path.join(repoRoot, report);
        if (fs.existsSync(source)) {
            copyFile(source, path.join(reportsDir, path.basename(report)));
        }
    }

    const evidenceInputs = args.includes.map((includePath) => path.resolve(repoRoot, includePath));
    for (const input of evidenceInputs) {
        if (!fs.existsSync(input)) {
            throw new Error(`Evidence input missing: ${input}`);
        }
        copyDir(input, path.join(evidenceDir, path.basename(input)));
    }

    const git = {
        meshAgentStatus: run(['git', 'status', '--short'], repoRoot),
        meshAgentDiffStat: run(['git', 'diff', '--stat'], repoRoot),
    };

    const releaseManifest = {
        generatedUtc: new Date().toISOString(),
        repoRoot,
        branding: {
            serviceName: branding.branding.serviceName,
            displayName: branding.branding.displayName,
            binaryName: branding.branding.binaryName,
            serviceDllName: branding.branding.serviceDllName,
            installRoot: branding.branding.installRoot,
        },
        signing: {
            enforceSigning,
            allowedThumbprints,
        },
        stagedFiles,
        evidenceInputs: evidenceInputs.map((entry) => toRepoRelative(repoRoot, entry)),
        git,
    };

    fs.writeFileSync(path.join(reportsDir, 'release_manifest.json'), `${JSON.stringify(releaseManifest, null, 2)}\n`);
    fs.writeFileSync(path.join(reportsDir, 'signing_report.json'), `${JSON.stringify(signingReport, null, 2)}\n`);

    const compressResult = compressDirectory(stagingRoot, bundlePath);
    const bundleStat = fs.statSync(bundlePath);
    const success = signingReport.every((entry) => entry.ok);
    const summaryLines = [
        `GENERATED_UTC=${releaseManifest.generatedUtc}`,
        `SUCCESS=${success}`,
        `SIGNING_ENFORCEMENT=${enforceSigning}`,
        `ALLOWED_SIGNER_COUNT=${allowedThumbprints.length}`,
        `STAGED_FILE_COUNT=${stagedFiles.length}`,
        `SIGNING_CHECK_COUNT=${signingReport.length}`,
        `EVIDENCE_INPUT_COUNT=${evidenceInputs.length}`,
        `BUNDLE_PATH=${bundlePath}`,
        `BUNDLE_SHA256=${sha(bundlePath, 'sha256')}`,
        `BUNDLE_SHA384=${sha(bundlePath, 'sha384')}`,
        `BUNDLE_SIZE=${bundleStat.size}`,
        `CHECKSUMS=${path.join(releaseDir, 'checksums.txt')}`,
        `SIGNING_REPORT=${path.join(reportsDir, 'signing_report.json')}`,
        `RELEASE_MANIFEST=${path.join(reportsDir, 'release_manifest.json')}`,
        `COMPRESS_STATUS=${compressResult.status}`,
    ];
    for (const entry of signingReport) {
        summaryLines.push(`SIGNING_STATUS ${entry.stagedAs} ${entry.status}`);
    }
    fs.writeFileSync(path.join(evidenceRoot, 'summary.txt'), `${summaryLines.join('\n')}\n`);
    console.log(summaryLines.join('\n'));

    if (!success) {
        process.exit(1);
    }
}

try {
    main();
} catch (err) {
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
}
