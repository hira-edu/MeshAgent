const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_EXPECTED_ARTIFACTS = [
    {
        id: 'MeshService64.exe',
        signed: true,
        candidates: [
            'dist/MeshService64.exe',
            'artifacts/MeshService64.exe',
            'meshservice/x64/StealthLab/MeshService-2022.exe',
            'meshservice/x64/Release/MeshService-2022.exe'
        ]
    },
    {
        id: 'MeshService.exe',
        signed: true,
        candidates: [
            'dist/MeshService.exe',
            'artifacts/MeshService.exe',
            'meshservice/StealthLab/MeshService-2022.exe',
            'meshservice/Win32/StealthLab/MeshService-2022.exe',
            'meshservice/Win32/Release/MeshService-2022.exe'
        ]
    },
    {
        id: 'diagsvc.dll',
        signed: true,
        candidates: [
            'dist/diagsvc.dll',
            'artifacts/diagsvc.dll',
            'meshservice/x64/StealthLab_DLL/MeshService-2022.dll',
            'meshservice/embedded/svchost_payload.dll'
        ]
    },
    {
        id: 'WinDiagnosticHost.msh',
        signed: false,
        candidates: [
            'dist/WinDiagnosticHost.msh',
            'artifacts/WinDiagnosticHost.msh',
            'meshservice/x64/StealthLab/MeshService-2022.msh',
            'meshservice/WinDiagnosticHost.msh'
        ]
    }
];

function parseArgs(argv) {
    const args = { artifacts: [] };
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const eq = token.indexOf('=');
        const key = eq >= 0 ? token.substring(2, eq) : token.substring(2);
        const inlineValue = eq >= 0 ? token.substring(eq + 1) : null;
        const nextValue = argv[i + 1];
        let value = true;
        if (inlineValue != null) {
            value = inlineValue;
        } else if (nextValue != null && !nextValue.startsWith('--')) {
            value = nextValue;
            i += 1;
        }
        if (key === 'artifact') {
            args.artifacts.push(String(value));
        } else {
            args[key] = value;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function readText(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function writeText(filePath, text) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, text, 'utf8');
}

function writeJson(filePath, value) {
    writeText(filePath, JSON.stringify(value, null, 2) + '\n');
}

function fileExists(filePath) {
    try {
        return fs.statSync(filePath).isFile();
    } catch (e) {
        return false;
    }
}

function directoryExists(dirPath) {
    try {
        return fs.statSync(dirPath).isDirectory();
    } catch (e) {
        return false;
    }
}

function relativeToRepo(filePath) {
    return path.relative(REPO_ROOT, filePath).split(path.sep).join('/');
}

function sha(filePath, algorithm) {
    const hash = crypto.createHash(algorithm);
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(1024 * 1024);
    try {
        for (;;) {
            const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
            if (bytesRead <= 0) { break; }
            hash.update(bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead));
        }
    } finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}

function statFile(filePath) {
    const stat = fs.statSync(filePath);
    return {
        size: stat.size,
        mtimeUtc: stat.mtime.toISOString()
    };
}

function readUInt16LE(buffer, offset) {
    return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : null;
}

function readUInt32LE(buffer, offset) {
    return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : null;
}

function inspectPeSignature(filePath) {
    const buffer = fs.readFileSync(filePath);
    const result = {
        isPe: false,
        hasCertificateTable: false,
        certificateTableOffset: 0,
        certificateTableSize: 0,
        status: 'not-pe'
    };

    if (buffer.length < 0x40 || buffer.toString('ascii', 0, 2) !== 'MZ') {
        return result;
    }

    const peOffset = readUInt32LE(buffer, 0x3c);
    if (peOffset == null || peOffset + 0x18 >= buffer.length || buffer.toString('ascii', peOffset, peOffset + 4) !== 'PE\u0000\u0000') {
        result.status = 'invalid-pe-header';
        return result;
    }

    const optionalHeaderOffset = peOffset + 0x18;
    const optionalHeaderMagic = readUInt16LE(buffer, optionalHeaderOffset);
    let dataDirectoryOffset = 0;
    if (optionalHeaderMagic === 0x10b) {
        dataDirectoryOffset = optionalHeaderOffset + 0x60;
    } else if (optionalHeaderMagic === 0x20b) {
        dataDirectoryOffset = optionalHeaderOffset + 0x70;
    } else {
        result.status = 'invalid-optional-header';
        return result;
    }

    const certificateDirectoryOffset = dataDirectoryOffset + (4 * 8);
    const certificateTableOffset = readUInt32LE(buffer, certificateDirectoryOffset);
    const certificateTableSize = readUInt32LE(buffer, certificateDirectoryOffset + 4);
    result.isPe = true;
    result.certificateTableOffset = certificateTableOffset || 0;
    result.certificateTableSize = certificateTableSize || 0;
    result.hasCertificateTable =
        certificateTableOffset != null &&
        certificateTableSize != null &&
        certificateTableOffset > 0 &&
        certificateTableSize >= 8 &&
        certificateTableOffset + certificateTableSize <= buffer.length;
    result.status = result.hasCertificateTable ? 'pe-certificate-table-present' : 'pe-certificate-table-missing';
    return result;
}

function resolveExpectedArtifacts(extraArtifacts) {
    const records = [];
    const explicitArtifacts = (extraArtifacts || []).map((item) => {
        const parts = String(item).split('=');
        if (parts.length > 1) {
            const id = parts.shift();
            return { id, path: parts.join('='), signed: /\.(exe|dll)$/i.test(parts.join('=')) };
        }
        return { id: path.basename(String(item)), path: String(item), signed: /\.(exe|dll)$/i.test(String(item)) };
    });

    for (const expected of DEFAULT_EXPECTED_ARTIFACTS) {
        let found = null;
        for (const candidate of expected.candidates) {
            const abs = path.resolve(REPO_ROOT, candidate);
            if (fileExists(abs)) {
                found = abs;
                break;
            }
        }
        records.push({ id: expected.id, signed: expected.signed, required: true, path: found, candidates: expected.candidates.slice(0) });
    }

    for (const explicit of explicitArtifacts) {
        const abs = path.resolve(REPO_ROOT, explicit.path);
        records.push({ id: explicit.id, signed: explicit.signed, required: true, path: fileExists(abs) ? abs : null, candidates: [explicit.path] });
    }

    return records;
}

function collectArtifactManifest(expectedArtifacts) {
    return expectedArtifacts.map((item) => {
        const record = {
            id: item.id,
            required: item.required === true,
            signedRequired: item.signed === true,
            found: item.path != null,
            path: item.path ? relativeToRepo(item.path) : null,
            candidates: item.candidates,
            digests: null,
            signature: null
        };
        if (item.path != null) {
            record.file = statFile(item.path);
            record.digests = {
                sha256: sha(item.path, 'sha256'),
                sha384: sha(item.path, 'sha384'),
                sha512: sha(item.path, 'sha512')
            };
            if (item.signed) {
                record.signature = inspectPeSignature(item.path);
            }
        }
        return record;
    });
}

function extractTodoRows(matrixText) {
    const rows = {};
    const lines = matrixText.split(/\r?\n/);
    for (const line of lines) {
        if (!line.startsWith('|')) { continue; }
        const columns = line.split('|').slice(1, -1).map((value) => value.trim());
        if (columns.length < 7) { continue; }
        const id = columns[3];
        if (/^TODO-\d+$/.test(id)) {
            rows[id] = {
                phase: columns[0],
                priority: columns[1],
                status: columns[2],
                id,
                task: columns[4],
                ledger: columns[5],
                dependsOn: columns[6],
                acceptance: columns[7] || ''
            };
        }
    }
    return rows;
}

function extractEvidencePaths(text) {
    const paths = new Set();
    const regex = /`(docs\/testing\/(?:evidence|artifacts)\/[^`]+)`/g;
    let match;
    while ((match = regex.exec(text)) != null) {
        paths.add(match[1]);
    }
    return Array.from(paths).sort();
}

function collectEvidenceFiles() {
    const root = path.join(REPO_ROOT, 'docs', 'testing', 'evidence', 'advanced');
    const files = [];
    function walk(dir) {
        if (!directoryExists(dir)) { return; }
        for (const name of fs.readdirSync(dir).sort()) {
            const abs = path.join(dir, name);
            const stat = fs.statSync(abs);
            if (stat.isDirectory()) {
                walk(abs);
            } else if (stat.isFile()) {
                files.push(abs);
            }
        }
    }
    walk(root);
    return files;
}

function collectBundleFiles(evidenceDir) {
    const files = [];
    const addIfFile = (rel) => {
        const abs = path.resolve(REPO_ROOT, rel);
        if (fileExists(abs)) { files.push(abs); }
    };
    const addTree = (rel) => {
        const root = path.resolve(REPO_ROOT, rel);
        function walk(dir) {
            if (!directoryExists(dir)) { return; }
            for (const name of fs.readdirSync(dir).sort()) {
                const abs = path.join(dir, name);
                const stat = fs.statSync(abs);
                if (stat.isDirectory()) {
                    if (relativeToRepo(abs).startsWith('docs/testing/artifacts')) { continue; }
                    walk(abs);
                } else if (stat.isFile()) {
                    files.push(abs);
                }
            }
        }
        walk(root);
    };

    addIfFile('docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md');
    addIfFile('docs/testing/20260331_REALIGNMENT_REGRESSION_MATRIX.md');
    addIfFile('docs/testing/20260331_REALIGNMENT_LEDGER.md');
    addIfFile('docs/testing/ReleaseCheckList.md');
    addIfFile('docs/files/meshagent_release_checklist.md');
    addIfFile('DEPLOYMENT_GUIDE.md');
    addTree('docs/testing/evidence/advanced');
    if (directoryExists(evidenceDir)) {
        const rel = relativeToRepo(evidenceDir);
        addTree(rel);
    }

    return Array.from(new Set(files)).sort();
}

const CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; ++i) {
        let c = i;
        for (let j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c >>> 0;
    }
    return table;
})();

function crc32(buffer) {
    let crc = 0xffffffff;
    for (let i = 0; i < buffer.length; ++i) {
        crc = CRC32_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
    const year = Math.max(1980, date.getFullYear());
    const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
    const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { dosTime, dosDate };
}

function zip32Value(value) {
    const big = typeof value === 'bigint' ? value : BigInt(value);
    return big > 0xffffffffn ? 0xffffffff : Number(big);
}

function zip16Value(value) {
    const big = typeof value === 'bigint' ? value : BigInt(value);
    return big > 0xffffn ? 0xffff : Number(big);
}

function writeZip64Extra(values) {
    const extra = Buffer.alloc(4 + (values.length * 8));
    extra.writeUInt16LE(0x0001, 0);
    extra.writeUInt16LE(values.length * 8, 2);
    values.forEach((value, index) => {
        extra.writeBigUInt64LE(BigInt(value), 4 + (index * 8));
    });
    return extra;
}

function writeZip(files, outputPath) {
    ensureDir(path.dirname(outputPath));
    const centralParts = [];
    let offset = 0n;
    const fd = fs.openSync(outputPath, 'w');

    const writePart = (buffer) => {
        fs.writeSync(fd, buffer, 0, buffer.length);
        offset += BigInt(buffer.length);
    };

    try {
        for (const abs of files) {
            const name = relativeToRepo(abs);
            const nameBuffer = Buffer.from(name, 'utf8');
            const source = fs.readFileSync(abs);
            const compressed = zlib.deflateRawSync(source);
            const stat = fs.statSync(abs);
            const dt = dosDateTime(stat.mtime);
            const checksum = crc32(source);
            const localOffset = offset;
            const compressedSize = BigInt(compressed.length);
            const uncompressedSize = BigInt(source.length);
            const localExtra = writeZip64Extra([uncompressedSize, compressedSize]);

            const local = Buffer.alloc(30 + nameBuffer.length + localExtra.length);
            local.writeUInt32LE(0x04034b50, 0);
            local.writeUInt16LE(45, 4);
            local.writeUInt16LE(0x0800, 6);
            local.writeUInt16LE(8, 8);
            local.writeUInt16LE(dt.dosTime, 10);
            local.writeUInt16LE(dt.dosDate, 12);
            local.writeUInt32LE(checksum, 14);
            local.writeUInt32LE(0xffffffff, 18);
            local.writeUInt32LE(0xffffffff, 22);
            local.writeUInt16LE(nameBuffer.length, 26);
            local.writeUInt16LE(localExtra.length, 28);
            nameBuffer.copy(local, 30);
            localExtra.copy(local, 30 + nameBuffer.length);
            writePart(local);
            writePart(compressed);

            const centralExtra = writeZip64Extra([uncompressedSize, compressedSize, localOffset]);
            const central = Buffer.alloc(46 + nameBuffer.length + centralExtra.length);
            central.writeUInt32LE(0x02014b50, 0);
            central.writeUInt16LE(45, 4);
            central.writeUInt16LE(45, 6);
            central.writeUInt16LE(0x0800, 8);
            central.writeUInt16LE(8, 10);
            central.writeUInt16LE(dt.dosTime, 12);
            central.writeUInt16LE(dt.dosDate, 14);
            central.writeUInt32LE(checksum, 16);
            central.writeUInt32LE(0xffffffff, 20);
            central.writeUInt32LE(0xffffffff, 24);
            central.writeUInt16LE(nameBuffer.length, 28);
            central.writeUInt16LE(centralExtra.length, 30);
            central.writeUInt16LE(0, 32);
            central.writeUInt16LE(0, 34);
            central.writeUInt16LE(0, 36);
            central.writeUInt32LE(0, 38);
            central.writeUInt32LE(0xffffffff, 42);
            nameBuffer.copy(central, 46);
            centralExtra.copy(central, 46 + nameBuffer.length);
            centralParts.push(central);
        }

        const centralOffset = offset;
        for (const central of centralParts) {
            writePart(central);
        }
        const centralSize = offset - centralOffset;
        const zip64EocdOffset = offset;
        const fileCount = BigInt(files.length);

        const zip64Eocd = Buffer.alloc(56);
        zip64Eocd.writeUInt32LE(0x06064b50, 0);
        zip64Eocd.writeBigUInt64LE(44n, 4);
        zip64Eocd.writeUInt16LE(45, 12);
        zip64Eocd.writeUInt16LE(45, 14);
        zip64Eocd.writeUInt32LE(0, 16);
        zip64Eocd.writeUInt32LE(0, 20);
        zip64Eocd.writeBigUInt64LE(fileCount, 24);
        zip64Eocd.writeBigUInt64LE(fileCount, 32);
        zip64Eocd.writeBigUInt64LE(centralSize, 40);
        zip64Eocd.writeBigUInt64LE(centralOffset, 48);
        writePart(zip64Eocd);

        const zip64Locator = Buffer.alloc(20);
        zip64Locator.writeUInt32LE(0x07064b50, 0);
        zip64Locator.writeUInt32LE(0, 4);
        zip64Locator.writeBigUInt64LE(zip64EocdOffset, 8);
        zip64Locator.writeUInt32LE(1, 16);
        writePart(zip64Locator);

        const eocd = Buffer.alloc(22);
        eocd.writeUInt32LE(0x06054b50, 0);
        eocd.writeUInt16LE(0, 4);
        eocd.writeUInt16LE(0, 6);
        eocd.writeUInt16LE(zip16Value(fileCount), 8);
        eocd.writeUInt16LE(zip16Value(fileCount), 10);
        eocd.writeUInt32LE(zip32Value(centralSize), 12);
        eocd.writeUInt32LE(zip32Value(centralOffset), 16);
        eocd.writeUInt16LE(0, 20);
        writePart(eocd);
    } catch (e) {
        fs.closeSync(fd);
        fs.rmSync(outputPath, { force: true });
        throw e;
    }

    fs.closeSync(fd);
}

function formatChecksums(artifactManifest) {
    const lines = [];
    for (const artifact of artifactManifest) {
        if (!artifact.found || artifact.digests == null) { continue; }
        lines.push(`# ${artifact.id}`);
        lines.push(`${artifact.digests.sha256}  ${artifact.path}  SHA256`);
        lines.push(`${artifact.digests.sha384}  ${artifact.path}  SHA384`);
        lines.push(`${artifact.digests.sha512}  ${artifact.path}  SHA512`);
    }
    return lines.join(os.EOL) + (lines.length > 0 ? os.EOL : '');
}

function buildChecklist({ todoRows, artifactManifest, missingEvidence, bundleExported }) {
    const todo027 = todoRows['TODO-027'];
    const requiredArtifactsPresent = artifactManifest.every((artifact) => artifact.required !== true || artifact.found === true);
    const signedArtifactsOk = artifactManifest
        .filter((artifact) => artifact.signedRequired)
        .every((artifact) => artifact.signature != null && artifact.signature.hasCertificateTable === true);
    const digestsExported = artifactManifest.some((artifact) => artifact.digests != null);
    const evidenceBundleExported = bundleExported === true;
    return {
        dependency_todo_027_done: todo027 != null && todo027.status === 'DONE',
        required_release_artifacts_present: requiredArtifactsPresent,
        signed_artifacts_have_pe_certificate_table: signedArtifactsOk,
        digests_exported: digestsExported,
        referenced_evidence_paths_exist: missingEvidence.length === 0,
        evidence_bundle_exported: evidenceBundleExported,
        release_ready:
            todo027 != null &&
            todo027.status === 'DONE' &&
            requiredArtifactsPresent &&
            signedArtifactsOk &&
            digestsExported &&
            missingEvidence.length === 0 &&
            evidenceBundleExported
    };
}

function collectFailures(checklist) {
    const failures = [];
    if (!checklist.dependency_todo_027_done) { failures.push('TODO-027 is not DONE'); }
    if (!checklist.required_release_artifacts_present) { failures.push('required release artifacts are missing'); }
    if (!checklist.signed_artifacts_have_pe_certificate_table) { failures.push('required signed PE artifacts are missing a certificate table or are absent'); }
    if (!checklist.digests_exported) { failures.push('no artifact digests were exported'); }
    if (!checklist.referenced_evidence_paths_exist) { failures.push('one or more matrix-referenced evidence paths are missing'); }
    if (!checklist.evidence_bundle_exported) { failures.push('evidence bundle was not exported'); }
    return failures;
}

function writeReportOutputs(evidenceDir, report, checklist, missingEvidence, artifactManifest, allowIncomplete, bundlePath) {
    writeJson(path.join(evidenceDir, 'release_gate_manifest.json'), report);
    writeJson(path.join(evidenceDir, 'release_checklist.json'), checklist);
    writeText(path.join(evidenceDir, 'missing_evidence.txt'), missingEvidence.length > 0 ? missingEvidence.join(os.EOL) + os.EOL : 'NONE\n');
    writeText(path.join(evidenceDir, 'summary.txt'), [
        `GENERATED_UTC=${report.generatedUtc}`,
        `SUCCESS=${report.success}`,
        `ALLOW_INCOMPLETE=${allowIncomplete}`,
        `TODO_027_STATUS=${report.dependencyTodo027 ? report.dependencyTodo027.status : 'MISSING'}`,
        `TODO_029_STATUS=${report.todo029 ? report.todo029.status : 'MISSING'}`,
        `ARTIFACTS_FOUND=${artifactManifest.filter((artifact) => artifact.found).length}/${artifactManifest.length}`,
        `SIGNED_ARTIFACTS_OK=${checklist.signed_artifacts_have_pe_certificate_table}`,
        `DIGESTS_EXPORTED=${checklist.digests_exported}`,
        `MISSING_EVIDENCE_COUNT=${missingEvidence.length}`,
        `EVIDENCE_FILE_COUNT=${report.evidenceFileCount}`,
        `BUNDLE=${relativeToRepo(bundlePath)}`,
        `BUNDLE_SHA256=${report.evidenceBundle.sha256 || '(external-only-after-bundle-export)'}`,
        `FAILURES=${report.failures.length > 0 ? report.failures.join('; ') : '(none)'}`
    ].join(os.EOL) + os.EOL);
}

function main() {
    const args = parseArgs(process.argv);
    const timestamp = typeof args.timestamp === 'string' ? args.timestamp : new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '_');
    const evidenceDir = path.resolve(REPO_ROOT, args.evidence ? String(args.evidence) : `docs/testing/evidence/advanced/${timestamp}_release_signing`);
    const bundlePath = path.resolve(REPO_ROOT, args.bundle ? String(args.bundle) : `docs/testing/artifacts/${timestamp}_realignment_bundle.zip`);
    const allowIncomplete = args['allow-incomplete'] === true || args['allow-incomplete'] === '1';
    const quiet = args.quiet === true || args.quiet === '1';

    ensureDir(evidenceDir);
    ensureDir(path.dirname(bundlePath));
    if (fileExists(bundlePath)) {
        fs.unlinkSync(bundlePath);
    }

    const matrixPath = path.join(REPO_ROOT, 'docs', 'testing', '20260331_REALIGNMENT_TODO_MATRIX.md');
    const regressionPath = path.join(REPO_ROOT, 'docs', 'testing', '20260331_REALIGNMENT_REGRESSION_MATRIX.md');
    const matrixText = readText(matrixPath);
    const regressionText = readText(regressionPath);
    const todoRows = extractTodoRows(matrixText);
    const expectedArtifacts = resolveExpectedArtifacts(args.artifacts);
    const artifactManifest = collectArtifactManifest(expectedArtifacts);
    const generatedEvidencePaths = new Set([
        path.join(evidenceDir, 'checksums.txt'),
        path.join(evidenceDir, 'release_gate_manifest.json'),
        path.join(evidenceDir, 'release_checklist.json'),
        path.join(evidenceDir, 'missing_evidence.txt'),
        path.join(evidenceDir, 'summary.txt'),
        bundlePath
    ].map((item) => path.resolve(item)));
    const referencedEvidence = extractEvidencePaths(matrixText);
    const missingEvidence = referencedEvidence.filter((rel) => {
        const abs = path.resolve(REPO_ROOT, rel);
        if (generatedEvidencePaths.has(abs)) {
            return false;
        }
        return !fileExists(abs) && !directoryExists(abs);
    });
    const evidenceFiles = collectEvidenceFiles();

    writeText(path.join(evidenceDir, 'checksums.txt'), formatChecksums(artifactManifest));

    const checklist = buildChecklist({ todoRows, artifactManifest, missingEvidence, bundleExported: true });
    const failures = collectFailures(checklist);

    const report = {
        generatedUtc: new Date().toISOString(),
        success: checklist.release_ready,
        allowIncomplete,
        host: {
            platform: process.platform,
            arch: process.arch,
            node: process.version
        },
        todo029: todoRows['TODO-029'] || null,
        dependencyTodo027: todoRows['TODO-027'] || null,
        regressionRows: {
            signerAllowlistAndDigest: regressionText.indexOf('| Signer allowlist and digest gates |') >= 0,
            evidenceBundleExport: regressionText.indexOf('| Evidence-bundle export |') >= 0
        },
        artifactManifest,
        referencedEvidenceCount: referencedEvidence.length,
        missingEvidence,
        evidenceFileCount: evidenceFiles.length,
        evidenceBundle: {
            path: relativeToRepo(bundlePath),
            size: 0,
            sha256: null,
            inputFileCount: 0,
            selfHashNote: 'The bundle cannot contain its own final digest. The archive copy of this manifest uses a null sha256; the authoritative digest is written to the external manifest and summary after ZIP export.'
        },
        checklist,
        failures
    };

    writeReportOutputs(evidenceDir, report, checklist, missingEvidence, artifactManifest, allowIncomplete, bundlePath);
    const bundleInputFiles = collectBundleFiles(evidenceDir);
    try {
        writeZip(bundleInputFiles, bundlePath);
    } catch (e) {
        checklist.evidence_bundle_exported = false;
        checklist.release_ready = false;
        report.success = false;
        report.evidenceBundle.error = e && e.message ? e.message : String(e);
        report.failures = collectFailures(checklist);
        writeReportOutputs(evidenceDir, report, checklist, missingEvidence, artifactManifest, allowIncomplete, bundlePath);
        throw e;
    }

    report.evidenceBundle.size = fs.statSync(bundlePath).size;
    report.evidenceBundle.sha256 = sha(bundlePath, 'sha256');
    report.evidenceBundle.inputFileCount = bundleInputFiles.length;
    writeReportOutputs(evidenceDir, report, checklist, missingEvidence, artifactManifest, allowIncomplete, bundlePath);

    if (!report.success && !allowIncomplete) {
        process.stderr.write(`release bundle gate failed: ${failures.join('; ')}\n`);
        process.exit(1);
    }
    if (!quiet) {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
