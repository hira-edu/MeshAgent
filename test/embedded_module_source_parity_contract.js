const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// Static contract for update-critical JavaScript embedded in
// ILibDuktape_Polyfills_JS_Init(). These modules must be byte-for-byte (modulo
// line endings) identical to modules/<name>.js because MSBuild compiles the
// checked-in C payload directly.

const MSVC_STRING_LITERAL_LIMIT = 16300;
const MINIMUM_EXPECTED_MODULES = 50;
const EXCERPT_LENGTH = 100;
const UPDATE_CRITICAL_MODULES = new Set(['promise', 'update-helper', 'zip-reader']);

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

function readSource(filePath) {
    return fs.readFileSync(filePath, 'utf8').replace(/\r\n?/g, '\n');
}

function countOccurrences(haystack, needle) {
    let count = 0;
    let index = haystack.indexOf(needle);
    while (index !== -1) {
        count += 1;
        index = haystack.indexOf(needle, index + needle.length);
    }
    return count;
}

function excerpt(line) {
    if (line == null) {
        return '<end of file>';
    }
    return line.length > EXCERPT_LENGTH ? line.substring(0, EXCERPT_LENGTH) + '...' : line;
}

// Returns the lines of the JS_Init function body (from the signature line up to the
// first line that is exactly "}") together with the 1-based line number of the signature.
function extractJsInitBody(polyfillsSource) {
    const lines = polyfillsSource.split('\n');
    const signature = /^void ILibDuktape_Polyfills_JS_Init\(duk_context\s*\*\s*ctx\)\s*$/;
    let start = -1;
    for (let i = 0; i < lines.length; ++i) {
        if (signature.test(lines[i])) {
            start = i;
            break;
        }
    }
    assert(start !== -1, 'ILibDuktape_Polyfills_JS_Init(duk_context *ctx) definition not found in ILibDuktape_Polyfills.c');
    let end = -1;
    for (let i = start + 1; i < lines.length; ++i) {
        if (lines[i] === '}') {
            end = i;
            break;
        }
    }
    assert(end !== -1, 'ILibDuktape_Polyfills_JS_Init closing brace not found');
    return { lines: lines.slice(start, end + 1), firstLineNumber: start + 1 };
}

const SINGLE_LINE_COMPRESSED =
    /^\s*duk_peval_string_noresult\(ctx, "addCompressedModule\('([^']+)', Buffer\.from\('([^']*)', 'base64'\)(?:, '([^']*)')?\);"\);\s*$/;
const SINGLE_LINE_PLAIN =
    /^\s*duk_peval_string_noresult\(ctx, "addModule\('([^']+)', Buffer\.from\('([^']*)', 'base64'\)(?:\.toString\(\))?(?:, '([^']*)')?\);"\);\s*$/;
const CHUNK_ALLOCATE = /^\s*char\s*\*\s*_(\w+) = ILibMemory_Allocate\((\d+), 0, NULL, NULL\);\s*$/;
const CHUNK_MEMCPY = /^\s*memcpy_s\(_(\w+) \+ (\d+), (\d+), "([^"]*)", (\d+)\);\s*$/;
const CHUNK_TERMINATOR = /^\s*_(\w+)\[(\d+)\] = 0;\s*$/;
const CHUNK_ADD = /^\s*ILibDuktape_AddCompressedModuleEx\(ctx, "([^"]+)", _(\w+)(?:, "([^"]*)")?\);\s*$/;
const CHUNK_FREE = /^\s*free\(_(\w+)\);\s*$/;

// Parses a chunked (ILibMemory_Allocate + memcpy_s + ILibDuktape_AddCompressedModuleEx) entry
// starting at lines[index]. Returns { entry, nextIndex }. Structural problems are recorded in
// entry.integrityErrors rather than thrown so that every entry is reported in one run.
function parseChunkedEntry(lines, index, firstLineNumber) {
    const allocate = lines[index].match(CHUNK_ALLOCATE);
    const variable = allocate[1];
    const allocateSize = Number(allocate[2]);
    const entry = {
        name: null,
        form: 'chunked',
        timestamp: null,
        line: firstLineNumber + index,
        variable,
        allocateSize,
        chunkCount: 0,
        encodedLength: 0,
        terminatorIndex: null,
        encoded: '',
        integrityErrors: []
    };
    const errors = entry.integrityErrors;
    let expectedOffset = 0;
    let sawAdd = false;
    let sawFree = false;
    let i = index + 1;
    for (; i < lines.length; ++i) {
        const line = lines[i];
        const lineNumber = firstLineNumber + i;
        let match;
        if ((match = line.match(CHUNK_MEMCPY)) != null) {
            if (sawAdd) {
                errors.push(`line ${lineNumber}: memcpy_s after ILibDuktape_AddCompressedModuleEx`);
            }
            const target = match[1];
            const offset = Number(match[2]);
            const remaining = Number(match[3]);
            const chunk = match[4];
            const declaredLength = Number(match[5]);
            if (target !== variable) {
                errors.push(`line ${lineNumber}: memcpy_s target _${target} does not match _${variable}`);
            }
            if (offset !== expectedOffset) {
                errors.push(`line ${lineNumber}: memcpy_s offset ${offset}, expected contiguous offset ${expectedOffset}`);
            }
            if (declaredLength !== chunk.length) {
                errors.push(`line ${lineNumber}: memcpy_s length argument ${declaredLength} does not match chunk string length ${chunk.length}`);
            }
            entry.encoded += chunk;
            entry.chunkCount += 1;
            expectedOffset = offset + chunk.length;
            // remaining-size argument is validated against the final total once all chunks are known.
            entry[`_remaining_${entry.chunkCount}`] = { lineNumber, offset, remaining };
            continue;
        }
        if ((match = line.match(CHUNK_TERMINATOR)) != null) {
            if (match[1] !== variable) {
                errors.push(`line ${lineNumber}: terminator target _${match[1]} does not match _${variable}`);
            }
            if (entry.terminatorIndex != null) {
                errors.push(`line ${lineNumber}: duplicate terminator assignment`);
            }
            entry.terminatorIndex = Number(match[2]);
            continue;
        }
        if ((match = line.match(CHUNK_ADD)) != null) {
            if (sawAdd) {
                errors.push(`line ${lineNumber}: duplicate ILibDuktape_AddCompressedModuleEx`);
            }
            sawAdd = true;
            entry.name = match[1];
            entry.timestamp = match[3] != null ? match[3] : null;
            if (match[2] !== variable) {
                errors.push(`line ${lineNumber}: ILibDuktape_AddCompressedModuleEx uses _${match[2]} but the buffer is _${variable}`);
            }
            continue;
        }
        if ((match = line.match(CHUNK_FREE)) != null) {
            if (match[1] !== variable) {
                errors.push(`line ${lineNumber}: free() target _${match[1]} does not match _${variable}`);
            }
            sawFree = true;
            i += 1;
            break;
        }
        errors.push(`line ${lineNumber}: unexpected line inside chunked entry for _${variable}: ${excerpt(line.trim())}`);
        break;
    }

    const total = entry.encoded.length;
    entry.encodedLength = total;
    if (!sawAdd) {
        errors.push(`_${variable}: ILibDuktape_AddCompressedModuleEx call not found`);
    }
    if (!sawFree) {
        errors.push(`_${variable}: free() call not found`);
    }
    if (entry.chunkCount === 0) {
        errors.push(`_${variable}: no memcpy_s chunks found`);
    }
    if (allocateSize !== total + 1) {
        errors.push(`_${variable}: ILibMemory_Allocate size ${allocateSize}, expected encoded length + 1 = ${total + 1}`);
    }
    for (let c = 1; c <= entry.chunkCount; ++c) {
        const info = entry[`_remaining_${c}`];
        delete entry[`_remaining_${c}`];
        if (info.remaining !== total - info.offset) {
            errors.push(`line ${info.lineNumber}: memcpy_s remaining-size ${info.remaining}, expected total - offset = ${total - info.offset}`);
        }
    }
    if (entry.terminatorIndex != null && entry.terminatorIndex !== total) {
        errors.push(`_${variable}: terminator index ${entry.terminatorIndex}, expected encoded length ${total}`);
    }
    if (entry.name == null) {
        entry.name = `<unnamed:_${variable}>`;
    }
    return { entry, nextIndex: i };
}

function parseEmbeddedEntries(bodyLines, firstLineNumber) {
    const entries = [];
    let i = 0;
    while (i < bodyLines.length) {
        const line = bodyLines[i];
        let match;
        if ((match = line.match(SINGLE_LINE_COMPRESSED)) != null) {
            entries.push({
                name: match[1],
                form: 'single-line-compressed',
                timestamp: match[3] != null ? match[3] : null,
                line: firstLineNumber + i,
                statementLength: line.trim().length,
                encoded: match[2],
                compressed: true,
                integrityErrors: []
            });
            i += 1;
            continue;
        }
        if ((match = line.match(SINGLE_LINE_PLAIN)) != null) {
            entries.push({
                name: match[1],
                form: 'single-line-plain',
                timestamp: match[3] != null ? match[3] : null,
                line: firstLineNumber + i,
                statementLength: line.trim().length,
                encoded: match[2],
                compressed: false,
                integrityErrors: []
            });
            i += 1;
            continue;
        }
        if (CHUNK_ALLOCATE.test(line)) {
            const parsed = parseChunkedEntry(bodyLines, i, firstLineNumber);
            parsed.entry.compressed = true;
            entries.push(parsed.entry);
            i = parsed.nextIndex;
            continue;
        }
        i += 1;
    }
    return entries;
}

function decodeEmbedded(entry) {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(entry.encoded) || entry.encoded.length % 4 !== 0) {
        throw new Error('payload is not well-formed base64');
    }
    const raw = Buffer.from(entry.encoded, 'base64');
    if (!entry.compressed) {
        return raw.toString('utf8').replace(/\r\n?/g, '\n');
    }
    return zlib.inflateSync(raw).toString('utf8').replace(/\r\n?/g, '\n');
}

function firstDifference(embedded, source) {
    const embeddedLines = embedded.split('\n');
    const sourceLines = source.split('\n');
    const limit = Math.max(embeddedLines.length, sourceLines.length);
    for (let i = 0; i < limit; ++i) {
        if (embeddedLines[i] !== sourceLines[i]) {
            return {
                line: i + 1,
                embedded: excerpt(embeddedLines[i]),
                source: excerpt(sourceLines[i])
            };
        }
    }
    return { line: null, embedded: null, source: null };
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const root = args.root ? path.resolve(args.root) : process.cwd();
    const polyfillsPath = path.resolve(root, 'microscript', 'ILibDuktape_Polyfills.c');
    const modulesDir = path.resolve(root, 'modules');

    const polyfillsSource = readSource(polyfillsPath);
    const body = extractJsInitBody(polyfillsSource);
    const bodyText = body.lines.join('\n');
    const entries = parseEmbeddedEntries(body.lines, body.firstLineNumber);

    const rawReferences =
        countOccurrences(bodyText, "addCompressedModule('") +
        countOccurrences(bodyText, "addModule('") +
        countOccurrences(bodyText, 'ILibDuktape_AddCompressedModuleEx(ctx, "');

    const seen = new Set();
    const duplicateModules = [];
    const missingSources = [];
    const integrityFailures = [];
    const decodeFailures = [];
    const oversizedEntries = [];
    const driftedModules = [];
    const modules = [];

    for (const entry of entries) {
        if (seen.has(entry.name)) {
            duplicateModules.push(entry.name);
        }
        seen.add(entry.name);

        if (entry.integrityErrors.length > 0) {
            integrityFailures.push({ name: entry.name, line: entry.line, errors: entry.integrityErrors });
        }
        if (entry.statementLength != null && entry.statementLength > MSVC_STRING_LITERAL_LIMIT) {
            oversizedEntries.push({ name: entry.name, line: entry.line, statementLength: entry.statementLength });
        }

        const sourcePath = path.join(modulesDir, `${entry.name}.js`);
        const sourceExists = fs.existsSync(sourcePath);
        const updateCritical = UPDATE_CRITICAL_MODULES.has(entry.name);
        if (!sourceExists && updateCritical) {
            missingSources.push(entry.name);
        }

        let embedded = null;
        try {
            embedded = decodeEmbedded(entry);
        } catch (ex) {
            decodeFailures.push({ name: entry.name, line: entry.line, error: ex.message });
        }

        let matchesSource = false;
        let difference = null;
        if (embedded != null && sourceExists) {
            const source = readSource(sourcePath);
            matchesSource = embedded === source;
            if (!matchesSource && updateCritical) {
                difference = firstDifference(embedded, source);
                driftedModules.push({ name: entry.name, form: entry.form, line: entry.line, firstDifference: difference });
            }
        }

        modules.push({
            name: entry.name,
            form: entry.form,
            timestamp: entry.timestamp,
            line: entry.line,
            updateCritical,
            sourceExists,
            matchesSource
        });
    }

    const checks = {
        parserCoversAllEmbeddedEntries: entries.length === rawReferences,
        atLeastFiftyModulesEmbedded: entries.length >= MINIMUM_EXPECTED_MODULES,
        noDuplicateModuleNames: duplicateModules.length === 0,
        allEmbeddedModulesHaveSourceFiles: missingSources.length === 0,
        chunkedEntriesStructurallySound: integrityFailures.length === 0,
        allEmbeddedPayloadsDecode: decodeFailures.length === 0,
        singleLineEntriesWithinMsvcLiteralLimit: oversizedEntries.length === 0,
        allUpdateCriticalModulesPresent:
            [...UPDATE_CRITICAL_MODULES].every((name) => seen.has(name)),
        allEmbeddedUpdateModulesMatchSource:
            driftedModules.length === 0 && missingSources.length === 0 &&
            !decodeFailures.some((failure) => UPDATE_CRITICAL_MODULES.has(failure.name))
    };

    const report = {
        generatedUtc: new Date().toISOString(),
        root,
        polyfillsPath,
        modulesDir,
        jsInitLine: body.firstLineNumber,
        moduleCount: entries.length,
        coverage: { rawReferences, parsedEntries: entries.length },
        modules,
        duplicateModules,
        missingSources,
        integrityFailures,
        decodeFailures,
        oversizedEntries,
        driftedModules,
        checks
    };

    const failedChecks = Object.entries(checks).filter(([, passed]) => !passed).map(([name]) => name);
    const success = failedChecks.length === 0;

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'embedded_module_source_parity_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            `SUCCESS=${success}`,
            `MODULE_COUNT=${entries.length}`,
            `DRIFTED_MODULES=${driftedModules.map((d) => d.name).join(',')}`,
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }

    if (!success) {
        const lines = [`Embedded module source parity contract failed (${failedChecks.length} check(s)): ${failedChecks.join(', ')}`];
        if (!checks.parserCoversAllEmbeddedEntries) {
            lines.push(`  parser coverage: ${entries.length} parsed entries vs ${rawReferences} raw module references in ILibDuktape_Polyfills_JS_Init (unrecognized entry form?)`);
        }
        if (!checks.atLeastFiftyModulesEmbedded) {
            lines.push(`  module count: ${entries.length} < ${MINIMUM_EXPECTED_MODULES}`);
        }
        if (duplicateModules.length > 0) {
            lines.push(`  duplicate module names: ${duplicateModules.join(', ')}`);
        }
        if (missingSources.length > 0) {
            lines.push(`  update modules without modules/<name>.js: ${missingSources.join(', ')}`);
        }
        for (const failure of integrityFailures) {
            lines.push(`  chunked entry integrity (${failure.name}, line ${failure.line}):`);
            for (const error of failure.errors) {
                lines.push(`    ${error}`);
            }
        }
        for (const failure of decodeFailures) {
            lines.push(`  payload decode failure (${failure.name}, line ${failure.line}): ${failure.error}`);
        }
        for (const oversized of oversizedEntries) {
            lines.push(`  statement exceeds MSVC literal limit (${oversized.name}, line ${oversized.line}): ${oversized.statementLength} > ${MSVC_STRING_LITERAL_LIMIT}`);
        }
        if (driftedModules.length > 0) {
            lines.push(`  drifted update modules (${driftedModules.length}): ${driftedModules.map((d) => d.name).join(', ')}`);
            for (const drift of driftedModules) {
                lines.push(`    ${drift.name} (${drift.form}, C line ${drift.line}): first difference at line ${drift.firstDifference.line}`);
                lines.push(`      embedded: ${drift.firstDifference.embedded}`);
                lines.push(`      source:   ${drift.firstDifference.source}`);
            }
        }
        lines.push('  Re-embed modules into microscript/ILibDuktape_Polyfills.c via modules/code-utils.js shrink (readExpandedModules) or an equivalent generator, then rebuild.');
        throw new Error(lines.join('\n'));
    }
}

main();
