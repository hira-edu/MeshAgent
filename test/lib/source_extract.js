'use strict';
// Helpers for contracts that execute production code instead of grepping it. Every lookup fails
// loudly: a missing input, needle or function throws and names what was looked for, so a check can
// never pass because its slice came back empty.
const fs = require('fs');
const path = require('path');

class SourceExtractError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SourceExtractError';
    }
}

// Reads a required text input with line endings normalised to LF. A missing or empty file fails and
// says what it was for.
function readSource(filePath, purpose) {
    let text;
    try {
        text = fs.readFileSync(filePath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new SourceExtractError('required input missing: ' + filePath + ' (' + purpose + ')');
        }
        throw error;
    }
    if (text.trim().length === 0) {
        throw new SourceExtractError('required input is empty: ' + filePath + ' (' + purpose + ')');
    }
    return text.replace(/\r\n?/g, '\n');
}

function indexOfRequired(source, needle, from, label) {
    const index = source.indexOf(needle, from || 0);
    if (index < 0) {
        throw new SourceExtractError('missing ' + (label || 'text') + ': ' + JSON.stringify(needle));
    }
    return index;
}

// Returns the text from startNeedle (inclusive) to the next endNeedle after it (exclusive). Either
// needle missing throws; it never returns ''.
function sourceBetween(source, startNeedle, endNeedle) {
    const start = indexOfRequired(source, startNeedle, 0, 'start marker');
    const end = indexOfRequired(source, endNeedle, start + startNeedle.length, 'end marker after ' + JSON.stringify(startNeedle));
    return source.slice(start, end);
}

// Index of the brace that closes the one at openIndex. Skips string and template literals and
// comments (JavaScript and C), so braces inside them do not count.
function matchingBrace(source, openIndex) {
    let depth = 0;
    for (let i = openIndex; i < source.length; ++i) {
        const ch = source[i];
        const next = source[i + 1];
        if (ch === '/' && next === '/') { i = source.indexOf('\n', i); if (i < 0) break; continue; }
        if (ch === '/' && next === '*') { i = source.indexOf('*/', i + 2); if (i < 0) break; i += 1; continue; }
        if (ch === '"' || ch === "'" || ch === '`') {
            for (++i; i < source.length && source[i] !== ch; ++i) { if (source[i] === '\\') { ++i; } }
            continue;
        }
        if (ch === '{') { depth += 1; }
        if (ch === '}') { depth -= 1; if (depth === 0) { return i; } }
    }
    throw new SourceExtractError('unbalanced braces from offset ' + openIndex);
}

// Returns the definition that starts at signature and ends at its closing brace. A C prototype
// (signature followed by ';' before any '{') is skipped in favour of the definition.
function extractFunction(source, signature) {
    let start = indexOfRequired(source, signature, 0, 'function');
    for (;;) {
        const brace = source.indexOf('{', start + signature.length);
        const semicolon = source.indexOf(';', start + signature.length);
        if (brace < 0) { throw new SourceExtractError('missing function body: ' + signature); }
        if (semicolon >= 0 && semicolon < brace) {
            start = indexOfRequired(source, signature, semicolon, 'function definition');
            continue;
        }
        return source.slice(start, matchingBrace(source, brace) + 1);
    }
}

// Compiles extracted definitions into one function scope with the given free variables and returns
// what returnExpression evaluates to. The definitions run as written; only their surroundings are stubbed.
function compileDefinitions(definitions, freeVariables, returnExpression) {
    const factory = new Function(...freeVariables, definitions.join('\n') + '\nreturn (' + returnExpression + ');');
    return (...values) => factory(...values);
}

// Optional --evidence <dir>: writes <name>.json and summary.txt for the grouped regression.
function evidenceDirFromArgs(argv) {
    const index = argv.indexOf('--evidence');
    if (index < 0) { return null; }
    const dir = argv[index + 1];
    if (!dir || dir.startsWith('--')) { throw new SourceExtractError('--evidence needs a directory'); }
    return path.resolve(dir);
}

function writeEvidence(evidenceDir, name, report, summaryLines) {
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.writeFileSync(path.join(evidenceDir, name + '.json'), JSON.stringify(report, null, 2));
    fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), summaryLines.join('\n') + '\n', 'utf8');
}

// Runs named cases, reports each, and sets a failing exit code if any failed. Returns the results.
function runCases(title, cases) {
    const results = {};
    let failed = 0;
    for (const [name, fn] of Object.entries(cases)) {
        try {
            fn();
            results[name] = true;
            console.log('PASS ' + name);
        } catch (error) {
            failed += 1;
            results[name] = false;
            console.error('FAIL ' + name + ': ' + String(error && error.stack || error).split('\n').slice(0, 4).join('\n  '));
        }
    }
    console.log(title + ': ' + (failed ? 'FAIL (' + failed + '/' + Object.keys(cases).length + ' failed)' : 'PASS (' + Object.keys(cases).length + ' cases)'));
    if (failed) { process.exitCode = 1; }
    return { results, failed };
}

module.exports = {
    SourceExtractError,
    readSource,
    sourceBetween,
    extractFunction,
    compileDefinitions,
    evidenceDirFromArgs,
    writeEvidence,
    runCases
};
