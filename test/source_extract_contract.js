'use strict';
// Unit tests for test/lib/source_extract.js. Every lookup must fail loudly when its needle is
// missing, so a contract cannot pass on an empty slice.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const lib = require('./lib/source_extract');

const throwsExtract = (fn, fragment) => assert.throws(fn, (error) => error instanceof lib.SourceExtractError && error.message.includes(fragment));

lib.runCases('source_extract_contract', {
    sourceBetweenReturnsTheSlice() {
        assert.strictEqual(lib.sourceBetween('a START b END c END', 'START', 'END'), 'START b ');
    },
    sourceBetweenFailsOnMissingStart() {
        throwsExtract(() => lib.sourceBetween('a b c', 'START', 'c'), 'missing start marker: "START"');
    },
    sourceBetweenFailsOnMissingEnd() {
        throwsExtract(() => lib.sourceBetween('START b', 'START', 'END'), 'missing end marker');
    },
    sourceBetweenNeedsTheEndAfterTheStart() {
        throwsExtract(() => lib.sourceBetween('END START', 'START', 'END'), 'missing end marker');
    },
    extractFunctionSkipsBracesInStringsAndComments() {
        const source = "x();\nfunction f(a) {\n  var s = '}' + \"{\" + `}`; // }\n  /* { */ return { a: a };\n}\nfunction g() {}\n";
        const body = lib.extractFunction(source, 'function f(a)');
        assert(body.endsWith('return { a: a };\n}'), body);
        assert.deepStrictEqual(lib.compileDefinitions([body], [], 'f')()(3), { a: 3 });
    },
    extractFunctionSkipsCPrototypes() {
        const source = 'static int f(int a);\nint x;\nstatic int f(int a)\n{\n  if (a) { return \'}\'; }\n  return 0;\n}\n';
        assert.strictEqual(lib.extractFunction(source, 'static int f(int a)'), "static int f(int a)\n{\n  if (a) { return '}'; }\n  return 0;\n}");
    },
    extractFunctionFailsWhenMissing() {
        throwsExtract(() => lib.extractFunction('function g() {}', 'function f('), 'missing function: "function f("');
    },
    extractFunctionFailsWhenUnbalanced() {
        throwsExtract(() => lib.extractFunction('function f() { {', 'function f()'), 'unbalanced braces');
    },
    compileDefinitionsBindsFreeVariables() {
        const run = lib.compileDefinitions(['function add(x) { return x + base; }'], ['base'], 'add');
        assert.strictEqual(run(10)(5), 15);
    },
    readSourceNormalisesAndFailsLoudly() {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'source-extract-'));
        try {
            fs.writeFileSync(path.join(dir, 'crlf.js'), 'a\r\nb\rc\n');
            assert.strictEqual(lib.readSource(path.join(dir, 'crlf.js'), 'fixture'), 'a\nb\nc\n');
            fs.writeFileSync(path.join(dir, 'empty.js'), '  \n');
            throwsExtract(() => lib.readSource(path.join(dir, 'empty.js'), 'fixture'), 'required input is empty');
            throwsExtract(() => lib.readSource(path.join(dir, 'absent.js'), 'fixture'), 'required input missing');
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    },
    evidenceArgumentNeedsADirectory() {
        assert.strictEqual(lib.evidenceDirFromArgs(['node', 'x.js']), null);
        assert.strictEqual(lib.evidenceDirFromArgs(['node', 'x.js', '--evidence', 'out']), path.resolve('out'));
        throwsExtract(() => lib.evidenceDirFromArgs(['node', 'x.js', '--evidence']), '--evidence needs a directory');
    }
});
