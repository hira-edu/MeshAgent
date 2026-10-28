'use strict';
// Executes the agent promise module's chaining code (modules/promise.js, and the build copy when a
// local build wrote one) with stand-in promise objects. When a promise is resolved with another
// promise, _resolver subscribes return_resolved / return_rejected to the inner one. The inner
// promise's rejection must reach the outer promise's then() child with the same arguments, and its
// resolution must be re-emitted on the outer promise. The Duktape event emitter is not emulated:
// only these three functions run, as written.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { readSource, extractFunction, compileDefinitions, runCases } = require('./lib/source_extract');

const required = ['modules/promise.js'];
// Copies a local build writes (gitignored). Each is checked when present and listed when absent.
const buildOutput = ['meshconsole/Release/modules_expanded/promise.js'];

function loadChaining(filePath) {
    const source = readSource(path.resolve(filePath), 'agent promise module whose rejection propagation is executed');
    const definitions = [
        extractFunction(source, 'function getRootPromise(obj)'),
        extractFunction(source, 'function return_resolved()'),
        extractFunction(source, 'function return_rejected()'),
        'var _resolver = ' + extractFunction(source, 'function _resolver()') + ';'
    ];
    return compileDefinitions(definitions, [], '{ resolver: _resolver, returnResolved: return_resolved, returnRejected: return_rejected }')();
}

// An outer promise with a then() child, resolved with an inner promise whose handlers are captured.
function chain(functions) {
    const child = { calls: [], _rej() { child.calls.push({ self: this, args: Array.from(arguments) }); } };
    const outer = { _ObjectID: 'promise', __childPromise: child };
    const emitted = [];
    const internal = { promise: outer, completed: false, emit() { emitted.push(Array.from(arguments)); } };
    const inner = { _ObjectID: 'promise', handlers: null, then(resolved, rejected) { this.handlers = { resolved, rejected }; } };
    functions.resolver.call(internal, inner);
    return { child, outer, internal, inner, emitted };
}

function casesFor(functions) {
    return {
        resolvingWithAPromiseSubscribesToIt() {
            const { inner, internal, emitted } = chain(functions);
            assert(inner.handlers, '_resolver must call then() on the inner promise');
            assert.strictEqual(inner._XSLF, internal, 'the inner promise keeps the outer internal state');
            assert.deepStrictEqual(emitted, [], 'the outer promise is not settled before the inner one');
        },
        innerRejectionRejectsTheChildWithTheSameArguments() {
            const { inner, child } = chain(functions);
            const reason = new Error('inner failed');
            inner.handlers.rejected.call(inner, reason, 'detail');
            assert.strictEqual(child.calls.length, 1, 'the child is rejected once');
            assert.strictEqual(child.calls[0].self, child, 'the child rejector runs with the child as this');
            assert.deepStrictEqual(child.calls[0].args, [reason, 'detail']);
        },
        innerResolutionIsReEmitted() {
            const { inner, emitted } = chain(functions);
            inner.handlers.resolved.call(inner, 'value', 2);
            assert.deepStrictEqual(emitted, [['resolved', 'value', 2]]);
        },
        rejectionWithoutAChildIsDropped() {
            const { inner, outer } = chain(functions);
            delete outer.__childPromise; // a settled promise clears its child
            assert.doesNotThrow(() => inner.handlers.rejected.call(inner, new Error('late')));
            outer.__childPromise = {}; // a child without a rejector
            assert.doesNotThrow(() => inner.handlers.rejected.call(inner, new Error('late')));
        },
        nonPromiseValueIsEmittedDirectly() {
            const emitted = [];
            const internal = { promise: { _ObjectID: 'promise' }, completed: false, emit() { emitted.push(Array.from(arguments)); } };
            functions.resolver.call(internal, 42);
            assert.deepStrictEqual(emitted, [['resolved', 42], ['settled']]);
        }
    };
}

const missing = required.filter((rel) => !fs.existsSync(path.resolve(rel)));
assert.strictEqual(missing.length, 0, 'required input missing: ' + missing.map((rel) => path.resolve(rel)).join(', '));
const absent = buildOutput.filter((rel) => !fs.existsSync(path.resolve(rel)));
for (const rel of absent) { console.error('optional input absent, not checked: ' + rel + ' (build copy of the promise module)'); }

const report = { absentOptionalInputs: absent, results: {} };
let failed = 0;
for (const rel of required.concat(buildOutput.filter((r) => !absent.includes(r)))) {
    const run = runCases('promise_rejection_contract ' + rel, casesFor(loadChaining(rel)));
    report.results[rel] = run.results;
    failed += run.failed;
}
if (failed) { process.exitCode = 1; }
if (process.argv.includes('--json')) { console.log(JSON.stringify(report, null, 2)); }
