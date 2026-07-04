const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function read(relPath) {
    return fs.readFileSync(path.resolve(relPath), 'utf8').replace(/\r\n?/g, '\n');
}

function existingPaths(paths) {
    return paths.filter((relPath) => fs.existsSync(path.resolve(relPath)));
}

function checkPromiseModule(source) {
    const rejectedStart = source.indexOf('function return_rejected()');
    const rejectedEnd = source.indexOf('function emitreject', rejectedStart);
    const rejectedBlock = rejectedStart >= 0 && rejectedEnd > rejectedStart ? source.slice(rejectedStart, rejectedEnd) : '';

    return {
        hasRejectedHelper: rejectedBlock.length > 0,
        propagatesActualRejection:
            rejectedBlock.includes('var child = this._XSLF && this._XSLF.promise ? this._XSLF.promise.__childPromise : null;') &&
            rejectedBlock.includes("if (child != null && typeof(child._rej) == 'function')") &&
            rejectedBlock.includes('child._rej.apply(child, arguments);'),
        noUndefinedRejectionVariable:
            !rejectedBlock.includes('__childPromise._rej(e);') &&
            !/\b_rej\(e\)/.test(rejectedBlock)
    };
}

function main() {
    const promisePaths = existingPaths([
        'modules/promise.js',
        'meshconsole/Release/modules_expanded/promise.js'
    ]);

    assert(promisePaths.length > 0, 'no promise module copies found');

    const report = {};
    for (const promisePath of promisePaths) {
        const checks = checkPromiseModule(read(promisePath));
        report[promisePath] = checks;
        for (const [name, passed] of Object.entries(checks)) {
            assert(passed, `${promisePath}: ${name} failed`);
        }
    }

    if (process.argv.includes('--json')) {
        console.log(JSON.stringify(report, null, 2));
    }
}

main();
