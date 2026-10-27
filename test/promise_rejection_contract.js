const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

// A missing or empty input fails the contract and says what it was for.
function read(relPath, purpose) {
    const fullPath = path.resolve(relPath);
    let text;
    try {
        text = fs.readFileSync(fullPath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error(`required input missing: ${fullPath} (${purpose})`, { cause: error });
        }
        throw error;
    }
    assert(text.trim().length > 0, `required input is empty: ${fullPath} (${purpose})`);
    return text.replace(/\r\n?/g, '\n');
}

// Declares every copy the contract checks:
// - required: tracked sources. Each one must exist.
// - buildOutput: copies a local build writes (gitignored). Each is checked when present and listed
//   in the report (and on stderr) when absent.
function declaredInputs(purpose, declared, absentOptional) {
    const required = declared.required || [];
    assert(required.length > 0, `declares no required input (${purpose})`);
    const missing = required.filter((relPath) => !fs.existsSync(path.resolve(relPath)));
    assert(missing.length === 0,
        `required input missing: ${missing.map((relPath) => path.resolve(relPath)).join(', ')} (${purpose})`);
    const optional = declared.buildOutput || [];
    const absent = optional.filter((relPath) => !fs.existsSync(path.resolve(relPath)));
    for (const relPath of absent) {
        absentOptional.push(relPath);
        console.error(`optional input absent, not checked: ${relPath} (${purpose})`);
    }
    return required.concat(optional.filter((relPath) => !absent.includes(relPath)));
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
    const purpose = 'promise module copies whose rejection propagation is checked';
    const absentOptionalInputs = [];
    const promisePaths = declaredInputs(purpose, {
        required: [
            'modules/promise.js'
        ],
        buildOutput: [
            'meshconsole/Release/modules_expanded/promise.js'
        ]
    }, absentOptionalInputs);

    const report = { absentOptionalInputs };
    for (const promisePath of promisePaths) {
        const checks = checkPromiseModule(read(promisePath, purpose));
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
