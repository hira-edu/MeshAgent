// Duktape terminates a script by throwing from process.exit(). A successful
// -nodeid query must not catch that termination and turn it into an error exit.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

for (const file of ['meshservice/ServiceMain.c', 'meshconsole/main.c']) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    const match = source.match(/char script\[\] = ("[^\r\n]*Unable to resolve the agent node id[^\r\n]*");/);
    assert(match, `${file}: missing node-id command script`);
    const script = JSON.parse(match[1]);
    for (const fails of [false, true]) {
        const output = [], errors = [], exits = [];
        const termination = new Error('Process.exit() forced script termination');
        const context = {
            require(name) {
                assert.strictEqual(name, '_agentNodeId');
                return () => {
                    if (fails) throw new Error('fixture identity unavailable');
                    return 'ab'.repeat(48);
                };
            },
            console: { log(value) { output.push(value); } },
            process: {
                stderr: { write(value) { errors.push(value); } },
                exit(code = 0) { exits.push(code); throw termination; }
            }
        };
        assert.throws(() => vm.runInNewContext(script, context), error => error === termination);
        assert.deepStrictEqual(exits, [fails ? 1 : 0], `${file}: preserve command exit status`);
        assert.deepStrictEqual(output, fails ? [] : ['ab'.repeat(48)]);
        assert.strictEqual(errors.length, fails ? 1 : 0);
        if (fails) assert(errors[0].includes('fixture identity unavailable'));
    }
    console.log(`PASS ${file}: successful and failed node-id command exit status`);
}
