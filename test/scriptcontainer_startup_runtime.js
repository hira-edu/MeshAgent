'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.platform !== 'win32' || !process.argv[2] || !process.argv[3]) {
    throw new Error('Requires Windows, an explicit MeshConsole executable, and an evidence directory');
}
const runner = path.resolve(process.argv[2]);
const evidence = path.resolve(process.argv[3]);
fs.mkdirSync(evidence, { recursive: true });
const cases = [
    { name: 'ready-error', when: 'ready', payload: 'throw new Error("startup-probe");', error: 'startup-probe' },
    { name: 'early-error', when: 'early', payload: 'throw new Error("startup-probe");', error: 'startup-probe' },
    { name: 'immediate-error', payload: 'throw new Error("startup-probe");', error: 'startup-probe' },
    { name: 'early-syntax-error', when: 'early', payload: 'function (', error: 'SyntaxError' },
    { name: 'early-module-access', when: 'early', payload: 'require("ScriptContainer").send(typeof process.on);', data: ['function'] },
    { name: 'immediate-command-order', payload: 'var parent=require("ScriptContainer");parent.on("data",function(d){parent.send(d);});', send: [1, 2, 3], data: [1, 2, 3] },
    { name: 'immediate-exit', exit: true },
    { name: 'early-exit', when: 'early', exit: true },
    { name: 'early-permissions', when: 'early', permissions: 0x04000003,
      payload: 'var denied=[];["net","fs","child_process"].forEach(function(m){try{require(m);}catch(e){denied.push(m);}});require("ScriptContainer").send(denied.join(","));', data: ['net,fs,child_process'] }
];
const results = [];
for (const c of cases) {
    const work = path.join(evidence, c.name);
    fs.mkdirSync(work, { recursive: true });
    const action = c.exit ? 'worker.exit();' : 'worker.ExecuteString(' + JSON.stringify(c.payload) + ');' +
        (c.send || []).map(x => 'worker.send(' + JSON.stringify(x) + ');').join('');
    const script = `
var worker=require('ScriptContainer').Create({processIsolation:0,permissions:${c.permissions || 0}});
var result={ready:0,errors:[],data:[],exits:0};
var finishTimer;
var deadline=setTimeout(function(){console.log('STARTUP_RESULT '+JSON.stringify(result));process.exit(12);},5000);
worker.on('ready',function(){++result.ready;${c.when === 'ready' ? action : ''}});
worker.on('error',function(e){result.errors.push(String(e));this.exit();});
worker.on('data',function(d){result.data.push(d);if(result.data.length===${(c.data || []).length}){this.exit();}});
worker.on('exit',function(code){++result.exits;result.exitCode=code;clearTimeout(deadline);
    worker.send('after-exit');worker.ExecuteString('throw new Error("must not execute");');worker.exit();
    finishTimer=setTimeout(function(){console.log('STARTUP_RESULT '+JSON.stringify(result));process.exit(0);},30);});
${c.when === 'early' ? 'var until=Date.now()+500;while(Date.now()<until){};' : ''}
${c.when === 'ready' ? '' : action}
`;
    fs.writeFileSync(path.join(work, 'probe.js'), script);
    const child = spawnSync(runner, ['-exec', script], { cwd: work, windowsHide: true, encoding: 'utf8', timeout: 8000 });
    const row = { name: c.name, status: child.status, signal: child.signal, error: child.error && String(child.error), stdout: child.stdout, stderr: child.stderr };
    try {
        assert.strictEqual(child.status, 0, 'native process must exit successfully');
        const match = child.stdout.match(/^STARTUP_RESULT (.+)$/m);
        assert(match, 'missing completion report');
        row.result = JSON.parse(match[1]);
        assert.strictEqual(row.result.ready, 1, 'exactly one ready event');
        assert.strictEqual(row.result.exits, 1, 'exactly one exit event');
        assert.strictEqual(row.result.exitCode, '0');
        assert.deepStrictEqual(row.result.data, c.data || []);
        if (c.error) {
            assert.strictEqual(row.result.errors.length, 1);
            assert(row.result.errors[0].includes(c.error), 'original error must reach the parent');
        } else { assert.deepStrictEqual(row.result.errors, []); }
        row.success = true;
    } catch (e) { row.success = false; row.failure = String(e); }
    fs.writeFileSync(path.join(work, 'result.json'), JSON.stringify(row, null, 2) + '\n');
    results.push(row);
    console.log((row.success ? 'PASS ' : 'FAIL ') + c.name + (row.failure ? ': ' + row.failure : ''));
}
const report = { runner, generatedUtc: new Date().toISOString(), success: results.every(x => x.success), results };
fs.writeFileSync(path.join(evidence, 'result.json'), JSON.stringify(report, null, 2) + '\n');
process.exitCode = report.success ? 0 : 1;
