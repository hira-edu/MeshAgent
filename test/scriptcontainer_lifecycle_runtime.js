'use strict';
// Owned console processes only. No service changes, remote commands, or input.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
if (process.platform !== 'win32' || !process.argv[2] || !process.argv[3]) {
    throw new Error('Requires Windows, an explicit MeshConsole executable, and an evidence directory');
}
const runner = path.resolve(process.argv[2]), evidence = path.resolve(process.argv[3]);
fs.mkdirSync(evidence, { recursive: true });
const results = [];
for (const mode of ['immediate', 'ready', 'error', 'data']) {
    const script = `var worker=require('ScriptContainer').Create({processIsolation:0});var released=0;
var done=setTimeout(function(){console.log('GC_RESULT '+released);process.exit(0);},300);
function release(){++released;worker=null;Duktape.gc();Duktape.gc();}
worker.on('ready',function(){${mode === 'ready' ? 'release();' : mode === 'error' ? 'this.ExecuteString(\'throw new Error("gc");\');' : mode === 'data' ? 'this.ExecuteString(\'require("ScriptContainer").send(1);\');' : ''}});
worker.on('error',function(){release();});worker.on('data',function(){release();});
${mode === 'immediate' ? 'release();' : ''}`;
    const dir = path.join(evidence, mode);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'probe.js'), script);
    const child = spawnSync(runner, ['-exec', script], { cwd: dir, encoding: 'utf8', windowsHide: true, timeout: 5000 });
    const row = { name: mode, code: child.status, stdout: child.stdout, stderr: child.stderr, error: child.error && String(child.error) };
    row.success = child.status === 0 && /^GC_RESULT 1\r?$/m.test(child.stdout);
    results.push(row);
    fs.writeFileSync(path.join(dir, 'result.json'), JSON.stringify(row, null, 2));
    console.log((row.success ? 'PASS ' : 'FAIL ') + mode + ' release');
}
const script = `var worker,tick,completed=0,ready=0;
var deadline=setTimeout(function(){console.log('TIMEOUT');process.exit(12);},30000);
function next(){worker=require('ScriptContainer').Create({processIsolation:0});
 worker.on('ready',function(){++ready;this.exit();});
 worker.on('error',function(e){console.log('ERROR '+e);process.exit(11);});
 worker.on('exit',function(){worker=null;++completed;tick=setTimeout(afterExit,10);});}
function afterExit(){Duktape.gc();Duktape.gc();
 if(completed===5||completed===25||completed===45){console.log('SNAPSHOT '+completed);
  tick=setTimeout(function(){if(completed===45){clearTimeout(deadline);console.log('DONE '+ready+' '+completed);process.exit(0);}else{next();}},2500);
 }else{next();}}
next();`;
fs.writeFileSync(path.join(evidence, 'repeat-probe.js'), script);
const child = spawn(runner, ['-exec', script], { cwd: evidence, windowsHide: true });
const row = { name: 'repeat-release', pid: child.pid, stdout: '', stderr: '', snapshots: [] };
let pending = '';
const watchdog = setTimeout(() => { row.timeout = true; child.kill(); }, 40000);
child.on('error', error => { row.error = String(error); });
child.stderr.on('data', data => { row.stderr += data; });
child.stdout.on('data', data => {
    row.stdout += data; pending += data;
    let end;
    while ((end = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, end).trim(); pending = pending.slice(end + 1);
        if (!line.startsWith('SNAPSHOT ')) { continue; }
        const query = spawnSync('powershell.exe', ['-NoProfile', '-Command',
            '$ErrorActionPreference="Stop"; $probeProcess=Get-Process -Id ' + child.pid + '; [pscustomobject]@{handles=$probeProcess.HandleCount;threads=$probeProcess.Threads.Count}|ConvertTo-Json -Compress'],
            { encoding: 'utf8', windowsHide: true, timeout: 5000 });
        const sample = { completed: Number(line.split(' ')[1]), code: query.status, stdout: query.stdout, stderr: query.stderr };
        try { sample.resources = JSON.parse(query.stdout); } catch (e) { sample.error = String(e); }
        row.snapshots.push(sample);
    }
});
child.on('close', (code, signal) => {
    clearTimeout(watchdog); row.code = code; row.signal = signal;
    try {
        assert.strictEqual(code, 0, 'native process must exit successfully');
        assert(/^DONE 45 45\r?$/m.test(row.stdout), 'all workers must become ready and exit exactly once');
        assert.deepStrictEqual(row.snapshots.map(x => x.completed), [5, 25, 45]);
        row.snapshots.forEach(x => { assert.strictEqual(x.code, 0); assert(x.resources && Number.isInteger(x.resources.handles)); });
        const first = row.snapshots[0].resources, last = row.snapshots[2].resources;
        // Allow small runtime variation; the original leaked 120 handles here.
        assert(last.handles <= first.handles + 4, 'worker cleanup must not accumulate handles');
        assert(last.threads <= first.threads + 1, 'worker threads must terminate');
        row.success = true;
    } catch (e) { row.success = false; row.failure = String(e); }
    results.push(row);
    const report = { runner, generatedUtc: new Date().toISOString(), success: results.every(x => x.success), results };
    fs.writeFileSync(path.join(evidence, 'result.json'), JSON.stringify(report, null, 2));
    console.log((row.success ? 'PASS ' : 'FAIL ') + '45 worker lifecycles' + (row.failure ? ': ' + row.failure : ''));
    process.exitCode = report.success ? 0 : 1;
});
