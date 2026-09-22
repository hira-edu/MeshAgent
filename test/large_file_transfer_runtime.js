const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        if (!argv[i].startsWith('--') || i + 1 >= argv.length) throw new Error(`Invalid argument: ${argv[i]}`);
        args[argv[i].substring(2)] = argv[++i];
    }
    return args;
}

function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }

function createAgentScript(inputPath, expectedBytes) {
    return [
        "var fs=require('fs'),http=require('http'),done=false,fragmentOk=false,limitOk=false,readOk=false,limitedDecoded=0;",
        `var inputPath=${JSON.stringify(inputPath)},expectedBytes=${expectedBytes};`,
        "function finish(code,message){if(done)return;done=true;console.log(message);process.exit(code);}",
        "function check(){if(fragmentOk&&limitOk&&readOk){if(limitedDecoded!==0){finish(26,'LARGE_FILE_RUNTIME_FAIL over-limit decoded='+limitedDecoded);}else{finish(0,'LARGE_FILE_RUNTIME_OK bytes='+expectedBytes);}}}",
        "function frame(fin,opcode,size){var h=4,b=Buffer.alloc(size+h),i;b[0]=(fin?128:0)|opcode;b[1]=126;b[2]=(size>>8)&255;b[3]=size&255;for(i=h;i<b.length;i++)b[i]=i&255;return b;}",
        "try{var ws=http.webSocketStream(null,{maxFragmentBufferSize:1024*1024}),decoded=0,events=0;",
        "ws.decoded.on('data',function(chunk){decoded+=chunk.length;events++;});",
        "ws.encoded.write(frame(false,2,60000));ws.encoded.write(frame(true,0,1000));",
        "if(decoded!==61000||events!==1){finish(21,'LARGE_FILE_RUNTIME_FAIL fragment bytes='+decoded+' events='+events);}fragmentOk=true;}catch(e){finish(22,'LARGE_FILE_RUNTIME_FAIL fragment='+e);}",
        "try{var limited=http.webSocketStream(null,{maxFragmentBufferSize:4096}),firstRejected=false,secondRejected=false;",
        "limited.decoded.on('data',function(chunk){limitedDecoded+=chunk.length;});",
        "try{limited.encoded.write(frame(false,2,5000));}catch(e){firstRejected=true;}",
        "try{limited.encoded.write(frame(true,0,8));}catch(e){secondRejected=true;}",
        "if(limitedDecoded!==0){finish(26,'LARGE_FILE_RUNTIME_FAIL over-limit decoded='+limitedDecoded);}limitOk=true;}catch(e){finish(27,'LARGE_FILE_RUNTIME_FAIL over-limit='+e);}",
        "var ticks=0,total=0,timer=setInterval(function(){ticks++;},1),stream=fs.createReadStream(inputPath,{flags:'rb'});",
        "stream.on('data',function(chunk){total+=chunk.length;});",
        "stream.on('error',function(e){clearInterval(timer);finish(23,'LARGE_FILE_RUNTIME_FAIL read='+e);});",
        "stream.on('end',function(){clearInterval(timer);if(total!==expectedBytes||ticks<1){finish(24,'LARGE_FILE_RUNTIME_FAIL bytes='+total+' ticks='+ticks);return;}readOk=true;check();});",
        "stream.resume();",
        "setTimeout(function(){finish(25,'LARGE_FILE_RUNTIME_FAIL timeout fragment='+fragmentOk+' limit='+limitOk+' read='+readOk+' bytes='+total+' ticks='+ticks);},30000);",
        "check();"
    ].join('');
}

async function main() {
    const args = parseArgs(process.argv);
    if (!args.runner) throw new Error('--runner is required');
    const runner = path.resolve(args.runner);
    const sizeMb = args['size-mb'] == null ? 64 : Number(args['size-mb']);
    if (!Number.isInteger(sizeMb) || sizeMb < 8 || sizeMb > 1024) throw new Error('--size-mb must be an integer from 8 to 1024');
    if (!fs.existsSync(runner)) throw new Error(`Runner does not exist: ${runner}`);

    const evidenceDir = path.resolve(args.evidence || path.join(REPO_ROOT, 'artifacts', 'validation', 'large-file-transfer'));
    ensureDir(evidenceDir);
    const inputPath = path.join(evidenceDir, 'large-file-runtime-input.bin');
    const expectedBytes = sizeMb * 1024 * 1024;
    const fd = fs.openSync(inputPath, 'w');
    try { fs.ftruncateSync(fd, expectedBytes); } finally { fs.closeSync(fd); }

    const child = spawn(runner, ['-exec', createAgentScript(inputPath, expectedBytes)], { cwd: REPO_ROOT, windowsHide: true });
    let stdout = '', stderr = '', timedOut = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const watchdog = setTimeout(() => { timedOut = true; child.kill(); }, 35000);
    const exit = await new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    clearTimeout(watchdog);
    try { fs.unlinkSync(inputPath); } catch (error) { }

    const success = !timedOut && exit.code === 0 && exit.signal == null && stdout.includes('LARGE_FILE_RUNTIME_OK');
    const report = {
        generatedUtc: new Date().toISOString(), success, runner, sizeMb, expectedBytes,
        exitCode: exit.code, signal: exit.signal, timedOut, stdout, stderr
    };
    fs.writeFileSync(path.join(evidenceDir, 'large_file_transfer_runtime.json'), JSON.stringify(report, null, 2) + '\n');
    fs.writeFileSync(path.join(evidenceDir, 'summary.txt'), [
        `SUCCESS=${success}`,
        `RUNNER=${runner}`,
        `SIZE_MB=${sizeMb}`,
        `EXIT_CODE=${exit.code}`,
        `SIGNAL=${exit.signal || '(none)'}`,
        `STDOUT=${stdout.trim() || '(empty)'}`,
        `STDERR=${stderr.trim() || '(empty)'}`
    ].join('\n') + '\n');
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    if (!success) process.exit(1);
}

main().catch((error) => { console.error(error && error.stack ? error.stack : String(error)); process.exit(1); });
