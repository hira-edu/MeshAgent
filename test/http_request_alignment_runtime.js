const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_RUNNER = path.join(REPO_ROOT, 'meshconsole', 'Release', 'MeshConsole64.exe');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) throw new Error(`Missing value for ${token}`);
        args[token.substring(2)] = value;
        ++i;
    }
    return args;
}

function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }
function writeJson(file, value) { ensureDir(path.dirname(file)); fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function writeText(file, value) { ensureDir(path.dirname(file)); fs.writeFileSync(file, value, 'utf8'); }

function createAgentScript(port) {
    return [
        "var http=require('http');",
        `var port=${port},paths=['/','//','///','////','/////','//////','///////','////////'],index=0,done=false;`,
        "function finish(code,message){if(done)return;done=true;console.log(message);process.exit(code);}",
        "function next(){if(index===paths.length){finish(0,'ALIGNMENT_RUNTIME_OK count='+index);return;}var requestPath=paths[index++];",
        "var request=http.request({protocol:'http:',host:'127.0.0.1',port:port,path:requestPath,method:'GET',headers:{Host:'h'},agent:false});",
        "var body='';request.on('response',function(response){response.on('data',function(chunk){body+=chunk.toString();});response.on('end',function(){if(response.statusCode!==200||body!=='OK'){finish(12,'ALIGNMENT_RUNTIME_FAIL response='+response.statusCode+'/'+body);return;}next();});});",
        "request.on('error',function(error){finish(11,'ALIGNMENT_RUNTIME_FAIL request='+error.message);});request.end();}",
        "setTimeout(function(){finish(13,'ALIGNMENT_RUNTIME_FAIL timeout index='+index);},15000);next();"
    ].join('');
}

async function main() {
    const args = parseArgs(process.argv);
    const runner = args.runner ? path.resolve(args.runner) : DEFAULT_RUNNER;
    const evidence = args.evidence ? path.resolve(args.evidence) : null;
    if (!fs.existsSync(runner)) throw new Error(`MeshConsole runner missing: ${runner}`);

    const receivedPaths = [];
    const serverErrors = [];
    const server = net.createServer((socket) => {
        let request = '';
        socket.setEncoding('utf8');
        socket.on('data', (chunk) => {
            request += chunk;
            if (!request.includes('\r\n\r\n')) return;
            const firstLine = request.substring(0, request.indexOf('\r\n'));
            const match = /^GET (\/+?) HTTP\/1\.1$/.exec(firstLine);
            if (match) receivedPaths.push(match[1]);
            socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
        });
        socket.on('error', (error) => serverErrors.push(error.message));
    });

    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });

    const port = server.address().port;
    const child = spawn(runner, ['-exec', createAgentScript(port)], { cwd: REPO_ROOT, windowsHide: true });
    let stdout = '', stderr = '', timedOut = false;
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const watchdog = setTimeout(() => { timedOut = true; child.kill(); }, 20000);
    const exit = await new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
    clearTimeout(watchdog);
    await new Promise((resolve) => server.close(resolve));

    const expectedPaths = ['/', '//', '///', '////', '/////', '//////', '///////', '////////'];
    const success = !timedOut && exit.code === 0 && exit.signal == null && stdout.includes('ALIGNMENT_RUNTIME_OK') &&
        JSON.stringify(receivedPaths) === JSON.stringify(expectedPaths) && serverErrors.length === 0;
    const report = { success, runner, port, exitCode: exit.code, signal: exit.signal, timedOut, stdout, stderr, expectedPaths, receivedPaths, serverErrors };

    if (evidence) {
        writeJson(path.join(evidence, 'http_request_alignment_runtime.json'), report);
        writeText(path.join(evidence, 'summary.txt'), [
            `SUCCESS=${success}`,
            `RUNNER=${runner}`,
            `EXIT_CODE=${exit.code}`,
            `SIGNAL=${exit.signal || '(none)'}`,
            `RECEIVED_PATHS=${JSON.stringify(receivedPaths)}`,
            `STDOUT=${stdout.trim() || '(empty)'}`,
            `STDERR=${stderr.trim() || '(empty)'}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
    if (!success) process.exit(1);
}

main().catch((error) => { console.error(error && error.stack ? error.stack : String(error)); process.exit(1); });
