"""Drive real Files handlers through the built Duktape/native agent boundary."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid
import winreg
import shutil

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'artifacts/validation/native-file-actions'
EVIDENCE.mkdir(parents=True, exist_ok=True)
cores = [ROOT.parent / 'MeshCentral/agents' / name for name in ('meshcore.js', 'meshcore.min.js', 'recoverycore.js')]
agents = [ROOT / 'meshservice/x64/MeshServiceRuntime/MeshService-2022.exe', ROOT / 'meshservice/MeshServiceRuntime/MeshService-2022.exe']
canary = r'''
#include <windows.h>
int wmain(void) { return 0; }
'''
records = []
with tempfile.TemporaryDirectory(prefix='binding-', dir=EVIDENCE) as directory:
    base = Path(directory).resolve()
    assert base.parent == EVIDENCE.resolve()
    source = base / 'canary.c'
    source.write_text(canary)
    executable = base / "literal & O'Brien Ω.exe"
    subprocess.run([os.environ.get('CC', 'clang'), str(source), '-o', str(executable)], check=True)
    extension = '.meshNativeBinding' + uuid.uuid4().hex
    key = 'Software\\Classes\\' + extension
    document = base / ('literal & document Ω' + extension)
    document.write_text('owned')
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + '\\shell\\open\\command') as association:
            winreg.SetValueEx(association, '', 0, winreg.REG_SZ, '"' + str(executable) + '" "%1"')
        for agent in agents:
            assert agent.is_file(), f'Build the Windows package first: {agent}'
            # Exercise the console-user branch without changing the production
            # service's requireAdministrator manifest. Only an isolated copy's
            # manifest changes; its compiled native code and payload stay intact.
            manifest_tools = sorted(Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')).glob('Windows Kits/10/bin/*/x64/mt.exe'))
            assert manifest_tools, 'Windows SDK manifest tool is required'
            test_agent = base / ('test-x64.exe' if 'x64' in agent.parts else 'test-x86.exe')
            shutil.copyfile(agent, test_agent)
            manifest = base / 'manifest.xml'
            subprocess.run([str(manifest_tools[-1]), '-nologo', '-inputresource:' + str(test_agent) + ';#1', '-out:' + str(manifest)], check=True, capture_output=True)
            original = manifest.read_text(encoding='utf-8-sig')
            assert 'requireAdministrator' in original
            manifest.write_text(original.replace('requireAdministrator', 'asInvoker'), encoding='utf-8')
            subprocess.run([str(manifest_tools[-1]), '-nologo', '-manifest', str(manifest), '-outputresource:' + str(test_agent) + ';#1'], check=True, capture_output=True)
            for core in cores:
                text = core.read_text(encoding='utf-8')
                start = text.index('function nativeFileAction(')
                brace = text.index('{', start)
                end, depth = brace + 1, 1
                while depth:
                    depth += (text[end] == '{') - (text[end] == '}')
                    end += 1
                helper = text[start:end]
                owned = base / 'native-delete-Ω-😀.txt'
                owned.write_text('owned')
                result_file = base / 'result.json'
                if result_file.exists(): result_file.unlink()
                script = base / 'probe.js'
                script.write_text('var progressFile = ' + json.dumps(str(result_file)) + ';\n' + helper + '\n' + '''
var replies = [], logs = [];
function sendConsoleText(text) { logs.push(text); }
function invoke(rights, action, path, option) {
    require('fs').writeFileSync(progressFile, JSON.stringify({ stage: action, count: replies.length, path: path }));
    return nativeFileAction({ httprequest: { rights: rights, sessionid: 'owned' }, write: function (data) { replies.push(JSON.parse(data)); } },
        { action: action, path: path, privileged: option, rec: option, reqid: 'owned-' + replies.length });
}
var results = [];
''' + '\n'.join([
                    "results.push(invoke(8, 'execute', " + json.dumps(str(executable)) + ', true));',
                    "results.push(invoke(8, 'delete', " + json.dumps(str(owned)) + ', true));',
                    "results.push(invoke(131080, 'execute', " + json.dumps(str(executable)) + ', false));',
                    "results.push(invoke(131080, 'open', " + json.dumps(str(document)) + ', false));',
                    "results.push(invoke(8, 'delete', 'C:\\\\', true));",
                    "results.push(invoke(131080, 'execute', 'C:relative.exe', false));",
                    "require('fs').writeFileSync(" + json.dumps(str(result_file)) + ', JSON.stringify({results:results, replies:replies}));',
                    # Exit synchronously before agent-mode setup can create an
                    # endpoint identity or connect this disposable test process.
                    'process._exit();'
                ]), encoding='utf-8')
                completed = subprocess.run([str(test_agent), str(script), '--script-connect'], cwd=ROOT, capture_output=True, text=True, timeout=30)
                assert result_file.is_file(), f'{agent.name} exit={completed.returncode}: ' + completed.stdout + completed.stderr
                result = json.loads(result_file.read_text())
                assert 'results' in result, {'exit': completed.returncode, 'progress': result}
                results = result['results']
                assert not results[0]['ok'] and results[0]['error'] == 'Access denied.'
                assert results[1]['ok'] and results[1]['deleted'] == 1 and not owned.exists(), result
                assert results[2]['ok'] and results[2]['pid'] > 0, result
                assert results[3]['ok'] and results[3]['pid'] > 0, result
                assert not results[4]['ok'] and not results[5]['ok']
                assert result['replies'] == results
                for launch in results[2:4]:
                    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                    kernel.OpenProcess.restype = ctypes.c_void_p
                    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                    handle = kernel.OpenProcess(0x100000, False, launch['pid'])
                    if handle:
                        assert kernel.WaitForSingleObject(handle, 10000) == 0
                        kernel.CloseHandle(handle)
                records.append({'agent': str(agent.relative_to(ROOT)), 'testManifest': 'asInvoker copy; production unchanged', 'core': core.name, 'success': True, 'results': results})
    finally:
        for suffix in ('\\shell\\open\\command', '\\shell\\open', '\\shell', ''):
            try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key + suffix)
            except FileNotFoundError: pass
(EVIDENCE / 'binding-results.json').write_text(json.dumps(records, indent=2))
print(f'Native Files binding: {len(records)} real x64/Win32 core combinations passed; Unicode/emoji delete, literal EXE and association open, rights and root rejection')
