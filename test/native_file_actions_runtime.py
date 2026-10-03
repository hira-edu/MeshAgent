"""Exercise native Files APIs against isolated files and a harmless EXE on Windows."""
import os
from pathlib import Path
import subprocess
import tempfile
import uuid
import winreg

ROOT = Path(__file__).resolve().parents[1]
fixture = r'''
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include "meshcore/native_file_actions.h"
static void wait_child(DWORD pid) {
    HANDLE child = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (child) { assert(WaitForSingleObject(child, 10000) == WAIT_OBJECT_0); CloseHandle(child); }
}
int wmain(int argc, wchar_t** argv) {
    wchar_t full[MESH_FILE_PATH_CHARS], command[MESH_FILE_PATH_CHARS], path[MESH_FILE_PATH_CHARS];
    DWORD count, pid;
    assert(argc == 3);
    assert(MeshFileAction_Path(L"C:\\owned & O'Brien\\unicode-\x03a9.exe", full));
    assert(!MeshFileAction_Path(L"C:relative.exe", full));
    assert(!MeshFileAction_Path(L"\\\\?\\C:\\device.exe", full));
    assert(!MeshFileAction_Path(L"C:\\bad\"name.exe", full));
    assert(!MeshFileAction_Path(L"C:\\file:stream", full));
    assert(MeshFileAction_AssociationCommand(L"\"C:\\app.exe\" \"%1\" %*", L"C:\\owned & O'Brien\\\x03a9.txt", command));
    assert(wcscmp(command, L"\"C:\\app.exe\" \"C:\\owned & O'Brien\\\x03a9.txt\" ") == 0);
    assert(MeshFileAction_AssociationCommand(L"app.exe %L", L"C:\\owned name.txt", command));
    assert(wcscmp(command, L"app.exe \"C:\\owned name.txt\"") == 0);
    assert(!MeshFileAction_AssociationCommand(L"app.exe %2", L"C:\\owned.txt", command));
    assert(!MeshFileAction_AssociationCommand(L"app.exe", L"C:\\owned.txt", command));
    assert(!MeshFileAction_Delete(L"C:\\", TRUE, &count));
    assert(!MeshFileAction_Delete(L"C:\\test\\..\\", TRUE, &count));
    assert(!MeshFileAction_Delete(L"\\\\server\\share\\", TRUE, &count));
    swprintf_s(path, _countof(path), L"%ls\\single.txt", argv[1]);
    assert(MeshFileAction_Delete(path, TRUE, &count) && count == 1);
    swprintf_s(path, _countof(path), L"%ls\\tree", argv[1]);
    assert(!MeshFileAction_Delete(path, FALSE, &count) && count == 0);
    assert(MeshFileAction_Delete(path, TRUE, &count) && count == 4);
    swprintf_s(path, _countof(path), L"%ls\\outside\\keep.txt", argv[1]);
    assert(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    swprintf_s(path, _countof(path), L"%ls\\readonly.txt", argv[1]);
    assert(!MeshFileAction_Delete(path, FALSE, &count) && count == 0);
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    assert(MeshFileAction_Delete(path, FALSE, &count) && count == 1);
    assert(!MeshFileAction_Delete(path, FALSE, &count) && count == 0);
    swprintf_s(path, _countof(path), L"%ls\\literal & O'Brien \x03a9.exe", argv[1]);
    assert(MeshFileAction_Launch(path, FALSE, FALSE, &pid) && pid != 0);
    wait_child(pid);
    assert(MeshFileAction_Launch(path, TRUE, FALSE, &pid) && pid != 0);
    wait_child(pid);
    assert(MeshFileAction_Launch(argv[2], TRUE, FALSE, &pid) && pid != 0);
    wait_child(pid);
    wcscpy_s(command, _countof(command), path);
    swprintf_s(path, _countof(path), L"%ls\\locked.txt", argv[1]);
    HANDLE locked = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    assert(locked != INVALID_HANDLE_VALUE);
    assert(!MeshFileAction_Delete(path, TRUE, &count) && count == 0 && GetLastError() == ERROR_SHARING_VIOLATION);
    CloseHandle(locked);
    assert(MeshFileAction_Delete(path, FALSE, &count) && count == 1);
    wcscpy_s(path, _countof(path), command);
    if (!MeshFileAction_Launch(path, FALSE, TRUE, &pid)) { assert(GetLastError() == ERROR_ELEVATION_REQUIRED); }
    else { assert(pid != 0); wait_child(pid); }
    assert(!MeshFileAction_Launch(path, TRUE, TRUE, &pid) && GetLastError() == ERROR_INVALID_PARAMETER);
    puts("native Files: literal quoting, user launches, token policy, recursive/leaf delete, root/ADS rejection and junction preservation passed");
    return 0;
}
'''
canary = r'''
#include <windows.h>
#include <stdio.h>
int wmain(void) {
    wchar_t path[32768]; DWORD session;
    GetModuleFileNameW(NULL, path, 32768);
    wcscat_s(path, 32768, L".result");
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { return 2; }
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    char text[65536]; int length = WideCharToMultiByte(CP_UTF8, 0, GetCommandLineW(), -1, text, sizeof(text), NULL, NULL) - 1; DWORD written;
    WriteFile(file, text, length, &written, NULL); CloseHandle(file); return 0;
}
'''
if os.name != 'nt':
    raise SystemExit('Windows native Files fixture requires Windows')
with tempfile.TemporaryDirectory(prefix='native-files-', dir=ROOT / 'artifacts/validation/native-file-actions') as directory:
    base = Path(directory).resolve()
    assert base.parent == (ROOT / 'artifacts/validation/native-file-actions').resolve()
    (base / 'tree/sub').mkdir(parents=True)
    (base / 'outside').mkdir()
    (base / 'outside/keep.txt').write_text('outside target must survive')
    (base / 'tree/sub/owned.txt').write_text('owned')
    (base / 'single.txt').write_text('owned')
    (base / 'readonly.txt').write_text('owned')
    (base / 'locked.txt').write_text('owned')
    subprocess.run(['attrib', '+R', str(base / 'readonly.txt')], check=True)
    subprocess.run(['cmd', '/c', 'mklink', '/J', str(base / 'tree/link'), str(base / 'outside')], check=True, capture_output=True)
    source = base / 'fixture.c'
    source.write_text(fixture)
    canary_source = base / 'canary.c'
    canary_source.write_text(canary)
    executable = base / 'fixture.exe'
    canary_exe = base / "literal & O'Brien Ω.exe"
    compiler = os.environ.get('CC', 'clang')
    subprocess.run([compiler, '-std=c11', str(canary_source), '-o', str(canary_exe)], check=True)
    subprocess.run([compiler, '-std=c11', '-I', str(ROOT), str(source), '-o', str(executable), '-ladvapi32', '-luserenv', '-lwtsapi32', '-lshlwapi'], check=True)
    extension = '.meshNativeFiles' + uuid.uuid4().hex
    progid = 'MeshAgent.NativeFilesFixture.' + uuid.uuid4().hex
    classes = 'Software\\Classes\\'
    association_keys = [classes + extension, classes + progid, classes + progid + '\\shell', classes + progid + '\\shell\\open', classes + progid + '\\shell\\open\\command']
    document = base / ('literal & document Ω' + extension)
    document.write_text('owned native association fixture')
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, classes + extension) as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, progid)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, association_keys[-1]) as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, '"' + str(canary_exe) + '" "%1"')
        subprocess.run([str(executable), str(base), str(document)], check=True, timeout=30)
    finally:
        for key in reversed(association_keys):
            try: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except FileNotFoundError: pass
    import time
    result = Path(str(canary_exe) + '.result')
    for _ in range(30):
        if result.exists(): break
        time.sleep(0.1)
    assert result.exists(), 'the direct native child must actually execute'
    print(result.read_text())
