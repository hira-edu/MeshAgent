#!/usr/bin/env python3
"""Probe the production Windows log sink and session telemetry on disposable files/processes.

Uses a private HKCU key, not an installed service. Exception reporting is fault
injected; abrupt exits kill only the disposable probe child.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import uuid
import winreg
from connection_failure_telemetry_native import extract


SOURCE = r'''
#define WIN32 1
#define UNICODE 1
#define _UNICODE 1
#define MESHCORE_CONFIG_ACTIVE_PROFILE_H
#include <winsock2.h>
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
typedef struct mesh_branding_definition_t { const wchar_t *logDirectory, *logFileName; } mesh_branding_definition_t;
static mesh_branding_definition_t branding;
static const mesh_branding_definition_t* MeshConfig_GetBranding(void) { return &branding; }
#include "meshcore/diagnostic_log.h"
#include "meshservice/service_telemetry.h"
#define MNG_DEBUG 64
/*KVM_PACKET_FUNCTION*/
volatile LONG g_MeshDiagnosticLogDisabled = 0;
static MeshServiceTelemetry telemetry = {0};
static wchar_t path[4096];

static void exception_probe(DWORD code) {
    EXCEPTION_RECORD record = {0}; EXCEPTION_POINTERS exception = {0};
    record.ExceptionCode=code; record.ExceptionAddress=(void*)&exception_probe;
    record.NumberParameters=2; record.ExceptionInformation[0]=1; record.ExceptionInformation[1]=0x1234;
    exception.ExceptionRecord=&record;
    assert(MeshServiceTelemetry_RecordException(&telemetry,&exception)==EXCEPTION_CONTINUE_SEARCH);
}
int wmain(int argc, wchar_t **argv) {
    assert(argc>=3); branding.logDirectory=argv[2]; branding.logFileName=L"diagnostics.log";
    assert(MeshDiagnosticLog_GetPathW(path,_countof(path)));
    if (!wcscmp(argv[1],L"write")) {
        for(int i=0;i<200;i++) {
            char message[80]; sprintf_s(message,sizeof(message),"[CONCURRENT] seq=%d",i);
            SetLastError(12345); assert(MeshDiagnosticLog_Write("probe",message)); assert(GetLastError()==12345);
        }
    } else if (!wcscmp(argv[1],L"packet")) {
        const char *message="[KVM_CAPTURE_FAILURE] helperPid=321 stage=desktop nativeError=5";
        int length=4+(int)strlen(message); unsigned short header[2]={htons(MNG_DEBUG),htons((unsigned short)length)};
        char *packet=(char*)malloc(length); memcpy(packet,header,4); memcpy(packet+4,message,length-4);
        SetLastError(13579); assert(MeshAgent_LogKvmFailurePacket(packet,length)==1); assert(GetLastError()==13579);
        assert(MeshAgent_LogKvmFailurePacket(packet,length-1)==0);
        assert(MeshAgent_LogKvmFailurePacket(packet,3)==0); assert(MeshAgent_LogKvmFailurePacket(NULL,0)==0);
        packet[4]='x'; assert(MeshAgent_LogKvmFailurePacket(packet,length)==0); free(packet);
    } else if (!wcscmp(argv[1],L"prune")) {
        char message[2048]; memset(message,'x',sizeof(message)-1); message[sizeof(message)-1]=0;
        for(int i=0;i<1200;i++) { assert(MeshDiagnosticLog_Write("prune",message)); }
        assert(MeshDiagnosticLog_Write("probe","[NEWEST_RECORD]"));
    } else if (!wcscmp(argv[1],L"legacy")) {
        assert(MeshDiagnosticLog_Write("probe","[AFTER_UTF16]"));
    } else if (!wcscmp(argv[1],L"unicode")) {
        SetLastError(54321); assert(MeshDiagnosticLog_PrintfW("probe",L"[UNICODE] %ls",L"\x03bb\x4e2d")); assert(GetLastError()==54321);
    } else if (!wcscmp(argv[1],L"disabled")) {
        g_MeshDiagnosticLogDisabled=1; assert(!MeshDiagnosticLog_Write("probe","must not recreate uninstall directory"));
    } else if (!wcscmp(argv[1],L"locked")) {
        HANDLE file=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_ALWAYS,0,NULL);
        OVERLAPPED lock={0}; assert(file!=INVALID_HANDLE_VALUE);
        assert(LockFileEx(file,LOCKFILE_EXCLUSIVE_LOCK,0,MAXDWORD,MAXDWORD,&lock));
        SetLastError(987); assert(!MeshDiagnosticLog_Write("probe","blocked")); assert(GetLastError()==987);
        UnlockFileEx(file,0,MAXDWORD,MAXDWORD,&lock); CloseHandle(file);
    } else if (!wcscmp(argv[1],L"open_failure")) {
        assert(!MeshDiagnosticLog_Write("probe","cannot open directory as file"));
    } else {
        assert(argc==4);
        MeshServiceTelemetry_Begin(&telemetry,HKEY_CURRENT_USER,argv[3]);
        assert(telemetry.key!=NULL);
        MeshServiceTelemetry_Update(&telemetry,MESH_TELEMETRY_RUNNING,0);
        if (!wcscmp(argv[1],L"hang")) { puts("READY"); fflush(stdout); Sleep(INFINITE); }
        else if (!wcscmp(argv[1],L"exception")) { exception_probe(EXCEPTION_ACCESS_VIOLATION); }
        else if (!wcscmp(argv[1],L"heap_code")) { exception_probe(0xC0000374u); }
        else if (!wcscmp(argv[1],L"clean")) { MeshServiceTelemetry_End(&telemetry,MESH_TELEMETRY_CLEAN_EXIT,0); }
        else if (!wcscmp(argv[1],L"startup_failure")) { MeshServiceTelemetry_End(&telemetry,MESH_TELEMETRY_START_FAILURE,5); }
        else if (!wcscmp(argv[1],L"unexpected")) { MeshServiceTelemetry_End(&telemetry,MESH_TELEMETRY_UNEXPECTED_RETURN,1067); }
        else { assert(0); }
    }
    return 0;
}
'''


def main():
    if os.name != "nt":
        raise SystemExit("This probe requires Windows and Clang.")
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--evidence", type=Path, default=root / "artifacts/validation/unified-failure-telemetry")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    run_dir = args.evidence / str(uuid.uuid4())
    run_dir.mkdir()
    fixture = args.evidence / "unified-failure-telemetry.c"
    executable = args.evidence / "unified-failure-telemetry.exe"
    core = (root / "meshcore/agentcore.c").read_text()
    fixture.write_text(SOURCE.replace("/*KVM_PACKET_FUNCTION*/", extract(core, "MeshAgent_LogKvmFailurePacket")))
    subprocess.run([args.cc, "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-I", str(root), str(fixture), "-ladvapi32", "-lws2_32", "-o", str(executable)], check=True)
    env = os.environ.copy()
    compiler = shutil.which(args.cc)
    if compiler:
        runtimes = list(Path(compiler).parent.parent.glob("lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll"))
        if runtimes:
            env["PATH"] = str(runtimes[0].parent) + os.pathsep + env.get("PATH", "")
    results = []

    def run(mode, folder, key=None):
        if mode != "disabled":
            folder.mkdir(parents=True, exist_ok=True)
        command = [str(executable), mode, str(folder)] + ([key] if key else [])
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=40)
        assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
        return result

    concurrent = run_dir / "concurrent"
    concurrent.mkdir()
    children = [subprocess.Popen([str(executable), "write", str(concurrent)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for _ in range(4)]
    for child in children:
        stdout, stderr = child.communicate(timeout=40)
        assert child.returncode == 0, (child.returncode, stdout, stderr)
    log = concurrent / "diagnostics.log"
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 800 and all("[CONCURRENT] seq=" in line and "tid=" in line for line in lines)
    assert len(list(concurrent.iterdir())) == 1
    results.append("PASS: four processes append 800 intact records to exactly one file; native error state retained")
    run("prune", concurrent)
    assert log.stat().st_size <= 2 * 1024 * 1024 and log.read_text().endswith("[NEWEST_RECORD]\n")
    assert len(list(concurrent.iterdir())) == 1
    results.append("PASS: bounded in-place retention keeps newest record without backup files")
    legacy = run_dir / "legacy"
    legacy.mkdir()
    legacy_log = legacy / "diagnostics.log"
    legacy_log.write_text("[OLD_INSTALLER] preserved\r\n", encoding="utf-16")
    run("legacy", legacy)
    assert "[OLD_INSTALLER] preserved" in legacy_log.read_text(encoding="utf-8") and "[AFTER_UTF16]" in legacy_log.read_text()
    results.append("PASS: old UTF-16 diagnostics convert to UTF-8 in place")
    unicode_dir = run_dir / ("unicode-" + chr(0x03bb))
    run("unicode", unicode_dir)
    assert chr(0x03bb) + chr(0x4e2d) in (unicode_dir / "diagnostics.log").read_text(encoding="utf-8")
    results.append("PASS: Unicode paths/messages and wide-format error preservation")
    packet_dir = run_dir / "restricted-helper-packet"
    run("packet", packet_dir)
    assert "helperPid=321 stage=desktop nativeError=5" in (packet_dir / "diagnostics.log").read_text()
    results.append("PASS: parent persists non-NUL-terminated helper failure packets; malformed/normal packets stay quiet")
    run("locked", concurrent)
    assert "blocked" not in log.read_text()
    run("disabled", run_dir / "removed-install")
    assert not (run_dir / "removed-install").exists()
    failure = run_dir / "open-failure"
    (failure / "diagnostics.log").mkdir(parents=True)
    run("open_failure", failure)
    assert len(list(failure.iterdir())) == 1
    results.append("PASS: lock/open failures do not spawn fallback logs; uninstall does not recreate directories")
    key = "Software\\MeshAgentTelemetryProbe\\" + str(uuid.uuid4())
    sessions = run_dir / "sessions"
    try:
        run("clean", sessions, key)
        session_log = sessions / "diagnostics.log"
        run("clean", sessions, key)
        assert "[PREVIOUS_SESSION]" not in session_log.read_text()
        run("exception", sessions, key)
        run("clean", sessions, key)
        text = session_log.read_text()
        assert "classification=access_violation" in text and "target=0x1234" in text and "classification=recorded_crash" in text
        run("heap_code", sessions, key)
        run("clean", sessions, key)
        assert "heap_corruption_reported" in session_log.read_text()
        run("startup_failure", sessions, key)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            value, kind = winreg.QueryValueEx(handle, "TelemetrySession")
        assert kind == winreg.REG_BINARY and int.from_bytes(value[8:12], "little") == 6
        child = subprocess.Popen([str(executable), "hang", str(sessions), key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        try:
            assert child.stdout.readline().strip() == "READY"
            child.kill()
            child.communicate(timeout=15)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        run("clean", sessions, key)
        text = session_log.read_text()
        assert "classification=unclean_exit" in text and "cause=unknown_crash_external_termination_power_loss_or_interrupted_shutdown" in text
        assert len(list(sessions.iterdir())) == 1
        results.append("PASS: clean/start-failure/crash-code/externally killed probe sessions are classified without attributing an unknown killer")
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
        except FileNotFoundError:
            pass
    (args.evidence / "runtime.log").write_text("\n".join(results) + "\n")
    print("\n".join(results))


if __name__ == "__main__":
    main()
