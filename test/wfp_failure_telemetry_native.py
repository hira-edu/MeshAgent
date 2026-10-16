#!/usr/bin/env python3
"""Check WFP failure/cleanup diagnostics without accessing the real firewall."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
static int step, fail_step, aborts, closes, logs;
static wchar_t last_log[1024];
static struct { const wchar_t *nameSuffix; } g_ServiceWfpFilters[]={{L"v4"},{L"v6"}};
static DWORD next(void) { return ++step==fail_step ? 0x80320009 : ERROR_SUCCESS; }
static DWORD Security_WfpOpenEngine(HANDLE *engine) {
    DWORD status=next(); *engine=status==ERROR_SUCCESS?(HANDLE)1:NULL; return status;
}
static DWORD FwpmTransactionBegin0(HANDLE e,DWORD flags) { assert(e); return next(); }
static DWORD Security_WfpRemoveObjectsIfPresent(HANDLE e) { assert(e); return next(); }
static DWORD Security_WfpAddProviderAndSubLayer(HANDLE e,const wchar_t*s) { assert(e&&s); return next(); }
static DWORD Security_WfpAddPermitFilter(HANDLE e,const wchar_t*s,const wchar_t*p,const void*d) { assert(e&&s&&p&&d); return next(); }
static DWORD FwpmTransactionCommit0(HANDLE e) { assert(e); return next(); }
static DWORD FwpmTransactionAbort0(HANDLE e) { assert(e); ++aborts; SetLastError(111); return 111; }
static DWORD FwpmEngineClose0(HANDLE e) { assert(e); ++closes; SetLastError(222); return 222; }
static void ServiceDeploy_LogInstallEvent(const wchar_t *format,...) {
    va_list args; va_start(args,format); vswprintf(last_log,1024,format,args); va_end(args);
    ++logs; SetLastError(333);
}
'''
TESTS = r'''
int main(void) {
    assert(!Security_AddWfpHardPermitForApp(NULL,L"agent.exe") && GetLastError()==ERROR_INVALID_PARAMETER);
    assert(!Security_AddWfpHardPermitForApp(L"svc",L"") && GetLastError()==ERROR_INVALID_PARAMETER);
    assert(step==0 && logs==0 && closes==0);
    const wchar_t *stages[]={L"open",L"begin",L"remove-existing",L"provider-sublayer",L"filter",L"filter",L"commit"};
    for(fail_step=1;fail_step<=7;++fail_step) {
        step=aborts=closes=logs=0;
        assert(!Security_AddWfpHardPermitForApp(L"svc",L"agent.exe"));
        assert(GetLastError()==0x80320009 && step==fail_step && logs==1);
        assert(aborts==(fail_step>=3) && closes==(fail_step>=2));
        wchar_t stage[80]; swprintf(stage,80,L"stage=%ls ",stages[fail_step-1]);
        assert(wcsstr(last_log,stage) && wcsstr(last_log,L"0x80320009"));
        if(fail_step==5)assert(wcsstr(last_log,L"filter=v4"));
        if(fail_step==6)assert(wcsstr(last_log,L"filter=v6"));
        printf("PASS: WFP stage %d retains original status through cleanup/logging\n",fail_step);
    }
    step=aborts=closes=logs=0; fail_step=0;
    assert(Security_AddWfpHardPermitForApp(L"svc",L"agent.exe"));
    assert(step==7 && aborts==0 && closes==1 && logs==0);
    puts("PASS: successful commit stays successful; invalid arguments have deterministic status");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts/validation/wfp-failure-telemetry')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Requires Windows SDK and Clang')
    args.out.mkdir(parents=True, exist_ok=True)
    source = (ROOT / 'meshservice/security_firewall.c').read_text()
    fixture = args.out / 'probe.c'
    fixture.write_text(PRELUDE + extract(source, 'Security_AddWfpHardPermitForApp') + TESTS)
    exe = args.out / 'probe.exe'
    subprocess.run([args.cc, '-std=c11', '-g', '-O1', '-fsanitize=address,undefined', str(fixture), '-o', str(exe)], check=True)
    env = os.environ.copy()
    compiler = shutil.which(args.cc)
    if compiler:
        runtimes = list(Path(compiler).parent.parent.glob('lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll'))
        if runtimes:
            env['PATH'] = str(runtimes[0].parent) + os.pathsep + env.get('PATH', '')
    result = subprocess.run([str(exe)], capture_output=True, text=True, env=env, timeout=30)
    (args.out / 'results.txt').write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end='')
    result.check_returncode()


if __name__ == '__main__':
    main()
