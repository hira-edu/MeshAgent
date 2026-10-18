#!/usr/bin/env python3
"""Check WFP reconciliation and failure diagnostics without changing firewall rules.

Runs extracted production orchestration with injected WFP observations. POSIX
hosts use a small Win32 type shim; MinGW also checks the real Windows headers.
"""
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#ifndef _WIN32
static size_t wcsnlen_s(const wchar_t* s,size_t n){size_t i=0;while(i<n&&s[i])++i;return i;}
#endif
#ifdef _WIN32
#include <windows.h>
#else
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_INVALID_PARAMETER 87
static DWORD last_error;
static void SetLastError(DWORD error) { last_error=error; }
static DWORD GetLastError(void) { return last_error; }
#endif
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
static int step, fail_step, aborts, closes, logs;
static int existing_valid, checks;
static int live_policy=1, transaction_policy;
static DWORD failure_status=0x80320009;
static wchar_t last_log[1024];
static struct { const wchar_t *nameSuffix; } g_ServiceWfpFilters[]={{L"v4"},{L"v6"}};
static BOOL Security_CheckWfpHardPermitForApp(const wchar_t *service,const wchar_t *exe) {
    assert(!wcscmp(service,L"svc") && !wcscmp(exe,L"agent.exe"));
    ++checks; SetLastError(444); return existing_valid;
}
static DWORD next(void) { return ++step==fail_step ? failure_status : ERROR_SUCCESS; }
static DWORD Security_WfpOpenEngine(HANDLE *engine) {
    DWORD status=next(); *engine=status==ERROR_SUCCESS?(HANDLE)1:NULL; return status;
}
static DWORD FwpmTransactionBegin0(HANDLE e,DWORD flags) { assert(e); transaction_policy=live_policy; return next(); }
static DWORD Security_WfpRemoveObjectsIfPresent(HANDLE e) { assert(e); DWORD result=next(); if(!result)transaction_policy=0; return result; }
static DWORD Security_WfpAddProviderAndSubLayer(HANDLE e,const wchar_t*s) { assert(e&&s); DWORD result=next(); if(!result)transaction_policy=2; return result; }
static DWORD Security_WfpAddPermitFilter(HANDLE e,const wchar_t*s,const wchar_t*p,const void*d) { assert(e&&s&&p&&d); return next(); }
static DWORD FwpmTransactionCommit0(HANDLE e) { assert(e); DWORD result=next(); if(!result)live_policy=transaction_policy; return result; }
static DWORD FwpmTransactionAbort0(HANDLE e) { assert(e); ++aborts; SetLastError(111); return 111; }
static DWORD FwpmEngineClose0(HANDLE e) { assert(e); ++closes; SetLastError(222); return 222; }
static void ServiceDeploy_LogInstallEvent(const wchar_t *format,...) {
    va_list args; va_start(args,format); vswprintf(last_log,1024,format,args); va_end(args);
    ++logs; SetLastError(333);
}
'''
DEPLOY_PRELUDE = r'''
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#ifndef _WIN32
#define _wcsicmp wcscmp
#endif
#define SECURITY_FIREWALL_MAX_ATTEMPTS 3
#define SECURITY_FIREWALL_SETTLE_TIMEOUT_MS 1
#define SECURITY_FIREWALL_RETRY_DELAY_MS 1
static int ordinary_valid, repair_ok, convergence_ok;
static int removals, path_removals, additions, convergence_checks;
static BOOL MeshRuntimeHost_GetServiceHostPathW(wchar_t *path,size_t count) {
    assert(count>8); wcscpy(path,L"host.exe"); return TRUE;
}
static BOOL Security_CheckFirewallRuleForService(const wchar_t*s,const wchar_t*p) { return ordinary_valid; }
static BOOL Security_CheckWebRtcFirewallRuleForService(const wchar_t*s,const wchar_t*p,BOOL host) { return ordinary_valid; }
static int migrate_ok=1, migrations;
static BOOL Security_MigrateFirewallRuleNames(const wchar_t*s,const wchar_t*h,const wchar_t*a) { ++migrations; return migrate_ok; }
static int wfp_removals, ordinary_cleanup_ok=1;
static BOOL Security_RemoveOrdinaryFirewallRulesForService(const wchar_t*s) {
    ++removals; ordinary_valid=0; step=0; return ordinary_cleanup_ok;
}
static BOOL Security_RemoveWfpHardPermitForService(const wchar_t*s) {
    ++wfp_removals; live_policy=0; return TRUE;
}
static BOOL Security_RemoveFirewallRulesByExePath(const wchar_t*p) {
    assert(!wcscmp(p,L"agent.exe")); ++path_removals; return TRUE;
}
static BOOL Security_AddFirewallRuleForService(const wchar_t*s,const wchar_t*p) {
    ++additions; ordinary_valid=repair_ok; return repair_ok;
}
static BOOL Security_AddWebRtcFirewallRuleForService(const wchar_t*s,const wchar_t*p,BOOL host) {
    ++additions; return repair_ok;
}
static BOOL ServiceDeploy_WaitForFirewallRuleConvergence(const wchar_t*s,const wchar_t*h,const wchar_t*a,DWORD timeout) {
    ++convergence_checks; return convergence_ok;
}
// Never sleep in a fault-injection test (including Windows).
#define Sleep(ms) ((void)(ms))
'''
DEPLOY_TESTS = r'''
static void test_refresh(void) {
    step=aborts=closes=logs=checks=0;
    existing_valid=ordinary_valid=repair_ok=convergence_ok=1;
    fail_step=3; failure_status=0x8032000A;
    assert(ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(removals==0 && path_removals==0 && additions==0 && step==0 && checks==1);
    puts("PASS: healthy update reconciliation does not remove any firewall rules");

    ordinary_valid=0;
    assert(ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(removals==1 && path_removals==1 && additions==3 && step==0 && convergence_checks==1);
    puts("PASS: ordinary rule drift repairs successfully while valid in-use WFP survives cleanup");

    removals=path_removals=additions=convergence_checks=0;
    existing_valid=ordinary_valid=convergence_ok=0; step=0; fail_step=3;
    assert(!ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(removals==3 && additions==9 && convergence_checks==3 && aborts==3 && closes==3);
    assert(wcsstr(last_log,L"wfpError=2150760458"));
    puts("PASS: invalid in-use WFP exhausts retries and reports the original failure");

    removals=path_removals=additions=convergence_checks=0;
    existing_valid=convergence_ok=1; ordinary_valid=repair_ok=0; step=0;
    assert(!ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(removals==3 && additions==9 && convergence_checks==3 && step==0);
    puts("PASS: retaining valid WFP does not hide ordinary firewall repair failure");
    // Label-only drift is invalid to the new verifier, but the old rules still
    // work. Every failed replacement must retain that committed policy.
    for(fail_step=1;fail_step<=7;++fail_step) {
        live_policy=1; existing_valid=0; ordinary_valid=repair_ok=1; convergence_ok=0;
        removals=path_removals=additions=convergence_checks=0; step=aborts=closes=0;
        assert(!ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
        assert(live_policy==1 && wfp_removals==0 && removals==3);
    }
    live_policy=1; fail_step=0; step=0; existing_valid=0;
    ordinary_valid=repair_ok=convergence_ok=1;
    assert(ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(live_policy==2 && wfp_removals==0);
    puts("PASS: label migration retains working WFP on every replacement failure and changes it only at commit");
    assert(Security_RemoveFirewallRuleForService(L"svc") && wfp_removals==1 && live_policy==0);
    ordinary_cleanup_ok=0;live_policy=1;
    assert(!Security_RemoveFirewallRuleForService(L"svc") && wfp_removals==2 && live_policy==0);
    puts("PASS: uninstall still removes WFP even when ordinary-rule cleanup fails");
    // A failed historical-label rename must not skip check/repair.
    ordinary_cleanup_ok=1; migrate_ok=0; migrations=0; live_policy=2; fail_step=0; step=0;
    existing_valid=ordinary_valid=repair_ok=convergence_ok=1;
    removals=path_removals=additions=convergence_checks=0;
    assert(ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(migrations==1 && removals==0 && additions==0 && wcsstr(last_log,L"branding migration failed"));
    ordinary_valid=0;
    assert(ServiceDeploy_RefreshFirewallRulesWithRetry(L"svc",L"host.exe",L"agent.exe"));
    assert(migrations==2 && removals==1 && additions==3 && convergence_checks==1);
    migrate_ok=1;
    puts("PASS: a failed label rename still checks and repairs firewall rules");

}
'''
TESTS = r'''
int main(void) {
    assert(!Security_AddWfpHardPermitForApp(NULL,L"agent.exe") && GetLastError()==ERROR_INVALID_PARAMETER);
    assert(!Security_AddWfpHardPermitForApp(L"svc",L"") && GetLastError()==ERROR_INVALID_PARAMETER);
    assert(step==0 && logs==0 && closes==0 && checks==0);
    // The reported incident: the existing chain matches, but attempting to
    // remove it would return FWP_E_IN_USE. Reuse it without opening a writer.
    existing_valid=1; fail_step=3; failure_status=0x8032000A;
    assert(Security_AddWfpHardPermitForApp(L"svc",L"agent.exe"));
    assert(checks==1 && step==0 && aborts==0 && closes==0 && logs==0);
    puts("PASS: valid in-use WFP configuration is retained without mutation");
    // The same deletion failure must remain a failure for an incomplete chain
    // or a different app ID; the preflight verifier has rejected reuse.
    existing_valid=0;
    assert(!Security_AddWfpHardPermitForApp(L"svc",L"agent.exe"));
    assert(GetLastError()==0x8032000A && step==3 && aborts==1 && closes==1 && logs==1);
    puts("PASS: invalid configuration cannot turn FWP_E_IN_USE into success");
    failure_status=0x80320009;
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
    test_refresh();
    return 0;
}
'''
# Production removal and legacy-filter helpers run against an in-memory WFP
# store that enforces references: a sublayer with filters, or a provider with a
# sublayer or filters, returns FWP_E_IN_USE, and an aborted transaction restores
# the store.
LEGACY_PRELUDE = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <stddef.h>
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { unsigned int Data1; unsigned short Data2, Data3; unsigned char Data4[8]; } GUID;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_INVALID_PARAMETER 87
#define UNREFERENCED_PARAMETER(p) ((void)(p))
static DWORD last_error;
static void SetLastError(DWORD error) { last_error=error; }
static DWORD GetLastError(void) { return last_error; }
#endif
#ifndef FWP_E_FILTER_NOT_FOUND
#define FWP_E_FILTER_NOT_FOUND 0x80320003UL
#define FWP_E_PROVIDER_NOT_FOUND 0x80320005UL
#define FWP_E_SUBLAYER_NOT_FOUND 0x80320007UL
#define FWP_E_IN_USE 0x8032000AUL
#define FWP_E_SESSION_ABORTED 0x80320010UL
#endif
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
typedef struct { int unused; } FWPM_FILTER0;
static const GUID SECURITY_WFP_SUBLAYER_KEY = { 0x05af9ca4, 0x8e4a, 0x44e4, { 0x90, 0x6d, 0x70, 0xef, 0xda, 0xe2, 0x3c, 0x19 } };
static const GUID SECURITY_WFP_PROVIDER_KEY = { 0xa756f5fb, 0x9416, 0x4c60, { 0x96, 0xf1, 0x61, 0x4d, 0x88, 0x44, 0x79, 0x03 } };
static const GUID OWN_KEYS[4] = { {1}, {2}, {3}, {4} };
static const GUID UNKNOWN_KEY = { 9 };
static struct { const GUID *filterKey; } g_ServiceWfpFilters[] = { {&OWN_KEYS[0]}, {&OWN_KEYS[1]}, {&OWN_KEYS[2]}, {&OWN_KEYS[3]} };
typedef struct { GUID keys[8]; int count, sublayer, provider; } Store;
static Store store, saved;
static int transactions, aborts, commits, frees;
static DWORD get_error;
static FWPM_FILTER0 found_filter;
static int find_key(const GUID *key) {
    for (int i=0;i<store.count;++i) { if (!memcmp(&store.keys[i],key,sizeof(GUID))) { return i; } }
    return -1;
}
static void add_key(const GUID *key) { assert(store.count<8); store.keys[store.count++]=*key; }
static DWORD Security_WfpOpenEngine(HANDLE *engine) { *engine=(HANDLE)1; return ERROR_SUCCESS; }
static DWORD FwpmEngineClose0(HANDLE engine) { assert(engine); return ERROR_SUCCESS; }
static DWORD FwpmTransactionBegin0(HANDLE engine,DWORD flags) { assert(engine); saved=store; ++transactions; return ERROR_SUCCESS; }
static DWORD FwpmTransactionCommit0(HANDLE engine) { assert(engine); ++commits; return ERROR_SUCCESS; }
static DWORD FwpmTransactionAbort0(HANDLE engine) { assert(engine); store=saved; ++aborts; return ERROR_SUCCESS; }
static DWORD FwpmFilterDeleteByKey0(HANDLE engine,const GUID *key) {
    int i=find_key(key); if (i<0) { return FWP_E_FILTER_NOT_FOUND; }
    store.keys[i]=store.keys[--store.count]; return ERROR_SUCCESS;
}
static DWORD FwpmSubLayerDeleteByKey0(HANDLE engine,const GUID *key) {
    if (!store.sublayer) { return FWP_E_SUBLAYER_NOT_FOUND; }
    if (store.count) { return FWP_E_IN_USE; }
    store.sublayer=0; return ERROR_SUCCESS;
}
static DWORD FwpmProviderDeleteByKey0(HANDLE engine,const GUID *key) {
    if (!store.provider) { return FWP_E_PROVIDER_NOT_FOUND; }
    if (store.count || store.sublayer) { return FWP_E_IN_USE; }
    store.provider=0; return ERROR_SUCCESS;
}
static DWORD FwpmFilterGetByKey0(HANDLE engine,const GUID *key,FWPM_FILTER0 **filter) {
    if (get_error) { return get_error; }
    if (find_key(key)<0) { return FWP_E_FILTER_NOT_FOUND; }
    *filter=&found_filter; return ERROR_SUCCESS;
}
static void FwpmFreeMemory0(void **p) { *p=NULL; ++frees; }
'''
LEGACY_TESTS = r'''
static void reset_store(int legacy, int unknown) {
    memset(&store,0,sizeof(store));
    for (size_t i=0;i<_countof(OWN_KEYS);++i) { add_key(&OWN_KEYS[i]); }
    if (legacy) { for (size_t i=0;i<_countof(g_ServiceWfpLegacyFilterKeys);++i) { add_key(g_ServiceWfpLegacyFilterKeys[i]); } }
    if (unknown) { add_key(&UNKNOWN_KEY); }
    store.sublayer=store.provider=1;
    transactions=aborts=commits=frees=0; get_error=0;
}
int main(void) {
    HANDLE engine=(HANDLE)1;
    // The reported endpoint: four agent filters plus both svchost.exe filters.
    reset_store(1,0);
    assert(Security_WfpLegacyFilterPresent(engine) && frees==1);
    assert(Security_WfpRemoveObjectsIfPresent(engine)==ERROR_SUCCESS);
    assert(store.count==0 && !store.sublayer && !store.provider);
    puts("PASS: repair removal deletes legacy svchost.exe filters before the sublayer and provider");

    reset_store(1,0);
    assert(Security_RemoveWfpHardPermitForService(L"svc"));
    assert(store.count==0 && !store.sublayer && !store.provider && commits==1 && aborts==0);
    puts("PASS: uninstall removal deletes legacy filters and commits");

    reset_store(0,0);
    assert(!Security_WfpLegacyFilterPresent(engine));
    assert(Security_RemoveWfpHardPermitForService(L"svc") && store.count==0 && commits==1);
    puts("PASS: removal without legacy filters is unchanged");

    reset_store(0,0); get_error=FWP_E_SESSION_ABORTED;
    assert(Security_WfpLegacyFilterPresent(engine));
    puts("PASS: an unverifiable legacy-filter lookup fails closed");

    // Only known keys are deleted; any other reference keeps failing atomically.
    reset_store(1,1);
    assert(!Security_RemoveWfpHardPermitForService(L"svc"));
    assert(GetLastError()==FWP_E_IN_USE && aborts==1 && commits==0);
    assert(store.count==7 && store.sublayer && store.provider);
    puts("PASS: an unknown filter still fails with FWP_E_IN_USE and the transaction restores every filter");
    return 0;
}
'''


def extract_legacy_keys(source):
    keys = re.findall(r'(?m)^static const GUID SECURITY_WFP_LEGACY_\w+ = \{.*\};$', source)
    table = re.search(r'static const GUID\* const g_ServiceWfpLegacyFilterKeys\[\] =\s*\{[^;]*\};', source)
    if len(keys) != 2 or not table:
        raise AssertionError('Missing legacy WFP filter keys')
    for guid in ('0x8b3e5b31, 0x4a32, 0x460e', '0x61f71df4, 0x3861, 0x4683'):
        if not any(guid in key for key in keys):
            raise AssertionError('Missing legacy WFP filter key ' + guid)
    return '\n'.join(keys) + '\n' + table.group() + '\n'


def run_fixture(args, fixture, name):
    exe = args.out / (name + '.exe')
    subprocess.run([args.cc, '-std=c11', '-g', '-O1', '-fsanitize=address,undefined', str(fixture), '-o', str(exe)], check=True)
    env = os.environ.copy()
    compiler = shutil.which(args.cc)
    if compiler:
        runtimes = list(Path(compiler).parent.parent.glob('lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll'))
        if runtimes:
            env['PATH'] = str(runtimes[0].parent) + os.pathsep + env.get('PATH', '')
    result = subprocess.run([str(exe)], capture_output=True, text=True, env=env, timeout=30)
    (args.out / (name + '-results.txt')).write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end='')
    result.check_returncode()
    if os.name != 'nt' and shutil.which('x86_64-w64-mingw32-gcc'):
        subprocess.run(['x86_64-w64-mingw32-gcc', '-std=c11', '-Wall', '-Wextra',
                        '-Wno-unused-parameter', '-Wno-sign-compare', '-c', str(fixture), '-o',
                        str(args.out / (name + '-windows.o'))], check=True)
        print('PASS: ' + name + ' fixture compiles against Windows headers')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts/validation/wfp-failure-telemetry')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source = (ROOT / 'meshservice/security_firewall.c').read_text()
    fixture = args.out / 'probe.c'
    deployment = (ROOT / 'meshservice/service_deployment.c').read_text()
    fixture.write_text(PRELUDE + extract(source, 'Security_AddWfpHardPermitForApp') +
                       DEPLOY_PRELUDE + extract(source, 'Security_RemoveFirewallRuleForService') +
                       extract(deployment, 'ServiceDeploy_DoFirewallRulesMatch') +
                       extract(deployment, 'ServiceDeploy_RefreshFirewallRulesWithRetry') +
                       DEPLOY_TESTS + TESTS)
    run_fixture(args, fixture, 'probe')

    # extract() would match the guard call inside Security_AddWfpHardPermitForApp.
    check = extract(source[source.index('BOOL Security_CheckWfpHardPermitForApp('):], 'Security_CheckWfpHardPermitForApp')
    if 'Security_WfpLegacyFilterPresent(engine)' not in check:
        raise AssertionError('Hard-permit check does not reject legacy WFP filters')
    legacy = args.out / 'legacy.c'
    legacy.write_text(LEGACY_PRELUDE + extract_legacy_keys(source) +
                      extract(source, 'Security_WfpDeleteFilterByKeyIfPresent') +
                      extract(source, 'Security_WfpDeleteLegacyFiltersIfPresent') +
                      extract(source, 'Security_WfpLegacyFilterPresent') +
                      extract(source, 'Security_WfpRemoveObjectsIfPresent') +
                      extract(source, 'Security_RemoveWfpHardPermitForService') +
                      LEGACY_TESTS)
    run_fixture(args, legacy, 'legacy')
    print('PASS: hard-permit check rejects a chain that still contains legacy filters')


if __name__ == '__main__':
    main()
