#!/usr/bin/env python3
"""Exercise production firewall label migration and WFP name admission.

Uses in-memory COM/WFP fixtures, never the machine's firewall. Runs with Clang
sanitizers on POSIX and also compiles against real Windows COM/WFP headers.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'meshservice/security_firewall.c').read_text()
OUT = ROOT / 'artifacts/validation/network-policy-branding'
FORMATS = '\n'.join(re.findall(r'^#define SECURITY_(?:(?:FW_RULE|WFP_\w+_NAME)_\w*FMT|FW_WEBRTC_DESCRIPTION)\s+.*$', SOURCE, re.M))


def production(name):
    # Locate the definition, not an earlier call inside maintenance code.
    match = re.search(r'(?m)^(?:static )?(?:BOOL|DWORD) ' + re.escape(name) + r'\(', SOURCE)
    assert match, name
    return extract(SOURCE[match.start():], name)


COMMON = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#ifdef _WIN32
#include <windows.h>
#include <initguid.h>
#include <netfw.h>
#include <fwpmu.h>
#include <strsafe.h>
#else
typedef int BOOL, HRESULT;
typedef long LONG;
typedef unsigned long DWORD, ULONG;
typedef unsigned int UINT32;
typedef void* HANDLE;
typedef wchar_t* BSTR;
typedef struct { unsigned int Data1; unsigned short Data2,Data3; unsigned char Data4[8]; } GUID;
typedef const GUID *REFIID, *REFCLSID;
#define STDMETHODCALLTYPE
#define TRUE 1
#define FALSE 0
#define S_OK 0
#define S_FALSE 1
#define E_FAIL (-1)
#define FAILED(v) ((v)<0)
#define SUCCEEDED(v) ((v)>=0)
#define CLSCTX_INPROC_SERVER 1
#define ERROR_SUCCESS 0
#define _wcsicmp wcscasecmp
#define wcsnlen_s wcsnlen
#define swprintf_s swprintf
static int StringCchPrintfW(wchar_t* out,size_t count,const wchar_t* format,...) {
    va_list args;va_start(args,format);int n=vswprintf(out,count,format,args);va_end(args);
    return n<0||(size_t)n>=count?-1:0;
}
#endif
#ifndef _countof
#define _countof(a) (sizeof(a)/sizeof(*(a)))
#endif
'''
COM = r'''
#ifndef _WIN32
typedef struct IUnknown IUnknown;
typedef struct IDispatch IDispatch;
typedef struct IEnumVARIANT IEnumVARIANT;
typedef struct INetFwRule INetFwRule;
typedef struct INetFwRules INetFwRules;
typedef struct INetFwPolicy2 INetFwPolicy2;
typedef struct { int vt; IDispatch* pdispVal; } VARIANT;
#define VT_DISPATCH 9
typedef struct { HRESULT (*QueryInterface)(IUnknown*,REFIID,void**);ULONG (*Release)(IUnknown*); } IUnknownVtbl;
typedef struct { HRESULT (*QueryInterface)(IDispatch*,REFIID,void**); } IDispatchVtbl;
typedef struct { HRESULT (*Next)(IEnumVARIANT*,ULONG,VARIANT*,ULONG*);ULONG (*Release)(IEnumVARIANT*); } IEnumVARIANTVtbl;
typedef struct { HRESULT (*get_Name)(INetFwRule*,BSTR*);HRESULT (*get_ServiceName)(INetFwRule*,BSTR*);HRESULT (*get_ApplicationName)(INetFwRule*,BSTR*);HRESULT (*put_Name)(INetFwRule*,BSTR);ULONG (*Release)(INetFwRule*); } INetFwRuleVtbl;
typedef struct { HRESULT (*get__NewEnum)(INetFwRules*,IUnknown**);ULONG (*Release)(INetFwRules*); } INetFwRulesVtbl;
typedef struct { HRESULT (*get_Rules)(INetFwPolicy2*,INetFwRules**);ULONG (*Release)(INetFwPolicy2*); } INetFwPolicy2Vtbl;
struct IUnknown { const IUnknownVtbl* lpVtbl; };
struct IDispatch { const IDispatchVtbl* lpVtbl; };
struct IEnumVARIANT { const IEnumVARIANTVtbl* lpVtbl; };
struct INetFwRule { const INetFwRuleVtbl* lpVtbl; };
struct INetFwRules { const INetFwRulesVtbl* lpVtbl; };
struct INetFwPolicy2 { const INetFwPolicy2Vtbl* lpVtbl; };
static const GUID CLSID_NetFwPolicy2={0},IID_INetFwPolicy2={0},IID_IEnumVARIANT={0},IID_INetFwRule={0};
#endif
typedef struct { INetFwRule rule; IDispatch dispatch; wchar_t name[384];const wchar_t* service;const wchar_t* app; } Entry;
static Entry entries[8];static int count,index_,renames,removes,allocations,failRename,failNext,failProperty,failRemove,guids;
static INetFwPolicy2 policy;static INetFwRules rules;static IUnknown unknown;static IEnumVARIANT enumerator;
static BSTR allocate(const wchar_t* text) { if(!text)return NULL;BSTR out=malloc((wcslen(text)+1)*sizeof(wchar_t));assert(out);wcscpy(out,text);++allocations;return out; }
static void release_string(BSTR text){if(text){free(text);--allocations;}}
#define SysAllocString allocate
#define SysFreeString release_string
#define VariantInit(v) memset(v,0,sizeof(*(v)))
#define VariantClear(v) ((void)(v))
static void Security_FreeBstr(BSTR* text){release_string(*text);*text=NULL;}
static BOOL Security_ComInit(BOOL* initialized){*initialized=TRUE;return TRUE;}
static void Security_ComUninit(BOOL initialized){assert(initialized);}
static Entry* from_rule(INetFwRule* rule){return (Entry*)((char*)rule - offsetof(Entry,rule));}
static HRESULT STDMETHODCALLTYPE get_name(INetFwRule* r,BSTR* out){*out=allocate(from_rule(r)->name);return S_OK;}
static HRESULT STDMETHODCALLTYPE get_service(INetFwRule* r,BSTR* out){if(failProperty)return E_FAIL;*out=allocate(from_rule(r)->service);return S_OK;}
static HRESULT STDMETHODCALLTYPE get_app(INetFwRule* r,BSTR* out){*out=allocate(from_rule(r)->app);return S_OK;}
static HRESULT STDMETHODCALLTYPE set_name(INetFwRule* r,BSTR text){if(++renames==failRename)return E_FAIL;wcscpy(from_rule(r)->name,text);return S_OK;}
static ULONG STDMETHODCALLTYPE rule_release(INetFwRule* r){(void)r;return 0;}
static ULONG STDMETHODCALLTYPE policy_release(INetFwPolicy2* r){(void)r;return 0;}
static ULONG STDMETHODCALLTYPE rules_release(INetFwRules* r){(void)r;return 0;}
static ULONG STDMETHODCALLTYPE unknown_release(IUnknown* r){(void)r;return 0;}
static ULONG STDMETHODCALLTYPE enum_release(IEnumVARIANT* r){(void)r;return 0;}
static HRESULT STDMETHODCALLTYPE dispatch_query(IDispatch* dispatch,REFIID iid,void** out){(void)iid;Entry* e=(Entry*)((char*)dispatch - offsetof(Entry,dispatch));*out=&e->rule;return S_OK;}
static HRESULT STDMETHODCALLTYPE enum_query(IUnknown* object,REFIID iid,void** out){(void)object;(void)iid;*out=&enumerator;return S_OK;}
static HRESULT STDMETHODCALLTYPE next_rule(IEnumVARIANT* e,ULONG n,VARIANT* value,ULONG* fetched){(void)e;assert(n==1);if(failNext)return E_FAIL;if(index_==count)return S_FALSE;value->vt=VT_DISPATCH;value->pdispVal=&entries[index_++].dispatch;*fetched=1;return S_OK;}
static HRESULT STDMETHODCALLTYPE get_enum(INetFwRules* r,IUnknown** out){(void)r;index_=0;*out=&unknown;return S_OK;}
static HRESULT STDMETHODCALLTYPE get_rules(INetFwPolicy2* p,INetFwRules** out){(void)p;*out=&rules;return S_OK;}
static HRESULT create_policy(REFCLSID cls,IUnknown* outer,DWORD context,REFIID iid,void** out){(void)cls;(void)outer;(void)context;(void)iid;*out=&policy;return S_OK;}
#define CoCreateInstance create_policy
/* Removal selects by label alone, so it can reach foreign duplicates. */
static BOOL Security_RemoveRuleByName(INetFwRules* r,const wchar_t* name){
    assert(r==&rules&&name);++removes;if(failRemove)return FALSE;
    int kept=0;for(int i=0;i<count;++i)if(_wcsicmp(entries[i].name,name))entries[kept++]=entries[i];
    count=kept;return TRUE;
}
#ifndef _WIN32
static HRESULT CoCreateGuid(GUID* id){memset(id,0,sizeof(*id));id->Data1=++guids;return S_OK;}
static int StringFromGUID2(const GUID* id,wchar_t* out,int cch){int n=swprintf(out,cch,L"{%08X}",id->Data1);return n<0?0:n+1;}
#endif
static INetFwRuleVtbl ruleVtbl={.get_Name=get_name,.get_ServiceName=get_service,.get_ApplicationName=get_app,.put_Name=set_name,.Release=rule_release};
static IDispatchVtbl dispatchVtbl={.QueryInterface=dispatch_query};
static INetFwPolicy2Vtbl policyVtbl={.get_Rules=get_rules,.Release=policy_release};
static INetFwRulesVtbl rulesVtbl={.get__NewEnum=get_enum,.Release=rules_release};
static IUnknownVtbl unknownVtbl={.QueryInterface=enum_query,.Release=unknown_release};
static IEnumVARIANTVtbl enumVtbl={.Next=next_rule,.Release=enum_release};
static void add(const wchar_t* name,const wchar_t* service,const wchar_t* app){Entry* e=&entries[count++];e->rule.lpVtbl=&ruleVtbl;e->dispatch.lpVtbl=&dispatchVtbl;wcscpy(e->name,name);e->service=service;e->app=app;}
static void reset(void){assert(allocations==0);count=index_=renames=removes=failRename=failNext=failProperty=failRemove=0;policy.lpVtbl=&policyVtbl;rules.lpVtbl=&rulesVtbl;unknown.lpVtbl=&unknownVtbl;enumerator.lpVtbl=&enumVtbl;}
#ifndef _WIN32
typedef int NET_FW_RULE_DIRECTION;
#define NET_FW_RULE_DIR_OUT 2
#define NET_FW_RULE_DIR_IN 1
#define NET_FW_IP_PROTOCOL_ANY 256
#define NET_FW_IP_PROTOCOL_UDP 17
#endif
#ifndef NET_FW_IP_PROTOCOL_ANY
#define NET_FW_IP_PROTOCOL_ANY 256
#endif
static wchar_t emitted[3][384];static int additions;
static BOOL Security_AddFirewallRuleEx(const wchar_t* name,const wchar_t* service,const wchar_t* app,NET_FW_RULE_DIRECTION dir,LONG protocol,BOOL edge,const wchar_t* description){
    assert(additions<3&&service&&app);wcscpy(emitted[additions++],name);
    assert(wcsncmp(name,service,wcslen(service))==0);
    assert((dir==NET_FW_RULE_DIR_OUT&&protocol==NET_FW_IP_PROTOCOL_ANY&&!edge&&!description)||
        (dir==NET_FW_RULE_DIR_IN&&protocol==NET_FW_IP_PROTOCOL_UDP&&edge&&description));return TRUE;
}
'''
COM += r'''
static BOOL wfpPresent;
static int wfpRemoves;
static void ServiceDeploy_LogInstallEvent(const wchar_t* format, ...){(void)format;}
static BOOL Security_RemoveWfpHardPermitForService(const wchar_t* service){assert(service);++wfpRemoves;wfpPresent=FALSE;return TRUE;}
static BOOL Security_CheckWfpHardPermitExists(const wchar_t* service){assert(service);return wfpPresent;}
'''
COM_TESTS = r'''
int main(void){
    reset();
    add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",L"host.exe");
    add(L"Windows AcmeSupport - WebRTC UDP Inbound (Host)",L"AcmeSupport",L"host.exe");
    add(L"Windows AcmeSupport - WebRTC UDP Inbound (Agent)",L"AcmeSupport",L"agent.exe");
    add(L"Windows AcmeSupport - Outbound",L"Unrelated",L"host.exe");
    add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",L"other.exe");
    add(L"Unrelated label",L"AcmeSupport",L"host.exe");
    assert(Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe"));
    assert(renames==3&&removes==0&&allocations==0);
    assert(!wcscmp(entries[0].name,L"AcmeSupport - Outbound"));
    assert(!wcscmp(entries[1].name,L"AcmeSupport - WebRTC UDP Inbound (Host)"));
    assert(!wcscmp(entries[2].name,L"AcmeSupport - WebRTC UDP Inbound (Agent)"));
    assert(!wcscmp(entries[3].name,L"Windows AcmeSupport - Outbound")&&!wcscmp(entries[4].name,entries[3].name));
    assert(Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe")&&renames==3);
    /* The owned stale-path duplicate is moved to a unique label and removed;
     * the foreign rule sharing the historical label is never modified. */
    assert(Security_RemoveRuleByNameForService(&rules,L"Windows AcmeSupport - Outbound",L"AcmeSupport")&&removes==1&&renames==4);
    assert(count==5&&!wcscmp(entries[3].name,L"Windows AcmeSupport - Outbound")&&!wcscmp(entries[3].service,L"Unrelated"));
    assert(Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Outbound",L"AcmeSupport")&&removes==2&&count==4);
    reset();add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",L"host.exe");failRename=1;
    assert(!Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe")&&allocations==0);
    assert(!wcscmp(entries[0].name,L"Windows AcmeSupport - Outbound")&&removes==0);
    failRename=0;assert(Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe"));
    failNext=1;assert(!Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe"));
    /* netsh/GPO rules carry no service or program; they are foreign, and an
     * owned rule later in the enumeration must still migrate. */
    failNext=0;reset();
    add(L"Windows AcmeSupport - Outbound",NULL,NULL);
    add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",NULL);
    add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",L"host.exe");
    assert(Security_MigrateFirewallRuleNames(L"AcmeSupport",L"host.exe",L"agent.exe")&&renames==1&&allocations==0);
    assert(!wcscmp(entries[0].name,L"Windows AcmeSupport - Outbound")&&!wcscmp(entries[1].name,entries[0].name));
    assert(!wcscmp(entries[2].name,L"AcmeSupport - Outbound"));
    failNext=0;failProperty=1;assert(!Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Outbound",L"AcmeSupport"));
    assert(allocations==0);

    /* A failed move or removal restores every owned label for a later retry. */
    reset();
    add(L"AcmeSupport - Outbound",L"Unrelated",L"x.exe");
    add(L"AcmeSupport - Outbound",L"AcmeSupport",L"host.exe");
    add(L"AcmeSupport - Outbound",L"AcmeSupport",L"agent.exe");
    failRename=2;
    assert(!Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Outbound",L"AcmeSupport"));
    assert(removes==0&&count==3&&renames==3);
    for(int i=0;i<3;++i)assert(!wcscmp(entries[i].name,L"AcmeSupport - Outbound"));
    failRename=renames=0;failRemove=1;
    assert(!Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Outbound",L"AcmeSupport"));
    assert(removes==1&&renames==4&&count==3);
    for(int i=0;i<3;++i)assert(!wcscmp(entries[i].name,L"AcmeSupport - Outbound"));
    failRemove=0;
    assert(Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Outbound",L"AcmeSupport"));
    assert(count==1&&!wcscmp(entries[0].service,L"Unrelated")&&!wcscmp(entries[0].name,L"AcmeSupport - Outbound"));
    assert(allocations==0);

    assert(!Security_RemoveFirewallRuleForService(NULL) && !Security_RemoveFirewallRuleForService(L""));
    assert(wfpRemoves==0);
    reset();
    add(L"Windows AcmeSupport - Outbound",L"Unrelated",L"host.exe");
    /* Foreign-only labels are absent for removal and replacement alike, so
     * install/repair can add an owned duplicate beside them. */
    assert(Security_RemoveRuleByNameForService(&rules,L"Windows AcmeSupport - Outbound",L"AcmeSupport"));
    assert(count==1&&removes==0&&renames==0);
    assert(!Security_IsFirewallRulePresentForService(L"Windows AcmeSupport - Outbound",L"AcmeSupport"));
    assert(!Security_CheckFirewallRuleExists(L"AcmeSupport") && removes==0);
    wfpPresent=TRUE;
    assert(Security_RemoveOrdinaryFirewallRulesForService(L"AcmeSupport") && wfpPresent && wfpRemoves==0);
    assert(Security_RemoveFirewallRuleForService(L"AcmeSupport") && !wfpPresent && wfpRemoves==1 && removes==0);
    add(L"AcmeSupport - Inbound",NULL,L"host.exe");
    assert(!Security_CheckFirewallRuleExists(L"AcmeSupport"));
    assert(Security_RemoveRuleByNameForService(&rules,L"AcmeSupport - Inbound",L"AcmeSupport")&&count==2);
    add(L"Windows AcmeSupport - Outbound",L"AcmeSupport",L"host.exe");
    assert(Security_CheckFirewallRuleExists(L"AcmeSupport"));
    /* Uninstall removes the owned duplicate and leaves both foreign rules. */
    assert(Security_RemoveFirewallRuleForService(L"AcmeSupport") && wfpRemoves==2 && removes==1 && count==2);
    assert(!wcscmp(entries[0].name,L"Windows AcmeSupport - Outbound")&&!wcscmp(entries[0].service,L"Unrelated"));
    assert(!wcscmp(entries[1].name,L"AcmeSupport - Inbound")&&!entries[1].service);
    assert(!Security_CheckFirewallRuleExists(L"AcmeSupport"));
    assert(Security_RemoveRuleByNameForService(&rules,L"Windows AcmeSupport - Outbound",L"AcmeSupport"));
    assert(removes==1);
    failNext=1;
    assert(Security_CheckFirewallRuleExists(L"AcmeSupport"));
    assert(!Security_RemoveRuleByNameForService(&rules,L"missing",L"AcmeSupport"));
    failNext=0;failProperty=1;
    assert(Security_CheckFirewallRuleExists(L"AcmeSupport"));
    assert(!Security_RemoveRuleByNameForService(&rules,L"Windows AcmeSupport - Outbound",L"AcmeSupport"));
    reset();
    assert(!Security_CheckFirewallRuleExists(L"AcmeSupport"));
    wfpPresent=1;assert(Security_CheckFirewallRuleExists(L"AcmeSupport"));wfpPresent=0;
    assert(Security_RemoveRuleByNameForService(&rules,L"missing",L"AcmeSupport")&&removes==0);
    assert(Security_AddFirewallRuleForService(L"AcmeSupport",L"host.exe"));
    assert(Security_AddWebRtcFirewallRuleForService(L"AcmeSupport",L"host.exe",TRUE));
    assert(Security_AddWebRtcFirewallRuleForService(L"AcmeSupport",L"agent.exe",FALSE));
    assert(!wcscmp(emitted[0],L"AcmeSupport - Outbound"));
    assert(!wcscmp(emitted[1],L"AcmeSupport - WebRTC UDP Inbound (Host)"));
    assert(!wcscmp(emitted[2],L"AcmeSupport - WebRTC UDP Inbound (Agent)"));
    wchar_t longName[256];for(size_t i=0;i<255;++i)longName[i]=L'x';longName[255]=0;additions=0;
    assert(Security_AddWebRtcFirewallRuleForService(longName,L"host.exe",TRUE)&&wcslen(emitted[0])>255);
    puts("PASS: firewall branding migration is idempotent, preserves scope, rejects failures and protects unrelated duplicate names");
}
'''
WFP = r'''
#ifdef __MINGW32__
/* MinGW supplies the SDK structures but omits these constants/GUID declarations.
 * Fixture keys only need distinct identities; no real WFP engine is contacted. */
#define FWPM_PROVIDER_FLAG_PERSISTENT 1
#define FWPM_SUBLAYER_FLAG_PERSISTENT 1
#define FWPM_FILTER_FLAG_PERSISTENT 1
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 8
static const GUID FWPM_CONDITION_ALE_APP_ID={11};
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4={21},FWPM_LAYER_ALE_AUTH_CONNECT_V6={22},FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4={23},FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6={24};
#endif
#ifndef _WIN32
#define FWPM_PROVIDER_FLAG_PERSISTENT 1
#define FWPM_SUBLAYER_FLAG_PERSISTENT 1
#define FWPM_FILTER_FLAG_PERSISTENT 1
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 2
#define FWP_BYTE_BLOB_TYPE 12
#define FWP_MATCH_EQUAL 0
#define FWP_ACTION_PERMIT 1
typedef struct { unsigned int size;unsigned char* data; } FWP_BYTE_BLOB;
typedef struct { wchar_t* name;wchar_t* description; } FWPM_DISPLAY_DATA0;
typedef struct { GUID providerKey;FWPM_DISPLAY_DATA0 displayData;DWORD flags;wchar_t* serviceName; } FWPM_PROVIDER0;
typedef struct { GUID subLayerKey;FWPM_DISPLAY_DATA0 displayData;DWORD flags;GUID* providerKey; } FWPM_SUBLAYER0;
typedef struct { int type;FWP_BYTE_BLOB* byteBlob; } FWP_CONDITION_VALUE0;
typedef struct { GUID fieldKey;int matchType;FWP_CONDITION_VALUE0 conditionValue; } FWPM_FILTER_CONDITION0;
typedef struct { GUID layerKey,subLayerKey;GUID* providerKey;FWPM_DISPLAY_DATA0 displayData;DWORD flags;struct {int type;} action;DWORD numFilterConditions;FWPM_FILTER_CONDITION0* filterCondition; } FWPM_FILTER0;
static const GUID FWPM_CONDITION_ALE_APP_ID={11};
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4={21},FWPM_LAYER_ALE_AUTH_CONNECT_V6={22},FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4={23},FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6={24};
#endif
static FWPM_PROVIDER0 provider;
static FWPM_SUBLAYER0 sublayer;
static FWPM_FILTER0 filters[4];static FWPM_FILTER_CONDITION0 conditions[4];
static unsigned char appBytes[]={1,2,3};static FWP_BYTE_BLOB appId={3,appBytes};
static int engineOpens,engineCloses,frees,legacyFilter;
static wchar_t providerName[384],sublayerName[384],filterNames[4][384];
static DWORD Security_WfpOpenEngine(HANDLE* engine){*engine=(HANDLE)1;++engineOpens;return ERROR_SUCCESS;}
static BOOL Security_WfpGuidEquals(const GUID* a,const GUID* b){return !memcmp(a,b,sizeof(GUID));}
static BOOL Security_WfpLegacyFilterPresent(HANDLE engine){assert(engine);return legacyFilter;}
static DWORD get_provider(HANDLE e,const GUID* k,FWPM_PROVIDER0** p){assert(e&&k);*p=&provider;return 0;}
static DWORD get_sublayer(HANDLE e,const GUID* k,FWPM_SUBLAYER0** p){assert(e&&k);*p=&sublayer;return 0;}
static DWORD get_filter(HANDLE e,const GUID* k,FWPM_FILTER0** p);
static DWORD get_app_id(const wchar_t* path,FWP_BYTE_BLOB** p){assert(!wcscmp(path,L"agent.exe"));*p=&appId;return 0;}
static void free_wfp(void** p){*p=NULL;++frees;}
static DWORD close_engine(HANDLE e){assert(e);++engineCloses;return 0;}
#define FwpmProviderGetByKey0 get_provider
#define FwpmSubLayerGetByKey0 get_sublayer
#define FwpmFilterGetByKey0 get_filter
#define FwpmGetAppIdFromFileName0 get_app_id
#define FwpmFreeMemory0 free_wfp
#define FwpmEngineClose0 close_engine
#ifndef _WIN32
#define SetLastError(e) ((void)(e))
#endif
'''
WFP_TESTS = r'''
static DWORD get_filter(HANDLE e,const GUID* k,FWPM_FILTER0** p){assert(e);for(size_t i=0;i<4;++i)if(Security_WfpGuidEquals(k,g_ServiceWfpFilters[i].filterKey)){*p=&filters[i];return 0;}return 1;}
static void reset(const wchar_t* service){
    StringCchPrintfW(providerName,384,SECURITY_WFP_PROVIDER_NAME_FMT,service);
    StringCchPrintfW(sublayerName,384,SECURITY_WFP_SUBLAYER_NAME_FMT,service);
    provider.displayData.name=providerName;provider.flags=FWPM_PROVIDER_FLAG_PERSISTENT;provider.serviceName=(wchar_t*)service;
    sublayer.displayData.name=sublayerName;sublayer.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;sublayer.providerKey=(GUID*)&SECURITY_WFP_PROVIDER_KEY;
    for(size_t i=0;i<4;++i){
        StringCchPrintfW(filterNames[i],384,SECURITY_WFP_FILTER_NAME_FMT,service,g_ServiceWfpFilters[i].nameSuffix);
        FWPM_FILTER0* f=&filters[i];memset(f,0,sizeof(*f));f->displayData.name=filterNames[i];f->layerKey=*g_ServiceWfpFilters[i].layerKey;
        f->providerKey=(GUID*)&SECURITY_WFP_PROVIDER_KEY;f->subLayerKey=SECURITY_WFP_SUBLAYER_KEY;f->flags=FWPM_FILTER_FLAG_PERSISTENT|FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        f->action.type=FWP_ACTION_PERMIT;f->numFilterConditions=1;f->filterCondition=&conditions[i];
        conditions[i].fieldKey=FWPM_CONDITION_ALE_APP_ID;conditions[i].matchType=FWP_MATCH_EQUAL;conditions[i].conditionValue.type=FWP_BYTE_BLOB_TYPE;conditions[i].conditionValue.byteBlob=&appId;
    }
    legacyFilter=0;
}
int main(void){
    reset(L"AcmeSupport");assert(!wcscmp(providerName,L"AcmeSupport WFP Provider"));
    assert(!wcscmp(sublayerName,L"AcmeSupport WFP Sublayer"));
    assert(!wcscmp(filterNames[0],L"AcmeSupport Hard Permit Connect V4"));
    assert(Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));
    /* Installer and service may resolve the SCM identity with different case. */
    assert(Security_CheckWfpHardPermitForApp(L"acmesupport",L"agent.exe")&&Security_CheckWfpHardPermitForApp(L"ACMESUPPORT",L"agent.exe"));
    wcscpy(providerName,L"Windows AcmeSupport WFP Provider");assert(!Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));
    reset(L"AcmeSupport");wcscpy(sublayerName,L"Windows AcmeSupport WFP Sublayer");assert(!Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));
    for(size_t i=0;i<4;++i){reset(L"AcmeSupport");wcscpy(filterNames[i],L"Windows AcmeSupport old label");assert(!Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));}
    reset(L"AcmeSupport");legacyFilter=1;assert(!Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));
    reset(L"AcmeSupport");conditions[0].conditionValue.type=0;assert(!Security_CheckWfpHardPermitForApp(L"AcmeSupport",L"agent.exe"));
    wchar_t longName[256];for(size_t i=0;i<255;++i)longName[i]=L'x';longName[255]=0;reset(longName);
    assert(Security_CheckWfpHardPermitForApp(longName,L"agent.exe"));assert(wcslen(filterNames[0])>255);
    assert(engineOpens==engineCloses);
    puts("PASS: WFP admits branded provider/sublayer/all four filters and rejects every historical label without weakening app-ID checks");
}
'''


def run(name, contents):
    fixture = OUT / (name + '.c')
    fixture.write_text(contents)
    executable = OUT / (name + '.exe')
    compiler = os.environ.get('CC', 'clang')
    libraries = ['-lole32', '-loleaut32', '-luuid', '-lfwpuclnt'] if os.name == 'nt' else []
    subprocess.run([compiler, '-std=c11', '-g', '-O1', '-fsanitize=address,undefined',
                    str(fixture), '-o', str(executable), *libraries], check=True)
    env = os.environ.copy()
    compiler_path = shutil.which(compiler)
    if os.name == 'nt' and compiler_path:
        runtimes = list(Path(compiler_path).parent.parent.glob('lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll'))
        if runtimes:
            env['PATH'] = str(runtimes[0].parent) + os.pathsep + env.get('PATH', '')
    subprocess.run([str(executable)], check=True, env=env, timeout=30)
    cross = shutil.which('x86_64-w64-mingw32-gcc')
    if cross:
        subprocess.run([cross, '-std=c11', '-Werror=incompatible-pointer-types', '-c', str(fixture),
                        '-o', str(OUT / (name + '-windows.o'))], check=True)
        print('PASS: ' + name + ' compiles against Windows headers')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    run('firewall', COMMON + FORMATS + COM + production('Security_MigrateFirewallRuleNames') +
        production('Security_QueryRuleNameOwnership') + production('Security_RenameOwnedRules') +
        production('Security_RemoveRuleByNameForService') +
        production('Security_IsFirewallRulePresentForService') + production('Security_CheckFirewallRuleExists') +
        production('Security_RemoveOrdinaryFirewallRulesForService') + production('Security_RemoveFirewallRuleForService') +
        production('Security_AddFirewallRuleForService') +
        production('Security_AddWebRtcFirewallRuleForService') + COM_TESTS)
    keys = SOURCE[SOURCE.index('static const GUID SECURITY_WFP_PROVIDER_KEY'):SOURCE.index('// "Host Hard Permit Connect')]
    check = SOURCE[SOURCE.index('BOOL Security_CheckWfpHardPermitForApp('):]
    # Forward declaration: the fixture store is defined after the descriptors.
    run('wfp', COMMON + FORMATS + WFP + keys + extract(SOURCE, 'Security_WfpByteBlobEquals') + extract(SOURCE, 'Security_WfpCheckFilter') +
        extract(check, 'Security_CheckWfpHardPermitForApp') + WFP_TESTS)


if __name__ == '__main__':
    main()
