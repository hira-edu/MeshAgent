"""Execute production Task Scheduler/WMI cleanup with injected COM boundaries.

No live COM connections, tasks, subscriptions or services are created.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'meshservice/fault_recovery.cpp').read_text()
def extract(name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: ' ' * len(m.group()), source, flags=re.S)
    match = re.search(r'(?:static )?(?:BOOL|bool) ' + name + r'\s*\([^;{]+\)\s*\{', masked)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}'); end += 1
    return source[match.start():end]

prelude = r'''
#include <windows.h>
#include <oleauto.h>
#include <strsafe.h>
#include <assert.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <cwctype>
#define TASK_ENUM_HIDDEN 1
#define WBEM_INFINITE 0xffffffff
#define WBEM_FLAG_FORWARD_ONLY 32
#define WBEM_S_FALSE ((HRESULT)0x40001)
#define WBEM_E_NOT_FOUND ((HRESULT)0x80041002)
static int calls,failAt,stopFalse,folderAbsent,deletedTasks,disabled,stopped,deletedWmi;
static std::vector<std::wstring> deletedPaths;
static bool step(){return ++calls!=failAt;}
struct ComInitGuard {HRESULT status(){return step()?S_OK:E_ACCESSDENIED;}};
static HRESULT EnsureComSecurity(){return step()?S_OK:E_ACCESSDENIED;}
template<class T> struct ComPtr {T* p=nullptr;T* Get(){return p;}T** operator&(){return &p;}T* operator->(){return p;}explicit operator bool()const{return p!=nullptr;}void Reset(){p=nullptr;}};
struct ScopedBstr {BSTR value=nullptr;ScopedBstr(){}ScopedBstr(const wchar_t* s){value=SysAllocString(s);}~ScopedBstr(){SysFreeString(value);}BSTR Get(){return value;}};
struct ScopedVariant {VARIANT v;ScopedVariant(){VariantInit(&v);}~ScopedVariant(){VariantClear(&v);}VARIANT& get(){return v;}};
static bool IsNullOrEmpty(const wchar_t* s){return !s||!*s;}
static std::wstring EscapeWmiName(const wchar_t* s){std::wstring r;for(;*s;++s){if(*s=='"'||*s=='\\')r+=L'\\';r+=*s;}return r;}
static std::wstring NormalizeNamespace(const wchar_t* s){return s;}
static bool SplitTaskFullPath(const wchar_t* p,std::wstring& folder,std::wstring& name){const wchar_t* end=wcsrchr(p,L'\\');if(!end||!end[1])return false;folder.assign(p,end-p);if(folder.empty())folder=L"\\";name=end+1;return true;}
struct IRegisteredTask {
    std::wstring name;
    HRESULT get_Name(BSTR* out){if(!step())return E_ACCESSDENIED;*out=SysAllocString(name.c_str());return S_OK;}
    HRESULT put_Enabled(VARIANT_BOOL enabled){assert(enabled==VARIANT_FALSE);if(!step())return E_ACCESSDENIED;++disabled;return S_OK;}
    HRESULT Stop(LONG flags){assert(!flags);if(!step())return E_ACCESSDENIED;if(stopFalse)return S_FALSE;++stopped;return S_OK;}
};
static IRegisteredTask ownTask{L"Agent-ServiceRecovery-Current"},otherTask{L"Other-Agent-ServiceRecovery-Current"};
struct IRegisteredTaskCollection {
    HRESULT get_Count(LONG* n){if(!step())return E_ACCESSDENIED;*n=2;return S_OK;}
    HRESULT get_Item(VARIANT index,IRegisteredTask** out){if(!step())return E_ACCESSDENIED;*out=index.lVal==1?&ownTask:&otherTask;return S_OK;}
};
static IRegisteredTaskCollection collection;
static std::wstring openedFolder;
struct ITaskFolder {
    HRESULT GetTasks(LONG flags,IRegisteredTaskCollection** out){assert(flags==TASK_ENUM_HIDDEN);if(!step())return E_ACCESSDENIED;*out=&collection;return S_OK;}
    HRESULT GetTask(BSTR name,IRegisteredTask** out){if(!step())return E_ACCESSDENIED;if(wcscmp(name,ownTask.name.c_str()))return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);*out=&ownTask;return S_OK;}
    HRESULT DeleteTask(BSTR name,LONG flags){assert(!flags&&!wcscmp(name,ownTask.name.c_str()));if(!step())return E_ACCESSDENIED;assert(disabled&&stopped);++deletedTasks;return S_OK;}
};
static ITaskFolder folder;
struct ITaskService {HRESULT GetFolder(BSTR name,ITaskFolder** out){openedFolder=name;if(!step())return E_ACCESSDENIED;if(folderAbsent)return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);*out=&folder;return S_OK;}};
static ITaskService scheduler;
static HRESULT ConnectTaskService(ComPtr<ITaskService>& out){out.p=&scheduler;return step()?S_OK:E_ACCESSDENIED;}
static HRESULT OpenServiceRecoveryFolder(ITaskService* s,ComPtr<ITaskFolder>& out){ScopedBstr name(L"\\Microsoft\\Windows\\Diagnostics");return s->GetFolder(name.Get(),&out);}
static bool IsTaskFolderMissing(HRESULT hr){return hr==HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)||hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);}
struct IWbemClassObject {
    std::wstring name,filter,consumer,path;
    HRESULT Get(const wchar_t* key,LONG flags,VARIANT* out,void*,void*){assert(!flags);if(!step())return E_ACCESSDENIED;const std::wstring* s=!wcscmp(key,L"Name")?&name:!wcscmp(key,L"Filter")?&filter:!wcscmp(key,L"Consumer")?&consumer:&path;out->vt=VT_BSTR;out->bstrVal=SysAllocString(s->c_str());return S_OK;}
};
static std::vector<IWbemClassObject> objects[3];
struct IEnumWbemClassObject {
    int kind=0;size_t position=0;
    HRESULT Next(LONG wait,ULONG count,IWbemClassObject** out,ULONG* fetched){(void)wait;assert(count==1);if(!step())return E_ACCESSDENIED;if(position==objects[kind].size()){*fetched=0;return WBEM_S_FALSE;}*fetched=1;*out=&objects[kind][position++];return S_OK;}
};
static IEnumWbemClassObject enumerators[3];
struct IWbemServices {
    HRESULT ExecQuery(BSTR language,BSTR query,LONG flags,void*,IEnumWbemClassObject** out){assert(!wcscmp(language,L"WQL")&&flags==WBEM_FLAG_FORWARD_ONLY);if(!step())return E_ACCESSDENIED;int kind=wcsstr(query,L"__FilterToConsumerBinding")?0:wcsstr(query,L"CommandLineEventConsumer")?1:2;enumerators[kind].kind=kind;enumerators[kind].position=0;*out=&enumerators[kind];return S_OK;}
};
static IWbemServices wmi;
static HRESULT ConnectWmi(const std::wstring&,ComPtr<IWbemServices>& out){out.p=&wmi;return step()?S_OK:E_ACCESSDENIED;}
static HRESULT DeleteWmiInstance(IWbemServices*,const std::wstring& path){if(!step())return E_ACCESSDENIED;++deletedWmi;deletedPaths.push_back(path);return S_OK;}
struct RecoveryMonitorObjects {std::vector<std::wstring> bindings,filters,consumers;};
'''
cases = r'''
static void reset(){calls=failAt=stopFalse=folderAbsent=deletedTasks=disabled=stopped=deletedWmi=0;deletedPaths.clear();}
int main(){
    reset();assert(FaultRecovery_DeleteTasksByPrefix(L"Agent-",nullptr,nullptr)&&deletedTasks==1&&stopped==1);int boundaries=calls;
    for(int fail=1;fail<=boundaries;++fail){reset();failAt=fail;assert(!FaultRecovery_DeleteTasksByPrefix(L"Agent-",nullptr,nullptr));}
    reset();stopFalse=1;assert(!FaultRecovery_DeleteTask(L"Agent-ServiceRecovery-Current")&&!deletedTasks);
    reset();assert(FaultRecovery_DeleteTask(L"\\Custom\\Agent-ServiceRecovery-Current")&&openedFolder==L"\\Custom");
    reset();folderAbsent=1;assert(FaultRecovery_DeleteTask(L"Agent-ServiceRecovery-Current")&&!deletedTasks);
    reset();BOOL present=FALSE;assert(FaultRecovery_QueryTasksByPrefix(L"Agent-",&present)&&present);boundaries=calls;
    for(int fail=1;fail<=boundaries;++fail){reset();failAt=fail;assert(!FaultRecovery_QueryTasksByPrefix(L"Agent-",&present));}
    reset();assert(FaultRecovery_QueryTasksByPrefix(L"NoMatch-",&present)&&!present);
    reset();folderAbsent=1;assert(FaultRecovery_QueryTasksByPrefix(L"Agent-",&present)&&!present);
    const wchar_t* fp=L"Agent_ServiceStateMonitor_",*cp=L"Agent_ServiceRecoveryHandler_";
    objects[0]={{L"",L"\\\\host\\root\\subscription:__EventFilter.Name=\"Agent_ServiceStateMonitor_1\"",L"CommandLineEventConsumer.Name=\"Agent_ServiceRecoveryHandler_1\"",L"owned-binding"},
        {L"",L"__EventFilter.Name=\"Other_Agent_ServiceStateMonitor_1\"",L"CommandLineEventConsumer.Name=\"Other_Agent_ServiceRecoveryHandler_1\"",L"foreign-binding"}};
    objects[1]={{L"Agent_ServiceRecoveryHandler_1"},{L"Other_Agent_ServiceRecoveryHandler_1"}};
    objects[2]={{L"Agent_ServiceStateMonitor_1"},{L"AgentXServiceStateMonitorX1"}};
    reset();assert(FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(fp,cp,nullptr,nullptr)&&deletedWmi==3);boundaries=calls;
    assert(deletedPaths[0]==L"owned-binding"&&deletedPaths[1].find(L"CommandLineEventConsumer")==0&&deletedPaths[2].find(L"__EventFilter")==0);
    for(int fail=1;fail<=boundaries;++fail){reset();failAt=fail;assert(!FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix(fp,cp,nullptr,nullptr));}
    reset();assert(FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(fp,cp,&present)&&present);boundaries=calls;
    for(int fail=1;fail<=boundaries;++fail){reset();failAt=fail;assert(!FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(fp,cp,&present));}
    objects[1].clear();objects[2].clear();reset();assert(FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(fp,cp,&present)&&present); // dangling binding
    objects[0].clear();reset();assert(FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(fp,cp,&present)&&!present);
    objects[1]={{L"Agent_ServiceRecoveryHandler_1"}};reset();assert(FaultRecovery_QueryServiceRecoveryMonitorsByPrefix(fp,cp,&present)&&present); // lone consumer
    assert(!RecoveryMonitorReferenceMatches(L"__EventFilter.Name=\"Other_Agent_ServiceStateMonitor_1\"",L"__EventFilter",fp));
    puts("Recovery COM boundaries: stop/disable/delete, exact folders, literal prefixes, orphan objects, partial enumeration and API failure propagation passed");
}
'''
names = ['FaultRecovery_DeleteTask', 'FaultRecovery_DeleteTasksByPrefix', 'FaultRecovery_QueryTasksByPrefix',
         'RecoveryMonitorReferenceMatches', 'CollectRecoveryMonitorObjects',
         'FaultRecovery_QueryServiceRecoveryMonitorsByPrefix', 'FaultRecovery_RemoveServiceRecoveryMonitorsByPrefix']
with tempfile.TemporaryDirectory(prefix='mesh-recovery-com-') as directory:
    path = Path(directory) / 'fixture.cpp'
    exe = Path(directory) / 'fixture.exe'
    path.write_text(prelude + '\n'.join(extract(n) for n in names) + cases)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c++17', str(path), '-loleaut32', '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
