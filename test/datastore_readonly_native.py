#!/usr/bin/env python3
"""Run production snapshot opening/parsing against real disposable datastore files.

Uses real SHA384, file I/O and the production legacy reader. Only the in-memory
hashtable and unrelated compaction serializer are fixture implementations.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'microstack/ILibSimpleDataStore.c').read_text()

def extract(name):
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', lambda m: ' '*len(m.group()), source, flags=re.S)
    match = re.search(r'^(?:__EXPORT_TYPE )?(?:void|int|FILE\*|ILibSimpleDataStore|ILibSimpleDataStore_RecordHeader_NG\*)\s+' + name + r'\([^;{]*\)\s*\{', masked, re.M)
    assert match, name
    start, brace = match.start(), match.end()-1
    end, depth = brace + 1, 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[start:end]

prelude = r'''
#define _POSIX 1
#define __EXPORT_TYPE
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define ILIBLOGMESSAGEX(...) ((void)0)
#define ignore_result(x) ((void)(x))
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#define SHA384HASHSIZE 48
#define ILibSimpleDataStore_MaxFilePath 4096
#define ILibSimpleDataStore_GetPosition(f) ftell(f)
#define ILibSimpleDataStore_SeekPosition(f,p,w) fseek(f,p,w)
#define ILibMemory_Allocate(n,e,a,b) calloc(1,(n)+(e))
#define memcpy_s(d,n,s,c) memcpy(d,s,c)
#define strnlen_s strnlen
#define ILibSimpleDataStore_OpenFileEx(p,t) ILibSimpleDataStore_OpenFileEx3(p,t,0,NULL)
#define ILibSimpleDataStore_OpenFile(p) ILibSimpleDataStore_OpenFileEx3(p,0,0,NULL)
typedef void* ILibSimpleDataStore;
typedef void (*ILibSimpleDataStore_SizeWarningHandler)(void);
typedef void (*ILibSimpleDataStore_WriteErrorHandler)(void);
typedef struct Table { char keys[16][1024]; int lengths[16];void* values[16];int count; } *ILibHashtable;
static char ILibScratchPad[4096];
static ILibHashtable ILibHashtable_Create(void){return calloc(1,sizeof(struct Table));}
static void* ILibHashtable_Get(ILibHashtable t,void* k,char* s,int n){(void)k;for(int i=0;i<t->count;++i)if(t->lengths[i]==n&&!memcmp(t->keys[i],s,n))return t->values[i];return NULL;}
static void ILibHashtable_Put(ILibHashtable t,void* k,char* s,int n,void* v){(void)k;assert(n>0&&n<1024);for(int i=0;i<t->count;++i)if(t->lengths[i]==n&&!memcmp(t->keys[i],s,n)){t->values[i]=v;return;}assert(t->count<16);int i=t->count++;memcpy(t->keys[i],s,n);t->lengths[i]=n;t->values[i]=v;}
static void ILibHashtable_Remove(ILibHashtable t,void* k,char* s,int n){(void)k;for(int i=0;i<t->count;++i)if(t->lengths[i]==n&&!memcmp(t->keys[i],s,n)){t->values[i]=NULL;return;}}
static void ILibHashtable_ClearEx(ILibHashtable t,void(*sink)(ILibHashtable,void*,char*,int,void*,void*),void* u){for(int i=0;i<t->count;++i)sink(t,NULL,t->keys[i],t->lengths[i],t->values[i],u);t->count=0;}
static uint32_t crc32c(uint32_t c,unsigned char* p,int n){(void)c;(void)p;(void)n;return 0xdeadbeef;}
static int compactions,repairs;
static char* ILibString_Cat(char* a,int al,char* b,int bl){(void)al;(void)bl;char* p=malloc(strlen(a)+strlen(b)+1);strcpy(p,a);strcat(p,b);return p;}
static char* ILibString_Copy(char* p,size_t n){char* c=malloc(n+1);memcpy(c,p,n);c[n]=0;return c;}
static char* ILibString_Replace(char* a,size_t al,char* b,int bl,char* c,int cl){(void)al;(void)b;(void)bl;(void)c;(void)cl;return ILibString_Cat(a,-1,".corrupt",-1);}
static int ILibFile_CopyTo(char* a,char* b){(void)a;(void)b;++repairs;return 0;}
static void ILibSimpleDataStore_Compact_EnumerateSink(void){assert(0);}
static void ILibHashtable_Enumerate(ILibHashtable t,void(*sink)(void),void* u){(void)t;(void)sink;(void)u;++compactions;}
int ILibSimpleDataStore_Compact(ILibSimpleDataStore);
'''
types = source[source.index('typedef struct ILibSimpleDataStore_Root'):source.index('const int ILibMemory_SimpleDataStore_CONTAINERSIZE')]
types += '\nconst int ILibMemory_SimpleDataStore_CONTAINERSIZE = sizeof(ILibSimpleDataStore_Root);\n'
cases = r'''
static void record(FILE* f,int padding,const char* key,const char* value){
    unsigned char h[72]={0};uint32_t n=(uint32_t)strlen(key),v=(uint32_t)strlen(value),size=60+padding+n+v;
    uint32_t numbers[]={htonl(size),htonl(n),htonl(v)};memcpy(h,numbers,12);SHA384((const unsigned char*)value,v,h+12);
    assert(fwrite(h,1,60+padding,f)==(size_t)(60+padding));assert(fwrite(key,1,n,f)==n);assert(fwrite(value,1,v,f)==v);
}
static void inspect(const char* path,int expected){
    unsigned char before[4096],after[4096];FILE* f=fopen(path,"rb");assert(f);size_t n=fread(before,1,sizeof(before),f);fclose(f);
    ILibSimpleDataStore_Root* r=ILibSimpleDataStore_CreateEx2((char*)path,0,1);assert(r&&r->readOnly);
    ILibSimpleDataStore_TableEntry* entry=ILibHashtable_Get(r->keyTable,NULL,"NodeID",6);assert(!!entry==expected);
    if(entry){char v[16]={0};assert(!fseek(r->dataFile,(long)entry->valueOffset,SEEK_SET));assert(fread(v,1,entry->valueLength,r->dataFile)==(size_t)entry->valueLength);assert(!strcmp(v,"old-node"));}
    assert(ILibSimpleDataStore_Compact(r)==1&&!compactions&&!repairs);
    fclose(r->dataFile);ILibHashtable_ClearEx(r->keyTable,ILibSimpleDataStore_TableClear_Sink,r);free(r->keyTable);free(r->filePath);free(r);
    f=fopen(path,"rb");assert(f);size_t m=fread(after,1,sizeof(after),f);fclose(f);assert(n==m&&!memcmp(before,after,n));
    char tmp[512];snprintf(tmp,sizeof(tmp),"%s.tmp",path);assert(access(tmp,F_OK));
}
int main(void){
    for(int padding=0;padding<=12;padding+=4){if(padding==8)continue;FILE* f=fopen("identity.db","wb");record(f,padding,"NodeID","old-node");fclose(f);inspect("identity.db",1);}
    FILE* f=fopen("identity.db","wb");record(f,0,"NodeID","old-node");fwrite("torn tail",1,9,f);fclose(f);inspect("identity.db",1);
    f=fopen("payload.exe","wb");fwrite("MZ NOT A DATASTORE",1,18,f);fclose(f);inspect("payload.exe",0);
    f=fopen("negative.db","wb");unsigned char h[60]={0};memset(h+4,255,4);fwrite(h,1,60,f);fclose(f);inspect("negative.db",0);
    assert(!ILibSimpleDataStore_CreateEx2("missing.db",0,1));assert(access("missing.db",F_OK));
    puts("Datastore snapshots: NG, legacy32/64, torn tail, non-DB, negative length and missing files remain unchanged");return 0;
}
'''
functions = '\n'.join(extract(n) for n in ('ILibSimpleDataStore_ReadNextRecord','ILibSimpleDataStore_TableClear_Sink','ILibSimpleDataStore_RebuildKeyTable','ILibSimpleDataStore_OpenFileEx3','ILibSimpleDataStore_CreateEx2','ILibSimpleDataStore_Compact'))
with tempfile.TemporaryDirectory(prefix='mesh-readonly-') as tmp:
    c, exe = Path(tmp)/'readonly.c', Path(tmp)/'readonly'
    c.write_text(prelude+types+functions+cases)
    openssl = Path(os.environ.get('OPENSSL_ROOT','/opt/homebrew/opt/openssl@3'))
    flags = ['-I'+str(openssl/'include'),'-L'+str(openssl/'lib')] if openssl.exists() else []
    subprocess.run([os.environ.get('CC','clang'),'-std=gnu11','-fsanitize=address,undefined','-Wno-deprecated-declarations',*flags,str(c),'-lcrypto','-o',str(exe)],check=True)
    subprocess.run([str(exe)],cwd=tmp,check=True)
