#!/usr/bin/env python3
"""Fault-test production datastore record writes, deletion and durability checks.

POSIX host, disposable real files, injected CRT/device flush failures; ASan/UBSan.
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
    match = re.search(r'^(?:__EXPORT_TYPE )?(?:int|uint64_t)\s+' + name + r'\([^;{]*\)\s*\{', masked, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end]


prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#define __EXPORT_TYPE
#define SHA384HASHSIZE 48
#define ILibSimpleDataStore_GetPosition ftell
#define memcpy_s(d,n,s,c) memcpy(d,s,c)
#define ignore_result(x) ((void)(x))
typedef void* ILibSimpleDataStore;
typedef struct {int nodeSize,keyLen,valueLength;char hash[48];} ILibSimpleDataStore_RecordHeader_NG;
typedef struct {int valueLength;} ILibSimpleDataStore_TableEntry;
typedef struct {char key[64];int length;void* value;} Table;
typedef struct {FILE* dataFile;char* filePath;int readOnly;Table* keyTable;void(*ErrorHandler)(void*,void*);void* ErrorHandlerUser;} ILibSimpleDataStore_Root;
static int failFlush,failSync,errors,flushes,syncs;
static int injectedFlush(FILE* f){++flushes;int r=fflush(f);return failFlush?EOF:r;}
static int injectedSync(int fd){++syncs;return failSync?-1:fsync(fd);}
#define fflush injectedFlush
#define fsync injectedSync
static void errorHandler(void* s,void* u){(void)s;(void)u;++errors;}
static void* ILibHashtable_Get(Table* t,void* k,char* s,int n){(void)k;return n==t->length&&!memcmp(s,t->key,n)?t->value:NULL;}
static void* ILibHashtable_Remove(Table* t,void* k,char* s,int n){void* v=ILibHashtable_Get(t,k,s,n);if(v)t->value=NULL;return v;}
static void* ILibMemory_SmartAllocate(size_t n){size_t* p=malloc(n+sizeof(size_t));*p=n;return p+1;}
static size_t ILibMemory_Size(void* p){return ((size_t*)p)[-1];}
static void ILibMemory_Free(void* p){free((size_t*)p-1);}
static uint32_t crc32c(uint32_t c,unsigned char* p,uint32_t n){(void)c;(void)p;(void)n;return 0x12345678;}
'''
cases = r'''
int main(void){
    FILE* f=tmpfile();assert(f);Table t={0};ILibSimpleDataStore_Root r={f,"fixture.db",0,&t,errorHandler,NULL};
    assert(ILibSimpleDataStore_Flush(&r)==0);failSync=1;assert(ILibSimpleDataStore_Flush(&r)==1);failSync=0;
    failFlush=1;int priorSync=syncs;assert(ILibSimpleDataStore_Flush(&r)==1&&syncs==priorSync);failFlush=0;
    r.readOnly=1;int priorFlush=flushes;assert(ILibSimpleDataStore_Flush(&r)==1&&flushes==priorFlush);r.readOnly=0;
    r.filePath=NULL;assert(ILibSimpleDataStore_Flush(&r)==1);r.filePath="fixture.db";
    r.dataFile=NULL;assert(ILibSimpleDataStore_Flush(&r)==1);r.dataFile=f;assert(ILibSimpleDataStore_Flush(NULL)==1);
    assert(ILibSimpleDataStore_WriteRecord(NULL,"key",3,"old",3,NULL)==0);
    assert(ILibSimpleDataStore_WriteRecord(f,"key",3,"old",3,NULL)!=0);long original=ftell(f);
    failFlush=1;assert(ILibSimpleDataStore_WriteRecord(f,"key",3,"new",3,NULL)==0);failFlush=0;
    assert(!fseek(f,0,SEEK_END)&&ftell(f)==original);
    for(int compressed=0;compressed<2;++compressed){
        memcpy(t.key,"key",3);t.length=3;
        if(compressed){uint32_t crc=0x12345678;memcpy(t.key+3,&crc,4);t.length=7;}
        t.value=calloc(1,sizeof(ILibSimpleDataStore_TableEntry));void* entry=t.value;
        r.readOnly=1;assert(!ILibSimpleDataStore_DeleteEx(&r,"key",3)&&t.value==entry);r.readOnly=0;
        failFlush=1;int before=errors;assert(!ILibSimpleDataStore_DeleteEx(&r,"key",3)&&t.value==entry&&errors==before+1);failFlush=0;
        assert(ILibSimpleDataStore_DeleteEx(&r,"key",3)==1&&!t.value);
        assert(!ILibSimpleDataStore_DeleteEx(&r,"key",3));
    }
    fclose(f);puts("Datastore persistence: flush failures, readonly/cache-only rejection and plain/compressed deletion passed");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-persistence-') as tmp:
    c, exe = Path(tmp)/'persistence.c', Path(tmp)/'persistence'
    c.write_text(prelude+'\n'.join(extract(n) for n in ('ILibSimpleDataStore_WriteRecord','ILibSimpleDataStore_Flush','ILibSimpleDataStore_DeleteEx'))+cases)
    subprocess.run([os.environ.get('CC','clang'),'-std=gnu11','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
