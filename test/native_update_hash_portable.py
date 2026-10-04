#!/usr/bin/env python3
"""Compile the production Windows normalized hash reader and exercise PE/trailer bounds."""
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'meshcore/agentcore.c').read_text()
start=source.index('int GenerateSHA384FileHash(')
end=source.index('// Called when the connection',start)
function=source[start:end]
prelude=r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <wchar.h>
#include <alloca.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#define WIN32 1
#define UTIL_SHA384_HASHSIZE 48
#define ignore_result(x) ((void)(x))
static char ILibScratchPad[4096];
static wchar_t pathWide[4096];
static wchar_t* ILibUTF8ToWide(char* p,int n){(void)n;mbstowcs(pathWide,p,4096);return pathWide;}
static int _wfopen_s(FILE** out,const wchar_t* p,const wchar_t* mode){char path[4096];(void)mode;wcstombs(path,p,sizeof(path));*out=fopen(path,"rb");return *out?0:1;}
#define ILibMemory_AllocateA(n) ({size_t z=(n);size_t* p=alloca(z+sizeof(size_t));*p=z;(char*)(p+1);})
#define ILibMemory_AllocateA_Size(p) (((size_t*)(p))[-1])
'''
guids={}
for name in ('exeMeshPolicyGuid','exeNullPolicyGuid'):
    values=re.search(r'char '+name+r'\[\] = \{([^}]+)',source)[1]
    guids[name]=bytes(int(x,16) for x in values.split(','))
    prelude+='static char '+name+'[] = {'+values+'};\n'
main=r'''
int main(int argc,char** argv){char hash[48];if(argc==3){char expected[48];for(int i=0;i<48;++i){unsigned value;if(sscanf(argv[2]+i*2,"%2x",&value)!=1)return 2;expected[i]=(char)value;}printf("%d\n",MeshServer_VerifyUpdateFileHash(argv[1],expected));return 0;}if(argc!=2)return 2;int result=GenerateSHA384FileHash(argv[1],hash);if(result){puts("REJECT");return 0;}for(int i=0;i<48;++i)printf("%02x",(unsigned char)hash[i]);puts("");return 0;}
'''
def pe(bits,cert=0,opt=None,size=1024):
    data=bytearray((i*17+5)%256 for i in range(size))
    data[:2]=b'MZ';struct.pack_into('<I',data,60,128);data[128:132]=b'PE\0\0'
    struct.pack_into('<H',data,148,opt if opt is not None else (224 if bits==32 else 240))
    struct.pack_into('<H',data,152,0x10b if bits==32 else 0x20b)
    struct.pack_into('<II',data,152+(128 if bits==32 else 144),cert,64 if cert else 0)
    return data
def expected_pe(data,bits,stop=None):
    normal=bytearray(data[:stop]);normal[216:220]=b'\0'*4
    offset=152+(128 if bits==32 else 144);normal[offset:offset+8]=b'\0'*8
    return hashlib.sha384(normal).hexdigest()
fixtures=[]
for size in (0,1,15,16,19,20,4096,4097):
    raw=b'A'*size;fixtures.append((f'raw-{size}',raw,hashlib.sha384(raw).hexdigest()))
for bits in (32,64):
    for signed in (False,True):
        data=pe(bits,768 if signed else 0)
        fixtures.append((f'pe-{bits}-{signed}',data,expected_pe(data,bits,768 if signed else None)))
    data=pe(bits)
    policy=b'provisioning test data'
    for guid in guids.values():
        fixtures.append((f'policy-{bits}',data+policy+struct.pack('>I',len(policy))+guid,expected_pe(data,bits)))
    for offset in (1,215,280 if bits==32 else 296,1025,0xffffffff):
        fixtures.append((f'bad-cert-{bits}-{offset}',pe(bits,offset),'REJECT'))
    fixtures.append((f'short-optional-{bits}',pe(bits,opt=132 if bits==32 else 148),'REJECT'))
    fixtures.append((f'truncated-header-{bits}',pe(bits)[:300],'REJECT'))
for guid in guids.values():
    # A trailer covering the entire non-PE payload normalizes to the empty prefix.
    raw=b'policy'+struct.pack('>I',6)+guid
    fixtures.append(('empty-normalized',raw,hashlib.sha384(b'').hexdigest()))
    raw=b'content'+struct.pack('>I',0xffffffff)+guid
    fixtures.append(('bad-policy-length',raw,hashlib.sha384(raw).hexdigest()))
with tempfile.TemporaryDirectory(prefix='mesh-update-hash-') as tmp:
    c,exe=Path(tmp)/'hash.c',Path(tmp)/'hash';c.write_text(prelude+function+main)
    cmd=[os.environ.get('CC','clang'),'-std=gnu11','-Wno-deprecated-declarations','-fsanitize=address,undefined']
    brew=Path('/opt/homebrew/opt/openssl@3')
    if brew.exists():cmd+=['-I'+str(brew/'include'),'-L'+str(brew/'lib')]
    subprocess.run(cmd+[str(c),'-lcrypto','-o',str(exe)],check=True)
    for index,(label,data,expected) in enumerate(fixtures):
        p=Path(tmp)/str(index);p.write_bytes(data)
        result=subprocess.run([str(exe),str(p)],capture_output=True,text=True,check=True)
        assert not result.stderr,(label,result.stderr)
        assert result.stdout.strip()==expected,(label,result.stdout,expected)
        for digest in {hashlib.sha384(data).hexdigest(), expected if expected!='REJECT' else '00'*48, 'ff'*48}:
            verified=subprocess.run([str(exe),str(p),digest],capture_output=True,text=True,check=True)
            want=expected!='REJECT' and digest in (expected,hashlib.sha384(data).hexdigest())
            assert not verified.stderr,(label,verified.stderr)
            assert verified.stdout.strip()==str(int(want)),(label,'verification',digest,verified.stdout)
print(f'Native update hash: {len(fixtures)} raw, signed PE32/64, policy and malformed-boundary cases passed; normalized/whole-file/wrong-digest verification passed')
