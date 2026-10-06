#!/usr/bin/env python3
"""Exercise production native-buffer inspection against exact-size allocations."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--agent', type=Path, help='Also check buffers and process-output conversion in the built runtime')
args = parser.parse_args()
source = (root/'microscript/ILibDuktape_Helpers.c').read_text()
start = source.index('char* Duktape_GetBuffer(')
body = source[start:source.index('\nstruct sockaddr_in6*', start)]
prelude = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int duk_context, duk_idx_t;
typedef size_t duk_size_t;
typedef struct {size_t size,extraSize;int CANARY,memoryType;} ILibMemory_Header;
static char *input;static size_t length;static int kind;
static int duk_is_string(void*c,int i){(void)c;(void)i;return kind==2;}
static int duk_is_buffer(void*c,int i){(void)c;(void)i;return kind==0;}
static int duk_is_buffer_data(void*c,int i){(void)c;(void)i;return kind==1;}
static int duk_is_object(void*c,int i){(void)c;(void)i;return 0;}
static int duk_is_null_or_undefined(void*c,int i){(void)c;(void)i;return 0;}
static char *duk_require_buffer(void*c,int i,size_t*n){(void)c;(void)i;*n=length;return input;}
static char *duk_require_buffer_data(void*c,int i,size_t*n){return duk_require_buffer(c,i,n);}
static char *duk_get_lstring(void*c,int i,size_t*n){(void)c;(void)i;if(n)*n=length;return input;}
static void duk_json_encode(void*c,int i){(void)c;(void)i;abort();}
static void ILibDuktape_Error(void*c,const char*m){(void)c;(void)m;abort();}
'''
main = r'''
int main(void) {
    for(kind=0;kind<3;++kind)for(size_t n=0;n<80;++n)for(size_t offset=0;offset<8;++offset){
        char *allocation=malloc(n+offset);input=allocation+offset;length=n;
        if(n)memset(input,'A',n);
        size_t actual=999;assert(Duktape_GetBuffer(NULL,0,&actual)==input&&actual==n);
        assert(Duktape_GetBuffer(NULL,0,NULL)==input);free(allocation);
    }
    for(kind=0;kind<2;++kind)for(size_t offset=0;offset<8;++offset){
        length=sizeof(ILibMemory_Header)+9;
        char *allocation=malloc(length+offset);input=allocation+offset;
        ILibMemory_Header header={.size=9,.extraSize=0,.memoryType=2};memcpy(&header.CANARY,"broe",4);
        memcpy(input,&header,sizeof(header));memset(input+sizeof(header),'Z',9);
        size_t actual;assert(Duktape_GetBuffer(NULL,0,&actual)==input+sizeof(header)&&actual==9);
        header.size=SIZE_MAX;header.extraSize=10;memcpy(input,&header,sizeof(header));
        assert(Duktape_GetBuffer(NULL,0,&actual)==input&&actual==length);
        free(allocation);
    }
    puts("PASS: native buffers, short views, unaligned slices, internal headers and size overflow");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-buffer-bounds-') as directory:
    folder=Path(directory)
    (folder/'probe.c').write_text(prelude+body+main)
    subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined',str(folder/'probe.c'),'-o',str(folder/'probe')],check=True)
    subprocess.run([str(folder/'probe')],check=True)
    if args.agent:
        script = r'''
function check(value,reason){if(!value){throw new Error(reason);}}
try {
    for(var n=1;n<=80;++n){
        var data=Buffer.alloc(n+7);for(var i=0;i<data.length;++i){data[i]=65;}
        for(var offset=0;offset<8;++offset){
            var text=data.slice(offset,offset+n).toString();
            check(text.length===n&&/^A+$/.test(text),'slice text '+n+'/'+offset);
        }
    }
    var value='';for(var i=0;i<4096;++i){value+='Z';}
    var child=require('child_process').execFile('/usr/bin/printf',['printf','%s',value]),out='',status=-1;
    child.stdout.on('data',function(buffer){out+=buffer.toString();});
    child.stderr.on('data',function(){});child.on('exit',function(code){status=code;});
    child.waitExit();check(status===0&&out===value,'full process-output buffer');
    console.log('PASS: built buffer slices and non-terminated process-output conversion');process.exit(0);
} catch(e){
    if((''+e).indexOf('Process.exit() forced script termination')>=0){throw e;}
    console.log('FAIL: '+e);process.exit(1);
}
'''
        script_path=folder/'runtime.js'
        script_path.write_text(script)
        result=subprocess.run([str(args.agent.resolve()),str(script_path)],cwd=folder,timeout=20,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        print(result.stdout,end='')
        if result.returncode or 'PASS: built buffer slices' not in result.stdout:
            raise SystemExit('Built buffer probe failed: '+str(result.returncode))
