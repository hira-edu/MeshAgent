"""Check production smart-memory sizing/initialization against a guard page."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
header = (ROOT / 'microstack/ILibParsers.h').read_text()
source = (ROOT / 'microstack/ILibParsers.c').read_text()
start = source.index('void* ILibMemory_Init(void *ptr,')
end = source.index('\nvoid ILibMemory_SecureZero(', start)
initializer = source[start:end]
fixture = r'''
#include <winsock2.h>
#include <windows.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define WIN32
#define MICROSTACK_NOTLS
#define MICROSTACK_NO_STDAFX
#include "microstack/ILibParsers.h"
#undef ILIBCRITICALEXIT
#define ILIBCRITICALEXIT(code) abort()
'''
cases = r'''
int main(void) {
    SYSTEM_INFO info; GetSystemInfo(&info);
    char* region = VirtualAlloc(NULL, 2 * info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD protection; unsigned checks = 0;
    assert(region && VirtualProtect(region + info.dwPageSize, info.dwPageSize, PAGE_NOACCESS, &protection));
    assert(!ILibMemory_Size_Validate(SIZE_MAX, 1));
    assert(!ILibMemory_Size_Validate(1, SIZE_MAX));
    assert(!ILibMemory_Size_Validate(UINT32_MAX, 0));
    assert(!ILibMemory_Size_Validate(UINT32_MAX - sizeof(ILibMemory_Header), 1));
    for (size_t primary = 0; primary < 129; ++primary) {
        for (size_t extra = 0; extra < 17; ++extra) {
            size_t aligned = extra ? ((primary + sizeof(void*) - 1) & ~(sizeof(void*) - 1)) : primary;
            size_t storage = ILibMemory_Init_Size(primary, extra);
            assert(storage == aligned + extra + sizeof(ILibMemory_Header) * (extra ? 2 : 1));
            char* raw = region + info.dwPageSize - storage;
            memset(raw - 16, 0xa5, storage + 16);
            void* data = ILibMemory_Init(raw, primary, extra, ILibMemory_Types_HEAP);
            assert(ILibMemory_Size(data) == aligned && ILibMemory_ExtraSize(data) == extra);
            assert(ILibMemory_Ex_CanaryOK(data));
            if (extra) {
                assert(ILibMemory_Ex_CanaryOK(ILibMemory_Extra(data)));
                assert(ILibMemory_Size(ILibMemory_Extra(data)) == extra);
            }
            for (unsigned i = 1; i <= 16; ++i) { assert((unsigned char)raw[-(int)i] == 0xa5); }
            ++checks;
        }
    }
    VirtualFree(region, 0, MEM_RELEASE);
    printf("smart-memory guard pages: pointer=%zu checks=%u overflow/alignment/header boundaries passed\n", sizeof(void*), checks);
    return 0;
}
'''
if os.name != 'nt': raise SystemExit('Windows guard page test requires Windows')
with tempfile.TemporaryDirectory(prefix='mesh-memory-') as directory:
    base = Path(directory)
    c = base / 'memory.c'
    c.write_text(fixture + initializer + cases)
    for architecture in ('x64', 'x86'):
        executable = base / (architecture + '.exe')
        command = [os.environ.get('CC', 'clang'), '-std=c11', '-I', str(ROOT), str(c), '-o', str(executable)]
        if architecture == 'x86': command.insert(1, '-m32')
        subprocess.run(command, check=True)
        subprocess.run([str(executable)], check=True)
