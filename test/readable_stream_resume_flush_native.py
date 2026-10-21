#!/usr/bin/env python3
"""Unit-test readable-stream resume after buffered data is flushed (microscript/ILibDuktape_ReadableStream.c).

Compiles the production ILibDuktape_readableStream_resume_flush() and
ILibDuktape_readableStream_ResumeIfUncongested() into a C harness with clang (or CC) under
ASan/UBSan and -Werror. Delivery to destinations is stubbed. Checks that when redelivering the
last buffered chunk congests a destination again, the stream stays paused and the source is not
resumed. Any POSIX host; no agent build, endpoint or OS input is used.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

from connection_failure_telemetry_native import extract

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ILibDuktape_readableStream_bufferedData
{
    struct ILibDuktape_readableStream_bufferedData *Next;
    void *ctx;
    int bufferLen;
    int Reserved;
    char buffer[];
} ILibDuktape_readableStream_bufferedData;

typedef struct ILibDuktape_readableStream ILibDuktape_readableStream;
typedef void(*ILibDuktape_readableStream_PauseResumeHandler)(ILibDuktape_readableStream *sender, void *user);
struct ILibDuktape_readableStream
{
    void *emitter;
    void *nextWriteable;
    int paused;
    int pipePaused;
    int resumeFlushDepth;
    void *paused_data;
    ILibDuktape_readableStream_PauseResumeHandler ResumeHandler;
    void *user;
};

static int has_listeners = 1, congested_pipe = 0, resumes = 0, delivered = 0;
static int congest_on_delivery = -1;   /* 1-based delivery that congests a destination again */

#define ILibMemory_CanaryOK(p) ((p) != NULL)
static int ILibDuktape_EventEmitter_HasListeners(void *emitter, const char *name) { (void)emitter; (void)name; return has_listeners; }
static int ILibDuktape_readableStream_HasCongestedPipe(ILibDuktape_readableStream *stream) { (void)stream; return congested_pipe; }
/* Mirrors Dispatch(): a congested destination pauses the stream for pipe flow control and the return is stream->paused. */
static int ILibDuktape_readableStream_WriteDataEx(ILibDuktape_readableStream *rs, int reserved, char *buffer, size_t len)
{
    (void)reserved; (void)buffer; (void)len;
    if (++delivered == congest_on_delivery) { rs->paused = 1; rs->pipePaused = 1; }
    return rs->paused;
}
static void on_resume(ILibDuktape_readableStream *sender, void *user) { (void)sender; (void)user; ++resumes; }
int ILibDuktape_readableStream_resume_flush(ILibDuktape_readableStream *rs);
'''

TESTS = r'''
static void queue(ILibDuktape_readableStream *rs, int count)
{
    ILibDuktape_readableStream_bufferedData **tail = (ILibDuktape_readableStream_bufferedData**)&rs->paused_data;
    for (int i = 0; i < count; ++i)
    {
        ILibDuktape_readableStream_bufferedData *b = calloc(1, sizeof(*b) + 4);
        assert(b != NULL);
        b->bufferLen = 4;
        *tail = b;
        tail = &b->Next;
    }
}
static void drop(ILibDuktape_readableStream *rs)
{
    while (rs->paused_data != NULL) { ILibDuktape_readableStream_bufferedData *b = rs->paused_data; rs->paused_data = b->Next; free(b); }
}
static ILibDuktape_readableStream reset(int chunks, int congestOn)
{
    ILibDuktape_readableStream rs;
    memset(&rs, 0, sizeof(rs));
    rs.emitter = &rs;
    rs.paused = 1;
    rs.pipePaused = 1;
    rs.ResumeHandler = on_resume;
    has_listeners = 1; congested_pipe = 0; resumes = 0; delivered = 0; congest_on_delivery = congestOn;
    queue(&rs, chunks);
    return rs;
}

int main(void)
{
    ILibDuktape_readableStream rs;

    /* Every buffered chunk is accepted: flushed, and the source resumes once. */
    rs = reset(3, -1);
    ILibDuktape_readableStream_ResumeIfUncongested(&rs);
    assert(delivered == 3 && rs.paused_data == NULL && rs.paused == 0 && resumes == 1);

    /* The only buffered chunk congests the destination again: still paused, source not resumed. */
    rs = reset(1, 1);
    assert(ILibDuktape_readableStream_resume_flush(&rs) == 1);
    assert(rs.paused_data == NULL && rs.paused == 1 && rs.resumeFlushDepth == 0);
    rs = reset(1, 1);
    ILibDuktape_readableStream_ResumeIfUncongested(&rs);
    assert(delivered == 1 && rs.paused == 1 && rs.pipePaused == 1 && resumes == 0);

    /* The last of several chunks congests the destination: same result. */
    rs = reset(3, 3);
    ILibDuktape_readableStream_ResumeIfUncongested(&rs);
    assert(delivered == 3 && rs.paused_data == NULL && rs.paused == 1 && resumes == 0);

    /* An earlier chunk congests it: delivery stops in order, the rest stays queued. */
    rs = reset(3, 1);
    assert(ILibDuktape_readableStream_resume_flush(&rs) == 1);
    assert(delivered == 1 && rs.paused_data != NULL && ((ILibDuktape_readableStream_bufferedData*)rs.paused_data)->Next != NULL);
    drop(&rs);

    /* Unchanged cases: nothing buffered, no listeners, a destination still congested. */
    rs = reset(0, -1);
    assert(ILibDuktape_readableStream_resume_flush(&rs) == 0);
    rs = reset(1, -1); has_listeners = 0; rs.nextWriteable = NULL;
    assert(ILibDuktape_readableStream_resume_flush(&rs) == 1 && delivered == 0);
    drop(&rs);
    rs = reset(1, -1); congested_pipe = 1;
    ILibDuktape_readableStream_ResumeIfUncongested(&rs);
    assert(delivered == 0 && rs.paused == 1 && resumes == 0);
    drop(&rs);

    printf("PASS readable stream resume_flush\n");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'microscript/ILibDuktape_ReadableStream.c')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    source = args.source.read_text()

    def definition(name):
        # Start at the definition: extract() alone can match a call site such as "if (f(x) != 0) {".
        match = re.search(r'(?m)^[A-Za-z_][\w \*]*\b' + re.escape(name) + r'\([^;)]*\)\s*\{', source)
        if not match:
            raise AssertionError('Missing production function: ' + name)
        return extract(source[match.start():], name)

    funcs = '\n'.join(definition(name) for name in [
        'ILibDuktape_readableStream_resume_flush', 'ILibDuktape_readableStream_ResumeIfUncongested'])
    with tempfile.TemporaryDirectory() as tmp:
        harness = Path(tmp) / 'probe.c'
        exe = Path(tmp) / 'probe'
        harness.write_text(PRELUDE + funcs + TESTS)
        subprocess.run([args.cc, '-std=c11', '-g', '-O1', '-Wall', '-Werror', '-fsanitize=address,undefined',
                        str(harness), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    main()
