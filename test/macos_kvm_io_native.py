#!/usr/bin/env python3
"""Run the production KVM input loop and output writer under ASan/UBSan.

Injected reads/polls/writes exercise fragmented pipes without accessing a screen
or generating keyboard/mouse events.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'meshcore/KVM/MacOS/mac_kvm.c').read_text()
writer = source[source.index('int KVM_SEND('):source.index('\n\n\nCGDirectDisplayID')]
reader = source[source.index('void* kvm_mainloopinput('):source.index('\nvoid ExitSink(')]
prelude = r'''
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define UNREFERENCED_PARAMETER(x) (void)(x)
static int KVM_AGENT_FD=-1, g_shutdown, g_resetipc;
static unsigned char incoming[70000], received[70000], outgoing[70000];
static size_t incomingLength, offset, receivedLength, outgoingLength, readLimit, firstRead;
static int readInterrupt, pollInterrupt, writeInterrupt, readCalls, writeFailure, stopOnPoll;
static ssize_t fake_read(int fd, void *buffer, size_t size) {
    assert(fd==(KVM_AGENT_FD==-1?STDIN_FILENO:KVM_AGENT_FD));++readCalls;
    if(readInterrupt){readInterrupt=0;errno=EINTR;return -1;}
    size_t count=incomingLength-offset;
    if(readCalls==1 && firstRead && count>firstRead)count=firstRead;
    if(count>readLimit)count=readLimit;if(count>size)count=size;
    memcpy(buffer,incoming+offset,count);offset+=count;return (ssize_t)count;
}
static int fake_poll(struct pollfd *p,nfds_t n,int timeout) {
    assert(n==1 && timeout==100);
    if(pollInterrupt){pollInterrupt=0;errno=EINTR;return -1;}
    if(stopOnPoll){g_shutdown=1;return 0;}
    p->revents=POLLIN;return 1;
}
static ssize_t fake_write(int fd,const void *buffer,size_t length) {
    assert(fd==(KVM_AGENT_FD==-1?STDOUT_FILENO:KVM_AGENT_FD));
    if(writeInterrupt){writeInterrupt=0;errno=EINTR;return -1;}
    if(writeFailure){errno=EPIPE;return writeFailure==1?-1:0;}
    size_t count=length>3?3:length;assert(outgoingLength+count<=sizeof(outgoing));
    memcpy(outgoing+outgoingLength,buffer,count);outgoingLength+=count;return (ssize_t)count;
}
static int kvm_server_inputdata(char *data,int length) {
    if(length<4)return 0;
    unsigned char *p=(unsigned char*)data;
    int size=(p[2]<<8)|p[3];if(size<4)return -1;if(size>length)return 0;
    assert(receivedLength+(size_t)size<=sizeof(received));
    memcpy(received+receivedLength,data,(size_t)size);receivedLength+=(size_t)size;return size;
}
#define read fake_read
#define poll fake_poll
#define write fake_write
'''
main = r'''
static void reset(void) {
    g_shutdown=g_resetipc=readCalls=0;offset=receivedLength=outgoingLength=0;
    readInterrupt=pollInterrupt=writeInterrupt=writeFailure=stopOnPoll=0;
    readLimit=sizeof(incoming);firstRead=0;
}
int main(void) {
    unsigned char packets[]={0,1,0,6,0,65, 0,85,0,7,0,0,66, 0,2,0,10,0,0,0,1,0,2, 0,5,0,4};
    memcpy(incoming,packets,sizeof(packets));incomingLength=sizeof(packets);
    for(int socket=0;socket<2;++socket)for(size_t split=1;split<=sizeof(packets);++split) {
        reset();KVM_AGENT_FD=socket?4:-1;firstRead=split;
        kvm_mainloopinput(NULL);
        assert(receivedLength==sizeof(packets) && !memcmp(received,packets,sizeof(packets)));
        assert(socket?g_resetipc:g_shutdown);
    }
    reset();readLimit=1;readInterrupt=pollInterrupt=1;kvm_mainloopinput(NULL);
    assert(receivedLength==sizeof(packets)&&!memcmp(received,packets,sizeof(packets)));
    reset();incomingLength=65535;memset(incoming,0xa5,incomingLength);incoming[2]=incoming[3]=255;readLimit=997;
    kvm_mainloopinput(NULL);assert(receivedLength==65535&&!memcmp(incoming,received,65535));
    reset();incomingLength=4;incoming[2]=0;incoming[3]=3;kvm_mainloopinput(NULL);assert(receivedLength==0&&readCalls==1);
    reset();stopOnPoll=1;kvm_mainloopinput(NULL);assert(g_shutdown&&readCalls==0);
    for(int socket=0;socket<2;++socket) {
        reset();KVM_AGENT_FD=socket?4:-1;writeInterrupt=1;
        assert(KVM_SEND((char*)packets,sizeof(packets))==(int)sizeof(packets));
        assert(outgoingLength==sizeof(packets)&&!memcmp(packets,outgoing,sizeof(packets)));
        writeFailure=1;assert(KVM_SEND((char*)packets,sizeof(packets))==-1&&errno==EPIPE);
        writeFailure=2;assert(KVM_SEND((char*)packets,sizeof(packets))==-1&&errno==EIO);
    }
    puts("PASS: KVM fragmented/coalesced input, 65535-byte frame, EINTR, invalid frame, shutdown, short output writes and disconnects");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-kvm-io-') as directory:
    probe = Path(directory)
    (probe / 'probe.c').write_text(prelude + writer + reader + main)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(probe / 'probe.c'), '-o', str(probe / 'probe')], check=True)
    subprocess.run([str(probe / 'probe')], check=True, timeout=20)
