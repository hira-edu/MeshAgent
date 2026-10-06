#!/usr/bin/env python3
"""Test production HID report encoding and failure state without creating devices."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

if sys.platform != 'darwin':
    raise SystemExit('This native probe requires macOS SDKs')
root = Path(__file__).resolve().parents[1]
source = r'''
#define IOHIDUserDeviceHandleReportWithTimeStamp capture_report
#include "meshcore/KVM/MacOS/mac_hid.c"
#include <assert.h>
#include <stdio.h>
static int calls, failCall;
static kbd_report_t keys;
static ptr_report_t mouse;
IOReturn capture_report(IOHIDUserDeviceRef device, uint64_t timestamp,
                        const uint8_t *report, CFIndex length) {
    (void)timestamp;
    ++calls;
    if (calls == failCall) return kIOReturnError;
    if (device == g_kbd) { assert(length == sizeof(keys)); memcpy(&keys,report,length); }
    else { assert(device == g_ptr && length == sizeof(mouse)); memcpy(&mouse,report,length); }
    return kIOReturnSuccess;
}
static void clear_state(void) {
    memset(&g_kr,0,sizeof(g_kr));g_btn=0;calls=failCall=0;
    memset(&keys,0,sizeof(keys));memset(&mouse,0,sizeof(mouse));
}
int main(void) {
    // Dummy values are only compared by the report sink. No IOKit creation,
    // activation, cancellation, or real report delivery is invoked.
    g_kbd=(IOHIDUserDeviceRef)(uintptr_t)1;
    g_ptr=(IOHIDUserDeviceRef)(uintptr_t)2;
    clear_state();
    assert(vk_to_hid(VK_NUMPAD0)==0x62);
    for(int i=1;i<=9;++i)assert(vk_to_hid(VK_NUMPAD0+i)==0x58+i);
    assert(vhid_key(VK_LCONTROL,0)==0&&keys.mod==1);
    assert(vhid_key(VK_RSHIFT,0)==0&&keys.mod==0x21);
    assert(vhid_key(VK_LCONTROL,1)==0&&keys.mod==0x20);
    for(int i=0;i<6;++i)assert(vhid_key(VK_A+i,0)==0);
    int before=calls;
    assert(vhid_key(VK_A+6,0)==-1&&calls==before);
    assert(vhid_key(VK_A,1)==0&&vhid_key(VK_A+6,0)==0);
    for(int i=0;i<6;++i)assert(g_kr.keys[i]!=0);
    kbd_report_t saved=g_kr;
    failCall=calls+1;assert(vhid_key(VK_RSHIFT,1)==-1);
    assert(!memcmp(&saved,&g_kr,sizeof(saved)));
    failCall=0;assert(vhid_key(VK_RSHIFT,1)==0&&keys.mod==0);
    before=calls;assert(vhid_key(0xff,0)==-1&&calls==before);
    clear_state();
    assert(vhid_mouse(1919,1079,0,300,1920,1080)==0);
    assert(mouse.x==32767&&mouse.y==32767&&mouse.wheel==127);
    assert(vhid_mouse(-100,100000,0,-300,1920,1080)==0);
    assert(mouse.x==0&&mouse.y==32767&&mouse.wheel==-127);
    before=calls;
    assert(vhid_mouse(NAN,0,0,0,1920,1080)==-1);
    assert(vhid_mouse(0,INFINITY,0,0,1920,1080)==-1);
    assert(vhid_mouse(0,0,0,0,0,1080)==-1&&calls==before);
    assert(vhid_mouse(10,10,MOUSEEVENTF_RIGHTDOWN,0,100,100)==0&&g_btn==2);
    failCall=calls+1;
    assert(vhid_mouse(10,10,MOUSEEVENTF_LEFTDOWN,0,100,100)==-1&&g_btn==2);
    failCall=0;
    assert(vhid_mouse(10,10,0x88,0,100,100)==0&&g_btn==2&&mouse.btn==2);
    failCall=calls+2;
    assert(vhid_mouse(10,10,0x88,0,100,100)==-1&&g_btn==3);
    failCall=0;
    assert(vhid_mouse(10,10,MOUSEEVENTF_LEFTUP,0,100,100)==0&&g_btn==2);
    g_kbd=g_ptr=NULL;
    before=calls;assert(vhid_key(VK_A,0)==-1&&vhid_mouse(0,0,0,0,100,100)==-1&&calls==before);
    puts("PASS: native HID reports, keypad, rollover, modifiers, bounds, failure state and held-button preservation");
}
'''
with tempfile.TemporaryDirectory(prefix='mesh-hid-reports-') as directory:
    folder = Path(directory)
    (folder / 'probe.c').write_text(source)
    subprocess.run([os.environ.get('CC','clang'), '-std=gnu11', '-D_POSIX', '-D__APPLE__',
                    '-fsanitize=address,undefined,float-cast-overflow', '-g', '-I', str(root),
                    str(folder/'probe.c'), '-framework', 'IOKit', '-framework', 'CoreFoundation',
                    '-framework', 'Carbon', '-o', str(folder/'probe')], check=True)
    subprocess.run([str(folder/'probe')], check=True)
