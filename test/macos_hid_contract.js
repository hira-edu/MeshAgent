'use strict';
// Static source contract for the macOS virtual HID (IOHIDUserDevice) input path.
// No runtime: every check is a string/regex assertion against the C sources.
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const KVM = path.join(__dirname, '..', 'meshcore', 'KVM', 'MacOS');
const read = (f) => fs.readFileSync(path.join(KVM, f), 'utf8');

// Return the brace-delimited body of the function whose signature contains `sig`.
function fnBody(src, sig) {
    const start = src.indexOf(sig);
    assert.ok(start >= 0, `function not found: ${sig}`);
    const open = src.indexOf('{', start);
    assert.ok(open >= 0, `no opening brace for: ${sig}`);
    let depth = 0;
    for (let i = open; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
    }
    assert.fail(`unbalanced braces for: ${sig}`);
}

// ---------------------------------------------------------------------------
// mac_hid.h: public API surface
// ---------------------------------------------------------------------------
const hdr = read('mac_hid.h');
assert.ok(hdr.includes('#ifndef MAC_HID_H_') && hdr.includes('#define MAC_HID_H_'), 'include guard');
assert.ok(hdr.includes('#include <stdint.h>'), 'stdint for uint16_t unicode');
const api = {
    vhid_init:        /int\s+vhid_init\(void\);/,
    vhid_cleanup:     /void\s+vhid_cleanup\(void\);/,
    vhid_available:   /int\s+vhid_available\(void\);/,
    vhid_key:         /int\s+vhid_key\(unsigned char vk, int up\);/,
    vhid_key_unicode: /int\s+vhid_key_unicode\(uint16_t unicode, int up\);/,
    vhid_mouse:       /int\s+vhid_mouse\(double x, double y, int button, short wheel, int sw, int sh\);/,
};
for (const [fn, re] of Object.entries(api)) {
    assert.ok(re.test(hdr), `mac_hid.h must declare ${fn} with the expected signature`);
}
console.log('PASS: mac_hid.h API surface');

// ---------------------------------------------------------------------------
// mac_hid.c: report layout and descriptors
// ---------------------------------------------------------------------------
const src = read('mac_hid.c');
assert.ok(src.includes('#include "mac_hid.h"'), 'implements its own header');
assert.ok(src.includes('#include <IOKit/hidsystem/IOHIDUserDevice.h>'), 'IOHIDUserDevice header');
assert.ok(src.includes('#pragma pack(push, 1)') && src.includes('#pragma pack(pop)'), 'report structs are byte-packed');
assert.ok(/typedef struct \{ uint8_t mod; uint8_t _pad; uint8_t keys\[6\]; \} kbd_report_t;/.test(src), 'boot-keyboard report: mod, pad, 6 keys');
assert.ok(/typedef struct \{ uint8_t btn; uint16_t x; uint16_t y; int8_t wheel; \} ptr_report_t;/.test(src), 'absolute-pointer report: btn, x, y, wheel');

const kbdDesc = src.slice(src.indexOf('kbd_desc[]'), src.indexOf('ptr_desc[]'));
assert.ok(kbdDesc.includes('0x05,0x01, 0x09,0x06'), 'keyboard descriptor: Generic Desktop / Keyboard');
assert.ok(kbdDesc.includes('0x05,0x07, 0x19,0xE0, 0x29,0xE7'), 'keyboard descriptor: modifier usages E0..E7');
assert.ok(kbdDesc.includes('0x95,0x06, 0x75,0x08'), 'keyboard descriptor: six 8-bit key slots');

const ptrDesc = src.slice(src.indexOf('ptr_desc[]'), src.indexOf('vk_to_hid'));
assert.ok(ptrDesc.includes('0x05,0x01, 0x09,0x02'), 'pointer descriptor: Generic Desktop / Mouse');
assert.ok(ptrDesc.includes('0x05,0x09, 0x19,0x01, 0x29,0x03'), 'pointer descriptor: three buttons');
assert.ok(ptrDesc.includes('0x09,0x30, 0x15,0x00, 0x26,0xFF,0x7F, 0x75,0x10'), 'pointer descriptor: absolute X 0..32767');
assert.ok(ptrDesc.includes('0x09,0x31, 0x15,0x00, 0x26,0xFF,0x7F, 0x75,0x10'), 'pointer descriptor: absolute Y 0..32767');
assert.ok(ptrDesc.includes('0x09,0x38, 0x15,0x81, 0x25,0x7F'), 'pointer descriptor: wheel -127..127 (relative)');
console.log('PASS: mac_hid.c report layout and descriptors');

// ---------------------------------------------------------------------------
// mac_hid.c: VK -> HID usage mapping
// ---------------------------------------------------------------------------
const vkToHid = fnBody(src, 'static uint8_t vk_to_hid(unsigned char vk)');
assert.ok(/vk >= VK_A && vk <= VK_Z\)\s+return 0x04/.test(vkToHid), 'letters map to usage 0x04+');
assert.ok(/vk >= VK_1 && vk <= VK_9\)\s+return 0x1E/.test(vkToHid), 'digits 1-9 map to usage 0x1E+');
assert.ok(/vk == VK_0\)\s+return 0x27/.test(vkToHid), 'digit 0 maps to usage 0x27');
assert.ok(/vk >= VK_F1\s+&& vk <= VK_F12\)\s+return 0x3A/.test(vkToHid), 'F1-F12 map to usage 0x3A+');
assert.ok(/vk >= VK_F13 && vk <= VK_F24\)\s+return 0x68/.test(vkToHid), 'F13-F24 map to usage 0x68+');
// Keypad: HID places Keypad 1..9 at 0x59..0x61 and Keypad 0 at 0x62 (not contiguous with 1).
assert.ok(/vk == VK_NUMPAD0\)\s+return 0x62/.test(vkToHid), 'numpad 0 maps to usage 0x62');
assert.ok(/vk >= VK_NUMPAD1 && vk <= VK_NUMPAD9\)\s+return 0x58 \+ \(vk - VK_NUMPAD0\)/.test(vkToHid), 'numpad 1-9 map to usage 0x59..0x61');
for (const [vk, usage] of [['VK_DIVIDE', '0x54'], ['VK_MULTIPLY', '0x55'], ['VK_SUBTRACT', '0x56'], ['VK_ADD', '0x57'], ['VK_DECIMAL', '0x63'], ['VK_NUMLOCK', '0x53']]) {
    assert.ok(new RegExp(`case ${vk}:\\s+return ${usage};`).test(vkToHid), `${vk} maps to keypad usage ${usage}`);
}
assert.ok(/default:\s+return 0;/.test(vkToHid), 'unmapped VK yields usage 0');

const vkToMod = fnBody(src, 'static uint8_t vk_to_mod(unsigned char vk)');
for (const [vks, bit] of [
    ['VK_CONTROL:  case VK_LCONTROL', '0x01'], ['VK_SHIFT:    case VK_LSHIFT', '0x02'], ['VK_MENU:     case VK_LMENU', '0x04'],
    ['VK_LWIN', '0x08'], ['VK_RCONTROL', '0x10'], ['VK_RSHIFT', '0x20'], ['VK_RMENU', '0x40'], ['VK_RWIN', '0x80'],
]) {
    assert.ok(vkToMod.includes(`case ${vks}:`) && vkToMod.includes(`return ${bit};`), `modifier ${vks} -> bit ${bit}`);
}
console.log('PASS: mac_hid.c VK mapping');

// Every VK the CGEvent keymap knows is either HID-mapped, a modifier, or on the
// explicit CGEvent-fallback list. A new keymap entry must land in one of these.
const ev = read('mac_events.c');
const keymapVKs = new Set();
let m;
const keymapRe = /\{\s*\w+,\s+(VK_\w+)\s*\}/g;
while ((m = keymapRe.exec(ev)) !== null) keymapVKs.add(m[1]);
assert.ok(keymapVKs.size > 100, `keymap extraction looks wrong (${keymapVKs.size} VKs)`);
const hidCases = new Set();
const caseRe = /case\s+(VK_\w+):/g;
while ((m = caseRe.exec(vkToHid + vkToMod)) !== null) hidCases.add(m[1]);
const cgFallbackOnly = new Set(['VK_CLEAR', 'VK_SELECT', 'VK_EXECUTE', 'VK_CANCEL', 'VK_SEPARATOR', 'VK_KANA']);
const unmapped = [];
for (const vk of keymapVKs) {
    if (hidCases.has(vk)) continue;
    if (/^VK_[A-Z]$/.test(vk) || /^VK_[0-9]$/.test(vk) || /^VK_F\d+$/.test(vk) || /^VK_NUMPAD\d$/.test(vk)) continue;
    if (cgFallbackOnly.has(vk)) continue;
    unmapped.push(vk);
}
assert.deepStrictEqual(unmapped, [], `keymap VKs with no HID mapping and not on the CGEvent-fallback list: ${unmapped.join(', ')}`);
console.log(`PASS: ${keymapVKs.size} keymap VK codes accounted for (${cgFallbackOnly.size} CGEvent-only)`);

// ---------------------------------------------------------------------------
// mac_hid.c: IOHIDUserDevice lifecycle
// ---------------------------------------------------------------------------
const openDev = fnBody(src, 'static IOHIDUserDeviceRef open_device(');
assert.ok(openDev.includes('CFSTR(kIOHIDReportDescriptorKey)'), 'open_device sets report descriptor');
assert.ok(openDev.includes('CFSTR(kIOHIDProductKey)'), 'open_device sets product name');
assert.ok(openDev.includes('CFSTR(kIOHIDVendorIDKey)') && openDev.includes('CFSTR(kIOHIDProductIDKey)'), 'open_device sets vendor/product IDs');
assert.ok(openDev.includes('IOHIDUserDeviceCreateWithProperties'), 'IOHIDUserDevice creation API');
assert.ok(openDev.includes('IOHIDUserDeviceSetDispatchQueue') && openDev.includes('IOHIDUserDeviceActivate'), 'device gets a dispatch queue and is activated');
assert.ok(/CFRelease\(p\);/.test(openDev), 'open_device releases the property dictionary');
assert.ok(/if \(!dq\) \{ CFRelease\(dev\); return NULL; \}/.test(openDev), 'open_device fails closed when queue creation fails');

const closeDev = fnBody(src, 'static void close_device(');
assert.ok(closeDev.includes('IOHIDUserDeviceCancel'), 'close_device cancels the device');
assert.ok(closeDev.includes('CFRelease(*ref)') && closeDev.includes('*ref = NULL'), 'close_device releases and nulls the device ref');
assert.ok(closeDev.includes('dispatch_release(*q)') && closeDev.includes('*q = NULL'), 'close_device releases and nulls the dispatch queue');

const init = fnBody(src, 'int vhid_init(void)');
assert.ok(/if \(g_ready\) return 1;/.test(init), 'vhid_init is idempotent');
assert.ok(init.includes('memset(&g_kr, 0, sizeof(g_kr))') && init.includes('g_btn = 0'), 'vhid_init resets key/button state');
assert.ok(init.includes('open_device(kbd_desc') && init.includes('open_device(ptr_desc'), 'vhid_init opens keyboard and pointer');
assert.ok(/if \(g_kbd && g_ptr\) \{ g_ready = 1;/.test(init), 'vhid_init only reports ready when both devices exist');
assert.ok((init.match(/close_device\(/g) || []).length >= 2 && /return 0;\s*\}$/.test(init), 'vhid_init closes both devices and returns 0 on partial failure');

const cleanup = fnBody(src, 'void vhid_cleanup(void)');
assert.ok(cleanup.includes('memset(&g_kr, 0, sizeof(g_kr))') && cleanup.includes('IOHIDUserDeviceHandleReportWithTimeStamp(g_kbd'), 'cleanup posts an all-keys-up report');
assert.ok(cleanup.includes('ptr_report_t r = {0}') && cleanup.includes('IOHIDUserDeviceHandleReportWithTimeStamp(g_ptr'), 'cleanup posts an all-buttons-up report');
assert.ok(cleanup.includes('close_device(&g_kbd') && cleanup.includes('close_device(&g_ptr'), 'cleanup closes both devices');
assert.ok(/g_ready = 0;\s*\}$/.test(cleanup), 'cleanup clears the ready flag');
assert.ok(/int vhid_available\(void\) \{ return g_ready; \}/.test(src), 'vhid_available reflects g_ready');
console.log('PASS: mac_hid.c IOHIDUserDevice lifecycle');

// ---------------------------------------------------------------------------
// mac_hid.c: input posting
// ---------------------------------------------------------------------------
const key = fnBody(src, 'int vhid_key(unsigned char vk, int up)');
assert.ok(/if \(!g_kbd\) return -1;/.test(key), 'vhid_key fails when no keyboard device');
assert.ok(/if \(!u\) return -1;/.test(key), 'vhid_key returns -1 for unmapped VK so CGEvent fallback runs');
assert.ok(key.includes('next.mod &= ~m') && key.includes('next.mod |= m'), 'vhid_key maintains the modifier bitmask');
assert.ok(key.includes('IOHIDUserDeviceHandleReportWithTimeStamp(g_kbd'), 'vhid_key posts a keyboard report');
assert.ok(key.indexOf('g_kr = next') > key.indexOf('!= kIOReturnSuccess'), 'keyboard state commits after successful delivery');

const unicode = fnBody(src, 'int vhid_key_unicode(uint16_t unicode, int up)');
assert.ok(/return -1;/.test(unicode), 'vhid_key_unicode declines so CGEvent unicode path handles it');

const scale = fnBody(src, 'static uint16_t scale_coord(double v, int span)');
assert.ok(scale.includes('span <= 1 || !isfinite(v)'), 'scale_coord guards invalid spans and non-finite coordinates');
assert.ok(/if \(n < 0\.0\) n = 0\.0;/.test(scale) && /if \(n > 32767\.0\) n = 32767\.0;/.test(scale), 'scale_coord clamps to the 0..32767 descriptor range');

const mouse = fnBody(src, 'int vhid_mouse(double x, double y, int button, short wheel, int sw, int sh)');
assert.ok(/if \(!g_ptr\) return -1;/.test(mouse), 'vhid_mouse fails when no pointer device');
for (const [evt, op] of [
    ['MOUSEEVENTF_LEFTDOWN', 'g_btn |= 0x01'], ['MOUSEEVENTF_LEFTUP', 'g_btn &= ~0x01'],
    ['MOUSEEVENTF_RIGHTDOWN', 'g_btn |= 0x02'], ['MOUSEEVENTF_RIGHTUP', 'g_btn &= ~0x02'],
    ['MOUSEEVENTF_MIDDLEDOWN', 'g_btn |= 0x04'], ['MOUSEEVENTF_MIDDLEUP', 'g_btn &= ~0x04'],
]) {
    assert.ok(mouse.includes(`case ${evt}:`) && mouse.includes(op), `vhid_mouse handles ${evt}`);
}
assert.ok(mouse.includes('case 0x88:'), 'vhid_mouse handles the 0x88 double-click code');
assert.ok((mouse.match(/scale_coord\(x, sw\)/g) || []).length >= 2 && (mouse.match(/scale_coord\(y, sh\)/g) || []).length >= 2, 'both pointer paths use clamped coordinates');
assert.ok(/wheel > 127 \? 127 : \(wheel < -127 \? -127 : wheel\)/.test(mouse), 'wheel is clamped to the int8 descriptor range');
assert.ok(mouse.includes('IOHIDUserDeviceHandleReportWithTimeStamp(g_ptr'), 'vhid_mouse posts a pointer report');
console.log('PASS: mac_hid.c input posting');

// ---------------------------------------------------------------------------
// mac_events.c: VHID-first with CGEvent fallback preserved
// ---------------------------------------------------------------------------
assert.ok(ev.includes('#include "mac_hid.h"'), 'mac_events.c includes mac_hid.h');
const mouseAction = fnBody(ev, 'void MouseAction(double absX, double absY, int button, short wheel)');
assert.ok(/if \(vhid_available\(\)\) \{\s*if \(vhid_mouse\(absX, absY, button, wheel, SCREEN_WIDTH, SCREEN_HEIGHT\) == 0\) return;/.test(mouseAction), 'MouseAction tries VHID first');
assert.ok(mouseAction.includes('MouseAction_CGEvent(absX, absY, button, wheel)'), 'MouseAction falls back to CGEvent');

const keyAction = fnBody(ev, 'void KeyAction(unsigned char vk, int up)');
assert.ok(keyAction.indexOf('MNG_KVM_KEYSTATE') < keyAction.indexOf('vhid_available()'), 'lock-key state is still reported before VHID posting');
assert.ok(/if \(vhid_available\(\)\) \{\s*if \(vhid_key\(vk, up\) == 0\) return;/.test(keyAction), 'KeyAction tries VHID first');
assert.ok(keyAction.includes('KeyAction_CGEvent(vk, up)'), 'KeyAction falls back to CGEvent');

const keyUnicode = fnBody(ev, 'void KeyActionUnicode(uint16_t unicode, int up)');
assert.ok(keyUnicode.includes('vhid_available() && vhid_key_unicode(unicode, up) == 0'), 'KeyActionUnicode tries VHID first');
assert.ok(keyUnicode.includes('CGEventKeyboardSetUnicodeString'), 'KeyActionUnicode falls back to CGEvent unicode');

const mouseCG = fnBody(ev, 'static void MouseAction_CGEvent(');
const keyCG = fnBody(ev, 'static void KeyAction_CGEvent(');
assert.ok(mouseCG.includes('CGEventPost(kCGHIDEventTap') && mouseCG.includes('CGEventCreateMouseEvent'), 'CGEvent mouse fallback still posts');
assert.ok(keyCG.includes('CGEventPost(kCGHIDEventTap') && keyCG.includes('CGEventCreateKeyboardEvent'), 'CGEvent keyboard fallback still posts');
assert.ok(!mouseCG.includes('vhid_') && !keyCG.includes('vhid_'), 'CGEvent fallbacks do not recurse into VHID');
console.log('PASS: CGEvent fallback preserved');

// ---------------------------------------------------------------------------
// mac_kvm.c: lifecycle wiring
// ---------------------------------------------------------------------------
const kvm = read('mac_kvm.c');
assert.ok(kvm.includes('#include "mac_hid.h"'), 'mac_kvm.c includes mac_hid.h');
const initIdx = kvm.indexOf('vhid_init()');
const kvmInitIdx = kvm.indexOf('kvm_init()');
const cleanupIdx = kvm.indexOf('vhid_cleanup()');
assert.ok(initIdx > 0, 'vhid_init called');
assert.ok(kvmInitIdx > 0 && kvmInitIdx < initIdx, 'vhid_init runs after kvm_init');
assert.ok(/if \(vhid_init\(\)\)\s*\{/.test(kvm) && !/if \(!vhid_init\(\)\)/.test(kvm), 'vhid_init failure is non-fatal (CGEvent path remains)');
assert.ok(cleanupIdx > initIdx, 'vhid_cleanup called on shutdown');
const destroyIdx = kvm.indexOf('ILibQueue_Destroy(g_messageQ)');
const joinIdx = kvm.lastIndexOf('pthread_join(kvmthread', cleanupIdx);
assert.ok(joinIdx > 0 && joinIdx < cleanupIdx, 'input thread is joined before vhid_cleanup');
assert.ok(destroyIdx > cleanupIdx, 'vhid_cleanup precedes message-queue teardown');
console.log('PASS: lifecycle wired');

// ---------------------------------------------------------------------------
// mac_kvm.c: input authorization gate
// Both input transports retain the same desktop authorization check.
// ---------------------------------------------------------------------------
const permissionBody = fnBody(kvm, 'static int MacKvm_CanPostInput(void)');
assert.ok(!permissionBody.includes('vhid_available()'), 'device availability does not grant desktop control');
assert.ok(permissionBody.includes('AXIsProcessTrustedWithOptions(NULL)'), 'input requires the silent Accessibility check');
assert.ok(!permissionBody.includes('kAXTrustedCheckOptionPrompt'), 'authorization check must never raise a consent prompt');
for (const type of ['MNG_KVM_KEY_UNICODE', 'MNG_KVM_KEY', 'MNG_KVM_MOUSE']) {
    const caseIdx = kvm.indexOf(`case ${type}:`);
    assert.ok(caseIdx > 0, `${type} handled`);
    const nextCase = kvm.indexOf('case ', caseIdx + 5);
    const handler = kvm.slice(caseIdx, nextCase > 0 ? nextCase : undefined);
    assert.ok(handler.includes('MacKvm_CanPostInput()'), `${type} is gated by MacKvm_CanPostInput`);
}
assert.ok(kvm.includes('int canInput = MacKvm_CanPostInput();'), 'permission status loop rechecks input authorization');
console.log('PASS: both input transports retain desktop authorization');

console.log('\nAll contract tests passed.');
