#include "mac_hid.h"
#include "mac_events.h"
#include <IOKit/hidsystem/IOHIDUserDevice.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach_time.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#pragma pack(push, 1)
typedef struct { uint8_t mod; uint8_t _pad; uint8_t keys[6]; } kbd_report_t;
typedef struct { uint8_t btn; uint16_t x; uint16_t y; int8_t wheel; } ptr_report_t;
#pragma pack(pop)

static IOHIDUserDeviceRef g_kbd = NULL;
static IOHIDUserDeviceRef g_ptr = NULL;
static dispatch_queue_t g_kbd_q = NULL;
static dispatch_queue_t g_ptr_q = NULL;
static int g_ready = 0;
static kbd_report_t g_kr;
static uint8_t g_btn = 0;

static const uint8_t kbd_desc[] = {
    0x05,0x01, 0x09,0x06, 0xA1,0x01,
    0x05,0x07, 0x19,0xE0, 0x29,0xE7,
    0x15,0x00, 0x25,0x01, 0x75,0x01, 0x95,0x08, 0x81,0x02,
    0x95,0x01, 0x75,0x08, 0x81,0x01,
    0x95,0x06, 0x75,0x08, 0x15,0x00, 0x26,0xFF,0x00,
    0x05,0x07, 0x19,0x00, 0x29,0xFF, 0x81,0x00,
    0xC0
};

static const uint8_t ptr_desc[] = {
    0x05,0x01, 0x09,0x02, 0xA1,0x01,
    0x09,0x01, 0xA1,0x00,
    0x05,0x09, 0x19,0x01, 0x29,0x03,
    0x15,0x00, 0x25,0x01, 0x95,0x03, 0x75,0x01, 0x81,0x02,
    0x95,0x01, 0x75,0x05, 0x81,0x01,
    0x05,0x01,
    0x09,0x30, 0x15,0x00, 0x26,0xFF,0x7F, 0x75,0x10, 0x95,0x01, 0x81,0x02,
    0x09,0x31, 0x15,0x00, 0x26,0xFF,0x7F, 0x75,0x10, 0x95,0x01, 0x81,0x02,
    0x09,0x38, 0x15,0x81, 0x25,0x7F, 0x75,0x08, 0x95,0x01, 0x81,0x06,
    0xC0, 0xC0
};

static uint8_t vk_to_hid(unsigned char vk) {
    if (vk >= VK_A && vk <= VK_Z)     return 0x04 + (vk - VK_A);
    if (vk >= VK_1 && vk <= VK_9)     return 0x1E + (vk - VK_1);
    if (vk == VK_0)                    return 0x27;
    if (vk >= VK_F1  && vk <= VK_F12) return 0x3A + (vk - VK_F1);
    if (vk >= VK_F13 && vk <= VK_F24) return 0x68 + (vk - VK_F13);
    if (vk == VK_NUMPAD0)                      return 0x62;
    if (vk >= VK_NUMPAD1 && vk <= VK_NUMPAD9) return 0x58 + (vk - VK_NUMPAD0);
    switch (vk) {
        case VK_RETURN:     return 0x28;  case VK_ESCAPE:     return 0x29;
        case VK_BACK:       return 0x2A;  case VK_TAB:        return 0x2B;
        case VK_SPACE:      return 0x2C;  case VK_OEM_MINUS:  return 0x2D;
        case VK_OEM_PLUS:   return 0x2E;  case VK_OEM_4:      return 0x2F;
        case VK_OEM_6:      return 0x30;  case VK_OEM_5:      return 0x31;
        case VK_OEM_1:      return 0x33;  case VK_OEM_7:      return 0x34;
        case VK_OEM_3:      return 0x35;  case VK_OEM_COMMA:  return 0x36;
        case VK_OEM_PERIOD: return 0x37;  case VK_OEM_2:      return 0x38;
        case VK_CAPITAL:    return 0x39;  case VK_SNAPSHOT:    return 0x46;
        case VK_SCROLL:     return 0x47;  case VK_PAUSE:       return 0x48;
        case VK_INSERT:     return 0x49;  case VK_HOME:        return 0x4A;
        case VK_PRIOR:      return 0x4B;  case VK_DELETE:      return 0x4C;
        case VK_END:        return 0x4D;  case VK_NEXT:        return 0x4E;
        case VK_RIGHT:      return 0x4F;  case VK_LEFT:        return 0x50;
        case VK_DOWN:       return 0x51;  case VK_UP:          return 0x52;
        case VK_NUMLOCK:    return 0x53;  case VK_DIVIDE:      return 0x54;
        case VK_MULTIPLY:   return 0x55;  case VK_SUBTRACT:    return 0x56;
        case VK_ADD:        return 0x57;  case VK_DECIMAL:     return 0x63;
        case VK_APPS:       return 0x65;  case VK_HELP:        return 0x75;
        default:            return 0;
    }
}

static uint8_t vk_to_mod(unsigned char vk) {
    switch (vk) {
        case VK_CONTROL:  case VK_LCONTROL: return 0x01;
        case VK_SHIFT:    case VK_LSHIFT:   return 0x02;
        case VK_MENU:     case VK_LMENU:    return 0x04;
        case VK_LWIN:                       return 0x08;
        case VK_RCONTROL:                   return 0x10;
        case VK_RSHIFT:                     return 0x20;
        case VK_RMENU:                      return 0x40;
        case VK_RWIN:                       return 0x80;
        default:                            return 0;
    }
}

static IOHIDUserDeviceRef open_device(const uint8_t *desc, size_t len, const char *label, dispatch_queue_t *out_q) {
    if (out_q) *out_q = NULL;
    CFMutableDictionaryRef p = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!p) return NULL;

    CFDataRef d = CFDataCreate(NULL, desc, (CFIndex)len);
    if (!d) { CFRelease(p); return NULL; }
    CFDictionarySetValue(p, CFSTR(kIOHIDReportDescriptorKey), d);
    CFRelease(d);

    CFStringRef n = CFStringCreateWithCString(NULL, label, kCFStringEncodingUTF8);
    if (!n) { CFRelease(p); return NULL; }
    CFDictionarySetValue(p, CFSTR(kIOHIDProductKey), n);
    CFRelease(n);

    int vid = 0x2342, pid = 0x4D41;
    CFNumberRef v = CFNumberCreate(NULL, kCFNumberIntType, &vid);
    CFNumberRef q = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    if (!v || !q) { if (v) CFRelease(v); if (q) CFRelease(q); CFRelease(p); return NULL; }
    CFDictionarySetValue(p, CFSTR(kIOHIDVendorIDKey), v);
    CFDictionarySetValue(p, CFSTR(kIOHIDProductIDKey), q);
    CFRelease(v); CFRelease(q);

    IOHIDUserDeviceRef dev = IOHIDUserDeviceCreateWithProperties(NULL, p, 0);
    CFRelease(p);
    if (!dev) return NULL;

    dispatch_queue_t dq = dispatch_queue_create(label, DISPATCH_QUEUE_SERIAL);
    if (!dq) { CFRelease(dev); return NULL; }
    IOHIDUserDeviceSetDispatchQueue(dev, dq);
    IOHIDUserDeviceActivate(dev);
    if (out_q) *out_q = dq; else dispatch_release(dq);
    return dev;
}

static void close_device(IOHIDUserDeviceRef *ref, dispatch_queue_t *q) {
    if (*ref) { IOHIDUserDeviceCancel(*ref); usleep(50000); CFRelease(*ref); *ref = NULL; }
    if (q && *q) { dispatch_release(*q); *q = NULL; }
}

int vhid_init(void) {
    if (!__builtin_available(macOS 10.15, *)) return 0;
    if (g_ready) return 1;
    memset(&g_kr, 0, sizeof(g_kr));
    g_btn = 0;

    g_kbd = open_device(kbd_desc, sizeof(kbd_desc), "meshagent.vkbd", &g_kbd_q);
    g_ptr = open_device(ptr_desc, sizeof(ptr_desc), "meshagent.vptr", &g_ptr_q);

    if (g_kbd && g_ptr) { g_ready = 1; usleep(200000); return 1; }
    close_device(&g_kbd, &g_kbd_q);
    close_device(&g_ptr, &g_ptr_q);
    return 0;
}

void vhid_cleanup(void) {
    if (g_kbd) {
        memset(&g_kr, 0, sizeof(g_kr));
        IOHIDUserDeviceHandleReportWithTimeStamp(g_kbd, mach_absolute_time(), (uint8_t*)&g_kr, sizeof(g_kr));
    }
    if (g_ptr) {
        ptr_report_t r = {0};
        IOHIDUserDeviceHandleReportWithTimeStamp(g_ptr, mach_absolute_time(), (uint8_t*)&r, sizeof(r));
    }
    close_device(&g_kbd, &g_kbd_q);
    close_device(&g_ptr, &g_ptr_q);
    g_ready = 0;
}

int vhid_available(void) { return g_ready; }

int vhid_key(unsigned char vk, int up) {
    if (!g_kbd) return -1;
    kbd_report_t next = g_kr;
    uint8_t m = vk_to_mod(vk);
    if (m) {
        if (up) next.mod &= ~m; else next.mod |= m;
    } else {
        uint8_t u = vk_to_hid(vk);
        if (!u) return -1;
        if (up) {
            for (int i = 0; i < 6; i++) { if (next.keys[i] == u) { next.keys[i] = 0; break; } }
        } else {
            for (int i = 0; i < 6; i++) { if (next.keys[i] == u) goto post; }
            for (int i = 0; i < 6; i++) { if (!next.keys[i]) { next.keys[i] = u; goto post; } }
            return -1; // The boot-keyboard report cannot represent a seventh key.
        }
    }
post:
    if (IOHIDUserDeviceHandleReportWithTimeStamp(g_kbd, mach_absolute_time(),
        (uint8_t*)&next, sizeof(next)) != kIOReturnSuccess) return -1;
    g_kr = next;
    return 0;
}

int vhid_key_unicode(uint16_t unicode, int up) {
    (void)unicode; (void)up;
    return -1;
}

static uint16_t scale_coord(double v, int span) {
    double n;
    if (span <= 1 || !isfinite(v)) return 0;
    n = (v / (span - 1)) * 32767.0;
    if (n < 0.0) n = 0.0;
    if (n > 32767.0) n = 32767.0;
    return (uint16_t)n;
}

int vhid_mouse(double x, double y, int button, short wheel, int sw, int sh) {
    if (!g_ptr) return -1;
    if (sw <= 1 || sh <= 1 || !isfinite(x) || !isfinite(y)) return -1;
    uint8_t previous = g_btn;

    switch (button) {
        case MOUSEEVENTF_LEFTDOWN:   g_btn |= 0x01;  break;
        case MOUSEEVENTF_LEFTUP:     g_btn &= ~0x01; break;
        case MOUSEEVENTF_RIGHTDOWN:  g_btn |= 0x02;  break;
        case MOUSEEVENTF_RIGHTUP:    g_btn &= ~0x02; break;
        case MOUSEEVENTF_MIDDLEDOWN: g_btn |= 0x04;  break;
        case MOUSEEVENTF_MIDDLEUP:   g_btn &= ~0x04; break;
        case 0x88: {
            ptr_report_t r = {0};
            r.x = scale_coord(x, sw);
            r.y = scale_coord(y, sh);
            for (int i = 0; i < 4; ++i) {
                r.btn = (previous & ~0x01) | ((i & 1) ? 0 : 0x01);
                if (IOHIDUserDeviceHandleReportWithTimeStamp(g_ptr, mach_absolute_time(), (uint8_t*)&r, sizeof(r)) != kIOReturnSuccess) return -1;
                g_btn = r.btn;
                if (i < 3) usleep(i == 1 ? 30000 : 10000);
            }
            return 0;
        }
        default: break;
    }

    ptr_report_t r;
    r.btn   = g_btn;
    r.x     = scale_coord(x, sw);
    r.y     = scale_coord(y, sh);
    r.wheel = (int8_t)(wheel > 127 ? 127 : (wheel < -127 ? -127 : wheel));

    if (IOHIDUserDeviceHandleReportWithTimeStamp(g_ptr, mach_absolute_time(),
        (uint8_t*)&r, sizeof(r)) != kIOReturnSuccess) { g_btn = previous; return -1; }
    return 0;
}
