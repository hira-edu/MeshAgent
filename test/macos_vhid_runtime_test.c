/**
 * macos_vhid_runtime_test.c — Standalone test for IOHIDUserDevice on this Mac.
 *
 * Tests whether virtual HID device creation works as root without the
 * com.apple.developer.hid.virtual.device entitlement.
 *
 * Build:  clang -o macos_vhid_runtime_test test/macos_vhid_runtime_test.c \
 *               -framework IOKit -framework CoreFoundation -mmacosx-version-min=10.15
 * Run:    sudo ./macos_vhid_runtime_test
 *
 * Expected output on success:
 *   [1] Virtual keyboard: OK
 *   [2] Virtual pointer:  OK
 *   [3] Keyboard report:  OK
 *   [4] Pointer report:   OK
 *   RESULT: PASS — IOHIDUserDevice works. Accessibility TCC not needed for input.
 *
 * Expected output on failure (entitlement required):
 *   [1] Virtual keyboard: FAIL (IOHIDUserDeviceCreateWithProperties returned NULL)
 *   RESULT: FAIL — entitlement required. Use Karabiner DriverKit approach instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/hidsystem/IOHIDUserDevice.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach_time.h>

static const uint8_t kKbdDesc[] = {
    0x05,0x01, 0x09,0x06, 0xA1,0x01,
    0x05,0x07, 0x19,0xE0, 0x29,0xE7,
    0x15,0x00, 0x25,0x01, 0x75,0x01, 0x95,0x08, 0x81,0x02,
    0x95,0x01, 0x75,0x08, 0x81,0x01,
    0x95,0x06, 0x75,0x08, 0x15,0x00, 0x26,0xFF,0x00,
    0x05,0x07, 0x19,0x00, 0x29,0xFF, 0x81,0x00,
    0xC0
};

static const uint8_t kPtrDesc[] = {
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

static IOHIDUserDeviceRef make(const uint8_t *d, size_t n, const char *name) {
    CFMutableDictionaryRef p = CFDictionaryCreateMutable(NULL,0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef dd = CFDataCreate(NULL, d, (CFIndex)n);
    CFDictionarySetValue(p, CFSTR(kIOHIDReportDescriptorKey), dd);
    CFRelease(dd);
    CFStringRef s = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    CFDictionarySetValue(p, CFSTR(kIOHIDProductKey), s);
    CFRelease(s);
    int v=0x2342, q=0x4D41;
    CFNumberRef vr=CFNumberCreate(NULL,kCFNumberIntType,&v);
    CFNumberRef qr=CFNumberCreate(NULL,kCFNumberIntType,&q);
    CFDictionarySetValue(p, CFSTR(kIOHIDVendorIDKey), vr);
    CFDictionarySetValue(p, CFSTR(kIOHIDProductIDKey), qr);
    CFRelease(vr); CFRelease(qr);
    IOHIDUserDeviceRef dev = IOHIDUserDeviceCreateWithProperties(NULL, p, 0);
    CFRelease(p);
    if (!dev) return NULL;
    dispatch_queue_t dq = dispatch_queue_create(name, DISPATCH_QUEUE_SERIAL);
    IOHIDUserDeviceSetDispatchQueue(dev, dq);
    IOHIDUserDeviceActivate(dev);
    return dev;
}

int main(void) {
    printf("=== macOS Virtual HID Runtime Test ===\n");
    printf("UID: %d (%s)\n\n", getuid(), getuid()==0?"root":"non-root");

    IOHIDUserDeviceRef kbd = make(kKbdDesc, sizeof(kKbdDesc), "Test-VKbd");
    printf("[1] Virtual keyboard: %s\n", kbd ? "OK" : "FAIL (IOHIDUserDeviceCreateWithProperties returned NULL)");

    IOHIDUserDeviceRef ptr = make(kPtrDesc, sizeof(kPtrDesc), "Test-VPtr");
    printf("[2] Virtual pointer:  %s\n", ptr ? "OK" : "FAIL");

    if (!kbd || !ptr) {
        printf("\nRESULT: FAIL — entitlement required. Use Karabiner DriverKit approach instead.\n");
        if (kbd) { IOHIDUserDeviceCancel(kbd); CFRelease(kbd); }
        if (ptr) { IOHIDUserDeviceCancel(ptr); CFRelease(ptr); }
        return 1;
    }

    usleep(300000);

    // Post a keyboard report (press 'a' = USB HID 0x04, then release)
    uint8_t kr[8] = {0};
    kr[2] = 0x04;
    IOReturn r1 = IOHIDUserDeviceHandleReportWithTimeStamp(kbd, mach_absolute_time(), kr, 8);
    kr[2] = 0x00;
    IOHIDUserDeviceHandleReportWithTimeStamp(kbd, mach_absolute_time(), kr, 8);
    printf("[3] Keyboard report:  %s (0x%x)\n", r1==kIOReturnSuccess?"OK":"FAIL", r1);

    // Post a pointer report (move to center)
    uint8_t pr[6] = {0, 0xFF,0x3F, 0xFF,0x3F, 0};
    IOReturn r2 = IOHIDUserDeviceHandleReportWithTimeStamp(ptr, mach_absolute_time(), pr, 6);
    printf("[4] Pointer report:   %s (0x%x)\n", r2==kIOReturnSuccess?"OK":"FAIL", r2);

    printf("\nRESULT: %s\n",
        (r1==kIOReturnSuccess && r2==kIOReturnSuccess)
            ? "PASS — IOHIDUserDevice works. Accessibility TCC not needed for input."
            : "PARTIAL — device created but reports failed.");

    IOHIDUserDeviceCancel(kbd); IOHIDUserDeviceCancel(ptr);
    usleep(100000);
    CFRelease(kbd); CFRelease(ptr);
    return (r1==kIOReturnSuccess && r2==kIOReturnSuccess) ? 0 : 1;
}
