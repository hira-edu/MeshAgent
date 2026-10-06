#ifndef MAC_HID_H_
#define MAC_HID_H_

#include <stdint.h>

int  vhid_init(void);
void vhid_cleanup(void);
int  vhid_available(void);
int  vhid_key(unsigned char vk, int up);
int  vhid_key_unicode(uint16_t unicode, int up);
int  vhid_mouse(double x, double y, int button, short wheel, int sw, int sh);

#endif
