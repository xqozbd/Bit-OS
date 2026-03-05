#ifndef HID_KBD_H
#define HID_KBD_H

#include <stddef.h>
#include <stdint.h>

int hid_kbd_inject_report(const uint8_t *report, size_t len);

#endif /* HID_KBD_H */
