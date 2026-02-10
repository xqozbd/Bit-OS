#include "drivers/usb/usbmgr.h"

#include <stdint.h>

#include "drivers/usb/xhci.h"
#include "lib/log.h"

struct usb_dev_stub {
    uint8_t port;
    uint8_t speed;
    uint8_t has_descriptor;
    uint8_t dev_class;
    uint8_t dev_subclass;
    uint8_t dev_proto;
};

static struct usb_dev_stub g_devices[16];
static uint8_t g_device_count;
static int g_ready;

static void usbmgr_stage1_enumerate(void) {
    g_device_count = 0;
    uint8_t ports = xhci_port_count();
    log_printf("USB: enumerating ports (%u)\n", (unsigned)ports);
    for (uint8_t i = 0; i < ports && g_device_count < (uint8_t)(sizeof(g_devices) / sizeof(g_devices[0])); ++i) {
        struct xhci_port_info info;
        if (xhci_port_info(i, &info) != 0) continue;
        if (!info.connected) continue;
        struct usb_dev_stub *dev = &g_devices[g_device_count++];
        dev->port = (uint8_t)(i + 1);
        dev->speed = info.speed;
        dev->has_descriptor = 0;
        dev->dev_class = 0;
        dev->dev_subclass = 0;
        dev->dev_proto = 0;
        log_printf("USB: port %u connected speed=%u\n", (unsigned)dev->port, (unsigned)dev->speed);
    }
    if (g_device_count == 0) {
        log_printf("USB: no devices connected\n");
    }
}

static void usbmgr_stage2_hid_keyboard(void) {
    for (uint8_t i = 0; i < g_device_count; ++i) {
        struct usb_dev_stub *dev = &g_devices[i];
        if (!dev->has_descriptor) continue;
        if (dev->dev_class == 3 && dev->dev_subclass == 1 && dev->dev_proto == 1) {
            log_printf("USB: HID keyboard on port %u (stub)\n", (unsigned)dev->port);
        }
    }
}

static void usbmgr_stage3_hid_mouse(void) {
    for (uint8_t i = 0; i < g_device_count; ++i) {
        struct usb_dev_stub *dev = &g_devices[i];
        if (!dev->has_descriptor) continue;
        if (dev->dev_class == 3 && dev->dev_subclass == 1 && dev->dev_proto == 2) {
            log_printf("USB: HID mouse on port %u (stub)\n", (unsigned)dev->port);
        }
    }
}

static void usbmgr_stage4_msc(void) {
    for (uint8_t i = 0; i < g_device_count; ++i) {
        struct usb_dev_stub *dev = &g_devices[i];
        if (!dev->has_descriptor) continue;
        if (dev->dev_class == 8) {
            log_printf("USB: MSC device on port %u (stub)\n", (unsigned)dev->port);
        }
    }
}

int usbmgr_init(void) {
    g_ready = 0;
    if (!xhci_is_ready()) {
        log_printf("USB: xHCI not ready\n");
        return -1;
    }
    usbmgr_stage1_enumerate();
    usbmgr_stage2_hid_keyboard();
    usbmgr_stage3_hid_mouse();
    usbmgr_stage4_msc();
    g_ready = 1;
    return 0;
}

int usbmgr_is_ready(void) {
    return g_ready;
}
