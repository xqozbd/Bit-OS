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
static uint8_t g_port_state[32];
static uint8_t g_port_count;

static void usbmgr_stage1_enumerate(void) {
    g_device_count = 0;
    uint8_t ports = xhci_port_count();
    g_port_count = ports;
    log_printf("USB: enumerating ports (%u)\n", (unsigned)ports);
    for (uint8_t i = 0; i < ports && g_device_count < (uint8_t)(sizeof(g_devices) / sizeof(g_devices[0])); ++i) {
        struct xhci_port_info info;
        if (xhci_port_info(i, &info) != 0) continue;
        g_port_state[i] = info.connected ? 1u : 0u;
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
    for (uint8_t i = 0; i < (uint8_t)sizeof(g_port_state); ++i) g_port_state[i] = 0;
    g_port_count = 0;
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

void usbmgr_poll(void) {
    if (!g_ready || !xhci_is_ready()) return;
    uint8_t ports = xhci_port_count();
    if (ports > (uint8_t)sizeof(g_port_state)) ports = (uint8_t)sizeof(g_port_state);
    int changed = 0;
    for (uint8_t i = 0; i < ports; ++i) {
        struct xhci_port_info info;
        if (xhci_port_info(i, &info) != 0) continue;
        uint8_t connected = info.connected ? 1u : 0u;
        if (connected != g_port_state[i]) {
            g_port_state[i] = connected;
            changed = 1;
            if (connected) {
                log_printf("USB: hotplug connect port %u speed=%u\n",
                           (unsigned)(i + 1), (unsigned)info.speed);
            } else {
                log_printf("USB: hotplug disconnect port %u\n", (unsigned)(i + 1));
            }
        }
    }
    if (ports != g_port_count) {
        g_port_count = ports;
        changed = 1;
    }
    if (changed) {
        usbmgr_stage1_enumerate();
        usbmgr_stage2_hid_keyboard();
        usbmgr_stage3_hid_mouse();
        usbmgr_stage4_msc();
    }
}

int usbmgr_shutdown(void) {
    g_ready = 0;
    g_device_count = 0;
    return 1;
}
