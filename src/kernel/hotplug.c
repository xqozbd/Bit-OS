#include "kernel/hotplug.h"

#include "drivers/pci/pci.h"
#include "drivers/usb/usbmgr.h"
#include "kernel/rng.h"
#include "kernel/sleep.h"
#include "kernel/thread.h"
#include "lib/log.h"
#include "arch/x86_64/timer.h"

static volatile int g_hotplug_running = 0;
static volatile int g_hotplug_stop = 0;

static void hotplug_thread(void *arg) {
    (void)arg;
    while (!g_hotplug_stop) {
        int pci_changes = pci_rescan();
        usbmgr_poll();
        if (pci_changes > 0) {
            rng_seed((uint64_t)pci_changes ^ (uint64_t)timer_uptime_ticks());
        }
        sleep_ms(2000);
    }
    g_hotplug_running = 0;
    thread_exit();
}

int hotplug_start(void) {
    if (g_hotplug_running) return 1;
    g_hotplug_stop = 0;
    if (!thread_create(hotplug_thread, NULL, 8192, "hotplug")) {
        log_printf("hotplug: thread spawn failed\n");
        return 0;
    }
    g_hotplug_running = 1;
    log_printf("hotplug: monitoring PCI/USB\n");
    return 1;
}

int hotplug_stop(void) {
    if (!g_hotplug_running) return 1;
    g_hotplug_stop = 1;
    return 1;
}

int hotplug_is_running(void) {
    return g_hotplug_running != 0;
}
