#include "drivers/pci/pci.h"

#include <stddef.h>

#include "arch/x86_64/io.h"
#include "arch/x86_64/cpu_info.h"
#include "lib/log.h"
#include "lib/strutil.h"
#include "sys/boot_params.h"

#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

static struct pci_driver *g_drivers[32];
static uint32_t g_driver_count = 0;

static struct pci_device g_devices[256];
static uint32_t g_device_count = 0;
static int g_rescan_active = 0;
static const struct pci_device *g_old_devices = NULL;
static uint32_t g_old_count = 0;
static struct pci_device g_rescan_old[256];
static volatile int g_rescan_busy = 0;
static uint16_t g_scan_max_bus = 0xFF;
static int g_scan_max_bus_set = 0;

enum {
    PCI_BAR_IO = 1u << 0,
    PCI_BAR_PREFETCH = 1u << 1,
    PCI_BAR_64 = 1u << 2
};

static inline uint32_t pci_addr(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    return (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)slot << 11) |
           ((uint32_t)func << 8) | (offset & 0xFC);
}

static uint16_t pci_get_max_bus(void) {
    if (g_scan_max_bus_set) return g_scan_max_bus;
    g_scan_max_bus_set = 1;
    uint16_t max_bus = 0xFF;
    const char *param = boot_param_get("pci_max_bus");
    if (param && param[0]) {
        uint64_t val = 0;
        if (str_to_u64(param, &val)) {
            if (val > 0xFFu) val = 0xFFu;
            max_bus = (uint16_t)val;
        }
    } else {
        char hv[13];
        cpu_get_hypervisor_vendor(hv);
        if (hv[0] != '\0') {
            if (str_eq(hv, "VMwareVMware") || str_eq(hv, "VBoxVBoxVBox")) {
                max_bus = 0x1Fu;
            }
        }
    }
    g_scan_max_bus = max_bus;
    log_printf("PCI: scanning buses 0..%u\n", (unsigned)g_scan_max_bus);
    return g_scan_max_bus;
}

uint32_t pci_read_config32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    outl(PCI_CONFIG_ADDR, pci_addr(bus, slot, func, offset));
    return inl(PCI_CONFIG_DATA);
}

uint16_t pci_read_config16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t v = pci_read_config32(bus, slot, func, offset & 0xFC);
    return (uint16_t)((v >> ((offset & 2) * 8)) & 0xFFFF);
}

uint8_t pci_read_config8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t v = pci_read_config32(bus, slot, func, offset & 0xFC);
    return (uint8_t)((v >> ((offset & 3) * 8)) & 0xFF);
}

void pci_write_config32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    outl(PCI_CONFIG_ADDR, pci_addr(bus, slot, func, offset));
    outl(PCI_CONFIG_DATA, value);
}

void pci_write_config16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t value) {
    uint32_t cur = pci_read_config32(bus, slot, func, offset & 0xFC);
    uint32_t shift = (offset & 2) * 8;
    uint32_t mask = 0xFFFFu << shift;
    uint32_t v = (cur & ~mask) | ((uint32_t)value << shift);
    pci_write_config32(bus, slot, func, offset & 0xFC, v);
}

void pci_write_config8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t value) {
    uint32_t cur = pci_read_config32(bus, slot, func, offset & 0xFC);
    uint32_t shift = (offset & 3) * 8;
    uint32_t mask = 0xFFu << shift;
    uint32_t v = (cur & ~mask) | ((uint32_t)value << shift);
    pci_write_config32(bus, slot, func, offset & 0xFC, v);
}

void pci_enable_bus_mastering(const struct pci_device *dev) {
    uint16_t cmd = pci_read_config16(dev->bus, dev->slot, dev->func, 0x04);
    cmd |= (1u << 2);
    pci_write_config16(dev->bus, dev->slot, dev->func, 0x04, cmd);
}

void pci_enable_io(const struct pci_device *dev) {
    uint16_t cmd = pci_read_config16(dev->bus, dev->slot, dev->func, 0x04);
    cmd |= (1u << 0);
    pci_write_config16(dev->bus, dev->slot, dev->func, 0x04, cmd);
}

void pci_enable_mem(const struct pci_device *dev) {
    uint16_t cmd = pci_read_config16(dev->bus, dev->slot, dev->func, 0x04);
    cmd |= (1u << 1);
    pci_write_config16(dev->bus, dev->slot, dev->func, 0x04, cmd);
}

void pci_register_driver(struct pci_driver *drv) {
    if (!drv) return;
    if (g_driver_count < (uint32_t)(sizeof(g_drivers) / sizeof(g_drivers[0]))) {
        g_drivers[g_driver_count++] = drv;
    }
}

uint32_t pci_device_count(void) {
    return g_device_count;
}

const struct pci_device *pci_device_at(uint32_t index) {
    if (index >= g_device_count) return NULL;
    return &g_devices[index];
}

static int match_driver(const struct pci_driver *drv, const struct pci_device *dev) {
    if (!drv) return 0;
    if (drv->vendor_id != PCI_VENDOR_ANY && drv->vendor_id != dev->vendor_id) return 0;
    if (drv->device_id != PCI_DEVICE_ANY && drv->device_id != dev->device_id) return 0;
    if (drv->class_code != PCI_CLASS_ANY && drv->class_code != dev->class_code) return 0;
    if (drv->subclass != PCI_SUBCLASS_ANY && drv->subclass != dev->subclass) return 0;
    return 1;
}

static int pci_dev_same(const struct pci_device *a, const struct pci_device *b) {
    if (!a || !b) return 0;
    return a->bus == b->bus && a->slot == b->slot && a->func == b->func;
}

static int pci_dev_in_list(const struct pci_device *list, uint32_t count, const struct pci_device *dev) {
    if (!list || !dev) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (pci_dev_same(&list[i], dev)) return 1;
    }
    return 0;
}

static void pci_probe_device(struct pci_device *dev) {
    for (uint32_t i = 0; i < g_driver_count; ++i) {
        struct pci_driver *drv = g_drivers[i];
        if (!match_driver(drv, dev)) continue;
        if (drv->probe) {
            int handled = drv->probe(dev);
            if (handled) {
                log_printf("PCI: driver %s bound to %u:%u.%u\n",
                           drv->name ? drv->name : "(unnamed)",
                           dev->bus, dev->slot, dev->func);
                break;
            }
        }
    }
}

static void pci_read_bars(struct pci_device *dev) {
    for (uint8_t i = 0; i < 6; ++i) {
        dev->bar[i] = 0;
        dev->bar_size[i] = 0;
        dev->bar_hi[i] = 0;
        dev->bar_flags[i] = 0;
    }

    for (uint8_t i = 0; i < 6; ++i) {
        uint8_t off = (uint8_t)(0x10 + (i * 4));
        uint32_t orig = pci_read_config32(dev->bus, dev->slot, dev->func, off);
        dev->bar[i] = orig;

        if (orig == 0) continue;

        pci_write_config32(dev->bus, dev->slot, dev->func, off, 0xFFFFFFFFu);
        uint32_t mask = pci_read_config32(dev->bus, dev->slot, dev->func, off);
        pci_write_config32(dev->bus, dev->slot, dev->func, off, orig);

        if (orig & 0x1u) {
            uint32_t size_mask = mask & ~0x3u;
            if (size_mask) {
                dev->bar_size[i] = (~size_mask) + 1u;
            }
            dev->bar_flags[i] = PCI_BAR_IO;
        } else {
            uint8_t type = (uint8_t)((orig >> 1) & 0x3);
            uint32_t size_mask = mask & ~0xFu;
            if (type == 0x2) {
                uint32_t orig_hi = pci_read_config32(dev->bus, dev->slot, dev->func,
                                                     (uint8_t)(off + 4));
                pci_write_config32(dev->bus, dev->slot, dev->func, (uint8_t)(off + 4), 0xFFFFFFFFu);
                uint32_t mask_hi = pci_read_config32(dev->bus, dev->slot, dev->func,
                                                     (uint8_t)(off + 4));
                pci_write_config32(dev->bus, dev->slot, dev->func, (uint8_t)(off + 4), orig_hi);

                uint64_t size64 = ((uint64_t)mask_hi << 32) | (uint64_t)(size_mask);
                if (size64) {
                    uint64_t sz = (~size64) + 1ull;
                    if (sz > 0xFFFFFFFFu) {
                        dev->bar_size[i] = 0xFFFFFFFFu;
                    } else {
                        dev->bar_size[i] = (uint32_t)sz;
                    }
                }
                dev->bar_hi[i] = orig_hi;
                dev->bar_flags[i] = PCI_BAR_64;
                if (orig & (1u << 3)) dev->bar_flags[i] |= PCI_BAR_PREFETCH;
                i++; /* skip upper BAR */
            } else {
                if (size_mask) {
                    dev->bar_size[i] = (~size_mask) + 1u;
                }
                dev->bar_flags[i] = 0;
                if (orig & (1u << 3)) dev->bar_flags[i] |= PCI_BAR_PREFETCH;
            }
        }
    }
}

static uint8_t pci_find_cap(uint8_t bus, uint8_t slot, uint8_t func, uint8_t cap_id) {
    uint16_t status = pci_read_config16(bus, slot, func, 0x06);
    if ((status & 0x10u) == 0) return 0;
    uint8_t ptr = pci_read_config8(bus, slot, func, 0x34);
    for (uint8_t i = 0; i < 48 && ptr; ++i) {
        uint8_t id = pci_read_config8(bus, slot, func, ptr);
        if (id == cap_id) return ptr;
        ptr = pci_read_config8(bus, slot, func, (uint8_t)(ptr + 1));
    }
    return 0;
}

int pci_msi_enable(const struct pci_device *dev, uint8_t vector, uint8_t apic_id) {
    if (!dev || dev->msi_cap == 0) return 0;
    uint8_t cap = dev->msi_cap;
    uint16_t ctrl = pci_read_config16(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 2));
    uint8_t is_64 = (uint8_t)((ctrl >> 7) & 1u);

    uint32_t msg_addr = 0xFEE00000u | ((uint32_t)apic_id << 12);
    pci_write_config32(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 4), msg_addr);
    if (is_64) {
        pci_write_config32(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 8), 0u);
        pci_write_config16(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 12), vector);
    } else {
        pci_write_config16(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 8), vector);
    }
    ctrl |= 1u;
    pci_write_config16(dev->bus, dev->slot, dev->func, (uint8_t)(cap + 2), ctrl);
    return 1;
}

static void pci_scan_function(uint8_t bus, uint8_t slot, uint8_t func) {
    uint16_t vendor = pci_read_config16(bus, slot, func, 0x00);
    if (vendor == 0xFFFF) return;

    struct pci_device dev;
    dev.bus = bus;
    dev.slot = slot;
    dev.func = func;
    dev.vendor_id = vendor;
    dev.device_id = pci_read_config16(bus, slot, func, 0x02);
    dev.revision = pci_read_config8(bus, slot, func, 0x08);
    dev.prog_if = pci_read_config8(bus, slot, func, 0x09);
    dev.subclass = pci_read_config8(bus, slot, func, 0x0A);
    dev.class_code = pci_read_config8(bus, slot, func, 0x0B);
    dev.header_type = pci_read_config8(bus, slot, func, 0x0E);
    dev.irq_line = pci_read_config8(bus, slot, func, 0x3C);
    dev.irq_pin = pci_read_config8(bus, slot, func, 0x3D);
    dev.msi_cap = pci_find_cap(bus, slot, func, 0x05);
    dev.msi_enabled = 0;
    pci_read_bars(&dev);

    if (g_device_count < (uint32_t)(sizeof(g_devices) / sizeof(g_devices[0]))) {
        g_devices[g_device_count++] = dev;
    }

    if (!g_rescan_active || !pci_dev_in_list(g_old_devices, g_old_count, &dev)) {
        log_printf("PCI %u:%u.%u vendor=0x%x device=0x%x class=%u/%u\n",
                   dev.bus, dev.slot, dev.func,
                   (unsigned)dev.vendor_id, (unsigned)dev.device_id,
                   (unsigned)dev.class_code, (unsigned)dev.subclass);
        if (dev.msi_cap) {
            log_printf("PCI %u:%u.%u MSI cap=0x%x\n",
                       dev.bus, dev.slot, dev.func, (unsigned)dev.msi_cap);
        }
        pci_probe_device(&dev);
    }
}

static void pci_scan_slot(uint8_t bus, uint8_t slot) {
    uint16_t vendor = pci_read_config16(bus, slot, 0, 0x00);
    if (vendor == 0xFFFF) return;
    uint8_t header = pci_read_config8(bus, slot, 0, 0x0E);
    pci_scan_function(bus, slot, 0);
    if (header & 0x80) {
        for (uint8_t func = 1; func < 8; ++func) {
            pci_scan_function(bus, slot, func);
        }
    }
}

int pci_init(void) {
    const char *param = boot_param_get("pci");
    int force_on = (param && (param[0] == '1' || str_eq(param, "on")));
    if (boot_param_has("nopci") || (param && (param[0] == '0' || str_eq(param, "off")))) {
        log_printf("PCI: disabled by boot param\n");
        return 0;
    }
    if (!force_on) {
        char hv[13];
        cpu_get_hypervisor_vendor(hv);
        if (hv[0] != '\0' && (str_eq(hv, "VMwareVMware") || str_eq(hv, "VBoxVBoxVBox"))) {
            log_printf("PCI: disabled on %s (use pci=on to enable)\n", hv);
            return 0;
        }
    }
    uint16_t max_bus = pci_get_max_bus();
    for (uint16_t bus = 0; bus <= max_bus; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            pci_scan_slot((uint8_t)bus, slot);
        }
    }
    return 0;
}

int pci_rescan(void) {
    const char *param = boot_param_get("pci");
    int force_on = (param && (param[0] == '1' || str_eq(param, "on")));
    if (boot_param_has("nopci") || (param && (param[0] == '0' || str_eq(param, "off")))) {
        return 0;
    }
    if (!force_on) {
        char hv[13];
        cpu_get_hypervisor_vendor(hv);
        if (hv[0] != '\0' && (str_eq(hv, "VMwareVMware") || str_eq(hv, "VBoxVBoxVBox"))) {
            return 0;
        }
    }
    if (g_rescan_busy) return 0;
    g_rescan_busy = 1;
    uint32_t old_count = g_device_count;
    for (uint32_t i = 0; i < old_count && i < (uint32_t)(sizeof(g_rescan_old) / sizeof(g_rescan_old[0])); ++i) {
        g_rescan_old[i] = g_devices[i];
    }

    g_device_count = 0;
    g_rescan_active = 1;
    g_old_devices = g_rescan_old;
    g_old_count = old_count;

    uint16_t max_bus = pci_get_max_bus();
    for (uint16_t bus = 0; bus <= max_bus; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            pci_scan_slot((uint8_t)bus, slot);
        }
    }

    g_rescan_active = 0;
    g_old_devices = NULL;
    g_old_count = 0;

    int changes = 0;
    for (uint32_t i = 0; i < g_device_count; ++i) {
        if (!pci_dev_in_list(g_rescan_old, old_count, &g_devices[i])) {
            changes++;
            log_printf("PCI hotplug: added %u:%u.%u vendor=0x%x device=0x%x\n",
                       g_devices[i].bus, g_devices[i].slot, g_devices[i].func,
                       (unsigned)g_devices[i].vendor_id, (unsigned)g_devices[i].device_id);
        }
    }
    for (uint32_t i = 0; i < old_count; ++i) {
        if (!pci_dev_in_list(g_devices, g_device_count, &g_rescan_old[i])) {
            changes++;
            log_printf("PCI hotplug: removed %u:%u.%u vendor=0x%x device=0x%x\n",
                       g_rescan_old[i].bus, g_rescan_old[i].slot, g_rescan_old[i].func,
                       (unsigned)g_rescan_old[i].vendor_id, (unsigned)g_rescan_old[i].device_id);
        }
    }
    g_rescan_busy = 0;
    return changes;
}

int pci_shutdown(void) {
    g_device_count = 0;
    return 1;
}
