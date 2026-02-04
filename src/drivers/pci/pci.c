#include "drivers/pci/pci.h"

#include "arch/x86_64/io.h"
#include "lib/log.h"

#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

static struct pci_driver *g_drivers[32];
static uint32_t g_driver_count = 0;

static inline uint32_t pci_addr(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    return (1u << 31) | ((uint32_t)bus << 16) | ((uint32_t)slot << 11) |
           ((uint32_t)func << 8) | (offset & 0xFC);
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

static int match_driver(const struct pci_driver *drv, const struct pci_device *dev) {
    if (!drv) return 0;
    if (drv->vendor_id != PCI_VENDOR_ANY && drv->vendor_id != dev->vendor_id) return 0;
    if (drv->device_id != PCI_DEVICE_ANY && drv->device_id != dev->device_id) return 0;
    if (drv->class_code != PCI_CLASS_ANY && drv->class_code != dev->class_code) return 0;
    if (drv->subclass != PCI_SUBCLASS_ANY && drv->subclass != dev->subclass) return 0;
    return 1;
}

static void pci_probe_device(struct pci_device *dev) {
    for (uint32_t i = 0; i < g_driver_count; ++i) {
        struct pci_driver *drv = g_drivers[i];
        if (!match_driver(drv, dev)) continue;
        if (drv->probe && drv->probe(dev)) break;
    }
}

static void pci_read_bars(struct pci_device *dev) {
    for (uint8_t i = 0; i < 6; ++i) {
        dev->bar[i] = pci_read_config32(dev->bus, dev->slot, dev->func, 0x10 + (uint8_t)(i * 4));
    }
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
    pci_read_bars(&dev);

    log_printf("PCI %u:%u.%u vendor=0x%x device=0x%x class=%u/%u\n",
               dev.bus, dev.slot, dev.func,
               (unsigned)dev.vendor_id, (unsigned)dev.device_id,
               (unsigned)dev.class_code, (unsigned)dev.subclass);

    pci_probe_device(&dev);
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

void pci_init(void) {
    for (uint16_t bus = 0; bus < 256; ++bus) {
        for (uint8_t slot = 0; slot < 32; ++slot) {
            pci_scan_slot((uint8_t)bus, slot);
        }
    }
}
