#include "drivers/net/pcnet.h"

#include <stdint.h>

#include "arch/x86_64/io.h"
#include "drivers/pci/pci.h"
#include "lib/log.h"

#define PCNET_VENDOR_ID 0x1022
#define PCNET_DEVICE_ID 0x2000
#define PCNET_DEVICE_ID_III 0x2001

#define PCNET_PORT_RDP   0x10
#define PCNET_PORT_RAP   0x12
#define PCNET_PORT_RESET 0x14
#define PCNET_PORT_BDP   0x16

#define PCNET_CSR0_STOP  (1u << 2)

static int g_pcnet_found = 0;
static int g_pcnet_error = 0;
static uint16_t g_pcnet_io = 0;
static uint8_t g_pcnet_irq = 0;
static uint8_t g_pcnet_mac[6];

static inline void pcnet_write_rap(uint16_t io_base, uint16_t reg) {
    outw((uint16_t)(io_base + PCNET_PORT_RAP), reg);
}

static inline uint16_t pcnet_read_csr(uint16_t io_base, uint16_t reg) {
    pcnet_write_rap(io_base, reg);
    return inw((uint16_t)(io_base + PCNET_PORT_RDP));
}

static inline void pcnet_write_csr(uint16_t io_base, uint16_t reg, uint16_t val) {
    pcnet_write_rap(io_base, reg);
    outw((uint16_t)(io_base + PCNET_PORT_RDP), val);
}

static inline void pcnet_reset(uint16_t io_base) {
    (void)inw((uint16_t)(io_base + PCNET_PORT_RESET));
}

static void pcnet_read_mac(uint16_t io_base, uint8_t mac[6]) {
    for (uint8_t i = 0; i < 6; ++i) {
        mac[i] = inb((uint16_t)(io_base + i));
    }
}

static int pcnet_probe(const struct pci_device *dev) {
    if (!dev) return 0;
    if (dev->vendor_id != PCNET_VENDOR_ID) return 0;
    if (dev->device_id != PCNET_DEVICE_ID && dev->device_id != PCNET_DEVICE_ID_III) return 0;
    g_pcnet_found = 1;

    uint32_t bar0 = dev->bar[0];
    if ((bar0 & 0x1) == 0) {
        log_printf("PCNet: BAR0 not I/O space, skipping\n");
        g_pcnet_error = 1;
        return 0;
    }

    uint16_t io_base = (uint16_t)(bar0 & ~0x3u);
    pci_enable_io(dev);
    pci_enable_bus_mastering(dev);

    pcnet_reset(io_base);
    pcnet_write_csr(io_base, 0, PCNET_CSR0_STOP);

    pcnet_read_mac(io_base, g_pcnet_mac);
    g_pcnet_io = io_base;
    g_pcnet_irq = dev->irq_line;
    log_printf("PCNet: io=0x%x irq=%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned)io_base, (unsigned)dev->irq_line,
               g_pcnet_mac[0], g_pcnet_mac[1], g_pcnet_mac[2],
               g_pcnet_mac[3], g_pcnet_mac[4], g_pcnet_mac[5]);

    return 1;
}

void pcnet_init(void) {
    static struct pci_driver pcnet_driver = {
        .vendor_id = PCNET_VENDOR_ID,
        .device_id = PCI_DEVICE_ANY,
        .class_code = 0x02,
        .subclass = 0x00,
        .probe = pcnet_probe
    };
    pci_register_driver(&pcnet_driver);
}

void pcnet_log_status(void) {
    if (!g_pcnet_found) {
        log_printf("PCNet: not found\n");
        return;
    }
    if (g_pcnet_error) {
        log_printf("PCNet: found, init failed (BAR0 not I/O)\n");
        return;
    }
    log_printf("PCNet: io=0x%x irq=%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned)g_pcnet_io, (unsigned)g_pcnet_irq,
               g_pcnet_mac[0], g_pcnet_mac[1], g_pcnet_mac[2],
               g_pcnet_mac[3], g_pcnet_mac[4], g_pcnet_mac[5]);
}
