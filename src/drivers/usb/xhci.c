#include "drivers/usb/xhci.h"

#include <stdint.h>
#include <stddef.h>

#include "drivers/pci/pci.h"
#include "lib/compat.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/sleep.h"
#include "lib/log.h"

extern void *memset(void *s, int c, size_t n);

#define XHCI_CLASS    0x0Cu
#define XHCI_SUBCLASS 0x03u
#define XHCI_PROGIF   0x30u

#define PCI_BAR_IO  (1u << 0)
#define PCI_BAR_64  (1u << 2)

#define XHCI_USBCMD_RUN   (1u << 0)
#define XHCI_USBCMD_HCRST (1u << 1)

#define XHCI_USBSTS_HCH   (1u << 0)
#define XHCI_USBSTS_CNR   (1u << 11)

#define XHCI_IMAN_IE      (1u << 1)

#define XHCI_OP_USBCMD  0x00
#define XHCI_OP_USBSTS  0x04
#define XHCI_OP_CRCR    0x18
#define XHCI_OP_DCBAAP  0x30
#define XHCI_OP_CONFIG  0x38

#define XHCI_RT_IMAN    0x00
#define XHCI_RT_IMOD    0x04
#define XHCI_RT_ERSTSZ  0x08
#define XHCI_RT_ERSTBA  0x10
#define XHCI_RT_ERDP    0x18

#define XHCI_TRB_TYPE_LINK    6u
#define XHCI_TRB_TYPE_ENABLE_SLOT 9u
#define XHCI_TRB_TYPE_ADDRESS_DEVICE 11u
#define XHCI_TRB_TYPE_CMD_COMPLETE 33u

#define XHCI_PORTSC_CCS   (1u << 0)
#define XHCI_PORTSC_PED   (1u << 1)
#define XHCI_PORTSC_PR    (1u << 4)

struct xhci_trb {
    uint32_t d0;
    uint32_t d1;
    uint32_t d2;
    uint32_t d3;
};

struct xhci_erst_entry {
    uint64_t ring_base;
    uint32_t ring_size;
    uint32_t rsvd;
} __attribute__((packed));

struct xhci_state {
    volatile uint8_t *mmio;
    volatile uint32_t *op;
    volatile uint32_t *rt;
    volatile uint32_t *db;
    uint8_t caplen;
    uint8_t max_ports;
    uint8_t max_slots;
    uint64_t cmd_ring_phys;
    struct xhci_trb *cmd_ring;
    uint64_t erst_phys;
    struct xhci_erst_entry *erst;
    uint64_t ev_ring_phys;
    struct xhci_trb *ev_ring;
    uint64_t dcbaa_phys;
    uint64_t *dcbaa;
    int ready;
    uint32_t cmd_ring_size;
    uint32_t cmd_ring_idx;
    uint8_t cmd_cycle;
    uint32_t ev_ring_size;
    uint32_t ev_ring_idx;
    uint8_t ev_cycle;
    uint8_t ctx_size;
    uint8_t slot_id;
};

static struct xhci_state g_xhci;

static inline void *phys_to_virt(uint64_t phys) {
    return (void *)(uintptr_t)(paging_hhdm_offset() + phys);
}

static uint64_t alloc_page_zero(void **out_virt) {
    uint64_t phys = pmm_alloc_frame();
    if (phys == 0) return 0;
    void *virt = phys_to_virt(phys);
    memset(virt, 0, PMM_PAGE_SIZE);
    if (out_virt) *out_virt = virt;
    return phys;
}

static uint32_t mmio_read32(uint32_t off) {
    return *(volatile uint32_t *)(g_xhci.mmio + off);
}

static void mmio_write32(uint32_t off, uint32_t val) {
    *(volatile uint32_t *)(g_xhci.mmio + off) = val;
}

static void mmio_write64(uint32_t off, uint64_t val) {
    *(volatile uint64_t *)(g_xhci.mmio + off) = val;
}

static void xhci_reset_controller(void) {
    uint32_t usbcmd = mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD));
    usbcmd &= ~XHCI_USBCMD_RUN;
    mmio_write32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD), usbcmd);
    for (int i = 0; i < 1000; ++i) {
        if (mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBSTS)) & XHCI_USBSTS_HCH) break;
        sleep_ms(1);
    }
    usbcmd = mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD));
    usbcmd |= XHCI_USBCMD_HCRST;
    mmio_write32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD), usbcmd);
    for (int i = 0; i < 1000; ++i) {
        if ((mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD)) & XHCI_USBCMD_HCRST) == 0) break;
        sleep_ms(1);
    }
    for (int i = 0; i < 1000; ++i) {
        if ((mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBSTS)) & XHCI_USBSTS_CNR) == 0) break;
        sleep_ms(1);
    }
}

static int xhci_setup_rings(void) {
    g_xhci.cmd_ring_phys = alloc_page_zero((void **)&g_xhci.cmd_ring);
    g_xhci.ev_ring_phys = alloc_page_zero((void **)&g_xhci.ev_ring);
    g_xhci.erst_phys = alloc_page_zero((void **)&g_xhci.erst);
    g_xhci.dcbaa_phys = alloc_page_zero((void **)&g_xhci.dcbaa);
    if (!g_xhci.cmd_ring_phys || !g_xhci.ev_ring_phys || !g_xhci.erst_phys || !g_xhci.dcbaa_phys) {
        log_printf("xHCI: ring allocation failed\n");
        return -1;
    }

    const uint32_t trb_count = (PMM_PAGE_SIZE / sizeof(struct xhci_trb));
    g_xhci.cmd_ring_size = trb_count - 1;
    g_xhci.cmd_ring_idx = 0;
    g_xhci.cmd_cycle = 1;
    g_xhci.cmd_ring[trb_count - 1].d0 = (uint32_t)(g_xhci.cmd_ring_phys & 0xFFFFFFFFu);
    g_xhci.cmd_ring[trb_count - 1].d1 = (uint32_t)(g_xhci.cmd_ring_phys >> 32);
    g_xhci.cmd_ring[trb_count - 1].d2 = 0;
    g_xhci.cmd_ring[trb_count - 1].d3 = (XHCI_TRB_TYPE_LINK << 10) | (1u << 1);

    g_xhci.erst[0].ring_base = g_xhci.ev_ring_phys;
    g_xhci.erst[0].ring_size = trb_count;
    g_xhci.erst[0].rsvd = 0;

    g_xhci.ev_ring_size = trb_count;
    g_xhci.ev_ring_idx = 0;
    g_xhci.ev_cycle = 1;

    mmio_write64((uint32_t)(g_xhci.caplen + XHCI_OP_DCBAAP), g_xhci.dcbaa_phys);
    mmio_write64((uint32_t)(g_xhci.caplen + XHCI_OP_CRCR), g_xhci.cmd_ring_phys | 1u);

    volatile uint8_t *ir0 = (volatile uint8_t *)g_xhci.rt + 0x20;
    *(volatile uint32_t *)(ir0 + XHCI_RT_ERSTSZ) = 1;
    *(volatile uint64_t *)(ir0 + XHCI_RT_ERSTBA) = g_xhci.erst_phys;
    *(volatile uint64_t *)(ir0 + XHCI_RT_ERDP) = g_xhci.ev_ring_phys;
    *(volatile uint32_t *)(ir0 + XHCI_RT_IMAN) = XHCI_IMAN_IE;

    return 0;
}

static void xhci_ring_doorbell(uint8_t target) {
    g_xhci.db[0] = target;
}

static void xhci_cmd_submit(uint32_t d0, uint32_t d1, uint32_t d2, uint32_t type) {
    uint32_t idx = g_xhci.cmd_ring_idx;
    struct xhci_trb *trb = &g_xhci.cmd_ring[idx];
    trb->d0 = d0;
    trb->d1 = d1;
    trb->d2 = d2;
    trb->d3 = (type << 10) | (g_xhci.cmd_cycle & 1u);
    idx++;
    if (idx >= g_xhci.cmd_ring_size) {
        idx = 0;
        g_xhci.cmd_cycle ^= 1u;
    }
    g_xhci.cmd_ring_idx = idx;
    xhci_ring_doorbell(0);
}

static int xhci_poll_cmd_complete(uint32_t *out_d0, uint32_t *out_d1, uint32_t *out_d2, uint32_t *out_d3) {
    for (int attempt = 0; attempt < 500; ++attempt) {
        struct xhci_trb *trb = &g_xhci.ev_ring[g_xhci.ev_ring_idx];
        uint32_t cycle = trb->d3 & 1u;
        if (cycle != (uint32_t)g_xhci.ev_cycle) {
            sleep_ms(1);
            continue;
        }
        uint32_t type = (trb->d3 >> 10) & 0x3Fu;
        if (type == XHCI_TRB_TYPE_CMD_COMPLETE) {
            if (out_d0) *out_d0 = trb->d0;
            if (out_d1) *out_d1 = trb->d1;
            if (out_d2) *out_d2 = trb->d2;
            if (out_d3) *out_d3 = trb->d3;
        }
        g_xhci.ev_ring_idx++;
        if (g_xhci.ev_ring_idx >= g_xhci.ev_ring_size) {
            g_xhci.ev_ring_idx = 0;
            g_xhci.ev_cycle ^= 1u;
        }
        return (type == XHCI_TRB_TYPE_CMD_COMPLETE) ? 0 : -1;
    }
    return -1;
}

static void xhci_enable_slot(void) {
    log_printf("xHCI: issuing Enable Slot\n");
    xhci_cmd_submit(0, 0, 0, XHCI_TRB_TYPE_ENABLE_SLOT);
    uint32_t d0 = 0, d1 = 0, d2 = 0, d3 = 0;
    if (xhci_poll_cmd_complete(&d0, &d1, &d2, &d3) == 0) {
        uint8_t slot_id = (uint8_t)(d3 >> 24);
        uint8_t cc = (uint8_t)(d2 >> 24);
        log_printf("xHCI: Enable Slot complete slot=%u cc=%u\n", (unsigned)slot_id, (unsigned)cc);
        if (cc == 1) {
            g_xhci.slot_id = slot_id;
        }
    } else {
        log_printf("xHCI: Enable Slot timeout\n");
    }
}

static uint16_t xhci_port_max_packet(uint8_t speed) {
    switch (speed) {
        case 1: return 8;
        case 2: return 64;
        case 3: return 8;
        case 4: return 512;
        default: return 64;
    }
}

static inline uint32_t *xhci_ctx_ptr(void *ctx, uint32_t index) {
    return (uint32_t *)((uint8_t *)ctx + (index * g_xhci.ctx_size));
}

static int xhci_address_device(uint8_t port_id, uint8_t speed) {
    if (g_xhci.slot_id == 0) return -1;

    void *input_ctx = NULL;
    void *dev_ctx = NULL;
    void *ep0_ring = NULL;
    uint64_t input_ctx_phys = alloc_page_zero(&input_ctx);
    uint64_t dev_ctx_phys = alloc_page_zero(&dev_ctx);
    uint64_t ep0_ring_phys = alloc_page_zero(&ep0_ring);
    if (!input_ctx_phys || !dev_ctx_phys || !ep0_ring_phys) {
        log_printf("xHCI: Address Device alloc failed\n");
        return -1;
    }

    const uint32_t trb_count = (PMM_PAGE_SIZE / sizeof(struct xhci_trb));
    struct xhci_trb *ring = (struct xhci_trb *)ep0_ring;
    ring[trb_count - 1].d0 = (uint32_t)(ep0_ring_phys & 0xFFFFFFFFu);
    ring[trb_count - 1].d1 = (uint32_t)(ep0_ring_phys >> 32);
    ring[trb_count - 1].d2 = 0;
    ring[trb_count - 1].d3 = (XHCI_TRB_TYPE_LINK << 10) | (1u << 1);

    uint32_t *control = xhci_ctx_ptr(input_ctx, 0);
    control[0] = 0;
    control[1] = (1u << 0) | (1u << 1);

    uint32_t *slot = xhci_ctx_ptr(input_ctx, 1);
    slot[0] = 0;
    slot[1] = (1u << 27) | ((uint32_t)port_id << 16) | ((uint32_t)speed << 20);
    slot[2] = 0;
    slot[3] = 0;

    uint16_t mps = xhci_port_max_packet(speed);
    uint32_t *ep0 = xhci_ctx_ptr(input_ctx, 2);
    ep0[0] = 0;
    ep0[1] = (uint32_t)mps << 16 | 4u;
    uint64_t dq = ep0_ring_phys | 1u;
    ep0[2] = (uint32_t)(dq & 0xFFFFFFFFu);
    ep0[3] = (uint32_t)(dq >> 32);

    g_xhci.dcbaa[g_xhci.slot_id] = dev_ctx_phys;

    log_printf("xHCI: issuing Address Device slot=%u port=%u speed=%u\n",
               (unsigned)g_xhci.slot_id, (unsigned)port_id, (unsigned)speed);
    xhci_cmd_submit((uint32_t)(input_ctx_phys & 0xFFFFFFFFu),
                    (uint32_t)(input_ctx_phys >> 32),
                    (uint32_t)g_xhci.slot_id,
                    XHCI_TRB_TYPE_ADDRESS_DEVICE);
    uint32_t d0 = 0, d1 = 0, d2 = 0, d3 = 0;
    if (xhci_poll_cmd_complete(&d0, &d1, &d2, &d3) == 0) {
        uint8_t cc = (uint8_t)(d2 >> 24);
        log_printf("xHCI: Address Device complete cc=%u\n", (unsigned)cc);
        return (cc == 1) ? 0 : -1;
    }
    log_printf("xHCI: Address Device timeout\n");
    return -1;
}

static int xhci_port_reset(uint8_t port_index) {
    volatile uint32_t *port = g_xhci.op + 0x100;
    volatile uint32_t *portsc = &port[port_index * 4 + 0];
    uint32_t v = *portsc;
    if ((v & XHCI_PORTSC_CCS) == 0) return 0;
    *portsc = v | XHCI_PORTSC_PR;
    for (int i = 0; i < 200; ++i) {
        v = *portsc;
        if ((v & XHCI_PORTSC_PR) == 0) break;
        sleep_ms(1);
    }
    v = *portsc;
    if ((v & XHCI_PORTSC_PED) == 0) return -1;
    return 1;
}

static void xhci_log_ports(void) {
    volatile uint32_t *port = g_xhci.op + 0x100;
    for (uint8_t i = 0; i < g_xhci.max_ports; ++i) {
        uint32_t portsc = port[i * 4 + 0];
        uint8_t ccs = (uint8_t)(portsc & 1u);
        uint8_t speed = (uint8_t)((portsc >> 10) & 0xFu);
        log_printf("xHCI: port %u status=0x%x ccs=%u speed=%u\n",
                   (unsigned)(i + 1), (unsigned)portsc, (unsigned)ccs, (unsigned)speed);
    }
}

static int xhci_probe(const struct pci_device *dev) {
    if (!dev) return -1;
    uint64_t bar0 = dev->bar[0];
    if ((dev->bar_flags[0] & PCI_BAR_IO) != 0) {
        log_printf("xHCI: BAR0 is IO, not MMIO\n");
        return -1;
    }
    if ((dev->bar_flags[0] & PCI_BAR_64) != 0) {
        bar0 |= ((uint64_t)dev->bar_hi[0] << 32);
    }
    if ((bar0 & ~0xFULL) == 0) {
        log_printf("xHCI: BAR0 missing\n");
        return -1;
    }
    pci_enable_mem(dev);
    pci_enable_bus_mastering(dev);

    g_xhci.mmio = (volatile uint8_t *)(uintptr_t)(paging_hhdm_offset() + (bar0 & ~0xFULL));
    g_xhci.caplen = (uint8_t)mmio_read32(0x00);
    uint32_t hcs1 = mmio_read32(0x04);
    uint32_t dboff = mmio_read32(0x14);
    uint32_t rtsoff = mmio_read32(0x18);
    uint32_t hcc1 = mmio_read32(0x10);

    g_xhci.max_slots = (uint8_t)(hcs1 & 0xFFu);
    g_xhci.max_ports = (uint8_t)((hcs1 >> 24) & 0xFFu);
    g_xhci.ctx_size = (hcc1 & (1u << 2)) ? 64 : 32;

    g_xhci.op = (volatile uint32_t *)(g_xhci.mmio + g_xhci.caplen);
    g_xhci.db = (volatile uint32_t *)(g_xhci.mmio + (dboff & ~0x3u));
    g_xhci.rt = (volatile uint32_t *)(g_xhci.mmio + (rtsoff & ~0x1Fu));

    log_printf("xHCI: found ctrl slots=%u ports=%u caplen=%u\n",
               (unsigned)g_xhci.max_slots, (unsigned)g_xhci.max_ports, (unsigned)g_xhci.caplen);

    xhci_reset_controller();
    if (xhci_setup_rings() != 0) return -1;

    mmio_write32((uint32_t)(g_xhci.caplen + XHCI_OP_CONFIG), g_xhci.max_slots);
    mmio_write32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD),
                 mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBCMD)) | XHCI_USBCMD_RUN);
    for (int i = 0; i < 1000; ++i) {
        if ((mmio_read32((uint32_t)(g_xhci.caplen + XHCI_OP_USBSTS)) & XHCI_USBSTS_HCH) == 0) break;
        sleep_ms(1);
    }

    xhci_log_ports();
    int any_port = 0;
    uint8_t first_port_id = 0;
    uint8_t first_speed = 0;
    for (uint8_t i = 0; i < g_xhci.max_ports; ++i) {
        int rc = xhci_port_reset(i);
        if (rc > 0) {
            log_printf("xHCI: port %u reset ok\n", (unsigned)(i + 1));
            any_port = 1;
            if (first_port_id == 0) {
                volatile uint32_t *port = g_xhci.op + 0x100;
                uint32_t portsc = port[i * 4 + 0];
                first_port_id = (uint8_t)(i + 1);
                first_speed = (uint8_t)((portsc >> 10) & 0xFu);
            }
        } else if (rc < 0) {
            log_printf("xHCI: port %u reset failed\n", (unsigned)(i + 1));
        }
    }
    if (any_port) {
        xhci_enable_slot();
        if (g_xhci.slot_id != 0 && first_port_id != 0) {
            xhci_address_device(first_port_id, first_speed);
        }
    }
    g_xhci.ready = 1;
    return 0;
}

int xhci_init(void) {
    g_xhci.ready = 0;
    static struct pci_driver drv = {
        .vendor_id = PCI_VENDOR_ANY,
        .device_id = PCI_DEVICE_ANY,
        .class_code = XHCI_CLASS,
        .subclass = XHCI_SUBCLASS,
        .name = "xhci",
        .probe = xhci_probe
    };
    pci_register_driver(&drv);
    return 0;
}

int xhci_is_ready(void) {
    return g_xhci.ready;
}
