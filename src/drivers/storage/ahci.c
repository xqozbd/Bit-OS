#include "drivers/storage/ahci.h"

#include <stddef.h>
#include <stdint.h>

#include "drivers/pci/pci.h"
#include "kernel/block.h"
#include "kernel/pmm.h"
#include "arch/x86_64/paging.h"
#include "lib/log.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);
extern void *memset(void *s, int c, size_t n);

#define AHCI_CLASS 0x01
#define AHCI_SUBCLASS 0x06
#define AHCI_PROGIF 0x01

#define HBA_GHC_HR   (1u << 0)
#define HBA_GHC_IE   (1u << 1)
#define HBA_GHC_AE   (1u << 31)

#define PORT_CMD_ST  (1u << 0)
#define PORT_CMD_FRE (1u << 4)
#define PORT_CMD_FR  (1u << 14)
#define PORT_CMD_CR  (1u << 15)

#define PORT_TFD_BSY (1u << 7)
#define PORT_TFD_DRQ (1u << 3)

#define FIS_TYPE_REG_H2D 0x27

#define ATA_CMD_IDENTIFY 0xEC
#define ATA_CMD_READ_DMA_EXT 0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35

struct hba_port {
    volatile uint32_t clb;
    volatile uint32_t clbu;
    volatile uint32_t fb;
    volatile uint32_t fbu;
    volatile uint32_t is;
    volatile uint32_t ie;
    volatile uint32_t cmd;
    volatile uint32_t rsv0;
    volatile uint32_t tfd;
    volatile uint32_t sig;
    volatile uint32_t ssts;
    volatile uint32_t sctl;
    volatile uint32_t serr;
    volatile uint32_t sact;
    volatile uint32_t ci;
    volatile uint32_t sntf;
    volatile uint32_t fbs;
    volatile uint32_t rsv1[11];
    volatile uint32_t vendor[4];
};

struct hba_mem {
    volatile uint32_t cap;
    volatile uint32_t ghc;
    volatile uint32_t is;
    volatile uint32_t pi;
    volatile uint32_t vs;
    volatile uint32_t ccc_ctl;
    volatile uint32_t ccc_pts;
    volatile uint32_t em_loc;
    volatile uint32_t em_ctl;
    volatile uint32_t cap2;
    volatile uint32_t bohc;
    volatile uint8_t rsv[0xA0 - 0x2C];
    volatile uint8_t vendor[0x100 - 0xA0];
    struct hba_port ports[32];
};

struct hba_cmd_header {
    uint16_t flags;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t rsv[4];
};

struct hba_prdt_entry {
    uint32_t dba;
    uint32_t dbau;
    uint32_t rsv0;
    uint32_t dbc;
};

struct hba_cmd_tbl {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t rsv[48];
    struct hba_prdt_entry prdt[1];
};

struct fis_reg_h2d {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 3;
    uint8_t c : 1;
    uint8_t command;
    uint8_t featurel;

    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;

    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t featureh;

    uint8_t countl;
    uint8_t counth;
    uint8_t icc;
    uint8_t control;

    uint8_t rsv1[4];
};

struct ahci_port_ctx {
    volatile struct hba_port *port;
    struct hba_cmd_header *cmd_list;
    struct hba_cmd_tbl *cmd_tbl;
    uint64_t cmd_list_phys;
    uint64_t fis_phys;
    uint64_t cmd_tbl_phys;
    uint64_t bounce_phys;
    void *bounce_virt;
    uint64_t sector_count;
};

static struct hba_mem *g_hba = NULL;
static struct ahci_port_ctx g_port_ctx;
static int g_has_device = 0;

static inline void *phys_to_virt(uint64_t phys) {
    return (void *)(uintptr_t)(paging_hhdm_offset() + phys);
}

static void port_stop(volatile struct hba_port *p) {
    p->cmd &= ~(PORT_CMD_ST | PORT_CMD_FRE);
    while (p->cmd & (PORT_CMD_FR | PORT_CMD_CR)) {
        /* wait */
    }
}

static void port_start(volatile struct hba_port *p) {
    while (p->cmd & PORT_CMD_CR) {
    }
    p->cmd |= PORT_CMD_FRE;
    p->cmd |= PORT_CMD_ST;
}

static int port_wait_ready(volatile struct hba_port *p) {
    for (uint32_t i = 0; i < 1000000; ++i) {
        uint32_t tfd = p->tfd;
        if ((tfd & (PORT_TFD_BSY | PORT_TFD_DRQ)) == 0) return 0;
    }
    return -1;
}

static int ahci_issue_cmd(struct ahci_port_ctx *ctx, struct fis_reg_h2d *fis, uint32_t bytes, int write) {
    volatile struct hba_port *p = ctx->port;
    if (!p) return -1;
    if (port_wait_ready(p) != 0) return -1;

    struct hba_cmd_header *hdr = &ctx->cmd_list[0];
    memset(hdr, 0, sizeof(*hdr));
    hdr->flags = (uint16_t)(5 | (write ? (1u << 6) : 0));
    hdr->prdtl = 1;
    hdr->ctba = (uint32_t)ctx->cmd_tbl_phys;
    hdr->ctbau = (uint32_t)(ctx->cmd_tbl_phys >> 32);

    struct hba_cmd_tbl *tbl = ctx->cmd_tbl;
    memset(tbl, 0, sizeof(*tbl));
    memcpy(tbl->cfis, fis, sizeof(*fis));
    tbl->prdt[0].dba = (uint32_t)ctx->bounce_phys;
    tbl->prdt[0].dbau = (uint32_t)(ctx->bounce_phys >> 32);
    tbl->prdt[0].dbc = (bytes - 1) | (1u << 31);

    p->is = 0xFFFFFFFFu;
    p->ci = 1u;

    for (uint32_t i = 0; i < 1000000; ++i) {
        if ((p->ci & 1u) == 0) break;
    }
    if (p->ci & 1u) return -1;
    if (p->is & (1u << 30)) return -1;
    return 0;
}

static int ahci_identify(struct ahci_port_ctx *ctx, uint16_t out[256]) {
    struct fis_reg_h2d fis;
    memset(&fis, 0, sizeof(fis));
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.c = 1;
    fis.command = ATA_CMD_IDENTIFY;
    fis.device = 0;
    if (ahci_issue_cmd(ctx, &fis, 512, 0) != 0) return -1;
    memcpy(out, ctx->bounce_virt, 512);
    return 0;
}

static int ahci_read_sector(struct ahci_port_ctx *ctx, uint64_t lba, void *buf) {
    struct fis_reg_h2d fis;
    memset(&fis, 0, sizeof(fis));
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.c = 1;
    fis.command = ATA_CMD_READ_DMA_EXT;
    fis.lba0 = (uint8_t)(lba & 0xFF);
    fis.lba1 = (uint8_t)((lba >> 8) & 0xFF);
    fis.lba2 = (uint8_t)((lba >> 16) & 0xFF);
    fis.lba3 = (uint8_t)((lba >> 24) & 0xFF);
    fis.lba4 = (uint8_t)((lba >> 32) & 0xFF);
    fis.lba5 = (uint8_t)((lba >> 40) & 0xFF);
    fis.device = 1u << 6;
    fis.countl = 1;

    if (ahci_issue_cmd(ctx, &fis, 512, 0) != 0) return -1;
    memcpy(buf, ctx->bounce_virt, 512);
    return 0;
}

static int ahci_write_sector(struct ahci_port_ctx *ctx, uint64_t lba, const void *buf) {
    memcpy(ctx->bounce_virt, buf, 512);

    struct fis_reg_h2d fis;
    memset(&fis, 0, sizeof(fis));
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.c = 1;
    fis.command = ATA_CMD_WRITE_DMA_EXT;
    fis.lba0 = (uint8_t)(lba & 0xFF);
    fis.lba1 = (uint8_t)((lba >> 8) & 0xFF);
    fis.lba2 = (uint8_t)((lba >> 16) & 0xFF);
    fis.lba3 = (uint8_t)((lba >> 24) & 0xFF);
    fis.lba4 = (uint8_t)((lba >> 32) & 0xFF);
    fis.lba5 = (uint8_t)((lba >> 40) & 0xFF);
    fis.device = 1u << 6;
    fis.countl = 1;

    if (ahci_issue_cmd(ctx, &fis, 512, 1) != 0) return -1;
    return 0;
}

static int ahci_block_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    struct ahci_port_ctx *port = (struct ahci_port_ctx *)ctx;
    if (!port || !buf || count == 0) return -1;
    if (lba + count > port->sector_count) return -1;

    uint8_t *dst = (uint8_t *)buf;
    for (uint32_t i = 0; i < count; ++i) {
        if (ahci_read_sector(port, lba + i, dst) != 0) return -1;
        dst += 512;
    }
    return 0;
}

static int ahci_block_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    struct ahci_port_ctx *port = (struct ahci_port_ctx *)ctx;
    if (!port || !buf || count == 0) return -1;
    if (lba + count > port->sector_count) return -1;

    const uint8_t *src = (const uint8_t *)buf;
    for (uint32_t i = 0; i < count; ++i) {
        if (ahci_write_sector(port, lba + i, src) != 0) return -1;
        src += 512;
    }
    return 0;
}

static int ahci_init_port(uint32_t port_index) {
    volatile struct hba_port *p = &g_hba->ports[port_index];
    uint32_t ssts = p->ssts;
    uint8_t det = (uint8_t)(ssts & 0x0F);
    uint8_t ipm = (uint8_t)((ssts >> 8) & 0x0F);
    if (det != 3 || ipm != 1) return -1;
    if (p->sig != 0x00000101u) return -1;

    port_stop(p);

    uint64_t clb_phys = pmm_alloc_frame();
    uint64_t fis_phys = pmm_alloc_frame();
    uint64_t tbl_phys = pmm_alloc_frame();
    uint64_t bounce_phys = pmm_alloc_frame();
    if (!clb_phys || !fis_phys || !tbl_phys || !bounce_phys) return -1;

    p->clb = (uint32_t)clb_phys;
    p->clbu = (uint32_t)(clb_phys >> 32);
    p->fb = (uint32_t)fis_phys;
    p->fbu = (uint32_t)(fis_phys >> 32);

    memset(phys_to_virt(clb_phys), 0, 1024);
    memset(phys_to_virt(fis_phys), 0, 256);
    memset(phys_to_virt(tbl_phys), 0, 256);
    memset(phys_to_virt(bounce_phys), 0, 512);

    port_start(p);

    g_port_ctx.port = p;
    g_port_ctx.cmd_list = (struct hba_cmd_header *)phys_to_virt(clb_phys);
    g_port_ctx.cmd_tbl = (struct hba_cmd_tbl *)phys_to_virt(tbl_phys);
    g_port_ctx.cmd_list_phys = clb_phys;
    g_port_ctx.fis_phys = fis_phys;
    g_port_ctx.cmd_tbl_phys = tbl_phys;
    g_port_ctx.bounce_phys = bounce_phys;
    g_port_ctx.bounce_virt = phys_to_virt(bounce_phys);

    uint16_t ident[256];
    memset(ident, 0, sizeof(ident));
    if (ahci_identify(&g_port_ctx, ident) != 0) {
        log_printf("AHCI: identify failed on port %u\n", port_index);
        return -1;
    }

    uint64_t sectors = ((uint64_t)ident[103] << 48) | ((uint64_t)ident[102] << 32) |
                       ((uint64_t)ident[101] << 16) | (uint64_t)ident[100];
    if (sectors == 0) {
        sectors = ((uint64_t)ident[61] << 16) | (uint64_t)ident[60];
    }
    if (sectors == 0) {
        log_printf("AHCI: no usable LBA count\n");
        return -1;
    }
    g_port_ctx.sector_count = sectors;

    struct block_device bdev;
    bdev.name = "ahci0";
    bdev.sector_count = sectors;
    bdev.sector_size = 512;
    bdev.read = ahci_block_read;
    bdev.write = ahci_block_write;
    bdev.ctx = &g_port_ctx;
    block_register(&bdev);

    log_printf("AHCI: port %u ready sectors=%u\n", port_index, (unsigned)sectors);
    return 0;
}

static int ahci_probe(const struct pci_device *dev) {
    if (dev->class_code != AHCI_CLASS || dev->subclass != AHCI_SUBCLASS) return 0;
    if (dev->prog_if != AHCI_PROGIF) return 0;

    uint64_t bar5 = (uint64_t)dev->bar[5];
    if (bar5 == 0) {
        log_printf("AHCI: missing BAR5\n");
        return 0;
    }

    pci_enable_bus_mastering(dev);
    pci_enable_mem(dev);

    g_hba = (struct hba_mem *)phys_to_virt(bar5 & ~0xFULL);
    g_hba->ghc |= HBA_GHC_AE;
    g_hba->ghc |= HBA_GHC_IE;

    uint32_t pi = g_hba->pi;
    for (uint32_t i = 0; i < 32; ++i) {
        if (pi & (1u << i)) {
            if (ahci_init_port(i) == 0) {
                g_has_device = 1;
                return 1;
            }
        }
    }
    return 0;
}

static struct pci_driver g_ahci_driver = {
    .vendor_id = PCI_VENDOR_ANY,
    .device_id = PCI_DEVICE_ANY,
    .class_code = AHCI_CLASS,
    .subclass = AHCI_SUBCLASS,
    .name = "ahci",
    .probe = ahci_probe
};

void ahci_init(void) {
    g_has_device = 0;
    g_hba = NULL;
    memset(&g_port_ctx, 0, sizeof(g_port_ctx));
    pci_register_driver(&g_ahci_driver);
}

int ahci_has_device(void) {
    return g_has_device;
}
