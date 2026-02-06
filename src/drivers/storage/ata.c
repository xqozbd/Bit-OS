#include "drivers/storage/ata.h"

#include <stddef.h>
#include <stdint.h>

#include "arch/x86_64/io.h"
#include "kernel/block.h"
#include "lib/log.h"

extern void *memset(void *s, int c, size_t n);

#define ATA_PRIMARY_IO  0x1F0
#define ATA_PRIMARY_CTL 0x3F6
#define ATA_SECONDARY_IO  0x170
#define ATA_SECONDARY_CTL 0x376

#define ATA_REG_DATA       0
#define ATA_REG_ERROR      1
#define ATA_REG_FEATURES   1
#define ATA_REG_SECCOUNT0  2
#define ATA_REG_LBA0       3
#define ATA_REG_LBA1       4
#define ATA_REG_LBA2       5
#define ATA_REG_HDDEVSEL   6
#define ATA_REG_COMMAND    7
#define ATA_REG_STATUS     7

#define ATA_CMD_IDENTIFY   0xEC
#define ATA_CMD_READ_PIO   0x20
#define ATA_CMD_WRITE_PIO  0x30
#define ATA_CMD_CACHE_FLUSH 0xE7

#define ATA_SR_BSY  0x80
#define ATA_SR_DRDY 0x40
#define ATA_SR_DRQ  0x08
#define ATA_SR_ERR  0x01

struct ata_device {
    uint16_t io;
    uint16_t ctl;
    uint8_t slave;
    uint32_t sectors28;
};

static struct ata_device g_ata_devs[4];
static size_t g_ata_count = 0;

static void ata_io_wait(uint16_t ctl) {
    (void)ctl;
    inb(0x80);
    inb(0x80);
    inb(0x80);
    inb(0x80);
}

static int ata_wait_bsy(uint16_t io) {
    for (uint32_t i = 0; i < 100000; ++i) {
        if ((inb(io + ATA_REG_STATUS) & ATA_SR_BSY) == 0) return 0;
    }
    return -1;
}

static int ata_wait_drq(uint16_t io) {
    for (uint32_t i = 0; i < 100000; ++i) {
        uint8_t st = inb(io + ATA_REG_STATUS);
        if (st & ATA_SR_ERR) return -1;
        if ((st & ATA_SR_BSY) == 0 && (st & ATA_SR_DRQ)) return 0;
    }
    return -1;
}

static void ata_select(uint16_t io, uint8_t slave, uint32_t lba) {
    outb(io + ATA_REG_HDDEVSEL, (uint8_t)(0xE0 | (slave ? 0x10 : 0x00) | ((lba >> 24) & 0x0F)));
    ata_io_wait(io);
}

static int ata_pio_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    struct ata_device *dev = (struct ata_device *)ctx;
    if (!dev || !buf || count == 0) return -1;
    if (lba + count > dev->sectors28) return -1;

    uint8_t *dst = (uint8_t *)buf;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t l = (uint32_t)(lba + i);
        ata_select(dev->io, dev->slave, l);
        outb(dev->io + ATA_REG_SECCOUNT0, 1);
        outb(dev->io + ATA_REG_LBA0, (uint8_t)(l & 0xFF));
        outb(dev->io + ATA_REG_LBA1, (uint8_t)((l >> 8) & 0xFF));
        outb(dev->io + ATA_REG_LBA2, (uint8_t)((l >> 16) & 0xFF));
        outb(dev->io + ATA_REG_COMMAND, ATA_CMD_READ_PIO);
        if (ata_wait_bsy(dev->io) != 0) return -1;
        if (ata_wait_drq(dev->io) != 0) return -1;
        for (uint32_t w = 0; w < 256; ++w) {
            uint16_t data = inw(dev->io + ATA_REG_DATA);
            dst[w * 2] = (uint8_t)(data & 0xFF);
            dst[w * 2 + 1] = (uint8_t)(data >> 8);
        }
        dst += 512;
    }
    return 0;
}

static int ata_pio_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    struct ata_device *dev = (struct ata_device *)ctx;
    if (!dev || !buf || count == 0) return -1;
    if (lba + count > dev->sectors28) return -1;

    const uint8_t *src = (const uint8_t *)buf;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t l = (uint32_t)(lba + i);
        ata_select(dev->io, dev->slave, l);
        outb(dev->io + ATA_REG_SECCOUNT0, 1);
        outb(dev->io + ATA_REG_LBA0, (uint8_t)(l & 0xFF));
        outb(dev->io + ATA_REG_LBA1, (uint8_t)((l >> 8) & 0xFF));
        outb(dev->io + ATA_REG_LBA2, (uint8_t)((l >> 16) & 0xFF));
        outb(dev->io + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);
        if (ata_wait_bsy(dev->io) != 0) return -1;
        if (ata_wait_drq(dev->io) != 0) return -1;
        for (uint32_t w = 0; w < 256; ++w) {
            uint16_t data = (uint16_t)src[w * 2] | ((uint16_t)src[w * 2 + 1] << 8);
            outw(dev->io + ATA_REG_DATA, data);
        }
        outb(dev->io + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
        ata_wait_bsy(dev->io);
        src += 512;
    }
    return 0;
}

static int ata_identify(uint16_t io, uint16_t ctl, uint8_t slave, uint16_t out[256]) {
    outb(ctl, 0);
    ata_select(io, slave, 0);
    outb(io + ATA_REG_SECCOUNT0, 0);
    outb(io + ATA_REG_LBA0, 0);
    outb(io + ATA_REG_LBA1, 0);
    outb(io + ATA_REG_LBA2, 0);
    outb(io + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    uint8_t st = inb(io + ATA_REG_STATUS);
    if (st == 0) return -1;
    if (ata_wait_bsy(io) != 0) return -1;
    if (ata_wait_drq(io) != 0) return -1;
    for (uint32_t i = 0; i < 256; ++i) {
        out[i] = inw(io + ATA_REG_DATA);
    }
    return 0;
}

static void ata_probe_channel(uint16_t io, uint16_t ctl) {
    for (uint8_t slave = 0; slave < 2; ++slave) {
        uint16_t ident[256];
        memset(ident, 0, sizeof(ident));
        if (ata_identify(io, ctl, slave, ident) != 0) continue;

        uint32_t sectors = ((uint32_t)ident[61] << 16) | ident[60];
        if (sectors == 0) continue;

        struct ata_device *dev = &g_ata_devs[g_ata_count++];
        dev->io = io;
        dev->ctl = ctl;
        dev->slave = slave;
        dev->sectors28 = sectors;

        struct block_device bdev;
        bdev.name = (slave == 0) ? "ata0" : "ata1";
        bdev.sector_count = sectors;
        bdev.sector_size = 512;
        bdev.read = ata_pio_read;
        bdev.write = ata_pio_write;
        bdev.ctx = dev;
        block_register(&bdev);

        log_printf("ATA: %s sectors=%u\n", bdev.name, sectors);
        if (g_ata_count >= 4) return;
    }
}

void ata_init(void) {
    g_ata_count = 0;
    ata_probe_channel(ATA_PRIMARY_IO, ATA_PRIMARY_CTL);
    ata_probe_channel(ATA_SECONDARY_IO, ATA_SECONDARY_CTL);
    if (g_ata_count == 0) {
        log_printf("ATA: no devices found\n");
    }
}

int ata_has_device(void) {
    return g_ata_count > 0;
}
