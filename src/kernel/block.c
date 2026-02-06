#include "kernel/block.h"

#include "lib/log.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);
extern void *memset(void *s, int c, size_t n);

#define MAX_BLOCK_DEVS 8
#define BLOCK_CACHE_SLOTS 4

struct block_cache_entry {
    const struct block_device *dev;
    uint64_t lba;
    uint32_t sector_size;
    uint8_t valid;
    uint8_t dirty;
    uint8_t data[BLOCK_CACHE_MAX_SECTOR_SIZE];
};

static struct block_device g_block_devs[MAX_BLOCK_DEVS];
static size_t g_block_dev_count = 0;
static struct block_cache_entry g_cache[BLOCK_CACHE_SLOTS];
static uint32_t g_cache_rr = 0;

void block_init(void) {
    memset(g_block_devs, 0, sizeof(g_block_devs));
    g_block_dev_count = 0;
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_rr = 0;
    log_printf("Boot: block layer ready\n");
}

int block_register(const struct block_device *dev) {
    if (!dev || !dev->name || !dev->read || !dev->write) return -1;
    if (dev->sector_size == 0 || dev->sector_size > BLOCK_CACHE_MAX_SECTOR_SIZE) return -1;
    if (g_block_dev_count >= MAX_BLOCK_DEVS) return -1;
    g_block_devs[g_block_dev_count] = *dev;
    return (int)g_block_dev_count++;
}

size_t block_device_count(void) {
    return g_block_dev_count;
}

const struct block_device *block_get(size_t index) {
    if (index >= g_block_dev_count) return NULL;
    return &g_block_devs[index];
}

int block_read(const struct block_device *dev, uint64_t lba, uint32_t count, void *buf) {
    if (!dev || !buf || !dev->read) return -1;
    if (count == 0) return 0;
    return dev->read(dev->ctx, lba, count, buf);
}

int block_write(const struct block_device *dev, uint64_t lba, uint32_t count, const void *buf) {
    if (!dev || !buf || !dev->write) return -1;
    if (count == 0) return 0;
    return dev->write(dev->ctx, lba, count, buf);
}

static struct block_cache_entry *cache_find(const struct block_device *dev, uint64_t lba) {
    for (uint32_t i = 0; i < BLOCK_CACHE_SLOTS; ++i) {
        if (g_cache[i].valid && g_cache[i].dev == dev && g_cache[i].lba == lba) {
            return &g_cache[i];
        }
    }
    return NULL;
}

static int cache_flush_entry(struct block_cache_entry *ent) {
    if (!ent || !ent->valid || !ent->dirty) return 0;
    if (!ent->dev || !ent->dev->write) return -1;
    int rc = ent->dev->write(ent->dev->ctx, ent->lba, 1, ent->data);
    if (rc == 0) ent->dirty = 0;
    return rc;
}

static struct block_cache_entry *cache_pick_slot(void) {
    struct block_cache_entry *ent = &g_cache[g_cache_rr % BLOCK_CACHE_SLOTS];
    g_cache_rr++;
    if (ent->valid && ent->dirty) {
        (void)cache_flush_entry(ent);
    }
    ent->valid = 0;
    ent->dirty = 0;
    return ent;
}

int block_read_cached(const struct block_device *dev, uint64_t lba, uint32_t count, void *buf) {
    if (!dev || !buf) return -1;
    if (count == 0) return 0;
    if (count != 1) {
        return block_read(dev, lba, count, buf);
    }
    if (dev->sector_size == 0 || dev->sector_size > BLOCK_CACHE_MAX_SECTOR_SIZE) {
        return block_read(dev, lba, count, buf);
    }

    struct block_cache_entry *ent = cache_find(dev, lba);
    if (!ent) {
        ent = cache_pick_slot();
        ent->dev = dev;
        ent->lba = lba;
        ent->sector_size = dev->sector_size;
        int rc = dev->read(dev->ctx, lba, 1, ent->data);
        if (rc != 0) {
            ent->valid = 0;
            return rc;
        }
        ent->valid = 1;
    }
    memcpy(buf, ent->data, dev->sector_size);
    return 0;
}

int block_write_cached(const struct block_device *dev, uint64_t lba, uint32_t count, const void *buf) {
    if (!dev || !buf) return -1;
    if (count == 0) return 0;
    if (count != 1) {
        return block_write(dev, lba, count, buf);
    }
    if (dev->sector_size == 0 || dev->sector_size > BLOCK_CACHE_MAX_SECTOR_SIZE) {
        return block_write(dev, lba, count, buf);
    }

    struct block_cache_entry *ent = cache_find(dev, lba);
    if (!ent) {
        ent = cache_pick_slot();
        ent->dev = dev;
        ent->lba = lba;
        ent->sector_size = dev->sector_size;
        ent->valid = 1;
    }
    memcpy(ent->data, buf, dev->sector_size);
    ent->dirty = 1;
    return 0;
}

int block_flush(const struct block_device *dev) {
    if (!dev) return -1;
    int rc = 0;
    for (uint32_t i = 0; i < BLOCK_CACHE_SLOTS; ++i) {
        if (g_cache[i].valid && g_cache[i].dev == dev) {
            int tmp = cache_flush_entry(&g_cache[i]);
            if (tmp != 0) rc = tmp;
        }
    }
    return rc;
}

int block_flush_all(void) {
    int rc = 0;
    for (uint32_t i = 0; i < BLOCK_CACHE_SLOTS; ++i) {
        int tmp = cache_flush_entry(&g_cache[i]);
        if (tmp != 0) rc = tmp;
    }
    return rc;
}
