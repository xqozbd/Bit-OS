#ifndef BLOCK_H
#define BLOCK_H

#include <stddef.h>
#include <stdint.h>

#define BLOCK_CACHE_MAX_SECTOR_SIZE 4096u

struct block_device;

typedef int (*block_read_fn)(void *ctx, uint64_t lba, uint32_t count, void *buf);
typedef int (*block_write_fn)(void *ctx, uint64_t lba, uint32_t count, const void *buf);

struct block_device {
    const char *name;
    uint64_t sector_count;
    uint32_t sector_size;
    block_read_fn read;
    block_write_fn write;
    void *ctx;
};

void block_init(void);
int block_register(const struct block_device *dev);
size_t block_device_count(void);
const struct block_device *block_get(size_t index);

int block_read(const struct block_device *dev, uint64_t lba, uint32_t count, void *buf);
int block_write(const struct block_device *dev, uint64_t lba, uint32_t count, const void *buf);

int block_read_cached(const struct block_device *dev, uint64_t lba, uint32_t count, void *buf);
int block_write_cached(const struct block_device *dev, uint64_t lba, uint32_t count, const void *buf);
int block_flush(const struct block_device *dev);
int block_flush_all(void);
int block_writeback_poll(uint32_t max_flush);

#endif /* BLOCK_H */
