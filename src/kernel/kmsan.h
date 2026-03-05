#ifndef KERNEL_KMSAN_H
#define KERNEL_KMSAN_H

#include <stddef.h>
#include <stdint.h>

enum {
    KMSAN_POISON_ALLOC = 0xCC,
    KMSAN_POISON_FREE = 0xDD
};

void kmsan_init(void);
void kmsan_enable(int on);
int kmsan_is_enabled(void);

void kmsan_alloc(void *ptr, size_t size);
void kmsan_free(void *ptr, size_t size);
void kmsan_poison(void *ptr, size_t size, uint8_t value);

void kmsan_get_stats(uint64_t *allocs, uint64_t *frees,
                     uint64_t *poisoned_bytes, uint64_t *unpoisoned_bytes);

#endif /* KERNEL_KMSAN_H */
