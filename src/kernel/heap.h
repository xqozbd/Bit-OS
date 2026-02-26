#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>
#include <stdint.h>

void heap_init(void);
void *kmalloc(size_t size);
void kfree(void *ptr);
void *krealloc(void *ptr, size_t size);
int heap_check(void);
void heap_reclaim(void);

struct heap_stats {
    uint64_t allocs;
    uint64_t frees;
    uint64_t active_allocs;
    uint64_t active_bytes;
    uint64_t peak_bytes;
    uint64_t failures;
};

void heap_get_stats(struct heap_stats *out);

#endif /* HEAP_H */
