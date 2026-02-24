#ifndef SLAB_H
#define SLAB_H

#include <stddef.h>
#include <stdint.h>

void slab_init(void);
void *slab_alloc(size_t size);
void slab_free(void *ptr);
int slab_owns(void *ptr);
size_t slab_obj_size(void *ptr);

struct slab_stats {
    uint64_t allocs;
    uint64_t frees;
    uint64_t active_allocs;
    uint64_t active_bytes;
    uint64_t peak_bytes;
};

void slab_get_stats(struct slab_stats *out);

#endif /* SLAB_H */
