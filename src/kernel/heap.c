#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
#include "kernel/slab.h"
#include "lib/log.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/thread.h"

enum { HEAP_PAGE_SIZE = 0x1000ull };
enum { HEAP_MAGIC = 0xB17B0050B17B0050ull };

/* From memutils.c */
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

struct heap_block {
    uint64_t magic;
    size_t size;
    int free;
    struct thread *owner;
    struct heap_block *next;
};

/* Keep heap far from kernel and HHDM. */
static uint64_t heap_base = 0xffffc00000000000ull;
static uint64_t heap_end = 0;
static struct heap_block *heap_head = NULL;
static uint64_t g_heap_allocs = 0;
static uint64_t g_heap_frees = 0;
static uint64_t g_heap_active_allocs = 0;
static uint64_t g_heap_active_bytes = 0;
static uint64_t g_heap_peak_bytes = 0;
static uint64_t g_heap_failures = 0;

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static inline size_t align_up_size(size_t v, size_t a) {
    return (size_t)(((v + a - 1) / a) * a);
}

static struct heap_block *heap_last(void) {
    struct heap_block *b = heap_head;
    if (!b) return NULL;
    while (b->next) b = b->next;
    return b;
}

static struct heap_block *heap_last_prev(struct heap_block **out_prev) {
    struct heap_block *prev = NULL;
    struct heap_block *b = heap_head;
    if (!b) {
        if (out_prev) *out_prev = NULL;
        return NULL;
    }
    while (b->next) {
        prev = b;
        b = b->next;
    }
    if (out_prev) *out_prev = prev;
    return b;
}

static void heap_append_block(struct heap_block *b) {
    if (!heap_head) {
        heap_head = b;
        return;
    }
    struct heap_block *last = heap_last();
    last->next = b;
}

static int heap_expand(size_t min_bytes) {
    uint64_t need = align_up_u64((uint64_t)min_bytes, HEAP_PAGE_SIZE);
    uint64_t start = heap_end;
    for (uint64_t off = 0; off < need; off += HEAP_PAGE_SIZE) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) return -1;
        if (paging_map_4k(start + off, phys, 0) != 0) return -1;
    }
    heap_end += need;

    struct heap_block *b = (struct heap_block *)(uintptr_t)start;
    b->magic = HEAP_MAGIC;
    b->size = (size_t)(need - sizeof(struct heap_block));
    b->free = 1;
    b->next = NULL;
    heap_append_block(b);
    return 0;
}

static void heap_coalesce(void) {
    struct heap_block *b = heap_head;
    while (b && b->next) {
        uintptr_t b_end = (uintptr_t)b + sizeof(struct heap_block) + b->size;
        if (b->free && b->next->free && b_end == (uintptr_t)b->next) {
            if (b->next->magic != HEAP_MAGIC) {
                log_printf("Heap: corruption detected (next magic)\n");
                return;
            }
            b->size += sizeof(struct heap_block) + b->next->size;
            b->next = b->next->next;
            continue;
        }
        b = b->next;
    }
}

static void heap_trim(void) {
    struct heap_block *prev = NULL;
    struct heap_block *last = heap_last_prev(&prev);
    if (!last || !last->free) return;

    uintptr_t block_start = (uintptr_t)last;
    uintptr_t data_start = block_start + sizeof(struct heap_block);
    uintptr_t block_end = data_start + last->size;
    if (block_end != (uintptr_t)heap_end) return;

    uintptr_t min_keep_end = data_start + 16;
    if (min_keep_end > block_end) return;

    uintptr_t release_start = align_up_u64(min_keep_end, HEAP_PAGE_SIZE);
    uintptr_t release_end = block_end & ~(HEAP_PAGE_SIZE - 1);
    if (release_start >= release_end) return;

    for (uintptr_t addr = release_start; addr < release_end; addr += HEAP_PAGE_SIZE) {
        uint64_t phys = paging_unmap_4k((uint64_t)addr);
        if (phys) pmm_free_frame(phys);
    }
    heap_end = (uint64_t)release_start;
    last->size = (size_t)(heap_end - data_start);
    if (last->size == 0 && prev) {
        prev->next = NULL;
    }
}

void heap_reclaim(void) {
    heap_coalesce();
    heap_trim();
}

static void heap_track_alloc(size_t size) {
    g_heap_allocs++;
    g_heap_active_allocs++;
    g_heap_active_bytes += (uint64_t)size;
    if (g_heap_active_bytes > g_heap_peak_bytes) g_heap_peak_bytes = g_heap_active_bytes;
}

static void heap_track_free(size_t size) {
    g_heap_frees++;
    if (g_heap_active_allocs > 0) g_heap_active_allocs--;
    if (g_heap_active_bytes >= (uint64_t)size) {
        g_heap_active_bytes -= (uint64_t)size;
    } else {
        g_heap_active_bytes = 0;
    }
}

static void heap_track_resize(size_t old_size, size_t new_size) {
    if (new_size == old_size) return;
    if (new_size > old_size) {
        uint64_t delta = (uint64_t)(new_size - old_size);
        g_heap_active_bytes += delta;
        if (g_heap_active_bytes > g_heap_peak_bytes) g_heap_peak_bytes = g_heap_active_bytes;
    } else {
        uint64_t delta = (uint64_t)(old_size - new_size);
        if (g_heap_active_bytes >= delta) g_heap_active_bytes -= delta;
        else g_heap_active_bytes = 0;
    }
}

void heap_init(void) {
    heap_end = heap_base;
    heap_head = NULL;
    slab_init();
    g_heap_allocs = 0;
    g_heap_frees = 0;
    g_heap_active_allocs = 0;
    g_heap_active_bytes = 0;
    g_heap_peak_bytes = 0;
    g_heap_failures = 0;
    log_printf("Heap: base=0x%x\n", (unsigned)heap_base);
}

void *kmalloc(size_t size) {
    if (size == 0) return NULL;
    size = align_up_size(size, 16);
    if (size <= 2048) {
        void *s = slab_alloc(size);
        if (s) return s;
    }

    struct heap_block *best = NULL;
    struct heap_block *b = heap_head;
    while (b) {
        if (b->magic != HEAP_MAGIC) {
            log_printf("Heap: corruption detected\n");
            return NULL;
        }
        if (b->free && b->size >= size) {
            if (!best || b->size < best->size) best = b;
        }
        b = b->next;
    }
    if (best) {
        size_t remaining = best->size - size;
        if (remaining > sizeof(struct heap_block) + 16) {
            struct heap_block *nb = (struct heap_block *)((uintptr_t)best + sizeof(struct heap_block) + size);
            nb->magic = HEAP_MAGIC;
            nb->size = remaining - sizeof(struct heap_block);
            nb->free = 1;
            nb->next = best->next;
            best->next = nb;
            best->size = size;
        }
        best->free = 0;
        best->owner = thread_current();
        thread_account_alloc(best->owner, best->size);
        heap_track_alloc(best->size);
        return (void *)((uintptr_t)best + sizeof(struct heap_block));
    }

    size_t need = size + sizeof(struct heap_block);
    if (heap_expand(need) != 0) {
        log_printf("Heap: expand failed\n");
        g_heap_failures++;
        return NULL;
    }

    return kmalloc(size);
}

void kfree(void *ptr) {
    if (!ptr) return;
    if (slab_owns(ptr)) {
        slab_free(ptr);
        return;
    }
    struct heap_block *b = (struct heap_block *)((uintptr_t)ptr - sizeof(struct heap_block));
    if (b->magic != HEAP_MAGIC) {
        log_printf("Heap: bad free (magic)\n");
        return;
    }
    thread_account_free(b->owner, b->size);
    heap_track_free(b->size);
    b->free = 1;
    heap_coalesce();
    heap_trim();
}

void *krealloc(void *ptr, size_t size) {
    if (!ptr) return kmalloc(size);
    if (size == 0) {
        kfree(ptr);
        return NULL;
    }

    size = align_up_size(size, 16);
    if (slab_owns(ptr)) {
        size_t old_size = slab_obj_size(ptr);
        if (size <= old_size) return ptr;
        void *n = kmalloc(size);
        if (!n) return NULL;
        size_t to_copy = old_size < size ? old_size : size;
        memcpy(n, ptr, to_copy);
        slab_free(ptr);
        return n;
    }
    struct heap_block *b = (struct heap_block *)((uintptr_t)ptr - sizeof(struct heap_block));
    if (b->magic != HEAP_MAGIC) {
        log_printf("Heap: bad realloc (magic)\n");
        return NULL;
    }

    if (size <= b->size) {
        size_t old_size = b->size;
        size_t remaining = old_size - size;
        if (remaining > sizeof(struct heap_block) + 16) {
            struct heap_block *nb = (struct heap_block *)((uintptr_t)b + sizeof(struct heap_block) + size);
            nb->magic = HEAP_MAGIC;
            nb->size = remaining - sizeof(struct heap_block);
            nb->free = 1;
            nb->owner = NULL;
            nb->next = b->next;
            b->next = nb;
            b->size = size;
        }
        if (b->owner && old_size > size) {
            thread_account_free(b->owner, old_size - size);
        }
        heap_track_resize(old_size, size);
        return ptr;
    }

    size_t old_size = b->size;
    struct heap_block *next = b->next;
    uintptr_t b_end = (uintptr_t)b + sizeof(struct heap_block) + b->size;
    if (next && next->free && b_end == (uintptr_t)next) {
        size_t total = b->size + sizeof(struct heap_block) + next->size;
        if (total >= size) {
            size_t old_size = b->size;
            b->size = total;
            b->next = next->next;
            size_t remaining = b->size - size;
            if (remaining > sizeof(struct heap_block) + 16) {
                struct heap_block *nb = (struct heap_block *)((uintptr_t)b + sizeof(struct heap_block) + size);
                nb->magic = HEAP_MAGIC;
                nb->size = remaining - sizeof(struct heap_block);
                nb->free = 1;
                nb->owner = NULL;
                nb->next = b->next;
                b->next = nb;
                b->size = size;
            }
            if (b->owner) {
                if (size > old_size) {
                    thread_account_alloc(b->owner, size - old_size);
                } else if (old_size > size) {
                    thread_account_free(b->owner, old_size - size);
                }
            }
            heap_track_resize(old_size, size);
            return ptr;
        }
    }

    void *n = kmalloc(size);
    if (!n) return NULL;
    size_t to_copy = b->size < size ? b->size : size;
    memcpy(n, ptr, to_copy);
    if (b->owner) {
        thread_account_free(b->owner, b->size);
    }
    kfree(ptr);
    return n;
}

int heap_check(void) {
    struct heap_block *b = heap_head;
    uintptr_t last = 0;
    while (b) {
        if (b->magic != HEAP_MAGIC) return -1;
        uintptr_t addr = (uintptr_t)b;
        if (last != 0 && addr <= last) return -2;
        uintptr_t end = addr + sizeof(struct heap_block) + b->size;
        if (end > (uintptr_t)heap_end) return -3;
        last = addr;
        b = b->next;
    }
    return 0;
}

void heap_get_stats(struct heap_stats *out) {
    if (!out) return;
    out->allocs = g_heap_allocs;
    out->frees = g_heap_frees;
    out->active_allocs = g_heap_active_allocs;
    out->active_bytes = g_heap_active_bytes;
    out->peak_bytes = g_heap_peak_bytes;
    out->failures = g_heap_failures;
}
