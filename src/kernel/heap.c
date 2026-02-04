#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
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

void heap_init(void) {
    heap_end = heap_base;
    heap_head = NULL;
    log_printf("Heap: base=0x%x\n", (unsigned)heap_base);
}

void *kmalloc(size_t size) {
    if (size == 0) return NULL;
    size = align_up_size(size, 16);

    struct heap_block *b = heap_head;
    while (b) {
        if (b->magic != HEAP_MAGIC) {
            log_printf("Heap: corruption detected\n");
            return NULL;
        }
        if (b->free && b->size >= size) {
            size_t remaining = b->size - size;
            if (remaining > sizeof(struct heap_block) + 16) {
                struct heap_block *nb = (struct heap_block *)((uintptr_t)b + sizeof(struct heap_block) + size);
                nb->magic = HEAP_MAGIC;
                nb->size = remaining - sizeof(struct heap_block);
                nb->free = 1;
                nb->next = b->next;
                b->next = nb;
                b->size = size;
            }
            b->free = 0;
            b->owner = thread_current();
            thread_account_alloc(b->owner, b->size);
            return (void *)((uintptr_t)b + sizeof(struct heap_block));
        }
        b = b->next;
    }

    size_t need = size + sizeof(struct heap_block);
    if (heap_expand(need) != 0) {
        log_printf("Heap: expand failed\n");
        return NULL;
    }

    return kmalloc(size);
}

void kfree(void *ptr) {
    if (!ptr) return;
    struct heap_block *b = (struct heap_block *)((uintptr_t)ptr - sizeof(struct heap_block));
    if (b->magic != HEAP_MAGIC) {
        log_printf("Heap: bad free (magic)\n");
        return;
    }
    thread_account_free(b->owner, b->size);
    b->free = 1;
    heap_coalesce();
}

void *krealloc(void *ptr, size_t size) {
    if (!ptr) return kmalloc(size);
    if (size == 0) {
        kfree(ptr);
        return NULL;
    }

    size = align_up_size(size, 16);
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
        return ptr;
    }

    size_t old_size = b->size;
    struct heap_block *next = b->next;
    uintptr_t b_end = (uintptr_t)b + sizeof(struct heap_block) + b->size;
    if (next && next->free && b_end == (uintptr_t)next) {
        size_t total = b->size + sizeof(struct heap_block) + next->size;
        if (total >= size) {
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
