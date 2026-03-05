#include "kernel/kmsan.h"

#include "lib/compat.h"

void *memset(void *s, int c, size_t n);

static int g_kmsan_enabled = 1;
static uint64_t g_allocs = 0;
static uint64_t g_frees = 0;
static uint64_t g_poisoned_bytes = 0;
static uint64_t g_unpoisoned_bytes = 0;

void kmsan_init(void) {
    g_kmsan_enabled = 1;
    g_allocs = 0;
    g_frees = 0;
    g_poisoned_bytes = 0;
    g_unpoisoned_bytes = 0;
}

void kmsan_enable(int on) {
    g_kmsan_enabled = on ? 1 : 0;
}

int kmsan_is_enabled(void) {
    return g_kmsan_enabled != 0;
}

void kmsan_poison(void *ptr, size_t size, uint8_t value) {
    if (!g_kmsan_enabled || !ptr || size == 0) return;
    memset(ptr, (int)value, size);
}

void kmsan_alloc(void *ptr, size_t size) {
    if (!g_kmsan_enabled || !ptr || size == 0) return;
    __atomic_fetch_add(&g_allocs, 1u, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&g_unpoisoned_bytes, size, __ATOMIC_SEQ_CST);
    kmsan_poison(ptr, size, KMSAN_POISON_ALLOC);
}

void kmsan_free(void *ptr, size_t size) {
    if (!g_kmsan_enabled || !ptr || size == 0) return;
    __atomic_fetch_add(&g_frees, 1u, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&g_poisoned_bytes, size, __ATOMIC_SEQ_CST);
    kmsan_poison(ptr, size, KMSAN_POISON_FREE);
}

void kmsan_get_stats(uint64_t *allocs, uint64_t *frees,
                     uint64_t *poisoned_bytes, uint64_t *unpoisoned_bytes) {
    if (allocs) *allocs = __atomic_load_n(&g_allocs, __ATOMIC_SEQ_CST);
    if (frees) *frees = __atomic_load_n(&g_frees, __ATOMIC_SEQ_CST);
    if (poisoned_bytes) *poisoned_bytes = __atomic_load_n(&g_poisoned_bytes, __ATOMIC_SEQ_CST);
    if (unpoisoned_bytes) *unpoisoned_bytes = __atomic_load_n(&g_unpoisoned_bytes, __ATOMIC_SEQ_CST);
}
