#include <stdint.h>

#include "kernel/slab.h"
#include "kernel/pmm.h"
#include "arch/x86_64/paging.h"

enum { SLAB_PAGE_SIZE = 0x1000u };
enum { SLAB_MAGIC = 0x51424C53u }; /* 'SLBQ' */

struct slab_page {
    uint32_t magic;
    uint16_t obj_size;
    uint16_t total;
    uint16_t free_count;
    uint16_t _pad;
    void *free_list;
    struct slab_page *next;
};

struct slab_cache {
    uint16_t obj_size;
    struct slab_page *pages;
};

static struct slab_cache g_caches[] = {
    { 8, NULL },
    { 16, NULL },
    { 32, NULL },
    { 64, NULL },
    { 128, NULL },
    { 256, NULL },
    { 512, NULL },
    { 1024, NULL },
    { 2048, NULL },
};

static uint64_t g_slab_allocs = 0;
static uint64_t g_slab_frees = 0;
static uint64_t g_slab_active_allocs = 0;
static uint64_t g_slab_active_bytes = 0;
static uint64_t g_slab_peak_bytes = 0;

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static struct slab_cache *cache_for_size(size_t size) {
    for (unsigned i = 0; i < sizeof(g_caches) / sizeof(g_caches[0]); ++i) {
        if (size <= g_caches[i].obj_size) return &g_caches[i];
    }
    return NULL;
}

static void page_list_remove(struct slab_cache *cache, struct slab_page *page) {
    struct slab_page **pp = &cache->pages;
    while (*pp) {
        if (*pp == page) {
            *pp = page->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

static struct slab_page *slab_new_page(struct slab_cache *cache) {
    uint64_t phys = pmm_alloc_frame();
    if (phys == 0) return NULL;
    uint64_t virt = paging_hhdm_offset() + phys;
    struct slab_page *page = (struct slab_page *)(uintptr_t)virt;
    page->magic = SLAB_MAGIC;
    page->obj_size = cache->obj_size;
    page->next = NULL;

    uint64_t start = align_up_u64((uint64_t)(uintptr_t)page + sizeof(struct slab_page),
                                  cache->obj_size);
    uint64_t end = (uint64_t)(uintptr_t)page + SLAB_PAGE_SIZE;
    uint16_t count = 0;
    void *prev = NULL;
    for (uint64_t cur = start; cur + cache->obj_size <= end; cur += cache->obj_size) {
        void *obj = (void *)(uintptr_t)cur;
        *(void **)obj = prev;
        prev = obj;
        ++count;
    }

    page->total = count;
    page->free_count = count;
    page->free_list = prev;
    cache->pages = page;
    return page;
}

void slab_init(void) {
    for (unsigned i = 0; i < sizeof(g_caches) / sizeof(g_caches[0]); ++i) {
        g_caches[i].pages = NULL;
    }
    g_slab_allocs = 0;
    g_slab_frees = 0;
    g_slab_active_allocs = 0;
    g_slab_active_bytes = 0;
    g_slab_peak_bytes = 0;
}

static void slab_track_alloc(uint16_t size) {
    g_slab_allocs++;
    g_slab_active_allocs++;
    g_slab_active_bytes += size;
    if (g_slab_active_bytes > g_slab_peak_bytes) g_slab_peak_bytes = g_slab_active_bytes;
}

static void slab_track_free(uint16_t size) {
    g_slab_frees++;
    if (g_slab_active_allocs > 0) g_slab_active_allocs--;
    if (g_slab_active_bytes >= size) g_slab_active_bytes -= size;
    else g_slab_active_bytes = 0;
}

void *slab_alloc(size_t size) {
    if (size == 0) return NULL;
    struct slab_cache *cache = cache_for_size(size);
    if (!cache) return NULL;

    struct slab_page *page = cache->pages;
    while (page && page->free_count == 0) {
        page = page->next;
    }
    if (!page) {
        page = slab_new_page(cache);
        if (!page) return NULL;
    }

    void *obj = page->free_list;
    if (!obj) return NULL;
    page->free_list = *(void **)obj;
    page->free_count--;
    slab_track_alloc(page->obj_size);
    return obj;
}

void slab_free(void *ptr) {
    if (!ptr) return;
    struct slab_page *page = (struct slab_page *)((uintptr_t)ptr & ~(SLAB_PAGE_SIZE - 1));
    if (page->magic != SLAB_MAGIC) return;

    *(void **)ptr = page->free_list;
    page->free_list = ptr;
    page->free_count++;
    slab_track_free(page->obj_size);

    if (page->free_count == page->total) {
        struct slab_cache *cache = cache_for_size(page->obj_size);
        if (cache) {
            page_list_remove(cache, page);
        }
        uint64_t phys = ((uint64_t)(uintptr_t)page) - paging_hhdm_offset();
        pmm_free_frame(phys);
    }
}

int slab_owns(void *ptr) {
    if (!ptr) return 0;
    struct slab_page *page = (struct slab_page *)((uintptr_t)ptr & ~(SLAB_PAGE_SIZE - 1));
    return page->magic == SLAB_MAGIC;
}

size_t slab_obj_size(void *ptr) {
    if (!ptr) return 0;
    struct slab_page *page = (struct slab_page *)((uintptr_t)ptr & ~(SLAB_PAGE_SIZE - 1));
    if (page->magic != SLAB_MAGIC) return 0;
    return page->obj_size;
}

void slab_get_stats(struct slab_stats *out) {
    if (!out) return;
    out->allocs = g_slab_allocs;
    out->frees = g_slab_frees;
    out->active_allocs = g_slab_active_allocs;
    out->active_bytes = g_slab_active_bytes;
    out->peak_bytes = g_slab_peak_bytes;
}
