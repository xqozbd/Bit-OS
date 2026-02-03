#include <stddef.h>
#include <stdint.h>

#include "boot_requests.h"
#include "limine.h"
#include "log.h"
#include "pmm.h"

/* From memutils.c */
void *memset(void *s, int c, size_t n);

static uint8_t *g_bitmap = 0;
static uint64_t g_bitmap_bytes = 0;
static uint64_t g_total_frames = 0;
static uint64_t g_used_frames = 0;
static uint64_t g_hhdm_offset = 0;
static uint64_t g_last_alloc = 0;

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static inline void bitmap_set(uint64_t frame) {
    g_bitmap[frame / 8] |= (uint8_t)(1u << (frame % 8));
}

static inline void bitmap_clear(uint64_t frame) {
    g_bitmap[frame / 8] &= (uint8_t)~(1u << (frame % 8));
}

static inline int bitmap_test(uint64_t frame) {
    return g_bitmap[frame / 8] & (uint8_t)(1u << (frame % 8));
}

static void mark_range_free(uint64_t base, uint64_t length) {
    uint64_t start = base / PMM_PAGE_SIZE;
    uint64_t end = align_up_u64(base + length, PMM_PAGE_SIZE) / PMM_PAGE_SIZE;
    if (end > g_total_frames) end = g_total_frames;
    for (uint64_t f = start; f < end; ++f) {
        if (bitmap_test(f)) {
            bitmap_clear(f);
            if (g_used_frames > 0) g_used_frames--;
        }
    }
}

static void mark_range_used(uint64_t base, uint64_t length) {
    uint64_t start = base / PMM_PAGE_SIZE;
    uint64_t end = align_up_u64(base + length, PMM_PAGE_SIZE) / PMM_PAGE_SIZE;
    if (end > g_total_frames) end = g_total_frames;
    for (uint64_t f = start; f < end; ++f) {
        if (!bitmap_test(f)) {
            bitmap_set(f);
            g_used_frames++;
        }
    }
}

void pmm_init(void) {
    if (!memmap_request.response) {
        log_printf("PMM: memmap unavailable\n");
        return;
    }
    if (!hhdm_request.response) {
        log_printf("PMM: HHDM unavailable\n");
        return;
    }

    g_hhdm_offset = hhdm_request.response->offset;

    /* Find max physical address */
    uint64_t max_addr = 0;
    struct limine_memmap_response *resp = memmap_request.response;
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (!e) continue;
        uint64_t end = e->base + e->length;
        if (end > max_addr) max_addr = end;
    }
    g_total_frames = align_up_u64(max_addr, PMM_PAGE_SIZE) / PMM_PAGE_SIZE;
    g_bitmap_bytes = align_up_u64((g_total_frames + 7) / 8, 8);

    /* Place bitmap in a usable region (prefer highest base). */
    uint64_t bitmap_phys = 0;
    int bitmap_found = 0;
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (!e || e->type != LIMINE_MEMMAP_USABLE) continue;
        uint64_t base = align_up_u64(e->base, 8);
        if (base + g_bitmap_bytes > e->base + e->length) continue;
        if (!bitmap_found || base >= bitmap_phys) {
            bitmap_phys = base;
            bitmap_found = 1;
        }
    }
    if (!bitmap_found) {
        log_printf("PMM: no space for bitmap\n");
        return;
    }

    g_bitmap = (uint8_t *)(uintptr_t)(g_hhdm_offset + bitmap_phys);
    memset(g_bitmap, 0xFF, (size_t)g_bitmap_bytes);
    g_used_frames = g_total_frames;

    /* Mark usable frames as free. */
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (!e || e->type != LIMINE_MEMMAP_USABLE) continue;
        mark_range_free(e->base, e->length);
    }

    /* Reserve the bitmap storage itself. */
    mark_range_used(bitmap_phys, g_bitmap_bytes);

    /* Keep frame 0 reserved (null pointer protection). */
    mark_range_used(0, PMM_PAGE_SIZE);

    log_printf("PMM: %u frames total, %u free\n",
               (unsigned)g_total_frames,
               (unsigned)(g_total_frames - g_used_frames));
}

uint64_t pmm_alloc_frame(void) {
    if (!g_bitmap || g_total_frames == 0) return 0;

    for (uint64_t f = g_last_alloc; f < g_total_frames; ++f) {
        if (!bitmap_test(f)) {
            bitmap_set(f);
            g_used_frames++;
            g_last_alloc = f + 1;
            return f * PMM_PAGE_SIZE;
        }
    }
    for (uint64_t f = 0; f < g_last_alloc; ++f) {
        if (!bitmap_test(f)) {
            bitmap_set(f);
            g_used_frames++;
            g_last_alloc = f + 1;
            return f * PMM_PAGE_SIZE;
        }
    }
    return 0;
}

void pmm_free_frame(uint64_t phys_addr) {
    if (!g_bitmap || phys_addr == 0) return;
    uint64_t frame = phys_addr / PMM_PAGE_SIZE;
    if (frame >= g_total_frames) return;
    if (bitmap_test(frame)) {
        bitmap_clear(frame);
        if (g_used_frames > 0) g_used_frames--;
    }
}

uint64_t pmm_total_frames(void) { return g_total_frames; }
uint64_t pmm_used_frames(void) { return g_used_frames; }
uint64_t pmm_free_frames(void) { return g_total_frames - g_used_frames; }

int pmm_sanity_check(void) {
    if (g_used_frames > g_total_frames) return -1;
    return 0;
}
