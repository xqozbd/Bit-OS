#include "kernel/swap.h"

#include <stddef.h>

#include "sys/vfs.h"
#include "kernel/heap.h"
#include "lib/log.h"

static int g_swap_node = -1;
static uint64_t g_swap_size = 0;
static uint32_t g_swap_slots = 0;
static uint8_t *g_swap_bitmap = NULL;

static inline uint32_t slot_bytes(void) { return 0x1000u; }

static inline void bitmap_set(uint32_t slot) {
    g_swap_bitmap[slot / 8] |= (uint8_t)(1u << (slot % 8));
}

static inline void bitmap_clear(uint32_t slot) {
    g_swap_bitmap[slot / 8] &= (uint8_t)~(1u << (slot % 8));
}

static inline int bitmap_test(uint32_t slot) {
    return g_swap_bitmap[slot / 8] & (uint8_t)(1u << (slot % 8));
}

int swap_enabled(void) {
    return g_swap_node >= 0 && g_swap_bitmap && g_swap_slots > 0;
}

uint64_t swap_total_slots(void) {
    return g_swap_slots;
}

int swap_init(const char *path, uint64_t size_bytes) {
    if (!path || size_bytes < slot_bytes()) {
        return -1;
    }
    g_swap_node = vfs_resolve(0, path);
    if (g_swap_node < 0) {
        g_swap_node = vfs_create(0, path, 0);
    }
    if (g_swap_node < 0) {
        log_printf("swap: unable to create %s\n", path);
        return -2;
    }
    if (vfs_truncate(g_swap_node, size_bytes) != 0) {
        log_printf("swap: truncate failed\n");
        g_swap_node = -1;
        return -3;
    }

    g_swap_size = size_bytes;
    g_swap_slots = (uint32_t)(g_swap_size / slot_bytes());
    uint64_t bitmap_bytes = (g_swap_slots + 7u) / 8u;
    g_swap_bitmap = (uint8_t *)kmalloc(bitmap_bytes);
    if (!g_swap_bitmap) {
        g_swap_node = -1;
        g_swap_slots = 0;
        return -4;
    }
    for (uint64_t i = 0; i < bitmap_bytes; ++i) g_swap_bitmap[i] = 0;
    log_printf("swap: enabled %u slots (%u KB)\n",
               (unsigned)g_swap_slots,
               (unsigned)(g_swap_size / 1024u));
    return 0;
}

int swap_alloc(uint32_t *out_slot) {
    if (!swap_enabled() || !out_slot) return -1;
    for (uint32_t s = 0; s < g_swap_slots; ++s) {
        if (!bitmap_test(s)) {
            bitmap_set(s);
            *out_slot = s;
            return 0;
        }
    }
    return -2;
}

void swap_free(uint32_t slot) {
    if (!swap_enabled() || slot >= g_swap_slots) return;
    bitmap_clear(slot);
}

int swap_write(uint32_t slot, const void *buf) {
    if (!swap_enabled() || !buf || slot >= g_swap_slots) return -1;
    uint64_t off = (uint64_t)slot * (uint64_t)slot_bytes();
    int rc = vfs_write_file(g_swap_node, (const uint8_t *)buf, slot_bytes(), off);
    return (rc < 0) ? -2 : 0;
}

int swap_read(uint32_t slot, void *buf) {
    if (!swap_enabled() || !buf || slot >= g_swap_slots) return -1;
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(g_swap_node, &data, &size) || !data) return -2;
    uint64_t off = (uint64_t)slot * (uint64_t)slot_bytes();
    if (off + slot_bytes() > size) return -3;
    const uint8_t *src = data + off;
    uint8_t *dst = (uint8_t *)buf;
    for (uint32_t i = 0; i < slot_bytes(); ++i) dst[i] = src[i];
    return 0;
}
