#include "kernel/meminfo.h"
#include "boot/boot_requests.h"

uint64_t get_usable_ram_bytes(void) {
    if (!memmap_request.response) return 0;
    struct limine_memmap_response *resp = memmap_request.response;
    uint64_t total = 0;
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (e && e->type == LIMINE_MEMMAP_USABLE) {
            total += e->length;
        }
    }
    return total;
}

void format_gb_1dp(uint64_t bytes, uint64_t *gb_int, uint64_t *gb_tenths) {
    const uint64_t gb = 1024ull * 1024ull * 1024ull;
    *gb_int = bytes / gb;
    uint64_t rem = bytes % gb;
    *gb_tenths = (rem * 10) / gb;
}
