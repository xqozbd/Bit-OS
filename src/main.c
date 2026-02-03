#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>
#include "fb_printf.h"
/*
Limine boot bullshit
*/
__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[] = LIMINE_BASE_REVISION(4);

__attribute__((used, section(".limine_requests")))
static volatile struct limine_framebuffer_request framebuffer_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0
};

__attribute__((used, section(".limine_requests")))
static volatile struct limine_mp_request mp_request = {
    .id = LIMINE_MP_REQUEST_ID,
    .revision = 0,
    .flags = 0
};

__attribute__((used, section(".limine_requests_start")))
static volatile uint64_t limine_requests_start_marker[] = LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests_end")))
static volatile uint64_t limine_requests_end_marker[] = LIMINE_REQUESTS_END_MARKER;


void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
    uint8_t *restrict pdest = (uint8_t *restrict)dest;
    const uint8_t *restrict psrc = (const uint8_t *restrict)src;

    for (size_t i = 0; i < n; i++) {
        pdest[i] = psrc[i];
    }

    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;

    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }

    return s;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *pdest = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    if (src > dest) {
        for (size_t i = 0; i < n; i++) {
            pdest[i] = psrc[i];
        }
    } else if (src < dest) {
        for (size_t i = n; i > 0; i--) {
            pdest[i-1] = psrc[i-1];
        }
    }

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }

    return 0;
}

/* Kernel halt (avoid IntelliSense errors on non-GNU compilers) */
#if defined(__GNUC__) || defined(__clang__)
#define HALT() __asm__ volatile("hlt")
#else
#define HALT() do {} while (0)
#endif

static uint64_t get_usable_ram_bytes(void) {
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

static void format_gb_1dp(uint64_t bytes, uint64_t *gb_int, uint64_t *gb_tenths) {
    const uint64_t gb = 1024ull * 1024ull * 1024ull;
    *gb_int = bytes / gb;
    uint64_t rem = bytes % gb;
    *gb_tenths = (rem * 10) / gb;
}




void kmain(void) {
    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        for (;;) { HALT(); }
    }

    if (framebuffer_request.response == NULL || framebuffer_request.response->framebuffer_count < 1) {
        /* If no framebuffer, hang or fallback to text mode. */
        for (;;) { HALT(); }
    }

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];

    /* Initialize fb_printf with white on black */
    fb_init(fb, 0xE6E6E6, 0x0B0F14);
    fb_set_layout_ex(3, 4, 24, 24, 4, 2);

    fb_printf("Hello BitOS!\n");
    fb_printf("Width: %u Height: %u Pitch: %u BPP: %u\n",
              (unsigned)fb->width, (unsigned)fb->height, (unsigned)fb->pitch, (unsigned)fb->bpp);

    /* test formatters */
    fb_printf("int: %d hex: %x ptr: %p string: %s char: %c\n", -42, 0xABCD, fb, "hi!", 'A');

    uint64_t ram_bytes = get_usable_ram_bytes();
    if (ram_bytes > 0) {
        uint64_t gb_int = 0, gb_tenths = 0;
        format_gb_1dp(ram_bytes, &gb_int, &gb_tenths);
        fb_printf("Usable RAM: %u.%u GB\n", (unsigned)gb_int, (unsigned)gb_tenths);
    } else {
        fb_printf("Usable RAM: unknown\n");
    }

    if (mp_request.response) {
        fb_printf("CPU cores: %u\n", (unsigned)mp_request.response->cpu_count);
    } else {
        fb_printf("CPU cores: unknown\n");
    }

    for (;;) { HALT(); }
}
