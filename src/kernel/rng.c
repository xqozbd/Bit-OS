#include "kernel/rng.h"

#include <stdint.h>

#include "arch/x86_64/paging.h"
#include "arch/x86_64/timer.h"
#include "kernel/time.h"

static uint64_t g_rng_state = 0x9e3779b97f4a7c15ull;
static int g_rng_ready = 0;

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

void rng_seed(uint64_t seed) {
    g_rng_state ^= mix64(seed + 0x9e3779b97f4a7c15ull);
    if (g_rng_state == 0) g_rng_state = 0x1d0f5c8c2e1b9a43ull;
    g_rng_ready = 1;
}

void rng_init(void) {
    uint64_t seed = timer_uptime_ticks();
    seed ^= time_now_epoch();
    seed ^= paging_pml4_phys();
    seed ^= (uint64_t)(uintptr_t)&g_rng_state;
    rng_seed(seed);
}

uint64_t rng_next_u64(void) {
    if (!g_rng_ready) rng_init();
    uint64_t x = g_rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

void rng_fill(void *buf, size_t len) {
    if (!buf || len == 0) return;
    uint8_t *out = (uint8_t *)buf;
    while (len > 0) {
        uint64_t v = rng_next_u64();
        for (int i = 0; i < 8 && len > 0; ++i) {
            *out++ = (uint8_t)(v & 0xFFu);
            v >>= 8;
            len--;
        }
    }
}
