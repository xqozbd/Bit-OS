#include "monitor.h"

#include <stdint.h>

#include "cpu_info.h"
#include "heap.h"
#include "pmm.h"
#include "panic.h"

static uint64_t g_last_tsc = 0;
static uint64_t g_tsc_hz = 0;
static uint64_t g_interval = 0;
static uint32_t g_ticks = 0;

static inline uint64_t rdtsc(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

void monitor_init(void) {
    if (cpu_get_tsc_hz(&g_tsc_hz)) {
        g_interval = g_tsc_hz / 2; /* 500ms */
        g_last_tsc = rdtsc();
    } else {
        g_interval = 0;
    }
    g_ticks = 0;
}

void monitor_tick(void) {
    if (g_interval != 0) {
        uint64_t now = rdtsc();
        if (now - g_last_tsc < g_interval) return;
        g_last_tsc = now;
    } else {
        g_ticks++;
        if ((g_ticks % 1000) != 0) return;
    }

    int heap_rc = heap_check();
    if (heap_rc != 0) {
        panic_screen(0xE001, "Heap corruption detected");
    }
    int pmm_rc = pmm_sanity_check();
    if (pmm_rc != 0) {
        panic_screen(0xE002, "PMM counters invalid");
    }
}
