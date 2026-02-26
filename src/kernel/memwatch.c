#include "kernel/memwatch.h"

#include "kernel/pmm.h"
#include "kernel/heap.h"
#include "kernel/task.h"
#include "kernel/swap.h"
#include "kernel/block.h"
#include "kernel/sleep.h"
#include "kernel/thread.h"
#include "arch/x86_64/timer.h"
#include "sys/boot_params.h"
#include "lib/strutil.h"
#include "lib/log.h"

static volatile int g_memwatch_running = 0;
static volatile int g_memwatch_stop = 0;

static uint64_t memwatch_low_frames(void) {
    uint64_t total = pmm_total_frames();
    uint64_t low = total / 10; /* 10% */
    if (low < 256) low = 256;
    return low;
}

static uint64_t memwatch_crit_frames(void) {
    uint64_t total = pmm_total_frames();
    uint64_t crit = total / 20; /* 5% */
    if (crit < 128) crit = 128;
    return crit;
}

static void memwatch_reclaim(uint64_t freef, uint64_t total) {
    uint64_t low = memwatch_low_frames();
    uint64_t crit = memwatch_crit_frames();
    if (freef > low) return;

    log_printf("memwatch: low memory %u/%u frames free\n",
               (unsigned)freef, (unsigned)total);
    heap_reclaim();
    (void)block_writeback_poll(8);

    uint32_t evicted = 0;
    if (freef <= crit) {
        (void)block_flush_all();
        evicted = (uint32_t)task_reclaim_pages(64);
    } else {
        evicted = (uint32_t)task_reclaim_pages(16);
    }
    if (evicted > 0) {
        log_printf("memwatch: reclaimed %u pages\n", (unsigned)evicted);
    }
}

static void memwatch_thread(void *arg) {
    (void)arg;
    uint64_t last_log_tick = 0;
    while (!g_memwatch_stop) {
        uint64_t total = pmm_total_frames();
        uint64_t freef = pmm_free_frames();
        uint64_t now = timer_uptime_ticks();
        if (freef <= memwatch_low_frames()) {
            if (now - last_log_tick > 100) {
                memwatch_reclaim(freef, total);
                last_log_tick = now;
            } else {
                heap_reclaim();
                (void)task_reclaim_pages(4);
            }
            sleep_ms(250);
        } else {
            sleep_ms(1000);
        }
    }
    g_memwatch_running = 0;
    thread_exit();
}

int memwatch_start(void) {
    if (g_memwatch_running) return 1;
    const char *param = boot_param_get("memwatch");
    if (param && (param[0] == '0' || str_eq(param, "off"))) {
        log_printf("memwatch: disabled by boot param\n");
        return 1;
    }
    g_memwatch_stop = 0;
    if (!thread_create(memwatch_thread, NULL, 4096, "memwatch")) {
        log_printf("memwatch: thread spawn failed\n");
        return 0;
    }
    g_memwatch_running = 1;
    log_printf("memwatch: low=%u crit=%u frames\n",
               (unsigned)memwatch_low_frames(), (unsigned)memwatch_crit_frames());
    return 1;
}

int memwatch_stop(void) {
    if (!g_memwatch_running) return 1;
    g_memwatch_stop = 1;
    return 1;
}

int memwatch_is_running(void) {
    return g_memwatch_running != 0;
}
