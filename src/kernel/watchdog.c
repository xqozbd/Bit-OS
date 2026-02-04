#include "kernel/watchdog.h"

#include <stdint.h>

#include "arch/x86_64/cpu.h"
#include "lib/log.h"
#include "arch/x86_64/timer.h"

static volatile uint64_t g_deadline = 0;
static volatile int g_boot_ok = 0;
static const char *g_last_stage = "start";
static volatile uint64_t g_last_tick = 0;
static volatile uint32_t g_timeout_s = 1;

void watchdog_early_stage(const char *stage) {
    if (!stage) stage = "(null)";
    g_last_stage = stage;
    g_last_tick = 0;
}

const char *watchdog_last_stage(void) {
    return g_last_stage ? g_last_stage : "(null)";
}

void watchdog_init(uint32_t timeout_seconds) {
    g_boot_ok = 0;
    if (timeout_seconds == 0) timeout_seconds = 1;
    g_timeout_s = timeout_seconds;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    g_deadline = timer_pit_ticks() + (uint64_t)hz * timeout_seconds;
    g_last_stage = "watchdog_init";
    g_last_tick = timer_pit_ticks();
    log_printf("watchdog: armed (timeout=%us)\n", (unsigned)timeout_seconds);
}

void watchdog_checkpoint_boot_ok(void) {
    g_boot_ok = 1;
}

void watchdog_checkpoint(const char *stage) {
    if (!stage) stage = "(null)";
    g_last_stage = stage;
    g_last_tick = timer_pit_ticks();
}

void watchdog_log_stage(const char *stage) {
    if (!stage) stage = "(null)";
    log_printf("watchdog: stage=%s\n", stage);
}

void watchdog_tick(void) {
    if (g_boot_ok) return;
    if (g_deadline == 0) return;
    if (timer_pit_ticks() >= g_deadline) {
        cpu_disable_interrupts();
        uint32_t hz = timer_pit_hz();
        if (hz == 0) hz = 100;
        log_printf("\nWATCHDOG: boot timeout\n");
        log_printf("stage: %s\n", g_last_stage ? g_last_stage : "(null)");
        log_printf("ticks: now=%u last=%u hz=%u timeout=%us\n",
                   (unsigned)timer_pit_ticks(),
                   (unsigned)g_last_tick,
                   (unsigned)hz,
                   (unsigned)g_timeout_s);
        log_printf("System halted.\n");
        halt_forever();
    }
}
