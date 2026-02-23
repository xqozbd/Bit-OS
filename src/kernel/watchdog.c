#include "kernel/watchdog.h"

#include <stdint.h>

#include "arch/x86_64/cpu.h"
#include "lib/log.h"
#include "arch/x86_64/timer.h"
#include "kernel/power.h"

static volatile uint64_t g_deadline = 0;
static volatile int g_boot_ok = 0;
static const char *g_last_stage = "start";
static volatile uint64_t g_last_tick = 0;
static volatile uint32_t g_timeout_s = 1;
static int g_mode = 0; /* 0=halt,1=reboot,2=log,3=off */

static int mode_from_str(const char *mode) {
    if (!mode) return 0;
    if (mode[0] == 'o' && mode[1] == 'f' && mode[2] == 'f' && mode[3] == '\0') return 3;
    if (mode[0] == 'l' && mode[1] == 'o' && mode[2] == 'g' && mode[3] == '\0') return 2;
    if (mode[0] == 'r' && mode[1] == 'e' && mode[2] == 'b' && mode[3] == 'o'
        && mode[4] == 'o' && mode[5] == 't' && mode[6] == '\0') return 1;
    if (mode[0] == 'h' && mode[1] == 'a' && mode[2] == 'l' && mode[3] == 't' && mode[4] == '\0') return 0;
    return 0;
}

void watchdog_set_mode(const char *mode) {
    g_mode = mode_from_str(mode);
}

int watchdog_get_mode(void) {
    return g_mode;
}

void watchdog_early_stage(const char *stage) {
    if (g_mode == 3) return;
    if (!stage) stage = "(null)";
    g_last_stage = stage;
    g_last_tick = 0;
}

const char *watchdog_last_stage(void) {
    return g_last_stage ? g_last_stage : "(null)";
}

void watchdog_init(uint32_t timeout_seconds) {
    if (g_mode == 3) return;
    g_boot_ok = 0;
    if (timeout_seconds == 0) timeout_seconds = 1;
    g_timeout_s = timeout_seconds;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    g_deadline = timer_pit_ticks() + (uint64_t)hz * timeout_seconds;
    g_last_stage = "watchdog_init";
    g_last_tick = timer_pit_ticks();
    if (g_mode != 2) {
        log_printf("watchdog: armed (timeout=%us)\n", (unsigned)timeout_seconds);
    }
}

void watchdog_checkpoint_boot_ok(void) {
    if (g_mode == 3) return;
    g_boot_ok = 1;
}

void watchdog_checkpoint(const char *stage) {
    if (g_mode == 3) return;
    if (!stage) stage = "(null)";
    g_last_stage = stage;
    g_last_tick = timer_pit_ticks();
}

void watchdog_log_stage(const char *stage) {
    if (g_mode == 3) return;
    if (!stage) stage = "(null)";
    if (log_is_verbose()) {
        log_printf("watchdog: stage=%s\n", stage);
    }
}

void watchdog_tick(void) {
    if (g_mode == 3) return;
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
        if (g_mode == 2) {
            log_printf("watchdog: log-only, continuing\n");
            g_deadline = 0;
            cpu_enable_interrupts();
            return;
        }
        if (g_mode == 1) {
            log_printf("watchdog: rebooting\n");
            power_restart();
        }
        log_printf("System halted.\n");
        halt_forever();
    }
}
