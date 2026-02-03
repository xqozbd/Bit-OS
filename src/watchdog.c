#include "watchdog.h"

#include <stdint.h>

#include "cpu.h"
#include "log.h"
#include "timer.h"

static volatile uint64_t g_deadline = 0;
static volatile int g_boot_ok = 0;

void watchdog_init(uint32_t timeout_seconds) {
    g_boot_ok = 0;
    if (timeout_seconds == 0) timeout_seconds = 1;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    g_deadline = timer_pit_ticks() + (uint64_t)hz * timeout_seconds;
    log_printf("watchdog: armed (timeout=%us)\n", (unsigned)timeout_seconds);
}

void watchdog_checkpoint_boot_ok(void) {
    g_boot_ok = 1;
}

void watchdog_tick(void) {
    if (g_boot_ok) return;
    if (g_deadline == 0) return;
    if (timer_pit_ticks() >= g_deadline) {
        cpu_disable_interrupts();
        log_printf("\nWATCHDOG: boot timeout, console not ready\n");
        log_printf("System halted.\n");
        halt_forever();
    }
}
