#include "arch/x86_64/timer.h"

#include "arch/x86_64/apic.h"
#include "kernel/monitor.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/pit.h"
#include "kernel/watchdog.h"
#include "drivers/ps2/keyboard.h"

static uint64_t g_ticks = 0;
static uint64_t g_pit_ticks = 0;
static uint64_t g_apic_ticks = 0;
static uint32_t g_pit_hz = 100;

void timer_init(void) {
    pic_remap(0x20, 0x28);
    pic_clear_mask(0); /* enable PIT IRQ0 */
    g_pit_hz = 100;
    pit_init(g_pit_hz); /* 100 Hz */
    (void)apic_init(0x40, 10000000u);
}

void timer_pit_tick(void) {
    g_ticks++;
    g_pit_ticks++;
    monitor_tick();
    kb_tick();
    watchdog_tick();
}

void timer_apic_tick(void) {
    g_ticks++;
    g_apic_ticks++;
    monitor_tick();
}

uint64_t timer_uptime_ticks(void) {
    return g_ticks;
}

uint64_t timer_pit_ticks(void) {
    return g_pit_ticks;
}

uint32_t timer_pit_hz(void) {
    return g_pit_hz;
}
