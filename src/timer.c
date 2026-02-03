#include "timer.h"

#include "apic.h"
#include "monitor.h"
#include "pic.h"
#include "pit.h"

static uint64_t g_ticks = 0;

void timer_init(void) {
    pic_remap(0x20, 0x28);
    pic_clear_mask(0); /* enable PIT IRQ0 */
    pit_init(100);     /* 100 Hz */
    (void)apic_init(0x40, 10000000u);
}

void timer_pit_tick(void) {
    g_ticks++;
    monitor_tick();
}

void timer_apic_tick(void) {
    g_ticks++;
    monitor_tick();
}

uint64_t timer_uptime_ticks(void) {
    return g_ticks;
}
