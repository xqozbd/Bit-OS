#include "arch/x86_64/timer.h"

#include <stddef.h>

#include "arch/x86_64/apic.h"
#include "arch/x86_64/cpu.h"
#include "kernel/monitor.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/pit.h"
#include "kernel/watchdog.h"
#include "drivers/ps2/keyboard.h"
#include "lib/log.h"

static volatile uint64_t g_ticks = 0;
static volatile uint64_t g_pit_ticks = 0;
static volatile uint64_t g_apic_ticks = 0;
static uint32_t g_pit_hz = 100;
static uint32_t g_apic_hz = 0;
static int g_use_apic = 0;

void timer_init(void) {
    pic_remap(0x20, 0x28);
    g_pit_hz = 100;
    pit_init(g_pit_hz); /* 100 Hz */
    pic_clear_mask(0); /* enable PIT IRQ0 */
    (void)apic_init();
}

void timer_pit_tick(void) {
    g_pit_ticks++;
    if (!g_use_apic) {
        g_ticks++;
        monitor_tick();
        kb_tick();
        watchdog_tick();
    }
}

void timer_apic_tick(void) {
    g_ticks++;
    g_apic_ticks++;
    g_pit_ticks++;
    monitor_tick();
    kb_tick();
    watchdog_tick();
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

static int wait_pit_tick_advance(uint64_t *out_start) {
    uint64_t start = timer_pit_ticks();
    for (uint32_t i = 0; i < 5000000u; ++i) {
        if (timer_pit_ticks() != start) {
            if (out_start) *out_start = timer_pit_ticks();
            return 1;
        }
        cpu_pause();
    }
    return 0;
}

int timer_switch_to_apic(uint32_t target_hz) {
    if (g_use_apic) return 1;
    if (target_hz == 0) target_hz = g_pit_hz;
    if (target_hz == 0) target_hz = 100;
    if (!wait_pit_tick_advance(NULL)) {
        log_printf("timer: PIT not ticking, cannot calibrate APIC (keeping PIT)\n");
        return 0;
    }

    uint64_t start_tick = timer_pit_ticks();
    uint32_t sample_ticks = g_pit_hz / 10;
    if (sample_ticks == 0) sample_ticks = 1;
    uint64_t target = start_tick + sample_ticks;

    apic_timer_set_periodic(0x40, 0xFFFFFFFFu);
    uint32_t start_cnt = apic_timer_current();
    uint64_t guard = start_tick + (uint64_t)g_pit_hz * 2;
    while (timer_pit_ticks() < target) {
        if (timer_pit_ticks() > guard) {
            log_printf("timer: APIC calibration timeout (keeping PIT)\n");
            return 0;
        }
    }
    uint32_t end_cnt = apic_timer_current();
    if (start_cnt <= end_cnt) {
        log_printf("timer: APIC calibration failed (counter)\n");
        return 0;
    }

    uint32_t delta = start_cnt - end_cnt;
    uint64_t apic_hz = (uint64_t)delta * (uint64_t)g_pit_hz / (uint64_t)sample_ticks;
    if (apic_hz == 0) {
        log_printf("timer: APIC calibration failed (hz=0)\n");
        return 0;
    }
    g_apic_hz = (uint32_t)apic_hz;
    uint32_t initial = (uint32_t)(apic_hz / target_hz);
    if (initial == 0) initial = 1;
    apic_timer_set_periodic(0x40, initial);
    g_use_apic = 1;
    pic_set_mask(0); /* stop PIT IRQ0 once APIC is running */
    log_printf("timer: APIC enabled (hz=%u, tick=%u Hz)\n",
               (unsigned)g_apic_hz, (unsigned)target_hz);
    return 1;
}
