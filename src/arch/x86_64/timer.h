#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

void timer_init(void);
void timer_pit_tick(void);
void timer_apic_tick(void);
uint64_t timer_uptime_ticks(void);
uint64_t timer_pit_ticks(void);
uint32_t timer_pit_hz(void);
int timer_switch_to_apic(uint32_t target_hz);

#endif /* TIMER_H */
