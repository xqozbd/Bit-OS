#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>

void timer_init(void);
void timer_pit_tick(void);
void timer_apic_tick(void);
uint64_t timer_uptime_ticks(void);

#endif /* TIMER_H */
