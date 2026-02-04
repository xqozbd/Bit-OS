#ifndef APIC_H
#define APIC_H

#include <stdint.h>

int apic_init(void);
void apic_eoi(void);
void apic_timer_set_periodic(uint8_t vector, uint32_t initial_count);
uint32_t apic_timer_current(void);

#endif /* APIC_H */
