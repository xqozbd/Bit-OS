#ifndef APIC_H
#define APIC_H

#include <stdint.h>

int apic_init(uint8_t timer_vector, uint32_t initial_count);
void apic_eoi(void);

#endif /* APIC_H */
