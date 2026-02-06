#ifndef IRQ_H
#define IRQ_H

#include <stdint.h>

void irq_mask(uint8_t irq);
void irq_unmask(uint8_t irq);
void irq_set_priority(uint8_t tpr);
void irq_route_legacy(uint8_t irq, uint8_t vector);

#endif /* IRQ_H */
