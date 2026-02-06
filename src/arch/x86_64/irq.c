#include "arch/x86_64/irq.h"

#include "arch/x86_64/apic.h"
#include "arch/x86_64/pic.h"
#include "lib/log.h"

void irq_mask(uint8_t irq) {
    pic_set_mask(irq);
}

void irq_unmask(uint8_t irq) {
    pic_clear_mask(irq);
}

void irq_set_priority(uint8_t tpr) {
    if (!apic_is_ready()) return;
    apic_set_tpr(tpr);
}

void irq_route_legacy(uint8_t irq, uint8_t vector) {
    (void)irq;
    (void)vector;
    if (!apic_is_ready()) return;
    log_printf("IRQ: legacy routing not supported (IOAPIC not initialized)\n");
}
