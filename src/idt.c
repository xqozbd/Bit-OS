#include <stdint.h>

#include "compat.h"
#include "cpu.h"
#include "idt.h"
#include "log.h"
#include "pic.h"
#include "apic.h"
#include "timer.h"
#include "keyboard.h"

/* IDT + exceptions */
struct interrupt_frame {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static volatile struct idt_entry idt[256];

static inline uint16_t read_cs(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint16_t cs;
    __asm__ volatile ("mov %%cs, %0" : "=r"(cs));
    return cs;
#else
    return 0x08;
#endif
}

static void idt_set_gate(int vec, void *isr) {
    uint64_t addr = (uint64_t)isr;
    idt[vec].offset_low = (uint16_t)(addr & 0xFFFF);
    idt[vec].selector = read_cs();
    idt[vec].ist = 0;
    idt[vec].type_attr = 0x8E;
    idt[vec].offset_mid = (uint16_t)((addr >> 16) & 0xFFFF);
    idt[vec].offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFF);
    idt[vec].zero = 0;
}

static inline void lidt(const struct idt_ptr *p) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("lidt %0" : : "m"(*p) : "memory");
#else
    (void)p;
#endif
}

static void exception_common(uint8_t vec, uint64_t err, int has_err) {
    log_printf("\nEXCEPTION %u", (unsigned)vec);
    if (has_err) log_printf(" err=0x%x", (unsigned)err);
    log_printf("\nSystem halted.\n");
    halt_forever();
}

#define ISR_NOERR(n) \
    __attribute__((interrupt, target("general-regs-only"), used)) void isr_noerr_##n(struct interrupt_frame *frame) { \
        (void)frame; exception_common((uint8_t)n, 0, 0); \
    }

#define ISR_ERR(n) \
    __attribute__((interrupt, target("general-regs-only"), used)) void isr_err_##n(struct interrupt_frame *frame, uint64_t error_code) { \
        (void)frame; exception_common((uint8_t)n, error_code, 1); \
    }

ISR_NOERR(0)  ISR_NOERR(1)  ISR_NOERR(2)  ISR_NOERR(3)
ISR_NOERR(4)  ISR_NOERR(5)  ISR_NOERR(6)  ISR_NOERR(7)
ISR_ERR(8)    ISR_NOERR(9)  ISR_ERR(10)   ISR_ERR(11)
ISR_ERR(12)   ISR_ERR(13)   ISR_ERR(14)   ISR_NOERR(15)
ISR_NOERR(16) ISR_ERR(17)   ISR_NOERR(18) ISR_NOERR(19)
ISR_NOERR(20) ISR_ERR(21)   ISR_NOERR(22) ISR_NOERR(23)
ISR_NOERR(24) ISR_NOERR(25) ISR_NOERR(26) ISR_NOERR(27)
ISR_NOERR(28) ISR_NOERR(29) ISR_NOERR(30) ISR_NOERR(31)

__attribute__((interrupt, target("general-regs-only"), used))
void isr_irq0(struct interrupt_frame *frame) {
    (void)frame;
    timer_pit_tick();
    pic_send_eoi(0);
}

__attribute__((interrupt, target("general-regs-only"), used))
void isr_irq1(struct interrupt_frame *frame) {
    (void)frame;
    kb_irq_handler();
    pic_send_eoi(1);
}

__attribute__((interrupt, target("general-regs-only"), used))
void isr_apic_timer(struct interrupt_frame *frame) {
    (void)frame;
    timer_apic_tick();
    apic_eoi();
}

__attribute__((interrupt, target("general-regs-only"), used))
void isr_spurious(struct interrupt_frame *frame) {
    (void)frame;
    apic_eoi();
}

void idt_init(void) {
    for (int i = 0; i < 256; ++i) {
        idt[i].offset_low = 0;
        idt[i].selector = 0;
        idt[i].ist = 0;
        idt[i].type_attr = 0;
        idt[i].offset_mid = 0;
        idt[i].offset_high = 0;
        idt[i].zero = 0;
    }

    idt_set_gate(0,  isr_noerr_0);
    idt_set_gate(1,  isr_noerr_1);
    idt_set_gate(2,  isr_noerr_2);
    idt_set_gate(3,  isr_noerr_3);
    idt_set_gate(4,  isr_noerr_4);
    idt_set_gate(5,  isr_noerr_5);
    idt_set_gate(6,  isr_noerr_6);
    idt_set_gate(7,  isr_noerr_7);
    idt_set_gate(8,  isr_err_8);
    idt_set_gate(9,  isr_noerr_9);
    idt_set_gate(10, isr_err_10);
    idt_set_gate(11, isr_err_11);
    idt_set_gate(12, isr_err_12);
    idt_set_gate(13, isr_err_13);
    idt_set_gate(14, isr_err_14);
    idt_set_gate(15, isr_noerr_15);
    idt_set_gate(16, isr_noerr_16);
    idt_set_gate(17, isr_err_17);
    idt_set_gate(18, isr_noerr_18);
    idt_set_gate(19, isr_noerr_19);
    idt_set_gate(20, isr_noerr_20);
    idt_set_gate(21, isr_err_21);
    idt_set_gate(22, isr_noerr_22);
    idt_set_gate(23, isr_noerr_23);
    idt_set_gate(24, isr_noerr_24);
    idt_set_gate(25, isr_noerr_25);
    idt_set_gate(26, isr_noerr_26);
    idt_set_gate(27, isr_noerr_27);
    idt_set_gate(28, isr_noerr_28);
    idt_set_gate(29, isr_noerr_29);
    idt_set_gate(30, isr_noerr_30);
    idt_set_gate(31, isr_noerr_31);

    idt_set_gate(32, isr_irq0);
    idt_set_gate(33, isr_irq1);
    idt_set_gate(0x40, isr_apic_timer);
    idt_set_gate(0xFF, isr_spurious);

    struct idt_ptr idtp = { .limit = sizeof(idt) - 1, .base = (uint64_t)&idt };
    lidt(&idtp);
}
