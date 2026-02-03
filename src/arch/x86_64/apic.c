#include "arch/x86_64/apic.h"

#include "lib/compat.h"
#include "arch/x86_64/paging.h"

#define IA32_APIC_BASE_MSR 0x1B
#define APIC_ENABLE 0x800

#define APIC_REG_EOI     0x0B0
#define APIC_REG_SVR     0x0F0
#define APIC_REG_LVT_TMR 0x320
#define APIC_REG_TMRDIV  0x3E0
#define APIC_REG_TMRINIT 0x380

static volatile uint32_t *g_apic = 0;

static inline uint64_t rdmsr(uint32_t msr) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
#else
    (void)msr;
    return 0;
#endif
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo = (uint32_t)(val & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile ("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
#else
    (void)msr; (void)val;
#endif
}

static inline void apic_write(uint32_t reg, uint32_t val) {
    g_apic[reg / 4] = val;
}

int apic_init(uint8_t timer_vector, uint32_t initial_count) {
    uint64_t apic_base = rdmsr(IA32_APIC_BASE_MSR);
    apic_base |= APIC_ENABLE;
    wrmsr(IA32_APIC_BASE_MSR, apic_base);
    uint64_t phys = apic_base & 0xFFFFF000ull;
    uint64_t hhdm = paging_hhdm_offset();
    g_apic = (volatile uint32_t *)(uintptr_t)(hhdm + phys);

    if (!g_apic) return -1;

    apic_write(APIC_REG_SVR, 0x100u | 0xFFu);
    apic_write(APIC_REG_TMRDIV, 0x3); /* divide by 16 */
    apic_write(APIC_REG_LVT_TMR, 0x20000u | timer_vector); /* periodic */
    apic_write(APIC_REG_TMRINIT, initial_count);
    return 0;
}

void apic_eoi(void) {
    if (!g_apic) return;
    apic_write(APIC_REG_EOI, 0);
}
