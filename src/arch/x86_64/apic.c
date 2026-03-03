#include "arch/x86_64/apic.h"

#include "lib/compat.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/cpu.h"
#include "sys/boot_params.h"
#include "lib/strutil.h"

#define IA32_APIC_BASE_MSR 0x1B
#define APIC_ENABLE 0x800
#define APIC_X2APIC_ENABLE (1ull << 10)
#define APIC_GLOBAL_ENABLE (1ull << 11)

#define APIC_REG_EOI     0x0B0
#define APIC_REG_SVR     0x0F0
#define APIC_REG_TPR     0x080
#define APIC_REG_LVT_TMR 0x320
#define APIC_REG_TMRDIV  0x3E0
#define APIC_REG_TMRINIT 0x380
#define APIC_REG_TMRCUR  0x390

/* x2APIC MSR base */
#define X2APIC_MSR_BASE 0x800
#define X2APIC_MSR(reg) (X2APIC_MSR_BASE + ((reg) >> 4))
#define X2APIC_MSR_TPR    X2APIC_MSR(APIC_REG_TPR)
#define X2APIC_MSR_EOI    X2APIC_MSR(APIC_REG_EOI)
#define X2APIC_MSR_SVR    X2APIC_MSR(APIC_REG_SVR)
#define X2APIC_MSR_LVT_TMR X2APIC_MSR(APIC_REG_LVT_TMR)
#define X2APIC_MSR_TMRDIV X2APIC_MSR(APIC_REG_TMRDIV)
#define X2APIC_MSR_TMRINIT X2APIC_MSR(APIC_REG_TMRINIT)
#define X2APIC_MSR_TMRCUR X2APIC_MSR(APIC_REG_TMRCUR)

static volatile uint32_t *g_apic = 0;
static int g_x2apic = 0;

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                          uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("cpuid"
                      : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                      : "a"(leaf), "c"(subleaf));
#else
    *a = *b = *c = *d = 0;
    (void)leaf; (void)subleaf;
#endif
}

static inline void apic_write(uint32_t reg, uint32_t val) {
    if (g_x2apic) {
        cpu_write_msr(X2APIC_MSR(reg), (uint64_t)val);
        return;
    }
    g_apic[reg / 4] = val;
}

static inline uint32_t apic_read(uint32_t reg) {
    if (g_x2apic) {
        return (uint32_t)cpu_read_msr(X2APIC_MSR(reg));
    }
    return g_apic[reg / 4];
}

int apic_init(void) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    cpuid(1, 0, &a, &b, &c, &d);
    int has_x2apic = (c & (1u << 21)) != 0;
    const char *param = boot_param_get("x2apic");
    int force_off = (param && (param[0] == '0' || str_eq(param, "off")));
    int force_on = (param && (param[0] == '1' || str_eq(param, "on")));

    uint64_t apic_base = cpu_read_msr(IA32_APIC_BASE_MSR);
    int pre_x2 = (apic_base & APIC_X2APIC_ENABLE) != 0;
    apic_base |= APIC_GLOBAL_ENABLE;

    if ((has_x2apic && !force_off) || pre_x2) {
        apic_base |= APIC_X2APIC_ENABLE;
        cpu_write_msr(IA32_APIC_BASE_MSR, apic_base);
        g_x2apic = 1;
        g_apic = 0;
    } else if (force_on && !has_x2apic) {
        /* cannot honor */
        apic_base &= ~APIC_X2APIC_ENABLE;
        cpu_write_msr(IA32_APIC_BASE_MSR, apic_base);
        g_x2apic = 0;
    } else {
        apic_base &= ~APIC_X2APIC_ENABLE;
        apic_base |= APIC_ENABLE;
        cpu_write_msr(IA32_APIC_BASE_MSR, apic_base);
        uint64_t phys = apic_base & 0xFFFFF000ull;
        uint64_t hhdm = paging_hhdm_offset();
        g_apic = (volatile uint32_t *)(uintptr_t)(hhdm + phys);
        if (!g_apic) return -1;
    }

    apic_write(APIC_REG_SVR, 0x100u | 0xFFu);
    return 0;
}

void apic_eoi(void) {
    if (!g_apic && !g_x2apic) return;
    apic_write(APIC_REG_EOI, 0);
}

void apic_timer_set_periodic(uint8_t vector, uint32_t initial_count) {
    if (!g_apic && !g_x2apic) return;
    apic_write(APIC_REG_TMRDIV, 0x3); /* divide by 16 */
    apic_write(APIC_REG_LVT_TMR, 0x20000u | vector); /* periodic */
    apic_write(APIC_REG_TMRINIT, initial_count);
}

uint32_t apic_timer_current(void) {
    if (!g_apic && !g_x2apic) return 0;
    return apic_read(APIC_REG_TMRCUR);
}

int apic_is_ready(void) {
    return g_apic != 0 || g_x2apic != 0;
}

void apic_set_tpr(uint8_t tpr) {
    if (!g_apic && !g_x2apic) return;
    apic_write(APIC_REG_TPR, (uint32_t)tpr);
}

int apic_is_x2apic(void) {
    return g_x2apic != 0;
}
