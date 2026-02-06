#ifndef CPU_H
#define CPU_H

#include <stdint.h>
#include "lib/compat.h"

#if defined(__GNUC__) || defined(__clang__)
#define HALT() __asm__ volatile("hlt")
#else
#define HALT() do {} while (0)
#endif

static inline void halt_forever(void) {
    for (;;) { HALT(); }
}

void cpu_enable_sse(void);
#if defined(__GNUC__) || defined(__clang__)
static inline void cpu_enable_interrupts(void) { __asm__ volatile("sti"); }
static inline void cpu_disable_interrupts(void) { __asm__ volatile("cli"); }
static inline void cpu_pause(void) { __asm__ volatile("pause"); }
static inline void cpu_idle(void) {
    cpu_enable_interrupts();
    HALT(); /* C1 idle */
}
static inline uint64_t cpu_read_msr(uint32_t msr) {
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}
static inline void cpu_write_msr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)(val & 0xFFFFFFFFu);
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}
static inline uint64_t cpu_read_cr3(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}
#else
static inline void cpu_enable_interrupts(void) {}
static inline void cpu_disable_interrupts(void) {}
static inline void cpu_pause(void) {}
static inline void cpu_idle(void) {}
static inline uint64_t cpu_read_msr(uint32_t msr) { (void)msr; return 0; }
static inline void cpu_write_msr(uint32_t msr, uint64_t val) { (void)msr; (void)val; }
static inline uint64_t cpu_read_cr3(void) { return 0; }
#endif

#endif /* CPU_H */
