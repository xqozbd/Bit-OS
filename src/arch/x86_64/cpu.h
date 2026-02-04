#ifndef CPU_H
#define CPU_H

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
#else
static inline void cpu_enable_interrupts(void) {}
static inline void cpu_disable_interrupts(void) {}
static inline void cpu_pause(void) {}
#endif

#endif /* CPU_H */
