#ifndef CPU_H
#define CPU_H

#include "compat.h"

#if defined(__GNUC__) || defined(__clang__)
#define HALT() __asm__ volatile("hlt")
#else
#define HALT() do {} while (0)
#endif

static inline void halt_forever(void) {
    for (;;) { HALT(); }
}

void cpu_enable_sse(void);

#endif /* CPU_H */
