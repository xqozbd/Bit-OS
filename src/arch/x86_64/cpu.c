#include "lib/compat.h"
#include "arch/x86_64/cpu.h"
#include <stdint.h>

/* Enable SSE so GCC-generated interrupt prologues don't fault */
void cpu_enable_sse(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t cr0, cr4;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1ULL << 2); /* CR0.EM = 0 */
    cr0 |=  (1ULL << 1); /* CR0.MP = 1 */
    __asm__ volatile ("mov %0, %%cr0" : : "r"(cr0));

    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 9);  /* CR4.OSFXSR = 1 */
    cr4 |= (1ULL << 10); /* CR4.OSXMMEXCPT = 1 */
    __asm__ volatile ("mov %0, %%cr4" : : "r"(cr4));
#else
    /* no-op for IntelliSense / non-GNU builds */
#endif
}
