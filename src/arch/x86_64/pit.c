#include "arch/x86_64/pit.h"

#include "lib/compat.h"

#define PIT_CH0_DATA 0x40
#define PIT_CMD      0x43

#if defined(__GNUC__) || defined(__clang__)
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}
#else
static inline void outb(uint16_t port, uint8_t val) { (void)port; (void)val; }
#endif

void pit_init(uint32_t hz) {
    if (hz == 0) hz = 100;
    uint32_t divisor = 1193182u / hz;
    if (divisor == 0) divisor = 1;
    outb(PIT_CMD, 0x36); /* ch0, lobyte/hibyte, mode 3 */
    outb(PIT_CH0_DATA, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0_DATA, (uint8_t)((divisor >> 8) & 0xFF));
}
