#include <stdint.h>

static inline uint64_t sys_call(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3) {
    uint64_t ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

__attribute__((noreturn))
void _start(void) {
    const char msg[] = "BitOS init running\n";
    (void)sys_call(1, (uint64_t)msg, (uint64_t)(sizeof(msg) - 1), 0);
    for (;;) {
        (void)sys_call(3, 1000, 0, 0);
    }
}
