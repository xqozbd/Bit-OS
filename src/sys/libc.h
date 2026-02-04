#ifndef SYS_LIBC_H
#define SYS_LIBC_H

#include <stddef.h>
#include <stdint.h>

static inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(__GNUC__) || defined(__clang__)
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
                     : "rcx", "r11", "memory");
    return ret;
#else
    (void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return -1;
#endif
}

static inline long sys_write(const void *buf, size_t len) {
    return __syscall6(1, (long)buf, (long)len, 0, 0, 0, 0);
}

static inline long sys_exit(int code) {
    return __syscall6(2, (long)code, 0, 0, 0, 0, 0);
}

static inline long sys_sleep_ms(uint64_t ms) {
    return __syscall6(3, (long)ms, 0, 0, 0, 0, 0);
}

#endif /* SYS_LIBC_H */
