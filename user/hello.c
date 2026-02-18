#include "libu.h"

void _start(void) {
    uputs("hello from libu.so\n");
    for (;;) {
        /* exit syscall is not in libu to keep it tiny */
        __asm__ volatile("mov $2, %%rax; xor %%rdi, %%rdi; int $0x80" ::: "rax", "rdi", "memory");
    }
}