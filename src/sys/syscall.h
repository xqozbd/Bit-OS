#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

enum {
    SYS_WRITE = 1,
    SYS_EXIT  = 2,
    SYS_SLEEP = 3,
    SYS_SBRK  = 4,
    SYS_OPEN  = 5,
    SYS_READ  = 6,
    SYS_CLOSE = 7,
    SYS_FORK  = 8,
    SYS_EXEC  = 9,
    SYS_SIGNAL = 10,
    SYS_KILL   = 11,
    SYS_SOCKET = 12,
    SYS_BIND   = 13,
    SYS_CONNECT = 14,
    SYS_SENDTO = 15,
    SYS_RECVFROM = 16,
    SYS_LISTEN = 17,
    SYS_ACCEPT = 18,
    SYS_SEND = 19,
    SYS_RECV = 20,
    SYS_MMAP = 21,
    SYS_MUNMAP = 22,
    SYS_GETDNS = 23,
    SYS_MAX
};

struct syscall_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
};

void isr_syscall(void);
uint64_t syscall_dispatch(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6);
uint64_t syscall_handler(struct syscall_frame *f);

#endif /* SYSCALL_H */
