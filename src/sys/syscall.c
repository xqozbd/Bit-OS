#include "sys/syscall.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "lib/log.h"

static uint64_t sys_write(const char *buf, uint64_t len) {
    if (!buf || len == 0) return 0;
    if (len > 4096) len = 4096;
    for (uint64_t i = 0; i < len; ++i) {
        log_printf("%c", buf[i]);
    }
    return len;
}

static uint64_t sys_exit(uint64_t code) {
    log_printf("\n[sys_exit] code=%u\n", (unsigned)code);
    halt_forever();
    return 0;
}

uint64_t syscall_dispatch(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    switch (num) {
        case SYS_WRITE: return sys_write((const char *)a1, a2);
        case SYS_EXIT:  return sys_exit(a1);
        default:        return (uint64_t)-1;
    }
}

uint64_t syscall_handler(struct syscall_frame *f) {
    if (!f) return (uint64_t)-1;
    return syscall_dispatch(f->rax, f->rdi, f->rsi, f->rdx, f->r10, f->r8, f->r9);
}

__attribute__((naked))
void isr_syscall(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "push %r15\n"
        "push %r14\n"
        "push %r13\n"
        "push %r12\n"
        "push %r11\n"
        "push %r10\n"
        "push %r9\n"
        "push %r8\n"
        "push %rsi\n"
        "push %rdi\n"
        "push %rbp\n"
        "push %rdx\n"
        "push %rcx\n"
        "push %rbx\n"
        "push %rax\n"
        "mov %rsp, %rdi\n"
        "call syscall_handler\n"
        "mov %rax, (%rsp)\n"
        "pop %rax\n"
        "pop %rbx\n"
        "pop %rcx\n"
        "pop %rdx\n"
        "pop %rbp\n"
        "pop %rdi\n"
        "pop %rsi\n"
        "pop %r8\n"
        "pop %r9\n"
        "pop %r10\n"
        "pop %r11\n"
        "pop %r12\n"
        "pop %r13\n"
        "pop %r14\n"
        "pop %r15\n"
        "iretq\n"
    );
#else
    (void)syscall_handler;
    halt_forever();
#endif
}
