#include "sys/syscall.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "kernel/sleep.h"
#include "kernel/task.h"
#include "kernel/thread.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "lib/log.h"

typedef uint64_t (*syscall_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t sys_write_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    const char *buf = (const char *)a1;
    uint64_t len = a2;
    if (!buf || len == 0) return 0;
    if (len > 4096) len = 4096;
    for (uint64_t i = 0; i < len; ++i) {
        log_printf("%c", buf[i]);
    }
    return len;
}

static uint64_t sys_exit_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint64_t code = a1;
    log_printf("\n[sys_exit] code=%u\n", (unsigned)code);
    halt_forever();
    return 0;
}

static uint64_t sys_sleep_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    sleep_ms(a1);
    return 0;
}

static uint64_t sys_sbrk_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *task = task_current();
    if (!task || !task->is_user) return (uint64_t)-1;
    int64_t inc = (int64_t)a1;
    uint64_t old = task->brk;
    if (inc == 0) return old;

    uint64_t new_brk;
    if (inc > 0) {
        if (task->brk + (uint64_t)inc < task->brk) return (uint64_t)-1;
        new_brk = task->brk + (uint64_t)inc;
    } else {
        int64_t dec = -inc;
        if (task->brk < task->brk_base + (uint64_t)dec) return (uint64_t)-1;
        new_brk = task->brk - (uint64_t)dec;
    }
    if (new_brk > task->brk_limit) return (uint64_t)-1;

    uint64_t old_page = (old + 0xFFF) & ~0xFFFULL;
    uint64_t new_page = (new_brk + 0xFFF) & ~0xFFFULL;
    if (new_page > old_page) {
        for (uint64_t va = old_page; va < new_page; va += 0x1000ULL) {
            uint64_t phys = pmm_alloc_frame();
            if (phys == 0) return (uint64_t)-1;
            if (paging_map_user_4k(task->pml4_phys, va, phys, 0) != 0) return (uint64_t)-1;
        }
    }
    task->brk = new_brk;
    return old;
}

static syscall_fn g_syscalls[SYS_MAX] = {
    [SYS_WRITE] = sys_write_impl,
    [SYS_EXIT]  = sys_exit_impl,
    [SYS_SLEEP] = sys_sleep_impl,
    [SYS_SBRK]  = sys_sbrk_impl
};

uint64_t syscall_dispatch(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6) {
    if (num >= SYS_MAX) return (uint64_t)-1;
    syscall_fn fn = g_syscalls[num];
    if (!fn) return (uint64_t)-1;
    return fn(a1, a2, a3, a4, a5, a6);
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
