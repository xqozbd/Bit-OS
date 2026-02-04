#include "kernel/thread.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "kernel/heap.h"
#include "kernel/sched.h"

static void thread_trampoline(void) {
    struct thread *t = thread_current();
    if (t && t->entry) {
        t->entry(t->arg);
    }
    thread_exit();
}

struct thread *thread_create(void (*entry)(void *), void *arg, size_t stack_size, const char *name) {
    if (stack_size < 4096) stack_size = 4096;
    struct thread *t = (struct thread *)kmalloc(sizeof(*t));
    if (!t) return NULL;
    uint8_t *stack = (uint8_t *)kmalloc(stack_size);
    if (!stack) {
        kfree(t);
        return NULL;
    }

    uintptr_t sp = (uintptr_t)stack + stack_size;
    sp &= ~0xFULL;
    sp -= 8;
    *(uint64_t *)sp = (uint64_t)thread_trampoline;

    t->ctx.rsp = sp;
    t->ctx.rbx = 0;
    t->ctx.rbp = 0;
    t->ctx.r12 = 0;
    t->ctx.r13 = 0;
    t->ctx.r14 = 0;
    t->ctx.r15 = 0;

    t->next = NULL;
    t->entry = entry;
    t->arg = arg;
    t->stack = stack;
    t->stack_size = stack_size;
    t->cpu = sched_cpu_index();
    t->id = sched_next_tid();
    t->state = THREAD_READY;
    t->base_prio = 2;
    t->dyn_prio = 2;
    t->cpu_ticks = 0;
    t->last_run_tick = 0;
    t->mem_current = 0;
    t->mem_peak = 0;
    t->name = name;

    sched_enqueue(t);
    return t;
}

void thread_exit(void) {
    struct thread *t = thread_current();
    if (t) {
        t->state = THREAD_DEAD;
    }
    sched_yield();
    halt_forever();
    __builtin_unreachable();
}

void thread_account_alloc(struct thread *t, size_t bytes) {
    if (!t || bytes == 0) return;
    t->mem_current += bytes;
    if (t->mem_current > t->mem_peak) {
        t->mem_peak = t->mem_current;
    }
}

void thread_account_free(struct thread *t, size_t bytes) {
    if (!t || bytes == 0) return;
    if (t->mem_current >= bytes) {
        t->mem_current -= bytes;
    } else {
        t->mem_current = 0;
    }
}
