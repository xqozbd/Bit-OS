#include "kernel/thread.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/paging.h"
#include "kernel/heap.h"
#include "kernel/pmm.h"
#include "kernel/sched.h"
#include "kernel/task.h"

static void thread_trampoline(void) {
    struct thread *t = thread_current();
    if (t && t->entry) {
        t->entry(t->arg);
    }
    thread_exit();
}

static uint64_t g_stack_top = 0xffffb00000000000ull;

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static uint8_t *alloc_stack_guarded(size_t size, uint8_t **guard_out, size_t *guard_size_out) {
    size = (size_t)align_up_u64((uint64_t)size, 0x1000ull);
    if (size < 0x1000ull) size = 0x1000ull;
    uint64_t guard_base = g_stack_top - (uint64_t)size - 0x1000ull;
    uint64_t stack_base = guard_base + 0x1000ull;
    for (uint64_t addr = stack_base; addr < stack_base + (uint64_t)size; addr += 0x1000ull) {
        uint64_t phys = pmm_alloc_frame();
        if (!phys) return NULL;
        if (paging_map_4k(addr, phys, PTE_NX) != 0) return NULL;
    }
    g_stack_top = guard_base;
    if (guard_out) *guard_out = (uint8_t *)(uintptr_t)guard_base;
    if (guard_size_out) *guard_size_out = 0x1000ull;
    return (uint8_t *)(uintptr_t)stack_base;
}

struct thread *thread_create(void (*entry)(void *), void *arg, size_t stack_size, const char *name) {
    if (stack_size < 4096) stack_size = 4096;
    struct thread *t = (struct thread *)kmalloc(sizeof(*t));
    if (!t) return NULL;
    uint8_t *guard = NULL;
    size_t guard_size = 0;
    uint8_t *stack = alloc_stack_guarded(stack_size, &guard, &guard_size);
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
    t->stack_guard = guard;
    t->stack_guard_size = guard_size;
    t->cpu = sched_cpu_index();
    t->id = sched_next_tid();
    t->state = THREAD_READY;
    t->base_prio = 2;
    t->dyn_prio = 2;
    t->nice = 0;
    t->cpu_mask = 0;
    t->cpu_ticks = 0;
    t->last_run_tick = 0;
    t->mem_current = 0;
    t->mem_peak = 0;
    t->pml4_phys = paging_pml4_phys();
    fpu_state_init(t->fpu_state);
    t->fpu_valid = 1;
    t->is_user = 0;
    t->name = name;
    t->task = NULL;
    task_create_for_thread(t, name);
    if (t->task) {
        t->nice = t->task->nice;
        t->cpu_mask = t->task->cpu_mask;
        sched_set_nice(t, t->nice);
        sched_set_affinity(t, t->cpu_mask);
    }

    sched_enqueue(t);
    return t;
}

int thread_is_stack_guard_fault(struct thread *t, uint64_t addr) {
    if (!t || !t->stack_guard || t->stack_guard_size == 0) return 0;
    uint64_t base = (uint64_t)(uintptr_t)t->stack_guard;
    return addr >= base && addr < (base + (uint64_t)t->stack_guard_size);
}

void thread_exit(void) {
    struct thread *t = thread_current();
    if (t) {
        t->state = THREAD_DEAD;
        task_on_thread_exit(t);
    }
    for (;;) {
        sched_yield();
        cpu_idle();
    }
}

int thread_join(struct thread *t) {
    if (!t) return -1;
    /* Spin-yield until target is dead. */
    while (t->state != THREAD_DEAD) {
        sched_yield();
    }
    return 0;
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
