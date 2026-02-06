#ifndef KERNEL_THREAD_H
#define KERNEL_THREAD_H

#include <stddef.h>
#include <stdint.h>

#include "lib/compat.h"

struct task;

enum thread_state {
    THREAD_READY = 0,
    THREAD_RUNNING = 1,
    THREAD_BLOCKED = 2,
    THREAD_DEAD = 3,
    THREAD_IDLE = 4
};

struct cpu_context {
    uint64_t rsp;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
};

struct thread {
    struct cpu_context ctx;
    struct thread *next;
    void (*entry)(void *arg);
    void *arg;
    uint8_t *stack;
    size_t stack_size;
    uint32_t cpu;
    uint32_t id;
    uint32_t state;
    uint32_t base_prio;
    uint32_t dyn_prio;
    uint64_t cpu_ticks;
    uint64_t last_run_tick;
    uint64_t mem_current;
    uint64_t mem_peak;
    uint64_t pml4_phys;
    struct thread *sleep_next;
    uint64_t sleep_wake_tick;
    uint8_t is_user;
    const char *name;
    struct task *task;
};

struct thread *thread_current(void);
struct thread *thread_create(void (*entry)(void *), void *arg, size_t stack_size, const char *name);
void thread_exit(void) __attribute__((noreturn));
int thread_join(struct thread *t);
void thread_account_alloc(struct thread *t, size_t bytes);
void thread_account_free(struct thread *t, size_t bytes);

#endif /* KERNEL_THREAD_H */
