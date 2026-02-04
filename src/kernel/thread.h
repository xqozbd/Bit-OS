#ifndef KERNEL_THREAD_H
#define KERNEL_THREAD_H

#include <stddef.h>
#include <stdint.h>

#include "lib/compat.h"

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
    const char *name;
};

struct thread *thread_current(void);
struct thread *thread_create(void (*entry)(void *), void *arg, size_t stack_size, const char *name);
void thread_exit(void) __attribute__((noreturn));

#endif /* KERNEL_THREAD_H */
