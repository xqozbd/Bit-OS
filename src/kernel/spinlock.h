#ifndef KERNEL_SPINLOCK_H
#define KERNEL_SPINLOCK_H

#include <stdint.h>

#include "arch/x86_64/cpu.h"

typedef struct {
    volatile uint32_t locked;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    if (!lock) return;
    lock->locked = 0;
}

static inline void spinlock_lock(spinlock_t *lock) {
    if (!lock) return;
    while (__atomic_exchange_n(&lock->locked, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&lock->locked, __ATOMIC_RELAXED)) {
            cpu_pause();
        }
    }
}

static inline void spinlock_unlock(spinlock_t *lock) {
    if (!lock) return;
    __atomic_store_n(&lock->locked, 0u, __ATOMIC_RELEASE);
}

#endif /* KERNEL_SPINLOCK_H */
