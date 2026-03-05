#ifndef KERNEL_KSYNC_H
#define KERNEL_KSYNC_H

#include "kernel/spinlock.h"
#include "kernel/waitq.h"

struct ksem {
    int count;
    uint32_t refcount;
    spinlock_t lock;
    struct waitq wait;
};

struct kcond {
    uint32_t refcount;
    spinlock_t lock;
    struct waitq wait;
};

struct ksem *ksem_create(int initial);
void ksem_ref(struct ksem *sem);
void ksem_unref(struct ksem *sem);
int ksem_wait(struct ksem *sem);
int ksem_post(struct ksem *sem);

struct kcond *kcond_create(void);
void kcond_ref(struct kcond *cond);
void kcond_unref(struct kcond *cond);
int kcond_wait(struct kcond *cond, struct ksem *mutex);
int kcond_signal(struct kcond *cond);
int kcond_broadcast(struct kcond *cond);

#endif /* KERNEL_KSYNC_H */
