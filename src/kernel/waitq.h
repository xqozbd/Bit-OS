#ifndef KERNEL_WAITQ_H
#define KERNEL_WAITQ_H

#include "kernel/spinlock.h"

struct thread;

struct waitq {
    struct thread *head;
};

void waitq_init(struct waitq *q);
void waitq_sleep(struct waitq *q, spinlock_t *lock);
int waitq_wake_one(struct waitq *q);
int waitq_wake_all(struct waitq *q);

#endif /* KERNEL_WAITQ_H */
