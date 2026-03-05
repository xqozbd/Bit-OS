#include "kernel/ksync.h"

#include "kernel/heap.h"

struct ksem *ksem_create(int initial) {
    if (initial < 0) initial = 0;
    struct ksem *sem = (struct ksem *)kmalloc(sizeof(*sem));
    if (!sem) return NULL;
    sem->count = initial;
    sem->refcount = 1;
    spinlock_init(&sem->lock);
    waitq_init(&sem->wait);
    return sem;
}

void ksem_ref(struct ksem *sem) {
    if (!sem) return;
    __atomic_fetch_add(&sem->refcount, 1u, __ATOMIC_SEQ_CST);
}

void ksem_unref(struct ksem *sem) {
    if (!sem) return;
    if (__atomic_fetch_sub(&sem->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        kfree(sem);
    }
}

int ksem_wait(struct ksem *sem) {
    if (!sem) return -1;
    spinlock_lock(&sem->lock);
    while (sem->count <= 0) {
        waitq_sleep(&sem->wait, &sem->lock);
    }
    sem->count--;
    spinlock_unlock(&sem->lock);
    return 0;
}

int ksem_post(struct ksem *sem) {
    if (!sem) return -1;
    spinlock_lock(&sem->lock);
    sem->count++;
    waitq_wake_one(&sem->wait);
    spinlock_unlock(&sem->lock);
    return 0;
}

struct kcond *kcond_create(void) {
    struct kcond *cond = (struct kcond *)kmalloc(sizeof(*cond));
    if (!cond) return NULL;
    cond->refcount = 1;
    spinlock_init(&cond->lock);
    waitq_init(&cond->wait);
    return cond;
}

void kcond_ref(struct kcond *cond) {
    if (!cond) return;
    __atomic_fetch_add(&cond->refcount, 1u, __ATOMIC_SEQ_CST);
}

void kcond_unref(struct kcond *cond) {
    if (!cond) return;
    if (__atomic_fetch_sub(&cond->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        kfree(cond);
    }
}

int kcond_wait(struct kcond *cond, struct ksem *mutex) {
    if (!cond) return -1;
    if (mutex) ksem_post(mutex);
    spinlock_lock(&cond->lock);
    waitq_sleep(&cond->wait, &cond->lock);
    spinlock_unlock(&cond->lock);
    if (mutex) ksem_wait(mutex);
    return 0;
}

int kcond_signal(struct kcond *cond) {
    if (!cond) return -1;
    spinlock_lock(&cond->lock);
    waitq_wake_one(&cond->wait);
    spinlock_unlock(&cond->lock);
    return 0;
}

int kcond_broadcast(struct kcond *cond) {
    if (!cond) return -1;
    spinlock_lock(&cond->lock);
    waitq_wake_all(&cond->wait);
    spinlock_unlock(&cond->lock);
    return 0;
}
