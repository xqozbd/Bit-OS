#include "kernel/waitq.h"

#include "kernel/sched.h"
#include "kernel/thread.h"

void waitq_init(struct waitq *q) {
    if (!q) return;
    q->head = NULL;
}

void waitq_sleep(struct waitq *q, spinlock_t *lock) {
    if (!q || !lock) return;
    struct thread *t = thread_current();
    if (!t) {
        spinlock_unlock(lock);
        return;
    }
    t->sleep_next = q->head;
    q->head = t;
    t->state = THREAD_BLOCKED;
    spinlock_unlock(lock);
    sched_yield();
    spinlock_lock(lock);
}

int waitq_wake_one(struct waitq *q) {
    if (!q || !q->head) return 0;
    struct thread *t = q->head;
    q->head = t->sleep_next;
    t->sleep_next = NULL;
    t->state = THREAD_READY;
    sched_enqueue(t);
    return 1;
}

int waitq_wake_all(struct waitq *q) {
    if (!q) return 0;
    int count = 0;
    while (q->head) {
        struct thread *t = q->head;
        q->head = t->sleep_next;
        t->sleep_next = NULL;
        t->state = THREAD_READY;
        sched_enqueue(t);
        count++;
    }
    return count;
}
