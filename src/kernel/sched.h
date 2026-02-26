#ifndef KERNEL_SCHED_H
#define KERNEL_SCHED_H

#include <stddef.h>
#include <stdint.h>

struct thread;

void sched_init(void);
int sched_is_ready(void);
void sched_tick(void);
void sched_maybe_preempt(void);
void sched_yield(void);
void sched_preempt_from_isr(void);

/* Internal helpers used by thread creation */
uint32_t sched_cpu_index(void);
uint32_t sched_cpu_count(void);
uint32_t sched_next_tid(void);
void sched_enqueue(struct thread *t);
int sched_set_nice(struct thread *t, int nice);
int sched_get_nice(const struct thread *t);
int sched_set_affinity(struct thread *t, uint32_t mask);
uint32_t sched_get_affinity(const struct thread *t);
struct thread *thread_current(void);

#endif /* KERNEL_SCHED_H */
