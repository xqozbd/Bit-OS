#include "kernel/sched.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/smp.h"
#include "kernel/heap.h"
#include "kernel/thread.h"
#include "lib/log.h"

extern void context_switch(struct cpu_context *prev, struct cpu_context *next);

struct runqueue {
    struct thread *head;
    struct thread *tail;
};

static struct runqueue *g_runq = NULL;
static struct thread **g_current = NULL;
static struct thread **g_idle = NULL;
static volatile uint32_t *g_need_resched = NULL;
static uint32_t g_cpu_count = 1;
static uint32_t g_next_tid = 1;
static uint32_t g_quantum = 5;
static int g_sched_ready = 0;

static struct thread g_boot_thread;

static void idle_thread(void *arg) {
    (void)arg;
    for (;;) {
        cpu_enable_interrupts();
        HALT();
    }
}

uint32_t sched_cpu_index(void) {
    /* TODO: use APIC ID -> CPU index mapping for true SMP. */
    return smp_bsp_index();
}

uint32_t sched_next_tid(void) {
    return __atomic_fetch_add(&g_next_tid, 1u, __ATOMIC_SEQ_CST);
}

static void runq_push(struct runqueue *rq, struct thread *t) {
    t->next = NULL;
    if (!rq->tail) {
        rq->head = rq->tail = t;
        return;
    }
    rq->tail->next = t;
    rq->tail = t;
}

static struct thread *runq_pop(struct runqueue *rq) {
    struct thread *t = rq->head;
    if (!t) return NULL;
    rq->head = t->next;
    if (!rq->head) rq->tail = NULL;
    t->next = NULL;
    return t;
}

void sched_enqueue(struct thread *t) {
    if (!t) return;
    if (!g_runq) return;
    uint32_t cpu = t->cpu;
    if (cpu >= g_cpu_count) cpu = 0;
    runq_push(&g_runq[cpu], t);
}

struct thread *thread_current(void) {
    if (!g_current) return NULL;
    uint32_t cpu = sched_cpu_index();
    return g_current[cpu];
}

void sched_init(void) {
    g_cpu_count = smp_cpu_count();
    if (g_cpu_count == 0) g_cpu_count = 1;

    g_runq = (struct runqueue *)kmalloc(sizeof(*g_runq) * g_cpu_count);
    g_current = (struct thread **)kmalloc(sizeof(*g_current) * g_cpu_count);
    g_idle = (struct thread **)kmalloc(sizeof(*g_idle) * g_cpu_count);
    g_need_resched = (uint32_t *)kmalloc(sizeof(*g_need_resched) * g_cpu_count);
    if (!g_runq || !g_current || !g_idle || !g_need_resched) {
        log_printf("sched: allocation failed, scheduler disabled\n");
        return;
    }
    for (uint32_t i = 0; i < g_cpu_count; ++i) {
        g_runq[i].head = NULL;
        g_runq[i].tail = NULL;
        g_current[i] = NULL;
        g_idle[i] = NULL;
        g_need_resched[i] = 0;
    }

    /* Register bootstrap thread as current on BSP */
    g_boot_thread.ctx.rsp = 0;
    g_boot_thread.ctx.rbx = 0;
    g_boot_thread.ctx.rbp = 0;
    g_boot_thread.ctx.r12 = 0;
    g_boot_thread.ctx.r13 = 0;
    g_boot_thread.ctx.r14 = 0;
    g_boot_thread.ctx.r15 = 0;
    g_boot_thread.next = NULL;
    g_boot_thread.entry = NULL;
    g_boot_thread.arg = NULL;
    g_boot_thread.stack = NULL;
    g_boot_thread.stack_size = 0;
    g_boot_thread.cpu = smp_bsp_index();
    g_boot_thread.id = sched_next_tid();
    g_boot_thread.state = THREAD_RUNNING;
    g_boot_thread.name = "bootstrap";
    g_current[g_boot_thread.cpu] = &g_boot_thread;

    /* Create idle threads per CPU */
    for (uint32_t i = 0; i < g_cpu_count; ++i) {
        struct thread *idle = (struct thread *)kmalloc(sizeof(*idle));
        if (!idle) continue;
        uint8_t *stack = (uint8_t *)kmalloc(4096);
        if (!stack) {
            kfree(idle);
            continue;
        }
        uintptr_t sp = (uintptr_t)stack + 4096;
        sp &= ~0xFULL;
        sp -= 8;
        *(uint64_t *)sp = (uint64_t)idle_thread;
        idle->ctx.rsp = sp;
        idle->ctx.rbx = 0;
        idle->ctx.rbp = 0;
        idle->ctx.r12 = 0;
        idle->ctx.r13 = 0;
        idle->ctx.r14 = 0;
        idle->ctx.r15 = 0;
        idle->next = NULL;
        idle->entry = idle_thread;
        idle->arg = NULL;
        idle->stack = stack;
        idle->stack_size = 4096;
        idle->cpu = i;
        idle->id = sched_next_tid();
        idle->state = THREAD_IDLE;
        idle->name = "idle";
        g_idle[i] = idle;
    }

    g_sched_ready = 1;
    log_printf("sched: initialized (cpus=%u)\n", (unsigned)g_cpu_count);
}

void sched_tick(void) {
    if (!g_sched_ready) return;
    uint32_t cpu = sched_cpu_index();
    static uint32_t ticks[256];
    if (cpu >= 256) return;
    ticks[cpu]++;
    if (ticks[cpu] >= g_quantum) {
        ticks[cpu] = 0;
        if (g_runq && g_runq[cpu].head) {
            g_need_resched[cpu] = 1;
        }
    }
}

void sched_maybe_preempt(void) {
    if (!g_sched_ready) return;
    uint32_t cpu = sched_cpu_index();
    if (g_need_resched[cpu]) {
        sched_yield();
    }
}

void sched_yield(void) {
    if (!g_sched_ready) return;
    cpu_disable_interrupts();
    uint32_t cpu = sched_cpu_index();
    struct thread *prev = g_current[cpu];
    struct thread *next = runq_pop(&g_runq[cpu]);
    if (!next) {
        g_need_resched[cpu] = 0;
        cpu_enable_interrupts();
        return;
    }
    if (!next) {
        cpu_enable_interrupts();
        return;
    }

    g_need_resched[cpu] = 0;

    if (prev == next) {
        cpu_enable_interrupts();
        return;
    }

    if (prev && prev->state == THREAD_RUNNING && prev != g_idle[cpu]) {
        prev->state = THREAD_READY;
        runq_push(&g_runq[cpu], prev);
    }

    next->state = (next->state == THREAD_IDLE) ? THREAD_IDLE : THREAD_RUNNING;
    g_current[cpu] = next;

    if (!prev) {
        cpu_enable_interrupts();
        return;
    }
    context_switch(&prev->ctx, &next->ctx);
    cpu_enable_interrupts();
}
