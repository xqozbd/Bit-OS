#include "kernel/sleep.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/timer.h"
#include "kernel/sched.h"
#include "kernel/thread.h"
#include "lib/log.h"

struct sleep_node {
    struct sleep_node *next;
    struct thread *t;
    uint64_t wake_tick;
};

static struct sleep_node *g_sleep_head = NULL;

void sleep_init(void) {
    g_sleep_head = NULL;
}

static void sleep_insert(struct sleep_node *n) {
    if (!g_sleep_head || n->wake_tick < g_sleep_head->wake_tick) {
        n->next = g_sleep_head;
        g_sleep_head = n;
        return;
    }
    struct sleep_node *cur = g_sleep_head;
    while (cur->next && cur->next->wake_tick <= n->wake_tick) {
        cur = cur->next;
    }
    n->next = cur->next;
    cur->next = n;
}

void sleep_tick(void) {
    uint64_t now = timer_uptime_ticks();
    while (g_sleep_head && g_sleep_head->wake_tick <= now) {
        struct sleep_node *n = g_sleep_head;
        g_sleep_head = n->next;
        if (n->t && n->t->state == THREAD_BLOCKED) {
            n->t->state = THREAD_READY;
            sched_enqueue(n->t);
        }
    }
}

void sleep_ticks(uint64_t ticks) {
    if (ticks == 0) return;
    struct thread *t = thread_current();
    if (!t) return;

    struct sleep_node node;
    node.t = t;
    node.wake_tick = timer_uptime_ticks() + ticks;
    node.next = NULL;

    cpu_disable_interrupts();
    t->state = THREAD_BLOCKED;
    sleep_insert(&node);
    cpu_enable_interrupts();
    sched_yield();
}

void sleep_ms(uint64_t ms) {
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    uint64_t ticks = (ms * (uint64_t)hz + 999ull) / 1000ull;
    if (ticks == 0) ticks = 1;
    sleep_ticks(ticks);
}
