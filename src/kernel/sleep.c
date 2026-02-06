#include "kernel/sleep.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/timer.h"
#include "kernel/sched.h"
#include "kernel/thread.h"
#include "lib/log.h"

#define SLEEP_WHEEL_BITS 8u
#define SLEEP_WHEEL_SIZE (1u << SLEEP_WHEEL_BITS)

static struct thread *g_sleep_wheel[SLEEP_WHEEL_SIZE];
static struct thread *g_sleep_overflow = NULL;
static uint64_t g_sleep_last_tick = 0;

void sleep_init(void) {
    for (uint32_t i = 0; i < SLEEP_WHEEL_SIZE; ++i) {
        g_sleep_wheel[i] = NULL;
    }
    g_sleep_overflow = NULL;
    g_sleep_last_tick = timer_uptime_ticks();
}

static void overflow_insert(struct thread *t) {
    if (!g_sleep_overflow || t->sleep_wake_tick < g_sleep_overflow->sleep_wake_tick) {
        t->sleep_next = g_sleep_overflow;
        g_sleep_overflow = t;
        return;
    }
    struct thread *cur = g_sleep_overflow;
    while (cur->sleep_next && cur->sleep_next->sleep_wake_tick <= t->sleep_wake_tick) {
        cur = cur->sleep_next;
    }
    t->sleep_next = cur->sleep_next;
    cur->sleep_next = t;
}

static void wheel_insert(struct thread *t) {
    uint32_t slot = (uint32_t)(t->sleep_wake_tick & (SLEEP_WHEEL_SIZE - 1u));
    t->sleep_next = g_sleep_wheel[slot];
    g_sleep_wheel[slot] = t;
}

static void wake_thread(struct thread *t) {
    if (t && t->state == THREAD_BLOCKED) {
        t->state = THREAD_READY;
        t->sleep_next = NULL;
        sched_enqueue(t);
    }
}

void sleep_tick(void) {
    uint64_t now = timer_uptime_ticks();
    if (now <= g_sleep_last_tick) return;

    for (uint64_t tick = g_sleep_last_tick + 1; tick <= now; ++tick) {
        uint32_t slot = (uint32_t)(tick & (SLEEP_WHEEL_SIZE - 1u));
        struct thread *t = g_sleep_wheel[slot];
        g_sleep_wheel[slot] = NULL;
        while (t) {
            struct thread *next = t->sleep_next;
            t->sleep_next = NULL;
            if (t->sleep_wake_tick <= tick) {
                wake_thread(t);
            } else {
                wheel_insert(t);
            }
            t = next;
        }

        while (g_sleep_overflow && g_sleep_overflow->sleep_wake_tick <= tick) {
            struct thread *wake = g_sleep_overflow;
            g_sleep_overflow = wake->sleep_next;
            wake->sleep_next = NULL;
            wake_thread(wake);
        }

        while (g_sleep_overflow &&
               (g_sleep_overflow->sleep_wake_tick - tick) < SLEEP_WHEEL_SIZE) {
            struct thread *move = g_sleep_overflow;
            g_sleep_overflow = move->sleep_next;
            move->sleep_next = NULL;
            wheel_insert(move);
        }
    }

    g_sleep_last_tick = now;
}

void sleep_ticks(uint64_t ticks) {
    if (ticks == 0) return;
    struct thread *t = thread_current();
    if (!t) return;

    uint64_t now = timer_uptime_ticks();
    t->sleep_wake_tick = now + ticks;
    t->sleep_next = NULL;
    cpu_disable_interrupts();
    t->state = THREAD_BLOCKED;
    if (ticks < SLEEP_WHEEL_SIZE) {
        wheel_insert(t);
    } else {
        overflow_insert(t);
    }
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
