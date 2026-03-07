#include "kernel/input.h"

#include <stddef.h>

#include "kernel/spinlock.h"

#define INPUT_QUEUE_CAP 256u

static struct input_event g_events[INPUT_QUEUE_CAP];
static uint32_t g_head = 0;
static uint32_t g_tail = 0;
static spinlock_t g_lock;
static int g_ready = 0;

static inline uint32_t q_next(uint32_t idx) {
    return (idx + 1u) % INPUT_QUEUE_CAP;
}

static void input_push_event(const struct input_event *ev) {
    if (!g_ready || !ev) return;
    spinlock_lock(&g_lock);
    uint32_t next = q_next(g_head);
    if (next == g_tail) {
        g_tail = q_next(g_tail);
    }
    g_events[g_head] = *ev;
    g_head = next;
    spinlock_unlock(&g_lock);
}

void input_init(void) {
    spinlock_init(&g_lock);
    g_head = 0;
    g_tail = 0;
    g_ready = 1;
}

void input_push_key(uint16_t code, int pressed, int32_t ch) {
    struct input_event ev;
    ev.type = INPUT_EVENT_KEY;
    ev.code = code;
    ev.value = pressed ? 1 : 0;
    ev.x = ch;
    ev.y = 0;
    ev.dx = 0;
    ev.dy = 0;
    ev.buttons = 0;
    input_push_event(&ev);
}

void input_push_mouse(int32_t x, int32_t y, int32_t dx, int32_t dy, uint32_t buttons) {
    struct input_event ev;
    ev.type = INPUT_EVENT_MOUSE;
    ev.code = 0;
    ev.value = 1;
    ev.x = x;
    ev.y = y;
    ev.dx = dx;
    ev.dy = dy;
    ev.buttons = buttons;
    input_push_event(&ev);
}

int input_pop_event(struct input_event *out) {
    if (!out || !g_ready) return 0;
    int have = 0;
    spinlock_lock(&g_lock);
    if (g_tail != g_head) {
        *out = g_events[g_tail];
        g_tail = q_next(g_tail);
        have = 1;
    }
    spinlock_unlock(&g_lock);
    return have;
}

int input_has_event(void) {
    if (!g_ready) return 0;
    int have = 0;
    spinlock_lock(&g_lock);
    have = (g_tail != g_head);
    spinlock_unlock(&g_lock);
    return have;
}
