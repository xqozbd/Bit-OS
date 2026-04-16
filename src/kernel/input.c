#include "kernel/input.h"

#include <stddef.h>

#include "drivers/ps2/keyboard.h"
#include "kernel/spinlock.h"
#include "kernel/time.h"

#define INPUT_QUEUE_CAP 256u
#define INPUT_READER_CAP 64u
#define INPUT_SHORTCUT_CAP 16u

struct input_record {
    struct input_event ev;
    uint32_t target_cookie;
};

struct input_reader_ref {
    uint32_t cookie;
    uint32_t refs;
};

struct input_shortcut {
    uint32_t owner_cookie;
    uint32_t modifiers;
    uint32_t scancode;
    uint32_t keycode;
    uint32_t flags;
};

static struct input_record g_events[INPUT_QUEUE_CAP];
static struct input_reader_ref g_readers[INPUT_READER_CAP];
static struct input_shortcut g_shortcuts[INPUT_SHORTCUT_CAP];
static uint64_t g_base_seq = 0;
static uint64_t g_next_seq = 0;
static uint64_t g_overflow_events = 0;
static uint64_t g_total_events = 0;
static uint32_t g_next_cookie = 1;
static uint32_t g_secure_cookie = 0;
static uint32_t g_accel_profile = INPUT_ACCEL_NORMAL;
static struct input_confine_rect g_confine = {0, 0, 0, 0, 0, 0};
static uint32_t g_confine_cookie = 0;
static spinlock_t g_lock;
static int g_ready = 0;

static int input_record_visible_to(const struct input_record *rec, uint32_t cookie) {
    if (!rec) return 0;
    return (rec->target_cookie == 0 || rec->target_cookie == cookie);
}

static uint32_t input_shortcut_count_locked(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        if (g_shortcuts[i].owner_cookie != 0) count++;
    }
    return count;
}

static void input_push_event_locked(const struct input_event *ev, uint32_t target_cookie) {
    uint64_t seq;

    if (!ev) return;
    seq = g_next_seq;
    if (seq - g_base_seq >= INPUT_QUEUE_CAP) {
        g_base_seq++;
        g_overflow_events++;
    }
    g_events[seq % INPUT_QUEUE_CAP].ev = *ev;
    g_events[seq % INPUT_QUEUE_CAP].target_cookie = target_cookie;
    g_next_seq = seq + 1u;
    g_total_events++;
}

static int32_t apply_accel_component(int32_t delta, uint32_t profile) {
    int32_t sign = (delta < 0) ? -1 : 1;
    int32_t mag = (delta < 0) ? -delta : delta;

    switch (profile) {
        case INPUT_ACCEL_RAW:
        case INPUT_ACCEL_NORMAL:
            return delta;
        case INPUT_ACCEL_FAST:
            if (mag >= 4) mag *= 2;
            else if (mag >= 2) mag += 1;
            return sign * mag;
        case INPUT_ACCEL_PRECISE:
            if (mag > 1) {
                mag = (mag * 3) / 4;
                if (mag == 0) mag = 1;
            }
            return sign * mag;
        default:
            return delta;
    }
}

static uint32_t input_match_shortcut_locked(uint16_t scancode, int32_t keycode, uint32_t modifiers) {
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        const struct input_shortcut *sc = &g_shortcuts[i];
        if (sc->owner_cookie == 0) continue;
        if (sc->modifiers != modifiers) continue;
        if (sc->scancode != 0 && sc->scancode != (uint32_t)scancode) continue;
        if (sc->keycode != 0 && sc->keycode != (uint32_t)keycode) continue;
        return sc->owner_cookie;
    }
    return 0;
}

void input_init(void) {
    spinlock_init(&g_lock);
    g_base_seq = 0;
    g_next_seq = 0;
    g_overflow_events = 0;
    g_total_events = 0;
    g_next_cookie = 1;
    g_secure_cookie = 0;
    g_accel_profile = INPUT_ACCEL_NORMAL;
    g_confine.x = 0;
    g_confine.y = 0;
    g_confine.w = 0;
    g_confine.h = 0;
    g_confine.enabled = 0;
    g_confine_cookie = 0;
    for (uint32_t i = 0; i < INPUT_READER_CAP; ++i) {
        g_readers[i].cookie = 0;
        g_readers[i].refs = 0;
    }
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        g_shortcuts[i].owner_cookie = 0;
        g_shortcuts[i].modifiers = 0;
        g_shortcuts[i].scancode = 0;
        g_shortcuts[i].keycode = 0;
        g_shortcuts[i].flags = 0;
    }
    g_ready = 1;
}

void input_push_key(uint16_t scancode, int pressed, int32_t keycode, uint32_t modifiers, int repeat) {
    struct input_event ev;
    uint32_t target_cookie = 0;

    if (!g_ready) return;
    ev.type = INPUT_EVENT_KEY;
    ev.device = INPUT_DEVICE_KEYBOARD;
    ev.code = scancode;
    ev.flags = pressed ? INPUT_FLAG_PRESS : INPUT_FLAG_RELEASE;
    if (repeat) ev.flags |= INPUT_FLAG_REPEAT;
    ev.modifiers = modifiers;
    ev.timestamp_ns = time_monotonic_ns();
    ev.value = pressed ? 1 : 0;
    ev.keycode = keycode;
    ev.x = keycode;
    ev.y = 0;
    ev.dx = 0;
    ev.dy = 0;
    ev.wheel_x = 0;
    ev.wheel_y = 0;
    ev.buttons = 0;
    ev.reserved = 0;

    spinlock_lock(&g_lock);
    if (pressed) {
        if (g_secure_cookie != 0) {
            target_cookie = g_secure_cookie;
            ev.flags |= INPUT_FLAG_SECURE;
        } else {
            target_cookie = input_match_shortcut_locked(scancode, keycode, modifiers);
            if (target_cookie != 0) ev.flags |= INPUT_FLAG_SHORTCUT;
        }
    } else if (g_secure_cookie != 0) {
        target_cookie = g_secure_cookie;
        ev.flags |= INPUT_FLAG_SECURE;
    }
    input_push_event_locked(&ev, target_cookie);
    spinlock_unlock(&g_lock);
}

void input_push_mouse(int32_t x, int32_t y, int32_t dx, int32_t dy,
                      int32_t wheel_x, int32_t wheel_y, uint32_t buttons) {
    struct input_event ev;

    if (!g_ready) return;
    ev.type = INPUT_EVENT_MOUSE;
    ev.device = INPUT_DEVICE_MOUSE;
    ev.code = 0;
    ev.flags = 0;
    ev.modifiers = 0;
    ev.timestamp_ns = time_monotonic_ns();
    ev.value = 1;
    ev.keycode = 0;
    ev.x = x;
    ev.y = y;
    ev.dx = dx;
    ev.dy = dy;
    ev.wheel_x = wheel_x;
    ev.wheel_y = wheel_y;
    ev.buttons = buttons;
    ev.reserved = 0;

    spinlock_lock(&g_lock);
    input_push_event_locked(&ev, 0);
    spinlock_unlock(&g_lock);
}

void input_push_device(uint16_t device_code, int attached) {
    struct input_event ev;

    if (!g_ready) return;
    ev.type = INPUT_EVENT_DEVICE;
    ev.device = INPUT_DEVICE_HOTPLUG;
    ev.code = device_code;
    ev.flags = attached ? INPUT_FLAG_PRESS : INPUT_FLAG_RELEASE;
    ev.modifiers = 0;
    ev.timestamp_ns = time_monotonic_ns();
    ev.value = attached ? 1 : 0;
    ev.keycode = 0;
    ev.x = 0;
    ev.y = 0;
    ev.dx = 0;
    ev.dy = 0;
    ev.wheel_x = 0;
    ev.wheel_y = 0;
    ev.buttons = 0;
    ev.reserved = 0;

    spinlock_lock(&g_lock);
    input_push_event_locked(&ev, 0);
    spinlock_unlock(&g_lock);
}

void input_filter_mouse_motion(int32_t *x, int32_t *y, int32_t *dx, int32_t *dy) {
    int32_t ndx;
    int32_t ndy;
    int32_t nx;
    int32_t ny;
    struct input_confine_rect confine;
    uint32_t accel;

    if (!x || !y || !dx || !dy) return;

    spinlock_lock(&g_lock);
    confine = g_confine;
    accel = g_accel_profile;
    spinlock_unlock(&g_lock);

    ndx = apply_accel_component(*dx, accel);
    ndy = apply_accel_component(*dy, accel);
    nx = *x + ndx;
    ny = *y + ndy;

    if (confine.enabled && confine.w > 0 && confine.h > 0) {
        int32_t min_x = confine.x;
        int32_t min_y = confine.y;
        int32_t max_x = confine.x + confine.w - 1;
        int32_t max_y = confine.y + confine.h - 1;
        if (nx < min_x) nx = min_x;
        if (ny < min_y) ny = min_y;
        if (nx > max_x) nx = max_x;
        if (ny > max_y) ny = max_y;
        ndx = nx - *x;
        ndy = ny - *y;
    }

    *x = nx;
    *y = ny;
    *dx = ndx;
    *dy = ndy;
}

uint64_t input_current_seq(void) {
    uint64_t seq = 0;
    spinlock_lock(&g_lock);
    seq = g_next_seq;
    spinlock_unlock(&g_lock);
    return seq;
}

uint32_t input_reader_open(void) {
    uint32_t cookie = 0;

    if (!g_ready) return 0;
    spinlock_lock(&g_lock);
    for (uint32_t i = 0; i < INPUT_READER_CAP; ++i) {
        if (g_readers[i].refs == 0) {
            cookie = g_next_cookie++;
            if (cookie == 0) cookie = g_next_cookie++;
            g_readers[i].cookie = cookie;
            g_readers[i].refs = 1;
            break;
        }
    }
    spinlock_unlock(&g_lock);
    return cookie;
}

void input_reader_retain(uint32_t cookie) {
    if (!cookie) return;
    spinlock_lock(&g_lock);
    for (uint32_t i = 0; i < INPUT_READER_CAP; ++i) {
        if (g_readers[i].cookie == cookie && g_readers[i].refs != 0) {
            g_readers[i].refs++;
            break;
        }
    }
    spinlock_unlock(&g_lock);
}

void input_reader_close(uint32_t cookie) {
    if (!cookie) return;
    spinlock_lock(&g_lock);
    for (uint32_t i = 0; i < INPUT_READER_CAP; ++i) {
        if (g_readers[i].cookie != cookie || g_readers[i].refs == 0) continue;
        g_readers[i].refs--;
        if (g_readers[i].refs == 0) {
            g_readers[i].cookie = 0;
            if (g_secure_cookie == cookie) g_secure_cookie = 0;
            if (g_confine_cookie == cookie) {
                g_confine.enabled = 0;
                g_confine_cookie = 0;
            }
            for (uint32_t j = 0; j < INPUT_SHORTCUT_CAP; ++j) {
                if (g_shortcuts[j].owner_cookie == cookie) {
                    g_shortcuts[j].owner_cookie = 0;
                }
            }
        }
        break;
    }
    spinlock_unlock(&g_lock);
}

int input_reader_pop(uint64_t *seq_io, uint64_t *dropped_io, uint32_t cookie, struct input_event *out) {
    int found = 0;

    if (!g_ready || !seq_io || !dropped_io || !out) return 0;
    spinlock_lock(&g_lock);
    if (*seq_io < g_base_seq) {
        *dropped_io += (g_base_seq - *seq_io);
        *seq_io = g_base_seq;
    }
    while (*seq_io < g_next_seq) {
        const struct input_record *rec = &g_events[*seq_io % INPUT_QUEUE_CAP];
        (*seq_io)++;
        if (!input_record_visible_to(rec, cookie)) continue;
        *out = rec->ev;
        found = 1;
        break;
    }
    spinlock_unlock(&g_lock);
    return found;
}

int input_reader_has_event(uint64_t seq, uint32_t cookie) {
    int found = 0;

    if (!g_ready) return 0;
    spinlock_lock(&g_lock);
    if (seq < g_base_seq) seq = g_base_seq;
    while (seq < g_next_seq) {
        const struct input_record *rec = &g_events[seq % INPUT_QUEUE_CAP];
        if (input_record_visible_to(rec, cookie)) {
            found = 1;
            break;
        }
        seq++;
    }
    spinlock_unlock(&g_lock);
    return found;
}

void input_reader_fill_stats(uint64_t seq, uint64_t dropped, uint32_t cookie, struct input_stats *out) {
    if (!out) return;
    spinlock_lock(&g_lock);
    out->total_events = g_total_events;
    out->overflow_events = g_overflow_events;
    out->reader_dropped_events = dropped + ((seq < g_base_seq) ? (g_base_seq - seq) : 0);
    out->reader_seq = (seq < g_base_seq) ? g_base_seq : seq;
    out->queue_capacity = INPUT_QUEUE_CAP;
    out->queue_depth = (uint32_t)(g_next_seq - g_base_seq);
    out->secure_mode = (g_secure_cookie != 0 && g_secure_cookie == cookie) ? 2u :
                       (g_secure_cookie != 0 ? 1u : 0u);
    out->keymap = (uint32_t)kb_get_layout();
    out->accel_profile = g_accel_profile;
    out->shortcut_count = input_shortcut_count_locked();
    spinlock_unlock(&g_lock);
}

int input_set_secure(uint32_t cookie, int enabled) {
    if (!cookie) return 0;
    spinlock_lock(&g_lock);
    if (enabled) {
        if (g_secure_cookie != 0 && g_secure_cookie != cookie) {
            spinlock_unlock(&g_lock);
            return 0;
        }
        g_secure_cookie = cookie;
    } else if (g_secure_cookie == cookie) {
        g_secure_cookie = 0;
    }
    spinlock_unlock(&g_lock);
    return 1;
}

int input_get_secure(void) {
    int enabled;
    spinlock_lock(&g_lock);
    enabled = (g_secure_cookie != 0);
    spinlock_unlock(&g_lock);
    return enabled;
}

int input_set_keymap(const struct input_keymap_request *req) {
    char name[9];
    uint32_t i;

    if (!req) return 0;
    if (req->name[0] != '\0') {
        for (i = 0; i < sizeof(req->name); ++i) {
            name[i] = req->name[i];
            if (req->name[i] == '\0') break;
        }
        name[sizeof(name) - 1] = '\0';
        return kb_set_layout_name(name);
    }
    return kb_set_layout((enum kb_layout)req->layout);
}

void input_get_keymap(struct input_keymap_request *out) {
    int layout;
    const char *name;
    uint32_t i;

    if (!out) return;
    out->layout = 0;
    for (i = 0; i < sizeof(out->name); ++i) out->name[i] = '\0';
    layout = kb_get_layout();
    name = kb_layout_name(layout);
    out->layout = (uint32_t)layout;
    if (!name) return;
    for (i = 0; i + 1 < sizeof(out->name) && name[i] != '\0'; ++i) {
        out->name[i] = name[i];
    }
}

int input_set_accel_profile(uint32_t profile) {
    if (profile > INPUT_ACCEL_PRECISE) return 0;
    spinlock_lock(&g_lock);
    g_accel_profile = profile;
    spinlock_unlock(&g_lock);
    return 1;
}

uint32_t input_get_accel_profile(void) {
    uint32_t profile;
    spinlock_lock(&g_lock);
    profile = g_accel_profile;
    spinlock_unlock(&g_lock);
    return profile;
}

int input_set_confinement(uint32_t cookie, const struct input_confine_rect *rect) {
    if (!cookie || !rect) return 0;
    if (rect->w <= 0 || rect->h <= 0) return 0;
    spinlock_lock(&g_lock);
    if (g_confine_cookie != 0 && g_confine_cookie != cookie) {
        spinlock_unlock(&g_lock);
        return 0;
    }
    g_confine = *rect;
    g_confine.enabled = 1;
    g_confine_cookie = cookie;
    spinlock_unlock(&g_lock);
    return 1;
}

void input_get_confinement(struct input_confine_rect *out) {
    if (!out) return;
    spinlock_lock(&g_lock);
    *out = g_confine;
    spinlock_unlock(&g_lock);
}

void input_clear_confinement(uint32_t cookie) {
    if (!cookie) return;
    spinlock_lock(&g_lock);
    if (g_confine_cookie == cookie) {
        g_confine.enabled = 0;
        g_confine_cookie = 0;
    }
    spinlock_unlock(&g_lock);
}

int input_register_shortcut(uint32_t cookie, const struct input_shortcut_request *req) {
    if (!cookie || !req) return 0;
    if (req->scancode == 0 && req->keycode == 0) return 0;
    spinlock_lock(&g_lock);
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        if (g_shortcuts[i].owner_cookie != 0 &&
            g_shortcuts[i].modifiers == req->modifiers &&
            g_shortcuts[i].scancode == req->scancode &&
            g_shortcuts[i].keycode == req->keycode) {
            int same_owner = (g_shortcuts[i].owner_cookie == cookie);
            spinlock_unlock(&g_lock);
            return same_owner;
        }
    }
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        if (g_shortcuts[i].owner_cookie == 0) {
            g_shortcuts[i].owner_cookie = cookie;
            g_shortcuts[i].modifiers = req->modifiers;
            g_shortcuts[i].scancode = req->scancode;
            g_shortcuts[i].keycode = req->keycode;
            g_shortcuts[i].flags = req->flags;
            spinlock_unlock(&g_lock);
            return 1;
        }
    }
    spinlock_unlock(&g_lock);
    return 0;
}

int input_unregister_shortcut(uint32_t cookie, const struct input_shortcut_request *req) {
    if (!cookie || !req) return 0;
    spinlock_lock(&g_lock);
    for (uint32_t i = 0; i < INPUT_SHORTCUT_CAP; ++i) {
        if (g_shortcuts[i].owner_cookie == cookie &&
            g_shortcuts[i].modifiers == req->modifiers &&
            g_shortcuts[i].scancode == req->scancode &&
            g_shortcuts[i].keycode == req->keycode) {
            g_shortcuts[i].owner_cookie = 0;
            g_shortcuts[i].modifiers = 0;
            g_shortcuts[i].scancode = 0;
            g_shortcuts[i].keycode = 0;
            g_shortcuts[i].flags = 0;
            spinlock_unlock(&g_lock);
            return 1;
        }
    }
    spinlock_unlock(&g_lock);
    return 0;
}
