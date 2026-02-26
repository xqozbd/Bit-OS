#include "kernel/tty.h"

#include "kernel/console.h"
#include "lib/log.h"

enum { TTY_IN_BUF = 256, TTY_OUT_BUF = 8192 };

struct tty {
    uint8_t in_buf[TTY_IN_BUF];
    uint8_t in_head;
    uint8_t in_tail;
    char out_buf[TTY_OUT_BUF];
    size_t out_len;
};

static struct tty g_ttys[TTY_MAX];
static int g_active = 0;

void tty_init(void) {
    for (int i = 0; i < TTY_MAX; ++i) {
        g_ttys[i].in_head = 0;
        g_ttys[i].in_tail = 0;
        g_ttys[i].out_len = 0;
    }
    g_active = 0;
}

int tty_active(void) {
    return g_active;
}

static void tty_render(int tty_id) {
    if (tty_id < 0 || tty_id >= TTY_MAX) return;
    log_printf("\x1b[2J\x1b[H");
    struct tty *t = &g_ttys[tty_id];
    if (t->out_len > 0) {
        log_printf("%.*s", (int)t->out_len, t->out_buf);
    }
}

void tty_switch(int tty_id) {
    if (tty_id < 0 || tty_id >= TTY_MAX) return;
    if (tty_id == g_active) return;
    g_active = tty_id;
    tty_render(tty_id);
}

void tty_feed_char(int ch) {
    if (ch < 0) return;
    struct tty *t = &g_ttys[g_active];
    uint8_t next = (uint8_t)(t->in_head + 1);
    if (next == t->in_tail) return;
    t->in_buf[t->in_head] = (uint8_t)ch;
    t->in_head = next;
}

size_t tty_read(int tty_id, uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0;
    if (tty_id < 0 || tty_id >= TTY_MAX) return 0;
    struct tty *t = &g_ttys[tty_id];
    size_t n = 0;
    while (n < len && t->in_tail != t->in_head) {
        buf[n++] = t->in_buf[t->in_tail];
        t->in_tail = (uint8_t)(t->in_tail + 1);
    }
    return n;
}

size_t tty_write(int tty_id, const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0;
    if (tty_id < 0 || tty_id >= TTY_MAX) return 0;
    struct tty *t = &g_ttys[tty_id];
    size_t n = 0;
    while (n < len) {
        if (t->out_len + 1 < TTY_OUT_BUF) {
            t->out_buf[t->out_len++] = (char)buf[n];
        }
        if (tty_id == g_active) {
            log_printf("%c", (char)buf[n]);
        }
        n++;
    }
    return n;
}

int tty_can_read(int tty_id) {
    if (tty_id < 0 || tty_id >= TTY_MAX) return 0;
    struct tty *t = &g_ttys[tty_id];
    return t->in_tail != t->in_head;
}
