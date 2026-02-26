#include "kernel/pty.h"

#include "kernel/heap.h"
#include "kernel/pipe.h"

struct pty {
    struct pipe *to_master;
    struct pipe *to_slave;
    int ref_master;
    int ref_slave;
};

struct pty *pty_create(void) {
    struct pty *p = (struct pty *)kmalloc(sizeof(*p));
    if (!p) return NULL;
    p->to_master = pipe_create();
    p->to_slave = pipe_create();
    if (!p->to_master || !p->to_slave) {
        if (p->to_master) pipe_close_end(p->to_master, 0), pipe_close_end(p->to_master, 1);
        if (p->to_slave) pipe_close_end(p->to_slave, 0), pipe_close_end(p->to_slave, 1);
        kfree(p);
        return NULL;
    }
    p->ref_master = 1;
    p->ref_slave = 1;
    return p;
}

void pty_close_end(struct pty *p, int is_master) {
    if (!p) return;
    if (is_master) {
        if (p->ref_master > 0) p->ref_master--;
    } else {
        if (p->ref_slave > 0) p->ref_slave--;
    }
    if (p->ref_master == 0 && p->ref_slave == 0) {
        pipe_close_end(p->to_master, 0);
        pipe_close_end(p->to_master, 1);
        pipe_close_end(p->to_slave, 0);
        pipe_close_end(p->to_slave, 1);
        kfree(p);
    }
}

size_t pty_read(struct pty *p, int is_master, void *buf, size_t len) {
    if (!p || !buf || len == 0) return 0;
    if (is_master) {
        return pipe_read(p->to_master, buf, len);
    }
    return pipe_read(p->to_slave, buf, len);
}

size_t pty_write(struct pty *p, int is_master, const void *buf, size_t len) {
    if (!p || !buf || len == 0) return 0;
    if (is_master) {
        return pipe_write(p->to_slave, buf, len);
    }
    return pipe_write(p->to_master, buf, len);
}

int pty_can_read(struct pty *p, int is_master) {
    if (!p) return 0;
    struct pipe *src = is_master ? p->to_master : p->to_slave;
    return pipe_count(src) > 0;
}

int pty_can_write(struct pty *p, int is_master) {
    if (!p) return 0;
    struct pipe *dst = is_master ? p->to_slave : p->to_master;
    return pipe_space(dst) > 0;
}
