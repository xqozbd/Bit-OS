#include "kernel/pipe.h"

#include "kernel/heap.h"

enum { PIPE_BUF_SIZE = 4096 };

struct pipe {
    uint8_t buf[PIPE_BUF_SIZE];
    size_t rpos;
    size_t wpos;
    size_t count;
    int ref_read;
    int ref_write;
};

struct pipe *pipe_create(void) {
    struct pipe *p = (struct pipe *)kmalloc(sizeof(*p));
    if (!p) return NULL;
    p->rpos = 0;
    p->wpos = 0;
    p->count = 0;
    p->ref_read = 1;
    p->ref_write = 1;
    return p;
}

void pipe_retain(struct pipe *p) {
    if (!p) return;
    p->ref_read++;
    p->ref_write++;
}

void pipe_retain_end(struct pipe *p, int write_end) {
    if (!p) return;
    if (write_end) p->ref_write++;
    else p->ref_read++;
}

void pipe_close_end(struct pipe *p, int write_end) {
    if (!p) return;
    if (write_end) {
        if (p->ref_write > 0) p->ref_write--;
    } else {
        if (p->ref_read > 0) p->ref_read--;
    }
    if (p->ref_read == 0 && p->ref_write == 0) {
        kfree(p);
    }
}

int pipe_has_reader(struct pipe *p) {
    return p && p->ref_read > 0;
}

int pipe_has_writer(struct pipe *p) {
    return p && p->ref_write > 0;
}

size_t pipe_read(struct pipe *p, void *buf, size_t len) {
    if (!p || !buf || len == 0) return 0;
    size_t n = 0;
    while (n < len && p->count > 0) {
        ((uint8_t *)buf)[n++] = p->buf[p->rpos++];
        if (p->rpos >= PIPE_BUF_SIZE) p->rpos = 0;
        p->count--;
    }
    return n;
}

size_t pipe_write(struct pipe *p, const void *buf, size_t len) {
    if (!p || !buf || len == 0) return 0;
    size_t n = 0;
    while (n < len && p->count < PIPE_BUF_SIZE) {
        p->buf[p->wpos++] = ((const uint8_t *)buf)[n++];
        if (p->wpos >= PIPE_BUF_SIZE) p->wpos = 0;
        p->count++;
    }
    return n;
}

size_t pipe_count(struct pipe *p) {
    if (!p) return 0;
    return p->count;
}

size_t pipe_space(struct pipe *p) {
    if (!p) return 0;
    if (p->count >= PIPE_BUF_SIZE) return 0;
    return PIPE_BUF_SIZE - p->count;
}
