#include "kernel/resgroup.h"

#include <stddef.h>

#include "kernel/heap.h"
#include "kernel/task.h"

static struct res_group g_root_group;
static uint32_t g_next_resgroup_id = 2;

static int limit_allows_u32(uint32_t limit, uint32_t current, uint32_t add) {
    if (limit == 0) return 1;
    if (current > limit) return 0;
    if (add > limit - current) return 0;
    return 1;
}

static int limit_allows_u64(uint64_t limit, uint64_t current, uint64_t add) {
    if (limit == 0) return 1;
    if (current > limit) return 0;
    if (add > limit - current) return 0;
    return 1;
}

struct res_group *resgroup_root(void) {
    if (g_root_group.id == 0) {
        g_root_group.id = 1;
        g_root_group.refcount = 1;
        g_root_group.max_tasks = 0;
        g_root_group.max_fds = 0;
        g_root_group.max_sockets = 0;
        g_root_group.max_mem_bytes = 0;
        g_root_group.cur_tasks = 0;
        g_root_group.cur_fds = 0;
        g_root_group.cur_sockets = 0;
        g_root_group.cur_mem_bytes = 0;
    }
    return &g_root_group;
}

void resgroup_ref(struct res_group *g) {
    if (!g) return;
    __atomic_fetch_add(&g->refcount, 1u, __ATOMIC_SEQ_CST);
}

void resgroup_unref(struct res_group *g) {
    if (!g || g == &g_root_group) return;
    if (__atomic_fetch_sub(&g->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        kfree(g);
    }
}

uint32_t resgroup_new_id(void) {
    return __atomic_fetch_add(&g_next_resgroup_id, 1u, __ATOMIC_SEQ_CST);
}

void resgroup_clone(struct res_group *dst, const struct res_group *src) {
    if (!dst || !src) return;
    dst->id = 0;
    dst->refcount = 1;
    dst->max_tasks = src->max_tasks;
    dst->max_fds = src->max_fds;
    dst->max_sockets = src->max_sockets;
    dst->max_mem_bytes = src->max_mem_bytes;
    dst->cur_tasks = 0;
    dst->cur_fds = 0;
    dst->cur_sockets = 0;
    dst->cur_mem_bytes = 0;
}

int resgroup_acquire_task(struct res_group *g) {
    if (!g) return 0;
    uint32_t cur = g->cur_tasks;
    if (!limit_allows_u32(g->max_tasks, cur, 1u)) return 0;
    __atomic_fetch_add(&g->cur_tasks, 1u, __ATOMIC_SEQ_CST);
    return 1;
}

void resgroup_release_task(struct res_group *g) {
    if (!g) return;
    if (g->cur_tasks > 0) {
        __atomic_fetch_sub(&g->cur_tasks, 1u, __ATOMIC_SEQ_CST);
    }
}

int resgroup_charge_fd(struct res_group *g, uint32_t count) {
    if (!g || count == 0) return 1;
    uint32_t cur = g->cur_fds;
    if (!limit_allows_u32(g->max_fds, cur, count)) return 0;
    __atomic_fetch_add(&g->cur_fds, count, __ATOMIC_SEQ_CST);
    return 1;
}

void resgroup_uncharge_fd(struct res_group *g, uint32_t count) {
    if (!g || count == 0) return;
    if (g->cur_fds < count) g->cur_fds = 0;
    else __atomic_fetch_sub(&g->cur_fds, count, __ATOMIC_SEQ_CST);
}

int resgroup_charge_socket(struct res_group *g, uint32_t count) {
    if (!g || count == 0) return 1;
    uint32_t cur = g->cur_sockets;
    if (!limit_allows_u32(g->max_sockets, cur, count)) return 0;
    __atomic_fetch_add(&g->cur_sockets, count, __ATOMIC_SEQ_CST);
    return 1;
}

void resgroup_uncharge_socket(struct res_group *g, uint32_t count) {
    if (!g || count == 0) return;
    if (g->cur_sockets < count) g->cur_sockets = 0;
    else __atomic_fetch_sub(&g->cur_sockets, count, __ATOMIC_SEQ_CST);
}

int resgroup_charge_mem(struct res_group *g, uint64_t bytes) {
    if (!g || bytes == 0) return 1;
    uint64_t cur = g->cur_mem_bytes;
    if (!limit_allows_u64(g->max_mem_bytes, cur, bytes)) return 0;
    __atomic_fetch_add(&g->cur_mem_bytes, bytes, __ATOMIC_SEQ_CST);
    return 1;
}

void resgroup_uncharge_mem(struct res_group *g, uint64_t bytes) {
    if (!g || bytes == 0) return;
    if (g->cur_mem_bytes < bytes) g->cur_mem_bytes = 0;
    else __atomic_fetch_sub(&g->cur_mem_bytes, bytes, __ATOMIC_SEQ_CST);
}

int resgroup_move_task(struct task *t, struct res_group *new_group) {
    if (!t || !new_group) return 0;
    struct res_group *old = t->res_grp;
    if (!resgroup_acquire_task(new_group)) return 0;
    if (!resgroup_charge_fd(new_group, t->res_fd_count)) {
        resgroup_release_task(new_group);
        return 0;
    }
    if (!resgroup_charge_socket(new_group, t->res_sock_count)) {
        resgroup_uncharge_fd(new_group, t->res_fd_count);
        resgroup_release_task(new_group);
        return 0;
    }
    if (!resgroup_charge_mem(new_group, t->res_mem_bytes)) {
        resgroup_uncharge_socket(new_group, t->res_sock_count);
        resgroup_uncharge_fd(new_group, t->res_fd_count);
        resgroup_release_task(new_group);
        return 0;
    }
    if (old) {
        resgroup_uncharge_fd(old, t->res_fd_count);
        resgroup_uncharge_socket(old, t->res_sock_count);
        resgroup_uncharge_mem(old, t->res_mem_bytes);
        resgroup_release_task(old);
        resgroup_unref(old);
    }
    t->res_grp = new_group;
    return 1;
}
