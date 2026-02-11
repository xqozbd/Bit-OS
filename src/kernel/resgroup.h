#ifndef KERNEL_RESGROUP_H
#define KERNEL_RESGROUP_H

#include <stdint.h>

struct task;

struct res_group {
    uint32_t id;
    uint32_t refcount;
    uint32_t max_tasks;
    uint32_t max_fds;
    uint32_t max_sockets;
    uint64_t max_mem_bytes;
    uint32_t cur_tasks;
    uint32_t cur_fds;
    uint32_t cur_sockets;
    uint64_t cur_mem_bytes;
};

struct res_group *resgroup_root(void);
void resgroup_ref(struct res_group *g);
void resgroup_unref(struct res_group *g);
uint32_t resgroup_new_id(void);
void resgroup_clone(struct res_group *dst, const struct res_group *src);

int resgroup_acquire_task(struct res_group *g);
void resgroup_release_task(struct res_group *g);
int resgroup_charge_fd(struct res_group *g, uint32_t count);
void resgroup_uncharge_fd(struct res_group *g, uint32_t count);
int resgroup_charge_socket(struct res_group *g, uint32_t count);
void resgroup_uncharge_socket(struct res_group *g, uint32_t count);
int resgroup_charge_mem(struct res_group *g, uint64_t bytes);
void resgroup_uncharge_mem(struct res_group *g, uint64_t bytes);

int resgroup_move_task(struct task *t, struct res_group *new_group);

#endif /* KERNEL_RESGROUP_H */
