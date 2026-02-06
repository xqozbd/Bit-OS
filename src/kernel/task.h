#ifndef KERNEL_TASK_H
#define KERNEL_TASK_H

#include <stddef.h>
#include <stdint.h>

struct thread;

enum task_state {
    TASK_READY = 0,
    TASK_RUNNING = 1,
    TASK_BLOCKED = 2,
    TASK_DEAD = 3
};

struct task {
    uint32_t pid;
    uint32_t tid;
    uint32_t state;
    uint8_t is_user;
    uint8_t *kstack;
    size_t kstack_size;
    uint64_t pml4_phys;
    uint64_t brk_base;
    uint64_t brk;
    uint64_t brk_limit;
    const char *name;
    struct task_fd *fds;
    struct task *next;
};

struct task_fd {
    int used;
    int node;
    uint64_t offset;
    uint32_t flags;
};

void task_fd_init(struct task *t);
struct task_fd *task_fd_get(struct task *t, int fd);
int task_fd_alloc(struct task *t, int node, uint32_t flags);
int task_fd_close(struct task *t, int fd);

struct task *task_current(void);
struct task *task_create_for_thread(struct thread *t, const char *name);
void task_init_bootstrap(struct thread *t);
void task_on_thread_exit(struct thread *t);
uint32_t task_pid(struct task *t);
void task_dump_list(void);

#endif /* KERNEL_TASK_H */
