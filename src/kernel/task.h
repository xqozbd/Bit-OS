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
    uint64_t user_stack_top;
    uint64_t user_stack_size;
    uint64_t mmap_base;
    uint64_t mmap_limit;
    uint32_t pending_signals;
    uint64_t sig_handlers[32];
    const char *name;
    struct task_fd *fds;
    struct task_map *maps;
    struct task *next;
};

struct task_fd {
    int used;
    int type;
    int node;
    int sock_id;
    uint64_t offset;
    uint32_t flags;
};

struct task_map {
    uint64_t base;
    uint64_t size;
    uint32_t prot;
    uint32_t flags;
    struct task_map *next;
};

void task_fd_init(struct task *t);
struct task_fd *task_fd_get(struct task *t, int fd);
int task_fd_alloc(struct task *t, int node, uint32_t flags);
int task_fd_alloc_socket(struct task *t, int sock_id);
int task_fd_close(struct task *t, int fd);
void task_set_user_layout(struct task *t, uint64_t brk_base, uint64_t brk_limit,
                          uint64_t stack_top, uint64_t stack_size);
void task_clone_from(struct task *dst, const struct task *src);
int task_signal_set_handler(struct task *t, int sig, uint64_t handler);
void task_signal_raise(struct task *t, int sig);
int task_signal_handle_pending(struct task *t);
struct task *task_find_pid(uint32_t pid);
uint64_t task_mmap_anonymous(struct task *t, uint64_t addr, uint64_t len, uint32_t prot, uint32_t flags);
int task_munmap(struct task *t, uint64_t addr, uint64_t len);

struct task *task_current(void);
struct task *task_create_for_thread(struct thread *t, const char *name);
void task_init_bootstrap(struct thread *t);
void task_on_thread_exit(struct thread *t);
uint32_t task_pid(struct task *t);
void task_dump_list(void);

#endif /* KERNEL_TASK_H */
