#ifndef KERNEL_TASK_H
#define KERNEL_TASK_H

#include <stddef.h>
#include <stdint.h>

struct thread;
struct pid_namespace;
struct mount_namespace;
struct net_namespace;
struct res_group;

enum task_state {
    TASK_READY = 0,
    TASK_RUNNING = 1,
    TASK_BLOCKED = 2,
    TASK_DEAD = 3
};

#define FD_TYPE_FILE 1
#define FD_TYPE_SOCKET 2
#define FD_TYPE_CONSOLE 3
#define FD_TYPE_PIPE 4
#define FD_TYPE_PTY_MASTER 5
#define FD_TYPE_PTY_SLAVE 6

struct task {
    uint32_t pid;
    uint32_t ppid;
    uint32_t pgid;
    struct pid_namespace *pid_ns;
    uint32_t pid_ns_pid;
    struct mount_namespace *mnt_ns;
    struct net_namespace *net_ns;
    struct res_group *res_grp;
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
    uint32_t uid;
    uint32_t gid;
    uint32_t tty_id;
    uint16_t umask;
    int nice;
    uint32_t cpu_mask;
    uint64_t res_mem_bytes;
    uint32_t res_fd_count;
    uint32_t res_sock_count;
    uint64_t disk_quota_bytes;
    uint64_t disk_used_bytes;
    uint32_t pending_signals;
    uint64_t sig_handlers[32];
    uint32_t exit_code;
    uint8_t stopped;
    uint8_t core_pending;
    uint64_t core_fault_addr;
    uint64_t core_rip;
    uint64_t core_rsp;
    uint64_t core_err;
    char core_reason[32];
    const char *name;
    struct task_fd *fds;
    struct task_map *maps;
    struct task *next;
};

struct pid_namespace {
    uint32_t id;
    uint32_t next_pid;
    uint32_t refcount;
};

struct task_fd {
    int used;
    int type;
    int node;
    int sock_id;
    void *pipe;
    uint8_t pipe_end;
    uint64_t offset;
    uint32_t flags;
};

struct task_page {
    uint64_t vaddr;
    uint64_t phys;
    uint32_t swap_slot;
    uint8_t present;
    uint8_t swapped;
    struct task_page *next;
};

struct task_map {
    uint64_t base;
    uint64_t size;
    uint32_t prot;
    uint32_t flags;
    uint8_t map_type;
    int file_node;
    uint64_t file_off;
    uint64_t file_size;
    struct task_page *pages;
    struct task_map *next;
};

void task_fd_init(struct task *t);
struct task_fd *task_fd_get(struct task *t, int fd);
int task_fd_alloc(struct task *t, int node, uint32_t flags);
int task_fd_alloc_socket(struct task *t, int sock_id);
int task_fd_close(struct task *t, int fd);
void task_set_user_layout(struct task *t, uint64_t brk_base, uint64_t brk_limit,
                          uint64_t stack_top, uint64_t stack_size,
                          uint64_t mmap_base, uint64_t mmap_limit);
void task_clone_from(struct task *dst, const struct task *src);
int task_signal_set_handler(struct task *t, int sig, uint64_t handler);
void task_signal_raise(struct task *t, int sig);
int task_signal_handle_pending(struct task *t);
struct task *task_find_pid(uint32_t pid);
struct task *task_find_child_dead(struct task *parent, int pid);
struct task *task_find_child_stopped(struct task *parent, int pid);
uint64_t task_mmap_anonymous(struct task *t, uint64_t addr, uint64_t len, uint32_t prot, uint32_t flags);
uint64_t task_mmap_file(struct task *t, uint64_t addr, uint64_t len, uint32_t prot, uint32_t flags, int node, uint64_t off);
int task_munmap(struct task *t, uint64_t addr, uint64_t len);
int task_handle_page_fault(struct task *t, uint64_t addr, uint64_t error_code);
int task_reclaim_pages(uint32_t max_pages);
int task_charge_mem(struct task *t, uint64_t bytes);
void task_uncharge_mem(struct task *t, uint64_t bytes);
int task_charge_fd(struct task *t, uint32_t count);
void task_uncharge_fd(struct task *t, uint32_t count);
int task_charge_socket(struct task *t, uint32_t count);
void task_uncharge_socket(struct task *t, uint32_t count);
int task_charge_disk(struct task *t, uint64_t bytes);
void task_uncharge_disk(struct task *t, uint64_t bytes);

struct task *task_current(void);
struct task *task_create_for_thread(struct thread *t, const char *name);
void task_init_bootstrap(struct thread *t);
void task_on_thread_exit(struct thread *t);
uint32_t task_pid(struct task *t);
uint32_t task_pid_ns(struct task *t);
uint32_t task_pid_ns_id(struct task *t);
uint32_t task_unshare_pidns(struct task *t);
uint32_t task_unshare_mntns(struct task *t);
uint32_t task_unshare_netns(struct task *t);
uint32_t task_unshare_resgroup(struct task *t);
void task_dump_list(void);
size_t task_format_list(struct task *viewer, char *buf, size_t buf_len);

#endif /* KERNEL_TASK_H */
