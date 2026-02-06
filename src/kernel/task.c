#include "kernel/task.h"

#include <stddef.h>

#include "lib/compat.h"
#include "lib/log.h"
#include "kernel/heap.h"
#include "arch/x86_64/paging.h"
#include "kernel/thread.h"
#include "kernel/sched.h"
#include "kernel/socket.h"

static uint32_t g_next_pid = 2;
static struct task g_boot_task;
static struct task *g_task_head = NULL;
static struct task *g_task_tail = NULL;
static struct task_fd g_boot_fds[16];

static uint32_t next_pid(void) {
    return __atomic_fetch_add(&g_next_pid, 1u, __ATOMIC_SEQ_CST);
}

struct task *task_current(void) {
    struct thread *t = thread_current();
    if (!t) return NULL;
    return t->task;
}

void task_fd_init(struct task *t) {
    if (!t) return;
    if (!t->fds) {
        t->fds = (struct task_fd *)kmalloc(sizeof(struct task_fd) * 16);
    }
    if (!t->fds) return;
    for (int i = 0; i < 16; ++i) {
        t->fds[i].used = 0;
        t->fds[i].type = 0;
        t->fds[i].node = -1;
        t->fds[i].sock_id = -1;
        t->fds[i].offset = 0;
        t->fds[i].flags = 0;
    }
}

struct task_fd *task_fd_get(struct task *t, int fd) {
    if (!t || !t->fds) return NULL;
    if (fd < 0 || fd >= 16) return NULL;
    if (!t->fds[fd].used) return NULL;
    return &t->fds[fd];
}

int task_fd_alloc(struct task *t, int node, uint32_t flags) {
    if (!t || !t->fds) return -1;
    for (int i = 0; i < 16; ++i) {
        if (!t->fds[i].used) {
            t->fds[i].used = 1;
            t->fds[i].type = 1;
            t->fds[i].node = node;
            t->fds[i].sock_id = -1;
            t->fds[i].offset = 0;
            t->fds[i].flags = flags;
            return i;
        }
    }
    return -1;
}

int task_fd_alloc_socket(struct task *t, int sock_id) {
    if (!t || !t->fds) return -1;
    for (int i = 0; i < 16; ++i) {
        if (!t->fds[i].used) {
            t->fds[i].used = 1;
            t->fds[i].type = 2;
            t->fds[i].node = -1;
            t->fds[i].sock_id = sock_id;
            t->fds[i].offset = 0;
            t->fds[i].flags = 0;
            return i;
        }
    }
    return -1;
}

int task_fd_close(struct task *t, int fd) {
    if (!t || !t->fds) return -1;
    if (fd < 0 || fd >= 16) return -1;
    if (!t->fds[fd].used) return -1;
    if (t->fds[fd].type == 2 && t->fds[fd].sock_id >= 0) {
        socket_close(t->fds[fd].sock_id);
    }
    t->fds[fd].used = 0;
    t->fds[fd].type = 0;
    t->fds[fd].node = -1;
    t->fds[fd].sock_id = -1;
    t->fds[fd].offset = 0;
    t->fds[fd].flags = 0;
    return 0;
}

void task_init_bootstrap(struct thread *t) {
    if (!t) return;
    g_boot_task.pid = 1;
    g_boot_task.tid = t->id;
    g_boot_task.state = TASK_RUNNING;
    g_boot_task.is_user = 0;
    g_boot_task.kstack = t->stack;
    g_boot_task.kstack_size = t->stack_size;
    g_boot_task.pml4_phys = t->pml4_phys;
    g_boot_task.brk_base = 0;
    g_boot_task.brk = 0;
    g_boot_task.brk_limit = 0;
    g_boot_task.user_stack_top = 0;
    g_boot_task.user_stack_size = 0;
    g_boot_task.pending_signals = 0;
    for (int i = 0; i < 32; ++i) g_boot_task.sig_handlers[i] = 0;
    g_boot_task.name = t->name ? t->name : "bootstrap";
    g_boot_task.fds = g_boot_fds;
    g_boot_task.next = NULL;
    task_fd_init(&g_boot_task);
    t->task = &g_boot_task;
    g_task_head = &g_boot_task;
    g_task_tail = &g_boot_task;
}

struct task *task_create_for_thread(struct thread *t, const char *name) {
    if (!t) return NULL;
    struct task *task = (struct task *)kmalloc(sizeof(*task));
    if (!task) return NULL;
    task->pid = next_pid();
    task->tid = t->id;
    task->state = TASK_READY;
    task->is_user = t->is_user;
    task->kstack = t->stack;
    task->kstack_size = t->stack_size;
    task->pml4_phys = t->pml4_phys;
    if (task->is_user) {
        struct user_addr_space layout;
        paging_user_layout_default(&layout);
        task->brk_base = layout.heap_base;
        task->brk = layout.heap_base;
        task->brk_limit = layout.heap_limit;
    } else {
        task->brk_base = 0;
        task->brk = 0;
        task->brk_limit = 0;
    }
    task->user_stack_top = 0;
    task->user_stack_size = 0;
    task->pending_signals = 0;
    for (int i = 0; i < 32; ++i) task->sig_handlers[i] = 0;
    task->name = name ? name : "task";
    task->fds = NULL;
    task_fd_init(task);
    task->next = NULL;
    t->task = task;
    if (!g_task_head) {
        g_task_head = g_task_tail = task;
    } else {
        g_task_tail->next = task;
        g_task_tail = task;
    }
    return task;
}

void task_set_user_layout(struct task *t, uint64_t brk_base, uint64_t brk_limit,
                          uint64_t stack_top, uint64_t stack_size) {
    if (!t) return;
    t->is_user = 1;
    t->brk_base = brk_base;
    t->brk = brk_base;
    t->brk_limit = brk_limit;
    t->user_stack_top = stack_top;
    t->user_stack_size = stack_size;
}

void task_clone_from(struct task *dst, const struct task *src) {
    if (!dst || !src) return;
    dst->is_user = src->is_user;
    dst->pml4_phys = src->pml4_phys;
    dst->brk_base = src->brk_base;
    dst->brk = src->brk;
    dst->brk_limit = src->brk_limit;
    dst->user_stack_top = src->user_stack_top;
    dst->user_stack_size = src->user_stack_size;
    dst->pending_signals = 0;
    for (int i = 0; i < 32; ++i) {
        dst->sig_handlers[i] = src->sig_handlers[i];
    }
    if (!dst->fds) {
        dst->fds = (struct task_fd *)kmalloc(sizeof(struct task_fd) * 16);
    }
    if (dst->fds && src->fds) {
        for (int i = 0; i < 16; ++i) {
            dst->fds[i] = src->fds[i];
        }
    }
}

void task_on_thread_exit(struct thread *t) {
    if (!t || !t->task) return;
    t->task->state = TASK_DEAD;
}

uint32_t task_pid(struct task *t) {
    return t ? t->pid : 0;
}

struct task *task_find_pid(uint32_t pid) {
    struct task *cur = g_task_head;
    while (cur) {
        if (cur->pid == pid) return cur;
        cur = cur->next;
    }
    return NULL;
}

int task_signal_set_handler(struct task *t, int sig, uint64_t handler) {
    if (!t) return -1;
    if (sig <= 0 || sig >= 32) return -1;
    /* Only allow default or ignore for now. */
    if (handler > 1) return -1;
    t->sig_handlers[sig] = handler;
    return 0;
}

void task_signal_raise(struct task *t, int sig) {
    if (!t) return;
    if (sig <= 0 || sig >= 32) return;
    t->pending_signals |= (1u << (uint32_t)sig);
}

static int default_action(int sig) {
    switch (sig) {
        case 2:  /* SIGINT */
        case 9:  /* SIGKILL */
        case 11: /* SIGSEGV */
        case 15: /* SIGTERM */
            return 1;
        default:
            return 0;
    }
}

int task_signal_handle_pending(struct task *t) {
    if (!t || !t->pending_signals) return 0;
    for (int sig = 1; sig < 32; ++sig) {
        uint32_t mask = 1u << (uint32_t)sig;
        if (!(t->pending_signals & mask)) continue;
        t->pending_signals &= ~mask;
        uint64_t handler = t->sig_handlers[sig];
        if (handler == 1) {
            return 0; /* SIG_IGN */
        }
        if (default_action(sig)) {
            log_printf("signal %d default: terminate pid=%u\n", sig, (unsigned)t->pid);
            return 1;
        }
        return 0;
    }
    return 0;
}

static const char *task_state_name(uint32_t st) {
    switch (st) {
        case TASK_READY: return "ready";
        case TASK_RUNNING: return "running";
        case TASK_BLOCKED: return "blocked";
        case TASK_DEAD: return "dead";
        default: return "unknown";
    }
}

void task_dump_list(void) {
    struct task *cur = g_task_head;
    if (!cur) {
        log_printf("ps: no tasks\n");
        return;
    }
    log_printf("PID  TID  STATE    PML4        NAME\n");
    while (cur) {
        log_printf("%u   %u   %s   0x%08x %s\n",
                   (unsigned)cur->pid,
                   (unsigned)cur->tid,
                   task_state_name(cur->state),
                   (unsigned)cur->pml4_phys,
                   cur->name ? cur->name : "-");
        cur = cur->next;
    }
}
