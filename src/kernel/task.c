#include "kernel/task.h"

#include <stddef.h>

#include "lib/compat.h"
#include "lib/log.h"
#include "kernel/heap.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/thread.h"
#include "kernel/sched.h"
#include "kernel/socket.h"

static uint32_t g_next_pid = 2;
static struct task g_boot_task;
static struct task *g_task_head = NULL;
static struct task *g_task_tail = NULL;
static struct task_fd g_boot_fds[16];
static const uint64_t g_mmap_base_default = 0x0000000080000000ull;
static const uint64_t g_mmap_limit_default = 0x00000000F0000000ull;

static void fd_set_console(struct task_fd *fd) {
    if (!fd) return;
    fd->used = 1;
    fd->type = FD_TYPE_CONSOLE;
    fd->node = -1;
    fd->sock_id = -1;
    fd->offset = 0;
    fd->flags = 0;
}

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
    fd_set_console(&t->fds[0]);
    fd_set_console(&t->fds[1]);
    fd_set_console(&t->fds[2]);
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
            t->fds[i].type = FD_TYPE_FILE;
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
            t->fds[i].type = FD_TYPE_SOCKET;
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
    if (t->fds[fd].type == FD_TYPE_SOCKET && t->fds[fd].sock_id >= 0) {
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
    g_boot_task.mmap_base = g_mmap_base_default;
    g_boot_task.mmap_limit = g_mmap_limit_default;
    g_boot_task.pending_signals = 0;
    for (int i = 0; i < 32; ++i) g_boot_task.sig_handlers[i] = 0;
    g_boot_task.name = t->name ? t->name : "bootstrap";
    g_boot_task.fds = g_boot_fds;
    g_boot_task.maps = NULL;
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
    task->mmap_base = g_mmap_base_default;
    task->mmap_limit = g_mmap_limit_default;
    task->pending_signals = 0;
    for (int i = 0; i < 32; ++i) task->sig_handlers[i] = 0;
    task->name = name ? name : "task";
    task->fds = NULL;
    task->maps = NULL;
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
    t->mmap_base = g_mmap_base_default;
    if (stack_top && stack_size) {
        uint64_t guard = 0x00100000ull;
        uint64_t top = stack_top;
        if (top > guard) {
            uint64_t limit = top - guard;
            if (limit > g_mmap_base_default) t->mmap_limit = limit;
        }
    }
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
    dst->mmap_base = src->mmap_base;
    dst->mmap_limit = src->mmap_limit;
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
    dst->maps = NULL;
    if (src->maps) {
        struct task_map *cur = src->maps;
        struct task_map *tail = NULL;
        while (cur) {
            struct task_map *m = (struct task_map *)kmalloc(sizeof(*m));
            if (!m) break;
            *m = *cur;
            m->next = NULL;
            if (!dst->maps) dst->maps = m;
            else tail->next = m;
            tail = m;
            cur = cur->next;
        }
    }
}

static int map_overlaps(const struct task_map *m, uint64_t base, uint64_t size) {
    uint64_t end = base + size;
    uint64_t m_end = m->base + m->size;
    return (base < m_end) && (end > m->base);
}

static int range_free(const struct task *t, uint64_t base, uint64_t size) {
    if (!t) return 0;
    if (size == 0) return 0;
    if (base < t->mmap_base || base + size > t->mmap_limit) return 0;
    const struct task_map *cur = t->maps;
    while (cur) {
        if (map_overlaps(cur, base, size)) return 0;
        cur = cur->next;
    }
    return 1;
}

static void insert_map_sorted(struct task *t, struct task_map *m) {
    if (!t || !m) return;
    if (!t->maps || m->base < t->maps->base) {
        m->next = t->maps;
        t->maps = m;
        return;
    }
    struct task_map *cur = t->maps;
    while (cur->next && cur->next->base < m->base) {
        cur = cur->next;
    }
    m->next = cur->next;
    cur->next = m;
}

uint64_t task_mmap_anonymous(struct task *t, uint64_t addr, uint64_t len, uint32_t prot, uint32_t flags) {
    if (!t || !t->is_user) return 0;
    if (len == 0) return 0;
    uint64_t size = (len + 0xFFFull) & ~0xFFFull;
    uint64_t base = addr & ~0xFFFull;

    if (base != 0) {
        if (!range_free(t, base, size)) return 0;
    } else {
        base = t->mmap_base;
        while (base + size <= t->mmap_limit) {
            if (range_free(t, base, size)) break;
            base += 0x1000ull;
        }
        if (base + size > t->mmap_limit) return 0;
    }

    for (uint64_t va = base; va < base + size; va += 0x1000ull) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) return 0;
        if (paging_map_user_4k(t->pml4_phys, va, phys, 0) != 0) return 0;
    }

    struct task_map *m = (struct task_map *)kmalloc(sizeof(*m));
    if (!m) return 0;
    m->base = base;
    m->size = size;
    m->prot = prot;
    m->flags = flags;
    m->next = NULL;
    insert_map_sorted(t, m);
    return base;
}

int task_munmap(struct task *t, uint64_t addr, uint64_t len) {
    if (!t || !t->is_user) return -1;
    if (len == 0) return -1;
    uint64_t size = (len + 0xFFFull) & ~0xFFFull;
    uint64_t base = addr & ~0xFFFull;

    struct task_map *prev = NULL;
    struct task_map *cur = t->maps;
    while (cur) {
        if (cur->base == base && cur->size == size) break;
        prev = cur;
        cur = cur->next;
    }
    if (!cur) return -1;

    for (uint64_t va = base; va < base + size; va += 0x1000ull) {
        uint64_t phys = paging_unmap_user_4k(t->pml4_phys, va);
        if (phys) pmm_dec_ref(phys);
    }

    if (prev) prev->next = cur->next;
    else t->maps = cur->next;
    kfree(cur);
    return 0;
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

static void buf_append(char **dst, size_t *remain, const char *s) {
    if (!dst || !*dst || !remain || !s) return;
    while (*s && *remain > 1) {
        **dst = *s++;
        (*dst)++;
        (*remain)--;
    }
}

static void buf_append_u32(char **dst, size_t *remain, uint32_t v) {
    char tmp[16];
    size_t n = 0;
    if (v == 0) {
        if (*remain > 1) {
            **dst = '0';
            (*dst)++;
            (*remain)--;
        }
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0 && *remain > 1) {
        **dst = tmp[--n];
        (*dst)++;
        (*remain)--;
    }
}

static void buf_append_hex32(char **dst, size_t *remain, uint32_t v) {
    static const char hex[] = "0123456789abcdef";
    if (*remain <= 2) return;
    **dst = '0'; (*dst)++; (*remain)--;
    **dst = 'x'; (*dst)++; (*remain)--;
    for (int i = 7; i >= 0; --i) {
        if (*remain <= 1) break;
        uint32_t nib = (v >> (i * 4)) & 0xF;
        **dst = hex[nib];
        (*dst)++;
        (*remain)--;
    }
}

size_t task_format_list(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return 0;
    char *w = buf;
    size_t remain = buf_len;
    struct task *cur = g_task_head;
    if (!cur) {
        buf_append(&w, &remain, "ps: no tasks\n");
        *w = '\0';
        return (size_t)(w - buf);
    }
    buf_append(&w, &remain, "PID  TID  STATE    PML4        NAME\n");
    while (cur) {
        buf_append_u32(&w, &remain, cur->pid);
        buf_append(&w, &remain, "   ");
        buf_append_u32(&w, &remain, cur->tid);
        buf_append(&w, &remain, "   ");
        buf_append(&w, &remain, task_state_name(cur->state));
        buf_append(&w, &remain, "   ");
        buf_append_hex32(&w, &remain, (uint32_t)cur->pml4_phys);
        buf_append(&w, &remain, " ");
        buf_append(&w, &remain, cur->name ? cur->name : "-");
        buf_append(&w, &remain, "\n");
        cur = cur->next;
    }
    *w = '\0';
    return (size_t)(w - buf);
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
