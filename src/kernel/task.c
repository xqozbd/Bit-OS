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
#include "kernel/netns.h"
#include "kernel/resgroup.h"
#include "sys/vfs.h"
#include "kernel/swap.h"
#include "sys/mman.h"

/* From memutils.c */
void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

static uint32_t g_next_pid = 2;
static uint32_t g_next_pidns_id = 1;
static uint32_t g_next_mntns_id = 1;
static uint32_t g_next_netns_id = 2;
static struct pid_namespace g_root_pidns;
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

static uint32_t pidns_next_pid(struct pid_namespace *ns) {
    if (!ns) return 0;
    return __atomic_fetch_add(&ns->next_pid, 1u, __ATOMIC_SEQ_CST);
}

static void pidns_ref(struct pid_namespace *ns) {
    if (!ns) return;
    __atomic_fetch_add(&ns->refcount, 1u, __ATOMIC_SEQ_CST);
}

static void pidns_unref(struct pid_namespace *ns) {
    if (!ns) return;
    if (__atomic_fetch_sub(&ns->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        if (ns != &g_root_pidns) kfree(ns);
    }
}

static void mntns_ref(struct mount_namespace *ns) {
    if (!ns) return;
    __atomic_fetch_add(&ns->refcount, 1u, __ATOMIC_SEQ_CST);
}

static void mntns_unref(struct mount_namespace *ns) {
    if (!ns) return;
    if (__atomic_fetch_sub(&ns->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        if (ns != vfs_root_namespace()) kfree(ns);
    }
}

struct task *task_current(void) {
    struct thread *t = thread_current();
    if (!t) return NULL;
    return t->task;
}

int task_charge_mem(struct task *t, uint64_t bytes) {
    if (!t || bytes == 0) return 1;
    if (!t->res_grp) return 0;
    if (!resgroup_charge_mem(t->res_grp, bytes)) return 0;
    t->res_mem_bytes += bytes;
    return 1;
}

void task_uncharge_mem(struct task *t, uint64_t bytes) {
    if (!t || bytes == 0 || !t->res_grp) return;
    if (t->res_mem_bytes < bytes) t->res_mem_bytes = 0;
    else t->res_mem_bytes -= bytes;
    resgroup_uncharge_mem(t->res_grp, bytes);
}

int task_charge_fd(struct task *t, uint32_t count) {
    if (!t || count == 0) return 1;
    if (!t->res_grp) return 0;
    if (!resgroup_charge_fd(t->res_grp, count)) return 0;
    t->res_fd_count += count;
    return 1;
}

void task_uncharge_fd(struct task *t, uint32_t count) {
    if (!t || count == 0 || !t->res_grp) return;
    if (t->res_fd_count < count) t->res_fd_count = 0;
    else t->res_fd_count -= count;
    resgroup_uncharge_fd(t->res_grp, count);
}

int task_charge_socket(struct task *t, uint32_t count) {
    if (!t || count == 0) return 1;
    if (!t->res_grp) return 0;
    if (!resgroup_charge_socket(t->res_grp, count)) return 0;
    t->res_sock_count += count;
    return 1;
}

void task_uncharge_socket(struct task *t, uint32_t count) {
    if (!t || count == 0 || !t->res_grp) return;
    if (t->res_sock_count < count) t->res_sock_count = 0;
    else t->res_sock_count -= count;
    resgroup_uncharge_socket(t->res_grp, count);
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
    task_charge_fd(t, 3);
}

struct task_fd *task_fd_get(struct task *t, int fd) {
    if (!t || !t->fds) return NULL;
    if (fd < 0 || fd >= 16) return NULL;
    if (!t->fds[fd].used) return NULL;
    return &t->fds[fd];
}

int task_fd_alloc(struct task *t, int node, uint32_t flags) {
    if (!t || !t->fds) return -1;
    if (!task_charge_fd(t, 1)) return -1;
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
    task_uncharge_fd(t, 1);
    return -1;
}

int task_fd_alloc_socket(struct task *t, int sock_id) {
    if (!t || !t->fds) return -1;
    if (!task_charge_fd(t, 1)) return -1;
    if (!task_charge_socket(t, 1)) {
        task_uncharge_fd(t, 1);
        return -1;
    }
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
    task_uncharge_socket(t, 1);
    task_uncharge_fd(t, 1);
    return -1;
}

int task_fd_close(struct task *t, int fd) {
    if (!t || !t->fds) return -1;
    if (fd < 0 || fd >= 16) return -1;
    if (!t->fds[fd].used) return -1;
    if (t->fds[fd].type == FD_TYPE_SOCKET && t->fds[fd].sock_id >= 0) {
        socket_close(t->fds[fd].sock_id);
        if (t->res_sock_count > 0) task_uncharge_socket(t, 1);
    }
    t->fds[fd].used = 0;
    t->fds[fd].type = 0;
    t->fds[fd].node = -1;
    t->fds[fd].sock_id = -1;
    t->fds[fd].offset = 0;
    t->fds[fd].flags = 0;
    if (t->res_fd_count > 0) task_uncharge_fd(t, 1);
    return 0;
}

void task_init_bootstrap(struct thread *t) {
    if (!t) return;
    g_root_pidns.id = g_next_pidns_id++;
    g_root_pidns.next_pid = 2;
    g_root_pidns.refcount = 1;
    g_boot_task.pid = 1;
    g_boot_task.pid_ns = &g_root_pidns;
    g_boot_task.pid_ns_pid = 1;
    g_boot_task.mnt_ns = vfs_root_namespace();
    mntns_ref(g_boot_task.mnt_ns);
    g_boot_task.net_ns = netns_root();
    netns_ref(g_boot_task.net_ns);
    g_boot_task.res_grp = resgroup_root();
    resgroup_ref(g_boot_task.res_grp);
    resgroup_acquire_task(g_boot_task.res_grp);
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
    g_boot_task.res_mem_bytes = 0;
    g_boot_task.res_fd_count = 0;
    g_boot_task.res_sock_count = 0;
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
    struct task *cur = task_current();
    if (cur && cur->pid_ns) {
        task->pid_ns = cur->pid_ns;
        pidns_ref(task->pid_ns);
    } else {
        task->pid_ns = &g_root_pidns;
        pidns_ref(task->pid_ns);
    }
    if (cur && cur->mnt_ns) {
        task->mnt_ns = cur->mnt_ns;
        mntns_ref(task->mnt_ns);
    } else {
        task->mnt_ns = vfs_root_namespace();
        mntns_ref(task->mnt_ns);
    }
    if (cur && cur->net_ns) {
        task->net_ns = cur->net_ns;
        netns_ref(task->net_ns);
    } else {
        task->net_ns = netns_root();
        netns_ref(task->net_ns);
    }
    if (cur && cur->res_grp) {
        task->res_grp = cur->res_grp;
        resgroup_ref(task->res_grp);
    } else {
        task->res_grp = resgroup_root();
        resgroup_ref(task->res_grp);
    }
    if (!resgroup_acquire_task(task->res_grp)) {
        if (task->pid_ns) pidns_unref(task->pid_ns);
        if (task->mnt_ns) mntns_unref(task->mnt_ns);
        if (task->net_ns) netns_unref(task->net_ns);
        resgroup_unref(task->res_grp);
        kfree(task);
        return NULL;
    }
    task->pid_ns_pid = pidns_next_pid(task->pid_ns);
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
        task->mmap_base = layout.mmap_base;
        task->mmap_limit = layout.mmap_limit;
    } else {
        task->brk_base = 0;
        task->brk = 0;
        task->brk_limit = 0;
    }
    task->user_stack_top = 0;
    task->user_stack_size = 0;
    if (!task->is_user) {
        task->mmap_base = g_mmap_base_default;
        task->mmap_limit = g_mmap_limit_default;
    }
    task->res_mem_bytes = 0;
    task->res_fd_count = 0;
    task->res_sock_count = 0;
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
                          uint64_t stack_top, uint64_t stack_size,
                          uint64_t mmap_base, uint64_t mmap_limit) {
    if (!t) return;
    t->is_user = 1;
    t->brk_base = brk_base;
    t->brk = brk_base;
    t->brk_limit = brk_limit;
    t->user_stack_top = stack_top;
    t->user_stack_size = stack_size;
    t->mmap_base = mmap_base ? mmap_base : g_mmap_base_default;
    t->mmap_limit = mmap_limit ? mmap_limit : g_mmap_limit_default;
    if (stack_top && stack_size) {
        uint64_t guard = 0x00100000ull;
        if (stack_top > guard) {
            uint64_t limit = stack_top - guard;
            if (limit > t->mmap_base && limit < t->mmap_limit) {
                t->mmap_limit = limit;
            }
        }
    }
    if (t->mmap_limit < t->mmap_base) t->mmap_limit = t->mmap_base;
}

void task_clone_from(struct task *dst, const struct task *src) {
    if (!dst || !src) return;
    if (dst->pid_ns) pidns_unref(dst->pid_ns);
    dst->pid_ns = src->pid_ns;
    if (dst->pid_ns) pidns_ref(dst->pid_ns);
    dst->pid_ns_pid = pidns_next_pid(dst->pid_ns);
    if (dst->mnt_ns) mntns_unref(dst->mnt_ns);
    dst->mnt_ns = src->mnt_ns;
    if (dst->mnt_ns) mntns_ref(dst->mnt_ns);
    if (dst->net_ns) netns_unref(dst->net_ns);
    dst->net_ns = src->net_ns;
    if (dst->net_ns) netns_ref(dst->net_ns);
    struct res_group *old_rg = dst->res_grp;
    dst->is_user = src->is_user;
    dst->pml4_phys = src->pml4_phys;
    dst->brk_base = src->brk_base;
    dst->brk = src->brk;
    dst->brk_limit = src->brk_limit;
    dst->user_stack_top = src->user_stack_top;
    dst->user_stack_size = src->user_stack_size;
    dst->mmap_base = src->mmap_base;
    dst->mmap_limit = src->mmap_limit;
    if (old_rg) {
        resgroup_uncharge_fd(old_rg, dst->res_fd_count);
        resgroup_uncharge_socket(old_rg, dst->res_sock_count);
        resgroup_uncharge_mem(old_rg, dst->res_mem_bytes);
    }
    if (old_rg && old_rg != src->res_grp) {
        resgroup_unref(old_rg);
    }
    dst->res_grp = src->res_grp;
    if (dst->res_grp && dst->res_grp != old_rg) {
        resgroup_ref(dst->res_grp);
    }
    dst->res_fd_count = src->res_fd_count;
    dst->res_sock_count = src->res_sock_count;
    dst->res_mem_bytes = src->res_mem_bytes;
    if (dst->res_grp) {
        resgroup_charge_fd(dst->res_grp, dst->res_fd_count);
        resgroup_charge_socket(dst->res_grp, dst->res_sock_count);
        resgroup_charge_mem(dst->res_grp, dst->res_mem_bytes);
    }
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
            m->pages = NULL;
            struct task_page *pcur = cur->pages;
            struct task_page *ptail = NULL;
            while (pcur) {
                struct task_page *np = (struct task_page *)kmalloc(sizeof(*np));
                if (!np) break;
                *np = *pcur;
                np->next = NULL;
                if (np->swapped) {
                    uint32_t new_slot = 0;
                    uint8_t *buf = (uint8_t *)kmalloc(0x1000u);
                    if (buf && swap_alloc(&new_slot) == 0 && swap_read(np->swap_slot, buf) == 0 &&
                        swap_write(new_slot, buf) == 0) {
                        np->swap_slot = new_slot;
                    } else {
                        np->swapped = 0;
                        np->swap_slot = 0;
                    }
                    if (buf) kfree(buf);
                }
                if (!m->pages) m->pages = np;
                else ptail->next = np;
                ptail = np;
                pcur = pcur->next;
            }
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

static struct task_map *find_map(struct task *t, uint64_t addr) {
    if (!t) return NULL;
    struct task_map *cur = t->maps;
    while (cur) {
        if (addr >= cur->base && addr < cur->base + cur->size) return cur;
        cur = cur->next;
    }
    return NULL;
}

static struct task_page *find_page(struct task_map *m, uint64_t vaddr) {
    if (!m) return NULL;
    struct task_page *p = m->pages;
    while (p) {
        if (p->vaddr == vaddr) return p;
        p = p->next;
    }
    return NULL;
}

static struct task_page *ensure_page(struct task_map *m, uint64_t vaddr) {
    struct task_page *p = find_page(m, vaddr);
    if (p) return p;
    p = (struct task_page *)kmalloc(sizeof(*p));
    if (!p) return NULL;
    p->vaddr = vaddr;
    p->phys = 0;
    p->swap_slot = 0;
    p->present = 0;
    p->swapped = 0;
    p->next = m->pages;
    m->pages = p;
    return p;
}

static int evict_one_page(void) {
    struct task *t = g_task_head;
    while (t) {
        if (!t->is_user) {
            t = t->next;
            continue;
        }
        struct task_map *m = t->maps;
        while (m) {
            struct task_page *p = m->pages;
            while (p) {
                if (p->present) {
                    uint64_t phys = p->phys;
                    if (m->map_type == MAP_FILE && !p->swapped) {
                        paging_unmap_user_4k(t->pml4_phys, p->vaddr);
                        pmm_dec_ref(phys);
                        task_uncharge_mem(t, 0x1000ull);
                        p->present = 0;
                        p->phys = 0;
                        return 1;
                    }
                    if (!swap_enabled()) return 0;
                    uint32_t slot = 0;
                    if (swap_alloc(&slot) != 0) return 0;
                    uint64_t hhdm = paging_hhdm_offset();
                    void *src = (void *)(uintptr_t)(hhdm + phys);
                    if (swap_write(slot, src) != 0) {
                        swap_free(slot);
                        return 0;
                    }
                    paging_unmap_user_4k(t->pml4_phys, p->vaddr);
                    pmm_dec_ref(phys);
                    task_uncharge_mem(t, 0x1000ull);
                    p->present = 0;
                    p->swapped = 1;
                    p->swap_slot = slot;
                    p->phys = 0;
                    return 1;
                }
                p = p->next;
            }
            m = m->next;
        }
        t = t->next;
    }
    return 0;
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

    struct task_map *m = (struct task_map *)kmalloc(sizeof(*m));
    if (!m) return 0;
    m->base = base;
    m->size = size;
    m->prot = prot;
    m->flags = flags;
    m->map_type = MAP_ANON;
    m->file_node = -1;
    m->file_off = 0;
    m->file_size = 0;
    m->pages = NULL;
    m->next = NULL;
    insert_map_sorted(t, m);
    return base;
}

uint64_t task_mmap_file(struct task *t, uint64_t addr, uint64_t len, uint32_t prot, uint32_t flags, int node, uint64_t off) {
    if (!t || !t->is_user) return 0;
    if (len == 0 || node < 0) return 0;
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

    struct task_map *m = (struct task_map *)kmalloc(sizeof(*m));
    if (!m) return 0;
    m->base = base;
    m->size = size;
    m->prot = prot;
    m->flags = flags;
    m->map_type = MAP_FILE;
    m->file_node = node;
    m->file_off = off;
    m->file_size = vfs_get_size(node);
    m->pages = NULL;
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

    struct task_page *p = cur->pages;
    while (p) {
        struct task_page *next = p->next;
        if (p->present) {
            if (cur->map_type == MAP_FILE && cur->file_node >= 0) {
                uint64_t off = cur->file_off + (p->vaddr - cur->base);
                uint64_t hhdm = paging_hhdm_offset();
                const uint8_t *src = (const uint8_t *)(uintptr_t)(hhdm + p->phys);
                vfs_write_file(cur->file_node, src, 0x1000u, off);
            }
            paging_unmap_user_4k(t->pml4_phys, p->vaddr);
            pmm_dec_ref(p->phys);
            task_uncharge_mem(t, 0x1000ull);
        }
        if (p->swapped) {
            swap_free(p->swap_slot);
        }
        kfree(p);
        p = next;
    }

    if (prev) prev->next = cur->next;
    else t->maps = cur->next;
    kfree(cur);
    return 0;
}

int task_handle_page_fault(struct task *t, uint64_t addr, uint64_t error_code) {
    if (!t || !t->is_user) return 0;
    if (error_code & 1u) return 0; /* present fault */
    uint64_t vaddr = addr & ~0xFFFull;
    struct task_map *m = find_map(t, vaddr);
    if (!m) return 0;

    struct task_page *p = ensure_page(m, vaddr);
    if (!p) return 0;
    if (p->present) return 1;

    uint64_t phys = pmm_alloc_frame();
    if (phys == 0) {
        if (evict_one_page()) {
            phys = pmm_alloc_frame();
        }
    }
    if (phys == 0) return 0;

    uint64_t map_flags = (m->prot & PROT_EXEC) ? 0 : PTE_NX;
    if (paging_map_user_4k(t->pml4_phys, vaddr, phys, map_flags) != 0) {
        pmm_dec_ref(phys);
        return 0;
    }

    uint64_t hhdm = paging_hhdm_offset();
    void *dst = (void *)(uintptr_t)(hhdm + phys);
    if (p->swapped) {
        if (swap_read(p->swap_slot, dst) != 0) {
            pmm_dec_ref(phys);
            return 0;
        }
        swap_free(p->swap_slot);
        p->swapped = 0;
        p->swap_slot = 0;
    } else if (m->map_type == MAP_FILE && m->file_node >= 0) {
        const uint8_t *data = NULL;
        uint64_t size = 0;
        if (vfs_read_file(m->file_node, &data, &size) && data) {
            uint64_t off = m->file_off + (vaddr - m->base);
            uint64_t avail = (off < size) ? (size - off) : 0;
            uint64_t copy = avail < 0x1000ull ? avail : 0x1000ull;
            if (copy > 0) memcpy(dst, data + off, (size_t)copy);
            if (copy < 0x1000ull) memset((uint8_t *)dst + copy, 0, (size_t)(0x1000ull - copy));
        } else {
            memset(dst, 0, 0x1000u);
        }
    } else {
        memset(dst, 0, 0x1000u);
    }

    p->present = 1;
    p->phys = phys;
    task_charge_mem(t, 0x1000ull);
    return 1;
}

void task_on_thread_exit(struct thread *t) {
    if (!t || !t->task) return;
    t->task->state = TASK_DEAD;
    if (t->task->res_grp) {
        resgroup_uncharge_fd(t->task->res_grp, t->task->res_fd_count);
        resgroup_uncharge_socket(t->task->res_grp, t->task->res_sock_count);
        resgroup_uncharge_mem(t->task->res_grp, t->task->res_mem_bytes);
        resgroup_release_task(t->task->res_grp);
        resgroup_unref(t->task->res_grp);
        t->task->res_grp = NULL;
        t->task->res_fd_count = 0;
        t->task->res_sock_count = 0;
        t->task->res_mem_bytes = 0;
    }
    if (t->task->pid_ns) {
        pidns_unref(t->task->pid_ns);
        t->task->pid_ns = NULL;
    }
    if (t->task->mnt_ns) {
        mntns_unref(t->task->mnt_ns);
        t->task->mnt_ns = NULL;
    }
    if (t->task->net_ns) {
        netns_unref(t->task->net_ns);
        t->task->net_ns = NULL;
    }
}

uint32_t task_pid(struct task *t) {
    return t ? t->pid : 0;
}

uint32_t task_pid_ns(struct task *t) {
    return t ? t->pid_ns_pid : 0;
}

uint32_t task_pid_ns_id(struct task *t) {
    return (t && t->pid_ns) ? t->pid_ns->id : 0;
}

uint32_t task_unshare_pidns(struct task *t) {
    if (!t) return 0;
    struct pid_namespace *ns = (struct pid_namespace *)kmalloc(sizeof(*ns));
    if (!ns) return 0;
    ns->id = g_next_pidns_id++;
    ns->next_pid = 2;
    ns->refcount = 1;
    if (t->pid_ns) pidns_unref(t->pid_ns);
    t->pid_ns = ns;
    t->pid_ns_pid = 1;
    return ns->id;
}

uint32_t task_unshare_mntns(struct task *t) {
    if (!t) return 0;
    struct mount_namespace *cur = t->mnt_ns;
    struct mount_namespace *ns = (struct mount_namespace *)kmalloc(sizeof(*ns));
    if (!ns) return 0;
    vfs_ns_clone(ns, cur);
    ns->id = g_next_mntns_id++;
    ns->refcount = 1;
    if (t->mnt_ns) mntns_unref(t->mnt_ns);
    t->mnt_ns = ns;
    return ns->id;
}

uint32_t task_unshare_netns(struct task *t) {
    if (!t) return 0;
    struct net_namespace *cur = t->net_ns ? t->net_ns : netns_root();
    struct net_namespace *ns = (struct net_namespace *)kmalloc(sizeof(*ns));
    if (!ns) return 0;
    netns_clone(ns, cur);
    ns->id = g_next_netns_id++;
    if (t->net_ns) netns_unref(t->net_ns);
    t->net_ns = ns;
    return ns->id;
}

uint32_t task_unshare_resgroup(struct task *t) {
    if (!t) return 0;
    struct res_group *cur = t->res_grp ? t->res_grp : resgroup_root();
    struct res_group *g = (struct res_group *)kmalloc(sizeof(*g));
    if (!g) return 0;
    resgroup_clone(g, cur);
    g->id = resgroup_new_id();
    if (!resgroup_move_task(t, g)) {
        kfree(g);
        return 0;
    }
    return g->id;
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

size_t task_format_list(struct task *viewer, char *buf, size_t buf_len) {
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
        if (viewer && viewer->pid_ns && cur->pid_ns != viewer->pid_ns) {
            cur = cur->next;
            continue;
        }
        buf_append_u32(&w, &remain, cur->pid_ns_pid ? cur->pid_ns_pid : cur->pid);
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
    struct task *viewer = task_current();
    struct task *cur = g_task_head;
    if (!cur) {
        log_printf("ps: no tasks\n");
        return;
    }
    log_printf("PID  TID  STATE    PML4        NAME\n");
    while (cur) {
        if (viewer && viewer->pid_ns && cur->pid_ns != viewer->pid_ns) {
            cur = cur->next;
            continue;
        }
        log_printf("%u   %u   %s   0x%08x %s\n",
                   (unsigned)(cur->pid_ns_pid ? cur->pid_ns_pid : cur->pid),
                   (unsigned)cur->tid,
                   task_state_name(cur->state),
                   (unsigned)cur->pml4_phys,
                   cur->name ? cur->name : "-");
        cur = cur->next;
    }
}
