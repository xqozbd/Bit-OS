#include "kernel/task.h"

#include <stddef.h>

#include "lib/compat.h"
#include "kernel/heap.h"
#include "kernel/thread.h"
#include "kernel/sched.h"

static uint32_t g_next_pid = 2;
static struct task g_boot_task;
static struct task *g_task_head = NULL;
static struct task *g_task_tail = NULL;

enum {
    USER_HEAP_BASE  = 0x0000000040000000ull,
    USER_HEAP_LIMIT = 0x0000000080000000ull
};

static uint32_t next_pid(void) {
    return __atomic_fetch_add(&g_next_pid, 1u, __ATOMIC_SEQ_CST);
}

struct task *task_current(void) {
    struct thread *t = thread_current();
    if (!t) return NULL;
    return t->task;
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
    g_boot_task.name = t->name ? t->name : "bootstrap";
    g_boot_task.next = NULL;
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
        task->brk_base = USER_HEAP_BASE;
        task->brk = USER_HEAP_BASE;
        task->brk_limit = USER_HEAP_LIMIT;
    } else {
        task->brk_base = 0;
        task->brk = 0;
        task->brk_limit = 0;
    }
    task->name = name ? name : "task";
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

void task_on_thread_exit(struct thread *t) {
    if (!t || !t->task) return;
    t->task->state = TASK_DEAD;
}

uint32_t task_pid(struct task *t) {
    return t ? t->pid : 0;
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
