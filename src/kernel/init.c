#include "kernel/init.h"

#include <stddef.h>

#include "kernel/heap.h"
#include "kernel/task.h"
#include "kernel/thread.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/usermode.h"
#include "lib/log.h"
#include "sys/boot_params.h"
#include "sys/elf_loader.h"
#include "sys/vfs.h"

struct init_payload {
    char path[128];
    int argc;
    char *argv[4];
    char arg0[128];
    char arg1[32];
};

static int vfs_path_exists(const char *path) {
    if (!path || !path[0]) return 0;
    int node = vfs_resolve(0, path);
    return node >= 0;
}

static void init_thread(void *arg) {
    struct init_payload *p = (struct init_payload *)arg;
    if (!p) {
        thread_exit();
    }

    uint64_t entry = 0;
    uint64_t pml4 = 0;
    uint64_t rsp = 0;
    struct user_addr_space layout;
    paging_user_layout_default(&layout);

    int rc = elf_load_user(p->path, p->argc, p->argv, NULL,
                           &layout, &entry, &pml4, &rsp);
    if (rc != 0) {
        log_printf("init: exec failed rc=%d path=%s\n", rc, p->path);
        kfree(p);
        thread_exit();
    }

    struct thread *t = thread_current();
    struct task *task = task_current();
    if (t) {
        t->is_user = 1;
        t->pml4_phys = pml4;
    }
    if (task) {
        task_set_user_layout(task, layout.heap_base, layout.heap_limit,
                             layout.stack_top, layout.stack_size,
                             layout.mmap_base, layout.mmap_limit);
        task->pml4_phys = pml4;
    }

    paging_switch_to(pml4);
    kfree(p);
    user_enter_iret(entry, rsp, 0x202);
    __builtin_unreachable();
}

int init_spawn(void) {
    const char *init_param = boot_param_get("init");
    const char *candidates[] = {
        init_param,
        "/bin/init",
        "/sbin/init",
        "/init",
        "/bin/sh",
        "/bin/busybox",
        NULL
    };

    const char *chosen = NULL;
    int use_busybox = 0;
    for (int i = 0; candidates[i]; ++i) {
        if (candidates[i] && vfs_path_exists(candidates[i])) {
            chosen = candidates[i];
            if (candidates[i][0] == '/' &&
                candidates[i][1] == 'b' &&
                candidates[i][2] == 'i' &&
                candidates[i][3] == 'n' &&
                candidates[i][4] == '/' &&
                candidates[i][5] == 'b') {
                use_busybox = 1;
            }
            break;
        }
    }

    if (!chosen) {
        log_printf("init: no init binary found\n");
        return -1;
    }

    struct init_payload *p = (struct init_payload *)kmalloc(sizeof(*p));
    if (!p) return -1;
    p->argc = 1;
    p->argv[0] = p->arg0;
    p->argv[1] = NULL;
    p->argv[2] = NULL;
    p->argv[3] = NULL;
    p->arg0[0] = '\0';
    p->arg1[0] = '\0';

    /* Copy path */
    size_t n = 0;
    while (chosen[n] && n + 1 < sizeof(p->path)) {
        p->path[n] = chosen[n];
        n++;
    }
    p->path[n] = '\0';

    /* argv[0] = path by default */
    n = 0;
    while (p->path[n] && n + 1 < sizeof(p->arg0)) {
        p->arg0[n] = p->path[n];
        n++;
    }
    p->arg0[n] = '\0';

    if (use_busybox) {
        p->argc = 2;
        p->argv[0] = p->arg0;
        p->argv[1] = p->arg1;
        n = 0;
        const char *sh = "sh";
        while (sh[n] && n + 1 < sizeof(p->arg1)) {
            p->arg1[n] = sh[n];
            n++;
        }
        p->arg1[n] = '\0';
    }

    log_printf("init: spawning %s\n", p->path);
    struct thread *t = thread_create(init_thread, p, 8192, "init");
    if (!t) {
        kfree(p);
        return -1;
    }
    return 0;
}
