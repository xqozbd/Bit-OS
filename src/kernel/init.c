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
#include "sys/initramfs.h"
#include "sys/vfs.h"

static int g_safe_mode = -1;

struct init_payload {
    char path[128];
    int argc;
    char *argv[6];
    char arg0[128];
    char arg1[64];
    char arg2[32];
};

static int vfs_path_node(const char *path) {
    if (!path || !path[0]) return -1;
    return vfs_resolve(0, path);
}

static int str_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

static int path_basename_eq(const char *path, const char *base) {
    if (!path || !base) return 0;
    const char *p = path;
    const char *last = path;
    while (*p) {
        if (*p == '/') last = p + 1;
        p++;
    }
    return str_eq(last, base);
}

static void str_copy(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static int safe_mode_from_params(void) {
    const char *safe_param = boot_param_get("safe");
    if (safe_param) {
        if (str_eq(safe_param, "0") || str_eq(safe_param, "off")) return 0;
        return 1;
    }
    if (boot_param_has("nomod")) return 1;
    return 0;
}

void init_set_safe_mode(int enabled) {
    g_safe_mode = enabled ? 1 : 0;
}

static void init_thread(void *arg) {
    struct init_payload *p = (struct init_payload *)arg;
    if (!p) {
        thread_exit();
    }

    log_printf("init: thread start path=%s argc=%d\n", p->path, p->argc);

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

    if (entry >= 0x0000800000000000ull || rsp >= 0x0000800000000000ull) {
        log_printf("init: bad user entry/rsp entry=%p rsp=%p\n",
                   (void *)(uintptr_t)entry, (void *)(uintptr_t)rsp);
        kfree(p);
        thread_exit();
    }
    log_printf("init: entering userspace entry=%p rsp=%p\n",
               (void *)(uintptr_t)entry, (void *)(uintptr_t)rsp);
    paging_switch_to(pml4);
    kfree(p);
    user_enter_iret(entry, rsp, 0x202);
    __builtin_unreachable();
}

int init_spawn(void) {
    if (!initramfs_available()) {
        if (initramfs_init_from_limine()) {
            vfs_set_root(VFS_BACKEND_INITRAMFS, initramfs_root());
        }
    }
    const char *init_param = boot_param_get("init");
    const char *candidates[] = {
        "/initramfs/bin/init",
        "/bin/init",
        "/sbin/init",
        "/initramfs/sbin/init",
        "/init",
        "/initramfs/init",
        "/bin/login",
        "/initramfs/bin/login",
        "/bin/sh",
        "/bin/busybox",
        "/initramfs/bin/sh",
        "/initramfs/bin/busybox",
        NULL
    };
    const char *boot_mode = boot_param_get("boot.mode");
    if (!boot_mode || !boot_mode[0]) boot_mode = "desktop";
    int safe_mode = (g_safe_mode >= 0) ? g_safe_mode : safe_mode_from_params();

    const char *chosen = NULL;
    int chosen_node = -1;
    int use_busybox = 0;
    if (init_param) {
        int node = vfs_path_node(init_param);
        if (node >= 0 && !vfs_is_dir(node)) {
            chosen = init_param;
            chosen_node = node;
        }
    }
    if (!chosen) {
        for (int i = 0; candidates[i]; ++i) {
            int node = vfs_path_node(candidates[i]);
            if (node >= 0 && !vfs_is_dir(node)) {
                chosen = candidates[i];
                chosen_node = node;
                break;
            }
        }
    }

    if (chosen && path_basename_eq(chosen, "busybox")) use_busybox = 1;

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
    p->argv[4] = NULL;
    p->argv[5] = NULL;
    p->arg0[0] = '\0';
    p->arg1[0] = '\0';
    p->arg2[0] = '\0';

    /* Copy path */
    str_copy(p->path, sizeof(p->path), chosen);

    /* argv[0] = path by default */
    str_copy(p->arg0, sizeof(p->arg0), p->path);

    if (path_basename_eq(p->path, "init")) {
        p->argc = 2;
        p->argv[1] = p->arg1;
        if (str_eq(boot_mode, "console")) {
            str_copy(p->arg1, sizeof(p->arg1), "--mode=console");
        } else {
            str_copy(p->arg1, sizeof(p->arg1), "--mode=desktop");
        }
        if (safe_mode) {
            p->argc = 3;
            p->argv[2] = p->arg2;
            str_copy(p->arg2, sizeof(p->arg2), "--safe-mode=1");
        }
    }

    if (use_busybox) {
        p->argc = 2;
        p->argv[0] = p->arg0;
        p->argv[1] = p->arg1;
        p->argv[2] = NULL;
        str_copy(p->arg1, sizeof(p->arg1), "sh");
    }

    log_printf("init: spawning %s (node=%d mode=%s safe=%d)\n",
               p->path, chosen_node, boot_mode, safe_mode);
    struct thread *t = thread_create(init_thread, p, 8192, "init");
    if (!t) {
        kfree(p);
        return -1;
    }
    return 0;
}
