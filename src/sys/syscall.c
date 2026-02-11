#include "sys/syscall.h"

#include <stddef.h>

#include "arch/x86_64/cpu.h"
#include "kernel/sleep.h"
#include "kernel/task.h"
#include "kernel/thread.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/heap.h"
#include "lib/log.h"
#include "sys/elf_loader.h"
#include "sys/vfs.h"
#include "sys/fcntl.h"
#include "arch/x86_64/usermode.h"
#include "kernel/socket.h"
#include "kernel/dhcp.h"
#include "sys/journal.h"
#include "sys/initramfs.h"
#include "sys/fat32.h"
#include "sys/ext2.h"
#include "sys/fs_mock.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);

typedef uint64_t (*syscall_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t sys_write_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    const uint8_t *buf = (const uint8_t *)a2;
    uint64_t len = a3;
    if (!buf || len == 0) return 0;
    if (len > 4096) len = 4096;

    struct task *t = task_current();
    if (!t) {
        for (uint64_t i = 0; i < len; ++i) log_printf("%c", (char)buf[i]);
        return len;
    }
    struct task_fd *ent = task_fd_get(t, fd);
    if (!ent) return (uint64_t)-1;
    if (ent->type == FD_TYPE_CONSOLE) {
        for (uint64_t i = 0; i < len; ++i) log_printf("%c", (char)buf[i]);
        return len;
    }
    if (ent->type != FD_TYPE_FILE) return (uint64_t)-1;
    if (ent->flags & O_APPEND) {
        ent->offset = vfs_get_size(ent->node);
    }
    int rc = vfs_write_file(ent->node, buf, len, ent->offset);
    if (rc < 0) return (uint64_t)-1;
    ent->offset += (uint64_t)rc;
    return (uint64_t)rc;
}

static uint64_t sys_exit_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint64_t code = a1;
    struct thread *t = thread_current();
    if (t && t->is_user) {
        log_printf("\n[sys_exit] tid=%u code=%u\n", (unsigned)t->id, (unsigned)code);
        thread_exit();
    }
    log_printf("\n[sys_exit] code=%u\n", (unsigned)code);
    halt_forever();
    return 0;
}

static uint64_t sys_sleep_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    sleep_ms(a1);
    return 0;
}

static uint64_t sys_sbrk_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *task = task_current();
    if (!task || !task->is_user) return (uint64_t)-1;
    int64_t inc = (int64_t)a1;
    uint64_t old = task->brk;
    if (inc == 0) return old;

    uint64_t new_brk;
    if (inc > 0) {
        if (task->brk + (uint64_t)inc < task->brk) return (uint64_t)-1;
        new_brk = task->brk + (uint64_t)inc;
    } else {
        int64_t dec = -inc;
        if (task->brk < task->brk_base + (uint64_t)dec) return (uint64_t)-1;
        new_brk = task->brk - (uint64_t)dec;
    }
    if (new_brk > task->brk_limit) return (uint64_t)-1;

    uint64_t old_page = (old + 0xFFF) & ~0xFFFULL;
    uint64_t new_page = (new_brk + 0xFFF) & ~0xFFFULL;
    if (new_page > old_page) {
        if (!task_charge_mem(task, new_page - old_page)) return (uint64_t)-1;
        for (uint64_t va = old_page; va < new_page; va += 0x1000ULL) {
            uint64_t phys = pmm_alloc_frame();
            if (phys == 0) {
                task_uncharge_mem(task, new_page - old_page);
                return (uint64_t)-1;
            }
            if (paging_map_user_4k(task->pml4_phys, va, phys, 0) != 0) {
                task_uncharge_mem(task, new_page - old_page);
                return (uint64_t)-1;
            }
        }
    } else if (new_page < old_page) {
        task_uncharge_mem(task, old_page - new_page);
    }
    task->brk = new_brk;
    return old;
}

static uint64_t sys_open_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    uint32_t flags = (uint32_t)a2;
    if (!path) return (uint64_t)-1;
    int node = vfs_resolve(0, path);
    if (node < 0) {
        if (flags & O_CREAT) {
            node = vfs_create(0, path, 0);
        }
        if (node < 0) return (uint64_t)-1;
    } else {
        if (vfs_is_dir(node)) return (uint64_t)-1;
        if (flags & O_TRUNC) {
            if (vfs_truncate(node, 0) != 0) return (uint64_t)-1;
        }
    }
    if (vfs_is_dir(node)) return (uint64_t)-1;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    int fd = task_fd_alloc(t, node, flags);
    if (fd < 0) return (uint64_t)-1;
    struct task_fd *ent = task_fd_get(t, fd);
    if (ent && (flags & O_APPEND)) {
        ent->offset = vfs_get_size(node);
    }
    return (uint64_t)fd;
}

static uint64_t sys_read_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    uint8_t *buf = (uint8_t *)a2;
    uint64_t len = a3;
    if (!buf || len == 0) return 0;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    struct task_fd *ent = task_fd_get(t, fd);
    if (!ent) return (uint64_t)-1;
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(ent->node, &data, &size) || !data) return (uint64_t)-1;
    if (ent->offset >= size) return 0;
    uint64_t avail = size - ent->offset;
    uint64_t to_copy = len < avail ? len : avail;
    memcpy(buf, data + ent->offset, (size_t)to_copy);
    ent->offset += to_copy;
    return to_copy;
}

static uint64_t sys_close_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)task_fd_close(t, fd);
}

struct fork_ctx {
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t pml4_phys;
};

static void fork_trampoline(void *arg) {
    struct fork_ctx *ctx = (struct fork_ctx *)arg;
    if (!ctx) {
        thread_exit();
    }
    uint64_t rip = ctx->rip;
    uint64_t rsp = ctx->rsp;
    uint64_t rflags = ctx->rflags;
    uint64_t pml4 = ctx->pml4_phys;
    kfree(ctx);
    if (pml4) {
        paging_switch_to(pml4);
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("xor %%rax, %%rax" ::: "rax");
#endif
    user_enter_iret(rip, rsp, rflags);
}

static uint64_t sys_fork_impl(struct syscall_frame *f) {
    struct thread *parent = thread_current();
    struct task *ptask = task_current();
    if (!parent || !ptask || !parent->is_user) return (uint64_t)-1;

    struct fork_ctx *ctx = (struct fork_ctx *)kmalloc(sizeof(*ctx));
    if (!ctx) return (uint64_t)-1;
    ctx->rip = f->rip;
    ctx->rsp = f->rsp;
    ctx->rflags = f->rflags;
    ctx->pml4_phys = paging_clone_user_pml4(parent->pml4_phys);
    if (ctx->pml4_phys == 0) {
        kfree(ctx);
        return (uint64_t)-1;
    }

    struct thread *child = thread_create(fork_trampoline, ctx, 8192, "fork");
    if (!child) {
        kfree(ctx);
        return (uint64_t)-1;
    }
    child->is_user = 1;
    child->pml4_phys = ctx->pml4_phys;
    if (child->task) {
        task_clone_from(child->task, ptask);
        child->task->pml4_phys = ctx->pml4_phys;
    }
    paging_switch_to(parent->pml4_phys);
    return (uint64_t)task_pid_ns(child->task);
}

static uint64_t sys_exec_impl(uint64_t a1, uint64_t a2, uint64_t a3) {
    const char *path = (const char *)a1;
    int argc = (int)a2;
    char **argv = (char **)a3;
    struct thread *t = thread_current();
    struct task *task = task_current();
    if (!t || !task || !path) return (uint64_t)-1;
    if (argc < 0 || argc > 16) return (uint64_t)-1;

    char **kargv = NULL;
    if (argc > 0) {
        kargv = (char **)kmalloc(sizeof(char *) * (size_t)(argc + 1));
        if (!kargv) return (uint64_t)-1;
        for (int i = 0; i < argc; ++i) kargv[i] = NULL;
        kargv[argc] = NULL;
        for (int i = 0; i < argc; ++i) {
            const char *u = argv ? argv[i] : NULL;
            if (!u) continue;
            size_t len = 0;
            while (u[len] && len < 255) len++;
            char *buf = (char *)kmalloc(len + 1);
            if (!buf) continue;
            for (size_t j = 0; j < len; ++j) buf[j] = u[j];
            buf[len] = '\0';
            kargv[i] = buf;
        }
    }

    uint64_t entry = 0;
    uint64_t pml4 = 0;
    uint64_t rsp = 0;
    uint64_t stack_top = 0;
    uint64_t stack_size = 0;
    int rc = elf_load_user(path, argc, kargv ? kargv : argv, NULL, &entry, &pml4, &rsp, &stack_top, &stack_size);
    if (kargv) {
        for (int i = 0; i < argc; ++i) {
            if (kargv[i]) kfree(kargv[i]);
        }
        kfree(kargv);
    }
    if (rc != 0) {
        log_printf("exec: failed rc=%d\n", rc);
        return (uint64_t)-1;
    }

    t->is_user = 1;
    t->pml4_phys = pml4;
    if (task) {
        task_set_user_layout(task, 0x0000000040000000ull, 0x0000000080000000ull,
                             stack_top, stack_size);
        task->pml4_phys = pml4;
    }
    paging_switch_to(pml4);
    user_enter_iret(entry, rsp, 0x202);
    __builtin_unreachable();
}

static uint64_t sys_signal_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int sig = (int)a1;
    uint64_t handler = a2;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)task_signal_set_handler(t, sig, handler);
}

static uint64_t sys_kill_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    uint32_t pid = (uint32_t)a1;
    int sig = (int)a2;
    struct task *t = task_find_pid(pid);
    if (!t) return (uint64_t)-1;
    task_signal_raise(t, sig);
    return 0;
}

static int fd_to_socket(struct task *t, int fd) {
    if (!t) return -1;
    struct task_fd *ent = task_fd_get(t, fd);
    if (!ent) return -1;
    if (ent->type != 2 || ent->sock_id < 0) return -1;
    return ent->sock_id;
}

static uint64_t sys_socket_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int domain = (int)a1;
    int type = (int)a2;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    int sid = socket_create(domain, type);
    if (sid < 0) return (uint64_t)-1;
    int fd = task_fd_alloc_socket(t, sid);
    if (fd < 0) {
        socket_close(sid);
        return (uint64_t)-1;
    }
    return (uint64_t)fd;
}

static uint64_t sys_bind_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    uint16_t port = (uint16_t)a2;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_bind(sid, port);
}

static uint64_t sys_connect_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    const uint8_t *ip = (const uint8_t *)a2;
    uint16_t port = (uint16_t)a3;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_connect(sid, ip, port);
}

static uint64_t sys_connect6_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    const uint8_t *ip = (const uint8_t *)a2;
    uint16_t port = (uint16_t)a3;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_connect6(sid, ip, port);
}

static uint64_t sys_sendto_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a6;
    int fd = (int)a1;
    const uint8_t *buf = (const uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    const uint8_t *ip = (const uint8_t *)a4;
    uint16_t port = (uint16_t)a5;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_sendto(sid, buf, len, ip, port);
}

static uint64_t sys_sendto6_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a6;
    int fd = (int)a1;
    const uint8_t *buf = (const uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    const uint8_t *ip = (const uint8_t *)a4;
    uint16_t port = (uint16_t)a5;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_sendto6(sid, buf, len, ip, port);
}

static uint64_t sys_recvfrom_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a6;
    int fd = (int)a1;
    uint8_t *buf = (uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    uint8_t *out_ip = (uint8_t *)a4;
    uint16_t *out_port = (uint16_t *)a5;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_recvfrom(sid, buf, len, out_ip, out_port);
}

static uint64_t sys_recvfrom6_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a6;
    int fd = (int)a1;
    uint8_t *buf = (uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    uint8_t *out_ip = (uint8_t *)a4;
    uint16_t *out_port = (uint16_t *)a5;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_recvfrom6(sid, buf, len, out_ip, out_port);
}

static uint64_t sys_listen_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_listen(sid);
}

static uint64_t sys_accept_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    int new_sid = socket_accept(sid);
    if (new_sid < 0) return (uint64_t)-1;
    int new_fd = task_fd_alloc_socket(t, new_sid);
    if (new_fd < 0) {
        socket_close(new_sid);
        return (uint64_t)-1;
    }
    return (uint64_t)new_fd;
}

static uint64_t sys_send_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    const uint8_t *buf = (const uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_sendto(sid, buf, len, NULL, 0);
}

static uint64_t sys_recv_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    uint8_t *buf = (uint8_t *)a2;
    uint16_t len = (uint16_t)a3;
    struct task *t = task_current();
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_recvfrom(sid, buf, len, NULL, NULL);
}

static uint64_t sys_mmap_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    uint64_t addr = a1;
    uint64_t len = a2;
    uint32_t prot = (uint32_t)a3;
    uint32_t flags = (uint32_t)a4;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    uint64_t out = task_mmap_anonymous(t, addr, len, prot, flags);
    if (out == 0) return (uint64_t)-1;
    return out;
}

static uint64_t sys_munmap_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    uint64_t addr = a1;
    uint64_t len = a2;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)task_munmap(t, addr, len);
}

static uint64_t sys_getdns_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint8_t *out = (uint8_t *)a1;
    if (!out) return (uint64_t)-1;
    if (dhcp_get_dns(out) != 0) return (uint64_t)-1;
    return 0;
}

static uint64_t sys_listdir_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    char *buf = (char *)a2;
    uint64_t len = a3;
    if (!buf || len == 0) return (uint64_t)-1;
    int rc = vfs_list_dir(path, buf, len);
    return (rc < 0) ? (uint64_t)-1 : (uint64_t)rc;
}

static uint64_t sys_mount_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    uint32_t part = (uint32_t)a1;
    uint32_t type = (uint32_t)a2; /* 1=ext2, 2=fat32 */
    if (type == 1) {
        if (ext2_init_from_partition(part) != 0) return (uint64_t)-1;
        vfs_set_root(VFS_BACKEND_EXT2, ext2_root());
        journal_init();
        return 0;
    }
    if (type == 2) {
        if (fat32_init_from_partition(part) != 0) return (uint64_t)-1;
        vfs_set_root(VFS_BACKEND_FAT32, fat32_root());
        return 0;
    }
    return (uint64_t)-1;
}

static uint64_t sys_umount_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    if (initramfs_available()) {
        vfs_set_root(VFS_BACKEND_INITRAMFS, initramfs_root());
        return 0;
    }
    vfs_set_root(VFS_BACKEND_MOCK, fs_root());
    return 0;
}

static uint64_t sys_unshare_pid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    uint32_t ns_id = task_unshare_pidns(t);
    return ns_id ? (uint64_t)ns_id : (uint64_t)-1;
}

static uint64_t sys_unshare_mnt_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    uint32_t ns_id = task_unshare_mntns(t);
    return ns_id ? (uint64_t)ns_id : (uint64_t)-1;
}

static uint64_t sys_unshare_net_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    uint32_t ns_id = task_unshare_netns(t);
    return ns_id ? (uint64_t)ns_id : (uint64_t)-1;
}

static syscall_fn g_syscalls[SYS_MAX] = {
    0,
    sys_write_impl,
    sys_exit_impl,
    sys_sleep_impl,
    sys_sbrk_impl,
    sys_open_impl,
    sys_read_impl,
    sys_close_impl,
    0,
    0,
    sys_signal_impl,
    sys_kill_impl,
    sys_socket_impl,
    sys_bind_impl,
    sys_connect_impl,
    sys_sendto_impl,
    sys_recvfrom_impl,
    sys_listen_impl,
    sys_accept_impl,
    sys_send_impl,
    sys_recv_impl,
    sys_mmap_impl,
    sys_munmap_impl,
    sys_getdns_impl,
    sys_listdir_impl,
    sys_mount_impl,
    sys_umount_impl,
    sys_connect6_impl,
    sys_sendto6_impl,
    sys_recvfrom6_impl,
    sys_unshare_pid_impl,
    sys_unshare_mnt_impl,
    sys_unshare_net_impl
};

uint64_t syscall_dispatch(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6) {
    if (num >= SYS_MAX) return (uint64_t)-1;
    syscall_fn fn = g_syscalls[num];
    if (!fn) return (uint64_t)-1;
    return fn(a1, a2, a3, a4, a5, a6);
}

uint64_t syscall_handler(struct syscall_frame *f) {
    if (!f) return (uint64_t)-1;
    uint64_t ret = 0;
    if (f->rax == SYS_FORK) {
        ret = sys_fork_impl(f);
        goto signal_check;
    }
    if (f->rax == SYS_EXEC) {
        ret = sys_exec_impl(f->rdi, f->rsi, f->rdx);
        goto signal_check;
    }
    ret = syscall_dispatch(f->rax, f->rdi, f->rsi, f->rdx, f->r10, f->r8, f->r9);

signal_check:
    {
        struct thread *t = thread_current();
        if (t && t->is_user && t->task) {
            if (task_signal_handle_pending(t->task)) {
                thread_exit();
            }
        }
    }
    return ret;
}

__attribute__((naked))
void isr_syscall(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "push %r15\n"
        "push %r14\n"
        "push %r13\n"
        "push %r12\n"
        "push %r11\n"
        "push %r10\n"
        "push %r9\n"
        "push %r8\n"
        "push %rsi\n"
        "push %rdi\n"
        "push %rbp\n"
        "push %rdx\n"
        "push %rcx\n"
        "push %rbx\n"
        "push %rax\n"
        "mov %rsp, %rdi\n"
        "call syscall_handler\n"
        "mov %rax, (%rsp)\n"
        "pop %rax\n"
        "pop %rbx\n"
        "pop %rcx\n"
        "pop %rdx\n"
        "pop %rbp\n"
        "pop %rdi\n"
        "pop %rsi\n"
        "pop %r8\n"
        "pop %r9\n"
        "pop %r10\n"
        "pop %r11\n"
        "pop %r12\n"
        "pop %r13\n"
        "pop %r14\n"
        "pop %r15\n"
        "iretq\n"
    );
#else
    (void)syscall_handler;
    halt_forever();
#endif
}
