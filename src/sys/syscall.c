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
#include "sys/mman.h"
#include "arch/x86_64/usermode.h"
#include "kernel/socket.h"
#include "kernel/dhcp.h"
#include "kernel/sched.h"
#include "arch/x86_64/timer.h"
#include "kernel/tty.h"
#include "kernel/pty.h"
#include "sys/journal.h"
#include "sys/initramfs.h"
#include "sys/fat32.h"
#include "sys/ext2.h"
#include "sys/fs_mock.h"
#include "kernel/pipe.h"
#include "drivers/ps2/keyboard.h"
#include "kernel/time.h"
#include "kernel/rng.h"
#include "sys/errno.h"
#include "sys/pseudofs.h"
#include "kernel/profiler.h"

#define SYS_ERR(e) ((uint64_t)(-(int)(e)))

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);

typedef uint64_t (*syscall_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint32_t g_fg_pgid = 0;

enum {
    CLOCK_REALTIME = 0,
    CLOCK_MONOTONIC = 1
};

struct timespec {
    uint64_t tv_sec;
    uint64_t tv_nsec;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

#define POLLIN  0x0001
#define POLLOUT 0x0004

static int user_range_ok(struct task *t, const void *ptr, uint64_t len) {
    if (!t || !t->is_user) return 1;
    if (!ptr) return 0;
    if (len == 0) return 1;
    uint64_t addr = (uint64_t)(uintptr_t)ptr;
    uint64_t limit = t->mmap_limit ? t->mmap_limit : 0xF0000000ull;
    if (addr < 0x1000ull) return 0;
    if (addr >= limit) return 0;
    if (addr + len < addr) return 0;
    if (addr + len > limit) return 0;
    return 1;
}

static int user_str_ok(struct task *t, const char *ptr) {
    if (!t || !t->is_user) return 1;
    if (!ptr) return 0;
    uint64_t addr = (uint64_t)(uintptr_t)ptr;
    uint64_t limit = t->mmap_limit ? t->mmap_limit : 0xF0000000ull;
    if (addr < 0x1000ull || addr >= limit) return 0;
    for (uint64_t i = 0; i < 256; ++i) {
        uint64_t cur = addr + i;
        if (cur >= limit) return 0;
        if (((const char *)ptr)[i] == '\0') return 1;
    }
    return 0;
}

static uint64_t sys_write_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    int fd = (int)a1;
    const uint8_t *buf = (const uint8_t *)a2;
    uint64_t len = a3;
    if (!buf || len == 0) return 0;
    if (len > 4096) len = 4096;

    struct task *t = task_current();
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    if (!t) {
        for (uint64_t i = 0; i < len; ++i) log_printf("%c", (char)buf[i]);
        return len;
    }
    struct task_fd *ent = task_fd_get(t, fd);
    if (!ent) return (uint64_t)-1;
    int backend = vfs_node_backend(ent->node);
    int raw = vfs_node_raw(ent->node);
    if (backend == VFS_BACKEND_DEV &&
        (raw == PSEUDOFS_DEV_RANDOM || raw == PSEUDOFS_DEV_URANDOM)) {
        return len;
    }
    if (ent->type == FD_TYPE_CONSOLE) {
        return (uint64_t)tty_write((int)t->tty_id, buf, (size_t)len);
    }
    if (ent->type == FD_TYPE_PTY_MASTER || ent->type == FD_TYPE_PTY_SLAVE) {
        struct pty *p = (struct pty *)ent->pipe;
        size_t n = pty_write(p, ent->type == FD_TYPE_PTY_MASTER, buf, (size_t)len);
        return (uint64_t)n;
    }
    if (ent->type == FD_TYPE_PIPE) {
        struct pipe *p = (struct pipe *)ent->pipe;
        uint64_t written = 0;
        while (written < len) {
            if (!pipe_has_reader(p)) return (uint64_t)-1;
            size_t n = pipe_write(p, buf + written, (size_t)(len - written));
            if (n > 0) {
                written += n;
            } else {
                sleep_ms(1);
            }
        }
        return written;
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
        if (t->task) {
            t->task->exit_code = (uint32_t)code;
            t->task->state = TASK_DEAD;
        }
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

static uint64_t sys_usleep_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint64_t us = a1;
    if (us == 0) return 0;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    uint64_t ticks = (us * (uint64_t)hz + 999999ull) / 1000000ull;
    if (ticks == 0) ticks = 1;
    sleep_ticks(ticks);
    return 0;
}

static uint64_t sys_nanosleep_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint64_t ns = a1;
    if (ns == 0) return 0;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    uint64_t ticks = (ns * (uint64_t)hz + 999999999ull) / 1000000000ull;
    if (ticks == 0) ticks = 1;
    sleep_ticks(ticks);
    return 0;
}

static uint64_t sys_nice_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct thread *t = thread_current();
    if (!t) return (uint64_t)-1;
    int nice = (int)a1;
    if (!sched_set_nice(t, nice)) return (uint64_t)-1;
    if (t->task) t->task->nice = sched_get_nice(t);
    return (uint64_t)sched_get_nice(t);
}

static uint64_t sys_getnice_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct thread *t = thread_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)sched_get_nice(t);
}

static uint64_t sys_setaffinity_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct thread *t = thread_current();
    if (!t) return (uint64_t)-1;
    uint32_t mask = (uint32_t)a1;
    if (!sched_set_affinity(t, mask)) return (uint64_t)-1;
    if (t->task) t->task->cpu_mask = sched_get_affinity(t);
    return (uint64_t)sched_get_affinity(t);
}

static uint64_t sys_getaffinity_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct thread *t = thread_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)sched_get_affinity(t);
}

static uint64_t sys_clock_gettime_impl(uint64_t a1, uint64_t a2, uint64_t a3,
                                       uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int clk_id = (int)a1;
    struct timespec *ts = (struct timespec *)a2;
    if (!ts) return SYS_ERR(EINVAL);
    if (clk_id == CLOCK_REALTIME) {
        uint64_t ns = time_now_epoch_ns();
        if (ns == 0) return SYS_ERR(EINVAL);
        ts->tv_sec = ns / 1000000000ull;
        ts->tv_nsec = ns % 1000000000ull;
        return 0;
    }
    if (clk_id == CLOCK_MONOTONIC) {
        uint64_t ns = time_monotonic_ns();
        ts->tv_sec = ns / 1000000000ull;
        ts->tv_nsec = ns % 1000000000ull;
        return 0;
    }
    return SYS_ERR(EINVAL);
}

static uint64_t sys_timer_hz_impl(uint64_t a1, uint64_t a2, uint64_t a3,
                                  uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    return (uint64_t)hz;
}

static uint64_t sys_uptime_ticks_impl(uint64_t a1, uint64_t a2, uint64_t a3,
                                      uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return timer_uptime_ticks();
}

static int poll_fd_ready(struct task *t, struct pollfd *pfd) {
    if (!t || !pfd) return 0;
    pfd->revents = 0;
    if (pfd->fd < 0) return 0;
    struct task_fd *ent = task_fd_get(t, pfd->fd);
    if (!ent || !ent->used) return -1;

    if ((pfd->events & POLLIN) != 0) {
        switch (ent->type) {
        case FD_TYPE_FILE:
            if ((ent->flags & O_WRONLY) == 0) {
                uint64_t size = vfs_get_size(ent->node);
                if (ent->offset < size) pfd->revents |= POLLIN;
            }
            break;
        case FD_TYPE_PIPE:
            if (pipe_count((struct pipe *)ent->pipe) > 0) pfd->revents |= POLLIN;
            break;
        case FD_TYPE_SOCKET:
            if (socket_can_recv(ent->sock_id)) pfd->revents |= POLLIN;
            break;
        case FD_TYPE_CONSOLE:
            if (tty_can_read((int)t->tty_id)) pfd->revents |= POLLIN;
            break;
        case FD_TYPE_PTY_MASTER:
            if (pty_can_read((struct pty *)ent->pipe, 1)) pfd->revents |= POLLIN;
            break;
        case FD_TYPE_PTY_SLAVE:
            if (pty_can_read((struct pty *)ent->pipe, 0)) pfd->revents |= POLLIN;
            break;
        default:
            break;
        }
    }

    if ((pfd->events & POLLOUT) != 0) {
        switch (ent->type) {
        case FD_TYPE_FILE:
            if ((ent->flags & (O_WRONLY | O_RDWR)) != 0) pfd->revents |= POLLOUT;
            break;
        case FD_TYPE_PIPE:
            if (pipe_space((struct pipe *)ent->pipe) > 0) pfd->revents |= POLLOUT;
            break;
        case FD_TYPE_SOCKET:
            if (socket_can_send(ent->sock_id)) pfd->revents |= POLLOUT;
            break;
        case FD_TYPE_CONSOLE:
            pfd->revents |= POLLOUT;
            break;
        case FD_TYPE_PTY_MASTER:
            if (pty_can_write((struct pty *)ent->pipe, 1)) pfd->revents |= POLLOUT;
            break;
        case FD_TYPE_PTY_SLAVE:
            if (pty_can_write((struct pty *)ent->pipe, 0)) pfd->revents |= POLLOUT;
            break;
        default:
            break;
        }
    }

    return pfd->revents != 0;
}

static uint64_t sys_poll_impl(uint64_t a1, uint64_t a2, uint64_t a3,
                              uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    struct pollfd *fds = (struct pollfd *)a1;
    uint32_t nfds = (uint32_t)a2;
    int timeout_ms = (int)a3;
    if (!fds || nfds == 0) return SYS_ERR(EINVAL);
    if (nfds > 128) return SYS_ERR(EINVAL);

    struct task *t = task_current();
    if (!t) return SYS_ERR(EINVAL);
    if (!user_range_ok(t, fds, (uint64_t)nfds * sizeof(struct pollfd))) return SYS_ERR(EFAULT);

    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    uint64_t start = timer_uptime_ticks();
    uint64_t timeout_ticks = 0;
    int wait_forever = 0;
    if (timeout_ms < 0) {
        wait_forever = 1;
    } else if (timeout_ms > 0) {
        timeout_ticks = (uint64_t)timeout_ms * (uint64_t)hz;
        timeout_ticks = (timeout_ticks + 999) / 1000;
        if (timeout_ticks == 0) timeout_ticks = 1;
    }

    while (1) {
        int ready = 0;
        for (uint32_t i = 0; i < nfds; ++i) {
            int rc = poll_fd_ready(t, &fds[i]);
            if (rc < 0) return SYS_ERR(EBADF);
            if (rc > 0) ready++;
        }
        if (ready > 0) return (uint64_t)ready;
        if (!wait_forever && timeout_ms == 0) return 0;
        if (!wait_forever) {
            uint64_t now = timer_uptime_ticks();
            if ((now - start) >= timeout_ticks) return 0;
        }
        sleep_ms(1);
    }
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
            if (paging_map_user_4k(task->pml4_phys, va, phys, PTE_NX) != 0) {
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
    struct task *t = task_current();
    if (!user_str_ok(t, path)) return SYS_ERR(EFAULT);
    int node = vfs_resolve(0, path);
    if (node < 0) {
        if (flags & O_CREAT) {
            node = vfs_create(0, path, 0);
        }
        if (node < 0) return (uint64_t)-1;
    } else {
        if (vfs_is_dir(node)) return (uint64_t)-1;
        uint32_t uid = 0, gid = 0;
        uint16_t mode = 0;
        if (!vfs_get_attr(node, &uid, &gid, &mode, NULL)) return (uint64_t)-1;
        if (t && t->uid != 0) {
            uint16_t bits = 0;
            if (t->uid == uid) bits = (uint16_t)((mode >> 6) & 0x7);
            else if (t->gid == gid) bits = (uint16_t)((mode >> 3) & 0x7);
            else bits = (uint16_t)(mode & 0x7);
            if ((flags & O_WRONLY) == 0 || (flags & O_RDWR)) {
                if (!(bits & 4)) return (uint64_t)-1;
            }
            if ((flags & O_WRONLY) || (flags & O_RDWR)) {
                if (!(bits & 2)) return (uint64_t)-1;
            }
        }
        if (flags & O_TRUNC) {
            if (vfs_truncate(node, 0) != 0) return (uint64_t)-1;
        }
    }
    if (vfs_is_dir(node)) return (uint64_t)-1;
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    struct task_fd *ent = task_fd_get(t, fd);
    if (!ent) return (uint64_t)-1;
    if (ent->type == FD_TYPE_CONSOLE) {
        if (g_fg_pgid != 0 && t->pgid != g_fg_pgid) {
            task_signal_raise(t, 20);
            return 0;
        }
        uint64_t read = 0;
        while (read < len) {
            size_t n = tty_read((int)t->tty_id, buf + read, (size_t)(len - read));
            if (n == 0) {
                if (read > 0) break;
                sleep_ms(1);
                continue;
            }
            for (size_t i = 0; i < n; ++i) {
                if (buf[read + i] == 0x1A) { /* Ctrl+Z */
                    task_signal_raise(t, 19);
                    n = i;
                    break;
                }
                if (buf[read + i] == '\n') {
                    read += i + 1;
                    return read;
                }
            }
            read += n;
        }
        return read;
    }
    if (ent->type == FD_TYPE_PTY_MASTER || ent->type == FD_TYPE_PTY_SLAVE) {
        struct pty *p = (struct pty *)ent->pipe;
        size_t n = pty_read(p, ent->type == FD_TYPE_PTY_MASTER, buf, (size_t)len);
        return (uint64_t)n;
    }
    if (ent->type == FD_TYPE_PIPE) {
        struct pipe *p = (struct pipe *)ent->pipe;
        uint64_t read = 0;
        while (read < len) {
            size_t n = pipe_read(p, buf + read, (size_t)(len - read));
            if (n > 0) {
                read += n;
                if (read >= len) break;
            } else {
                if (!pipe_has_writer(p)) break;
                sleep_ms(1);
            }
        }
        return read;
    }
    if (ent->type == FD_TYPE_FILE) {
        int backend = vfs_node_backend(ent->node);
        int raw = vfs_node_raw(ent->node);
        if (backend == VFS_BACKEND_DEV &&
            (raw == PSEUDOFS_DEV_RANDOM || raw == PSEUDOFS_DEV_URANDOM)) {
            rng_fill(buf, (size_t)len);
            return len;
        }
    }
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

static int alloc_pipe_fd(struct task *t, struct pipe *p, uint8_t end, int *out_fd) {
    if (!t || !t->fds || !p || !out_fd) return 0;
    if (!task_charge_fd(t, 1)) return 0;
    for (int i = 0; i < 16; ++i) {
        if (!t->fds[i].used) {
            t->fds[i].used = 1;
            t->fds[i].type = FD_TYPE_PIPE;
            t->fds[i].node = -1;
            t->fds[i].sock_id = -1;
            t->fds[i].pipe = p;
            t->fds[i].pipe_end = end;
            t->fds[i].offset = 0;
            t->fds[i].flags = 0;
            *out_fd = i;
            return 1;
        }
    }
    task_uncharge_fd(t, 1);
    return 0;
}

static uint64_t sys_pipe_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    int *fds = (int *)a1;
    if (!fds) return (uint64_t)-1;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    if (!user_range_ok(t, fds, 2 * sizeof(int))) return SYS_ERR(EFAULT);
    struct pipe *p = pipe_create();
    if (!p) return (uint64_t)-1;
    int rfd = -1;
    int wfd = -1;
    if (!alloc_pipe_fd(t, p, 0, &rfd) || !alloc_pipe_fd(t, p, 1, &wfd)) {
        if (rfd >= 0) task_fd_close(t, rfd);
        if (wfd >= 0) task_fd_close(t, wfd);
        pipe_close_end(p, 0);
        pipe_close_end(p, 1);
        return (uint64_t)-1;
    }
    fds[0] = rfd;
    fds[1] = wfd;
    return 0;
}

static uint64_t sys_dup2_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int oldfd = (int)a1;
    int newfd = (int)a2;
    struct task *t = task_current();
    if (!t || !t->fds) return (uint64_t)-1;
    if (oldfd < 0 || oldfd >= 16 || newfd < 0 || newfd >= 16) return (uint64_t)-1;
    struct task_fd *src = task_fd_get(t, oldfd);
    if (!src) return (uint64_t)-1;
    if (oldfd == newfd) return (uint64_t)newfd;
    if (t->fds[newfd].used) {
        task_fd_close(t, newfd);
    } else {
        if (!task_charge_fd(t, 1)) return (uint64_t)-1;
    }
    t->fds[newfd] = *src;
    t->fds[newfd].used = 1;
    if (t->fds[newfd].type == FD_TYPE_PIPE && t->fds[newfd].pipe) {
        pipe_retain_end((struct pipe *)t->fds[newfd].pipe, t->fds[newfd].pipe_end);
    }
    return (uint64_t)newfd;
}

static uint64_t sys_waitpid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int pid = (int)a1;
    int *status = (int *)a2;
    struct task *self = task_current();
    if (!self) return (uint64_t)-1;
    if (status && !user_range_ok(self, status, sizeof(int))) return SYS_ERR(EFAULT);
    for (;;) {
        struct task *found = task_find_child_dead(self, pid);
        if (!found) {
            found = task_find_child_stopped(self, pid);
            if (found) {
                if (status) *status = 128 + 19;
                return (uint64_t)found->pid;
            }
        }
        if (found) {
            if (status) *status = (int)found->exit_code;
            return (uint64_t)found->pid;
        }
        sleep_ms(5);
    }
}

static uint64_t sys_execve_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    const char *path = (const char *)a1;
    int argc = (int)a2;
    char **argv = (char **)a3;
    char **envp = (char **)a4;
    struct thread *t = thread_current();
    struct task *task = task_current();
    if (!t || !task || !path) return (uint64_t)-1;
    if (argc < 0 || argc > 16) return (uint64_t)-1;
    if (!user_str_ok(task, path)) return SYS_ERR(EFAULT);
    if (argc > 0) {
        if (!user_range_ok(task, argv, (uint64_t)argc * sizeof(char *))) return SYS_ERR(EFAULT);
        for (int i = 0; i < argc; ++i) {
            if (argv && argv[i] && !user_str_ok(task, argv[i])) return SYS_ERR(EFAULT);
        }
    }
    if (envp) {
        if (!user_range_ok(task, envp, 16 * sizeof(char *))) return SYS_ERR(EFAULT);
        for (int i = 0; i < 16; ++i) {
            if (!envp[i]) break;
            if (!user_str_ok(task, envp[i])) return SYS_ERR(EFAULT);
        }
    }

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

    char **kenvp = NULL;
    int envc = 0;
    if (envp) {
        while (envp[envc] && envc < 16) envc++;
        if (envc > 0) {
            kenvp = (char **)kmalloc(sizeof(char *) * (size_t)(envc + 1));
            if (kenvp) {
                for (int i = 0; i < envc; ++i) kenvp[i] = NULL;
                kenvp[envc] = NULL;
                for (int i = 0; i < envc; ++i) {
                    const char *u = envp[i];
                    if (!u) continue;
                    size_t len = 0;
                    while (u[len] && len < 255) len++;
                    char *buf = (char *)kmalloc(len + 1);
                    if (!buf) continue;
                    for (size_t j = 0; j < len; ++j) buf[j] = u[j];
                    buf[len] = '\0';
                    kenvp[i] = buf;
                }
            }
        }
    }

    uint64_t entry = 0;
    uint64_t pml4 = 0;
    uint64_t rsp = 0;
    struct user_addr_space layout;
    paging_user_layout_default(&layout);
    int rc = elf_load_user(path, argc, kargv ? kargv : argv, kenvp, &layout, &entry, &pml4, &rsp);
    if (kargv) {
        for (int i = 0; i < argc; ++i) {
            if (kargv[i]) kfree(kargv[i]);
        }
        kfree(kargv);
    }
    if (kenvp) {
        for (int i = 0; i < envc; ++i) {
            if (kenvp[i]) kfree(kenvp[i]);
        }
        kfree(kenvp);
    }
    if (rc != 0) {
        log_printf("execve: failed rc=%d\n", rc);
        return (uint64_t)-1;
    }

    {
        uint32_t uid = 0, gid = 0;
        uint16_t mode = 0;
        int node = vfs_resolve(0, path);
        if (node >= 0 && vfs_get_attr(node, &uid, &gid, &mode, NULL)) {
            if (task->uid != 0) {
                uint16_t bits = (task->uid == uid) ? (uint16_t)((mode >> 6) & 0x7) :
                                (task->gid == gid) ? (uint16_t)((mode >> 3) & 0x7) :
                                                     (uint16_t)(mode & 0x7);
                if (!(bits & 1)) return (uint64_t)-1;
            }
            if (mode & 04000u) task->uid = uid;
            if (mode & 02000u) task->gid = gid;
        }
    }

    t->is_user = 1;
    t->pml4_phys = pml4;
    if (task) {
        task_set_user_layout(task, layout.heap_base, layout.heap_limit,
                             layout.stack_top, layout.stack_size,
                             layout.mmap_base, layout.mmap_limit);
        task->pml4_phys = pml4;
    }
    paging_switch_to(pml4);
    user_enter_iret(entry, rsp, 0x202);
    __builtin_unreachable();
}

static uint64_t sys_getpid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    return (uint64_t)t->pid;
}

static uint64_t sys_setpgid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int pid = (int)a1;
    int pgid = (int)a2;
    struct task *self = task_current();
    if (!self) return (uint64_t)-1;
    struct task *t = (pid == 0) ? self : task_find_pid((uint32_t)pid);
    if (!t) return (uint64_t)-1;
    if (pgid == 0) pgid = (int)t->pid;
    t->pgid = (uint32_t)pgid;
    return 0;
}

static uint64_t sys_tcsetpgrp_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    uint32_t pgid = (uint32_t)a1;
    if (pgid == 0) {
        struct task *t = task_current();
        if (t) pgid = t->pgid;
    }
    g_fg_pgid = pgid;
    return 0;
}

static uint64_t sys_tcgetpgrp_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    if (g_fg_pgid == 0) {
        struct task *t = task_current();
        if (t) g_fg_pgid = t->pgid;
    }
    return (uint64_t)g_fg_pgid;
}

static uint64_t sys_getuid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    return t ? (uint64_t)t->uid : (uint64_t)-1;
}

static uint64_t sys_getgid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    return t ? (uint64_t)t->gid : (uint64_t)-1;
}

static uint64_t sys_setuid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    if (t->uid != 0 && (uint32_t)a1 != t->uid) return (uint64_t)-1;
    t->uid = (uint32_t)a1;
    return 0;
}

static uint64_t sys_setgid_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    if (t->uid != 0 && (uint32_t)a1 != t->gid) return (uint64_t)-1;
    t->gid = (uint32_t)a1;
    return 0;
}

static uint64_t sys_chmod_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    uint16_t mode = (uint16_t)a2;
    if (!path) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, path)) return SYS_ERR(EFAULT);
    int node = vfs_resolve(0, path);
    if (node < 0) return (uint64_t)-1;
    uint32_t uid = 0, gid = 0;
    uint16_t cur_mode = 0;
    if (!vfs_get_attr(node, &uid, &gid, &cur_mode, NULL)) return (uint64_t)-1;
    if (!t) return (uint64_t)-1;
    if (t->uid != 0 && t->uid != uid) return (uint64_t)-1;
    if (!vfs_chmod(node, mode)) return (uint64_t)-1;
    return 0;
}

static uint64_t sys_chown_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    uint32_t uid = (uint32_t)a2;
    uint32_t gid = (uint32_t)a3;
    if (!path) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, path)) return SYS_ERR(EFAULT);
    int node = vfs_resolve(0, path);
    if (node < 0) return (uint64_t)-1;
    if (!t || t->uid != 0) return (uint64_t)-1;
    if (!vfs_chown(node, uid, gid)) return (uint64_t)-1;
    return 0;
}

static int alloc_pty_fd(struct task *t, struct pty *p, int is_master, int *out_fd) {
    if (!t || !t->fds || !p || !out_fd) return 0;
    if (!task_charge_fd(t, 1)) return 0;
    for (int i = 0; i < 16; ++i) {
        if (!t->fds[i].used) {
            t->fds[i].used = 1;
            t->fds[i].type = is_master ? FD_TYPE_PTY_MASTER : FD_TYPE_PTY_SLAVE;
            t->fds[i].node = -1;
            t->fds[i].sock_id = -1;
            t->fds[i].pipe = p;
            t->fds[i].pipe_end = (uint8_t)is_master;
            t->fds[i].offset = 0;
            t->fds[i].flags = 0;
            *out_fd = i;
            return 1;
        }
    }
    task_uncharge_fd(t, 1);
    return 0;
}

static uint64_t sys_pty_open_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    int *master_fd = (int *)a1;
    int *slave_fd = (int *)a2;
    if (!master_fd || !slave_fd) return (uint64_t)-1;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    if (!user_range_ok(t, master_fd, sizeof(int))) return SYS_ERR(EFAULT);
    if (!user_range_ok(t, slave_fd, sizeof(int))) return SYS_ERR(EFAULT);
    struct pty *p = pty_create();
    if (!p) return (uint64_t)-1;
    int mfd = -1, sfd = -1;
    if (!alloc_pty_fd(t, p, 1, &mfd) || !alloc_pty_fd(t, p, 0, &sfd)) {
        if (mfd >= 0) task_fd_close(t, mfd);
        if (sfd >= 0) task_fd_close(t, sfd);
        pty_close_end(p, 1);
        pty_close_end(p, 0);
        return (uint64_t)-1;
    }
    *master_fd = mfd;
    *slave_fd = sfd;
    return 0;
}

static uint64_t sys_umask_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    uint16_t old = t->umask;
    t->umask = (uint16_t)(a1 & 0777u);
    return old;
}

static uint64_t sys_link_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    const char *oldpath = (const char *)a1;
    const char *newpath = (const char *)a2;
    if (!oldpath || !newpath) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, oldpath) || !user_str_ok(t, newpath)) return SYS_ERR(EFAULT);
    int rc = vfs_link(0, oldpath, newpath);
    return (rc < 0) ? (uint64_t)-1 : 0;
}

static uint64_t sys_symlink_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    const char *target = (const char *)a1;
    const char *linkpath = (const char *)a2;
    if (!target || !linkpath) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, target) || !user_str_ok(t, linkpath)) return SYS_ERR(EFAULT);
    int rc = vfs_symlink(0, target, linkpath);
    return (rc < 0) ? (uint64_t)-1 : 0;
}

static uint64_t sys_readlink_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    char *out = (char *)a2;
    uint64_t len = a3;
    if (!path || !out || len == 0) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, path)) return SYS_ERR(EFAULT);
    if (!user_range_ok(t, out, len)) return SYS_ERR(EFAULT);
    int rc = vfs_readlink(path, out, (size_t)len);
    return (rc < 0) ? (uint64_t)-1 : (uint64_t)rc;
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
          child->nice = child->task->nice;
          child->cpu_mask = child->task->cpu_mask;
          sched_set_nice(child, child->nice);
          sched_set_affinity(child, child->cpu_mask);
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
    if (!user_str_ok(task, path)) return SYS_ERR(EFAULT);
    if (argc > 0) {
        if (!user_range_ok(task, argv, (uint64_t)argc * sizeof(char *))) return SYS_ERR(EFAULT);
        for (int i = 0; i < argc; ++i) {
            if (argv && argv[i] && !user_str_ok(task, argv[i])) return SYS_ERR(EFAULT);
        }
    }

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
    struct user_addr_space layout;
    paging_user_layout_default(&layout);
    int rc = elf_load_user(path, argc, kargv ? kargv : argv, NULL, &layout, &entry, &pml4, &rsp);
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

    {
        uint32_t uid = 0, gid = 0;
        uint16_t mode = 0;
        int node = vfs_resolve(0, path);
        if (node >= 0 && vfs_get_attr(node, &uid, &gid, &mode, NULL)) {
            struct task *ct = task_current();
            if (ct && ct->uid != 0) {
                uint16_t bits = (ct->uid == uid) ? (uint16_t)((mode >> 6) & 0x7) :
                                (ct->gid == gid) ? (uint16_t)((mode >> 3) & 0x7) :
                                                   (uint16_t)(mode & 0x7);
                if (!(bits & 1)) return (uint64_t)-1;
            }
            if (mode & 04000u) task->uid = uid;
            if (mode & 02000u) task->gid = gid;
        }
    }

    t->is_user = 1;
    t->pml4_phys = pml4;
    if (task) {
        task_set_user_layout(task, layout.heap_base, layout.heap_limit,
                             layout.stack_top, layout.stack_size,
                             layout.mmap_base, layout.mmap_limit);
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
    if (ip && !user_range_ok(t, ip, 4)) return SYS_ERR(EFAULT);
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
    if (ip && !user_range_ok(t, ip, 16)) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    if (ip && !user_range_ok(t, ip, 4)) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    if (ip && !user_range_ok(t, ip, 16)) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    if (out_ip && !user_range_ok(t, out_ip, 4)) return SYS_ERR(EFAULT);
    if (out_port && !user_range_ok(t, out_port, sizeof(uint16_t))) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    if (out_ip && !user_range_ok(t, out_ip, 16)) return SYS_ERR(EFAULT);
    if (out_port && !user_range_ok(t, out_port, sizeof(uint16_t))) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
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
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
    int sid = fd_to_socket(t, fd);
    if (sid < 0) return (uint64_t)-1;
    return (uint64_t)socket_recvfrom(sid, buf, len, NULL, NULL);
}

static uint64_t sys_mmap_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    uint64_t addr = a1;
    uint64_t len = a2;
    uint32_t prot = (uint32_t)a3;
    uint32_t flags = (uint32_t)a4;
    int fd = (int)a5;
    uint64_t offset = a6;
    struct task *t = task_current();
    if (!t) return (uint64_t)-1;
    if (flags & MAP_FILE) {
        if ((offset & 0xFFFull) != 0) return (uint64_t)-1;
        struct task_fd *ent = task_fd_get(t, fd);
        if (!ent || ent->type != FD_TYPE_FILE) return (uint64_t)-1;
        uint64_t out = task_mmap_file(t, addr, len, prot, flags, ent->node, offset);
        if (out == 0) return (uint64_t)-1;
        return out;
    }
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
    struct task *t = task_current();
    if (!user_range_ok(t, out, 4)) return SYS_ERR(EFAULT);
    if (dhcp_get_dns(out) != 0) return (uint64_t)-1;
    return 0;
}

static uint64_t sys_listdir_impl(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    const char *path = (const char *)a1;
    char *buf = (char *)a2;
    uint64_t len = a3;
    if (!buf || len == 0) return (uint64_t)-1;
    struct task *t = task_current();
    if (!user_str_ok(t, path)) return SYS_ERR(EFAULT);
    if (!user_range_ok(t, buf, len)) return SYS_ERR(EFAULT);
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
    sys_unshare_net_impl,
    sys_pipe_impl,
    sys_dup2_impl,
    sys_waitpid_impl,
    sys_execve_impl,
    sys_getpid_impl,
    sys_setpgid_impl,
    sys_tcsetpgrp_impl,
    sys_tcgetpgrp_impl,
    sys_getuid_impl,
    sys_getgid_impl,
    sys_setuid_impl,
    sys_setgid_impl,
    sys_chmod_impl,
    sys_chown_impl,
    sys_pty_open_impl,
    sys_umask_impl,
    sys_link_impl,
    sys_symlink_impl,
    sys_readlink_impl,
    sys_usleep_impl,
    sys_nanosleep_impl,
    sys_nice_impl,
    sys_getnice_impl,
    sys_setaffinity_impl,
    sys_getaffinity_impl,
    sys_clock_gettime_impl,
    sys_timer_hz_impl,
    sys_uptime_ticks_impl,
    sys_poll_impl
};

uint64_t syscall_dispatch(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6) {
    if (num >= SYS_MAX) return SYS_ERR(ENOSYS);
    syscall_fn fn = g_syscalls[num];
    if (!fn) return SYS_ERR(ENOSYS);
    uint64_t ret = fn(a1, a2, a3, a4, a5, a6);
    if (ret == (uint64_t)-1) return SYS_ERR(EINVAL);
    return ret;
}

uint64_t syscall_handler(struct syscall_frame *f) {
    if (!f) return (uint64_t)-1;
    profiler_inc(PROF_SYSCALLS);
    uint64_t ret = 0;
    if (f->rax == SYS_FORK) {
        ret = sys_fork_impl(f);
        if (ret == (uint64_t)-1) ret = SYS_ERR(EINVAL);
        goto signal_check;
    }
    if (f->rax == SYS_EXEC) {
        ret = sys_exec_impl(f->rdi, f->rsi, f->rdx);
        if (ret == (uint64_t)-1) ret = SYS_ERR(EINVAL);
        goto signal_check;
    }
    ret = syscall_dispatch(f->rax, f->rdi, f->rsi, f->rdx, f->r10, f->r8, f->r9);

signal_check:
    {
        struct thread *t = thread_current();
        if (t && t->is_user && t->task) {
            int sig_rc = task_signal_handle_pending(t->task);
            if (sig_rc == 1) {
                thread_exit();
            }
            if (sig_rc == 2) {
                t->state = THREAD_BLOCKED;
                sched_tick();
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
