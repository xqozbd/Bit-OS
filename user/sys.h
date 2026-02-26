#ifndef USER_SYS_H
#define USER_SYS_H

#include <stdint.h>
#include <stddef.h>

static inline uint64_t sys_call6(uint64_t n, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    uint64_t ret;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
                     : "rcx", "r11", "memory");
#else
    (void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    ret = 0;
#endif
    return ret;
}

enum {
    SYS_WRITE = 1,
    SYS_EXIT  = 2,
    SYS_SLEEP = 3,
    SYS_SBRK  = 4,
    SYS_OPEN  = 5,
    SYS_READ  = 6,
    SYS_CLOSE = 7,
    SYS_FORK  = 8,
    SYS_EXEC  = 9,
    SYS_SIGNAL = 10,
    SYS_KILL   = 11,
    SYS_SOCKET = 12,
    SYS_BIND   = 13,
    SYS_CONNECT = 14,
    SYS_SENDTO = 15,
    SYS_RECVFROM = 16,
    SYS_LISTEN = 17,
    SYS_ACCEPT = 18,
    SYS_SEND = 19,
    SYS_RECV = 20,
    SYS_MMAP = 21,
    SYS_MUNMAP = 22,
    SYS_GETDNS = 23,
    SYS_LISTDIR = 24,
    SYS_MOUNT = 25,
    SYS_UMOUNT = 26,
    SYS_CONNECT6 = 27,
    SYS_SENDTO6 = 28,
    SYS_RECVFROM6 = 29,
    SYS_UNSHARE_PID = 30,
    SYS_UNSHARE_MNT = 31,
    SYS_UNSHARE_NET = 32,
    SYS_PIPE = 33,
    SYS_DUP2 = 34,
    SYS_WAITPID = 35,
    SYS_EXECVE = 36,
    SYS_GETPID = 37,
    SYS_SETPGID = 38,
    SYS_TCSETPGRP = 39,
    SYS_TCGETPGRP = 40,
    SYS_GETUID = 41,
    SYS_GETGID = 42,
    SYS_SETUID = 43,
    SYS_SETGID = 44,
    SYS_CHMOD = 45,
    SYS_CHOWN = 46,
    SYS_PTY_OPEN = 47,
    SYS_UMASK = 48,
    SYS_LINK = 49,
    SYS_SYMLINK = 50,
    SYS_READLINK = 51,
    SYS_USLEEP = 52,
    SYS_NANOSLEEP = 53,
    SYS_NICE = 54,
    SYS_GETNICE = 55,
    SYS_SETAFFINITY = 56,
    SYS_GETAFFINITY = 57,
    SYS_CLOCK_GETTIME = 58,
    SYS_TIMER_HZ = 59,
    SYS_UPTIME_TICKS = 60,
    SYS_POLL = 61
};

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

enum {
    O_RDONLY = 0x0000u,
    O_WRONLY = 0x0001u,
    O_RDWR   = 0x0002u,
    O_CREAT  = 0x0100u,
    O_TRUNC  = 0x0200u,
    O_APPEND = 0x0400u
};

enum {
    PROT_READ  = 1,
    PROT_WRITE = 2,
    PROT_EXEC  = 4
};

enum {
    MAP_ANON = 1,
    MAP_FILE = 2
};

enum {
    SIG_DFL = 0,
    SIG_IGN = 1,
    SIGINT  = 2,
    SIGKILL = 9,
    SIGSEGV = 11,
    SIGTERM = 15,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20
};

static inline long sys_write(int fd, const void *buf, size_t len) {
    return (long)sys_call6(SYS_WRITE, (uint64_t)fd, (uint64_t)buf, (uint64_t)len, 0, 0, 0);
}

static inline long sys_exit(int code) {
    return (long)sys_call6(SYS_EXIT, (uint64_t)code, 0, 0, 0, 0, 0);
}

static inline long sys_sleep_ms(uint64_t ms) {
    return (long)sys_call6(SYS_SLEEP, ms, 0, 0, 0, 0, 0);
}

static inline long sys_usleep(uint64_t us) {
    return (long)sys_call6(SYS_USLEEP, us, 0, 0, 0, 0, 0);
}

static inline long sys_nanosleep(uint64_t ns) {
    return (long)sys_call6(SYS_NANOSLEEP, ns, 0, 0, 0, 0, 0);
}

static inline long sys_nice(int nice) {
    return (long)sys_call6(SYS_NICE, (uint64_t)nice, 0, 0, 0, 0, 0);
}

static inline long sys_getnice(void) {
    return (long)sys_call6(SYS_GETNICE, 0, 0, 0, 0, 0, 0);
}

static inline long sys_setaffinity(uint32_t mask) {
    return (long)sys_call6(SYS_SETAFFINITY, mask, 0, 0, 0, 0, 0);
}

static inline long sys_getaffinity(void) {
    return (long)sys_call6(SYS_GETAFFINITY, 0, 0, 0, 0, 0, 0);
}

static inline long sys_clock_gettime(int clk_id, struct timespec *ts) {
    return (long)sys_call6(SYS_CLOCK_GETTIME, (uint64_t)clk_id, (uint64_t)ts, 0, 0, 0, 0);
}

static inline long sys_timer_hz(void) {
    return (long)sys_call6(SYS_TIMER_HZ, 0, 0, 0, 0, 0, 0);
}

static inline long sys_uptime_ticks(void) {
    return (long)sys_call6(SYS_UPTIME_TICKS, 0, 0, 0, 0, 0, 0);
}

static inline long sys_poll(struct pollfd *fds, uint32_t nfds, int timeout_ms) {
    return (long)sys_call6(SYS_POLL, (uint64_t)fds, nfds, (uint64_t)timeout_ms, 0, 0, 0);
}

static inline long sys_open(const char *path, uint32_t flags) {
    return (long)sys_call6(SYS_OPEN, (uint64_t)path, (uint64_t)flags, 0, 0, 0, 0);
}

static inline long sys_read(int fd, void *buf, size_t len) {
    return (long)sys_call6(SYS_READ, (uint64_t)fd, (uint64_t)buf, (uint64_t)len, 0, 0, 0);
}

static inline long sys_close(int fd) {
    return (long)sys_call6(SYS_CLOSE, (uint64_t)fd, 0, 0, 0, 0, 0);
}

static inline long sys_exec(const char *path, int argc, char **argv) {
    return (long)sys_call6(SYS_EXEC, (uint64_t)path, (uint64_t)argc, (uint64_t)argv, 0, 0, 0);
}

static inline long sys_execve(const char *path, int argc, char **argv, char **envp) {
    return (long)sys_call6(SYS_EXECVE, (uint64_t)path, (uint64_t)argc, (uint64_t)argv, (uint64_t)envp, 0, 0);
}

static inline long sys_fork(void) {
    return (long)sys_call6(SYS_FORK, 0, 0, 0, 0, 0, 0);
}

static inline long sys_signal(int sig, void *handler) {
    return (long)sys_call6(SYS_SIGNAL, (uint64_t)sig, (uint64_t)handler, 0, 0, 0, 0);
}

static inline long sys_kill(int pid, int sig) {
    return (long)sys_call6(SYS_KILL, (uint64_t)pid, (uint64_t)sig, 0, 0, 0, 0);
}

static inline long sys_listdir(const char *path, char *buf, size_t len) {
    return (long)sys_call6(SYS_LISTDIR, (uint64_t)path, (uint64_t)buf, (uint64_t)len, 0, 0, 0);
}

static inline long sys_mount(uint32_t part_index, uint32_t type) {
    return (long)sys_call6(SYS_MOUNT, (uint64_t)part_index, (uint64_t)type, 0, 0, 0, 0);
}

static inline long sys_umount(void) {
    return (long)sys_call6(SYS_UMOUNT, 0, 0, 0, 0, 0, 0);
}

static inline long sys_pipe(int *fds) {
    return (long)sys_call6(SYS_PIPE, (uint64_t)fds, 0, 0, 0, 0, 0);
}

static inline long sys_dup2(int oldfd, int newfd) {
    return (long)sys_call6(SYS_DUP2, (uint64_t)oldfd, (uint64_t)newfd, 0, 0, 0, 0);
}

static inline long sys_waitpid(int pid, int *status) {
    return (long)sys_call6(SYS_WAITPID, (uint64_t)pid, (uint64_t)status, 0, 0, 0, 0);
}

static inline long sys_getpid(void) {
    return (long)sys_call6(SYS_GETPID, 0, 0, 0, 0, 0, 0);
}

static inline long sys_setpgid(int pid, int pgid) {
    return (long)sys_call6(SYS_SETPGID, (uint64_t)pid, (uint64_t)pgid, 0, 0, 0, 0);
}

static inline long sys_tcsetpgrp(int pgid) {
    return (long)sys_call6(SYS_TCSETPGRP, (uint64_t)pgid, 0, 0, 0, 0, 0);
}

static inline long sys_tcgetpgrp(void) {
    return (long)sys_call6(SYS_TCGETPGRP, 0, 0, 0, 0, 0, 0);
}

static inline long sys_getuid(void) {
    return (long)sys_call6(SYS_GETUID, 0, 0, 0, 0, 0, 0);
}

static inline long sys_getgid(void) {
    return (long)sys_call6(SYS_GETGID, 0, 0, 0, 0, 0, 0);
}

static inline long sys_setuid(uint32_t uid) {
    return (long)sys_call6(SYS_SETUID, uid, 0, 0, 0, 0, 0);
}

static inline long sys_setgid(uint32_t gid) {
    return (long)sys_call6(SYS_SETGID, gid, 0, 0, 0, 0, 0);
}

static inline long sys_chmod(const char *path, uint32_t mode) {
    return (long)sys_call6(SYS_CHMOD, (uint64_t)path, (uint64_t)mode, 0, 0, 0, 0);
}

static inline long sys_chown(const char *path, uint32_t uid, uint32_t gid) {
    return (long)sys_call6(SYS_CHOWN, (uint64_t)path, (uint64_t)uid, (uint64_t)gid, 0, 0, 0);
}

static inline long sys_pty_open(int *master_fd, int *slave_fd) {
    return (long)sys_call6(SYS_PTY_OPEN, (uint64_t)master_fd, (uint64_t)slave_fd, 0, 0, 0, 0);
}

static inline long sys_umask(uint32_t mask) {
    return (long)sys_call6(SYS_UMASK, (uint64_t)mask, 0, 0, 0, 0, 0);
}

static inline long sys_link(const char *oldpath, const char *newpath) {
    return (long)sys_call6(SYS_LINK, (uint64_t)oldpath, (uint64_t)newpath, 0, 0, 0, 0);
}

static inline long sys_symlink(const char *target, const char *linkpath) {
    return (long)sys_call6(SYS_SYMLINK, (uint64_t)target, (uint64_t)linkpath, 0, 0, 0, 0);
}

static inline long sys_readlink(const char *path, char *out, size_t out_len) {
    return (long)sys_call6(SYS_READLINK, (uint64_t)path, (uint64_t)out, (uint64_t)out_len, 0, 0, 0);
}

static inline void *sys_mmap(void *addr, size_t len, uint32_t prot, uint32_t flags, int fd, uint64_t offset) {
    return (void *)sys_call6(SYS_MMAP, (uint64_t)addr, (uint64_t)len, (uint64_t)prot,
                             (uint64_t)flags, (uint64_t)fd, (uint64_t)offset);
}

static inline long sys_munmap(void *addr, size_t len) {
    return (long)sys_call6(SYS_MUNMAP, (uint64_t)addr, (uint64_t)len, 0, 0, 0, 0);
}

static inline size_t ustrlen(const char *s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static inline int ustrcmp(const char *a, const char *b) {
    size_t i = 0;
    while (a && b) {
        if (a[i] != b[i] || a[i] == '\0' || b[i] == '\0') break;
        i++;
    }
    char ca = a ? a[i] : 0;
    char cb = b ? b[i] : 0;
    return (int)(ca - cb);
}

static inline void uputs(const char *s) {
    if (s) sys_write(1, s, ustrlen(s));
}

static inline void uputc(char c) {
    sys_write(1, &c, 1);
}

static inline int uatoi(const char *s) {
    int v = 0;
    if (!s) return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}

#endif /* USER_SYS_H */
