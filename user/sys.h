#ifndef USER_SYS_H
#define USER_SYS_H

#include <stdint.h>
#include <stddef.h>

static inline uint64_t sys_call6(uint64_t n, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    uint64_t ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
                     : "rcx", "r11", "memory");
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
    SYS_UMOUNT = 26
};

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

static inline long sys_write(int fd, const void *buf, size_t len) {
    return (long)sys_call6(SYS_WRITE, (uint64_t)fd, (uint64_t)buf, (uint64_t)len, 0, 0, 0);
}

static inline long sys_exit(int code) {
    return (long)sys_call6(SYS_EXIT, (uint64_t)code, 0, 0, 0, 0, 0);
}

static inline long sys_sleep_ms(uint64_t ms) {
    return (long)sys_call6(SYS_SLEEP, ms, 0, 0, 0, 0, 0);
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

static inline long sys_fork(void) {
    return (long)sys_call6(SYS_FORK, 0, 0, 0, 0, 0, 0);
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
