#ifndef SYS_LIBC_H
#define SYS_LIBC_H

#include <stddef.h>
#include <stdint.h>

static inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(__GNUC__) || defined(__clang__)
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(a4), "r"(a5), "r"(a6)
                     : "rcx", "r11", "memory");
    return ret;
#else
    (void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return -1;
#endif
}

static inline long sys_write(const void *buf, size_t len) {
    return __syscall6(1, (long)buf, (long)len, 0, 0, 0, 0);
}

static inline long sys_exit(int code) {
    return __syscall6(2, (long)code, 0, 0, 0, 0, 0);
}

static inline long sys_sleep_ms(uint64_t ms) {
    return __syscall6(3, (long)ms, 0, 0, 0, 0, 0);
}

static inline long sys_open(const char *path, uint32_t flags) {
    return __syscall6(5, (long)path, (long)flags, 0, 0, 0, 0);
}

static inline long sys_read(int fd, void *buf, size_t len) {
    return __syscall6(6, (long)fd, (long)buf, (long)len, 0, 0, 0);
}

static inline long sys_close(int fd) {
    return __syscall6(7, (long)fd, 0, 0, 0, 0, 0);
}

static inline long sys_fork(void) {
    return __syscall6(8, 0, 0, 0, 0, 0, 0);
}

static inline long sys_exec(const char *path, int argc, char **argv) {
    return __syscall6(9, (long)path, (long)argc, (long)argv, 0, 0, 0);
}

static inline long sys_signal(int sig, void *handler) {
    return __syscall6(10, (long)sig, (long)handler, 0, 0, 0, 0);
}

static inline long sys_kill(int pid, int sig) {
    return __syscall6(11, (long)pid, (long)sig, 0, 0, 0, 0);
}

static inline long sys_socket(int domain, int type) {
    return __syscall6(12, (long)domain, (long)type, 0, 0, 0, 0);
}

static inline long sys_bind(int fd, uint16_t port) {
    return __syscall6(13, (long)fd, (long)port, 0, 0, 0, 0);
}

static inline long sys_connect(int fd, const uint8_t ip[4], uint16_t port) {
    return __syscall6(14, (long)fd, (long)ip, (long)port, 0, 0, 0);
}

static inline long sys_sendto(int fd, const void *buf, size_t len, const uint8_t ip[4], uint16_t port) {
    return __syscall6(15, (long)fd, (long)buf, (long)len, (long)ip, (long)port, 0);
}

static inline long sys_recvfrom(int fd, void *buf, size_t len, uint8_t ip[4], uint16_t *port) {
    return __syscall6(16, (long)fd, (long)buf, (long)len, (long)ip, (long)port, 0);
}

static inline long sys_listen(int fd) {
    return __syscall6(17, (long)fd, 0, 0, 0, 0, 0);
}

static inline long sys_accept(int fd) {
    return __syscall6(18, (long)fd, 0, 0, 0, 0, 0);
}

static inline long sys_send(int fd, const void *buf, size_t len) {
    return __syscall6(19, (long)fd, (long)buf, (long)len, 0, 0, 0);
}

static inline long sys_recv(int fd, void *buf, size_t len) {
    return __syscall6(20, (long)fd, (long)buf, (long)len, 0, 0, 0);
}

static inline void *sys_mmap(void *addr, size_t len, uint32_t prot, uint32_t flags, int fd, uint64_t offset) {
    return (void *)__syscall6(21, (long)addr, (long)len, (long)prot, (long)flags, (long)fd, (long)offset);
}

static inline long sys_munmap(void *addr, size_t len) {
    return __syscall6(22, (long)addr, (long)len, 0, 0, 0, 0);
}

enum {
    SIG_DFL = 0,
    SIG_IGN = 1,
    SIGINT  = 2,
    SIGKILL = 9,
    SIGSEGV = 11,
    SIGTERM = 15,
    SIGCHLD = 17
};

#endif /* SYS_LIBC_H */
