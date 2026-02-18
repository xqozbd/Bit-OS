#include "libu.h"

static inline long sys_write(int fd, const void *buf, size_t len) {
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(1), "D"(fd), "S"(buf), "d"(len)
                     : "rcx", "r11", "memory");
    return ret;
}

size_t ustrlen(const char *s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

int ustrcmp(const char *a, const char *b) {
    size_t i = 0;
    while (a && b) {
        if (a[i] != b[i] || a[i] == '\0' || b[i] == '\0') break;
        i++;
    }
    char ca = a ? a[i] : 0;
    char cb = b ? b[i] : 0;
    return (int)(ca - cb);
}

void uputs(const char *s) {
    if (s) sys_write(1, s, ustrlen(s));
}

void uputc(char c) {
    sys_write(1, &c, 1);
}

int uatoi(const char *s) {
    int v = 0;
    if (!s) return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}
