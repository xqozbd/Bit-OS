#include "libu.h"

#include <stdarg.h>
#include <stdint.h>

static inline long sys_write(int fd, const void *buf, size_t len) {
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(1), "D"(fd), "S"(buf), "d"(len)
                     : "rcx", "r11", "memory");
    return ret;
}

void *umemcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

void *umemmove(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (size_t i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; --i) d[i - 1] = s[i - 1];
    }
    return dst;
}

void *umemset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; ++i) d[i] = (uint8_t)c;
    return dst;
}

int umemcmp(const void *a, const void *b, size_t n) {
    const uint8_t *p1 = (const uint8_t *)a;
    const uint8_t *p2 = (const uint8_t *)b;
    for (size_t i = 0; i < n; ++i) {
        if (p1[i] != p2[i]) return (p1[i] < p2[i]) ? -1 : 1;
    }
    return 0;
}

void *umemchr(const void *s, int c, size_t n) {
    const uint8_t *p = (const uint8_t *)s;
    for (size_t i = 0; i < n; ++i) {
        if (p[i] == (uint8_t)c) return (void *)(uintptr_t)(p + i);
    }
    return NULL;
}

size_t ustrlen(const char *s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

size_t ustrnlen(const char *s, size_t max) {
    size_t n = 0;
    if (!s) return 0;
    while (n < max && s[n]) n++;
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

int ustrncmp(const char *a, const char *b, size_t n) {
    if (n == 0) return 0;
    size_t i = 0;
    while (a && b && i < n - 1) {
        if (a[i] != b[i] || a[i] == '\0' || b[i] == '\0') break;
        i++;
    }
    char ca = a ? a[i] : 0;
    char cb = b ? b[i] : 0;
    return (int)(ca - cb);
}

char *ustrcpy(char *dst, const char *src) {
    if (!dst) return NULL;
    if (!src) {
        dst[0] = '\0';
        return dst;
    }
    size_t i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}

char *ustrncpy(char *dst, const char *src, size_t n) {
    if (!dst || n == 0) return dst;
    size_t i = 0;
    if (src) {
        for (; i < n && src[i]; ++i) dst[i] = src[i];
    }
    for (; i < n; ++i) dst[i] = '\0';
    return dst;
}

size_t ustrlcpy(char *dst, const char *src, size_t dstsz) {
    size_t src_len = ustrlen(src);
    if (!dst || dstsz == 0) return src_len;
    size_t n = (src_len >= dstsz) ? (dstsz - 1) : src_len;
    for (size_t i = 0; i < n; ++i) dst[i] = src[i];
    dst[n] = '\0';
    return src_len;
}

size_t ustrlcat(char *dst, const char *src, size_t dstsz) {
    size_t dlen = ustrnlen(dst, dstsz);
    size_t slen = ustrlen(src);
    if (dlen == dstsz) return dstsz + slen;
    size_t space = dstsz - dlen - 1;
    size_t n = (slen > space) ? space : slen;
    for (size_t i = 0; i < n; ++i) dst[dlen + i] = src[i];
    dst[dlen + n] = '\0';
    return dlen + slen;
}

char *ustrchr(const char *s, int c) {
    if (!s) return NULL;
    for (; *s; ++s) {
        if (*s == (char)c) return (char *)s;
    }
    if (c == '\0') return (char *)s;
    return NULL;
}

char *ustrrchr(const char *s, int c) {
    if (!s) return NULL;
    const char *last = NULL;
    for (; *s; ++s) {
        if (*s == (char)c) last = s;
    }
    if (c == '\0') return (char *)s;
    return (char *)last;
}

char *ustrstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return (char *)haystack;
    for (const char *p = haystack; *p; ++p) {
        const char *h = p;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++; n++;
        }
        if (!*n) return (char *)p;
    }
    return NULL;
}

void uputs(const char *s) {
    if (s) sys_write(1, s, ustrlen(s));
}

void uputc(char c) {
    sys_write(1, &c, 1);
}

int uatoi(const char *s) {
    int sign = 1;
    int v = 0;
    if (!s) return 0;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    if (*s == '-') { sign = -1; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v * sign;
}

long uatol(const char *s) {
    long sign = 1;
    long v = 0;
    if (!s) return 0;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    if (*s == '-') { sign = -1; s++; }
    else if (*s == '+') { s++; }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v * sign;
}

int uabs(int v) {
    return v < 0 ? -v : v;
}

long ulabs(long v) {
    return v < 0 ? -v : v;
}

int umin(int a, int b) {
    return a < b ? a : b;
}

int umax(int a, int b) {
    return a > b ? a : b;
}

int uclamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void uappend_char(char **dst, size_t *remain, size_t *count, char c) {
    if (dst && *dst && remain && *remain > 1) {
        **dst = c;
        (*dst)++;
        (*remain)--;
    }
    if (count) (*count)++;
}

static void uappend_str(char **dst, size_t *remain, size_t *count, const char *s) {
    if (!s) s = "(null)";
    while (*s) {
        uappend_char(dst, remain, count, *s++);
    }
}

static void uappend_uint(char **dst, size_t *remain, size_t *count, uint64_t v, unsigned base, int upper) {
    char tmp[32];
    size_t n = 0;
    if (v == 0) {
        uappend_char(dst, remain, count, '0');
        return;
    }
    while (v && n < sizeof(tmp)) {
        uint64_t digit = v % base;
        char c = (char)(digit < 10 ? ('0' + digit)
                                   : (upper ? ('A' + (digit - 10)) : ('a' + (digit - 10))));
        tmp[n++] = c;
        v /= base;
    }
    while (n > 0) {
        uappend_char(dst, remain, count, tmp[--n]);
    }
}

static void uappend_int(char **dst, size_t *remain, size_t *count, int64_t v) {
    if (v < 0) {
        uappend_char(dst, remain, count, '-');
        uappend_uint(dst, remain, count, (uint64_t)(-v), 10, 0);
    } else {
        uappend_uint(dst, remain, count, (uint64_t)v, 10, 0);
    }
}

int uvsnprintf(char *dst, size_t dstsz, const char *fmt, va_list ap) {
    char *out = dst;
    size_t remain = dstsz;
    size_t count = 0;
    if (!fmt) {
        if (dst && dstsz) dst[0] = '\0';
        return 0;
    }
    while (*fmt) {
        if (*fmt != '%') {
            uappend_char(&out, &remain, &count, *fmt++);
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            uappend_char(&out, &remain, &count, '%');
            fmt++;
            continue;
        }

        int long_mod = 0;
        int long_long_mod = 0;
        int size_mod = 0;
        if (*fmt == 'l') {
            fmt++;
            if (*fmt == 'l') {
                long_long_mod = 1;
                fmt++;
            } else {
                long_mod = 1;
            }
        } else if (*fmt == 'z') {
            size_mod = 1;
            fmt++;
        }

        switch (*fmt) {
            case 'c': {
                int c = va_arg(ap, int);
                uappend_char(&out, &remain, &count, (char)c);
                break;
            }
            case 's': {
                const char *s = va_arg(ap, const char *);
                uappend_str(&out, &remain, &count, s);
                break;
            }
            case 'd':
            case 'i': {
                int64_t v;
                if (long_long_mod) v = va_arg(ap, long long);
                else if (long_mod) v = va_arg(ap, long);
                else v = va_arg(ap, int);
                uappend_int(&out, &remain, &count, v);
                break;
            }
            case 'u': {
                uint64_t v;
                if (long_long_mod) v = va_arg(ap, unsigned long long);
                else if (long_mod) v = va_arg(ap, unsigned long);
                else if (size_mod) v = va_arg(ap, size_t);
                else v = va_arg(ap, unsigned int);
                uappend_uint(&out, &remain, &count, v, 10, 0);
                break;
            }
            case 'x':
            case 'X': {
                uint64_t v;
                int upper = (*fmt == 'X');
                if (long_long_mod) v = va_arg(ap, unsigned long long);
                else if (long_mod) v = va_arg(ap, unsigned long);
                else if (size_mod) v = va_arg(ap, size_t);
                else v = va_arg(ap, unsigned int);
                uappend_uint(&out, &remain, &count, v, 16, upper);
                break;
            }
            case 'p': {
                uintptr_t v = (uintptr_t)va_arg(ap, void *);
                uappend_str(&out, &remain, &count, "0x");
                uappend_uint(&out, &remain, &count, (uint64_t)v, 16, 0);
                break;
            }
            default:
                uappend_char(&out, &remain, &count, '%');
                uappend_char(&out, &remain, &count, *fmt);
                break;
        }
        if (*fmt) fmt++;
    }
    if (dst && dstsz) {
        if (remain == 0) dst[dstsz - 1] = '\0';
        else *out = '\0';
    }
    return (int)count;
}

int usnprintf(char *dst, size_t dstsz, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = uvsnprintf(dst, dstsz, fmt, ap);
    va_end(ap);
    return n;
}

int uprintf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = uvsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    size_t out_len = ustrnlen(buf, sizeof(buf));
    if (out_len) sys_write(1, buf, out_len);
    return n;
}

static int g_ulog_level = ULOG_INFO;

static const char *ulog_tag(int level) {
    switch (level) {
        case ULOG_DEBUG: return "[DEBUG] ";
        case ULOG_INFO: return "[INFO] ";
        case ULOG_WARN: return "[WARN] ";
        case ULOG_ERROR: return "[ERROR] ";
        default: return "[LOG] ";
    }
}

void ulog_set_level(int level) {
    if (level < ULOG_DEBUG) level = ULOG_DEBUG;
    if (level > ULOG_ERROR) level = ULOG_ERROR;
    g_ulog_level = level;
}

int ulog_get_level(void) {
    return g_ulog_level;
}

int ulogf(int level, const char *fmt, ...) {
    if (level < g_ulog_level) return 0;
    char msg[384];
    va_list ap;
    va_start(ap, fmt);
    (void)uvsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *tag = ulog_tag(level);
    size_t tag_len = ustrlen(tag);
    size_t msg_len = ustrnlen(msg, sizeof(msg));
    if (tag_len) sys_write(1, tag, tag_len);
    if (msg_len) sys_write(1, msg, msg_len);
    if (msg_len == 0 || msg[msg_len - 1] != '\n') {
        sys_write(1, "\n", 1);
        return (int)(tag_len + msg_len + 1);
    }
    return (int)(tag_len + msg_len);
}

int ulog_debug(const char *fmt, ...) {
    if (ULOG_DEBUG < g_ulog_level) return 0;
    va_list ap;
    va_start(ap, fmt);
    char msg[384];
    (void)uvsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    return ulogf(ULOG_DEBUG, "%s", msg);
}

int ulog_info(const char *fmt, ...) {
    if (ULOG_INFO < g_ulog_level) return 0;
    va_list ap;
    va_start(ap, fmt);
    char msg[384];
    (void)uvsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    return ulogf(ULOG_INFO, "%s", msg);
}

int ulog_warn(const char *fmt, ...) {
    if (ULOG_WARN < g_ulog_level) return 0;
    va_list ap;
    va_start(ap, fmt);
    char msg[384];
    (void)uvsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    return ulogf(ULOG_WARN, "%s", msg);
}

int ulog_error(const char *fmt, ...) {
    if (ULOG_ERROR < g_ulog_level) return 0;
    va_list ap;
    va_start(ap, fmt);
    char msg[384];
    (void)uvsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    return ulogf(ULOG_ERROR, "%s", msg);
}
