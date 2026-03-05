#ifndef LIBU_H
#define LIBU_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

size_t ustrlen(const char *s);
size_t ustrnlen(const char *s, size_t max);
int ustrcmp(const char *a, const char *b);
int ustrncmp(const char *a, const char *b, size_t n);
char *ustrcpy(char *dst, const char *src);
char *ustrncpy(char *dst, const char *src, size_t n);
size_t ustrlcpy(char *dst, const char *src, size_t dstsz);
size_t ustrlcat(char *dst, const char *src, size_t dstsz);
char *ustrchr(const char *s, int c);
char *ustrrchr(const char *s, int c);
char *ustrstr(const char *haystack, const char *needle);

void *umemcpy(void *dst, const void *src, size_t n);
void *umemmove(void *dst, const void *src, size_t n);
void *umemset(void *dst, int c, size_t n);
int umemcmp(const void *a, const void *b, size_t n);
void *umemchr(const void *s, int c, size_t n);

void uputs(const char *s);
void uputc(char c);
int uatoi(const char *s);
long uatol(const char *s);
int uabs(int v);
long ulabs(long v);
int umin(int a, int b);
int umax(int a, int b);
int uclamp(int v, int lo, int hi);

int uprintf(const char *fmt, ...);
int usnprintf(char *dst, size_t dstsz, const char *fmt, ...);
int uvsnprintf(char *dst, size_t dstsz, const char *fmt, va_list ap);

enum {
    ULOG_DEBUG = 0,
    ULOG_INFO = 1,
    ULOG_WARN = 2,
    ULOG_ERROR = 3
};

void ulog_set_level(int level);
int ulog_get_level(void);
int ulogf(int level, const char *fmt, ...);
int ulog_debug(const char *fmt, ...);
int ulog_info(const char *fmt, ...);
int ulog_warn(const char *fmt, ...);
int ulog_error(const char *fmt, ...);

#endif /* LIBU_H */
