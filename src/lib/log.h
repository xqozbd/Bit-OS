#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stddef.h>

enum log_level {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
    LOG_NONE  = 4
};

void log_init_serial(void);
void log_set_fb_ready(int ready);
void log_set_verbose(int verbose);
int log_is_verbose(void);
void log_set_level(enum log_level level);
enum log_level log_get_level(void);
int log_is_enabled(enum log_level level);
void log_printf(const char *fmt, ...);
void log_printf_level(enum log_level level, const char *fmt, ...);
void log_printf_verbose(const char *fmt, ...);
int log_serial_try_getc(void);

#define log_debug(...) log_printf_level(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  log_printf_level(LOG_INFO, __VA_ARGS__)
#define log_warn(...)  log_printf_level(LOG_WARN, __VA_ARGS__)
#define log_error(...) log_printf_level(LOG_ERROR, __VA_ARGS__)
void log_ring_dump(void);
void log_ring_freeze(int freeze);
size_t log_ring_snapshot(char *out, size_t max);

#endif /* LOG_H */
