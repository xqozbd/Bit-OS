#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stddef.h>

void log_init_serial(void);
void log_set_fb_ready(int ready);
void log_set_verbose(int verbose);
int log_is_verbose(void);
void log_printf(const char *fmt, ...);
void log_printf_verbose(const char *fmt, ...);
void log_ring_dump(void);
void log_ring_freeze(int freeze);
size_t log_ring_snapshot(char *out, size_t max);

#endif /* LOG_H */
