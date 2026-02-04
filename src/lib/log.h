#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

void log_init_serial(void);
void log_set_fb_ready(int ready);
void log_printf(const char *fmt, ...);
void log_ring_dump(void);
void log_ring_freeze(int freeze);

#endif /* LOG_H */
