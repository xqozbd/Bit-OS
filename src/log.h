#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

void log_init_serial(void);
void log_set_fb_ready(int ready);
void log_printf(const char *fmt, ...);

#endif /* LOG_H */
