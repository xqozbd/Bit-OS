#ifndef FB_PRINTF_H
#define FB_PRINTF_H

#include <stdint.h>
#include <stdarg.h>
#include "limine.h" /* Make sure limine.h is in your include path */

/* Initialize framebuffer printing with foreground/background color */
void fb_init(struct limine_framebuffer *fb, uint32_t fg, uint32_t bg);

/* Print functions */
void fb_clear(void);
void fb_putc(char c);
void fb_puts(const char *s);
void fb_printf(const char *fmt, ...);

/* Optional: change colors for next prints */
void fb_set_colors(uint32_t fg, uint32_t bg);

#endif /* FB_PRINTF_H */
