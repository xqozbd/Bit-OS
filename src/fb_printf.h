#ifndef FB_PRINTF_H
#define FB_PRINTF_H

#include <stdint.h>
#include <stdarg.h>
#include "compat.h"
#include "limine.h" /* Make sure limine.h is in your include path */

/* Initialize framebuffer printing with foreground/background color */
void fb_init(struct limine_framebuffer *fb, uint32_t fg, uint32_t bg);

/* Optional layout controls */
void fb_set_layout(uint32_t scale, uint32_t line_gap, uint32_t margin_x, uint32_t margin_y, uint32_t tab_width);
void fb_set_layout_ex(uint32_t scale, uint32_t line_gap, uint32_t margin_x, uint32_t margin_y, uint32_t tab_width, uint32_t char_spacing);

/* Print functions */
void fb_clear(void);
void fb_putc(char c);
void fb_puts(const char *s);
void fb_printf(const char *fmt, ...);
void fb_vprintf(const char *fmt, va_list ap);

/* Optional: change colors for next prints */
void fb_set_colors(uint32_t fg, uint32_t bg);

/* Optional: cursor/layout queries and drawing helpers */
void fb_set_cursor_px(uint32_t x, uint32_t y);
uint32_t fb_line_height(void);
uint32_t fb_margin_x(void);
uint32_t fb_margin_y(void);
void fb_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb24);

#endif /* FB_PRINTF_H */
