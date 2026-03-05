#ifndef FB_PRINTF_H
#define FB_PRINTF_H

#include <stdint.h>
#include <stdarg.h>
#include "lib/compat.h"
#include "boot/limine.h" /* Make sure limine.h is in your include path */

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
void fb_scrollback_up(uint32_t lines);
void fb_scrollback_down(uint32_t lines);
void fb_scrollback_reset(void);
uint32_t fb_scrollback_offset(void);
void fb_scrollback_suspend(int suspend);
void fb_vprintf(const char *fmt, va_list ap);

/* Optional: change colors for next prints */
void fb_set_colors(uint32_t fg, uint32_t bg);
void fb_get_colors(uint32_t *fg, uint32_t *bg);

/* Optional: cursor/layout queries and drawing helpers */
void fb_set_cursor_px(uint32_t x, uint32_t y);
void fb_get_cursor_px(uint32_t *x, uint32_t *y);
void fb_get_dimensions(uint32_t *w, uint32_t *h);
uint32_t fb_get_pitch(void);
uint32_t fb_get_bpp(void);
uint32_t fb_read_pixel(uint32_t x, uint32_t y);
void fb_write_pixel(uint32_t x, uint32_t y, uint32_t rgb24);
uint32_t fb_line_height(void);
uint32_t fb_margin_x(void);
uint32_t fb_margin_y(void);
void fb_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb24);
void fb_draw_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t rgb24);

struct fb_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
};

int fb_get_info(struct fb_info *out);

/* Double buffer helpers */
int fb_backbuffer_init(void);
int fb_backbuffer_ready(void);
void fb_backbuffer_clear(uint32_t rgb24);
void fb_backbuffer_write_pixel(uint32_t x, uint32_t y, uint32_t rgb24);
void fb_backbuffer_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb24);
void fb_backbuffer_draw_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t rgb24);
void fb_backbuffer_swap(void);

#endif /* FB_PRINTF_H */
