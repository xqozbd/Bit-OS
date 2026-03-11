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
    uint32_t format;
    uint32_t rotation;
    uint32_t dpi_x;
    uint32_t dpi_y;
};

int fb_get_info(struct fb_info *out);

enum {
    FB_FORMAT_UNKNOWN = 0,
    FB_FORMAT_XRGB8888 = 1,
    FB_FORMAT_RGB565 = 2
};

enum {
    FB_IOCTL_GET_MODE = 0x4601u,
    FB_IOCTL_GET_INFO = 0x4602u,
    FB_IOCTL_GET_MODES = 0x4603u,
    FB_IOCTL_SET_MODE = 0x4604u,
    FB_IOCTL_PAGE_FLIP = 0x4605u,
    FB_IOCTL_WAIT_VSYNC = 0x4606u,
    FB_IOCTL_SET_CLIP = 0x4607u,
    FB_IOCTL_GET_CLIP = 0x4608u,
    FB_IOCTL_CLEAR_CLIP = 0x4609u,
    FB_IOCTL_GET_DISPLAY = 0x460Au,
    FB_IOCTL_SET_DISPLAY = 0x460Bu
};

struct fb_mode_info {
    uint64_t phys_addr;
    uint64_t size_bytes;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint8_t red_mask_size;
    uint8_t red_mask_shift;
    uint8_t green_mask_size;
    uint8_t green_mask_shift;
    uint8_t blue_mask_size;
    uint8_t blue_mask_shift;
    uint32_t format;
    uint32_t mode_id;
};

int fb_get_mode_info(struct fb_mode_info *out);

struct fb_mode_set_request {
    uint32_t mode_id;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t format;
};

#define FB_MAX_ENUM_MODES 8u

struct fb_mode_list {
    uint32_t capacity;
    uint32_t count;
    struct fb_mode_info modes[FB_MAX_ENUM_MODES];
};

struct fb_clip_rect {
    uint32_t x;
    uint32_t y;
    uint32_t w;
    uint32_t h;
};

struct fb_flip_request {
    uint32_t flags;
    struct fb_clip_rect rect;
};

struct fb_vsync_request {
    uint32_t timeout_ms;
};

struct fb_display_info {
    uint32_t rotation;
    uint32_t dpi_x;
    uint32_t dpi_y;
    uint32_t reserved;
};

int fb_get_modes(struct fb_mode_list *out);
int fb_set_mode(const struct fb_mode_set_request *req);
void fb_get_display_info(struct fb_display_info *out);
int fb_set_display_info(const struct fb_display_info *in);
uint32_t fb_color_format(void);
uint32_t fb_rgb24_to_xrgb8888(uint32_t rgb24);
uint16_t fb_rgb24_to_rgb565(uint32_t rgb24);

/* Double buffer helpers */
int fb_backbuffer_init(void);
int fb_backbuffer_ready(void);
void fb_backbuffer_clear(uint32_t rgb24);
void fb_backbuffer_write_pixel(uint32_t x, uint32_t y, uint32_t rgb24);
void fb_backbuffer_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb24);
void fb_backbuffer_draw_line(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1, uint32_t rgb24);
void fb_backbuffer_swap(void);
void fb_backbuffer_swap_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h);

#endif /* FB_PRINTF_H */
