
#include "drivers/video/fb_printf.h"
#include "drivers/video/font8x8_basic.h"
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* global framebuffer state */
static struct limine_framebuffer *g_fb = 0;
static uint8_t *fb_ptr = 0;
static uint64_t fb_width = 0, fb_height = 0, fb_pitch = 0;
static uint16_t fb_bpp = 0;
static uint8_t fb_rm_size = 0, fb_rm_shift = 0;
static uint8_t fb_gm_size = 0, fb_gm_shift = 0;
static uint8_t fb_bm_size = 0, fb_bm_shift = 0;
static uint32_t fb_bytes_per_pixel = 0;

/* cursor (pixel coordinates) */
static uint32_t cursor_x = 0, cursor_y = 0;
/* base font dimensions */
static uint32_t char_w = 8, char_h = 8;
static uint32_t char_scale = 2;
static uint32_t line_gap = 4;
static uint32_t margin_x = 24, margin_y = 24;
static uint32_t tab_width = 4;
static uint32_t char_spacing = 2;

/* current colors */
static uint32_t cur_fg = 0xFFFFFF, cur_bg = 0x000000;

/* helpers */
static inline void min_max_uint32(uint32_t *v, uint32_t minv, uint32_t maxv) {
    if (*v < minv) *v = minv;
    if (*v > maxv) *v = maxv;
}

/* map 24-bit RGB to framebuffer pixel value */
static uint32_t pack_pixel(uint32_t rgb24) {
    uint32_t r = (rgb24 >> 16) & 0xFF;
    uint32_t g = (rgb24 >> 8) & 0xFF;
    uint32_t b = rgb24 & 0xFF;

    uint32_t r_part = (fb_rm_size == 0) ? 0 : ((r >> (8 - fb_rm_size)) & ((1u << fb_rm_size) - 1u));
    uint32_t g_part = (fb_gm_size == 0) ? 0 : ((g >> (8 - fb_gm_size)) & ((1u << fb_gm_size) - 1u));
    uint32_t b_part = (fb_bm_size == 0) ? 0 : ((b >> (8 - fb_bm_size)) & ((1u << fb_bm_size) - 1u));

    return (r_part << fb_rm_shift) | (g_part << fb_gm_shift) | (b_part << fb_bm_shift);
}

/* write pixel at x,y */
static void put_pixel(int x, int y, uint32_t rgb24) {
    if (!g_fb) return;
    if ((unsigned)x >= fb_width || (unsigned)y >= fb_height) return;

    uint8_t *addr = fb_ptr + (size_t)y * fb_pitch + (size_t)x * fb_bytes_per_pixel;
    uint32_t pixel = pack_pixel(rgb24);

    if (fb_bytes_per_pixel == 4) {
        *((uint32_t *)addr) = pixel;
    } else if (fb_bytes_per_pixel == 3) {
        addr[0] = pixel & 0xFF;
        addr[1] = (pixel >> 8) & 0xFF;
        addr[2] = (pixel >> 16) & 0xFF;
    } else if (fb_bytes_per_pixel == 2) {
        uint16_t v = (uint16_t)(pixel & 0xFFFF);
        addr[0] = v & 0xFF;
        addr[1] = (v >> 8) & 0xFF;
    }
}

uint32_t fb_read_pixel(uint32_t x, uint32_t y) {
    if (!g_fb) return 0;
    if (x >= fb_width || y >= fb_height) return 0;
    uint8_t *addr = fb_ptr + (size_t)y * fb_pitch + (size_t)x * fb_bytes_per_pixel;
    if (fb_bytes_per_pixel == 4) {
        return *((uint32_t *)addr);
    } else if (fb_bytes_per_pixel == 3) {
        return (uint32_t)addr[0] | ((uint32_t)addr[1] << 8) | ((uint32_t)addr[2] << 16);
    } else if (fb_bytes_per_pixel == 2) {
        return (uint32_t)addr[0] | ((uint32_t)addr[1] << 8);
    }
    return 0;
}

void fb_write_pixel(uint32_t x, uint32_t y, uint32_t rgb24) {
    put_pixel((int)x, (int)y, rgb24);
}

static uint32_t line_step(void) {
    return char_h * char_scale + line_gap;
}

/* draw character at pixel coordinates (x,y) with scaling */
static void draw_char_px(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg) {
    unsigned char uc = (unsigned char)c;
    if (uc > 127) uc = '?';
    const unsigned char *glyph = (const unsigned char *)font8x8_basic[uc];

    for (uint32_t row = 0; row < char_h; ++row) {
        unsigned char rowbits = glyph[row];
        for (uint32_t col = 0; col < char_w; ++col) {
            uint32_t color = (rowbits & (1u << col)) ? fg : bg;
            uint32_t px = x + col * char_scale;
            uint32_t py = y + row * char_scale;
            for (uint32_t sy = 0; sy < char_scale; ++sy)
                for (uint32_t sx = 0; sx < char_scale; ++sx)
                    put_pixel(px + sx, py + sy, color);
        }
    }
}

/* copy rows for scrolling (rows are counted in pixels) */
static void copy_rows(uint32_t dst_row, uint32_t src_row, uint32_t row_count) {
    uint8_t *addr = fb_ptr;
    uint8_t *dst = addr + (size_t)dst_row * fb_pitch;
    uint8_t *src = addr + (size_t)src_row * fb_pitch;
    size_t bytes = (size_t)row_count * fb_pitch;

    if (dst <= src) {
        for (size_t i = 0; i < bytes; ++i) dst[i] = src[i];
    } else {
        for (size_t i = bytes; i-- > 0;) dst[i] = src[i];
    }
}

static void clear_row_bg(uint32_t row) {
    uint8_t *addr = fb_ptr + (size_t)row * fb_pitch;
    uint32_t pixel = pack_pixel(cur_bg);

    if (fb_bytes_per_pixel == 4) {
        uint32_t *p = (uint32_t *)addr;
        for (uint64_t i = 0; i < fb_pitch / 4; ++i) p[i] = pixel;
    } else if (fb_bytes_per_pixel == 3) {
        for (uint64_t i = 0; i < fb_pitch; i += 3) {
            addr[i + 0] = pixel & 0xFF;
            addr[i + 1] = (pixel >> 8) & 0xFF;
            addr[i + 2] = (pixel >> 16) & 0xFF;
        }
    } else if (fb_bytes_per_pixel == 2) {
        uint16_t v = (uint16_t)(pixel & 0xFFFF);
        for (uint64_t i = 0; i < fb_pitch; i += 2) {
            addr[i + 0] = v & 0xFF;
            addr[i + 1] = (v >> 8) & 0xFF;
        }
    }
}

static void scroll_up_pixels(uint32_t n_rows) {
    if (!g_fb || n_rows == 0) return;
    if (n_rows >= fb_height) {
        for (uint32_t r = 0; r < fb_height; ++r) clear_row_bg(r);
        cursor_x = margin_x;
        cursor_y = margin_y;
        return;
    }
    uint32_t rows_to_move = fb_height - n_rows;
    copy_rows(0, n_rows, rows_to_move);
    for (uint32_t r = rows_to_move; r < fb_height; ++r) clear_row_bg(r);
}

static void new_line(void) {
    cursor_x = margin_x;
    cursor_y += line_step();
    if (cursor_y + char_h * char_scale > (fb_height - margin_y)) {
        scroll_up_pixels(line_step());
        cursor_y -= line_step();
    }
}

/* API functions */
void fb_putc(char c) {
    if (!g_fb) return;
    if (c == '\n') { new_line(); return; }
    if (c == '\r') { cursor_x = margin_x; return; }
    if (c == '\t') {
        uint32_t step = char_w * char_scale + char_spacing;
        uint32_t tab_px = tab_width * step;
        uint32_t next = ((cursor_x - margin_x + tab_px) / tab_px) * tab_px + margin_x;
        cursor_x = next;
        return;
    }
    if (c == '\b') {
        uint32_t step = char_w * char_scale + char_spacing;
        if (cursor_x >= margin_x + step) cursor_x -= step;
        return;
    }

    draw_char_px(cursor_x, cursor_y, c, cur_fg, cur_bg);
    cursor_x += char_w * char_scale + char_spacing;
    if (cursor_x + char_w * char_scale > (fb_width - margin_x)) new_line();
}

void fb_puts(const char *s) { while (*s) fb_putc(*s++); }

static void utoa_unsigned(uint64_t val, unsigned int base, char *out) {
    char buf[32]; int i = 0;
    if (val == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (val > 0) {
        int digit = val % base;
        buf[i++] = (digit < 10) ? ('0' + digit) : ('a' + (digit - 10));
        val /= base;
    }
    int j = 0; while (i > 0) out[j++] = buf[--i]; out[j] = '\0';
}

static void itoa_signed(int64_t val, char *out) {
    if (val < 0) { *out++ = '-'; utoa_unsigned((uint64_t)(-val), 10, out); }
    else utoa_unsigned((uint64_t)val, 10, out);
}

void fb_init(struct limine_framebuffer *fb, uint32_t fg, uint32_t bg) {
    if (!fb) return;
    g_fb = fb;
    fb_ptr = (uint8_t *)fb->address;
    fb_width = fb->width;
    fb_height = fb->height;
    fb_pitch = fb->pitch;
    fb_bpp = fb->bpp;
    fb_rm_size = fb->red_mask_size; fb_rm_shift = fb->red_mask_shift;
    fb_gm_size = fb->green_mask_size; fb_gm_shift = fb->green_mask_shift;
    fb_bm_size = fb->blue_mask_size; fb_bm_shift = fb->blue_mask_shift;
    fb_bytes_per_pixel = (fb_bpp + 7) / 8;
    cursor_x = margin_x;
    cursor_y = margin_y;
    cur_fg = fg; cur_bg = bg;

    /* clear framebuffer to bg color */
    for (uint32_t y = 0; y < fb_height; ++y) clear_row_bg(y);
}

void fb_clear(void) { fb_init(g_fb, cur_fg, cur_bg); cursor_x = margin_x; cursor_y = margin_y; }
void fb_set_colors(uint32_t fg, uint32_t bg) { cur_fg = fg; cur_bg = bg; }
void fb_get_colors(uint32_t *fg, uint32_t *bg) {
    if (fg) *fg = cur_fg;
    if (bg) *bg = cur_bg;
}
void fb_set_layout(uint32_t scale, uint32_t gap, uint32_t mx, uint32_t my, uint32_t tabw) {
    fb_set_layout_ex(scale, gap, mx, my, tabw, char_spacing);
}

void fb_set_layout_ex(uint32_t scale, uint32_t gap, uint32_t mx, uint32_t my, uint32_t tabw, uint32_t spacing) {
    if (scale == 0) scale = 1;
    char_scale = scale;
    line_gap = gap;
    margin_x = mx;
    margin_y = my;
    tab_width = (tabw == 0) ? 4 : tabw;
    char_spacing = spacing;
    cursor_x = margin_x;
    cursor_y = margin_y;
}

void fb_set_cursor_px(uint32_t x, uint32_t y) {
    cursor_x = x;
    cursor_y = y;
}

void fb_get_cursor_px(uint32_t *x, uint32_t *y) {
    if (x) *x = cursor_x;
    if (y) *y = cursor_y;
}

void fb_get_dimensions(uint32_t *w, uint32_t *h) {
    if (w) *w = (uint32_t)fb_width;
    if (h) *h = (uint32_t)fb_height;
}

uint32_t fb_line_height(void) {
    return line_step();
}

uint32_t fb_margin_x(void) {
    return margin_x;
}

uint32_t fb_margin_y(void) {
    return margin_y;
}

void fb_draw_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb24) {
    if (!g_fb) return;
    if (x >= fb_width || y >= fb_height) return;
    if (x + w > fb_width) w = fb_width - x;
    if (y + h > fb_height) h = fb_height - y;
    for (uint32_t py = y; py < y + h; ++py) {
        for (uint32_t px = x; px < x + w; ++px) {
            put_pixel((int)px, (int)py, rgb24);
        }
    }
}

void fb_vprintf(const char *fmt, va_list ap) {
    if (!g_fb) return;
    const char *p = fmt; char numbuf[64];

    while (*p) {
        if (*p == '%') {
            ++p; if (!*p) break;
            switch (*p) {
                case '%': fb_putc('%'); break;
                case 's': { const char *s = va_arg(ap,const char*); if(!s)s="(null)"; fb_puts(s); } break;
                case 'c': { int c = va_arg(ap,int); fb_putc((char)c); } break;
                case 'd': { int val = va_arg(ap,int); itoa_signed(val,numbuf); fb_puts(numbuf); } break;
                case 'u': { unsigned int val = va_arg(ap,unsigned int); utoa_unsigned(val,10,numbuf); fb_puts(numbuf); } break;
                case 'x': { unsigned int val = va_arg(ap,unsigned int); utoa_unsigned(val,16,numbuf); fb_puts(numbuf); } break;
                case 'p': { void *ptr = va_arg(ap,void*); utoa_unsigned((uintptr_t)ptr,16,numbuf); fb_puts("0x"); fb_puts(numbuf); } break;
                default: fb_putc('%'); fb_putc(*p); break;
            }
        } else if (*p == '\n') new_line();
        else fb_putc(*p);
        ++p;
    }
}

void fb_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fb_vprintf(fmt, ap);
    va_end(ap);
}
