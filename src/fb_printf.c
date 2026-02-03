
#include "fb_printf.h"
#include "font8x8_basic.h"
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
/* Horizontal glyph width stays 8; vertical height doubled to 16 */
static uint32_t char_w = 8, char_h = 16;

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

/*
 * draw character at pixel coordinates (x,y).
 * Uses font8x8_basic (8 rows). We duplicate each row vertically so
 * font 8x8 becomes 8x16 on screen.
 */
static void draw_char_px(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg) {
    unsigned char uc = (unsigned char)c;
    if (uc > 127) uc = '?';
    const unsigned char *glyph = font8x8_basic[uc];

    /* glyph has 8 rows; for each row we draw two pixel rows */
    for (uint32_t row = 0; row < 8; ++row) {
        unsigned char rowbits = glyph[row];
        /* compute the y positions for the doubled rows */
        uint32_t y_top = y + row * 2;
        uint32_t y_bottom = y_top + 1;

        for (uint32_t col = 0; col < char_w; ++col) {
            uint32_t color = (rowbits & (1u << col)) ? fg : bg;
            put_pixel(x + col, y_top, color);
            put_pixel(x + col, y_bottom, color);
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

static void clear_last_row_pixels(uint32_t row) {
    uint8_t *addr = fb_ptr + (size_t)row * fb_pitch;
    for (uint64_t i = 0; i < fb_pitch; ++i) addr[i] = 0;
}

/*
 * Scroll up by n_chars character-rows (n_chars * char_h pixels).
 * char_h is now 16 (8 glyph rows * 2 duplicate rows).
 */
static void scroll_up_chars(uint32_t n_chars) {
    if (!g_fb || n_chars == 0) return;

    /* number of pixel rows to move/skip */
    uint32_t pixel_rows = n_chars * char_h;

    /* rows_to_move = remaining pixel rows after removing the top pixel_rows */
    if (pixel_rows >= fb_height) {
        /* clear screen */
        for (size_t i = 0; i < fb_pitch * fb_height; ++i) fb_ptr[i] = 0;
        cursor_x = cursor_y = 0;
        return;
    }

    uint32_t rows_to_move = fb_height - pixel_rows;

    /* move the block up */
    copy_rows(0, pixel_rows, rows_to_move);

    /* clear bottom pixel_rows */
    for (uint32_t r = rows_to_move; r < fb_height; ++r) clear_last_row_pixels(r);
}

static void new_line(void) {
    cursor_x = 0;
    cursor_y += char_h;
    if (cursor_y + char_h > fb_height) {
        scroll_up_chars(1);
        cursor_y -= char_h;
    }
}

/* API functions */
void fb_putc(char c) {
    if (!g_fb) return;
    if (c == '\n') { new_line(); return; }
    if (c == '\r') { cursor_x = 0; return; }

    draw_char_px(cursor_x, cursor_y, c, cur_fg, cur_bg);
    cursor_x += char_w;
    if (cursor_x + char_w > fb_width) new_line();
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
    cursor_x = cursor_y = 0;
    cur_fg = fg; cur_bg = bg;

    /* clear framebuffer to bg color */
    for (uint32_t y = 0; y < fb_height; ++y)
        for (uint32_t x = 0; x < fb_width; ++x)
            put_pixel(x, y, bg);
}

void fb_clear(void) { fb_init(g_fb, cur_fg, cur_bg); cursor_x = cursor_y = 0; }
void fb_set_colors(uint32_t fg, uint32_t bg) { cur_fg = fg; cur_bg = bg; }

void fb_printf(const char *fmt, ...) {
    if (!g_fb) return;
    va_list ap; va_start(ap, fmt);
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

    va_end(ap);
}
