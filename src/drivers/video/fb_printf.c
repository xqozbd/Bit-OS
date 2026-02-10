
#include "drivers/video/fb_printf.h"
#include "drivers/video/font8x8_basic.h"
#include "drivers/ps2/mouse.h"
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
static uint32_t def_fg = 0xFFFFFF, def_bg = 0x000000;

/* VT100/ANSI state */
static int vt_esc_state = 0; /* 0=none, 1=ESC seen, 2=CSI */
static int vt_params[8];
static int vt_param_count = 0;
static int vt_param_value = 0;
static int vt_param_has_value = 0;
static int vt_bright = 0;

static const uint32_t vt_palette[8] = {
    0x000000, /* black */
    0xAA0000, /* red */
    0x00AA00, /* green */
    0xAA5500, /* yellow */
    0x0000AA, /* blue */
    0xAA00AA, /* magenta */
    0x00AAAA, /* cyan */
    0xAAAAAA  /* white */
};

static const uint32_t vt_palette_bright[8] = {
    0x555555, /* bright black */
    0xFF5555, /* bright red */
    0x55FF55, /* bright green */
    0xFFFF55, /* bright yellow */
    0x5555FF, /* bright blue */
    0xFF55FF, /* bright magenta */
    0x55FFFF, /* bright cyan */
    0xFFFFFF  /* bright white */
};

/* forward declarations */
static void draw_char_px(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg);
static void clear_row_bg(uint32_t row);
static void clear_to_eol(void);
static void vt_apply_sgr(void);
static int vt_handle_char(char c);

/* scrollback buffer */
#define SB_MAX_LINES 1024
#define SB_MAX_COLS 160
static char sb_lines[SB_MAX_LINES][SB_MAX_COLS];
static uint16_t sb_lens[SB_MAX_LINES];
static uint32_t sb_head = 0;
static uint32_t sb_count = 0;
static uint32_t sb_cur_line = 0;
static uint32_t sb_cursor_col = 0;
static uint32_t sb_cols = 0;
static uint32_t sb_rows = 0;
static uint32_t sb_view_offset = 0;
static int sb_record_enabled = 1;

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

static uint32_t col_step(void) {
    return char_w * char_scale + char_spacing;
}

static uint32_t sb_ring_index(uint32_t logical) {
    return (sb_head + logical) % SB_MAX_LINES;
}

static void sb_clear_lines(void) {
    for (uint32_t i = 0; i < SB_MAX_LINES; ++i) {
        sb_lens[i] = 0;
        sb_lines[i][0] = '\0';
    }
}

static void sb_recalc_geometry(void) {
    uint32_t step = col_step();
    if (step == 0) step = 1;
    uint32_t avail_w = (fb_width > (margin_x * 2)) ? (fb_width - margin_x * 2) : fb_width;
    uint32_t avail_h = (fb_height > (margin_y * 2)) ? (fb_height - margin_y * 2) : fb_height;
    sb_cols = avail_w / step;
    if (sb_cols == 0) sb_cols = 1;
    if (sb_cols > SB_MAX_COLS) sb_cols = SB_MAX_COLS;
    uint32_t lstep = line_step();
    if (lstep == 0) lstep = 1;
    sb_rows = avail_h / lstep;
    if (sb_rows == 0) sb_rows = 1;
    if (sb_rows > SB_MAX_LINES) sb_rows = SB_MAX_LINES;
}

static void sb_reset(void) {
    sb_clear_lines();
    sb_head = 0;
    sb_count = 1;
    sb_cur_line = 0;
    sb_cursor_col = 0;
    sb_view_offset = 0;
    sb_lens[0] = 0;
    sb_lines[0][0] = '\0';
}

static uint32_t sb_view_start(void) {
    if (sb_count <= sb_rows) return 0;
    uint32_t max_off = sb_count - sb_rows;
    if (sb_view_offset > max_off) sb_view_offset = max_off;
    return (sb_count - sb_rows) - sb_view_offset;
}

static void sb_set_cursor_px(void) {
    if (sb_count == 0) {
        cursor_x = margin_x;
        cursor_y = margin_y;
        return;
    }
    uint32_t row = 0;
    if (sb_count <= sb_rows) row = sb_count - 1;
    else row = sb_rows - 1;
    cursor_x = margin_x + sb_cursor_col * col_step();
    cursor_y = margin_y + row * line_step();
}

static void sb_newline(void) {
    if (sb_count < SB_MAX_LINES) {
        sb_cur_line = sb_ring_index(sb_count);
        sb_count++;
    } else {
        sb_head = (sb_head + 1) % SB_MAX_LINES;
        sb_cur_line = sb_ring_index(sb_count - 1);
    }
    sb_lens[sb_cur_line] = 0;
    sb_lines[sb_cur_line][0] = '\0';
    sb_cursor_col = 0;
    if (sb_view_offset > 0) {
        sb_view_offset++;
        uint32_t max_off = (sb_count > sb_rows) ? (sb_count - sb_rows) : 0;
        if (sb_view_offset > max_off) sb_view_offset = max_off;
    }
}

static void sb_put_char(char c) {
    if (c == '\n') { sb_newline(); return; }
    if (c == '\r') { sb_cursor_col = 0; return; }
    if (c == '\b') {
        if (sb_cursor_col > 0) {
            sb_cursor_col--;
            if (sb_lens[sb_cur_line] > sb_cursor_col) {
                sb_lens[sb_cur_line] = sb_cursor_col;
                sb_lines[sb_cur_line][sb_cursor_col] = '\0';
            }
        }
        return;
    }
    if (c == '\t') {
        uint32_t tab = (tab_width == 0) ? 4 : tab_width;
        uint32_t next = ((sb_cursor_col + tab) / tab) * tab;
        while (sb_cursor_col < next) {
            sb_put_char(' ');
        }
        return;
    }
    if (sb_cursor_col >= sb_cols) sb_newline();
    if (sb_cursor_col >= SB_MAX_COLS) return;
    sb_lines[sb_cur_line][sb_cursor_col++] = c;
    if (sb_cursor_col > sb_lens[sb_cur_line]) {
        sb_lens[sb_cur_line] = sb_cursor_col;
        if (sb_cursor_col < SB_MAX_COLS) sb_lines[sb_cur_line][sb_cursor_col] = '\0';
    }
}

static void sb_render_full(void) {
    if (!g_fb) return;
    ms_cursor_hide();
    for (uint32_t y = 0; y < fb_height; ++y) clear_row_bg(y);
    uint32_t start = sb_view_start();
    uint32_t rows = sb_rows;
    for (uint32_t r = 0; r < rows; ++r) {
        uint32_t line_idx = start + r;
        if (line_idx >= sb_count) break;
        uint32_t ring = sb_ring_index(line_idx);
        uint16_t len = sb_lens[ring];
        uint32_t px = margin_x;
        uint32_t py = margin_y + r * line_step();
        for (uint32_t c = 0; c < len && c < sb_cols; ++c) {
            draw_char_px(px, py, sb_lines[ring][c], cur_fg, cur_bg);
            px += col_step();
        }
    }
    if (sb_view_offset == 0) sb_set_cursor_px();
    ms_cursor_show();
}

static void clear_to_eol(void) {
    if (!g_fb) return;
    uint32_t row_top = cursor_y;
    uint32_t row_bottom = cursor_y + line_step();
    if (row_bottom > fb_height) row_bottom = (uint32_t)fb_height;
    uint32_t pixel = pack_pixel(cur_bg);
    for (uint32_t y = row_top; y < row_bottom; ++y) {
        uint8_t *addr = fb_ptr + (size_t)y * fb_pitch + (size_t)cursor_x * fb_bytes_per_pixel;
        uint64_t remaining = fb_width - cursor_x;
        if (fb_bytes_per_pixel == 4) {
            uint32_t *p = (uint32_t *)addr;
            for (uint64_t i = 0; i < remaining; ++i) p[i] = pixel;
        } else if (fb_bytes_per_pixel == 3) {
            for (uint64_t i = 0; i < remaining; ++i) {
                uint64_t off = i * 3;
                addr[off + 0] = pixel & 0xFF;
                addr[off + 1] = (pixel >> 8) & 0xFF;
                addr[off + 2] = (pixel >> 16) & 0xFF;
            }
        } else if (fb_bytes_per_pixel == 2) {
            uint16_t v = (uint16_t)(pixel & 0xFFFF);
            for (uint64_t i = 0; i < remaining; ++i) {
                uint64_t off = i * 2;
                addr[off + 0] = v & 0xFF;
                addr[off + 1] = (v >> 8) & 0xFF;
            }
        }
    }
}

static void vt_apply_sgr(void) {
    if (vt_param_count == 0) {
        cur_fg = def_fg;
        cur_bg = def_bg;
        vt_bright = 0;
        return;
    }
    for (int i = 0; i < vt_param_count; ++i) {
        int p = vt_params[i];
        if (p == 0) {
            cur_fg = def_fg;
            cur_bg = def_bg;
            vt_bright = 0;
        } else if (p == 1) {
            vt_bright = 1;
        } else if (p == 22) {
            vt_bright = 0;
        } else if (p >= 30 && p <= 37) {
            int idx = p - 30;
            cur_fg = vt_bright ? vt_palette_bright[idx] : vt_palette[idx];
        } else if (p >= 90 && p <= 97) {
            int idx = p - 90;
            cur_fg = vt_palette_bright[idx];
        } else if (p >= 40 && p <= 47) {
            int idx = p - 40;
            cur_bg = vt_palette[idx];
        } else if (p >= 100 && p <= 107) {
            int idx = p - 100;
            cur_bg = vt_palette_bright[idx];
        } else if (p == 39) {
            cur_fg = def_fg;
        } else if (p == 49) {
            cur_bg = def_bg;
        }
    }
}

static int vt_handle_char(char c) {
    if (vt_esc_state == 0) {
        if ((unsigned char)c == 0x1B) {
            vt_esc_state = 1;
            return 1;
        }
        return 0;
    }
    if (vt_esc_state == 1) {
        if (c == '[') {
            vt_esc_state = 2;
            vt_param_count = 0;
            vt_param_value = 0;
            vt_param_has_value = 0;
            return 1;
        }
        vt_esc_state = 0;
        return 1;
    }
    if (vt_esc_state == 2) {
        if (c >= '0' && c <= '9') {
            vt_param_value = (vt_param_value * 10) + (c - '0');
            vt_param_has_value = 1;
            return 1;
        }
        if (c == ';') {
            if (vt_param_count < (int)(sizeof(vt_params) / sizeof(vt_params[0]))) {
                vt_params[vt_param_count++] = vt_param_has_value ? vt_param_value : 0;
            }
            vt_param_value = 0;
            vt_param_has_value = 0;
            return 1;
        }
        if (vt_param_has_value || c == 'm') {
            if (vt_param_count < (int)(sizeof(vt_params) / sizeof(vt_params[0]))) {
                vt_params[vt_param_count++] = vt_param_has_value ? vt_param_value : 0;
            }
        }
        if (c == 'm') {
            vt_apply_sgr();
        } else if (c == 'H' || c == 'f') {
            cursor_x = margin_x;
            cursor_y = margin_y;
        } else if (c == 'J') {
            if (vt_param_count == 0 || vt_params[0] == 2) {
                fb_clear();
            }
        } else if (c == 'K') {
            clear_to_eol();
        }
        vt_esc_state = 0;
        return 1;
    }
    vt_esc_state = 0;
    return 1;
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
    if (vt_handle_char(c)) return;
    if (sb_record_enabled) sb_put_char(c);
    if (sb_view_offset > 0 && sb_record_enabled) {
        /* keep output buffered while scrolled back */
        return;
    }
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
    def_fg = fg; def_bg = bg;
    vt_bright = 0;

    /* clear framebuffer to bg color */
    for (uint32_t y = 0; y < fb_height; ++y) clear_row_bg(y);
    sb_recalc_geometry();
    sb_reset();
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
    if (g_fb) {
        sb_recalc_geometry();
        sb_reset();
    }
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

void fb_scrollback_up(uint32_t lines) {
    if (!g_fb || sb_count == 0) return;
    if (lines == 0) lines = 1;
    uint32_t max_off = (sb_count > sb_rows) ? (sb_count - sb_rows) : 0;
    if (max_off == 0) return;
    if (sb_view_offset + lines > max_off) sb_view_offset = max_off;
    else sb_view_offset += lines;
    sb_render_full();
}

void fb_scrollback_down(uint32_t lines) {
    if (!g_fb || sb_count == 0) return;
    if (lines == 0) lines = 1;
    if (sb_view_offset == 0) return;
    if (lines >= sb_view_offset) sb_view_offset = 0;
    else sb_view_offset -= lines;
    sb_render_full();
}

void fb_scrollback_reset(void) {
    if (!g_fb) return;
    if (sb_view_offset == 0) return;
    sb_view_offset = 0;
    sb_render_full();
}

uint32_t fb_scrollback_offset(void) {
    return sb_view_offset;
}

void fb_scrollback_suspend(int suspend) {
    sb_record_enabled = suspend ? 0 : 1;
}
