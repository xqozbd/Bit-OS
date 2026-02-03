#include "drivers/video/banner.h"

#include "drivers/video/fb_printf.h"
#include "lib/log.h"
#include "lib/version.h"

static struct limine_framebuffer *g_fb = 0;
static uint32_t g_banner_h = 0;

void banner_init(struct limine_framebuffer *fb) {
    g_fb = fb;
}

uint32_t banner_height(void) {
    return g_banner_h;
}

void banner_draw(void) {
    if (!g_fb) return;
    uint32_t banner_bg = 0x1C2533;
    uint32_t banner_fg = 0xE6E6E6;
    uint32_t line_h = fb_line_height();
    uint32_t banner_h = line_h + 10;
    uint32_t top_pad = 12;
    uint32_t y_text = (banner_h - line_h) / 2 + 2;
    uint32_t gap = 6;
    g_banner_h = banner_h + top_pad + gap;

    fb_draw_rect(0, top_pad, (uint32_t)g_fb->width, banner_h, banner_bg);
    fb_set_colors(banner_fg, banner_bg);
    fb_set_cursor_px(fb_margin_x(), top_pad + y_text);
    log_printf("BitOS v%s  |  build %s %s", BITOS_VERSION, __DATE__, __TIME__);

    fb_set_colors(0xE6E6E6, 0x0B0F14);
    fb_set_cursor_px(fb_margin_x(), fb_margin_y() + g_banner_h);
}
