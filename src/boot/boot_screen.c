#include "boot/boot_screen.h"

#include "boot/bootinfo.h"
#include "drivers/rtc/rtc_util.h"
#include "drivers/net/pcnet.h"
#include "drivers/video/fb_printf.h"
#include "kernel/time.h"

static uint32_t g_status_y = 0;
static uint32_t g_status_x = 0;

void boot_screen_print_loading(void) {
    fb_printf("BitOS boot screen\n");
    fb_printf("Loading modules...\n");
    g_status_x = fb_margin_x();
    g_status_y = fb_margin_y() + fb_line_height() * 2;
    boot_screen_set_status("init");
}

void boot_screen_print_main(void) {
    fb_printf("Hello BitOS!\n");

    char time_buf[20];
    int rc = time_get_string(time_buf);
    if (rc == 0) {
        fb_printf("Time: %s\n", time_buf);
    } else {
        char rtc_buf[20];
        int rrc = rtc_get_string(rtc_buf);
        if (rrc == 0) fb_printf("RTC: %s\n", rtc_buf);
        else fb_printf("RTC: unavailable (err=%d)\n", rrc);
    }

    bootinfo_log();
    systeminfo_log();
    pcnet_log_status();
}

void boot_screen_print_debug(void) {
    fb_set_cursor_px(fb_margin_x(), fb_margin_y() + fb_line_height() * 2);
    fb_printf("BitOS Debug Info\n");
    fb_printf("================\n");

    char rtc_buf[20];
    int rc = rtc_get_string(rtc_buf);
    if (rc == 0) {
        fb_printf("RTC: %s\n", rtc_buf);
    } else {
        fb_printf("RTC: unavailable (err=%d)\n", rc);
    }

    bootinfo_log();
    systeminfo_log();
    pcnet_log_status();
    fb_printf("\n");
}

void boot_screen_set_status(const char *status) {
    if (!status) status = "";
    uint32_t fg = 0, bg = 0;
    fb_get_colors(&fg, &bg);
    uint32_t fb_w = 0, fb_h = 0;
    fb_get_dimensions(&fb_w, &fb_h);
    uint32_t line_h = fb_line_height();
    if (g_status_y < fb_h) {
        uint32_t clear_h = line_h;
        if (g_status_y + clear_h > fb_h) clear_h = fb_h - g_status_y;
        if (fb_w > g_status_x && clear_h > 0) {
            fb_draw_rect(g_status_x, g_status_y, fb_w - g_status_x, clear_h, bg);
        }
    }
    fb_set_cursor_px(g_status_x, g_status_y);
    fb_set_colors(0xA0A6AD, bg);
    fb_puts("Loading: ");
    fb_puts(status);
    fb_set_colors(fg, bg);
}
