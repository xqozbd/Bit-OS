#include "boot/boot_screen.h"

#include "boot/bootinfo.h"
#include "drivers/rtc/rtc_util.h"
#include "drivers/net/pcnet.h"
#include "drivers/video/fb_printf.h"

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
}

void boot_screen_set_status(const char *status) {
    if (!status) status = "";
    uint32_t fg = 0, bg = 0;
    fb_get_colors(&fg, &bg);
    fb_set_cursor_px(g_status_x, g_status_y);
    fb_set_colors(0xA0A6AD, bg);
    fb_puts("Loading: ");
    fb_puts(status);
    fb_puts("                                ");
    fb_set_colors(fg, bg);
}
