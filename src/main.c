#include <stdbool.h>
#include <stdint.h>

#include "boot_requests.h"
#include "bootinfo.h"
#include "cmos.h"
#include "cpu.h"
#include "fb_printf.h"
#include "idt.h"
#include "log.h"
#include "paging.h"
#include "pmm.h"

static void u2(char *dst, unsigned v) {
    dst[0] = (char)('0' + (v / 10) % 10);
    dst[1] = (char)('0' + (v % 10));
}

static void format_rtc(char *out, unsigned year, unsigned mon, unsigned day,
                       unsigned hour, unsigned min, unsigned sec) {
    out[0] = (char)('0' + (year / 1000) % 10);
    out[1] = (char)('0' + (year / 100) % 10);
    out[2] = (char)('0' + (year / 10) % 10);
    out[3] = (char)('0' + (year % 10));
    out[4] = '-';
    u2(out + 5, mon);
    out[7] = '-';
    u2(out + 8, day);
    out[10] = ' ';
    u2(out + 11, hour);
    out[13] = ':';
    u2(out + 14, min);
    out[16] = ':';
    u2(out + 17, sec);
    out[19] = '\0';
}

void kmain(void) {
    log_init_serial();
    cpu_enable_sse();
    idt_init();

    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        halt_forever();
    }

    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        halt_forever();
    }

    pmm_init();
    paging_init();

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];
    fb_init(fb, 0xE6E6E6, 0x0B0F14);
    fb_set_layout_ex(3, 4, 24, 24, 4, 2);
    log_set_fb_ready(1);

    log_printf("Hello BitOS!\n");
    log_printf("Width: %u Height: %u Pitch: %u BPP: %u\n",
               (unsigned)fb->width, (unsigned)fb->height,
               (unsigned)fb->pitch, (unsigned)fb->bpp);

    struct rtc_time rtc;
    int rtc_rc = cmos_read_time(&rtc);
    if (rtc_rc == 0) {
        char rtc_buf[20];
        format_rtc(rtc_buf, (unsigned)rtc.year, (unsigned)rtc.month, (unsigned)rtc.day,
                   (unsigned)rtc.hour, (unsigned)rtc.minute, (unsigned)rtc.second);
        log_printf("RTC: %s\n", rtc_buf);
    } else {
        log_printf("RTC: unavailable (err=%d)\n", rtc_rc);
    }

    bootinfo_log();
    systeminfo_log();
    
    halt_forever();
}
