#include "boot/boot_screen.h"

#include "boot/bootinfo.h"
#include "lib/log.h"
#include "drivers/rtc/rtc_util.h"

void boot_screen_print(void) {
    log_printf("Hello BitOS!\n");

    char rtc_buf[20];
    int rc = rtc_get_string(rtc_buf);
    if (rc == 0) {
        log_printf("RTC: %s\n", rtc_buf);
    } else {
        log_printf("RTC: unavailable (err=%d)\n", rc);
    }

    bootinfo_log();
    systeminfo_log();
}
