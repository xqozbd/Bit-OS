#include "drivers/rtc/cmos.h"
#include "drivers/rtc/rtc_util.h"

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

int rtc_get_string(char out[20]) {
    struct rtc_time rtc;
    int rc = cmos_read_time(&rtc);
    if (rc != 0) return rc;
    format_rtc(out, (unsigned)rtc.year, (unsigned)rtc.month, (unsigned)rtc.day,
               (unsigned)rtc.hour, (unsigned)rtc.minute, (unsigned)rtc.second);
    return 0;
}
