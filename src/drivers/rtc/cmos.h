#ifndef CMOS_H
#define CMOS_H

#include <stdint.h>

struct rtc_time {
    uint8_t second;
    uint8_t minute;
    uint8_t hour;
    uint8_t day;
    uint8_t month;
    uint16_t year;
};

int cmos_read_time(struct rtc_time *out);

#endif /* CMOS_H */
