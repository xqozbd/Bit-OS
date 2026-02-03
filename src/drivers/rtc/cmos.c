#include <stdint.h>
#include <stdbool.h>

#include "lib/compat.h"
#include "drivers/rtc/cmos.h"

#define CMOS_ADDR 0x70
#define CMOS_DATA 0x71

#define CMOS_REG_SECONDS 0x00
#define CMOS_REG_MINUTES 0x02
#define CMOS_REG_HOURS   0x04
#define CMOS_REG_DAY     0x07
#define CMOS_REG_MONTH   0x08
#define CMOS_REG_YEAR    0x09
#define CMOS_REG_A       0x0A
#define CMOS_REG_B       0x0B
#define CMOS_REG_D       0x0D

#ifndef CURRENT_YEAR
#define CURRENT_YEAR 2026
#endif

#if defined(__GNUC__) || defined(__clang__)
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
#else
static inline void outb(uint16_t port, uint8_t val) { (void)port; (void)val; }
static inline uint8_t inb(uint16_t port) { (void)port; return 0; }
#endif

static inline uint8_t cmos_read(uint8_t reg) {
    outb(CMOS_ADDR, reg);
    return inb(CMOS_DATA);
}

static inline int cmos_updating(void) {
    return cmos_read(CMOS_REG_A) & 0x80;
}

static inline uint8_t bcd_to_bin(uint8_t v) {
    return (uint8_t)((v & 0x0F) + ((v >> 4) * 10));
}

int cmos_read_time(struct rtc_time *out) {
    if (!out) return -1;

    uint8_t reg_d = cmos_read(CMOS_REG_D);
    if ((reg_d & 0x80) == 0) {
        return -2; /* battery bad / time invalid */
    }

    uint8_t sec1, min1, hr1, day1, mon1, yr1;
    uint8_t sec2, min2, hr2, day2, mon2, yr2;
    uint8_t reg_b;

    do {
        while (cmos_updating()) {}
        sec1 = cmos_read(CMOS_REG_SECONDS);
        min1 = cmos_read(CMOS_REG_MINUTES);
        hr1  = cmos_read(CMOS_REG_HOURS);
        day1 = cmos_read(CMOS_REG_DAY);
        mon1 = cmos_read(CMOS_REG_MONTH);
        yr1  = cmos_read(CMOS_REG_YEAR);
        reg_b = cmos_read(CMOS_REG_B);

        while (cmos_updating()) {}
        sec2 = cmos_read(CMOS_REG_SECONDS);
        min2 = cmos_read(CMOS_REG_MINUTES);
        hr2  = cmos_read(CMOS_REG_HOURS);
        day2 = cmos_read(CMOS_REG_DAY);
        mon2 = cmos_read(CMOS_REG_MONTH);
        yr2  = cmos_read(CMOS_REG_YEAR);
    } while (sec1 != sec2 || min1 != min2 || hr1 != hr2 ||
             day1 != day2 || mon1 != mon2 || yr1 != yr2);

    int is_bcd = ((reg_b & 0x04) == 0);
    int is_12h = ((reg_b & 0x02) == 0);

    if (is_bcd) {
        sec1 = bcd_to_bin(sec1);
        min1 = bcd_to_bin(min1);
        hr1  = bcd_to_bin(hr1 & 0x7F);
        day1 = bcd_to_bin(day1);
        mon1 = bcd_to_bin(mon1);
        yr1  = bcd_to_bin(yr1);
    }

    if (is_12h) {
        int pm = (hr1 & 0x80) != 0;
        hr1 &= 0x7F;
        if (pm && hr1 < 12) hr1 = (uint8_t)(hr1 + 12);
        if (!pm && hr1 == 12) hr1 = 0;
    }

    int full_year = (CURRENT_YEAR / 100) * 100 + yr1;
    if (full_year < CURRENT_YEAR) full_year += 100;

    out->second = sec1;
    out->minute = min1;
    out->hour   = hr1;
    out->day    = day1;
    out->month  = mon1;
    out->year   = (uint16_t)full_year;

    return 0;
}
