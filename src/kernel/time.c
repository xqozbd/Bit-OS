#include "kernel/time.h"

#include "drivers/rtc/cmos.h"
#include "arch/x86_64/timer.h"
#include "lib/log.h"

static uint64_t g_epoch_base = 0;
static uint64_t g_tick_base = 0;
static uint32_t g_tick_hz = 0;
static int g_time_ok = 0;
static uint64_t g_last_alarm_check = 0;

#define TIME_MAX_ALARMS 8
struct time_alarm {
    uint64_t epoch;
    int active;
};

static struct time_alarm g_alarms[TIME_MAX_ALARMS];

static int is_leap_year(int year) {
    return ((year % 4) == 0 && (year % 100) != 0) || ((year % 400) == 0);
}

static uint64_t days_before_year(int year) {
    uint64_t days = 0;
    for (int y = 1970; y < year; ++y) {
        days += is_leap_year(y) ? 366 : 365;
    }
    return days;
}

static uint64_t days_before_month(int year, int month) {
    static const uint8_t mdays[12] = {
        31,28,31,30,31,30,31,31,30,31,30,31
    };
    uint64_t days = 0;
    for (int m = 1; m < month; ++m) {
        if (m == 2 && is_leap_year(year)) days += 29;
        else days += mdays[m - 1];
    }
    return days;
}

static uint64_t rtc_to_epoch(const struct rtc_time *t) {
    uint64_t days = days_before_year((int)t->year);
    days += days_before_month((int)t->year, (int)t->month);
    days += (uint64_t)(t->day - 1);
    uint64_t seconds = days * 86400ull;
    seconds += (uint64_t)t->hour * 3600ull;
    seconds += (uint64_t)t->minute * 60ull;
    seconds += (uint64_t)t->second;
    return seconds;
}

static void epoch_to_rtc(uint64_t epoch, struct rtc_time *out) {
    uint64_t days = epoch / 86400ull;
    uint64_t secs = epoch % 86400ull;
    out->hour = (uint8_t)(secs / 3600ull);
    secs %= 3600ull;
    out->minute = (uint8_t)(secs / 60ull);
    out->second = (uint8_t)(secs % 60ull);

    int year = 1970;
    while (1) {
        uint64_t yd = is_leap_year(year) ? 366 : 365;
        if (days < yd) break;
        days -= yd;
        year++;
    }
    out->year = (uint16_t)year;

    int month = 1;
    while (month <= 12) {
        uint64_t md = 31;
        if (month == 2) md = is_leap_year(year) ? 29 : 28;
        else if (month == 4 || month == 6 || month == 9 || month == 11) md = 30;
        if (days < md) break;
        days -= md;
        month++;
    }
    out->month = (uint8_t)month;
    out->day = (uint8_t)(days + 1);
}

int time_init(void) {
    struct rtc_time rtc;
    int rc = cmos_read_time(&rtc);
    if (rc != 0) {
        g_time_ok = 0;
        log_printf("time: RTC read failed (%d)\n", rc);
        return rc;
    }
    g_epoch_base = rtc_to_epoch(&rtc);
    g_tick_base = timer_uptime_ticks();
    g_tick_hz = timer_pit_hz();
    if (g_tick_hz == 0) g_tick_hz = 100;
    g_time_ok = 1;
    log_printf("time: synced to RTC\n");
    return 0;
}

uint64_t time_now_epoch(void) {
    if (!g_time_ok) return 0;
    uint64_t ticks = timer_uptime_ticks() - g_tick_base;
    return g_epoch_base + (ticks / (uint64_t)g_tick_hz);
}

int time_get_string(char out[20]) {
    if (!out) return -1;
    if (!g_time_ok) return -2;
    uint64_t epoch = time_now_epoch();
    struct rtc_time t;
    epoch_to_rtc(epoch, &t);
    out[0] = (char)('0' + (t.year / 1000) % 10);
    out[1] = (char)('0' + (t.year / 100) % 10);
    out[2] = (char)('0' + (t.year / 10) % 10);
    out[3] = (char)('0' + (t.year / 1) % 10);
    out[4] = '-';
    out[5] = (char)('0' + (t.month / 10));
    out[6] = (char)('0' + (t.month % 10));
    out[7] = '-';
    out[8] = (char)('0' + (t.day / 10));
    out[9] = (char)('0' + (t.day % 10));
    out[10] = ' ';
    out[11] = (char)('0' + (t.hour / 10));
    out[12] = (char)('0' + (t.hour % 10));
    out[13] = ':';
    out[14] = (char)('0' + (t.minute / 10));
    out[15] = (char)('0' + (t.minute % 10));
    out[16] = ':';
    out[17] = (char)('0' + (t.second / 10));
    out[18] = (char)('0' + (t.second % 10));
    out[19] = '\0';
    return 0;
}

int time_alarm_set_epoch(uint64_t epoch) {
    if (!g_time_ok || epoch == 0) return -1;
    for (int i = 0; i < TIME_MAX_ALARMS; ++i) {
        if (!g_alarms[i].active) {
            g_alarms[i].epoch = epoch;
            g_alarms[i].active = 1;
            return i;
        }
    }
    return -1;
}

int time_alarm_set_rel(uint64_t seconds) {
    if (!g_time_ok || seconds == 0) return -1;
    uint64_t now = time_now_epoch();
    if (now == 0) return -1;
    return time_alarm_set_epoch(now + seconds);
}

int time_alarm_clear(int id) {
    if (id < 0 || id >= TIME_MAX_ALARMS) return -1;
    g_alarms[id].active = 0;
    g_alarms[id].epoch = 0;
    return 0;
}

void time_alarm_tick(void) {
    if (!g_time_ok) return;
    uint64_t now = time_now_epoch();
    if (now == 0 || now == g_last_alarm_check) return;
    g_last_alarm_check = now;
    for (int i = 0; i < TIME_MAX_ALARMS; ++i) {
        if (!g_alarms[i].active) continue;
        if (now >= g_alarms[i].epoch) {
            g_alarms[i].active = 0;
            log_printf("alarm: fired id=%d epoch=%u\n", i, (unsigned)g_alarms[i].epoch);
        }
    }
}

void time_alarm_list(void) {
    if (!g_time_ok) {
        log_printf("alarm: time not synced\n");
        return;
    }
    uint64_t now = time_now_epoch();
    for (int i = 0; i < TIME_MAX_ALARMS; ++i) {
        if (!g_alarms[i].active) continue;
        uint64_t epoch = g_alarms[i].epoch;
        log_printf("alarm[%d]: epoch=%u in=%u s\n",
                   i,
                   (unsigned)epoch,
                   (unsigned)((epoch > now) ? (epoch - now) : 0));
    }
}
