#ifndef KERNEL_TIME_H
#define KERNEL_TIME_H

#include <stdint.h>

int time_init(void);
uint64_t time_now_epoch(void);
uint64_t time_now_epoch_ns(void);
uint64_t time_now_local_epoch(void);
uint64_t time_monotonic_ns(void);
int time_get_string(char out[20]);
void time_set_tz_offset_minutes(int minutes);
int time_get_tz_offset_minutes(void);
int time_alarm_set_epoch(uint64_t epoch);
int time_alarm_set_rel(uint64_t seconds);
int time_alarm_clear(int id);
void time_alarm_tick(void);
void time_alarm_list(void);

#endif /* KERNEL_TIME_H */
