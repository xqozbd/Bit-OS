#ifndef KERNEL_TIME_H
#define KERNEL_TIME_H

#include <stdint.h>

int time_init(void);
uint64_t time_now_epoch(void);
int time_get_string(char out[20]);
int time_alarm_set_epoch(uint64_t epoch);
int time_alarm_set_rel(uint64_t seconds);
int time_alarm_clear(int id);
void time_alarm_tick(void);
void time_alarm_list(void);

#endif /* KERNEL_TIME_H */
