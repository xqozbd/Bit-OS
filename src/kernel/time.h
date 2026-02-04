#ifndef KERNEL_TIME_H
#define KERNEL_TIME_H

#include <stdint.h>

int time_init(void);
uint64_t time_now_epoch(void);
int time_get_string(char out[20]);

#endif /* KERNEL_TIME_H */
