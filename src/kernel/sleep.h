#ifndef KERNEL_SLEEP_H
#define KERNEL_SLEEP_H

#include <stdint.h>

void sleep_init(void);
void sleep_tick(void);
void sleep_ticks(uint64_t ticks);
void sleep_ms(uint64_t ms);

#endif /* KERNEL_SLEEP_H */
