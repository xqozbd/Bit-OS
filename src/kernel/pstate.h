#ifndef KERNEL_PSTATE_H
#define KERNEL_PSTATE_H

#include <stdint.h>

int pstate_init(void);
int pstate_set(uint32_t index);
uint32_t pstate_count(void);

#endif /* KERNEL_PSTATE_H */
