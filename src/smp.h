#ifndef SMP_H
#define SMP_H

#include <stdint.h>

void smp_init(void);
int smp_is_initialized(void);
uint32_t smp_cpu_count(void);
uint32_t smp_online_count(void);

#endif /* SMP_H */
