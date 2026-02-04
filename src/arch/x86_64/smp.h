#ifndef SMP_H
#define SMP_H

#include <stdint.h>

void smp_init(void);
int smp_is_initialized(void);
uint32_t smp_cpu_count(void);
uint32_t smp_online_count(void);
uint32_t smp_bsp_index(void);

struct smp_percpu {
    uint32_t cpu_index;
    uint32_t lapic_id;
    uint8_t is_bsp;
    uintptr_t stack_top;
};

struct smp_percpu *smp_percpu(uint32_t cpu_index);

#endif /* SMP_H */
