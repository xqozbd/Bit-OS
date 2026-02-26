#ifndef KERNEL_RNG_H
#define KERNEL_RNG_H

#include <stddef.h>
#include <stdint.h>

void rng_init(void);
void rng_seed(uint64_t seed);
uint64_t rng_next_u64(void);
void rng_fill(void *buf, size_t len);

#endif /* KERNEL_RNG_H */
