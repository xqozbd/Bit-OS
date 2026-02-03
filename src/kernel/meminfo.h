#ifndef MEMINFO_H
#define MEMINFO_H

#include <stdint.h>

uint64_t get_usable_ram_bytes(void);
void format_gb_1dp(uint64_t bytes, uint64_t *gb_int, uint64_t *gb_tenths);

#endif /* MEMINFO_H */
