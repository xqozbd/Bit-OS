#ifndef KERNEL_SWAP_H
#define KERNEL_SWAP_H

#include <stdint.h>

int swap_init(const char *path, uint64_t size_bytes);
int swap_enabled(void);
int swap_alloc(uint32_t *out_slot);
void swap_free(uint32_t slot);
int swap_write(uint32_t slot, const void *buf);
int swap_read(uint32_t slot, void *buf);
uint64_t swap_total_slots(void);

#endif /* KERNEL_SWAP_H */
