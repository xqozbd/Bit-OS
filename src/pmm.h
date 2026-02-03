#ifndef PMM_H
#define PMM_H

#include <stdint.h>

#define PMM_PAGE_SIZE 4096ull

void pmm_init(void);
uint64_t pmm_alloc_frame(void);
void pmm_free_frame(uint64_t phys_addr);

uint64_t pmm_total_frames(void);
uint64_t pmm_used_frames(void);
uint64_t pmm_free_frames(void);

#endif /* PMM_H */
