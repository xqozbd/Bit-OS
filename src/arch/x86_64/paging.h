#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

int paging_init(void);

uint64_t paging_hhdm_offset(void);
uint64_t paging_pml4_phys(void);
int paging_map_4k(uint64_t virt, uint64_t phys, uint64_t flags);

#endif /* PAGING_H */
