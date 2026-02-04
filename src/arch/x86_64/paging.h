#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

int paging_init(void);

uint64_t paging_hhdm_offset(void);
uint64_t paging_pml4_phys(void);
int paging_map_4k(uint64_t virt, uint64_t phys, uint64_t flags);
int paging_map_4k_in_pml4(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags);
int paging_map_user_4k(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags);
uint64_t paging_new_user_pml4(void);
void paging_switch_to(uint64_t pml4_phys);

#endif /* PAGING_H */
