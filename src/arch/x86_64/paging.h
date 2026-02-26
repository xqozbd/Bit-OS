#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

#define PTE_NX (1ull << 63)

int paging_init(void);

uint64_t paging_hhdm_offset(void);
uint64_t paging_pml4_phys(void);
int paging_map_4k(uint64_t virt, uint64_t phys, uint64_t flags);
int paging_map_4k_in_pml4(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags);
int paging_map_user_4k(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags);
void *paging_map_mmio(uint64_t phys, uint64_t size);
uint64_t paging_unmap_4k(uint64_t virt);
uint64_t paging_unmap_user_4k(uint64_t pml4_phys, uint64_t virt);
uint64_t paging_new_user_pml4(void);
uint64_t paging_clone_user_pml4(uint64_t src_pml4_phys);
void paging_switch_to(uint64_t pml4_phys);
int paging_handle_cow(uint64_t fault_addr);

struct user_addr_space {
    uint64_t heap_base;
    uint64_t heap_limit;
    uint64_t stack_top;
    uint64_t stack_size;
    uint64_t mmap_base;
    uint64_t mmap_limit;
};

void paging_user_layout_default(struct user_addr_space *out);
uint64_t paging_aslr_slide(uint64_t max, uint64_t align);

#endif /* PAGING_H */
