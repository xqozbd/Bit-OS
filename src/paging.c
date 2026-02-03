#include <stddef.h>
#include <stdint.h>

#include "boot_requests.h"
#include "limine.h"
#include "log.h"
#include "paging.h"
#include "pmm.h"

/* From memutils.c */
void *memset(void *s, int c, size_t n);

extern char __kernel_start;
extern char __kernel_end;

enum {
    PAGE_SIZE = 0x1000ull,
    PAGE_2M   = 0x200000ull
};

enum {
    PTE_P  = 1ull << 0,
    PTE_RW = 1ull << 1,
    PTE_PS = 1ull << 7
};

static uint64_t g_hhdm_offset = 0;

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static uint64_t alloc_table(uint64_t *out_phys) {
    uint64_t phys = pmm_alloc_frame();
    if (phys == 0) return 0;
    uint64_t virt = g_hhdm_offset + phys;
    memset((void *)(uintptr_t)virt, 0, PAGE_SIZE);
    *out_phys = phys;
    return virt;
}

static uint64_t *table_from_entry(uint64_t entry) {
    uint64_t phys = entry & 0x000ffffffffff000ull;
    return (uint64_t *)(uintptr_t)(g_hhdm_offset + phys);
}

static void map_2m(uint64_t *pml4, uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t pml4_i = (virt >> 39) & 0x1FF;
    uint64_t pdpt_i = (virt >> 30) & 0x1FF;
    uint64_t pd_i   = (virt >> 21) & 0x1FF;

    if ((pml4[pml4_i] & PTE_P) == 0) {
        uint64_t phys_new = 0;
        uint64_t virt_new = alloc_table(&phys_new);
        if (virt_new == 0) return;
        pml4[pml4_i] = phys_new | PTE_P | PTE_RW;
    }
    uint64_t *pdpt = table_from_entry(pml4[pml4_i]);
    if ((pdpt[pdpt_i] & PTE_P) == 0) {
        uint64_t phys_new = 0;
        uint64_t virt_new = alloc_table(&phys_new);
        if (virt_new == 0) return;
        pdpt[pdpt_i] = phys_new | PTE_P | PTE_RW;
    }
    uint64_t *pd = table_from_entry(pdpt[pdpt_i]);
    pd[pd_i] = (phys & 0x000fffffe00000ull) | flags | PTE_P | PTE_RW | PTE_PS;
}

static void map_4k(uint64_t *pml4, uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t pml4_i = (virt >> 39) & 0x1FF;
    uint64_t pdpt_i = (virt >> 30) & 0x1FF;
    uint64_t pd_i   = (virt >> 21) & 0x1FF;
    uint64_t pt_i   = (virt >> 12) & 0x1FF;

    if ((pml4[pml4_i] & PTE_P) == 0) {
        uint64_t phys_new = 0;
        uint64_t virt_new = alloc_table(&phys_new);
        if (virt_new == 0) return;
        pml4[pml4_i] = phys_new | PTE_P | PTE_RW;
    }
    uint64_t *pdpt = table_from_entry(pml4[pml4_i]);
    if ((pdpt[pdpt_i] & PTE_P) == 0) {
        uint64_t phys_new = 0;
        uint64_t virt_new = alloc_table(&phys_new);
        if (virt_new == 0) return;
        pdpt[pdpt_i] = phys_new | PTE_P | PTE_RW;
    }
    uint64_t *pd = table_from_entry(pdpt[pdpt_i]);
    if ((pd[pd_i] & PTE_P) == 0 || (pd[pd_i] & PTE_PS)) {
        uint64_t phys_new = 0;
        uint64_t virt_new = alloc_table(&phys_new);
        if (virt_new == 0) return;
        pd[pd_i] = phys_new | PTE_P | PTE_RW;
    }
    uint64_t *pt = table_from_entry(pd[pd_i]);
    pt[pt_i] = (phys & 0x000ffffffffff000ull) | flags | PTE_P | PTE_RW;
}

static inline void load_cr3(uint64_t phys) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("mov %0, %%cr3" : : "r"(phys) : "memory");
#else
    (void)phys;
#endif
}

uint64_t paging_hhdm_offset(void) {
    return g_hhdm_offset;
}

int paging_init(void) {
    if (!memmap_request.response || !hhdm_request.response || !exec_addr_request.response) {
        log_printf("Paging: missing Limine response(s)\n");
        return -1;
    }

    g_hhdm_offset = hhdm_request.response->offset;
    if ((g_hhdm_offset & (PAGE_2M - 1)) != 0) {
        log_printf("Paging: HHDM not 2MiB aligned (0x%x)\n", (unsigned)g_hhdm_offset);
    }

    /* Compute max physical address from memmap. */
    uint64_t max_phys = 0;
    struct limine_memmap_response *resp = memmap_request.response;
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (!e) continue;
        uint64_t end = e->base + e->length;
        if (end > max_phys) max_phys = end;
    }
    max_phys = align_up_u64(max_phys, PAGE_2M);

    uint64_t pml4_phys = 0;
    uint64_t pml4_virt = alloc_table(&pml4_phys);
    if (pml4_virt == 0) {
        log_printf("Paging: failed to allocate PML4\n");
        return -1;
    }
    uint64_t *pml4 = (uint64_t *)(uintptr_t)pml4_virt;

    /* Identity map low memory and map HHDM using 2MiB pages. */
    for (uint64_t addr = 0; addr < max_phys; addr += PAGE_2M) {
        map_2m(pml4, addr, addr, 0);
        map_2m(pml4, g_hhdm_offset + addr, addr, 0);
    }

    /* Map kernel higher-half region using 4KiB pages. */
    uint64_t virt_base = (uint64_t)exec_addr_request.response->virtual_base;
    uint64_t phys_base = (uint64_t)exec_addr_request.response->physical_base;
    uint64_t kern_start = (uint64_t)(uintptr_t)&__kernel_start;
    uint64_t kern_end = (uint64_t)(uintptr_t)&__kernel_end;
    uint64_t kern_size = align_up_u64(kern_end - kern_start, PAGE_SIZE);
    uint64_t kern_phys_start = phys_base + (kern_start - virt_base);
    for (uint64_t off = 0; off < kern_size; off += PAGE_SIZE) {
        map_4k(pml4, kern_start + off, kern_phys_start + off, 0);
    }

    load_cr3(pml4_phys);
    log_printf("Paging: enabled (PML4=0x%x)\n", (unsigned)pml4_phys);
    return 0;
}
