#include <stddef.h>
#include <stdint.h>

#include "boot/boot_requests.h"
#include "boot/limine.h"
#include "lib/log.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "sys/boot_params.h"
#include "kernel/pmm.h"

/* From memutils.c */
void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

extern char __kernel_start;
extern char __kernel_end;

enum {
    PAGE_SIZE = 0x1000ull,
    PAGE_2M   = 0x200000ull
};

enum {
    PTE_P  = 1ull << 0,
    PTE_RW = 1ull << 1,
    PTE_US = 1ull << 2,
    PTE_PS = 1ull << 7,
    PTE_COW = 1ull << 9
};

static uint64_t g_hhdm_offset = 0;
static uint64_t *g_pml4 = 0;
static uint64_t g_pml4_phys = 0;
static uint64_t g_aslr_state = 0;

static uint64_t *walk_pt(uint64_t pml4_phys, uint64_t virt);

enum {
    USER_HEAP_BASE  = 0x0000000040000000ull,
    USER_HEAP_LIMIT = 0x0000000080000000ull,
    USER_STACK_TOP  = 0x0000000070000000ull,
    USER_STACK_SIZE = 0x0000000000020000ull,
    USER_MMAP_BASE  = 0x0000000080000000ull,
    USER_MMAP_LIMIT = 0x00000000F0000000ull
};

static inline uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static inline uint64_t rdtsc_now(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo = 0, hi = 0;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static void seed_aslr_state(void) {
    uint64_t seed = rdtsc_now();
    seed ^= (uint64_t)(uintptr_t)&g_aslr_state;
    seed ^= g_pml4_phys;
    seed ^= g_hhdm_offset;
    if (seed == 0) seed = 0x9e3779b97f4a7c15ull;
    g_aslr_state = seed;
}

static uint64_t rand_u64(void) {
    if (g_aslr_state == 0) seed_aslr_state();
    uint64_t x = g_aslr_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_aslr_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

uint64_t paging_aslr_slide(uint64_t max, uint64_t align) {
    if (align == 0) align = PAGE_SIZE;
    if (max < align) return 0;
    uint64_t slots = max / align;
    if (slots == 0) return 0;
    uint64_t pick = rand_u64() % slots;
    return pick * align;
}

static uint64_t alloc_table(uint64_t *out_phys) {
    uint64_t phys = pmm_alloc_frame();
    if (phys == 0) return 0;
    uint64_t virt = g_hhdm_offset + phys;
    memset((void *)(uintptr_t)virt, 0, PAGE_SIZE);
    *out_phys = phys;
    return virt;
}
// man page these fucking balls. this shit sucks -xqozbd
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

int paging_map_4k(uint64_t virt, uint64_t phys, uint64_t flags) {
    if (!g_pml4) return -1;
    map_4k(g_pml4, virt, phys, flags);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("invlpg (%0)" : : "r"(virt) : "memory");
#else
    (void)virt;
#endif
    return 0;
}

int paging_map_4k_in_pml4(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    if (pml4_phys == 0 || g_hhdm_offset == 0) return -1;
    uint64_t *pml4 = (uint64_t *)(uintptr_t)(g_hhdm_offset + pml4_phys);
    map_4k(pml4, virt, phys, flags);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("invlpg (%0)" : : "r"(virt) : "memory");
#else
    (void)virt;
#endif
    return 0;
}

int paging_map_user_4k(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    return paging_map_4k_in_pml4(pml4_phys, virt, phys, flags | PTE_US);
}

uint64_t paging_unmap_user_4k(uint64_t pml4_phys, uint64_t virt) {
    if (pml4_phys == 0 || g_hhdm_offset == 0) return 0;
    uint64_t *pte = walk_pt(pml4_phys, virt);
    if (!pte) return 0;
    uint64_t ent = *pte;
    if ((ent & PTE_P) == 0) return 0;
    *pte = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("invlpg (%0)" : : "r"(virt) : "memory");
#else
    (void)virt;
#endif
    return ent & 0x000ffffffffff000ull;
}

uint64_t paging_unmap_4k(uint64_t virt) {
    if (!g_pml4 || g_hhdm_offset == 0) return 0;
    uint64_t *pte = walk_pt(g_pml4_phys, virt);
    if (!pte) return 0;
    uint64_t ent = *pte;
    if ((ent & PTE_P) == 0) return 0;
    *pte = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("invlpg (%0)" : : "r"(virt) : "memory");
#else
    (void)virt;
#endif
    return ent & 0x000ffffffffff000ull;
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

uint64_t paging_pml4_phys(void) {
    return g_pml4_phys;
}

void *paging_map_mmio(uint64_t phys, uint64_t size) {
    if (!g_pml4 || g_hhdm_offset == 0) return NULL;
    if (size == 0) size = PAGE_SIZE;
    uint64_t start = phys & ~(PAGE_SIZE - 1);
    uint64_t end = align_up_u64(phys + size, PAGE_SIZE);
    for (uint64_t p = start; p < end; p += PAGE_SIZE) {
        paging_map_4k(g_hhdm_offset + p, p, PTE_NX);
    }
    return (void *)(uintptr_t)(g_hhdm_offset + phys);
}

void paging_switch_to(uint64_t pml4_phys) {
    if (pml4_phys == 0) return;
    load_cr3(pml4_phys);
}

uint64_t paging_new_user_pml4(void) {
    if (!g_pml4) return 0;
    uint64_t new_phys = 0;
    uint64_t new_virt = alloc_table(&new_phys);
    if (new_virt == 0) return 0;
    uint64_t *new_pml4 = (uint64_t *)(uintptr_t)new_virt;
    for (uint32_t i = 256; i < 512; ++i) {
        new_pml4[i] = g_pml4[i];
    }
    return new_phys;
}

static uint64_t clone_table(uint64_t src_entry, int level) {
    if ((src_entry & PTE_P) == 0) return 0;
    if (level == 1 && (src_entry & PTE_PS)) {
        /* 2MiB page at PD level, share mapping. */
        return src_entry;
    }

    uint64_t src_phys = src_entry & 0x000ffffffffff000ull;
    uint64_t *src_tbl = (uint64_t *)(uintptr_t)(g_hhdm_offset + src_phys);
    uint64_t new_phys = 0;
    uint64_t new_virt = alloc_table(&new_phys);
    if (new_virt == 0) return 0;
    uint64_t *dst_tbl = (uint64_t *)(uintptr_t)new_virt;

    for (uint32_t i = 0; i < 512; ++i) {
        uint64_t ent = src_tbl[i];
        if ((ent & PTE_P) == 0) {
            dst_tbl[i] = 0;
            continue;
        }
        if (level == 1 && (ent & PTE_PS)) {
            dst_tbl[i] = ent;
            continue;
        }
        if (level == 0) {
            /* PT level: mark COW and clear write in both tables */
            uint64_t phys = ent & 0x000ffffffffff000ull;
            uint64_t cow_ent = (ent | PTE_COW) & ~PTE_RW;
            src_tbl[i] = cow_ent;
            dst_tbl[i] = cow_ent;
            pmm_inc_ref(phys);
            continue;
        }
        uint64_t child = clone_table(ent, level - 1);
        if (child == 0) {
            dst_tbl[i] = 0;
            continue;
        }
        dst_tbl[i] = (child & 0x000ffffffffff000ull) | (ent & 0xFFF);
    }
    return new_phys | (src_entry & 0xFFF);
}

uint64_t paging_clone_user_pml4(uint64_t src_pml4_phys) {
    if (src_pml4_phys == 0 || g_hhdm_offset == 0) return 0;
    uint64_t *src = (uint64_t *)(uintptr_t)(g_hhdm_offset + src_pml4_phys);

    uint64_t new_phys = 0;
    uint64_t new_virt = alloc_table(&new_phys);
    if (new_virt == 0) return 0;
    uint64_t *dst = (uint64_t *)(uintptr_t)new_virt;

    /* Clone user half (0..255), copy kernel half (256..511). */
    for (uint32_t i = 0; i < 256; ++i) {
        uint64_t ent = src[i];
        if ((ent & PTE_P) == 0) {
            dst[i] = 0;
            continue;
        }
        uint64_t child = clone_table(ent, 2);
        if (child == 0) {
            dst[i] = 0;
            continue;
        }
        dst[i] = (child & 0x000ffffffffff000ull) | (ent & 0xFFF);
    }
    for (uint32_t i = 256; i < 512; ++i) {
        dst[i] = src[i];
    }
    return new_phys;
}

void paging_user_layout_default(struct user_addr_space *out) {
    if (!out) return;
    uint64_t heap_slide = paging_aslr_slide(0x02000000ull, PAGE_SIZE);
    uint64_t stack_slide = paging_aslr_slide(0x01000000ull, PAGE_SIZE);
    uint64_t mmap_slide = paging_aslr_slide(0x04000000ull, PAGE_SIZE);
    out->heap_base = USER_HEAP_BASE + heap_slide;
    out->heap_limit = USER_HEAP_LIMIT;
    out->stack_top = USER_STACK_TOP - stack_slide;
    out->stack_size = USER_STACK_SIZE;
    out->mmap_base = USER_MMAP_BASE + mmap_slide;
    out->mmap_limit = USER_MMAP_LIMIT;
}

static uint64_t *walk_pt(uint64_t pml4_phys, uint64_t virt) {
    uint64_t pml4_i = (virt >> 39) & 0x1FF;
    uint64_t pdpt_i = (virt >> 30) & 0x1FF;
    uint64_t pd_i   = (virt >> 21) & 0x1FF;
    uint64_t pt_i   = (virt >> 12) & 0x1FF;

    uint64_t *pml4 = (uint64_t *)(uintptr_t)(g_hhdm_offset + pml4_phys);
    if ((pml4[pml4_i] & PTE_P) == 0) return NULL;
    uint64_t *pdpt = table_from_entry(pml4[pml4_i]);
    if ((pdpt[pdpt_i] & PTE_P) == 0) return NULL;
    if (pdpt[pdpt_i] & PTE_PS) return NULL;
    uint64_t *pd = table_from_entry(pdpt[pdpt_i]);
    if ((pd[pd_i] & PTE_P) == 0) return NULL;
    if (pd[pd_i] & PTE_PS) return NULL;
    uint64_t *pt = table_from_entry(pd[pd_i]);
    return &pt[pt_i];
}

int paging_handle_cow(uint64_t fault_addr) {
    if (!g_pml4 || g_hhdm_offset == 0) return 0;
    uint64_t *pte = walk_pt(g_pml4_phys, fault_addr);
    if (!pte) return 0;
    uint64_t ent = *pte;
    if ((ent & PTE_P) == 0) return 0;
    if ((ent & PTE_COW) == 0) return 0;

    uint64_t phys = ent & 0x000ffffffffff000ull;
    uint16_t refs = pmm_refcount(phys);
    if (refs <= 1) {
        ent = (ent | PTE_RW) & ~PTE_COW;
        *pte = ent;
    } else {
        uint64_t new_phys = pmm_alloc_frame();
        if (new_phys == 0) return 0;
        void *src = (void *)(uintptr_t)(g_hhdm_offset + phys);
        void *dst = (void *)(uintptr_t)(g_hhdm_offset + new_phys);
        memcpy(dst, src, PMM_PAGE_SIZE);
        pmm_dec_ref(phys);
        uint64_t flags = ent & 0xFFF;
        if (ent & PTE_NX) flags |= PTE_NX;
        ent = (new_phys & 0x000ffffffffff000ull) | flags;
        ent |= PTE_RW;
        ent &= ~PTE_COW;
        *pte = ent;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("invlpg (%0)" : : "r"(fault_addr) : "memory");
#endif
    return 1;
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

    uint64_t pml4_virt = alloc_table(&g_pml4_phys);
    if (pml4_virt == 0) {
        log_printf("Paging: failed to allocate PML4\n");
        return -1;
    }
    uint64_t *pml4 = (uint64_t *)(uintptr_t)pml4_virt;
    g_pml4 = pml4;

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

    const char *nx_param = boot_param_get("nx");
    int nx_enable = 0;
    if (nx_param && nx_param[0] == 'o' && nx_param[1] == 'n' && nx_param[2] == '\0') {
        nx_enable = 1;
    }
    if (nx_enable) {
        uint32_t ext_edx = cpu_get_ext_feature_edx();
        if (ext_edx & (1u << 20)) {
            uint64_t efer = cpu_read_msr(0xC0000080u);
            if ((efer & (1ull << 11)) == 0) {
                cpu_write_msr(0xC0000080u, efer | (1ull << 11));
            }
            log_printf("Paging: NX enabled\n");
        } else {
            log_printf("Paging: NX not supported\n");
        }
    } else {
        log_printf("Paging: NX disabled (nx=on to enable)\n");
    }

    load_cr3(g_pml4_phys);
    log_printf("Paging: enabled (PML4=0x%x)\n", (unsigned)g_pml4_phys);
    return 0;
}
