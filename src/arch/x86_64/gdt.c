#include "arch/x86_64/gdt.h"

#include <stdint.h>

#include "lib/compat.h"

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t gran;
    uint8_t base_high;
    uint32_t base_upper;
    uint32_t reserved;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct tss64 {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb_offset;
} __attribute__((packed));

static struct {
    struct gdt_entry gdt[5];
    struct gdt_tss_entry tss_desc;
} gdt_table;

static struct tss64 g_tss;

static void set_gdt_entry(struct gdt_entry *e, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    e->limit_low = (uint16_t)(limit & 0xFFFFu);
    e->base_low = (uint16_t)(base & 0xFFFFu);
    e->base_mid = (uint8_t)((base >> 16) & 0xFFu);
    e->access = access;
    e->gran = (uint8_t)(((limit >> 16) & 0x0Fu) | (gran & 0xF0u));
    e->base_high = (uint8_t)((base >> 24) & 0xFFu);
}

static void set_tss_desc(struct gdt_tss_entry *e, uint64_t base, uint32_t limit) {
    e->limit_low = (uint16_t)(limit & 0xFFFFu);
    e->base_low = (uint16_t)(base & 0xFFFFu);
    e->base_mid = (uint8_t)((base >> 16) & 0xFFu);
    e->access = 0x89u; /* present, type 64-bit TSS (available) */
    e->gran = (uint8_t)((limit >> 16) & 0x0Fu);
    e->base_high = (uint8_t)((base >> 24) & 0xFFu);
    e->base_upper = (uint32_t)((base >> 32) & 0xFFFFFFFFu);
    e->reserved = 0;
}

void gdt_set_kernel_stack(uint64_t rsp0) {
    g_tss.rsp0 = rsp0;
}

void gdt_init(void) {
    g_tss = (struct tss64){0};
    g_tss.iopb_offset = sizeof(struct tss64);

    set_gdt_entry(&gdt_table.gdt[0], 0, 0, 0, 0); /* null */
    set_gdt_entry(&gdt_table.gdt[1], 0, 0xFFFFF, 0x9Au, 0xA0u); /* kernel code: G=1, L=1 */
    set_gdt_entry(&gdt_table.gdt[2], 0, 0xFFFFF, 0x92u, 0x80u); /* kernel data: G=1, L=0 */
    set_gdt_entry(&gdt_table.gdt[3], 0, 0xFFFFF, 0xF2u, 0x80u); /* user data: G=1, L=0 */
    set_gdt_entry(&gdt_table.gdt[4], 0, 0xFFFFF, 0xFAu, 0xA0u); /* user code: G=1, L=1 */

    set_tss_desc(&gdt_table.tss_desc, (uint64_t)&g_tss, sizeof(g_tss) - 1u);

    struct gdt_ptr gp;
    gp.limit = (uint16_t)(sizeof(gdt_table) - 1u);
    gp.base = (uint64_t)&gdt_table;

#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("lgdt %0" : : "m"(gp) : "memory");
    /* Reload CS via far return to flush old descriptor. */
    __asm__ volatile(
        "pushq %0\n"
        "lea 1f(%%rip), %%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        :
        : "r"((uint64_t)GDT_KERNEL_CODE)
        : "rax", "memory");
    __asm__ volatile(
        "mov %0, %%ds\n"
        "mov %0, %%es\n"
        "mov %0, %%ss\n"
        :
        : "r"((uint16_t)GDT_KERNEL_DATA)
        : "memory");
    __asm__ volatile("ltr %0" : : "r"((uint16_t)GDT_TSS) : "memory");
#endif
}
