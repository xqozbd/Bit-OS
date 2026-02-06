#include "arch/x86_64/usermode.h"

#include <stddef.h>

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"

int user_stack_build(uint64_t pml4_phys, uint64_t top, uint64_t size, uint64_t *out_rsp) {
    if (size == 0 || (size & 0xFFFu)) return -1;
    uint64_t base = top - size;
    for (uint64_t va = base; va < top; va += 0x1000ull) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) return -2;
        if (paging_map_user_4k(pml4_phys, va, phys, 0) != 0) return -3;
    }
    if (out_rsp) {
        uint64_t sp = top & ~0xFULL;
        sp -= 8;
        *out_rsp = sp;
    }
    return 0;
}

__attribute__((noreturn))
void user_enter_iret(uint64_t rip, uint64_t rsp, uint64_t rflags) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t user_cs = (uint64_t)(GDT_USER_CODE | 0x3u);
    uint64_t user_ss = (uint64_t)(GDT_USER_DATA | 0x3u);
    __asm__ volatile(
        "cli\n"
        "mov %0, %%ds\n"
        "mov %0, %%es\n"
        "pushq %1\n"
        "pushq %2\n"
        "pushq %3\n"
        "pushq %4\n"
        "pushq %5\n"
        "iretq\n"
        :
        : "r"((uint16_t)user_ss),
          "r"(user_ss),
          "r"(rsp),
          "r"(rflags),
          "r"(user_cs),
          "r"(rip)
        : "memory");
#else
    (void)rip; (void)rsp; (void)rflags;
    for (;;) { }
#endif
    __builtin_unreachable();
}
