#include "arch/x86_64/smp.h"

#include <stddef.h>
#include <stdint.h>

#include "boot/boot_requests.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/paging.h"
#include "kernel/heap.h"
#include "kernel/pmm.h"
#include "lib/log.h"

enum { AP_STACK_SIZE = 0x1000 };

static volatile uint32_t g_online = 1; /* BSP */
static uint32_t g_cpu_count = 1;
static int g_initialized = 0;
static uint32_t g_bsp_index = 0;
static struct smp_percpu *g_percpu = 0;
__attribute__((used))
static uint64_t g_boot_cr3 = 0;

static inline void atomic_inc_u32(volatile uint32_t *p) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_add(p, 1u, __ATOMIC_SEQ_CST);
#else
    (*p)++;
#endif
}

__attribute__((noreturn))
static void ap_main(struct limine_mp_info *info) {
    (void)info;
    atomic_inc_u32(&g_online);
    cpu_disable_interrupts();
    halt_forever();
    __builtin_unreachable();
}

__attribute__((noreturn, used))
static void ap_entry_c(struct limine_mp_info *info) {
    idt_reload();
    ap_main(info);
}

__attribute__((naked, noreturn, used))
static void ap_entry(struct limine_mp_info *info) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        ".intel_syntax noprefix\n"
        "cli\n"
        "mov rax, qword ptr [rdi + 32]\n" /* info->extra_argument (stack_top) */
        "mov rcx, qword ptr [rip + g_boot_cr3]\n"
        "test rcx, rcx\n"
        "jz 0f\n"
        "mov cr3, rcx\n"
        "0:\n"
        "test rax, rax\n"
        "jz 1f\n"
        "mov rsp, rax\n"
        "and rsp, -16\n"
        "sub rsp, 8\n"
        "1:\n"
        "xor rbp, rbp\n"
        "jmp ap_entry_c\n"
        ".att_syntax\n");
#else
    (void)info;
    ap_entry_c(info);
#endif
}

void smp_init(void) {
    g_initialized = 0;
    g_online = 1;
    g_cpu_count = 1;
    g_bsp_index = 0;
    g_percpu = 0;
    g_boot_cr3 = paging_pml4_phys();

    if (!mp_request.response) return;
    struct limine_mp_response *resp = mp_request.response;
    if (!resp || resp->cpu_count == 0) return;

    g_cpu_count = (uint32_t)resp->cpu_count;
    g_percpu = (struct smp_percpu *)kmalloc(sizeof(*g_percpu) * g_cpu_count);
    if (!g_percpu) {
        log_printf("SMP: failed to allocate per-CPU data\n");
        return;
    }
    for (uint32_t i = 0; i < g_cpu_count; ++i) {
        g_percpu[i].cpu_index = i;
        g_percpu[i].lapic_id = 0;
        g_percpu[i].is_bsp = 0;
        g_percpu[i].stack_top = 0;
    }

    for (uint64_t i = 0; i < resp->cpu_count; ++i) {
        struct limine_mp_info *info = resp->cpus[i];
        if (!info) continue;
        g_percpu[i].lapic_id = (uint32_t)info->lapic_id;
        if (info->lapic_id == resp->bsp_lapic_id) {
            g_bsp_index = (uint32_t)i;
            g_percpu[i].is_bsp = 1;
        }
    }

    if (g_cpu_count <= 1) {
        g_initialized = 1;
        return;
    }

    uint32_t launched = 0;
    for (uint64_t i = 0; i < resp->cpu_count; ++i) {
        struct limine_mp_info *info = resp->cpus[i];
        if (!info) continue;
        if (info->lapic_id == resp->bsp_lapic_id) continue;

        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) {
            log_printf("SMP: failed to allocate AP stack frame\n");
            continue;
        }
        uint64_t hhdm = paging_hhdm_offset();
        uintptr_t stack_top = (uintptr_t)(hhdm + phys + AP_STACK_SIZE);

        g_percpu[i].stack_top = stack_top;
        info->extra_argument = (uint64_t)stack_top;
        info->goto_address = ap_entry;
        launched++;
    }

    if (launched == 0) return;

    for (uint64_t spin = 0; spin < 10000000ull; ++spin) {
        if (g_online >= g_cpu_count) break;
    }

    g_initialized = (g_online >= g_cpu_count);
    if (!g_initialized) {
        log_printf("SMP: online=%u/%u\n", (unsigned)g_online, (unsigned)g_cpu_count);
    } else {
        log_printf("SMP: online=%u/%u bsp=%u\n", (unsigned)g_online, (unsigned)g_cpu_count, (unsigned)g_bsp_index);
    }
}

int smp_is_initialized(void) {
    return g_initialized;
}

uint32_t smp_cpu_count(void) {
    return g_cpu_count;
}

uint32_t smp_online_count(void) {
    return g_online;
}

uint32_t smp_bsp_index(void) {
    return g_bsp_index;
}

struct smp_percpu *smp_percpu(uint32_t cpu_index) {
    if (!g_percpu || cpu_index >= g_cpu_count) return 0;
    return &g_percpu[cpu_index];
}
