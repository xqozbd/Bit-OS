#include "smp.h"

#include <stddef.h>
#include <stdint.h>

#include "boot_requests.h"
#include "cpu.h"
#include "heap.h"
#include "log.h"

enum { AP_STACK_SIZE = 16 * 1024 };

static volatile uint32_t g_online = 1; /* BSP */
static uint32_t g_cpu_count = 1;
static int g_initialized = 0;

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

__attribute__((noreturn))
static void ap_entry(struct limine_mp_info *info) {
    uintptr_t stack_top = (uintptr_t)info->extra_argument;
    if (stack_top != 0) {
        stack_top &= ~0xFull; /* 16-byte align */
        stack_top -= 8;       /* SysV ABI: entry RSP%16 == 8 */
#if defined(__GNUC__) || defined(__clang__)
        __asm__ volatile(
            "mov %0, %%rsp\n"
            "xor %%rbp, %%rbp\n"
            :
            : "r"(stack_top)
            : "memory");
#endif
    }
    ap_main(info);
}

void smp_init(void) {
    g_initialized = 0;
    g_online = 1;
    g_cpu_count = 1;

    if (!mp_request.response) return;
    struct limine_mp_response *resp = mp_request.response;
    if (!resp || resp->cpu_count == 0) return;

    g_cpu_count = (uint32_t)resp->cpu_count;
    if (g_cpu_count <= 1) {
        g_initialized = 1;
        return;
    }

    uint32_t launched = 0;
    for (uint64_t i = 0; i < resp->cpu_count; ++i) {
        struct limine_mp_info *info = resp->cpus[i];
        if (!info) continue;
        if (info->lapic_id == resp->bsp_lapic_id) continue;

        void *stack = kmalloc(AP_STACK_SIZE);
        if (!stack) {
            log_printf("SMP: failed to allocate AP stack\n");
            continue;
        }
        uintptr_t stack_top = (uintptr_t)stack + AP_STACK_SIZE;
        stack_top &= ~0xFull; /* 16-byte align */

        info->extra_argument = stack_top;
        info->goto_address = ap_entry;
        launched++;
    }

    if (launched == 0) return;

    /* Spin for APs to report online. */
    for (uint64_t spin = 0; spin < 10000000ull; ++spin) {
        if (g_online >= g_cpu_count) break;
    }

    g_initialized = (g_online >= g_cpu_count);
    if (!g_initialized) {
        log_printf("SMP: online=%u/%u\n", (unsigned)g_online, (unsigned)g_cpu_count);
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
