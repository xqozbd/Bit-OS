#include <stdbool.h>
#include <stdint.h>

#include "banner.h"
#include "boot_requests.h"
#include "boot_screen.h"
#include "console.h"
#include "cpu.h"
#include "cpu_info.h"
#include "fb_printf.h"
#include "heap.h"
#include "idt.h"
#include "initramfs.h"
#include "log.h"
#include "monitor.h"
#include "paging.h"
#include "pmm.h"
#include "smp.h"
#include "timer.h"
#include "watchdog.h"

/* Bootstrap stack: keep it inside the kernel image so it's mapped in our page tables. */
#define KSTACK_SIZE (64 * 1024)
static uint8_t g_bootstrap_stack[KSTACK_SIZE] __attribute__((aligned(16)));

static void kmain_stage2(void);

__attribute__((noreturn, noinline))
static void stack_switch_and_jump(void (*entry)(void), void *stack_top) {
#if defined(__GNUC__) || defined(__clang__)
    uintptr_t sp = (uintptr_t)stack_top;
    sp &= ~0xFULL; /* 16-byte align */
    sp -= 8;       /* SysV ABI: entry RSP%16 == 8 */
    __asm__ volatile(
        "mov %0, %%rsp\n"
        "xor %%rbp, %%rbp\n"
        "jmp *%1\n"
        :
        : "r"(sp), "r"(entry)
        : "memory");
#else
    (void)stack_top;
    entry();
#endif
    __builtin_unreachable();
}

void kmain(void) {
    uintptr_t stack_top = (uintptr_t)g_bootstrap_stack + sizeof(g_bootstrap_stack);
    stack_switch_and_jump(kmain_stage2, (void *)stack_top);
}

static void kmain_stage2(void) {
    log_init_serial();
    cpu_enable_sse();
    idt_init();

    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        halt_forever();
    }

    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        halt_forever();
    }

    pmm_init();
    paging_init();
    heap_init();
    initramfs_init_from_limine();
    smp_init();

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];
    fb_init(fb, 0xE6E6E6, 0x0B0F14);
    fb_set_layout_ex(3, 4, 24, 24, 4, 2);
    log_set_fb_ready(1);
    banner_init(fb);
    banner_draw();
    boot_screen_print();
    monitor_init();
    timer_init();
    watchdog_init(1);
    cpu_enable_interrupts();
    if (cpu_calibrate_tsc_hz_pit(100)) {
        uint64_t hz = 0;
        if (cpu_get_tsc_hz(&hz)) {
            log_printf("TSC: %u Hz (PIT calibrated)\n", (unsigned)hz);
        }
    } else {
        log_printf("TSC: unavailable\n");
    }
    console_init();
    watchdog_checkpoint_boot_ok();
    console_run();
}
