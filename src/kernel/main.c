#include <stdbool.h>
#include <stdint.h>

#include "lib/compat.h"
#include "drivers/video/banner.h"
#include "boot/boot_requests.h"
#include "boot/boot_screen.h"
#include "kernel/console.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "drivers/video/fb_printf.h"
#include "kernel/heap.h"
#include "arch/x86_64/idt.h"
#include "sys/initramfs.h"
#include "lib/log.h"
#include "kernel/monitor.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "kernel/watchdog.h"
#include "drivers/ps2/mouse.h"
#include "drivers/pci/pci.h"
#include "drivers/net/pcnet.h"

/* Bootstrap stack: keep it inside the kernel image so it's mapped in our page tables. */
#define KSTACK_SIZE (64 * 1024)
static uint8_t g_bootstrap_stack[KSTACK_SIZE] __attribute__((aligned(16)));

static void kmain_stage2(void);
static void boot_delay_ms(uint32_t ms);

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
    log_printf("Init: serial logger\n");
    watchdog_early_stage("kmain_start");
    cpu_enable_sse();
    log_printf("Init: CPU SSE\n");
    idt_init();
    watchdog_early_stage("idt_init");
    watchdog_log_stage("idt_init");
    log_printf("Init: IDT\n");

    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        halt_forever();
    }

    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        halt_forever();
    }

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];
    log_printf("Init: framebuffer\n");
    fb_init(fb, 0xE6E6E6, 0x0B0F14);
    fb_set_layout_ex(3, 4, 24, 24, 4, 2);
    log_set_fb_ready(0);
    watchdog_early_stage("fb_ready");
    watchdog_log_stage("fb_ready");
    log_printf("Init: banner\n");
    banner_init(fb);
    banner_draw();
    log_printf("Init: boot screen\n");
    boot_screen_print_loading();

    boot_screen_set_status("pmm");
    log_printf("Init: PMM\n");
    pmm_init();
    watchdog_early_stage("pmm_init");
    watchdog_log_stage("pmm_init");
    boot_screen_set_status("paging");
    log_printf("Init: paging\n");
    paging_init();
    watchdog_early_stage("paging_init");
    watchdog_log_stage("paging_init");
    boot_screen_set_status("heap");
    log_printf("Init: heap\n");
    heap_init();
    watchdog_early_stage("heap_init");
    watchdog_log_stage("heap_init");
    boot_screen_set_status("pcnet");
    log_printf("Init: PCNet driver\n");
    pcnet_init();
    watchdog_early_stage("pcnet_init");
    watchdog_log_stage("pcnet_init");
    boot_screen_set_status("pci");
    log_printf("Init: PCI scan\n");
    pci_init();
    watchdog_early_stage("pci_init");
    watchdog_log_stage("pci_init");
    boot_screen_set_status("initramfs");
    log_printf("Init: initramfs\n");
    initramfs_init_from_limine();
    watchdog_early_stage("initramfs");
    watchdog_log_stage("initramfs");
    boot_screen_set_status("smp");
    log_printf("Init: SMP\n");
    smp_init();
    watchdog_early_stage("smp_init");
    watchdog_log_stage("smp_init");
    boot_screen_set_status("timer");
    log_printf("Init: timer\n");
    timer_init();
    watchdog_checkpoint("timer_init");
    watchdog_log_stage("timer_init");
    boot_screen_set_status("switching");
    boot_delay_ms(1200);
    fb_clear();
    banner_draw();
    boot_screen_print_main();
    log_set_fb_ready(1);
    monitor_init();
    watchdog_init(5);
    cpu_enable_interrupts();
    watchdog_checkpoint("sti");
    watchdog_log_stage("sti");
    if (cpu_calibrate_tsc_hz_pit(100)) {
        uint64_t hz = 0;
        if (cpu_get_tsc_hz(&hz)) {
            log_printf("TSC: %u Hz (PIT calibrated)\n", (unsigned)hz);
        }
    } else {
        log_printf("TSC: unavailable\n");
    }
    watchdog_checkpoint("tsc_done");
    watchdog_log_stage("tsc_done");
    watchdog_checkpoint("apic_calibrate");
    timer_switch_to_apic(100);
    watchdog_checkpoint("apic_done");
    console_init();
    watchdog_checkpoint_boot_ok();
    watchdog_checkpoint("mouse_init");
    ms_init();
    console_run();
}

static void boot_delay_ms(uint32_t ms) {
    for (volatile uint64_t spin = 0; spin < (uint64_t)ms * 20000ull; ++spin) {
        cpu_pause();
    }
}
