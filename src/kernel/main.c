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
#include "sys/vfs.h"
#include "lib/log.h"
#include "kernel/monitor.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/sched.h"
#include "kernel/sleep.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "kernel/watchdog.h"
#include "drivers/ps2/mouse.h"
#include "drivers/pci/pci.h"
#include "drivers/net/pcnet.h"
#include "kernel/time.h"

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
    log_printf("Boot: serial logger ready (COM1)\n");
    watchdog_early_stage("kmain_start");
    log_printf("Boot: enabling CPU SSE...\n");
    cpu_enable_sse();
    log_printf("Boot: CPU SSE enabled\n");
    log_printf("Boot: initializing IDT...\n");
    idt_init();
    watchdog_early_stage("idt_init");
    watchdog_log_stage("idt_init");
    log_printf("Boot: IDT ready\n");

    log_printf("Boot: checking Limine base revision...\n");
    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        log_printf("Boot: Limine base revision unsupported\n");
        halt_forever();
    }

    log_printf("Boot: checking framebuffer availability...\n");
    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        log_printf("Boot: no framebuffer available\n");
        halt_forever();
    }

    struct limine_framebuffer *fb = framebuffer_request.response->framebuffers[0];
    log_printf("Boot: initializing framebuffer (%ux%u, %u bpp)...\n",
               (unsigned)fb->width, (unsigned)fb->height, (unsigned)fb->bpp);
    fb_init(fb, 0xE6E6E6, 0x0B0F14);
    fb_set_layout_ex(3, 4, 24, 24, 4, 2);
    log_set_fb_ready(0);
    watchdog_early_stage("fb_ready");
    watchdog_log_stage("fb_ready");
    log_printf("Boot: drawing banner...\n");
    banner_init(fb);
    banner_draw();
    log_printf("Boot: showing boot screen...\n");
    boot_screen_print_loading();

    boot_screen_set_status("pmm");
    log_printf("Boot: initializing PMM...\n");
    pmm_init();
    watchdog_early_stage("pmm_init");
    watchdog_log_stage("pmm_init");
    log_printf("Boot: PMM ready\n");
    boot_screen_set_status("paging");
    log_printf("Boot: initializing paging...\n");
    paging_init();
    watchdog_early_stage("paging_init");
    watchdog_log_stage("paging_init");
    log_printf("Boot: paging ready\n");
    boot_screen_set_status("heap");
    log_printf("Boot: initializing heap...\n");
    heap_init();
    watchdog_early_stage("heap_init");
    watchdog_log_stage("heap_init");
    log_printf("Boot: heap ready\n");
    boot_screen_set_status("pcnet");
    log_printf("Boot: initializing PCNet driver...\n");
    pcnet_init();
    watchdog_early_stage("pcnet_init");
    watchdog_log_stage("pcnet_init");
    log_printf("Boot: PCNet ready\n");
    boot_screen_set_status("pci");
    log_printf("Boot: scanning PCI...\n");
    pci_init();
    watchdog_early_stage("pci_init");
    watchdog_log_stage("pci_init");
    log_printf("Boot: PCI scan complete\n");
    boot_screen_set_status("initramfs");
    log_printf("Boot: initializing initramfs...\n");
    initramfs_init_from_limine();
    watchdog_early_stage("initramfs");
    watchdog_log_stage("initramfs");
    log_printf("Boot: initramfs ready\n");
    boot_screen_set_status("vfs");
    log_printf("Boot: initializing VFS...\n");
    vfs_init();
    if (initramfs_available()) {
        vfs_set_root(VFS_BACKEND_INITRAMFS, initramfs_root());
        log_printf("Boot: VFS root set to initramfs\n");
    } else {
        vfs_set_root(VFS_BACKEND_MOCK, 0);
        log_printf("Boot: VFS root set to mock FS\n");
    }
    watchdog_early_stage("vfs_init");
    watchdog_log_stage("vfs_init");
    boot_screen_set_status("smp");
    log_printf("Boot: initializing SMP...\n");
    smp_init();
    watchdog_early_stage("smp_init");
    watchdog_log_stage("smp_init");
    log_printf("Boot: SMP ready\n");
    boot_screen_set_status("timer");
    log_printf("Boot: initializing timer...\n");
    timer_init();
    watchdog_checkpoint("timer_init");
    watchdog_log_stage("timer_init");
    log_printf("Boot: timer ready\n");
    boot_screen_set_status("sched");
    log_printf("Boot: initializing scheduler...\n");
    sched_init();
    sleep_init();
    watchdog_log_stage("sched_init");
    log_printf("Boot: scheduler ready\n");
    boot_screen_set_status("switching");
    log_printf("Boot: entering monitor...\n");
    monitor_init();
    watchdog_init(5);
    log_printf("Boot: enabling interrupts...\n");
    cpu_enable_interrupts();
    watchdog_checkpoint("sti");
    watchdog_log_stage("sti");
    log_printf("Boot: calibrating TSC...\n");
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
    log_printf("Boot: switching timer to APIC...\n");
    watchdog_checkpoint("apic_calibrate");
    timer_switch_to_apic(100);
    watchdog_checkpoint("apic_done");
    time_init();
    log_printf("Boot: preparing console screen...\n");
    boot_delay_ms(1000);
    fb_clear();
    banner_draw();
    log_set_fb_ready(1);
    boot_screen_print_debug();
    log_printf("Boot: initializing console...\n");
    console_init();
    watchdog_checkpoint_boot_ok();
    watchdog_checkpoint("mouse_init");
    log_printf("Boot: initializing mouse...\n");
    ms_init();
    log_printf("Boot: entering console loop\n");
    log_printf("\b");
    console_run();
}

static void boot_delay_ms(uint32_t ms) {
    for (volatile uint64_t spin = 0; spin < (uint64_t)ms * 20000ull; ++spin) {
        cpu_pause();
    }
}
