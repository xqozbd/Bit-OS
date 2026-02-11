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
#include "arch/x86_64/gdt.h"
#include "sys/initramfs.h"
#include "sys/fs_mock.h"
#include "sys/vfs.h"
#include "sys/journal.h"
#include "lib/log.h"
#include "kernel/monitor.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "kernel/sched.h"
#include "kernel/sleep.h"
#include "kernel/block.h"
#include "kernel/partition.h"
#include "drivers/storage/ata.h"
#include "drivers/storage/ahci.h"
#include "sys/blockfs.h"
#include "sys/fat32.h"
#include "sys/ext2.h"
#include "sys/pseudofs.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "kernel/watchdog.h"
#include "drivers/ps2/mouse.h"
#include "drivers/pci/pci.h"
#include "drivers/net/pcnet.h"
#include "drivers/usb/xhci.h"
#include "drivers/usb/usbmgr.h"
#include "kernel/time.h"
#include "kernel/pstate.h"
#include "sys/acpi.h"
#include "kernel/power.h"
#include "kernel/socket.h"
#include "kernel/driver_registry.h"
#include "kernel/init.h"
#include "kernel/dhcp.h"
#include "kernel/firewall.h"
#include "sys/boot_params.h"

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
    driver_registry_init();
    uint32_t drv_order = 0;
    int drv_idt = driver_register("idt", drv_order++);
    int drv_fb = driver_register("framebuffer", drv_order++);
    int drv_banner = driver_register("banner", drv_order++);
    int drv_pmm = driver_register("pmm", drv_order++);
    int drv_paging = driver_register("paging", drv_order++);
    int drv_heap = driver_register("heap", drv_order++);
    int drv_block = driver_register("block", drv_order++);
    int drv_ahci = driver_register("ahci", drv_order++);
    int drv_ata = driver_register("ata", drv_order++);
    int drv_partition = driver_register("partition", drv_order++);
    int drv_pcnet = driver_register("pcnet", drv_order++);
    int drv_xhci = driver_register("xhci", drv_order++);
    int drv_usbmgr = driver_register("usbmgr", drv_order++);
    int drv_pci = driver_register("pci", drv_order++);
    int drv_acpi = driver_register("acpi", drv_order++);
    int drv_pstate = driver_register("pstate", drv_order++);
    int drv_initramfs = driver_register("initramfs", drv_order++);
    int drv_vfs = driver_register("vfs", drv_order++);
    int drv_smp = driver_register("smp", drv_order++);
    int drv_timer = driver_register("timer", drv_order++);
    int drv_sched = driver_register("sched", drv_order++);
    int drv_console = driver_register("console", drv_order++);
    int drv_mouse = driver_register("mouse", drv_order++);
    watchdog_early_stage("kmain_start");
    log_printf("Boot: initializing GDT/TSS...\n");
    gdt_init();
    gdt_set_kernel_stack((uint64_t)(uintptr_t)(g_bootstrap_stack + sizeof(g_bootstrap_stack)));
    log_printf("Boot: GDT/TSS ready\n");
    log_printf("Boot: enabling CPU SSE...\n");
    cpu_enable_sse();
    log_printf("Boot: CPU SSE enabled\n");
    log_printf("Boot: initializing IDT...\n");
    idt_init();
    watchdog_early_stage("idt_init");
    watchdog_log_stage("idt_init");
    log_printf("Boot: IDT ready\n");
    driver_set_status_idx(drv_idt, DRIVER_STATUS_OK, NULL);

    log_printf("Boot: checking Limine base revision...\n");
    if (LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision) == false) {
        log_printf("Boot: Limine base revision unsupported\n");
        halt_forever();
    }
    if (exec_cmdline_request.response && exec_cmdline_request.response->cmdline) {
        boot_params_init(exec_cmdline_request.response->cmdline);
        log_printf("Boot: cmdline=%s\n", exec_cmdline_request.response->cmdline);
    } else {
        boot_params_init(NULL);
    }
    const char *log_mode = boot_param_get("log");
    if (log_mode && log_mode[0] == 'v' && log_mode[1] == 'e' && log_mode[2] == 'r'
        && log_mode[3] == 'b' && log_mode[4] == 'o' && log_mode[5] == 's' && log_mode[6] == 'e'
        && log_mode[7] == '\0') {
        log_set_verbose(1);
        log_printf("Boot: verbose logging enabled\n");
    }
    watchdog_set_mode(boot_param_get("watchdog"));
    log_printf_verbose("Boot: watchdog mode=%s\n", boot_param_get("watchdog"));

    log_printf("Boot: checking framebuffer availability...\n");
    if (!framebuffer_request.response || framebuffer_request.response->framebuffer_count < 1) {
        log_printf("Boot: no framebuffer available\n");
        driver_set_status_idx(drv_fb, DRIVER_STATUS_FAIL, "no framebuffer");
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
    driver_set_status_idx(drv_fb, DRIVER_STATUS_OK, NULL);
    log_printf("Boot: drawing banner...\n");
    banner_init(fb);
    banner_draw();
    driver_set_status_idx(drv_banner, DRIVER_STATUS_OK, NULL);
    log_printf("Boot: showing boot screen...\n");
    boot_screen_print_loading();

    boot_screen_set_status("pmm");
    log_printf("Boot: initializing PMM...\n");
    pmm_init();
    watchdog_early_stage("pmm_init");
    watchdog_log_stage("pmm_init");
    log_printf("Boot: PMM ready\n");
    driver_set_status_idx(drv_pmm, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("paging");
    log_printf("Boot: initializing paging...\n");
    paging_init();
    watchdog_early_stage("paging_init");
    watchdog_log_stage("paging_init");
    log_printf("Boot: paging ready\n");
    driver_set_status_idx(drv_paging, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("heap");
    log_printf("Boot: initializing heap...\n");
    heap_init();
    watchdog_early_stage("heap_init");
    watchdog_log_stage("heap_init");
    log_printf("Boot: heap ready\n");
    driver_set_status_idx(drv_heap, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("block");
    log_printf("Boot: initializing block layer...\n");
    block_init();
    if (block_device_count() == 0) {
        driver_set_status_idx(drv_block, DRIVER_STATUS_OK, "0 devices");
    } else {
        driver_set_status_idx(drv_block, DRIVER_STATUS_OK, NULL);
    }
    boot_screen_set_status("ahci");
    log_printf("Boot: initializing AHCI...\n");
    ahci_init();
    boot_screen_set_status("ata");
    log_printf("Boot: initializing ATA...\n");
    ata_init();
    if (ata_has_device()) {
        driver_set_status_idx(drv_ata, DRIVER_STATUS_OK, NULL);
    } else {
        driver_set_status_idx(drv_ata, DRIVER_STATUS_SKIPPED, "not found");
    }
    boot_screen_set_status("partition");
    log_printf("Boot: parsing partitions...\n");
    partition_init();
    if (partition_count() == 0) {
        driver_set_status_idx(drv_partition, DRIVER_STATUS_SKIPPED, "none");
    } else {
        driver_set_status_idx(drv_partition, DRIVER_STATUS_OK, NULL);
    }
    boot_screen_set_status("pcnet");
    log_printf("Boot: initializing PCNet driver...\n");
    pcnet_init();
    log_printf("Boot: registering xHCI driver...\n");
    xhci_init();
    watchdog_early_stage("pcnet_init");
    watchdog_log_stage("pcnet_init");
    log_printf("Boot: PCNet ready\n");
    boot_screen_set_status("pci");
    log_printf("Boot: scanning PCI...\n");
    pci_init();
    watchdog_early_stage("pci_init");
    watchdog_log_stage("pci_init");
    log_printf("Boot: PCI scan complete\n");
    driver_set_status_idx(drv_pci, DRIVER_STATUS_OK, NULL);
    if (ahci_has_device()) {
        driver_set_status_idx(drv_ahci, DRIVER_STATUS_OK, NULL);
    } else {
        driver_set_status_idx(drv_ahci, DRIVER_STATUS_SKIPPED, "not found");
    }
    pcnet_log_status();
    if (!pcnet_is_found()) {
        driver_set_status_idx(drv_pcnet, DRIVER_STATUS_SKIPPED, "not found");
    } else if (pcnet_has_error() || !pcnet_is_ready()) {
        driver_set_status_idx(drv_pcnet, DRIVER_STATUS_FAIL, "error");
    } else {
        driver_set_status_idx(drv_pcnet, DRIVER_STATUS_OK, NULL);
    }
    if (xhci_is_ready()) {
        driver_set_status_idx(drv_xhci, DRIVER_STATUS_OK, NULL);
        log_printf("Boot: starting USB manager...\n");
        if (usbmgr_init() == 0) {
            driver_set_status_idx(drv_usbmgr, DRIVER_STATUS_OK, NULL);
        } else {
            driver_set_status_idx(drv_usbmgr, DRIVER_STATUS_FAIL, "init failed");
        }
    } else {
        driver_set_status_idx(drv_xhci, DRIVER_STATUS_SKIPPED, "not found");
        driver_set_status_idx(drv_usbmgr, DRIVER_STATUS_SKIPPED, "xhci not ready");
    }
    socket_init();
    firewall_init();
    log_printf("Boot: socket layer ready\n");
    if (pcnet_is_ready()) {
        if (dhcp_request() == 0) {
            log_printf("Boot: DHCP configuration applied\n");
        } else {
            log_printf("Boot: DHCP failed, using static IP\n");
        }
    }
    boot_screen_set_status("acpi");
    log_printf("Boot: initializing ACPI...\n");
    acpi_init();
    watchdog_early_stage("acpi_init");
    watchdog_log_stage("acpi_init");
    acpi_log_status();
    log_printf("Boot: ACPI init complete\n");
    if (acpi_is_ready()) {
        driver_set_status_idx(drv_acpi, DRIVER_STATUS_OK, NULL);
    } else {
        driver_set_status_idx(drv_acpi, DRIVER_STATUS_SKIPPED, "not ready");
    }
    power_init();
    boot_screen_set_status("pstate");
    log_printf("Boot: initializing P-states...\n");
    pstate_init();
    watchdog_early_stage("pstate_init");
    watchdog_log_stage("pstate_init");
    log_printf("Boot: P-states ready\n");
    if (acpi_pss_count() > 0 && acpi_pct_count() > 0) {
        driver_set_status_idx(drv_pstate, DRIVER_STATUS_OK, NULL);
    } else {
        driver_set_status_idx(drv_pstate, DRIVER_STATUS_SKIPPED, "no _PSS/_PCT");
    }
    boot_screen_set_status("initramfs");
    log_printf("Boot: initializing initramfs...\n");
    initramfs_init_from_limine();
    watchdog_early_stage("initramfs");
    watchdog_log_stage("initramfs");
    log_printf("Boot: initramfs ready\n");
    driver_set_status_idx(drv_initramfs, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("vfs");
    log_printf("Boot: initializing VFS...\n");
    vfs_init();
    vfs_mount("/dev", VFS_BACKEND_DEV, pseudofs_root(PSEUDOFS_DEV));
    vfs_mount("/proc", VFS_BACKEND_PROC, pseudofs_root(PSEUDOFS_PROC));
    vfs_mount("/sys", VFS_BACKEND_SYS, pseudofs_root(PSEUDOFS_SYS));
    log_printf("Boot: mounted /dev, /proc, /sys\n");
    if (block_device_count() > 0 && partition_count() > 0) {
        vfs_mount("/block", VFS_BACKEND_BLOCK, blockfs_root());
        log_printf("Boot: mounted block devices at /block\n");
    }
    int fat_ready = 0;
    int ext2_ready = 0;
    if (partition_count() > 0) {
        if (fat32_init_from_partition(0) == 0 && fat32_is_ready()) {
            vfs_mount("/fat", VFS_BACKEND_FAT32, fat32_root());
            log_printf("Boot: mounted FAT32 at /fat\n");
            fat_ready = 1;
        }
        if (ext2_init_from_partition(0) == 0 && ext2_is_ready()) {
            vfs_mount("/ext2", VFS_BACKEND_EXT2, ext2_root());
            log_printf("Boot: mounted ext2 at /ext2\n");
            ext2_ready = 1;
        }
    }
    if (initramfs_available()) {
        vfs_set_root(VFS_BACKEND_INITRAMFS, initramfs_root());
        log_printf("Boot: VFS root set to initramfs\n");
        vfs_mount("/mock", VFS_BACKEND_MOCK, fs_root());
        log_printf("Boot: mounted mock FS at /mock\n");
    } else {
        if (ext2_ready) {
            vfs_set_root(VFS_BACKEND_EXT2, ext2_root());
            log_printf("Boot: VFS root set to ext2\n");
            journal_init();
        } else if (fat_ready) {
            vfs_set_root(VFS_BACKEND_FAT32, fat32_root());
            log_printf("Boot: VFS root set to FAT32\n");
        } else if (block_device_count() > 0 && partition_count() > 0) {
            vfs_set_root(VFS_BACKEND_BLOCK, blockfs_root());
            log_printf("Boot: VFS root set to block device\n");
        } else {
            vfs_set_root(VFS_BACKEND_MOCK, fs_root());
            log_printf("Boot: VFS root set to mock FS\n");
        }
    }
    if (initramfs_available()) {
        vfs_mount("/initramfs", VFS_BACKEND_INITRAMFS, initramfs_root());
        log_printf("Boot: mounted initramfs at /initramfs\n");
    }
    watchdog_early_stage("vfs_init");
    watchdog_log_stage("vfs_init");
    driver_set_status_idx(drv_vfs, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("smp");
    log_printf("Boot: initializing SMP...\n");
    smp_init();
    watchdog_early_stage("smp_init");
    watchdog_log_stage("smp_init");
    log_printf("Boot: SMP ready\n");
    driver_set_status_idx(drv_smp, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("timer");
    log_printf("Boot: initializing timer...\n");
    timer_init();
    watchdog_checkpoint("timer_init");
    watchdog_log_stage("timer_init");
    log_printf("Boot: timer ready\n");
    driver_set_status_idx(drv_timer, DRIVER_STATUS_OK, NULL);
    boot_screen_set_status("sched");
    log_printf("Boot: initializing scheduler...\n");
    sched_init();
    sleep_init();
    watchdog_log_stage("sched_init");
    log_printf("Boot: scheduler ready\n");
    driver_set_status_idx(drv_sched, DRIVER_STATUS_OK, NULL);
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
    boot_screen_print_main();
    log_printf("Boot: initializing console...\n");
    console_init();
    driver_set_status_idx(drv_console, DRIVER_STATUS_OK, NULL);
    log_printf("Boot: spawning init...\n");
    if (init_spawn() == 0) {
        log_printf("Boot: init started\n");
    } else {
        log_printf("Boot: init not started\n");
    }
    watchdog_checkpoint_boot_ok();
    watchdog_checkpoint("mouse_init");
    log_printf("Boot: initializing mouse...\n");
    ms_init();
    driver_set_status_idx(drv_mouse, DRIVER_STATUS_OK, NULL);
    log_printf("Boot: entering console loop\n");
    log_printf("\b");
    console_run();
}

static void boot_delay_ms(uint32_t ms) {
    for (volatile uint64_t spin = 0; spin < (uint64_t)ms * 20000ull; ++spin) {
        cpu_pause();
    }
}
