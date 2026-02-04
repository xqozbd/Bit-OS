#include "sys/commands.h"

#include <stddef.h>

#include "drivers/video/banner.h"
#include "sys/elf_loader.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu.h"
#include "drivers/video/fb_printf.h"
#include "sys/fs_mock.h"
#include "lib/log.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "drivers/rtc/rtc_util.h"
#include "kernel/time.h"
#include "kernel/heap.h"
#include "arch/x86_64/smp.h"
#include "lib/strutil.h"
#include "lib/version.h"
#include "boot/bootinfo.h"
#include "drivers/net/pcnet.h"

static const char *const g_commands[] = {
    "help", "clear", "time", "mem", "memtest", "cputest",
    "ls", "cd", "pwd", "cat", "run", "echo", "ver", "debug", "shutdown", "restart"
};


size_t commands_count(void) {
    return sizeof(g_commands) / sizeof(g_commands[0]);
}

const char *commands_get(size_t idx) {
    if (idx >= commands_count()) return NULL;
    return g_commands[idx];
}

static void cmd_help(void) {
    log_printf("Commands: ");
    for (size_t i = 0; i < commands_count(); ++i) {
        log_printf("%s%s", g_commands[i], (i + 1 < commands_count()) ? ", " : "\n");
    }
    log_printf("  memtest [--size N] [--time T] [--pages N]\n");
    log_printf("  run <path> (ELF64, higher-half)\n");
    log_printf("  debug\n");
    log_printf("  shutdown\n");
    log_printf("  restart\n");
    log_printf("  sizes: 1g 512m 256k (also gb/mb/kb/gig/meg)\n");
    log_printf("  time: 20s 1min 2minutes\n\n");

}

static void cmd_time(void) {
    char time_buf[20];
    int rc = time_get_string(time_buf);
    if (rc == 0) {
        log_printf("%s\n", time_buf);
        return;
    }
    char rtc_buf[20];
    int rrc = rtc_get_string(rtc_buf);
    if (rrc == 0) log_printf("%s\n", rtc_buf);
    else log_printf("RTC: unavailable (err=%d)\n", rrc);
}

static void cmd_debug(void) {
    log_printf("BitOS Debug Info\n");
    log_printf("================\n");

    char rtc_buf[20];
    int rc = rtc_get_string(rtc_buf);
    if (rc == 0) {
        log_printf("RTC: %s\n", rtc_buf);
    } else {
        log_printf("RTC: unavailable (err=%d)\n", rc);
    }

    bootinfo_log();
    systeminfo_log();
    pcnet_log_status();
    log_printf("\n");
}

static void cmd_shutdown(void) {
    log_printf("Shutting down Bit-OS...\n");
    log_printf("Goodbye\n");

    
    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    outw(0x4004, 0x3400);
    outw(0x4004, 0x2000);

    // fallback is to stop the cpu
    halt_forever();
}



static void cmd_mem(void) {
    uint64_t total = pmm_total_frames();
    uint64_t used = pmm_used_frames();
    uint64_t freef = pmm_free_frames();
    log_printf("PMM frames: total=%u used=%u free=%u\n",
               (unsigned)total, (unsigned)used, (unsigned)freef);
}

static void cmd_clear(void) {
    fb_clear();
    banner_draw();
}

static void cmd_ver(void) {
    log_printf("BitOS v%s (build %s %s)\n", BITOS_VERSION, __DATE__, __TIME__);
}

static void cmd_restart(void) {
    log_printf("Restarting...\n");
    outb(0x64, 0xFE);
    halt_forever();
}

static void cmd_cat(const char *path, int cwd) {
    if (!path) {
        log_printf("cat: missing file\n");
        return;
    }
    int node = fs_resolve(cwd, path);
    if (node < 0) {
        log_printf("cat: not found\n");
        return;
    }
    if (fs_is_dir(node)) {
        log_printf("cat: is a directory\n");
        return;
    }

    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!fs_read_file(node, &data, &size) || !data) {
        log_printf("cat: unreadable\n");
        return;
    }
    for (uint64_t i = 0; i < size; ++i) {
        log_printf("%c", (char)data[i]);
    }
    if (size == 0 || data[size - 1] != '\n') log_printf("\n");
}

static inline uint64_t rdtsc(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static void cmd_memtest(int pages, uint64_t bytes_limit, uint64_t seconds_limit) {
    if (pages <= 0 && bytes_limit == 0 && seconds_limit == 0) pages = 16;

    uint64_t hhdm = paging_hhdm_offset();
    if (bytes_limit > 0) {
        if (pages > 0) {
            log_printf("memtest: cannot use both --size and --pages\n");
            return;
        }
        uint64_t p = bytes_limit / 4096ull;
        if (p == 0) p = 1;
        pages = (int)p;
    }

    const uint64_t pattern1 = 0xAAAAAAAAAAAAAAAAull;
    const uint64_t pattern2 = 0x5555555555555555ull;
    int errors = 0;
    uint64_t tested = 0;
    uint64_t tsc_hz = 0;
    uint64_t end_tsc = 0;
    if (seconds_limit > 0) {
        if (cpu_get_tsc_hz(&tsc_hz)) {
            end_tsc = rdtsc() + tsc_hz * seconds_limit;
        } else {
            log_printf("memtest: no TSC frequency, ignoring --time\n");
        }
    }

    if (!smp_is_initialized() && smp_cpu_count() > 1) {
        log_printf("memtest: SMP not initialized, using 1 core\n");
    }

    if (pages <= 0) {
        log_printf("memtest: no pages to test\n");
        return;
    }

    uint64_t freef = pmm_free_frames();
    uint64_t free_bytes = freef * 4096ull;
    if (bytes_limit > 0 && bytes_limit > free_bytes) {
        log_printf("memtest: requested %u bytes, only %u bytes free\n",
                   (unsigned)bytes_limit, (unsigned)free_bytes);
        return;
    }
    if ((uint64_t)pages > freef) {
        log_printf("memtest: requested %u pages, only %u free\n",
                   (unsigned)pages, (unsigned)freef);
        return;
    }

    uint64_t *frames = (uint64_t *)kmalloc((size_t)pages * sizeof(uint64_t));
    if (!frames) {
        log_printf("memtest: unable to allocate frame list\n");
        return;
    }

    int allocated = 0;
    for (; allocated < pages; ++allocated) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) break;
        frames[allocated] = phys;
    }
    if (allocated < pages) {
        log_printf("memtest: allocation failed at %u/%u pages\n",
                   (unsigned)allocated, (unsigned)pages);
    }

    for (int i = 0; i < allocated; ++i) {
        if (end_tsc && rdtsc() >= end_tsc) break;
        uint64_t phys = frames[i];
        uint64_t *p = (uint64_t *)(uintptr_t)(hhdm + phys);
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) p[j] = pattern1;
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) {
            if (p[j] != pattern1) { errors++; break; }
        }
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) p[j] = pattern2;
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) {
            if (p[j] != pattern2) { errors++; break; }
        }
        tested++;
    }

    for (int i = 0; i < allocated; ++i) {
        pmm_free_frame(frames[i]);
    }
    kfree(frames);

    log_printf("memtest: pages=%u errors=%u\n", (unsigned)tested, (unsigned)errors);
}

static void cmd_cputest(void) {
    char vendor[13];
    char brand[49];
    uint32_t family = 0, model = 0, stepping = 0;
    cpu_get_vendor(vendor);
    cpu_get_brand(brand);
    cpu_get_family_model(&family, &model, &stepping);
    uint32_t ecx = cpu_get_feature_ecx();
    uint32_t edx = cpu_get_feature_edx();

    log_printf("CPU vendor: %s\n", vendor);
    if (brand[0]) log_printf("CPU brand: %s\n", brand);
    log_printf("Family %u Model %u Stepping %u\n",
               (unsigned)family, (unsigned)model, (unsigned)stepping);

    log_printf("Features:");
    if (edx & (1u << 25)) log_printf(" SSE");
    if (edx & (1u << 26)) log_printf(" SSE2");
    if (ecx & (1u << 0))  log_printf(" SSE3");
    if (ecx & (1u << 9))  log_printf(" SSSE3");
    if (ecx & (1u << 19)) log_printf(" SSE4.1");
    if (ecx & (1u << 20)) log_printf(" SSE4.2");
    if (ecx & (1u << 28)) log_printf(" AVX");
    log_printf("\n");
}

void commands_help(void) {
    cmd_help();
}

int commands_exec(int argc, char **argv, struct command_ctx *ctx) {
    if (argc <= 0 || !argv || !ctx) return 0;
    if (str_eq(argv[0], "help")) {
        cmd_help();
    } else if (str_eq(argv[0], "clear")) {
        cmd_clear();
    } else if (str_eq(argv[0], "time")) {
        cmd_time();
    } else if (str_eq(argv[0], "mem")) {
        cmd_mem();
    } else if (str_eq(argv[0], "memtest")) {
        int pages = 0;
        uint64_t bytes = 0;
        uint64_t seconds = 0;
        for (int i = 1; i < argc; ++i) {
            if (str_eq(argv[i], "--pages") && i + 1 < argc) {
                uint64_t v = 0;
                if (str_to_u64(argv[i + 1], &v)) pages = (int)v;
                i++;
            } else if (str_eq(argv[i], "--size") && i + 1 < argc) {
                uint64_t v = 0;
                if (str_parse_size_bytes(argv[i + 1], &v)) bytes = v;
                i++;
            } else if (str_eq(argv[i], "--time") && i + 1 < argc) {
                uint64_t v = 0;
                if (str_parse_seconds(argv[i + 1], &v)) seconds = v;
                i++;
            }
        }
        cmd_memtest(pages, bytes, seconds);
    } else if (str_eq(argv[0], "cputest")) {
        cmd_cputest();
    } else if (str_eq(argv[0], "pwd")) {
        fs_pwd(*ctx->cwd);
    } else if (str_eq(argv[0], "ls")) {
        int target = *ctx->cwd;
        if (argc > 1) target = fs_resolve(*ctx->cwd, argv[1]);
        if (target < 0) log_printf("ls: not found\n");
        else fs_ls(target);
    } else if (str_eq(argv[0], "cd")) {
        if (argc < 2) {
            *ctx->cwd = fs_root();
        } else {
            const char *target_path = argv[1];
            if (target_path[0] == '~') {
                int home = fs_resolve(fs_root(), "home");
                if (home < 0) {
                    if (target_path[1] == '\0' || (target_path[1] == '/' && target_path[2] == '\0')) {
                        *ctx->cwd = fs_root();
                    } else if (target_path[1] == '/' && target_path[2] != '\0') {
                        int tgt = fs_resolve(fs_root(), &target_path[2]);
                        if (tgt < 0 || !fs_is_dir(tgt)) log_printf("cd: not a directory\n");
                        else *ctx->cwd = tgt;
                    } else {
                        *ctx->cwd = fs_root();
                    }
                } else {
                    if (target_path[1] == '\0' || (target_path[1] == '/' && target_path[2] == '\0')) {
                        *ctx->cwd = home;
                    } else if (target_path[1] == '/' && target_path[2] != '\0') {
                        int tgt = fs_resolve(home, &target_path[2]);
                        if (tgt < 0 || !fs_is_dir(tgt)) log_printf("cd: not a directory\n");
                        else *ctx->cwd = tgt;
                    } else {
                        *ctx->cwd = home;
                    }
                }
            } else {
                int target = fs_resolve(*ctx->cwd, target_path);
                if (target < 0 || !fs_is_dir(target)) {
                    log_printf("cd: not a directory\n");
                } else {
                    *ctx->cwd = target;
                }
            }
        }
    } else if (str_eq(argv[0], "cat")) {
        if (argc < 2) {
            cmd_cat(NULL, *ctx->cwd);
        } else {
            cmd_cat(argv[1], *ctx->cwd);
        }
    } else if (str_eq(argv[0], "run")) {
        if (argc < 2) {
            log_printf("run: missing path\n");
        } else {
            elf_load_and_run(argv[1]);
        }
    } else if (str_eq(argv[0], "echo")) {
        if (argc > 1) {
            for (int i = 1; i < argc; ++i) {
                log_printf("%s%s", argv[i], (i + 1 < argc) ? " " : "");
            }
        }
        log_printf("\n");
    } else if (str_eq(argv[0], "ver")) {
        cmd_ver();
    } else if (str_eq(argv[0], "debug")) {
        cmd_debug();
    } else if (str_eq(argv[0], "shutdown")) {
        cmd_shutdown();
    } else if (str_eq(argv[0], "restart")) {
        cmd_restart();
    } else {
        return 0;
    }
    return 1;
}
