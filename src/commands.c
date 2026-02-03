#include "commands.h"

#include <stddef.h>

#include "banner.h"
#include "boot_requests.h"
#include "cpu_info.h"
#include "fb_printf.h"
#include "fs_mock.h"
#include "heap.h"
#include "log.h"
#include "paging.h"
#include "pmm.h"
#include "rtc_util.h"
#include "smp.h"
#include "strutil.h"
#include "timer.h"
#include "version.h"

static void cmd_help(void) {
    log_printf("Commands: help, clear, time, mem, memtest, cputest, ls, cd, pwd, echo, ver\n");
    log_printf("  memtest [--size N] [--time T] [--pages N] [--keep]\n");
    log_printf("  sizes: 1g 512m 256k (also gb/mb/kb/gig/meg)\n");
    log_printf("  time: 20s 1min 2minutes\n");
}

static void cmd_time(void) {
    char rtc_buf[20];
    int rc = rtc_get_string(rtc_buf);
    if (rc == 0) log_printf("%s\n", rtc_buf);
    else log_printf("RTC: unavailable (err=%d)\n", rc);
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
    log_printf("BitOS v%s\n", BITOS_VERSION);
}

static void cmd_ver(void) {
    log_printf("BitOS v%s (build %s %s)\n", BITOS_VERSION, __DATE__, __TIME__);
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

static void cmd_memtest(int pages, uint64_t bytes_limit, uint64_t seconds_limit, int keep) {
    if (pages <= 0 && bytes_limit == 0 && seconds_limit == 0) pages = 16;

    uint64_t hhdm = paging_hhdm_offset();
    if (bytes_limit > 0) {
        uint64_t p = bytes_limit / 4096ull;
        if (p == 0) p = 1;
        if (p > (uint64_t)pages) pages = (int)p;
    }

    const uint64_t pattern1 = 0xAAAAAAAAAAAAAAAAull;
    const uint64_t pattern2 = 0x5555555555555555ull;
    int errors = 0;
    uint64_t tested = 0;
    uint64_t tsc_hz = 0;
    uint64_t end_tsc = 0;
    uint64_t end_pit = 0;
    if (seconds_limit > 0) {
        if (cpu_get_tsc_hz(&tsc_hz)) {
            end_tsc = rdtsc() + tsc_hz * seconds_limit;
        } else {
            uint32_t pit_hz = timer_pit_hz();
            if (pit_hz != 0) {
                end_pit = timer_pit_ticks() + (uint64_t)pit_hz * seconds_limit;
                log_printf("memtest: no TSC frequency, using PIT timer\n");
            } else {
                log_printf("memtest: no TSC frequency, ignoring --time\n");
            }
        }
    }

    if (mp_request.response && mp_request.response->cpu_count > 1 && !smp_is_initialized()) {
        log_printf("memtest: SMP not initialized, using 1 core\n");
    }

    if (pages <= 0) pages = 1;

    uint64_t *frames = NULL;
    int alloc_pages = pages;
    while (alloc_pages > 0) {
        frames = (uint64_t *)kmalloc((size_t)alloc_pages * sizeof(uint64_t));
        if (frames) break;
        alloc_pages /= 2;
    }
    if (!frames) {
        log_printf("memtest: failed to allocate frame list\n");
        return;
    }

    log_printf("memtest: allocating %u pages\n", (unsigned)alloc_pages);
    uint64_t before_used = pmm_used_frames();

    for (int i = 0; i < alloc_pages; ++i) {
        if (end_tsc && rdtsc() >= end_tsc) { alloc_pages = i; break; }
        if (end_pit && timer_pit_ticks() >= end_pit) { alloc_pages = i; break; }
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) { alloc_pages = i; break; }
        frames[i] = phys;
    }

    uint64_t after_used = pmm_used_frames();
    log_printf("memtest: PMM used before=%u after=%u\n",
               (unsigned)before_used, (unsigned)after_used);

    const uint64_t test_va = 0xffffd00000000000ull;
    for (int i = 0; i < alloc_pages; ++i) {
        if (end_tsc && rdtsc() >= end_tsc) break;
        if (end_pit && timer_pit_ticks() >= end_pit) break;

        uint64_t phys = frames[i];
        uint64_t *h = (uint64_t *)(uintptr_t)(hhdm + phys);
        if (paging_map_4k(test_va, phys, 0) != 0) {
            errors++;
            continue;
        }
        uint64_t *v = (uint64_t *)(uintptr_t)test_va;

        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) v[j] = pattern1;
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) {
            if (h[j] != pattern1) { errors++; break; }
        }
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) h[j] = pattern2;
        for (size_t j = 0; j < 4096 / sizeof(uint64_t); ++j) {
            if (v[j] != pattern2) { errors++; break; }
        }
        paging_unmap_4k(test_va);
        tested++;
    }

    if (!keep) {
        for (int i = 0; i < alloc_pages; ++i) {
            if (frames[i]) pmm_free_frame(frames[i]);
        }
        uint64_t after_free = pmm_used_frames();
        log_printf("memtest: PMM used after free=%u\n", (unsigned)after_free);
    }
    kfree(frames);

    log_printf("memtest: pages=%u errors=%u%s\n",
               (unsigned)tested, (unsigned)errors, keep ? " (kept)" : "");
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
        int keep = 0;
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
            } else if (str_eq(argv[i], "--keep")) {
                keep = 1;
            }
        }
        cmd_memtest(pages, bytes, seconds, keep);
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
            int target = fs_resolve(*ctx->cwd, argv[1]);
            if (target < 0 || !fs_is_dir(target)) {
                log_printf("cd: not a directory\n");
            } else {
                *ctx->cwd = target;
            }
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
    } else {
        return 0;
    }
    return 1;
}
