#include "sys/commands.h"

#include <stddef.h>
#include <stdint.h>

#include "drivers/video/banner.h"
#include "sys/elf_loader.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu.h"
#include "drivers/video/fb_printf.h"
#include "sys/initramfs.h"
#include "sys/vfs.h"
#include "sys/fs_mock.h"
#include "sys/ext2.h"
#include "sys/fat32.h"
#include "sys/journal.h"
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
#include "kernel/power.h"
#include "kernel/task.h"
#include "sys/acpi.h"
#include "kernel/driver_registry.h"
#include "kernel/firewall.h"

static const char *const g_commands[] = {
    "help", "clear", "time", "mem", "memtest", "cputest", "ps",
    "ls", "cd", "pwd", "cat", "run", "echo", "ver", "debug", "ping",
    "ping6", "ip6",
    "mount", "umount", "dd",
    "shutdown", "restart", "s3", "s4", "thermal", "acpi", "dmesg", "drivers",
    "fw", "pidns"
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
    log_printf("  ping <ip>\n");
    log_printf("  ping6 <ipv6>\n");
    log_printf("  ip6 addr\n");
    log_printf("  ip6 route list\n");
    log_printf("  ip6 route add <prefix>/<len> <nexthop>\n");
    log_printf("  ip6 forward <on|off>\n");
    log_printf("  ps\n");
    log_printf("  debug\n");
    log_printf("  shutdown\n");
    log_printf("  restart\n");
    log_printf("  s3 (suspend to RAM)\n");
    log_printf("  s4 (hibernate)\n");
    log_printf("  thermal (ACPI thermal status)\n");
    log_printf("  acpi (ACPI table list)\n");
    log_printf("  dmesg (dump ring buffer log)\n");
    log_printf("  drivers (driver registry status)\n");
    log_printf("  fw list|clear|add <proto> <src_ip|any> <dst_ip|any> <src_port|any> <dst_port|any> <accept|drop>\n");
    log_printf("  pidns (create a new PID namespace for this shell)\n");
    log_printf("  mount <part> <ext2|fat32>\n");
    log_printf("  umount\n");
    log_printf("  dd <src> <dst>\n");
    log_printf("  sizes: 1g 512m 256k (also gb/mb/kb/gig/meg)\n");
    log_printf("  time: 20s 1min 2minutes\n\n");

}

static int parse_ipv4(const char *s, uint8_t out[4]) {
    if (!s || !out) return 0;
    uint32_t acc = 0;
    int octet = 0;
    int digit = 0;
    for (const char *p = s; ; ++p) {
        char c = *p;
        if (c >= '0' && c <= '9') {
            acc = acc * 10u + (uint32_t)(c - '0');
            if (acc > 255u) return 0;
            digit = 1;
        } else if (c == '.' || c == '\0') {
            if (!digit) return 0;
            if (octet >= 4) return 0;
            out[octet++] = (uint8_t)acc;
            acc = 0;
            digit = 0;
            if (c == '\0') break;
        } else {
            return 0;
        }
    }
    return octet == 4;
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
    driver_log_status();
    log_printf("\n");
}

static void cmd_shutdown(void) {
    log_printf("Shutting down Bit-OS...\n");
    log_printf("Goodbye\n");
    power_shutdown();
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
    power_restart();
}

static void cmd_s3(void) {
    if (!power_suspend_s3()) {
        log_printf("S3: not supported or failed\n");
    }
}

static void cmd_s4(void) {
    if (!power_suspend_s4()) {
        log_printf("S4: not supported or failed\n");
    }
}

static void cmd_thermal(void) {
    acpi_thermal_log();
}

static void cmd_acpi(void) {
    acpi_device_discovery_log();
}

static void cmd_dmesg(void) {
    log_ring_dump();
}

static void cmd_ps(void) {
    task_dump_list();
}

static void cmd_drivers(void) {
    driver_log_status();
}

static void cmd_pidns(void) {
    struct task *t = task_current();
    if (!t) {
        log_printf("pidns: no task\n");
        return;
    }
    uint32_t ns_id = task_unshare_pidns(t);
    if (!ns_id) {
        log_printf("pidns: failed\n");
        return;
    }
    log_printf("pidns: now in namespace %u (pid=%u)\n",
               (unsigned)ns_id, (unsigned)task_pid_ns(t));
}

static int parse_ipv6(const char *s, uint8_t out[16]) {
    if (!s || !out) return 0;
    uint16_t parts[8];
    int part_count = 0;
    int dbl = -1;
    const char *p = s;
    if (*p == ':') {
        if (p[1] != ':') return 0;
        dbl = 0;
        p += 2;
    }
    while (*p) {
        if (part_count >= 8) return 0;
        if (*p == ':') {
            if (dbl >= 0) return 0;
            dbl = part_count;
            p++;
            if (*p == ':') {
                p++;
            }
            continue;
        }
        uint32_t val = 0;
        int digits = 0;
        while (*p && *p != ':') {
            char c = *p++;
            if (c >= '0' && c <= '9') val = (val << 4) | (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f') val = (val << 4) | (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = (val << 4) | (uint32_t)(c - 'A' + 10);
            else return 0;
            if (++digits > 4) return 0;
        }
        if (digits == 0) return 0;
        parts[part_count++] = (uint16_t)val;
        if (*p == ':') {
            p++;
            if (*p == ':') {
                if (dbl >= 0) return 0;
                dbl = part_count;
                p++;
            }
        }
    }
    if (dbl >= 0) {
        int zeros = 8 - part_count;
        if (zeros < 0) return 0;
        for (int i = part_count - 1; i >= dbl; --i) parts[i + zeros] = parts[i];
        for (int i = 0; i < zeros; ++i) parts[dbl + i] = 0;
        part_count = 8;
    }
    if (part_count != 8) return 0;
    for (int i = 0; i < 8; ++i) {
        out[i * 2] = (uint8_t)(parts[i] >> 8);
        out[i * 2 + 1] = (uint8_t)(parts[i] & 0xFF);
    }
    return 1;
}

static int parse_ipv6_prefix(const char *s, uint8_t out[16], uint8_t *out_len) {
    if (!s || !out || !out_len) return 0;
    const char *slash = s;
    while (*slash && *slash != '/') slash++;
    if (*slash != '/') return 0;
    char buf[64];
    size_t n = (size_t)(slash - s);
    if (n == 0 || n >= sizeof(buf)) return 0;
    for (size_t i = 0; i < n; ++i) buf[i] = s[i];
    buf[n] = '\0';
    if (!parse_ipv6(buf, out)) return 0;
    uint64_t len = 0;
    if (!str_to_u64(slash + 1, &len) || len > 128u) return 0;
    *out_len = (uint8_t)len;
    return 1;
}

static void cmd_ip6(int argc, char **argv) {
    if (argc < 2) {
        log_printf("ip6: addr | route list | route add <prefix>/<len> <nexthop> | forward <on|off>\n");
        return;
    }
    if (str_eq(argv[1], "addr")) {
        uint8_t ip6[16];
        pcnet_get_ipv6(ip6);
        log_printf("ip6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                   ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
                   ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
        return;
    }
    if (str_eq(argv[1], "route")) {
        if (argc < 3) {
            log_printf("ip6: route list|add\n");
            return;
        }
        if (str_eq(argv[2], "list")) {
            pcnet_ipv6_route_list();
            return;
        }
        if (str_eq(argv[2], "add")) {
            if (argc < 5) {
                log_printf("ip6: route add <prefix>/<len> <nexthop>\n");
                return;
            }
            uint8_t prefix[16];
            uint8_t plen = 0;
            uint8_t nexthop[16];
            if (!parse_ipv6_prefix(argv[3], prefix, &plen)) {
                log_printf("ip6: bad prefix\n");
                return;
            }
            if (!parse_ipv6(argv[4], nexthop)) {
                log_printf("ip6: bad nexthop\n");
                return;
            }
            if (pcnet_ipv6_route_add(prefix, plen, nexthop) == 0) log_printf("ip6: route added\n");
            else log_printf("ip6: route table full\n");
            return;
        }
        log_printf("ip6: route list|add\n");
        return;
    }
    if (str_eq(argv[1], "forward")) {
        if (argc < 3) {
            log_printf("ip6: forward on|off\n");
            return;
        }
        if (str_eq(argv[2], "on")) {
            pcnet_ipv6_set_forwarding(1);
            log_printf("ip6: forwarding on\n");
        } else if (str_eq(argv[2], "off")) {
            pcnet_ipv6_set_forwarding(0);
            log_printf("ip6: forwarding off\n");
        } else {
            log_printf("ip6: forward on|off\n");
        }
        return;
    }
    log_printf("ip6: addr | route list | route add <prefix>/<len> <nexthop> | forward <on|off>\n");
}

static int parse_port_any(const char *s, uint16_t *out, uint8_t *any) {
    if (!s || !out || !any) return 0;
    if (str_eq(s, "any")) {
        *any = 1;
        *out = 0;
        return 1;
    }
    uint64_t v = 0;
    if (!str_to_u64(s, &v) || v > 65535u) return 0;
    *any = 0;
    *out = (uint16_t)v;
    return 1;
}

static int parse_ip_any(const char *s, uint8_t out[4], uint8_t *any) {
    if (!s || !out || !any) return 0;
    if (str_eq(s, "any")) {
        *any = 1;
        out[0] = out[1] = out[2] = out[3] = 0;
        return 1;
    }
    if (!parse_ipv4(s, out)) return 0;
    *any = 0;
    return 1;
}

static int parse_proto(const char *s, uint8_t *out) {
    if (!s || !out) return 0;
    if (str_eq(s, "any")) { *out = FW_PROTO_ANY; return 1; }
    if (str_eq(s, "icmp")) { *out = FW_PROTO_ICMP; return 1; }
    if (str_eq(s, "tcp")) { *out = FW_PROTO_TCP; return 1; }
    if (str_eq(s, "udp")) { *out = FW_PROTO_UDP; return 1; }
    return 0;
}

static void cmd_fw(int argc, char **argv) {
    if (argc < 2) {
        log_printf("fw: list|clear|add <proto> <src_ip|any> <dst_ip|any> <src_port|any> <dst_port|any> <accept|drop>\n");
        return;
    }
    if (str_eq(argv[1], "list")) {
        firewall_log_rules();
        return;
    }
    if (str_eq(argv[1], "clear")) {
        firewall_clear();
        log_printf("fw: cleared\n");
        return;
    }
    if (str_eq(argv[1], "add")) {
        if (argc < 8) {
            log_printf("fw: usage: fw add <proto> <src_ip|any> <dst_ip|any> <src_port|any> <dst_port|any> <accept|drop>\n");
            return;
        }
        struct fw_rule r;
        if (!parse_proto(argv[2], &r.proto)) {
            log_printf("fw: bad proto\n");
            return;
        }
        if (!parse_ip_any(argv[3], r.src_ip, &r.src_ip_any)) {
            log_printf("fw: bad src ip\n");
            return;
        }
        if (!parse_ip_any(argv[4], r.dst_ip, &r.dst_ip_any)) {
            log_printf("fw: bad dst ip\n");
            return;
        }
        if (!parse_port_any(argv[5], &r.src_port, &r.src_port_any)) {
            log_printf("fw: bad src port\n");
            return;
        }
        if (!parse_port_any(argv[6], &r.dst_port, &r.dst_port_any)) {
            log_printf("fw: bad dst port\n");
            return;
        }
        if (str_eq(argv[7], "accept")) r.action = FW_ACTION_ACCEPT;
        else if (str_eq(argv[7], "drop")) r.action = FW_ACTION_DROP;
        else {
            log_printf("fw: bad action\n");
            return;
        }
        if (firewall_add_rule(&r) == 0) log_printf("fw: rule added\n");
        else log_printf("fw: rule table full\n");
        return;
    }
    log_printf("fw: unknown subcommand\n");
}

static void cmd_cat(const char *path, int cwd) {
    if (!path) {
        log_printf("cat: missing file\n");
        return;
    }
    int node = vfs_resolve(cwd, path);
    if (node < 0) {
        log_printf("cat: not found\n");
        return;
    }
    if (vfs_is_dir(node)) {
        log_printf("cat: is a directory\n");
        return;
    }

    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(node, &data, &size) || !data) {
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

static int copy_file(const char *src_path, const char *dst_path, int cwd) {
    int src = vfs_resolve(cwd, src_path);
    if (src < 0 || vfs_is_dir(src)) return -1;
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(src, &data, &size) || !data) return -1;

    int dst = vfs_resolve(cwd, dst_path);
    if (dst < 0) {
        dst = vfs_create(cwd, dst_path, 0);
        if (dst < 0) return -1;
    }
    if (vfs_is_dir(dst)) return -1;
    if (vfs_truncate(dst, 0) != 0) return -1;
    if (vfs_write_file(dst, data, size, 0) < 0) return -1;
    return 0;
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
    } else if (str_eq(argv[0], "ps")) {
        cmd_ps();
    } else if (str_eq(argv[0], "pwd")) {
        vfs_pwd(*ctx->cwd);
    } else if (str_eq(argv[0], "ls")) {
        int target = *ctx->cwd;
        if (argc > 1) target = vfs_resolve(*ctx->cwd, argv[1]);
        if (target < 0) log_printf("ls: not found\n");
        else vfs_ls(target);
    } else if (str_eq(argv[0], "cd")) {
        if (argc < 2) {
            *ctx->cwd = vfs_resolve(0, "/");
        } else {
            const char *target_path = argv[1];
            if (target_path[0] == '~') {
                int home = vfs_resolve(vfs_resolve(0, "/"), "home");
                if (home < 0) {
                    if (target_path[1] == '\0' || (target_path[1] == '/' && target_path[2] == '\0')) {
                        *ctx->cwd = vfs_resolve(0, "/");
                    } else if (target_path[1] == '/' && target_path[2] != '\0') {
                        int tgt = vfs_resolve(vfs_resolve(0, "/"), &target_path[2]);
                        if (tgt < 0 || !vfs_is_dir(tgt)) log_printf("cd: not a directory\n");
                        else *ctx->cwd = tgt;
                    } else {
                        *ctx->cwd = vfs_resolve(0, "/");
                    }
                } else {
                    if (target_path[1] == '\0' || (target_path[1] == '/' && target_path[2] == '\0')) {
                        *ctx->cwd = home;
                    } else if (target_path[1] == '/' && target_path[2] != '\0') {
                        int tgt = vfs_resolve(home, &target_path[2]);
                        if (tgt < 0 || !vfs_is_dir(tgt)) log_printf("cd: not a directory\n");
                        else *ctx->cwd = tgt;
                    } else {
                        *ctx->cwd = home;
                    }
                }
            } else {
                int target = vfs_resolve(*ctx->cwd, target_path);
                if (target < 0 || !vfs_is_dir(target)) {
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
            int eargc = argc - 1;
            char **eargv = &argv[1];
            elf_load_and_run(argv[1], eargc, eargv, NULL);
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
    } else if (str_eq(argv[0], "ping")) {
        if (argc < 2) {
            log_printf("ping: missing ip\n");
        } else {
            uint8_t ip[4];
            if (!parse_ipv4(argv[1], ip)) {
                log_printf("ping: invalid ip\n");
            } else {
                pcnet_ping(ip);
            }
        }
    } else if (str_eq(argv[0], "ping6")) {
        if (argc < 2) {
            log_printf("ping6: missing ipv6\n");
        } else {
            uint8_t ip6[16];
            if (!parse_ipv6(argv[1], ip6)) {
                log_printf("ping6: invalid ipv6\n");
            } else {
                pcnet_ping6(ip6);
            }
        }
    } else if (str_eq(argv[0], "ip6")) {
        cmd_ip6(argc, argv);
    } else if (str_eq(argv[0], "shutdown")) {
        cmd_shutdown();
    } else if (str_eq(argv[0], "restart")) {
        cmd_restart();
    } else if (str_eq(argv[0], "s3")) {
        cmd_s3();
    } else if (str_eq(argv[0], "s4")) {
        cmd_s4();
    } else if (str_eq(argv[0], "thermal")) {
        cmd_thermal();
    } else if (str_eq(argv[0], "acpi")) {
        cmd_acpi();
    } else if (str_eq(argv[0], "dmesg")) {
        cmd_dmesg();
    } else if (str_eq(argv[0], "drivers")) {
        cmd_drivers();
    } else if (str_eq(argv[0], "fw")) {
        cmd_fw(argc, argv);
    } else if (str_eq(argv[0], "pidns")) {
        cmd_pidns();
    } else if (str_eq(argv[0], "mount")) {
        if (argc < 3) {
            log_printf("mount: usage: mount <part> <ext2|fat32>\n");
        } else {
            uint64_t part = 0;
            if (!str_to_u64(argv[1], &part)) {
                log_printf("mount: bad partition\n");
            } else if (str_eq(argv[2], "ext2")) {
                if (ext2_init_from_partition((uint32_t)part) == 0) {
                    vfs_set_root(VFS_BACKEND_EXT2, ext2_root());
                    journal_init();
                    log_printf("mounted ext2 partition %u\n", (unsigned)part);
                } else {
                    log_printf("mount: ext2 init failed\n");
                }
            } else if (str_eq(argv[2], "fat32")) {
                if (fat32_init_from_partition((uint32_t)part) == 0) {
                    vfs_set_root(VFS_BACKEND_FAT32, fat32_root());
                    log_printf("mounted fat32 partition %u\n", (unsigned)part);
                } else {
                    log_printf("mount: fat32 init failed\n");
                }
            } else {
                log_printf("mount: unknown fs\n");
            }
        }
    } else if (str_eq(argv[0], "umount")) {
        if (initramfs_available()) {
            vfs_set_root(VFS_BACKEND_INITRAMFS, initramfs_root());
            log_printf("root switched to initramfs\n");
        } else {
            vfs_set_root(VFS_BACKEND_MOCK, fs_root());
            log_printf("root switched to mock\n");
        }
    } else if (str_eq(argv[0], "dd")) {
        if (argc < 3) {
            log_printf("dd: usage: dd <src> <dst>\n");
        } else {
            if (copy_file(argv[1], argv[2], *ctx->cwd) == 0) log_printf("dd: ok\n");
            else log_printf("dd: failed\n");
        }
    } else {
        return 0;
    }
    return 1;
}
