#include "sys/pseudofs.h"

#include <stddef.h>

#include "lib/compat.h"
#include "lib/log.h"
#include "lib/strutil.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/cpu_info.h"
#include "kernel/meminfo.h"
#include "kernel/task.h"
#include "kernel/time.h"
#include "kernel/driver_registry.h"
#include "kernel/rng.h"
#include "kernel/profiler.h"
#include "lib/version.h"

static char g_buf[2048];

struct feature_bit {
    uint32_t bit;
    const char *name;
};

static const struct feature_bit g_feat_edx[] = {
    { 0, "fpu" }, { 3, "pse" }, { 4, "tsc" }, { 5, "msr" },
    { 6, "pae" }, { 7, "mce" }, { 8, "cx8" }, { 9, "apic" },
    { 11, "sep" }, { 12, "mtrr" }, { 13, "pge" }, { 14, "mca" },
    { 15, "cmov" }, { 16, "pat" }, { 17, "pse36" }, { 19, "clflush" },
    { 23, "mmx" }, { 24, "fxsr" }, { 25, "sse" }, { 26, "sse2" }
};

static const struct feature_bit g_feat_ecx[] = {
    { 0, "sse3" }, { 1, "pclmulqdq" }, { 9, "ssse3" }, { 12, "fma" },
    { 13, "cx16" }, { 19, "sse4_1" }, { 20, "sse4_2" }, { 21, "x2apic" },
    { 22, "movbe" }, { 23, "popcnt" }, { 25, "aes" }, { 26, "xsave" },
    { 27, "osxsave" }, { 28, "avx" }, { 30, "rdrand" }
};

static const struct feature_bit g_feat_ext_edx[] = {
    { 11, "syscall" }, { 20, "nx" }, { 29, "lm" }
};

static const struct feature_bit g_feat_ext_ecx[] = {
    { 0, "lahf_lm" }, { 2, "svm" }, { 6, "sse4a" }, { 11, "xop" },
    { 16, "fma4" }, { 21, "tbm" }, { 5, "abm" }
};

static const char *fs_name(int fs_id) {
    switch (fs_id) {
    case PSEUDOFS_DEV: return "dev";
    case PSEUDOFS_PROC: return "proc";
    case PSEUDOFS_SYS: return "sys";
    default: return "fs";
    }
}

int pseudofs_is_ready(int fs_id) {
    (void)fs_id;
    return 1;
}

int pseudofs_root(int fs_id) {
    (void)fs_id;
    return 0;
}

static int node_for_path(int fs_id, const char *path) {
    if (!path || path[0] == '\0' || str_eq(path, "/")) return 0;
    if (path[0] == '/') path++;
    if (fs_id == PSEUDOFS_DEV) {
        if (str_eq(path, "null")) return PSEUDOFS_DEV_NULL;
        if (str_eq(path, "tty0")) return PSEUDOFS_DEV_TTY0;
        if (str_eq(path, "random")) return PSEUDOFS_DEV_RANDOM;
        if (str_eq(path, "urandom")) return PSEUDOFS_DEV_URANDOM;
    } else if (fs_id == PSEUDOFS_PROC) {
        if (str_eq(path, "uptime")) return 1;
        if (str_eq(path, "meminfo")) return 2;
        if (str_eq(path, "tasks")) return 3;
        if (str_eq(path, "cpuinfo")) return 4;
        if (str_eq(path, "stat")) return 5;
    } else if (fs_id == PSEUDOFS_SYS) {
        if (str_eq(path, "build")) return 1;
        if (str_eq(path, "version")) return 2;
        if (str_eq(path, "drivers")) return 3;
    }
    return -1;
}

int pseudofs_resolve(int fs_id, int cwd, const char *path) {
    (void)cwd;
    return node_for_path(fs_id, path);
}

int pseudofs_is_dir(int fs_id, int node) {
    (void)fs_id;
    return node == 0;
}

static void append_char(char **dst, size_t *remain, char c) {
    if (!dst || !*dst || !remain || *remain == 0) return;
    **dst = c;
    (*dst)++;
    (*remain)--;
}

static void append_str(char **dst, size_t *remain, const char *s) {
    if (!dst || !*dst || !remain || !s) return;
    while (*s && *remain > 0) {
        **dst = *s++;
        (*dst)++;
        (*remain)--;
    }
}

static void append_u64(char **dst, size_t *remain, uint64_t v) {
    char tmp[32];
    size_t n = 0;
    if (v == 0) {
        append_char(dst, remain, '0');
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0) {
        append_char(dst, remain, tmp[--n]);
    }
}

static void append_u32(char **dst, size_t *remain, uint32_t v) {
    append_u64(dst, remain, (uint64_t)v);
}

static void append_feature(char **dst, size_t *remain, int *first, const char *name) {
    if (!dst || !*dst || !remain || !name) return;
    if (!*first) append_char(dst, remain, ' ');
    append_str(dst, remain, name);
    *first = 0;
}

static void append_feature_bits(char **dst, size_t *remain, int *first,
                                uint32_t value, const struct feature_bit *bits, size_t count) {
    if (!bits) return;
    for (size_t i = 0; i < count; ++i) {
        if (value & (1u << bits[i].bit)) {
            append_feature(dst, remain, first, bits[i].name);
        }
    }
}

int pseudofs_read_file(int fs_id, int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node == 0) return 0;
    char *w = g_buf;
    size_t remain = sizeof(g_buf) - 1;
    if (fs_id == PSEUDOFS_PROC) {
        if (node == 1) {
            uint64_t ticks = timer_uptime_ticks();
            uint64_t hz = 100;
            uint64_t ms = (ticks * 1000ull) / (hz ? hz : 1);
            append_str(&w, &remain, "uptime=");
            append_u64(&w, &remain, ms);
            append_str(&w, &remain, "ms\n");
        } else if (node == 2) {
            uint64_t usable = get_usable_ram_bytes();
            append_str(&w, &remain, "usable=");
            append_u64(&w, &remain, usable);
            append_char(&w, &remain, '\n');
        } else if (node == 3) {
            size_t used = task_format_list(task_current(), w, remain);
            w += used;
            remain = (remain > used) ? (remain - used) : 0;
        } else if (node == 4) {
            char vendor[13];
            char brand[49];
            char hv[13];
            uint32_t family = 0, model = 0, stepping = 0;
            cpu_get_vendor(vendor);
            cpu_get_brand(brand);
            cpu_get_family_model(&family, &model, &stepping);
            append_str(&w, &remain, "vendor_id\t: ");
            append_str(&w, &remain, vendor);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "model name\t: ");
            append_str(&w, &remain, brand[0] ? brand : "unknown");
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "family\t\t: ");
            append_u32(&w, &remain, family);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "model\t\t: ");
            append_u32(&w, &remain, model);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "stepping\t: ");
            append_u32(&w, &remain, stepping);
            append_char(&w, &remain, '\n');

            uint64_t tsc_hz = 0;
            if (cpu_get_tsc_hz(&tsc_hz)) {
                append_str(&w, &remain, "tsc_hz\t\t: ");
                append_u64(&w, &remain, tsc_hz);
                append_char(&w, &remain, '\n');
            }

            if (cpu_has_hypervisor()) {
                cpu_get_hypervisor_vendor(hv);
                append_str(&w, &remain, "hypervisor\t: ");
                append_str(&w, &remain, hv[0] ? hv : "present");
                append_char(&w, &remain, '\n');
            }

            uint32_t ecx = cpu_get_feature_ecx();
            uint32_t edx = cpu_get_feature_edx();
            uint32_t eecx = cpu_get_ext_feature_ecx();
            uint32_t eedx = cpu_get_ext_feature_edx();
            append_str(&w, &remain, "flags\t\t: ");
            int first = 1;
            append_feature_bits(&w, &remain, &first, edx, g_feat_edx, sizeof(g_feat_edx) / sizeof(g_feat_edx[0]));
            append_feature_bits(&w, &remain, &first, ecx, g_feat_ecx, sizeof(g_feat_ecx) / sizeof(g_feat_ecx[0]));
            append_feature_bits(&w, &remain, &first, eedx, g_feat_ext_edx, sizeof(g_feat_ext_edx) / sizeof(g_feat_ext_edx[0]));
            append_feature_bits(&w, &remain, &first, eecx, g_feat_ext_ecx, sizeof(g_feat_ext_ecx) / sizeof(g_feat_ext_ecx[0]));
            append_char(&w, &remain, '\n');
        } else if (node == 5) {
            uint64_t ticks = timer_uptime_ticks();
            append_str(&w, &remain, "cpu 0 0 ");
            append_u64(&w, &remain, ticks);
            append_str(&w, &remain, " 0 0 0 0\n");

            uint64_t ctxt = profiler_get(PROF_CTX_SWITCHES);
            uint64_t syscalls = profiler_get(PROF_SYSCALLS);
            uint64_t faults = profiler_get(PROF_PAGE_FAULTS);
            uint64_t evicts = profiler_get(PROF_TASK_EVICTS);
            append_str(&w, &remain, "ctxt ");
            append_u64(&w, &remain, ctxt);
            append_char(&w, &remain, '\n');
            uint64_t btime = time_now_epoch();
            append_str(&w, &remain, "btime ");
            append_u64(&w, &remain, btime);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "processes ");
            append_u32(&w, &remain, task_total_created());
            append_char(&w, &remain, '\n');
            uint32_t total = 0, running = 0, blocked = 0, dead = 0;
            task_get_counts(&total, &running, &blocked, &dead);
            append_str(&w, &remain, "procs_running ");
            append_u32(&w, &remain, running);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "procs_blocked ");
            append_u32(&w, &remain, blocked);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "bitos_syscalls ");
            append_u64(&w, &remain, syscalls);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "bitos_page_faults ");
            append_u64(&w, &remain, faults);
            append_char(&w, &remain, '\n');
            append_str(&w, &remain, "bitos_task_evicts ");
            append_u64(&w, &remain, evicts);
            append_char(&w, &remain, '\n');
        }
    } else if (fs_id == PSEUDOFS_SYS) {
        if (node == 1) {
            append_str(&w, &remain, "build=");
            append_str(&w, &remain, __DATE__ " " __TIME__);
            append_char(&w, &remain, '\n');
        } else if (node == 2) {
            append_str(&w, &remain, "version=");
            append_str(&w, &remain, BITOS_VERSION);
            append_char(&w, &remain, '\n');
        } else if (node == 3) {
            size_t used = driver_registry_format(w, remain);
            w += used;
            remain = (remain > used) ? (remain - used) : 0;
        }
    } else if (fs_id == PSEUDOFS_DEV) {
        if (node == PSEUDOFS_DEV_NULL) {
            append_str(&w, &remain, "null\n");
        } else if (node == PSEUDOFS_DEV_TTY0) {
            append_str(&w, &remain, "tty0\n");
        } else if (node == PSEUDOFS_DEV_RANDOM || node == PSEUDOFS_DEV_URANDOM) {
            size_t n = remain > 64 ? 64 : remain;
            rng_fill(g_buf, n);
            w = g_buf + n;
            remain = (remain > n) ? (remain - n) : 0;
        }
    }
    *w = '\0';
    *data = (const uint8_t *)g_buf;
    *size = (uint64_t)(w - g_buf);
    return (*size > 0);
}

void pseudofs_pwd(int fs_id, int cwd) {
    if (cwd == 0) {
        log_printf("/\n");
        return;
    }
    const char *base = fs_name(fs_id);
    if (fs_id == PSEUDOFS_DEV) {
        if (cwd == PSEUDOFS_DEV_NULL) log_printf("/%s/null\n", base);
        else if (cwd == PSEUDOFS_DEV_TTY0) log_printf("/%s/tty0\n", base);
        else if (cwd == PSEUDOFS_DEV_RANDOM) log_printf("/%s/random\n", base);
        else if (cwd == PSEUDOFS_DEV_URANDOM) log_printf("/%s/urandom\n", base);
        else log_printf("/%s\n", base);
    } else if (fs_id == PSEUDOFS_PROC) {
        if (cwd == 1) log_printf("/%s/uptime\n", base);
        else if (cwd == 2) log_printf("/%s/meminfo\n", base);
        else if (cwd == 3) log_printf("/%s/tasks\n", base);
        else if (cwd == 4) log_printf("/%s/cpuinfo\n", base);
        else if (cwd == 5) log_printf("/%s/stat\n", base);
        else log_printf("/%s\n", base);
    } else if (fs_id == PSEUDOFS_SYS) {
        if (cwd == 1) log_printf("/%s/build\n", base);
        else if (cwd == 2) log_printf("/%s/version\n", base);
        else if (cwd == 3) log_printf("/%s/drivers\n", base);
        else log_printf("/%s\n", base);
    } else {
        log_printf("/%s\n", base);
    }
}

void pseudofs_ls(int fs_id, int node) {
    if (node != 0) {
        pseudofs_pwd(fs_id, node);
        return;
    }
    if (fs_id == PSEUDOFS_DEV) {
        log_printf("null tty0 random urandom\n");
    } else if (fs_id == PSEUDOFS_PROC) {
        log_printf("uptime meminfo tasks cpuinfo stat\n");
    } else if (fs_id == PSEUDOFS_SYS) {
        log_printf("build version drivers\n");
    }
}
