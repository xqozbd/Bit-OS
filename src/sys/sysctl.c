#include "sys/sysctl.h"

#include <stdint.h>

#include "lib/strutil.h"
#include "lib/log.h"
#include "kernel/watchdog.h"
#include "drivers/net/pcnet.h"
#include "kernel/swap.h"
#include "sys/acpi.h"
#include "drivers/ps2/keyboard.h"
#include "kernel/heap.h"
#include "kernel/slab.h"
#include "kernel/time.h"
#include "kernel/profiler.h"
#include "kernel/task.h"

enum { SYSCTL_MAX = 32 };

struct sysctl_entry {
    const char *key;
    sysctl_get_fn get;
    sysctl_set_fn set;
    void *ctx;
};

static struct sysctl_entry g_sysctls[SYSCTL_MAX];
static size_t g_sysctl_count = 0;

static void u32_to_str(uint32_t v, char *out, size_t max) {
    if (!out || max == 0) return;
    char tmp[16];
    size_t n = 0;
    if (v == 0) {
        if (max > 1) { out[0] = '0'; out[1] = '\0'; }
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    size_t i = 0;
    while (n && i + 1 < max) {
        out[i++] = tmp[--n];
    }
    out[i] = '\0';
}

static void u64_to_str(uint64_t v, char *out, size_t max) {
    if (!out || max == 0) return;
    char tmp[24];
    size_t n = 0;
    if (v == 0) {
        if (max > 1) { out[0] = '0'; out[1] = '\0'; }
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    size_t i = 0;
    while (n && i + 1 < max) {
        out[i++] = tmp[--n];
    }
    out[i] = '\0';
}

static const char *level_to_str(enum log_level lvl) {
    switch (lvl) {
        case LOG_DEBUG: return "debug";
        case LOG_INFO: return "info";
        case LOG_WARN: return "warn";
        case LOG_ERROR: return "error";
        case LOG_NONE: return "none";
        default: return "info";
    }
}

static int str_to_level(const char *s, enum log_level *out) {
    if (!s || !out) return 0;
    if (str_eq(s, "debug") || str_eq(s, "verbose")) { *out = LOG_DEBUG; return 1; }
    if (str_eq(s, "info")) { *out = LOG_INFO; return 1; }
    if (str_eq(s, "warn")) { *out = LOG_WARN; return 1; }
    if (str_eq(s, "error")) { *out = LOG_ERROR; return 1; }
    if (str_eq(s, "none")) { *out = LOG_NONE; return 1; }
    return 0;
}

static int sysctl_get_log_level(char *out, size_t max, void *ctx) {
    (void)ctx;
    const char *s = level_to_str(log_get_level());
    size_t i = 0;
    while (s[i] && i + 1 < max) {
        out[i] = s[i];
        i++;
    }
    if (max) out[i] = '\0';
    return 1;
}

static int sysctl_set_log_level(const char *val, void *ctx) {
    (void)ctx;
    enum log_level lvl;
    if (!str_to_level(val, &lvl)) return 0;
    log_set_level(lvl);
    return 1;
}

static const char *watchdog_mode_str(void) {
    int mode = watchdog_get_mode();
    switch (mode) {
        case 3: return "off";
        case 2: return "log";
        case 1: return "reboot";
        default: return "halt";
    }
}

static int sysctl_get_watchdog(char *out, size_t max, void *ctx) {
    (void)ctx;
    const char *s = watchdog_mode_str();
    size_t i = 0;
    while (s[i] && i + 1 < max) {
        out[i] = s[i];
        i++;
    }
    if (max) out[i] = '\0';
    return 1;
}

static int sysctl_set_watchdog(const char *val, void *ctx) {
    (void)ctx;
    watchdog_set_mode(val);
    return 1;
}

static int sysctl_get_ipv6_forward(char *out, size_t max, void *ctx) {
    (void)ctx;
    uint32_t v = (uint32_t)(pcnet_ipv6_get_forwarding() ? 1 : 0);
    u32_to_str(v, out, max);
    return 1;
}

static int sysctl_set_ipv6_forward(const char *val, void *ctx) {
    (void)ctx;
    if (str_eq(val, "1") || str_eq(val, "on") || str_eq(val, "true")) {
        pcnet_ipv6_set_forwarding(1);
        return 1;
    }
    if (str_eq(val, "0") || str_eq(val, "off") || str_eq(val, "false")) {
        pcnet_ipv6_set_forwarding(0);
        return 1;
    }
    return 0;
}

static int sysctl_get_swap_enabled(char *out, size_t max, void *ctx) {
    (void)ctx;
    uint32_t v = (uint32_t)(swap_enabled() ? 1 : 0);
    u32_to_str(v, out, max);
    return 1;
}

static int sysctl_get_swap_slots(char *out, size_t max, void *ctx) {
    (void)ctx;
    uint32_t v = (uint32_t)swap_total_slots();
    u32_to_str(v, out, max);
    return 1;
}

static int sysctl_get_acpi_temp(char *out, size_t max, void *ctx) {
    (void)ctx;
    int temp_c = 0;
    if (!acpi_thermal_read_temp_c(&temp_c)) return 0;
    if (temp_c < 0) temp_c = 0;
    u32_to_str((uint32_t)temp_c, out, max);
    return 1;
}

static int sysctl_get_acpi_tz_present(char *out, size_t max, void *ctx) {
    (void)ctx;
    const struct acpi_thermal_info *info = acpi_thermal_info();
    uint32_t v = (info && info->has_tz) ? 1u : 0u;
    u32_to_str(v, out, max);
    return 1;
}

static int sysctl_get_kbd_layout(char *out, size_t max, void *ctx) {
    (void)ctx;
    const char *s = kb_layout_name(kb_get_layout());
    size_t i = 0;
    while (s[i] && i + 1 < max) {
        out[i] = s[i];
        i++;
    }
    if (max) out[i] = '\0';
    return 1;
}

static int sysctl_set_kbd_layout(const char *val, void *ctx) {
    (void)ctx;
    return kb_set_layout_name(val);
}

static int sysctl_get_kbd_repeat_delay(char *out, size_t max, void *ctx) {
    (void)ctx;
    uint32_t delay_ms = 0;
    kb_get_repeat(&delay_ms, NULL);
    u32_to_str(delay_ms, out, max);
    return 1;
}

static int sysctl_set_kbd_repeat_delay(const char *val, void *ctx) {
    (void)ctx;
    uint64_t v = 0;
    if (!str_to_u64(val, &v)) return 0;
    uint32_t delay_ms = (v > 60000u) ? 60000u : (uint32_t)v;
    uint32_t rate_hz = 0;
    kb_get_repeat(NULL, &rate_hz);
    kb_set_repeat(delay_ms, rate_hz);
    return 1;
}

static int sysctl_get_kbd_repeat_rate(char *out, size_t max, void *ctx) {
    (void)ctx;
    uint32_t rate_hz = 0;
    kb_get_repeat(NULL, &rate_hz);
    u32_to_str(rate_hz, out, max);
    return 1;
}

static int sysctl_set_kbd_repeat_rate(const char *val, void *ctx) {
    (void)ctx;
    uint64_t v = 0;
    if (!str_to_u64(val, &v)) return 0;
    uint32_t rate_hz = (v > 50u) ? 50u : (uint32_t)v;
    uint32_t delay_ms = 0;
    kb_get_repeat(&delay_ms, NULL);
    kb_set_repeat(delay_ms, rate_hz);
    return 1;
}

static int sysctl_get_heap_active_bytes(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.active_bytes, out, max);
    return 1;
}

static int sysctl_get_heap_active_allocs(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.active_allocs, out, max);
    return 1;
}

static int sysctl_get_heap_peak_bytes(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.peak_bytes, out, max);
    return 1;
}

static int sysctl_get_heap_total_allocs(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.allocs, out, max);
    return 1;
}

static int sysctl_get_heap_total_frees(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.frees, out, max);
    return 1;
}

static int sysctl_get_heap_failures(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct heap_stats s;
    heap_get_stats(&s);
    u64_to_str(s.failures, out, max);
    return 1;
}

static int sysctl_get_slab_active_bytes(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct slab_stats s;
    slab_get_stats(&s);
    u64_to_str(s.active_bytes, out, max);
    return 1;
}

static int sysctl_get_slab_active_allocs(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct slab_stats s;
    slab_get_stats(&s);
    u64_to_str(s.active_allocs, out, max);
    return 1;
}

static int sysctl_get_slab_peak_bytes(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct slab_stats s;
    slab_get_stats(&s);
    u64_to_str(s.peak_bytes, out, max);
    return 1;
}

static int sysctl_get_slab_total_allocs(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct slab_stats s;
    slab_get_stats(&s);
    u64_to_str(s.allocs, out, max);
    return 1;
}

static int sysctl_get_slab_total_frees(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct slab_stats s;
    slab_get_stats(&s);
    u64_to_str(s.frees, out, max);
    return 1;
}

static int sysctl_get_disk_quota(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct task *t = task_current();
    u64_to_str(t ? t->disk_quota_bytes : 0, out, max);
    return 1;
}

static int sysctl_set_disk_quota(const char *val, void *ctx) {
    (void)ctx;
    struct task *t = task_current();
    if (!t) return 0;
    uint64_t v = 0;
    if (!str_to_u64(val, &v)) return 0;
    t->disk_quota_bytes = v;
    return 1;
}

static int sysctl_get_disk_used(char *out, size_t max, void *ctx) {
    (void)ctx;
    struct task *t = task_current();
    u64_to_str(t ? t->disk_used_bytes : 0, out, max);
    return 1;
}

static int sysctl_get_prof_ctx(char *out, size_t max, void *ctx) {
    (void)ctx;
    u64_to_str(profiler_get(PROF_CTX_SWITCHES), out, max);
    return 1;
}

static int sysctl_get_prof_syscalls(char *out, size_t max, void *ctx) {
    (void)ctx;
    u64_to_str(profiler_get(PROF_SYSCALLS), out, max);
    return 1;
}

static int sysctl_get_prof_faults(char *out, size_t max, void *ctx) {
    (void)ctx;
    u64_to_str(profiler_get(PROF_PAGE_FAULTS), out, max);
    return 1;
}

static int sysctl_get_prof_evicts(char *out, size_t max, void *ctx) {
    (void)ctx;
    u64_to_str(profiler_get(PROF_TASK_EVICTS), out, max);
    return 1;
}

static int sysctl_get_tz_offset(char *out, size_t max, void *ctx) {
    (void)ctx;
    int v = time_get_tz_offset_minutes();
    if (v < 0) {
        if (max < 2) return 0;
        out[0] = '-';
        v = -v;
        u32_to_str((uint32_t)v, out + 1, max - 1);
        return 1;
    }
    u32_to_str((uint32_t)v, out, max);
    return 1;
}

static int sysctl_set_tz_offset(const char *val, void *ctx) {
    (void)ctx;
    if (!val) return 0;
    int sign = 1;
    size_t idx = 0;
    if (val[0] == '-') { sign = -1; idx = 1; }
    uint64_t v = 0;
    if (!str_to_u64(val + idx, &v)) return 0;
    if (v > 1440u) v = 1440u;
    time_set_tz_offset_minutes((int)(sign * (int)v));
    return 1;
}

void sysctl_init(void) {
    g_sysctl_count = 0;
    sysctl_register("log.level", sysctl_get_log_level, sysctl_set_log_level, NULL);
    sysctl_register("watchdog.mode", sysctl_get_watchdog, sysctl_set_watchdog, NULL);
    sysctl_register("net.ipv6.forwarding", sysctl_get_ipv6_forward, sysctl_set_ipv6_forward, NULL);
    sysctl_register("vm.swap.enabled", sysctl_get_swap_enabled, NULL, NULL);
    sysctl_register("vm.swap.slots", sysctl_get_swap_slots, NULL, NULL);
    sysctl_register("acpi.thermal.present", sysctl_get_acpi_tz_present, NULL, NULL);
    sysctl_register("acpi.thermal.temp_c", sysctl_get_acpi_temp, NULL, NULL);
    sysctl_register("kbd.layout", sysctl_get_kbd_layout, sysctl_set_kbd_layout, NULL);
    sysctl_register("kbd.repeat_delay_ms", sysctl_get_kbd_repeat_delay, sysctl_set_kbd_repeat_delay, NULL);
    sysctl_register("kbd.repeat_rate_hz", sysctl_get_kbd_repeat_rate, sysctl_set_kbd_repeat_rate, NULL);
    sysctl_register("time.tz_offset_min", sysctl_get_tz_offset, sysctl_set_tz_offset, NULL);
    sysctl_register("vm.heap.active_bytes", sysctl_get_heap_active_bytes, NULL, NULL);
    sysctl_register("vm.heap.active_allocs", sysctl_get_heap_active_allocs, NULL, NULL);
    sysctl_register("vm.heap.peak_bytes", sysctl_get_heap_peak_bytes, NULL, NULL);
    sysctl_register("vm.heap.total_allocs", sysctl_get_heap_total_allocs, NULL, NULL);
    sysctl_register("vm.heap.total_frees", sysctl_get_heap_total_frees, NULL, NULL);
    sysctl_register("vm.heap.failures", sysctl_get_heap_failures, NULL, NULL);
    sysctl_register("vm.slab.active_bytes", sysctl_get_slab_active_bytes, NULL, NULL);
    sysctl_register("vm.slab.active_allocs", sysctl_get_slab_active_allocs, NULL, NULL);
    sysctl_register("vm.slab.peak_bytes", sysctl_get_slab_peak_bytes, NULL, NULL);
    sysctl_register("vm.slab.total_allocs", sysctl_get_slab_total_allocs, NULL, NULL);
    sysctl_register("vm.slab.total_frees", sysctl_get_slab_total_frees, NULL, NULL);
    sysctl_register("kern.disk.quota_bytes", sysctl_get_disk_quota, sysctl_set_disk_quota, NULL);
    sysctl_register("kern.disk.used_bytes", sysctl_get_disk_used, NULL, NULL);
    sysctl_register("kern.prof.ctx_switches", sysctl_get_prof_ctx, NULL, NULL);
    sysctl_register("kern.prof.syscalls", sysctl_get_prof_syscalls, NULL, NULL);
    sysctl_register("kern.prof.page_faults", sysctl_get_prof_faults, NULL, NULL);
    sysctl_register("kern.prof.task_evicts", sysctl_get_prof_evicts, NULL, NULL);
}

int sysctl_register(const char *key, sysctl_get_fn get, sysctl_set_fn set, void *ctx) {
    if (!key || !get || g_sysctl_count >= SYSCTL_MAX) return 0;
    g_sysctls[g_sysctl_count].key = key;
    g_sysctls[g_sysctl_count].get = get;
    g_sysctls[g_sysctl_count].set = set;
    g_sysctls[g_sysctl_count].ctx = ctx;
    g_sysctl_count++;
    return 1;
}

static struct sysctl_entry *sysctl_find(const char *key) {
    for (size_t i = 0; i < g_sysctl_count; ++i) {
        if (str_eq(g_sysctls[i].key, key)) return &g_sysctls[i];
    }
    return NULL;
}

int sysctl_get(const char *key, char *out, size_t max) {
    if (!key || !out || max == 0) return 0;
    struct sysctl_entry *e = sysctl_find(key);
    if (!e || !e->get) return 0;
    return e->get(out, max, e->ctx);
}

int sysctl_set(const char *key, const char *val) {
    if (!key || !val) return 0;
    struct sysctl_entry *e = sysctl_find(key);
    if (!e || !e->set) return 0;
    return e->set(val, e->ctx);
}

void sysctl_dump(void) {
    char buf[64];
    for (size_t i = 0; i < g_sysctl_count; ++i) {
        const char *k = g_sysctls[i].key;
        buf[0] = '\0';
        if (g_sysctls[i].get) {
            g_sysctls[i].get(buf, sizeof(buf), g_sysctls[i].ctx);
        }
        log_printf("%s = %s\n", k, buf[0] ? buf : "(n/a)");
    }
}
