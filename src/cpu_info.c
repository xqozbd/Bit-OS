#include "cpu_info.h"

#include "compat.h"
#include "timer.h"

static uint64_t g_tsc_hz_cached = 0;

static inline uint64_t rdtsc(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                          uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("cpuid"
                      : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                      : "a"(leaf), "c"(subleaf));
#else
    *a = *b = *c = *d = 0;
    (void)leaf; (void)subleaf;
#endif
}

void cpu_get_vendor(char out[13]) {
    uint32_t a, b, c, d;
    cpuid(0, 0, &a, &b, &c, &d);
    out[0] = (char)(b & 0xFF);
    out[1] = (char)((b >> 8) & 0xFF);
    out[2] = (char)((b >> 16) & 0xFF);
    out[3] = (char)((b >> 24) & 0xFF);
    out[4] = (char)(d & 0xFF);
    out[5] = (char)((d >> 8) & 0xFF);
    out[6] = (char)((d >> 16) & 0xFF);
    out[7] = (char)((d >> 24) & 0xFF);
    out[8] = (char)(c & 0xFF);
    out[9] = (char)((c >> 8) & 0xFF);
    out[10] = (char)((c >> 16) & 0xFF);
    out[11] = (char)((c >> 24) & 0xFF);
    out[12] = '\0';
}

void cpu_get_brand(char out[49]) {
    uint32_t a, b, c, d;
    cpuid(0x80000000u, 0, &a, &b, &c, &d);
    if (a < 0x80000004u) {
        out[0] = '\0';
        return;
    }
    uint32_t regs[12];
    for (uint32_t i = 0; i < 3; ++i) {
        cpuid(0x80000002u + i, 0, &regs[i * 4 + 0], &regs[i * 4 + 1],
              &regs[i * 4 + 2], &regs[i * 4 + 3]);
    }
    for (int i = 0; i < 12; ++i) {
        out[i * 4 + 0] = (char)(regs[i] & 0xFF);
        out[i * 4 + 1] = (char)((regs[i] >> 8) & 0xFF);
        out[i * 4 + 2] = (char)((regs[i] >> 16) & 0xFF);
        out[i * 4 + 3] = (char)((regs[i] >> 24) & 0xFF);
    }
    out[48] = '\0';
}

void cpu_get_family_model(uint32_t *family, uint32_t *model, uint32_t *stepping) {
    uint32_t a, b, c, d;
    cpuid(1, 0, &a, &b, &c, &d);
    uint32_t base_family = (a >> 8) & 0xF;
    uint32_t base_model = (a >> 4) & 0xF;
    uint32_t ext_family = (a >> 20) & 0xFF;
    uint32_t ext_model = (a >> 16) & 0xF;
    uint32_t fam = base_family;
    uint32_t mod = base_model;
    if (base_family == 0x0F) fam = base_family + ext_family;
    if (base_family == 0x06 || base_family == 0x0F) mod = base_model + (ext_model << 4);
    if (family) *family = fam;
    if (model) *model = mod;
    if (stepping) *stepping = a & 0xF;
}

uint32_t cpu_get_feature_ecx(void) {
    uint32_t a, b, c, d;
    cpuid(1, 0, &a, &b, &c, &d);
    return c;
}

uint32_t cpu_get_feature_edx(void) {
    uint32_t a, b, c, d;
    cpuid(1, 0, &a, &b, &c, &d);
    return d;
}

uint32_t cpu_get_ext_feature_ecx(void) {
    uint32_t a, b, c, d;
    cpuid(0x80000001u, 0, &a, &b, &c, &d);
    return c;
}

uint32_t cpu_get_ext_feature_edx(void) {
    uint32_t a, b, c, d;
    cpuid(0x80000001u, 0, &a, &b, &c, &d);
    return d;
}

int cpu_get_tsc_hz(uint64_t *out_hz) {
    if (!out_hz) return 0;
    if (g_tsc_hz_cached != 0) {
        *out_hz = g_tsc_hz_cached;
        return 1;
    }
    uint32_t a, b, c, d;
    cpuid(0x15, 0, &a, &b, &c, &d);
    if (a != 0 && b != 0 && c != 0) {
        uint64_t hz = (uint64_t)c * (uint64_t)b / (uint64_t)a;
        if (hz > 0) {
            *out_hz = hz;
            return 1;
        }
    }
    cpuid(0x16, 0, &a, &b, &c, &d);
    if ((a & 0xFFFF) != 0) {
        uint64_t hz = (uint64_t)(a & 0xFFFF) * 1000000ull;
        *out_hz = hz;
        return 1;
    }
    return 0;
}

void cpu_set_tsc_hz(uint64_t hz) {
    g_tsc_hz_cached = hz;
}

int cpu_calibrate_tsc_hz_pit(uint32_t sample_ms) {
    uint32_t pit_hz = timer_pit_hz();
    if (pit_hz == 0) return 0;
    if (sample_ms < 10) sample_ms = 10;
    uint64_t ticks = ((uint64_t)pit_hz * sample_ms) / 1000ull;
    if (ticks == 0) ticks = 1;

    uint64_t start_tick = timer_pit_ticks();
    while (timer_pit_ticks() == start_tick) {}
    uint64_t tsc_start = rdtsc();

    uint64_t target = start_tick + ticks;
    while (timer_pit_ticks() < target) {}
    uint64_t tsc_end = rdtsc();

    uint64_t delta = tsc_end - tsc_start;
    uint64_t hz = (delta * 1000ull) / (uint64_t)sample_ms;
    if (hz == 0) return 0;
    g_tsc_hz_cached = hz;
    return 1;
}
