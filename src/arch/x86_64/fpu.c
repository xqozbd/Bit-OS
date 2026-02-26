#include "arch/x86_64/fpu.h"

#include <stddef.h>

static uint8_t g_fpu_default[FPU_STATE_SIZE] __attribute__((aligned(FPU_STATE_ALIGN)));
static int g_fpu_ready = 0;
static int g_use_xsave = 0;
static uint64_t g_xsave_mask = 0;
static uint32_t g_xsave_size = 512;

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(subleaf));
#else
    *a = *b = *c = *d = 0;
    (void)leaf; (void)subleaf;
#endif
}

static inline uint64_t xgetbv(uint32_t idx) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(idx));
    return ((uint64_t)hi << 32) | lo;
#else
    (void)idx;
    return 0;
#endif
}

static inline void xsetbv(uint32_t idx, uint64_t val) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("xsetbv" : : "a"(lo), "d"(hi), "c"(idx));
#else
    (void)idx; (void)val;
#endif
}

static inline void enable_osxsave(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 18); /* CR4.OSXSAVE */
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4));
#endif
}

static inline void do_xsave(uint8_t *state) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo = (uint32_t)g_xsave_mask;
    uint32_t hi = (uint32_t)(g_xsave_mask >> 32);
    __asm__ volatile("xsave (%0)" : : "r"(state), "a"(lo), "d"(hi) : "memory");
#else
    (void)state;
#endif
}

static inline void do_xrstor(const uint8_t *state) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo = (uint32_t)g_xsave_mask;
    uint32_t hi = (uint32_t)(g_xsave_mask >> 32);
    __asm__ volatile("xrstor (%0)" : : "r"(state), "a"(lo), "d"(hi) : "memory");
#else
    (void)state;
#endif
}

void fpu_init(void) {
    if (g_fpu_ready) return;
#if defined(__GNUC__) || defined(__clang__)
    uint32_t a, b, c, d;
    cpuid(1, 0, &a, &b, &c, &d);
    int has_xsave = (c & (1u << 26)) != 0;
    int has_osxsave = (c & (1u << 27)) != 0;
    int has_avx = (c & (1u << 28)) != 0;
    g_use_xsave = 0;
    g_xsave_mask = 0x3u; /* x87 + SSE */
    g_xsave_size = 512;
    if (has_xsave && has_osxsave) {
        enable_osxsave();
        if (has_avx) {
            g_xsave_mask |= (1u << 2); /* AVX */
        }
        xsetbv(0, g_xsave_mask);
        cpuid(0xD, 0, &a, &b, &c, &d);
        if (b >= 512 && b <= FPU_STATE_SIZE) {
            g_xsave_size = b;
        } else if (b > FPU_STATE_SIZE) {
            g_xsave_size = FPU_STATE_SIZE;
        }
        g_use_xsave = 1;
    }
    __asm__ volatile("fninit");
    if (g_use_xsave) {
        do_xsave(g_fpu_default);
        do_xrstor(g_fpu_default);
    } else {
        __asm__ volatile("fxsave (%0)" :: "r"(g_fpu_default) : "memory");
        __asm__ volatile("fxrstor (%0)" :: "r"(g_fpu_default) : "memory");
    }
#endif
    g_fpu_ready = 1;
}

void fpu_save(uint8_t *state) {
    if (!state) return;
#if defined(__GNUC__) || defined(__clang__)
    if (g_use_xsave) {
        do_xsave(state);
    } else {
        __asm__ volatile("fxsave (%0)" :: "r"(state) : "memory");
    }
#endif
}

void fpu_restore(const uint8_t *state) {
    if (!state) return;
#if defined(__GNUC__) || defined(__clang__)
    if (g_use_xsave) {
        do_xrstor(state);
    } else {
        __asm__ volatile("fxrstor (%0)" :: "r"(state) : "memory");
    }
#endif
}

void fpu_state_init(uint8_t *state) {
    if (!state) return;
    if (!g_fpu_ready) fpu_init();
    uint32_t size = g_use_xsave ? g_xsave_size : 512u;
    if (size > FPU_STATE_SIZE) size = FPU_STATE_SIZE;
    for (uint32_t i = 0; i < size; ++i) {
        state[i] = g_fpu_default[i];
    }
    for (uint32_t i = size; i < FPU_STATE_SIZE; ++i) {
        state[i] = 0;
    }
}

int fpu_using_xsave(void) {
    return g_use_xsave != 0;
}

uint32_t fpu_state_size(void) {
    return g_use_xsave ? g_xsave_size : 512u;
}
