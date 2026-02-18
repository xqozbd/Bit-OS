#include "lib/stack_chk.h"

#include <stdint.h>

#include "kernel/panic.h"

#if defined(__GNUC__) || defined(__clang__)
#define NO_STACK_PROTECTOR __attribute__((no_stack_protector))
#else
#define NO_STACK_PROTECTOR
#endif

__attribute__((used))
uintptr_t __stack_chk_guard = 0x7c9e54a2b1f8d3a5ull;

static inline uint64_t rdtsc_now(void) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

NO_STACK_PROTECTOR
void stack_canary_init_auto(void) {
    uint64_t seed = rdtsc_now();
    seed ^= (uint64_t)(uintptr_t)&__stack_chk_guard;
    if (seed == 0) seed = 0x9e3779b97f4a7c15ull;
    uint64_t guard = mix64(seed);
    guard &= 0xffffffffffffff00ull; /* avoid zero byte terminators */
    if (guard == 0) guard = 0x4f5d3c2b1a090800ull;
    __stack_chk_guard = (uintptr_t)guard;
}

__attribute__((noreturn))
void __stack_chk_fail(void) {
    panic_screen(0x53434b01u, "stack smashing detected");
    for (;;) { }
}

void __stack_chk_fail_local(void) __attribute__((noreturn, alias("__stack_chk_fail")));
