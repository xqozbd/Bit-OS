#ifndef KERNEL_ASSERT_H
#define KERNEL_ASSERT_H

#include "lib/log.h"
#include "kernel/panic.h"

/* lul im coding this drunk - Evan */ 

#define KDEBUG(...) log_debug(__VA_ARGS__)

#define KASSERT(expr) do { \
    if (!(expr)) { \
        log_printf("ASSERT failed: %s (%s:%d)\n", #expr, __FILE__, __LINE__); \
        panic_screen(0xA55E0001u, "assert"); \
    } \
} while (0)

#define KASSERT_MSG(expr, msg) do { \
    if (!(expr)) { \
        log_printf("ASSERT failed: %s (%s:%d)\n", #expr, __FILE__, __LINE__); \
        if (msg) log_printf("ASSERT msg: %s\n", msg); \
        panic_screen(0xA55E0002u, msg ? msg : "assert"); \
    } \
} while (0)

#endif /* KERNEL_ASSERT_H */
