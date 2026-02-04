#ifndef KERNEL_CRASH_H
#define KERNEL_CRASH_H

#include <stdint.h>

struct interrupt_frame {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

enum crash_action {
    CRASH_CONTINUE = 0,
    CRASH_KILL_TASK = 1,
    CRASH_RESTART = 2,
    CRASH_HALT = 3
};

enum crash_action crash_handle_exception(uint8_t vec,
                                         uint64_t err,
                                         int has_err,
                                         const struct interrupt_frame *frame);

void crash_panic(uint32_t code, const char *msg);

#endif /* KERNEL_CRASH_H */
