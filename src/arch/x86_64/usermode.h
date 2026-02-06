#ifndef ARCH_X86_64_USERMODE_H
#define ARCH_X86_64_USERMODE_H

#include <stdint.h>

#include "lib/compat.h"

int user_stack_build(uint64_t pml4_phys, uint64_t top, uint64_t size, uint64_t *out_rsp);
void user_enter_iret(uint64_t rip, uint64_t rsp, uint64_t rflags) __attribute__((noreturn));

#endif /* ARCH_X86_64_USERMODE_H */
