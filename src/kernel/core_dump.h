#ifndef KERNEL_CORE_DUMP_H
#define KERNEL_CORE_DUMP_H

#include <stdint.h>

struct task;

void task_core_mark(struct task *t, const char *reason,
                    uint64_t fault_addr, uint64_t rip,
                    uint64_t rsp, uint64_t err);
void task_core_dump_try(struct task *t);

#endif /* KERNEL_CORE_DUMP_H */
