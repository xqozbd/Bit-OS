#ifndef KERNEL_PROFILER_H
#define KERNEL_PROFILER_H

#include <stdint.h>

enum prof_counter {
    PROF_CTX_SWITCHES = 0,
    PROF_SYSCALLS,
    PROF_PAGE_FAULTS,
    PROF_TASK_EVICTS,
    PROF_MAX
};

void profiler_inc(enum prof_counter c);
uint64_t profiler_get(enum prof_counter c);
const char *profiler_name(enum prof_counter c);
void profiler_reset(void);

#endif /* KERNEL_PROFILER_H */
