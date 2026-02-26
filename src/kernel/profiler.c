#include "kernel/profiler.h"

#include "lib/compat.h"

static uint64_t g_prof[PROF_MAX];

void profiler_inc(enum prof_counter c) {
    if ((unsigned)c >= PROF_MAX) return;
    __atomic_fetch_add(&g_prof[c], 1u, __ATOMIC_SEQ_CST);
}

uint64_t profiler_get(enum prof_counter c) {
    if ((unsigned)c >= PROF_MAX) return 0;
    return __atomic_load_n(&g_prof[c], __ATOMIC_SEQ_CST);
}

const char *profiler_name(enum prof_counter c) {
    switch (c) {
        case PROF_CTX_SWITCHES: return "ctx_switches";
        case PROF_SYSCALLS: return "syscalls";
        case PROF_PAGE_FAULTS: return "page_faults";
        case PROF_TASK_EVICTS: return "task_evicts";
        default: return "unknown";
    }
}

void profiler_reset(void) {
    for (unsigned i = 0; i < PROF_MAX; ++i) {
        __atomic_store_n(&g_prof[i], 0u, __ATOMIC_SEQ_CST);
    }
}
