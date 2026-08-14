#ifndef KERNEL_SANDBOX_H
#define KERNEL_SANDBOX_H

#include <stdint.h>

#include "kernel/task.h"

enum sandbox_access {
    SANDBOX_ACCESS_READ = 1u << 0,
    SANDBOX_ACCESS_WRITE = 1u << 1,
    SANDBOX_ACCESS_EXEC = 1u << 2
};

enum sandbox_broker_op {
    SANDBOX_BROKER_REGISTER = 1,
    SANDBOX_BROKER_REQUEST_PATH = 2,
    SANDBOX_BROKER_CONSENT = 3
};

struct sandbox_broker_request {
    uint32_t op;
    uint32_t access;
    char target[SANDBOX_PATH_LEN];
    char reason[64];
};

void sandbox_task_init(struct task *t);
void sandbox_task_clone(struct task *dst, const struct task *src);
void sandbox_enable_legacy(struct task *t, uint32_t flags);
int sandbox_load_for_exec(struct task *t, const char *exec_path);
int sandbox_check_exec_isolation(struct task *t, uint64_t old_pml4, uint64_t new_pml4);
int sandbox_check_wx(struct task *t, const char *op, uint32_t prot);
int sandbox_check_path(struct task *t, const char *op, const char *path, uint32_t access);
int sandbox_check_syscall(struct task *t, uint64_t num);
int sandbox_broker_call(struct task *t, struct sandbox_broker_request *req);
void sandbox_audit_deny(struct task *t, const char *op, const char *target, const char *reason);

#endif /* KERNEL_SANDBOX_H */
