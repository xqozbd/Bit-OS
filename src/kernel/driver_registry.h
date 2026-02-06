#ifndef DRIVER_REGISTRY_H
#define DRIVER_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

enum driver_status {
    DRIVER_STATUS_UNINIT = 0,
    DRIVER_STATUS_OK,
    DRIVER_STATUS_FAIL,
    DRIVER_STATUS_SKIPPED
};

struct driver_entry {
    const char *name;
    uint32_t order;
    enum driver_status status;
    const char *detail;
};

void driver_registry_init(void);
int driver_register(const char *name, uint32_t order);
void driver_set_status_idx(int index, enum driver_status status, const char *detail);
void driver_set_status(const char *name, enum driver_status status, const char *detail);
const struct driver_entry *driver_entries(size_t *out_count);
void driver_log_status(void);

#endif
