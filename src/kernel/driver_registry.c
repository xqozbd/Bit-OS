#include "kernel/driver_registry.h"

#include "lib/log.h"
#include "lib/strutil.h"

#define MAX_DRIVERS 64

static struct driver_entry g_drivers[MAX_DRIVERS];
static size_t g_driver_count = 0;

void driver_registry_init(void) {
    memset(g_drivers, 0, sizeof(g_drivers));
    g_driver_count = 0;
}

static int find_driver(const char *name) {
    if (!name) return -1;
    for (size_t i = 0; i < g_driver_count; ++i) {
        if (g_drivers[i].name && str_eq(g_drivers[i].name, name)) {
            return (int)i;
        }
    }
    return -1;
}

int driver_register(const char *name, uint32_t order) {
    if (!name) return -1;
    int existing = find_driver(name);
    if (existing >= 0) return existing;
    if (g_driver_count >= MAX_DRIVERS) return -1;

    struct driver_entry *ent = &g_drivers[g_driver_count];
    ent->name = name;
    ent->order = order;
    ent->status = DRIVER_STATUS_UNINIT;
    ent->detail = NULL;
    return (int)g_driver_count++;
}

void driver_set_status_idx(int index, enum driver_status status, const char *detail) {
    if (index < 0 || (size_t)index >= g_driver_count) return;
    g_drivers[index].status = status;
    g_drivers[index].detail = detail;
}

void driver_set_status(const char *name, enum driver_status status, const char *detail) {
    int idx = find_driver(name);
    if (idx < 0) return;
    driver_set_status_idx(idx, status, detail);
}

const struct driver_entry *driver_entries(size_t *out_count) {
    if (out_count) *out_count = g_driver_count;
    return g_drivers;
}

static const char *status_str(enum driver_status st) {
    switch (st) {
    case DRIVER_STATUS_OK: return "ok";
    case DRIVER_STATUS_FAIL: return "fail";
    case DRIVER_STATUS_SKIPPED: return "skipped";
    case DRIVER_STATUS_UNINIT:
    default:
        return "uninit";
    }
}

void driver_log_status(void) {
    log_printf("Drivers:\n");
    for (size_t i = 0; i < g_driver_count; ++i) {
        const struct driver_entry *ent = &g_drivers[i];
        const char *status = status_str(ent->status);
        int use_detail_as_status = (ent->status == DRIVER_STATUS_SKIPPED &&
                                    ent->detail && str_eq(ent->detail, "not found"));
        if (use_detail_as_status) status = ent->detail;
        log_printf("  [%u] %s: %s", (unsigned)ent->order, ent->name, status);
        if (!use_detail_as_status && ent->detail && ent->detail[0]) {
            log_printf(" (%s)", ent->detail);
        }
        log_printf("\n");
    }
}
