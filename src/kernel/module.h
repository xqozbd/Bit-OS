#ifndef KERNEL_MODULE_H
#define KERNEL_MODULE_H

#include <stddef.h>

enum module_status {
    MODULE_UNLOADED = 0,
    MODULE_LOADED = 1,
    MODULE_FAILED = 2
};

struct module_entry {
    const char *name;
    int (*init)(void);
    int (*fini)(void);
    enum module_status status;
    const char *detail;
};

void module_registry_init(void);
int module_register(const char *name, int (*init)(void), int (*fini)(void));
int module_load(const char *name);
int module_unload(const char *name);
int module_mark_loaded(const char *name);
const struct module_entry *module_entries(size_t *out_count);
void module_log_status(void);
size_t module_format(char *buf, size_t buf_len);

#endif /* KERNEL_MODULE_H */
