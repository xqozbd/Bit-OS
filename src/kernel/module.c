#include "kernel/module.h"

#include "lib/log.h"
#include "lib/strutil.h"

extern void *memset(void *s, int c, size_t n);

#define MAX_MODULES 64

static struct module_entry g_modules[MAX_MODULES];
static size_t g_module_count = 0;

void module_registry_init(void) {
    memset(g_modules, 0, sizeof(g_modules));
    g_module_count = 0;
}

static int find_module(const char *name) {
    if (!name) return -1;
    for (size_t i = 0; i < g_module_count; ++i) {
        if (g_modules[i].name && str_eq(g_modules[i].name, name)) {
            return (int)i;
        }
    }
    return -1;
}

int module_register(const char *name, int (*init)(void), int (*fini)(void)) {
    if (!name) return -1;
    int existing = find_module(name);
    if (existing >= 0) return existing;
    if (g_module_count >= MAX_MODULES) return -1;
    struct module_entry *ent = &g_modules[g_module_count];
    ent->name = name;
    ent->init = init;
    ent->fini = fini;
    ent->status = MODULE_UNLOADED;
    ent->detail = NULL;
    return (int)g_module_count++;
}

int module_mark_loaded(const char *name) {
    int idx = find_module(name);
    if (idx < 0) return 0;
    g_modules[idx].status = MODULE_LOADED;
    return 1;
}

int module_load(const char *name) {
    int idx = find_module(name);
    if (idx < 0) return 0;
    struct module_entry *ent = &g_modules[idx];
    if (ent->status == MODULE_LOADED) return 1;
    if (!ent->init) return 0;
    int rc = ent->init();
    if (rc == 0 || rc == 1) {
        ent->status = MODULE_LOADED;
        ent->detail = NULL;
        return 1;
    }
    ent->status = MODULE_FAILED;
    ent->detail = "init failed";
    return 0;
}

int module_unload(const char *name) {
    int idx = find_module(name);
    if (idx < 0) return 0;
    struct module_entry *ent = &g_modules[idx];
    if (ent->status != MODULE_LOADED) return 0;
    if (!ent->fini) return 0;
    int rc = ent->fini();
    if (rc == 0 || rc == 1) {
        ent->status = MODULE_UNLOADED;
        ent->detail = NULL;
        return 1;
    }
    ent->status = MODULE_FAILED;
    ent->detail = "unload failed";
    return 0;
}

const struct module_entry *module_entries(size_t *out_count) {
    if (out_count) *out_count = g_module_count;
    return g_modules;
}

static const char *status_str(enum module_status st) {
    switch (st) {
    case MODULE_LOADED: return "loaded";
    case MODULE_FAILED: return "failed";
    case MODULE_UNLOADED:
    default:
        return "unloaded";
    }
}

void module_log_status(void) {
    log_printf("Modules:\n");
    for (size_t i = 0; i < g_module_count; ++i) {
        const struct module_entry *ent = &g_modules[i];
        const char *status = status_str(ent->status);
        log_printf("  %s: %s", ent->name ? ent->name : "unknown", status);
        if (ent->detail && ent->detail[0]) {
            log_printf(" (%s)", ent->detail);
        }
        log_printf("\n");
    }
}

static void buf_append(char **dst, size_t *remain, const char *s) {
    if (!dst || !*dst || !remain || !s) return;
    while (*s && *remain > 1) {
        **dst = *s++;
        (*dst)++;
        (*remain)--;
    }
}

size_t module_format(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return 0;
    char *w = buf;
    size_t remain = buf_len;
    buf_append(&w, &remain, "Modules:\n");
    for (size_t i = 0; i < g_module_count; ++i) {
        const struct module_entry *ent = &g_modules[i];
        const char *status = status_str(ent->status);
        buf_append(&w, &remain, "  ");
        buf_append(&w, &remain, ent->name ? ent->name : "unknown");
        buf_append(&w, &remain, ": ");
        buf_append(&w, &remain, status);
        if (ent->detail && ent->detail[0]) {
            buf_append(&w, &remain, " (");
            buf_append(&w, &remain, ent->detail);
            buf_append(&w, &remain, ")");
        }
        buf_append(&w, &remain, "\n");
    }
    if (remain > 0) *w = '\0';
    return (size_t)(w - buf);
}
