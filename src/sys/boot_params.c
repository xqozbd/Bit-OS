#include "sys/boot_params.h"

#include <stdint.h>
#include <stddef.h>

#define BOOT_PARAM_MAX 64
#define BOOT_CMDLINE_MAX 512

struct boot_param {
    const char *key;
    const char *value;
};

static char g_cmdline[BOOT_CMDLINE_MAX];
static struct boot_param g_params[BOOT_PARAM_MAX];
static uint32_t g_param_count = 0;

const char *boot_cmdline_raw(void) {
    return g_cmdline[0] ? g_cmdline : NULL;
}

void boot_params_init(const char *cmdline) {
    g_param_count = 0;
    if (!cmdline) {
        g_cmdline[0] = '\0';
        return;
    }

    size_t i = 0;
    for (; cmdline[i] && i + 1 < BOOT_CMDLINE_MAX; ++i) {
        g_cmdline[i] = cmdline[i];
    }
    g_cmdline[i] = '\0';

    char *p = g_cmdline;
    while (*p && g_param_count < BOOT_PARAM_MAX) {
        while (*p == ' ') ++p;
        if (!*p) break;

        char *key = p;
        char *value = NULL;
        while (*p && *p != ' ' && *p != '=') ++p;
        if (*p == '=') {
            *p++ = '\0';
            value = p;
            while (*p && *p != ' ') ++p;
        }
        if (*p) *p++ = '\0';
        if (key[0]) {
            g_params[g_param_count].key = key;
            g_params[g_param_count].value = value;
            g_param_count++;
        }
    }
}

static int key_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

const char *boot_param_get(const char *key) {
    for (uint32_t i = 0; i < g_param_count; ++i) {
        if (key_eq(g_params[i].key, key)) return g_params[i].value;
    }
    return NULL;
}

int boot_param_has(const char *key) {
    return boot_param_get(key) != NULL;
}
