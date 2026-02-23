#include "sys/boot_params.h"

#include <stdint.h>
#include <stddef.h>

#include "sys/vfs.h"

#define BOOT_PARAM_MAX 64
#define BOOT_CMDLINE_MAX 512
#define BOOT_CFG_MAX 1024

struct boot_param {
    const char *key;
    const char *value;
};

static char g_cmdline[BOOT_CMDLINE_MAX];
static char g_cfg[BOOT_CFG_MAX];
static struct boot_param g_params[BOOT_PARAM_MAX];
static uint32_t g_param_count = 0;

static int key_eq(const char *a, const char *b);

const char *boot_cmdline_raw(void) {
    return g_cmdline[0] ? g_cmdline : NULL;
}

static void boot_param_add(char *key, char *value, int override) {
    if (!key || !key[0]) return;
    for (uint32_t i = 0; i < g_param_count; ++i) {
        if (key_eq(g_params[i].key, key)) {
            if (override) g_params[i].value = value;
            return;
        }
    }
    if (g_param_count >= BOOT_PARAM_MAX) return;
    g_params[g_param_count].key = key;
    g_params[g_param_count].value = value;
    g_param_count++;
}

static void trim_right(char *s) {
    if (!s) return;
    size_t n = 0;
    while (s[n]) n++;
    while (n > 0) {
        char c = s[n - 1];
        if (c == ' ' || c == '\t' || c == '\r') {
            s[n - 1] = '\0';
            n--;
        } else {
            break;
        }
    }
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
        boot_param_add(key, value, 1);
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

int boot_params_load_config(const char *path) {
    if (!path) return 0;
    int node = vfs_resolve(0, path);
    if (node < 0) return 0;
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(node, &data, &size) || !data || size == 0) return 0;

    size_t copy = size < (BOOT_CFG_MAX - 1) ? (size_t)size : (BOOT_CFG_MAX - 1);
    for (size_t i = 0; i < copy; ++i) {
        g_cfg[i] = (char)data[i];
    }
    g_cfg[copy] = '\0';

    char *p = g_cfg;
    while (*p) {
        while (*p == '\n' || *p == '\r') ++p;
        if (!*p) break;
        char *line = p;
        while (*p && *p != '\n' && *p != '\r') ++p;
        if (*p) *p++ = '\0';

        while (*line == ' ' || *line == '\t') ++line;
        if (*line == '#' || *line == ';' || *line == '\0') continue;

        char *key = line;
        char *value = NULL;
        while (*line && *line != '=' && *line != ' ' && *line != '\t') ++line;
        if (*line == '=') {
            *line++ = '\0';
            while (*line == ' ' || *line == '\t') ++line;
            value = line;
        } else if (*line) {
            *line++ = '\0';
            while (*line == ' ' || *line == '\t') ++line;
            value = (*line) ? line : NULL;
        }
        trim_right(key);
        if (value) trim_right(value);
        boot_param_add(key, value, 0);
    }
    return 1;
}
