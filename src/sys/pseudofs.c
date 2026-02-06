#include "sys/pseudofs.h"

#include <stddef.h>

#include "lib/compat.h"
#include "lib/log.h"
#include "lib/strutil.h"
#include "arch/x86_64/timer.h"
#include "kernel/meminfo.h"
#include "lib/version.h"

static char g_buf[256];

static const char *fs_name(int fs_id) {
    switch (fs_id) {
    case PSEUDOFS_DEV: return "dev";
    case PSEUDOFS_PROC: return "proc";
    case PSEUDOFS_SYS: return "sys";
    default: return "fs";
    }
}

int pseudofs_is_ready(int fs_id) {
    (void)fs_id;
    return 1;
}

int pseudofs_root(int fs_id) {
    (void)fs_id;
    return 0;
}

static int node_for_path(int fs_id, const char *path) {
    if (!path || path[0] == '\0' || str_eq(path, "/")) return 0;
    if (path[0] == '/') path++;
    if (fs_id == PSEUDOFS_DEV) {
        if (str_eq(path, "null")) return 1;
        if (str_eq(path, "tty0")) return 2;
    } else if (fs_id == PSEUDOFS_PROC) {
        if (str_eq(path, "uptime")) return 1;
        if (str_eq(path, "meminfo")) return 2;
    } else if (fs_id == PSEUDOFS_SYS) {
        if (str_eq(path, "build")) return 1;
        if (str_eq(path, "version")) return 2;
    }
    return -1;
}

int pseudofs_resolve(int fs_id, int cwd, const char *path) {
    (void)cwd;
    return node_for_path(fs_id, path);
}

int pseudofs_is_dir(int fs_id, int node) {
    (void)fs_id;
    return node == 0;
}

static void append_char(char **dst, size_t *remain, char c) {
    if (!dst || !*dst || !remain || *remain == 0) return;
    **dst = c;
    (*dst)++;
    (*remain)--;
}

static void append_str(char **dst, size_t *remain, const char *s) {
    if (!dst || !*dst || !remain || !s) return;
    while (*s && *remain > 0) {
        **dst = *s++;
        (*dst)++;
        (*remain)--;
    }
}

static void append_u64(char **dst, size_t *remain, uint64_t v) {
    char tmp[32];
    size_t n = 0;
    if (v == 0) {
        append_char(dst, remain, '0');
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0) {
        append_char(dst, remain, tmp[--n]);
    }
}

int pseudofs_read_file(int fs_id, int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node == 0) return 0;
    char *w = g_buf;
    size_t remain = sizeof(g_buf) - 1;
    if (fs_id == PSEUDOFS_PROC) {
        if (node == 1) {
            uint64_t ticks = timer_uptime_ticks();
            uint64_t hz = 100;
            uint64_t ms = (ticks * 1000ull) / (hz ? hz : 1);
            append_str(&w, &remain, "uptime=");
            append_u64(&w, &remain, ms);
            append_str(&w, &remain, "ms\n");
        } else if (node == 2) {
            uint64_t usable = get_usable_ram_bytes();
            append_str(&w, &remain, "usable=");
            append_u64(&w, &remain, usable);
            append_char(&w, &remain, '\n');
        }
    } else if (fs_id == PSEUDOFS_SYS) {
        if (node == 1) {
            append_str(&w, &remain, "build=");
            append_str(&w, &remain, __DATE__ " " __TIME__);
            append_char(&w, &remain, '\n');
        } else if (node == 2) {
            append_str(&w, &remain, "version=");
            append_str(&w, &remain, BITOS_VERSION);
            append_char(&w, &remain, '\n');
        }
    } else if (fs_id == PSEUDOFS_DEV) {
        if (node == 1) {
            append_str(&w, &remain, "null\n");
        } else if (node == 2) {
            append_str(&w, &remain, "tty0\n");
        }
    }
    *w = '\0';
    *data = (const uint8_t *)g_buf;
    *size = (uint64_t)(w - g_buf);
    return (*size > 0);
}

void pseudofs_pwd(int fs_id, int cwd) {
    if (cwd == 0) {
        log_printf("/\n");
        return;
    }
    const char *base = fs_name(fs_id);
    if (fs_id == PSEUDOFS_DEV) {
        if (cwd == 1) log_printf("/%s/null\n", base);
        else if (cwd == 2) log_printf("/%s/tty0\n", base);
        else log_printf("/%s\n", base);
    } else if (fs_id == PSEUDOFS_PROC) {
        if (cwd == 1) log_printf("/%s/uptime\n", base);
        else if (cwd == 2) log_printf("/%s/meminfo\n", base);
        else log_printf("/%s\n", base);
    } else if (fs_id == PSEUDOFS_SYS) {
        if (cwd == 1) log_printf("/%s/build\n", base);
        else if (cwd == 2) log_printf("/%s/version\n", base);
        else log_printf("/%s\n", base);
    } else {
        log_printf("/%s\n", base);
    }
}

void pseudofs_ls(int fs_id, int node) {
    if (node != 0) {
        pseudofs_pwd(fs_id, node);
        return;
    }
    if (fs_id == PSEUDOFS_DEV) {
        log_printf("null tty0\n");
    } else if (fs_id == PSEUDOFS_PROC) {
        log_printf("uptime meminfo\n");
    } else if (fs_id == PSEUDOFS_SYS) {
        log_printf("build version\n");
    }
}
