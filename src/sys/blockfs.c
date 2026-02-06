#include "sys/blockfs.h"

#include <stddef.h>

#include "kernel/partition.h"
#include "lib/log.h"
#include "lib/strutil.h"

static char g_info_buf[128];

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

int blockfs_root(void) {
    return 0;
}

static int parse_part_name(const char *name, int *out_index) {
    if (!name || !out_index) return 0;
    if (str_starts_with(name, "gpt")) {
        uint64_t idx = 0;
        if (!str_to_u64(name + 3, &idx)) return 0;
        *out_index = (int)idx;
        return 1;
    }
    if (str_starts_with(name, "mbr")) {
        uint64_t idx = 0;
        if (!str_to_u64(name + 3, &idx)) return 0;
        *out_index = (int)idx;
        return 1;
    }
    return 0;
}

static void format_part_name(const struct partition_info *p, char *out, size_t out_size) {
    if (!p || !out || out_size == 0) return;
    const char *prefix = (p->scheme == PART_SCHEME_GPT) ? "gpt" : "mbr";
    size_t w = 0;
    for (size_t i = 0; prefix[i] && w + 1 < out_size; ++i) out[w++] = prefix[i];
    uint32_t idx = p->part_index;
    char tmp[16];
    size_t t = 0;
    do {
        tmp[t++] = (char)('0' + (idx % 10));
        idx /= 10;
    } while (idx && t < sizeof(tmp));
    while (t > 0 && w + 1 < out_size) out[w++] = tmp[--t];
    out[w] = '\0';
}

int blockfs_is_dir(int node) {
    return node == 0;
}

int blockfs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node <= 0) return 0;
    size_t idx = (size_t)(node - 1);
    const struct partition_info *p = partition_get(idx);
    if (!p) return 0;
    const char *scheme = (p->scheme == PART_SCHEME_GPT) ? "gpt" : "mbr";
    log_printf_verbose("blockfs: read %s%u\n", scheme, (unsigned)p->part_index);
    char *w = g_info_buf;
    size_t remain = sizeof(g_info_buf) - 1;
    append_str(&w, &remain, "scheme=");
    append_str(&w, &remain, scheme);
    append_char(&w, &remain, '\n');
    append_str(&w, &remain, "index=");
    append_u64(&w, &remain, (uint64_t)p->part_index);
    append_char(&w, &remain, '\n');
    append_str(&w, &remain, "device=");
    append_u64(&w, &remain, (uint64_t)p->device_index);
    append_char(&w, &remain, '\n');
    append_str(&w, &remain, "lba=");
    append_u64(&w, &remain, p->first_lba);
    append_str(&w, &remain, "..");
    append_u64(&w, &remain, p->last_lba);
    append_char(&w, &remain, '\n');
    append_str(&w, &remain, "count=");
    append_u64(&w, &remain, p->lba_count);
    append_char(&w, &remain, '\n');
    *w = '\0';
    *data = (const uint8_t *)g_info_buf;
    *size = (uint64_t)(w - g_info_buf);
    return 1;
}

int blockfs_resolve(int cwd, const char *path) {
    (void)cwd;
    if (!path || path[0] == '\0') return 0;
    if (str_eq(path, "/")) return 0;
    const char *p = path;
    if (p[0] == '/') p++;
    int idx = -1;
    if (!parse_part_name(p, &idx)) return -1;
    size_t count = partition_count();
    for (size_t i = 0; i < count; ++i) {
        const struct partition_info *pi = partition_get(i);
        if (!pi) continue;
        if ((int)pi->part_index == idx &&
            ((pi->scheme == PART_SCHEME_GPT && str_starts_with(p, "gpt")) ||
             (pi->scheme == PART_SCHEME_MBR && str_starts_with(p, "mbr")))) {
            return (int)(i + 1);
        }
    }
    return -1;
}

void blockfs_pwd(int cwd) {
    if (cwd <= 0) {
        log_printf("/\n");
        return;
    }
    size_t idx = (size_t)(cwd - 1);
    const struct partition_info *p = partition_get(idx);
    if (!p) {
        log_printf("/\n");
        return;
    }
    char name[16];
    format_part_name(p, name, sizeof(name));
    log_printf("/%s\n", name);
}

void blockfs_ls(int node) {
    if (node != 0) {
        size_t idx = (size_t)(node - 1);
        const struct partition_info *p = partition_get(idx);
        if (!p) return;
        char name[16];
        format_part_name(p, name, sizeof(name));
        log_printf("%s\n", name);
        return;
    }
    size_t count = partition_count();
    for (size_t i = 0; i < count; ++i) {
        const struct partition_info *p = partition_get(i);
        if (!p) continue;
        char name[16];
        format_part_name(p, name, sizeof(name));
        log_printf("%s ", name);
    }
    log_printf("\n");
}
