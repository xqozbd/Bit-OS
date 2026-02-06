#include "sys/initramfs.h"

#include <stddef.h>
#include <stdint.h>

#include "boot/boot_requests.h"
#include "lib/log.h"
#include "lib/strutil.h"

enum { IR_MAX_NODES = 256 };
enum { IR_NAME_BUF = 8192 };

struct ir_node {
    const char *name;
    int parent;
    int is_dir;
    const uint8_t *data;
    uint64_t size;
};

static struct ir_node g_nodes[IR_MAX_NODES];
static int g_node_count = 0;
static char g_name_buf[IR_NAME_BUF];
static size_t g_name_used = 0;
static int g_available = 0;

static uint32_t hex8_to_u32(const char *p) {
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        char c = p[i];
        uint32_t n = 0;
        if (c >= '0' && c <= '9') n = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') n = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') n = (uint32_t)(c - 'A' + 10);
        else n = 0;
        v = (v << 4) | n;
    }
    return v;
}

static const char *name_store(const char *s, size_t len) {
    if (g_name_used + len + 1 >= IR_NAME_BUF) return NULL;
    char *dst = &g_name_buf[g_name_used];
    for (size_t i = 0; i < len; ++i) dst[i] = s[i];
    dst[len] = '\0';
    g_name_used += len + 1;
    return dst;
}

static int node_new(const char *name, int parent, int is_dir) {
    if (g_node_count >= IR_MAX_NODES) return -1;
    int idx = g_node_count++;
    g_nodes[idx].name = name;
    g_nodes[idx].parent = parent;
    g_nodes[idx].is_dir = is_dir;
    g_nodes[idx].data = NULL;
    g_nodes[idx].size = 0;
    return idx;
}

static int find_child(int dir, const char *name) {
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i].parent != dir) continue;
        if (str_eq(g_nodes[i].name, name)) return i;
    }
    return -1;
}

static int get_or_create_dir(int parent, const char *name, size_t len) {
    char tmp[64];
    if (len >= sizeof(tmp)) return -1;
    for (size_t i = 0; i < len; ++i) tmp[i] = name[i];
    tmp[len] = '\0';

    int existing = find_child(parent, tmp);
    if (existing >= 0) return existing;

    const char *stored = name_store(tmp, len);
    if (!stored) return -1;
    return node_new(stored, parent, 1);
}

static int add_file(int parent, const char *name, size_t len, const uint8_t *data, uint64_t size) {
    char tmp[64];
    if (len >= sizeof(tmp)) return -1;
    for (size_t i = 0; i < len; ++i) tmp[i] = name[i];
    tmp[len] = '\0';

    int existing = find_child(parent, tmp);
    if (existing >= 0) return existing;

    const char *stored = name_store(tmp, len);
    if (!stored) return -1;
    int idx = node_new(stored, parent, 0);
    if (idx >= 0) {
        g_nodes[idx].data = data;
        g_nodes[idx].size = size;
    }
    return idx;
}

static int ensure_path_dirs(const char *path, int *parent_out, const char **name_out, size_t *name_len) {
    int cur = 0;
    size_t i = 0;
    size_t start = 0;
    while (path[i] != '\0') {
        if (path[i] == '/') {
            size_t len = i - start;
            if (len > 0) {
                cur = get_or_create_dir(cur, &path[start], len);
                if (cur < 0) return 0;
            }
            i++;
            start = i;
            continue;
        }
        i++;
    }
    size_t last_len = i - start;
    if (last_len == 0) return 0;
    *parent_out = cur;
    *name_out = &path[start];
    *name_len = last_len;
    return 1;
}

int initramfs_init_from_limine(void) {
    g_available = 0;
    g_node_count = 0;
    g_name_used = 0;

    if (!module_request.response || module_request.response->module_count == 0) {
        return 0;
    }

    struct limine_module_response *resp = module_request.response;
    struct limine_file *mod = resp->modules[0];
    if (!mod || !mod->address || mod->size == 0) return 0;

    g_node_count = 0;
    node_new("/", -1, 1);

    const uint8_t *base = (const uint8_t *)mod->address;
    uint64_t size = mod->size;
    uint64_t off = 0;

    while (off + 110 <= size) {
        const char *hdr = (const char *)(base + off);
        if (!(hdr[0] == '0' && hdr[1] == '7' && hdr[2] == '0' &&
              hdr[3] == '7' && hdr[4] == '0' && (hdr[5] == '1' || hdr[5] == '2'))) {
            break;
        }

        uint32_t namesz = hex8_to_u32(hdr + 94);
        uint32_t filesz = hex8_to_u32(hdr + 54);

        off += 110;
        if (off + namesz > size) break;

        const char *name = (const char *)(base + off);
        if (namesz == 0) break;
        if (name[0] == '\0') break;

        uint64_t name_end = off + namesz;
        off = (name_end + 3) & ~3ull;

        if (str_eq(name, "TRAILER!!!")) break;

        while (name[0] == '.' && name[1] == '/') name += 2;
        while (name[0] == '/') name++;
        if (name[0] == '\0') continue;
        size_t name_len = str_len(name);
        int is_dir = 0;
        if (name_len > 0 && name[name_len - 1] == '/') {
            is_dir = 1;
            name_len--;
            if (name_len == 0) continue;
        }

        const uint8_t *file_data = base + off;
        uint64_t data_end = off + filesz;
        off = (data_end + 3) & ~3ull;

        char path_buf[256];
        const char *path = name;
        if (name_len >= sizeof(path_buf)) continue;
        for (size_t i = 0; i < name_len; ++i) path_buf[i] = name[i];
        path_buf[name_len] = '\0';
        path = path_buf;

        int parent = 0;
        const char *leaf = NULL;
        size_t leaf_len = 0;
        if (!ensure_path_dirs(path, &parent, &leaf, &leaf_len)) continue;

        if (leaf_len == 0) continue;
        if (is_dir) {
            (void)get_or_create_dir(parent, leaf, leaf_len);
        } else {
            (void)add_file(parent, leaf, leaf_len, file_data, filesz);
        }
    }

    g_available = (g_node_count > 1);
    if (g_available) {
        log_printf("initramfs: loaded %u entries\n", (unsigned)(g_node_count - 1));
    } else {
        log_printf("initramfs: no entries\n");
    }
    return g_available;
}

int initramfs_available(void) {
    return g_available;
}

int initramfs_root(void) { return 0; }

int initramfs_is_dir(int node) {
    if (node < 0 || node >= g_node_count) return 0;
    return g_nodes[node].is_dir != 0;
}

int initramfs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node < 0 || node >= g_node_count) return 0;
    if (g_nodes[node].is_dir) return 0;
    *data = g_nodes[node].data;
    *size = g_nodes[node].size;
    return (*data != NULL);
}

int initramfs_resolve(int cwd, const char *path) {
    if (!path || path[0] == '\0') return cwd;
    int cur = (path[0] == '/') ? 0 : cwd;
    size_t i = (path[0] == '/') ? 1 : 0;
    char part[64];
    size_t p = 0;

    while (1) {
        char c = path[i];
        if (c == '/' || c == '\0') {
            part[p] = '\0';
            if (p > 0) {
                if (str_eq(part, ".")) {
                    /* no-op */
                } else if (str_eq(part, "..")) {
                    if (cur != 0) cur = g_nodes[cur].parent;
                } else {
                    int next = find_child(cur, part);
                    if (next < 0) return -1;
                    cur = next;
                }
            }
            p = 0;
            if (c == '\0') break;
        } else if (p + 1 < sizeof(part)) {
            part[p++] = c;
        }
        i++;
    }
    return cur;
}

void initramfs_pwd(int cwd) {
    char buf[256];
    size_t len = 0;
    int cur = cwd;
    if (cur == 0) {
        log_printf("/\n");
        return;
    }
    while (cur > 0 && len + 2 < sizeof(buf)) {
        const char *name = g_nodes[cur].name;
        size_t nlen = str_len(name);
        if (len + nlen + 1 >= sizeof(buf)) break;
        for (size_t i = 0; i < nlen; ++i) buf[len++] = name[i];
        buf[len++] = '/';
        cur = g_nodes[cur].parent;
    }
    for (size_t i = 0; i < len / 2; ++i) {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    buf[len - 1] = '\0';
    log_printf("/%s\n", buf);
}

void initramfs_ls(int node) {
    if (node < 0 || node >= g_node_count) return;
    const struct ir_node *d = &g_nodes[node];
    if (!d->is_dir) {
        log_printf("%s\n", d->name);
        return;
    }
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i].parent != node) continue;
        log_printf("%s%s ", g_nodes[i].name, g_nodes[i].is_dir ? "/" : "");
    }
    log_printf("\n");
}
