#include "sys/tmpfs.h"

#include <stddef.h>

#include "kernel/heap.h"
#include "lib/log.h"
#include "lib/strutil.h"

#define TMPFS_MAX_NODES 256

struct tmpfs_node {
    char *name;
    int is_dir;
    int parent;
    int first_child;
    int next_sibling;
    uint8_t *data;
    uint64_t size;
    uint64_t cap;
};

static struct tmpfs_node g_nodes[TMPFS_MAX_NODES];
static int g_node_count = 0;
static int g_root = -1;

static int node_alloc(const char *name, int is_dir, int parent) {
    if (g_node_count >= TMPFS_MAX_NODES) return -1;
    int idx = g_node_count++;
    struct tmpfs_node *n = &g_nodes[idx];
    n->name = NULL;
    n->is_dir = is_dir;
    n->parent = parent;
    n->first_child = -1;
    n->next_sibling = -1;
    n->data = NULL;
    n->size = 0;
    n->cap = 0;
    if (name) {
        size_t len = str_len(name);
        n->name = (char *)kmalloc(len + 1);
        if (n->name) {
            for (size_t i = 0; i < len; ++i) n->name[i] = name[i];
            n->name[len] = '\0';
        }
    }
    return idx;
}

static int find_child(int dir, const char *name) {
    if (dir < 0 || dir >= g_node_count) return -1;
    if (!name) return -1;
    int cur = g_nodes[dir].first_child;
    while (cur >= 0) {
        if (g_nodes[cur].name && str_eq(g_nodes[cur].name, name)) return cur;
        cur = g_nodes[cur].next_sibling;
    }
    return -1;
}

static void link_child(int parent, int child) {
    if (parent < 0 || child < 0) return;
    g_nodes[child].next_sibling = g_nodes[parent].first_child;
    g_nodes[parent].first_child = child;
}

int tmpfs_init(void) {
    g_node_count = 0;
    g_root = node_alloc("/", 1, -1);
    return (g_root >= 0) ? 0 : -1;
}

int tmpfs_root(void) {
    if (g_root < 0) tmpfs_init();
    return g_root;
}

int tmpfs_is_dir(int node) {
    if (node < 0 || node >= g_node_count) return 0;
    return g_nodes[node].is_dir != 0;
}

int tmpfs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node < 0 || node >= g_node_count) return 0;
    if (g_nodes[node].is_dir) return 0;
    *data = g_nodes[node].data;
    *size = g_nodes[node].size;
    return 1;
}

static int ensure_cap(struct tmpfs_node *n, uint64_t cap) {
    if (!n) return -1;
    if (cap <= n->cap) return 0;
    uint64_t new_cap = n->cap ? n->cap : 64;
    while (new_cap < cap) new_cap *= 2;
    uint8_t *buf = (uint8_t *)kmalloc((size_t)new_cap);
    if (!buf) return -1;
    for (uint64_t i = 0; i < n->size; ++i) buf[i] = n->data ? n->data[i] : 0;
    if (n->data) kfree(n->data);
    n->data = buf;
    n->cap = new_cap;
    return 0;
}

int tmpfs_write_file(int node, const uint8_t *data, uint64_t size, uint64_t offset) {
    if (node < 0 || node >= g_node_count) return -1;
    struct tmpfs_node *n = &g_nodes[node];
    if (n->is_dir) return -1;
    if (offset + size < offset) return -1;
    if (ensure_cap(n, offset + size) != 0) return -1;
    for (uint64_t i = 0; i < size; ++i) {
        n->data[offset + i] = data ? data[i] : 0;
    }
    if (offset + size > n->size) n->size = offset + size;
    return (int)size;
}

int tmpfs_truncate(int node, uint64_t new_size) {
    if (node < 0 || node >= g_node_count) return -1;
    struct tmpfs_node *n = &g_nodes[node];
    if (n->is_dir) return -1;
    if (ensure_cap(n, new_size) != 0) return -1;
    if (new_size > n->size) {
        for (uint64_t i = n->size; i < new_size; ++i) n->data[i] = 0;
    }
    n->size = new_size;
    return 0;
}

uint64_t tmpfs_get_size(int node) {
    if (node < 0 || node >= g_node_count) return 0;
    if (g_nodes[node].is_dir) return 0;
    return g_nodes[node].size;
}

static int split_path(const char *path, char *parent_out, size_t parent_len,
                      char *name_out, size_t name_len) {
    if (!path || !parent_out || !name_out) return -1;
    size_t len = str_len(path);
    if (len == 0) return -1;
    while (len > 1 && path[len - 1] == '/') len--;
    size_t last = len;
    while (last > 0 && path[last - 1] != '/') last--;
    size_t n_len = len - last;
    if (n_len == 0 || n_len >= name_len) return -1;
    for (size_t i = 0; i < n_len; ++i) name_out[i] = path[last + i];
    name_out[n_len] = '\0';

    if (last == 0) {
        if (path[0] == '/') {
            if (parent_len < 2) return -1;
            parent_out[0] = '/';
            parent_out[1] = '\0';
        } else {
            if (parent_len < 2) return -1;
            parent_out[0] = '.';
            parent_out[1] = '\0';
        }
        return 0;
    }
    if (last >= parent_len) return -1;
    for (size_t i = 0; i < last; ++i) parent_out[i] = path[i];
    parent_out[last] = '\0';
    return 0;
}

int tmpfs_create(int cwd, const char *path, int is_dir) {
    if (!path || path[0] == '\0') return -1;
    char parent[256];
    char name[128];
    if (split_path(path, parent, sizeof(parent), name, sizeof(name)) != 0) return -1;
    int parent_node = tmpfs_resolve(cwd, parent);
    if (parent_node < 0 || !g_nodes[parent_node].is_dir) return -1;
    if (find_child(parent_node, name) >= 0) return -1;
    int idx = node_alloc(name, is_dir, parent_node);
    if (idx < 0) return -1;
    link_child(parent_node, idx);
    return idx;
}

int tmpfs_resolve(int cwd, const char *path) {
    if (!path || path[0] == '\0') return cwd;
    if (g_root < 0) tmpfs_init();
    int cur = (path[0] == '/') ? g_root : cwd;
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
                    if (cur != g_root && g_nodes[cur].parent >= 0) cur = g_nodes[cur].parent;
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

int tmpfs_list_dir(int node, char *out, uint64_t out_len) {
    if (!out || out_len == 0) return -1;
    if (node < 0 || node >= g_node_count) return -1;
    if (!g_nodes[node].is_dir) return -1;
    char *w = out;
    uint64_t rem = out_len;
    int cur = g_nodes[node].first_child;
    while (cur >= 0) {
        const char *name = g_nodes[cur].name ? g_nodes[cur].name : "";
        size_t len = str_len(name);
        if (len + 2 > rem) break;
        for (size_t i = 0; i < len; ++i) w[i] = name[i];
        size_t used = len;
        if (g_nodes[cur].is_dir) w[used++] = '/';
        w[used++] = '\n';
        w += used;
        rem -= used;
        cur = g_nodes[cur].next_sibling;
    }
    if (rem > 0) *w = '\0';
    return (int)(out_len - rem);
}

void tmpfs_pwd(int node) {
    if (node < 0 || node >= g_node_count) return;
    char buf[256];
    size_t len = 0;
    int cur = node;
    if (cur == g_root) {
        log_printf("/\n");
        return;
    }
    while (cur >= 0 && cur != g_root && len + 2 < sizeof(buf)) {
        const char *name = g_nodes[cur].name ? g_nodes[cur].name : "";
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

void tmpfs_ls(int node) {
    if (node < 0 || node >= g_node_count) return;
    if (!g_nodes[node].is_dir) {
        log_printf("%s\n", g_nodes[node].name ? g_nodes[node].name : "");
        return;
    }
    int cur = g_nodes[node].first_child;
    while (cur >= 0) {
        log_printf("%s%s ", g_nodes[cur].name ? g_nodes[cur].name : "",
                   g_nodes[cur].is_dir ? "/" : "");
        cur = g_nodes[cur].next_sibling;
    }
    log_printf("\n");
}
