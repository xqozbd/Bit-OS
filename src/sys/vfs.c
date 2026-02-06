#include "sys/vfs.h"

#include <stddef.h>

#include "sys/initramfs.h"
#include "sys/fs_mock.h"
#include "sys/blockfs.h"
#include "sys/fat32.h"
#include "sys/pseudofs.h"
#include "lib/strutil.h"
#include "lib/log.h"
#include "kernel/slab.h"
enum { VFS_MAX_NODES = 512 };

struct vfs_node {
    int backend;
    int node;
    int parent;
    const char *name;
    int is_dir;
};

struct vfs_mount {
    const char *path;
    int backend;
    int root;
};

static struct vfs_node *g_nodes[VFS_MAX_NODES];
static int g_node_count = 0;
static struct vfs_mount g_mounts[8];
static int g_mount_count = 0;
static int g_root = 0;

static void nodes_reset(void) {
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i]) {
            slab_free(g_nodes[i]);
            g_nodes[i] = NULL;
        }
    }
    g_node_count = 0;
}

static int node_new(int backend, int node, int parent, const char *name, int is_dir) {
    if (g_node_count >= VFS_MAX_NODES) return -1;
    struct vfs_node *n = slab_alloc(sizeof(*n));
    if (!n) return -1;
    int idx = g_node_count++;
    n->backend = backend;
    n->node = node;
    n->parent = parent;
    n->name = name;
    n->is_dir = is_dir;
    g_nodes[idx] = n;
    return idx;
}

static int ensure_root(void) {
    nodes_reset();
    g_root = node_new(VFS_BACKEND_MOCK, 0, -1, "/", 1);
    return g_root;
}

void vfs_init(void) {
    ensure_root();
    g_mount_count = 0;
    g_mounts[g_mount_count].path = "/";
    g_mounts[g_mount_count].backend = g_nodes[g_root]->backend;
    g_mounts[g_mount_count].root = g_nodes[g_root]->node;
    g_mount_count++;
}

void vfs_set_root(int backend, int root_node) {
    ensure_root();
    g_nodes[g_root]->backend = backend;
    g_nodes[g_root]->node = root_node;
    if (g_mount_count > 0) {
        g_mounts[0].backend = backend;
        g_mounts[0].root = root_node;
    }
}

int vfs_mount(const char *path, int backend, int root_node) {
    if (!path || g_mount_count >= (int)(sizeof(g_mounts) / sizeof(g_mounts[0]))) return -1;
    g_mounts[g_mount_count].path = path;
    g_mounts[g_mount_count].backend = backend;
    g_mounts[g_mount_count].root = root_node;
    return g_mount_count++;
}

static int backend_is_dir(int backend, int node) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_is_dir(node);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_is_dir(node);
    if (backend == VFS_BACKEND_FAT32) return fat32_is_dir(node);
    if (backend == VFS_BACKEND_DEV) return pseudofs_is_dir(PSEUDOFS_DEV, node);
    if (backend == VFS_BACKEND_PROC) return pseudofs_is_dir(PSEUDOFS_PROC, node);
    if (backend == VFS_BACKEND_SYS) return pseudofs_is_dir(PSEUDOFS_SYS, node);
    return fs_is_dir(node);
}

static int backend_read_file(int backend, int node, const uint8_t **data, uint64_t *size) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_read_file(node, data, size);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_read_file(node, data, size);
    if (backend == VFS_BACKEND_FAT32) return fat32_read_file(node, data, size);
    if (backend == VFS_BACKEND_DEV) return pseudofs_read_file(PSEUDOFS_DEV, node, data, size);
    if (backend == VFS_BACKEND_PROC) return pseudofs_read_file(PSEUDOFS_PROC, node, data, size);
    if (backend == VFS_BACKEND_SYS) return pseudofs_read_file(PSEUDOFS_SYS, node, data, size);
    return fs_read_file(node, data, size);
}

static int backend_resolve(int backend, int cwd, const char *path) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_resolve(cwd, path);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_resolve(cwd, path);
    if (backend == VFS_BACKEND_FAT32) return fat32_resolve(cwd, path);
    if (backend == VFS_BACKEND_DEV) return pseudofs_resolve(PSEUDOFS_DEV, cwd, path);
    if (backend == VFS_BACKEND_PROC) return pseudofs_resolve(PSEUDOFS_PROC, cwd, path);
    if (backend == VFS_BACKEND_SYS) return pseudofs_resolve(PSEUDOFS_SYS, cwd, path);
    return fs_resolve(cwd, path);
}

static void normalize_path(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) return;
    size_t w = 0;
    size_t r = 0;
    if (path[0] != '/') {
        out[w++] = '/';
    }
    while (path[r] && w + 1 < out_size) {
        if (path[r] == '/') {
            while (path[r] == '/') r++;
            if (w == 0 || out[w - 1] != '/') out[w++] = '/';
            continue;
        }
        if (path[r] == '.' && (path[r + 1] == '/' || path[r + 1] == '\0')) {
            r += (path[r + 1] == '/') ? 2 : 1;
            continue;
        }
        if (path[r] == '.' && path[r + 1] == '.' &&
            (path[r + 2] == '/' || path[r + 2] == '\0')) {
            r += (path[r + 2] == '/') ? 3 : 2;
            if (w > 1) {
                w--;
                while (w > 1 && out[w - 1] != '/') w--;
            }
            continue;
        }
        out[w++] = path[r++];
    }
    if (w == 0) out[w++] = '/';
    if (w > 1 && out[w - 1] == '/') w--;
    out[w] = '\0';
}

static int mount_match(const char *path) {
    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < g_mount_count; ++i) {
        const char *mp = g_mounts[i].path;
        size_t len = str_len(mp);
        if (len > best_len && str_eq(mp, "/")) {
            best = i;
            best_len = len;
        }
        if (str_eq(mp, path)) {
            return i;
        }
        if (len > 1 && str_starts_with(path, mp) && path[len] == '/') {
            if (len > best_len) {
                best = i;
                best_len = len;
            }
        }
    }
    return best;
}

static int vfs_wrap_node(int backend, int node) {
    if (node < 0) return -1;
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i] && g_nodes[i]->backend == backend && g_nodes[i]->node == node) return i;
    }
    const char *name = "/";
    int is_dir = backend_is_dir(backend, node);
    return node_new(backend, node, g_root, name, is_dir);
}

int vfs_resolve(int cwd, const char *path) {
    if (!path || path[0] == '\0') return cwd;
    char norm[256];
    normalize_path(path, norm, sizeof(norm));

    int m = mount_match(norm);
    int backend = g_nodes[g_root]->backend;
    int root_node = g_nodes[g_root]->node;
    const char *sub = norm;
    if (m >= 0) {
        backend = g_mounts[m].backend;
        root_node = g_mounts[m].root;
        size_t len = str_len(g_mounts[m].path);
        sub = norm + len;
        if (sub[0] == '/') sub++;
        if (sub[0] == '\0') sub = "/";
    }
    int raw;
    if (sub[0] == '/') {
        raw = backend_resolve(backend, root_node, sub);
    } else {
        int backend_cwd = root_node;
        if (cwd >= 0 && cwd < g_node_count && g_nodes[cwd] && g_nodes[cwd]->backend == backend) {
            backend_cwd = g_nodes[cwd]->node;
        }
        raw = backend_resolve(backend, backend_cwd, sub);
    }
    return vfs_wrap_node(backend, raw);
}

int vfs_is_dir(int node) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return 0;
    return g_nodes[node]->is_dir;
}

int vfs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return 0;
    return backend_read_file(g_nodes[node]->backend, g_nodes[node]->node, data, size);
}

void vfs_pwd(int cwd) {
    if (cwd < 0 || cwd >= g_node_count || !g_nodes[cwd]) return;
    const struct vfs_node *n = g_nodes[cwd];
    if (n->backend == VFS_BACKEND_INITRAMFS) {
        initramfs_pwd(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_BLOCK) {
        blockfs_pwd(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_FAT32) {
        fat32_pwd(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_DEV) {
        pseudofs_pwd(PSEUDOFS_DEV, n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_PROC) {
        pseudofs_pwd(PSEUDOFS_PROC, n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_SYS) {
        pseudofs_pwd(PSEUDOFS_SYS, n->node);
        return;
    }
    fs_pwd(n->node);
}

void vfs_ls(int node) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return;
    const struct vfs_node *n = g_nodes[node];
    if (node == g_root) {
        /* List mount points that aren't part of the backend root. */
        int printed = 0;
        for (int i = 0; i < g_mount_count; ++i) {
            const char *mp = g_mounts[i].path;
            if (!mp || str_eq(mp, "/")) continue;
            if (mp[0] == '/') mp++;
            if (*mp == '\0') continue;
            log_printf("%s/ ", mp);
            printed = 1;
        }
        if (printed) log_printf("\n");
    }
    if (n->backend == VFS_BACKEND_INITRAMFS) {
        initramfs_ls(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_BLOCK) {
        blockfs_ls(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_FAT32) {
        fat32_ls(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_DEV) {
        pseudofs_ls(PSEUDOFS_DEV, n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_PROC) {
        pseudofs_ls(PSEUDOFS_PROC, n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_SYS) {
        pseudofs_ls(PSEUDOFS_SYS, n->node);
        return;
    }
    fs_ls(n->node);
}
