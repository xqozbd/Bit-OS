#include "sys/vfs.h"

#include <stddef.h>
#include <stdint.h>

#include "sys/initramfs.h"
#include "sys/fs_mock.h"
#include "sys/blockfs.h"
#include "sys/fat32.h"
#include "sys/ext2.h"
#include "sys/pseudofs.h"
#include "sys/tmpfs.h"
#include "lib/strutil.h"
#include "lib/log.h"
#include "kernel/slab.h"
#include "sys/journal.h"
#include "kernel/task.h"
enum { VFS_MAX_NODES = 512 };

struct vfs_node {
    int backend;
    int node;
    int parent;
    const char *name;
    int is_dir;
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
};

struct vfs_mount {
    const char *path;
    int backend;
    int root;
};

static struct vfs_node *g_nodes[VFS_MAX_NODES];
static int g_node_count = 0;
static struct mount_namespace g_root_ns;

static int mount_match(const char *path);
static int vfs_wrap_node(int backend, int node);

static int backend_get_attr(int backend, int node, uint32_t *uid, uint32_t *gid, uint16_t *mode, int *is_dir) {
    if (backend == VFS_BACKEND_DEV) {
        if (uid) *uid = 0;
        if (gid) *gid = 0;
        if (is_dir) *is_dir = (node == 0);
        if (mode) *mode = (uint16_t)((node == 0) ? 0755u : 0666u);
        return 1;
    }
    if (backend == VFS_BACKEND_EXT2) {
        return ext2_get_attr(node, uid, gid, mode, is_dir);
    }
    if (backend == VFS_BACKEND_TMPFS) {
        return tmpfs_get_attr(node, uid, gid, mode, is_dir);
    }
    if (uid) *uid = 0;
    if (gid) *gid = 0;
    if (mode) *mode = (uint16_t)((is_dir && *is_dir) ? 0755u : 0644u);
    return 1;
}

static int backend_set_attr(int backend, int node, uint32_t uid, uint32_t gid, uint16_t mode,
                            int set_uid, int set_gid, int set_mode) {
    if (backend == VFS_BACKEND_EXT2) {
        return ext2_set_attr(node, uid, gid, mode, set_uid, set_gid, set_mode);
    }
    if (backend == VFS_BACKEND_TMPFS) {
        return tmpfs_set_attr(node, uid, gid, mode, set_uid, set_gid, set_mode);
    }
    return 0;
}

static int backend_readlink(int backend, int node, char *out, size_t out_len) {
    if (backend == VFS_BACKEND_EXT2) return ext2_readlink(node, out, out_len);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_readlink(node, out, out_len);
    return -1;
}

static int backend_link_node(int backend, int parent, int target, const char *name) {
    if (backend == VFS_BACKEND_EXT2) return ext2_link_node(parent, target, name);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_link_node(parent, target, name);
    return -1;
}

static int backend_symlink_node(int backend, int parent, const char *name, const char *target) {
    if (backend == VFS_BACKEND_EXT2) return ext2_symlink_node(parent, name, target);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_symlink_node(parent, name, target);
    return -1;
}

static int mount_match(const char *path);
static int vfs_wrap_node(int backend, int node);

static void nodes_reset(void) {
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i]) {
            slab_free(g_nodes[i]);
            g_nodes[i] = NULL;
        }
    }
    g_node_count = 0;
}

static int backend_get_attr(int backend, int node, uint32_t *uid, uint32_t *gid, uint16_t *mode, int *is_dir);

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
    n->uid = 0;
    n->gid = 0;
    n->mode = (uint16_t)(is_dir ? 0755u : 0644u);
    (void)backend_get_attr(backend, node, &n->uid, &n->gid, &n->mode, &n->is_dir);
    g_nodes[idx] = n;
    return idx;
}

static int vfs_check_perm_node(struct vfs_node *n, int want) {
    if (!n) return 0;
    struct task *t = task_current();
    if (!t) return 1;
    if (t->uid == 0) return 1;
    uint32_t uid = n->uid;
    uint32_t gid = n->gid;
    uint16_t mode = n->mode;
    uint16_t bits = 0;
    if (t->uid == uid) bits = (uint16_t)((mode >> 6) & 0x7);
    else if (t->gid == gid) bits = (uint16_t)((mode >> 3) & 0x7);
    else bits = (uint16_t)(mode & 0x7);
    if ((want & 4) && !(bits & 4)) return 0;
    if ((want & 2) && !(bits & 2)) return 0;
    if ((want & 1) && !(bits & 1)) return 0;
    return 1;
}

static int ensure_root(void) {
    nodes_reset();
    g_root_ns.root_backend = VFS_BACKEND_MOCK;
    g_root_ns.root_node = 0;
    g_root_ns.root_index = node_new(VFS_BACKEND_MOCK, 0, -1, "/", 1);
    g_root_ns.mount_count = 0;
    g_root_ns.mounts[g_root_ns.mount_count].path = "/";
    g_root_ns.mounts[g_root_ns.mount_count].backend = g_root_ns.root_backend;
    g_root_ns.mounts[g_root_ns.mount_count].root = g_root_ns.root_node;
    g_root_ns.mount_count++;
    return g_root_ns.root_index;
}

void vfs_init(void) {
    g_root_ns.id = 1;
    g_root_ns.refcount = 1;
    ensure_root();
}

struct mount_namespace *vfs_root_namespace(void) {
    return &g_root_ns;
}

static struct mount_namespace *vfs_ns_current(void) {
    struct task *t = task_current();
    if (t && t->mnt_ns) return t->mnt_ns;
    return &g_root_ns;
}

void vfs_ns_clone(struct mount_namespace *dst, const struct mount_namespace *src) {
    if (!dst || !src) return;
    dst->root_backend = src->root_backend;
    dst->root_node = src->root_node;
    dst->root_index = node_new(dst->root_backend, dst->root_node, -1, "/", 1);
    dst->mount_count = 0;
    for (int i = 0; i < src->mount_count && i < VFS_MAX_MOUNTS; ++i) {
        dst->mounts[dst->mount_count] = src->mounts[i];
        dst->mount_count++;
    }
    if (dst->mount_count == 0) {
        dst->mounts[0].path = "/";
        dst->mounts[0].backend = dst->root_backend;
        dst->mounts[0].root = dst->root_node;
        dst->mount_count = 1;
    } else {
        dst->mounts[0].path = "/";
        dst->mounts[0].backend = dst->root_backend;
        dst->mounts[0].root = dst->root_node;
    }
}

void vfs_set_root(int backend, int root_node) {
    struct mount_namespace *ns = vfs_ns_current();
    if (!ns) return;
    if (ns->root_index < 0) {
        ns->root_index = node_new(backend, root_node, -1, "/", 1);
    }
    g_nodes[ns->root_index]->backend = backend;
    g_nodes[ns->root_index]->node = root_node;
    ns->root_backend = backend;
    ns->root_node = root_node;
    if (ns->mount_count > 0) {
        ns->mounts[0].backend = backend;
        ns->mounts[0].root = root_node;
    } else {
        ns->mounts[0].path = "/";
        ns->mounts[0].backend = backend;
        ns->mounts[0].root = root_node;
        ns->mount_count = 1;
    }
}

int vfs_mount(const char *path, int backend, int root_node) {
    struct mount_namespace *ns = vfs_ns_current();
    if (!ns) return -1;
    if (!path || ns->mount_count >= VFS_MAX_MOUNTS) return -1;
    ns->mounts[ns->mount_count].path = path;
    ns->mounts[ns->mount_count].backend = backend;
    ns->mounts[ns->mount_count].root = root_node;
    return ns->mount_count++;
}

static int backend_is_dir(int backend, int node) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_is_dir(node);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_is_dir(node);
    if (backend == VFS_BACKEND_FAT32) return fat32_is_dir(node);
    if (backend == VFS_BACKEND_DEV) return pseudofs_is_dir(PSEUDOFS_DEV, node);
    if (backend == VFS_BACKEND_PROC) return pseudofs_is_dir(PSEUDOFS_PROC, node);
    if (backend == VFS_BACKEND_SYS) return pseudofs_is_dir(PSEUDOFS_SYS, node);
    if (backend == VFS_BACKEND_EXT2) return ext2_is_dir(node);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_is_dir(node);
    return fs_is_dir(node);
}

static int backend_read_file(int backend, int node, const uint8_t **data, uint64_t *size) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_read_file(node, data, size);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_read_file(node, data, size);
    if (backend == VFS_BACKEND_FAT32) return fat32_read_file(node, data, size);
    if (backend == VFS_BACKEND_DEV) return pseudofs_read_file(PSEUDOFS_DEV, node, data, size);
    if (backend == VFS_BACKEND_PROC) return pseudofs_read_file(PSEUDOFS_PROC, node, data, size);
    if (backend == VFS_BACKEND_SYS) return pseudofs_read_file(PSEUDOFS_SYS, node, data, size);
    if (backend == VFS_BACKEND_EXT2) return ext2_read_file(node, data, size);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_read_file(node, data, size);
    return fs_read_file(node, data, size);
}

static int backend_write_file(int backend, int node, const uint8_t *data, uint64_t size, uint64_t offset) {
    if (backend == VFS_BACKEND_EXT2) return ext2_write(node, data, size, offset);
    if (backend == VFS_BACKEND_FAT32) {
        int rc = fat32_write_file(node, data, size, offset);
        return (rc == 0) ? (int)size : -1;
    }
    if (backend == VFS_BACKEND_DEV) {
        if (node == 1) return (int)size; /* /dev/null */
        if (node == 2) {
            for (uint64_t i = 0; i < size; ++i) {
                log_printf("%c", (char)data[i]);
            }
            return (int)size;
        }
    }
    if (backend == VFS_BACKEND_TMPFS) {
        return tmpfs_write_file(node, data, size, offset);
    }
    return -1;
}

static int backend_truncate(int backend, int node, uint64_t new_size) {
    if (backend == VFS_BACKEND_EXT2) return ext2_truncate(node, new_size);
    if (backend == VFS_BACKEND_FAT32) return fat32_truncate(node, new_size);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_truncate(node, new_size);
    return -1;
}

static uint64_t backend_get_size(int backend, int node) {
    if (backend == VFS_BACKEND_EXT2) return ext2_get_size(node);
    if (backend == VFS_BACKEND_FAT32) return fat32_get_size(node);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_get_size(node);
    return 0;
}

static int backend_counts_quota(int backend) {
    if (backend == VFS_BACKEND_EXT2) return 1;
    if (backend == VFS_BACKEND_FAT32) return 1;
    if (backend == VFS_BACKEND_BLOCK) return 1;
    return 0;
}

static int backend_resolve(int backend, int cwd, const char *path) {
    if (backend == VFS_BACKEND_INITRAMFS) return initramfs_resolve(cwd, path);
    if (backend == VFS_BACKEND_BLOCK) return blockfs_resolve(cwd, path);
    if (backend == VFS_BACKEND_FAT32) return fat32_resolve(cwd, path);
    if (backend == VFS_BACKEND_DEV) return pseudofs_resolve(PSEUDOFS_DEV, cwd, path);
    if (backend == VFS_BACKEND_PROC) return pseudofs_resolve(PSEUDOFS_PROC, cwd, path);
    if (backend == VFS_BACKEND_SYS) return pseudofs_resolve(PSEUDOFS_SYS, cwd, path);
    if (backend == VFS_BACKEND_EXT2) return ext2_resolve(cwd, path);
    if (backend == VFS_BACKEND_TMPFS) return tmpfs_resolve(cwd, path);
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

static int vfs_readlink_node(int node, char *out, size_t out_len) {
    if (node < 0 || node >= g_node_count || !g_nodes[node] || !out || out_len == 0) return -1;
    struct vfs_node *n = g_nodes[node];
    return backend_readlink(n->backend, n->node, out, out_len);
}

static int vfs_resolve_internal(int cwd, const char *path, int follow_symlinks, int depth) {
    if (!path || path[0] == '\0') return cwd;
    char norm[256];
    normalize_path(path, norm, sizeof(norm));

    int m = mount_match(norm);
    struct mount_namespace *ns = vfs_ns_current();
    int backend = g_nodes[ns->root_index]->backend;
    int root_node = g_nodes[ns->root_index]->node;
    const char *sub = norm;
    if (m >= 0) {
        backend = ns->mounts[m].backend;
        root_node = ns->mounts[m].root;
        size_t len = str_len(ns->mounts[m].path);
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
    int node = vfs_wrap_node(backend, raw);
    if (!follow_symlinks || node < 0 || depth <= 0) return node;

    uint16_t mode = 0;
    if (vfs_get_attr(node, NULL, NULL, &mode, NULL)) {
        if ((mode & 0xF000u) == 0xA000u) {
            char target[256];
            int n = vfs_readlink_node(node, target, sizeof(target));
            if (n > 0) {
                target[(n < (int)sizeof(target)) ? n : (int)sizeof(target) - 1] = '\0';
                char newpath[512];
                if (target[0] == '/') {
                    size_t tlen = str_len(target);
                    if (tlen >= sizeof(newpath)) return node;
                    for (size_t i = 0; i <= tlen; ++i) newpath[i] = target[i];
                } else {
                    char base[256];
                    int parent = g_nodes[node] ? g_nodes[node]->parent : -1;
                    if (parent >= 0) {
                        if (vfs_build_path(parent, base, sizeof(base)) != 0) {
                            base[0] = '/'; base[1] = '\0';
                        }
                    } else {
                        base[0] = '/'; base[1] = '\0';
                    }
                    size_t blen = str_len(base);
                    size_t tlen = str_len(target);
                    if (blen + 1 + tlen + 1 >= sizeof(newpath)) return node;
                    size_t w = 0;
                    for (size_t i = 0; i < blen; ++i) newpath[w++] = base[i];
                    if (w == 0 || newpath[w - 1] != '/') newpath[w++] = '/';
                    for (size_t i = 0; i < tlen; ++i) newpath[w++] = target[i];
                    newpath[w] = '\0';
                }
                return vfs_resolve_internal(cwd, newpath, 1, depth - 1);
            }
        }
    }
    return node;
}

int vfs_root_backend(void) {
    struct mount_namespace *ns = vfs_ns_current();
    return ns ? ns->root_backend : VFS_BACKEND_MOCK;
}

int vfs_node_backend(int node) {
    if (node < 0 || node >= g_node_count) return -1;
    if (!g_nodes[node]) return -1;
    return g_nodes[node]->backend;
}

int vfs_node_raw(int node) {
    if (node < 0 || node >= g_node_count) return -1;
    if (!g_nodes[node]) return -1;
    return g_nodes[node]->node;
}

int vfs_get_attr(int node, uint32_t *uid, uint32_t *gid, uint16_t *mode, int *is_dir) {
    if (node < 0 || node >= g_node_count) return 0;
    struct vfs_node *n = g_nodes[node];
    if (!n) return 0;
    uint32_t buid = n->uid;
    uint32_t bgid = n->gid;
    uint16_t bmode = n->mode;
    int bdir = n->is_dir;
    if (backend_get_attr(n->backend, n->node, &buid, &bgid, &bmode, &bdir)) {
        n->uid = buid;
        n->gid = bgid;
        n->mode = bmode;
        n->is_dir = bdir;
    }
    if (uid) *uid = n->uid;
    if (gid) *gid = n->gid;
    if (mode) *mode = n->mode;
    if (is_dir) *is_dir = n->is_dir;
    return 1;
}

int vfs_chmod(int node, uint16_t mode) {
    if (node < 0 || node >= g_node_count) return 0;
    struct vfs_node *n = g_nodes[node];
    if (!n) return 0;
    if (!backend_set_attr(n->backend, n->node, 0, 0, mode, 0, 0, 1)) return 0;
    n->mode = (uint16_t)(mode & 0x0FFFu);
    return 1;
}

int vfs_chown(int node, uint32_t uid, uint32_t gid) {
    if (node < 0 || node >= g_node_count) return 0;
    struct vfs_node *n = g_nodes[node];
    if (!n) return 0;
    if (!backend_set_attr(n->backend, n->node, uid, gid, 0, 1, 1, 0)) return 0;
    n->uid = uid;
    n->gid = gid;
    return 1;
}

int vfs_build_path(int node, char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return -1;
    const char *parts[32];
    size_t part_len[32];
    int depth = 0;
    int cur = node;
    while (cur >= 0 && cur < g_node_count && g_nodes[cur] && depth < (int)(sizeof(parts) / sizeof(parts[0]))) {
        const struct vfs_node *n = g_nodes[cur];
        const char *name = n->name ? n->name : "/";
        parts[depth] = name;
        part_len[depth] = str_len(name);
        depth++;
        if (cur == vfs_ns_current()->root_index) break;
        cur = n->parent;
    }
    size_t w = 0;
    for (int i = depth - 1; i >= 0; --i) {
        if (w + 1 >= out_len) return -1;
        if (w == 0 || out[w - 1] != '/') out[w++] = '/';
        const char *nm = parts[i];
        size_t nlen = part_len[i];
        if (nlen == 1 && nm[0] == '/') continue;
        if (w + nlen >= out_len) return -1;
        for (size_t j = 0; j < nlen; ++j) out[w++] = nm[j];
    }
    if (w == 0) {
        if (out_len < 2) return -1;
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }
    out[w] = '\0';
    return 0;
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

static int mount_match(const char *path) {
    struct mount_namespace *ns = vfs_ns_current();
    if (!ns) return -1;
    int best = -1;
    size_t best_len = 0;
    for (int i = 0; i < ns->mount_count; ++i) {
        const char *mp = ns->mounts[i].path;
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
    struct mount_namespace *ns = vfs_ns_current();
    if (node < 0) return -1;
    for (int i = 0; i < g_node_count; ++i) {
        if (g_nodes[i] && g_nodes[i]->backend == backend && g_nodes[i]->node == node) return i;
    }
    const char *name = "/";
    int is_dir = backend_is_dir(backend, node);
    return node_new(backend, node, ns ? ns->root_index : -1, name, is_dir);
}

int vfs_resolve(int cwd, const char *path) {
    return vfs_resolve_internal(cwd, path, 1, 8);
}

int vfs_is_dir(int node) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return 0;
    return g_nodes[node]->is_dir;
}

int vfs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return 0;
    vfs_get_attr(node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(g_nodes[node], 4)) return 0;
    return backend_read_file(g_nodes[node]->backend, g_nodes[node]->node, data, size);
}

int vfs_write_file(int node, const uint8_t *data, uint64_t size, uint64_t offset) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return -1;
    vfs_get_attr(node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(g_nodes[node], 2)) return -1;
    struct task *t = task_current();
    uint64_t old_size = 0;
    uint64_t growth = 0;
    if (backend_counts_quota(g_nodes[node]->backend)) {
        if (offset > UINT64_MAX - size) return -1;
        old_size = backend_get_size(g_nodes[node]->backend, g_nodes[node]->node);
        uint64_t end = offset + size;
        if (end > old_size) growth = end - old_size;
        if (growth > 0 && t && t->disk_quota_bytes &&
            (t->disk_used_bytes + growth > t->disk_quota_bytes)) {
            return -1;
        }
    }
    if (journal_can_log(node)) {
        (void)journal_log_write(node, offset, data, (uint32_t)size);
    }
    int rc = backend_write_file(g_nodes[node]->backend, g_nodes[node]->node, data, size, offset);
    if (rc >= 0 && journal_can_log(node)) {
        journal_clear();
    }
    if (rc >= 0 && growth > 0 && t) {
        (void)task_charge_disk(t, growth);
    }
    return rc;
}

int vfs_truncate(int node, uint64_t new_size) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return -1;
    vfs_get_attr(node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(g_nodes[node], 2)) return -1;
    struct task *t = task_current();
    uint64_t old_size = 0;
    uint64_t growth = 0;
    uint64_t shrink = 0;
    if (backend_counts_quota(g_nodes[node]->backend)) {
        old_size = backend_get_size(g_nodes[node]->backend, g_nodes[node]->node);
        if (new_size > old_size) {
            growth = new_size - old_size;
            if (growth > 0 && t && t->disk_quota_bytes &&
                (t->disk_used_bytes + growth > t->disk_quota_bytes)) {
                return -1;
            }
        } else if (new_size < old_size) {
            shrink = old_size - new_size;
        }
    }
    if (journal_can_log(node)) {
        (void)journal_log_truncate(node, new_size);
    }
    int rc = backend_truncate(g_nodes[node]->backend, g_nodes[node]->node, new_size);
    if (rc == 0 && journal_can_log(node)) {
        journal_clear();
    }
    if (rc == 0 && t) {
        if (growth > 0) {
            (void)task_charge_disk(t, growth);
        } else if (shrink > 0) {
            task_uncharge_disk(t, shrink);
        }
    }
    return rc;
}

uint64_t vfs_get_size(int node) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return 0;
    return backend_get_size(g_nodes[node]->backend, g_nodes[node]->node);
}

int vfs_create(int cwd, const char *path, int is_dir) {
    if (!path || path[0] == '\0') return -1;
    char parent[256];
    char name[128];
    if (split_path(path, parent, sizeof(parent), name, sizeof(name)) != 0) return -1;

    int parent_node = vfs_resolve(cwd, parent);
    if (parent_node < 0) return -1;
    if (!vfs_is_dir(parent_node)) return -1;
    struct vfs_node *p = g_nodes[parent_node];
    if (!p) return -1;
    vfs_get_attr(parent_node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(p, 3)) return -1;

    int raw = -1;
    if (p->backend == VFS_BACKEND_EXT2) {
        char tmp[260];
        size_t nlen = str_len(name);
        if (nlen + 3 >= sizeof(tmp)) return -1;
        tmp[0] = '.';
        tmp[1] = '/';
        for (size_t i = 0; i < nlen; ++i) tmp[2 + i] = name[i];
        tmp[2 + nlen] = '\0';
        uint16_t mode = is_dir ? 0755u : 0644u;
        struct task *t = task_current();
        if (t) mode = (uint16_t)(mode & (uint16_t)~t->umask);
        raw = ext2_create(p->node, tmp, mode, is_dir);
        if (raw >= 0) {
            struct task *t = task_current();
            if (t) ext2_set_attr(raw, t->uid, t->gid, mode, 1, 1, 0);
        }
    } else if (p->backend == VFS_BACKEND_FAT32) {
        raw = fat32_create(p->node, name, is_dir);
    } else if (p->backend == VFS_BACKEND_TMPFS) {
        uint16_t mode = is_dir ? 0755u : 0644u;
        struct task *t = task_current();
        if (t) mode = (uint16_t)(mode & (uint16_t)~t->umask);
        raw = tmpfs_create(p->node, name, is_dir);
        if (raw >= 0) {
            struct task *t = task_current();
            if (t) tmpfs_set_attr(raw, t->uid, t->gid, mode, 1, 1, 1);
        }
    } else {
        return -1;
    }
    return vfs_wrap_node(p->backend, raw);
}

int vfs_link(int cwd, const char *oldpath, const char *newpath) {
    if (!oldpath || !newpath) return -1;
    int old_node = vfs_resolve_internal(cwd, oldpath, 1, 8);
    if (old_node < 0 || old_node >= g_node_count) return -1;
    if (vfs_is_dir(old_node)) return -1;

    char parent[256];
    char name[128];
    if (split_path(newpath, parent, sizeof(parent), name, sizeof(name)) != 0) return -1;
    int parent_node = vfs_resolve_internal(cwd, parent, 1, 8);
    if (parent_node < 0 || !vfs_is_dir(parent_node)) return -1;
    struct vfs_node *p = g_nodes[parent_node];
    struct vfs_node *o = g_nodes[old_node];
    if (!p || !o) return -1;
    if (p->backend != o->backend) return -1;
    vfs_get_attr(parent_node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(p, 3)) return -1;

    int raw = backend_link_node(p->backend, p->node, o->node, name);
    return vfs_wrap_node(p->backend, raw);
}

int vfs_symlink(int cwd, const char *target, const char *linkpath) {
    if (!target || !linkpath) return -1;
    char parent[256];
    char name[128];
    if (split_path(linkpath, parent, sizeof(parent), name, sizeof(name)) != 0) return -1;
    int parent_node = vfs_resolve_internal(cwd, parent, 1, 8);
    if (parent_node < 0 || !vfs_is_dir(parent_node)) return -1;
    struct vfs_node *p = g_nodes[parent_node];
    if (!p) return -1;
    vfs_get_attr(parent_node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(p, 3)) return -1;

    int raw = backend_symlink_node(p->backend, p->node, name, target);
    return vfs_wrap_node(p->backend, raw);
}

int vfs_readlink(const char *path, char *out, size_t out_len) {
    if (!path || !out || out_len == 0) return -1;
    int node = vfs_resolve_internal(0, path, 0, 0);
    if (node < 0) return -1;
    return vfs_readlink_node(node, out, out_len);
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
    if (n->backend == VFS_BACKEND_EXT2) {
        ext2_pwd(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_TMPFS) {
        tmpfs_pwd(n->node);
        return;
    }
    fs_pwd(n->node);
}

void vfs_ls(int node) {
    if (node < 0 || node >= g_node_count || !g_nodes[node]) return;
    const struct vfs_node *n = g_nodes[node];
    struct mount_namespace *ns = vfs_ns_current();
    if (ns && node == ns->root_index) {
        /* List mount points that aren't part of the backend root. */
        int printed = 0;
        for (int i = 0; i < ns->mount_count; ++i) {
            const char *mp = ns->mounts[i].path;
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
    if (n->backend == VFS_BACKEND_EXT2) {
        ext2_ls(n->node);
        return;
    }
    if (n->backend == VFS_BACKEND_TMPFS) {
        tmpfs_ls(n->node);
        return;
    }
    fs_ls(n->node);
}

static int append_entry(char **w, uint64_t *remain, const char *name, int is_dir) {
    if (!w || !*w || !remain || !name) return -1;
    size_t len = str_len(name);
    if (len + 2 > *remain) return -1;
    for (size_t i = 0; i < len; ++i) (*w)[i] = name[i];
    size_t used = len;
    if (is_dir) (*w)[used++] = '/';
    (*w)[used++] = '\n';
    *w += used;
    *remain -= used;
    return 0;
}

int vfs_list_dir(const char *path, char *out, uint64_t out_len) {
    if (!out || out_len == 0) return -1;
    int node = vfs_resolve(0, (path && path[0]) ? path : "/");
    if (node < 0 || !vfs_is_dir(node)) return -1;
    const struct vfs_node *n = g_nodes[node];
    if (!n) return -1;
    vfs_get_attr(node, NULL, NULL, NULL, NULL);
    if (!vfs_check_perm_node(g_nodes[node], 5)) return -1;
    if (n->backend == VFS_BACKEND_TMPFS) {
        return tmpfs_list_dir(n->node, out, out_len);
    }

    if (n->backend == VFS_BACKEND_EXT2) ext2_ensure_scanned(n->node);
    if (n->backend == VFS_BACKEND_FAT32) fat32_ensure_scanned(n->node);

    char *w = out;
    uint64_t rem = out_len;

    struct mount_namespace *ns = vfs_ns_current();
    if (ns && node == ns->root_index) {
        for (int i = 0; i < ns->mount_count; ++i) {
            const char *mp = ns->mounts[i].path;
            if (!mp || str_eq(mp, "/")) continue;
            const char *name = mp;
            if (name[0] == '/') name++;
            if (*name == '\0') continue;
            if (append_entry(&w, &rem, name, 1) != 0) return -1;
        }
    }

    for (int i = 0; i < g_node_count; ++i) {
        if (!g_nodes[i]) continue;
        if (g_nodes[i]->parent == node) {
            if (append_entry(&w, &rem, g_nodes[i]->name, g_nodes[i]->is_dir) != 0) return -1;
        }
    }
    if (rem > 0) *w = '\0';
    return (int)(out_len - rem);
}
