#include "sys/fs_mock.h"

#include "sys/initramfs.h"
#include "lib/log.h"
#include "lib/strutil.h"

enum { FS_MAX_NODES = 16 };

struct fs_node {
    const char *name;
    int is_dir;
    int parent;
    int child_start;
    int child_count;
};

static const char g_readme_txt[] =
    "BitOS mock FS\n"
    "This is a placeholder file.\n";

static const char g_hello_txt[] =
    "#!/bin/bitos\n"
    "echo Hello from BitOS\n";

static const char g_echo_txt[] =
    "#!/bin/bitos\n"
    "echo $@\n";

static const char g_os_conf[] =
    "name=BitOS\n"
    "version=0.1.0\n";

static const char g_note_txt[] =
    "Welcome to BitOS.\n";

static const struct fs_node fs_nodes[FS_MAX_NODES] = {
    { "/", 1, -1, 1, 5 },        /* 0 */
    { "bin", 1, 0, 6, 2 },        /* 1 */
    { "etc", 1, 0, 8, 1 },        /* 2 */
    { "home", 1, 0, 9, 1 },       /* 3 */
    { "dev", 1, 0, 10, 2 },       /* 4 */
    { "README.txt", 0, 0, 0, 0 }, /* 5 */
    { "hello", 0, 1, 0, 0 },      /* 6 */
    { "echo", 0, 1, 0, 0 },       /* 7 */
    { "os.conf", 0, 2, 0, 0 },    /* 8 */
    { "guest", 1, 3, 12, 1 },     /* 9 */
    { "null", 0, 4, 0, 0 },       /* 10 */
    { "tty0", 0, 4, 0, 0 },       /* 11 */
    { "note.txt", 0, 9, 0, 0 },   /* 12 */
};

int fs_root(void) {
    if (initramfs_available()) return initramfs_root();
    return 0;
}

int fs_is_dir(int node) {
    if (initramfs_available()) return initramfs_is_dir(node);
    if (node < 0 || node >= FS_MAX_NODES) return 0;
    return fs_nodes[node].is_dir != 0;
}

int fs_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (initramfs_available()) return initramfs_read_file(node, data, size);
    if (!data || !size) return 0;
    if (node < 0 || node >= FS_MAX_NODES) return 0;
    if (fs_nodes[node].is_dir) return 0;

    const char *name = fs_nodes[node].name;
    if (str_eq(name, "README.txt")) {
        *data = (const uint8_t *)g_readme_txt;
        *size = (uint64_t)(sizeof(g_readme_txt) - 1);
        return 1;
    }
    if (str_eq(name, "hello")) {
        *data = (const uint8_t *)g_hello_txt;
        *size = (uint64_t)(sizeof(g_hello_txt) - 1);
        return 1;
    }
    if (str_eq(name, "echo")) {
        *data = (const uint8_t *)g_echo_txt;
        *size = (uint64_t)(sizeof(g_echo_txt) - 1);
        return 1;
    }
    if (str_eq(name, "os.conf")) {
        *data = (const uint8_t *)g_os_conf;
        *size = (uint64_t)(sizeof(g_os_conf) - 1);
        return 1;
    }
    if (str_eq(name, "note.txt")) {
        *data = (const uint8_t *)g_note_txt;
        *size = (uint64_t)(sizeof(g_note_txt) - 1);
        return 1;
    }

    return 0;
}

static int fs_find_child(int dir, const char *name) {
    if (dir < 0 || dir >= FS_MAX_NODES) return -1;
    const struct fs_node *d = &fs_nodes[dir];
    if (!d->is_dir) return -1;
    for (int i = 0; i < d->child_count; ++i) {
        int idx = d->child_start + i;
        if (idx >= FS_MAX_NODES) break;
        if (str_eq(fs_nodes[idx].name, name)) return idx;
    }
    return -1;
}

int fs_resolve(int cwd, const char *path) {
    if (initramfs_available()) return initramfs_resolve(cwd, path);
    if (!path || path[0] == '\0') return cwd;
    int cur = (path[0] == '/') ? 0 : cwd;
    size_t i = (path[0] == '/') ? 1 : 0;
    char part[32];
    size_t p = 0;

    while (1) {
        char c = path[i];
        if (c == '/' || c == '\0') {
            part[p] = '\0';
            if (p > 0) {
                if (str_eq(part, ".")) {
                    /* no-op */
                } else if (str_eq(part, "..")) {
                    if (cur != 0) cur = fs_nodes[cur].parent;
                } else {
                    int next = fs_find_child(cur, part);
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

void fs_pwd(int cwd) {
    if (initramfs_available()) {
        initramfs_pwd(cwd);
        return;
    }
    char buf[128];
    size_t len = 0;
    int cur = cwd;
    if (cur == 0) {
        log_printf("/\n");
        return;
    }
    while (cur > 0 && len + 2 < sizeof(buf)) {
        const char *name = fs_nodes[cur].name;
        size_t nlen = str_len(name);
        if (len + nlen + 1 >= sizeof(buf)) break;
        for (size_t i = 0; i < nlen; ++i) buf[len++] = name[i];
        buf[len++] = '/';
        cur = fs_nodes[cur].parent;
    }
    for (size_t i = 0; i < len / 2; ++i) {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    buf[len - 1] = '\0';
    log_printf("/%s\n", buf);
}

void fs_ls(int node) {
    if (initramfs_available()) {
        initramfs_ls(node);
        return;
    }
    if (node < 0 || node >= FS_MAX_NODES) return;
    const struct fs_node *d = &fs_nodes[node];
    if (!d->is_dir) {
        log_printf("%s\n", d->name);
        return;
    }
    for (int i = 0; i < d->child_count; ++i) {
        int idx = d->child_start + i;
        if (idx >= FS_MAX_NODES) break;
        log_printf("%s%s ", fs_nodes[idx].name, fs_nodes[idx].is_dir ? "/" : "");
    }
    log_printf("\n");
}
