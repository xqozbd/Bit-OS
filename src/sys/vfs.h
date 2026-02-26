#ifndef SYS_VFS_H
#define SYS_VFS_H

#include <stdint.h>
#include <stddef.h>

#define VFS_BACKEND_MOCK 1
#define VFS_BACKEND_INITRAMFS 2
#define VFS_BACKEND_BLOCK 3
#define VFS_BACKEND_FAT32 4
#define VFS_BACKEND_DEV 5
#define VFS_BACKEND_PROC 6
#define VFS_BACKEND_SYS 7
#define VFS_BACKEND_EXT2 8
#define VFS_BACKEND_TMPFS 9

#define VFS_MAX_MOUNTS 12

struct vfs_mount_entry {
    const char *path;
    int backend;
    int root;
};

struct mount_namespace {
    uint32_t id;
    uint32_t refcount;
    int root_backend;
    int root_node;
    int root_index;
    int mount_count;
    struct vfs_mount_entry mounts[VFS_MAX_MOUNTS];
};

void vfs_init(void);
void vfs_set_root(int backend, int root_node);
int vfs_mount(const char *path, int backend, int root_node);
struct mount_namespace *vfs_root_namespace(void);
void vfs_ns_clone(struct mount_namespace *dst, const struct mount_namespace *src);

int vfs_resolve(int cwd, const char *path);
int vfs_is_dir(int node);
int vfs_read_file(int node, const uint8_t **data, uint64_t *size);
int vfs_write_file(int node, const uint8_t *data, uint64_t size, uint64_t offset);
int vfs_truncate(int node, uint64_t new_size);
uint64_t vfs_get_size(int node);
int vfs_create(int cwd, const char *path, int is_dir);
void vfs_pwd(int cwd);
void vfs_ls(int node);
int vfs_list_dir(const char *path, char *out, uint64_t out_len);
int vfs_build_path(int node, char *out, size_t out_len);
int vfs_root_backend(void);
int vfs_node_backend(int node);
int vfs_node_raw(int node);
int vfs_chmod(int node, uint16_t mode);
int vfs_chown(int node, uint32_t uid, uint32_t gid);
int vfs_get_attr(int node, uint32_t *uid, uint32_t *gid, uint16_t *mode, int *is_dir);
int vfs_link(int cwd, const char *oldpath, const char *newpath);
int vfs_symlink(int cwd, const char *target, const char *linkpath);
int vfs_readlink(const char *path, char *out, size_t out_len);

#endif /* SYS_VFS_H */
