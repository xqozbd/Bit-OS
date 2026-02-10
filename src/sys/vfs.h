#ifndef SYS_VFS_H
#define SYS_VFS_H

#include <stdint.h>

#define VFS_BACKEND_MOCK 1
#define VFS_BACKEND_INITRAMFS 2
#define VFS_BACKEND_BLOCK 3
#define VFS_BACKEND_FAT32 4
#define VFS_BACKEND_DEV 5
#define VFS_BACKEND_PROC 6
#define VFS_BACKEND_SYS 7
#define VFS_BACKEND_EXT2 8

void vfs_init(void);
void vfs_set_root(int backend, int root_node);
int vfs_mount(const char *path, int backend, int root_node);

int vfs_resolve(int cwd, const char *path);
int vfs_is_dir(int node);
int vfs_read_file(int node, const uint8_t **data, uint64_t *size);
void vfs_pwd(int cwd);
void vfs_ls(int node);

#endif /* SYS_VFS_H */
