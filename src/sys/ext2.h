#ifndef SYS_EXT2_H
#define SYS_EXT2_H

#include <stdint.h>

int ext2_init_from_partition(uint32_t part_index);
int ext2_is_ready(void);
int ext2_root(void);
int ext2_resolve(int cwd, const char *path);
int ext2_is_dir(int node);
int ext2_read_file(int node, const uint8_t **data, uint64_t *size);
uint64_t ext2_get_size(int node);
void ext2_pwd(int cwd);
void ext2_ls(int node);
void ext2_ensure_scanned(int node);
int ext2_alloc_block(uint32_t *out_block);
int ext2_free_block(uint32_t block);
int ext2_alloc_inode(uint16_t mode, uint32_t *out_inode);
int ext2_free_inode(uint32_t inode);
int ext2_create(int cwd, const char *path, uint16_t mode, int is_dir);
int ext2_write(int node, const uint8_t *data, uint64_t len, uint64_t offset);
int ext2_truncate(int node, uint64_t new_size);
int ext2_unlink(int cwd, const char *path);
int ext2_rename(int cwd, const char *old_path, const char *new_name);
int ext2_get_attr(int node, uint32_t *uid, uint32_t *gid, uint16_t *mode, int *is_dir);
int ext2_set_attr(int node, uint32_t uid, uint32_t gid, uint16_t mode, int set_uid, int set_gid, int set_mode);
int ext2_link_node(int parent, int target, const char *name);
int ext2_symlink_node(int parent, const char *name, const char *target);
int ext2_readlink(int node, char *out, uint64_t out_len);

#endif /* SYS_EXT2_H */
