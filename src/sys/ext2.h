#ifndef SYS_EXT2_H
#define SYS_EXT2_H

#include <stdint.h>

int ext2_init_from_partition(uint32_t part_index);
int ext2_is_ready(void);
int ext2_root(void);
int ext2_resolve(int cwd, const char *path);
int ext2_is_dir(int node);
int ext2_read_file(int node, const uint8_t **data, uint64_t *size);
void ext2_pwd(int cwd);
void ext2_ls(int node);
int ext2_alloc_block(uint32_t *out_block);
int ext2_free_block(uint32_t block);
int ext2_alloc_inode(uint16_t mode, uint32_t *out_inode);
int ext2_free_inode(uint32_t inode);
int ext2_create(int cwd, const char *path, uint16_t mode, int is_dir);
int ext2_write(int node, const uint8_t *data, uint64_t len, uint64_t offset);
int ext2_truncate(int node, uint64_t new_size);
int ext2_unlink(int cwd, const char *path);
int ext2_rename(int cwd, const char *old_path, const char *new_name);

#endif /* SYS_EXT2_H */
