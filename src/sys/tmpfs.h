#ifndef SYS_TMPFS_H
#define SYS_TMPFS_H

#include <stdint.h>
#include <stddef.h>

int tmpfs_init(void);
int tmpfs_root(void);
int tmpfs_is_dir(int node);
int tmpfs_resolve(int cwd, const char *path);
int tmpfs_read_file(int node, const uint8_t **data, uint64_t *size);
int tmpfs_write_file(int node, const uint8_t *data, uint64_t size, uint64_t offset);
int tmpfs_truncate(int node, uint64_t new_size);
uint64_t tmpfs_get_size(int node);
int tmpfs_create(int cwd, const char *path, int is_dir);
int tmpfs_list_dir(int node, char *out, uint64_t out_len);
void tmpfs_pwd(int node);
void tmpfs_ls(int node);

#endif /* SYS_TMPFS_H */
