#ifndef BLOCKFS_H
#define BLOCKFS_H

#include <stdint.h>

int blockfs_root(void);
int blockfs_resolve(int cwd, const char *path);
int blockfs_is_dir(int node);
int blockfs_read_file(int node, const uint8_t **data, uint64_t *size);
void blockfs_pwd(int cwd);
void blockfs_ls(int node);

#endif /* BLOCKFS_H */
