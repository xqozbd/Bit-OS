#ifndef FS_MOCK_H
#define FS_MOCK_H

#include <stdint.h>

int fs_root(void);
int fs_resolve(int cwd, const char *path);
int fs_is_dir(int node);
int fs_read_file(int node, const uint8_t **data, uint64_t *size);
void fs_pwd(int cwd);
void fs_ls(int node);

#endif /* FS_MOCK_H */
