#ifndef PSEUDOFS_H
#define PSEUDOFS_H

#include <stdint.h>

#define PSEUDOFS_DEV 1
#define PSEUDOFS_PROC 2
#define PSEUDOFS_SYS 3

#define PSEUDOFS_DEV_NULL 1
#define PSEUDOFS_DEV_TTY0 2
#define PSEUDOFS_DEV_RANDOM 3
#define PSEUDOFS_DEV_URANDOM 4

int pseudofs_is_ready(int fs_id);
int pseudofs_root(int fs_id);
int pseudofs_resolve(int fs_id, int cwd, const char *path);
int pseudofs_is_dir(int fs_id, int node);
int pseudofs_read_file(int fs_id, int node, const uint8_t **data, uint64_t *size);
void pseudofs_pwd(int fs_id, int cwd);
void pseudofs_ls(int fs_id, int node);

#endif /* PSEUDOFS_H */
