#ifndef FS_MOCK_H
#define FS_MOCK_H

int fs_root(void);
int fs_resolve(int cwd, const char *path);
int fs_is_dir(int node);
void fs_pwd(int cwd);
void fs_ls(int node);

#endif /* FS_MOCK_H */
