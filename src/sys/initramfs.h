#ifndef INITRAMFS_H
#define INITRAMFS_H

#include <stdint.h>

int initramfs_init_from_limine(void);
int initramfs_available(void);

int initramfs_root(void);
int initramfs_is_dir(int node);
int initramfs_resolve(int cwd, const char *path);
int initramfs_read_file(int node, const uint8_t **data, uint64_t *size);
void initramfs_pwd(int cwd);
void initramfs_ls(int node);

#endif /* INITRAMFS_H */
