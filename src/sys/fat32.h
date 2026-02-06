#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>

int fat32_init_from_partition(uint32_t part_index);
int fat32_is_ready(void);
int fat32_root(void);

int fat32_resolve(int cwd, const char *path);
int fat32_is_dir(int node);
int fat32_read_file(int node, const uint8_t **data, uint64_t *size);
void fat32_pwd(int cwd);
void fat32_ls(int node);

#endif /* FAT32_H */
