#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include "arch/x86_64/paging.h"

int elf_load_and_run(const char *path, int argc, char **argv, char **envp);
int elf_load_user(const char *path, int argc, char **argv, char **envp,
                  struct user_addr_space *out_layout,
                  uint64_t *out_entry, uint64_t *out_pml4, uint64_t *out_rsp);

#endif /* ELF_LOADER_H */
